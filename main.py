"""CLI entry point. Two separate workflows:

  evaluate  LABELLED data: split, train, calibrate, measure, and save a versioned model bundle.
  detect    UNLABELLED traffic: load a saved bundle and score new flows. Never needs labels.

Examples
  python main.py demo                                   # offline end-to-end on synthetic data
  python main.py generate                               # synthetic labelled + unlabelled flows + sample feed
  python main.py ingest --source sample|urlhaus|otx|file --file feed.csv
  python main.py evaluate --flows data/raw/*.csv        # temporal split across the files
  python main.py evaluate --train mon.csv tue.csv --test wed.csv thu.csv   # cross-day generalisation
  python main.py detect --flows new_traffic.csv [--bundle models/bundle-...]
"""
import argparse
import hashlib
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

from alerts.alert_engine import build_alerts
from config.config import DATA_PROCESSED, DATA_SAMPLES, EMBARGO, MODELS_DIR
from database import db
from detection.bundle import BundleError, _environment, load_bundle, read_manifest
from detection.evaluation import run_experiment, save_results, to_markdown
from detection.preprocessing import (DataFormatError, load_flows_many, subsample_windows,
                                     temporal_split)
from detection.synthetic import generate
from intelligence.ioc_matcher import IOCMatcher, load_sample_iocs

FLOWS_SAMPLE = DATA_SAMPLES / "synthetic_flows.csv"            # labelled
UNSEEN_SAMPLE = DATA_SAMPLES / "synthetic_unseen.csv"          # unlabelled, different seed
IOCS_SAMPLE = DATA_SAMPLES / "sample_iocs.csv"


def _matcher(db_path):
    conn = db.get_conn(db_path); db.init_db(conn)
    return conn, IOCMatcher(db.load_indicators(conn))


def resolve_bundle(bundle, models_dir) -> Path:
    if bundle:
        return Path(bundle)
    latest = Path(models_dir) / "LATEST"
    if not latest.exists():
        raise SystemExit(f"No trained bundle found in {models_dir}. Run `evaluate` on labelled data first.")
    return Path(models_dir) / latest.read_text().strip()


def cmd_generate(args):
    flows, iocs = generate(n_benign=args.n_benign)
    unseen, _ = generate(n_benign=max(args.n_benign // 4, 1000), seed=43)   # different traffic, labels removed
    DATA_SAMPLES.mkdir(parents=True, exist_ok=True)
    flows.to_csv(FLOWS_SAMPLE, index=False); iocs.to_csv(IOCS_SAMPLE, index=False)
    unseen.drop(columns=["label", "attack_type"]).to_csv(UNSEEN_SAMPLE, index=False)
    print(f"Wrote {len(flows):,} labelled flows, {len(unseen):,} UNLABELLED flows and {len(iocs)} IOCs to {DATA_SAMPLES}")


def cmd_ingest(args):
    conn = db.get_conn(args.db); db.init_db(conn)
    if args.source in ("sample", "file"):
        iocs = load_sample_iocs(args.file or IOCS_SAMPLE)
    elif args.source == "urlhaus":
        from intelligence.urlhaus_collector import fetch_urlhaus; iocs = fetch_urlhaus()
    else:
        from intelligence.otx_collector import fetch_otx; iocs = fetch_otx()
    new = db.upsert_indicators(conn, iocs)
    print(f"{args.source}: {len(iocs)} read, {new} new indicators stored")


def _load(paths, args):
    try:
        df = load_flows_many(paths, fix_timestamps=not getattr(args, "no_timestamp_fix", False),
                             skip_bad_lines=getattr(args, "skip_bad_lines", False))
    except DataFormatError as e:
        raise SystemExit(f"Input error: {e}")
    print("Cleaning report:", df.attrs.get("clean_report"))
    return df


def _provenance(paths) -> list[dict]:
    """File name, size and SHA-256 of every input, so an experiment can be reproduced and audited."""
    out = []
    for p in paths:
        p = Path(p)
        if not p.exists():
            continue
        h = hashlib.sha256()
        with open(p, "rb") as f:
            for chunk in iter(lambda: f.read(1 << 22), b""):
                h.update(chunk)
        out.append({"file": p.name, "bytes": p.stat().st_size, "sha256": h.hexdigest()})
    return out


def cmd_evaluate(args):
    frac, note = 1.0, None
    sub = lambda d: subsample_windows(d, args.benign_window_frac, seed=args.seed)
    if args.train and args.test:
        train_all, test = _load(args.train, args), _load(args.test, args)
        if args.benign_window_frac < 1.0:
            (train_all, f1), (test, f2) = sub(train_all), sub(test); frac = (f1 + f2) / 2
        train, val = temporal_split(train_all, 0.8, embargo=args.embargo)
        splits, df = (train, val, test), None
    else:
        df, splits = _load(args.flows or [FLOWS_SAMPLE], args), None
        if args.benign_window_frac < 1.0:
            df, frac = sub(df)
    if frac < 1.0:
        note = (f"benign time-windows subsampled to ~{frac:.1%} of benign rows (all attack windows kept); "
                "raw precision is inflated, use precision_at_original_prevalence")
        print("NOTE:", note)
    if getattr(args, "no_ioc", False):
        matcher = IOCMatcher()
        print("IOC matching disabled for this evaluation (historical dataset / no temporally valid IOC source).")
    else:
        conn, matcher = _matcher(args.db)
        print(f"{len(matcher):,} indicators loaded for IOC matching {matcher.stats}")
    try:
        results, _, pipe = run_experiment(df, matcher, strict_dedup=not args.keep_duplicates, embargo=args.embargo,
                                          splits=splits, rf_max_rows=args.rf_max_rows, seed=args.seed,
                                          benign_row_fraction=frac, sampling_note=note)
    except ValueError as e:
        raise SystemExit(f"Cannot evaluate: {e}")
    results["reproducibility"] = {
        "command": "python main.py " + " ".join(sys.argv[1:]), "environment": _environment(),
        "inputs": _provenance((args.train or []) + (args.test or []) + (args.flows or [str(FLOWS_SAMPLE)])),
        "embargo": args.embargo, "strict_dedup": not args.keep_duplicates, "random_state": args.seed,
        "benign_window_frac": args.benign_window_frac, "rf_max_rows": args.rf_max_rows,
        "ioc_matching_enabled": not getattr(args, "no_ioc", False)}
    save_results(results, Path(args.results_dir))
    summary = {"dataset": results["dataset"], "leakage": results["leakage"],
               "headline": {k: {m: v[m] for m in ("precision", "recall", "f1", "false_positive_rate")}
                            for k, v in results["models"].items()}}
    name = f"bundle-{datetime.now(timezone.utc):%Y%m%dT%H%M%SZ}"
    path = pipe.save(Path(args.models_dir) / name, evaluation=summary)
    (Path(args.models_dir) / "LATEST").write_text(name)
    print("\n" + to_markdown(results))
    print("\nCalibration:", results["calibration"])
    print("Leakage:", results["leakage"])
    print("Performance:", results["performance"])
    print(f"\nModel bundle saved to {path} (and marked LATEST)")


def cmd_detect(args):
    bundle = resolve_bundle(args.bundle, args.models_dir)
    conn, matcher = _matcher(args.db)
    try:
        pipe = load_bundle(bundle, matcher=matcher, strict_versions=args.strict_versions)
    except BundleError as e:
        raise SystemExit(f"Cannot load model bundle: {e}")
    flows = _load(args.flows, args)
    context = _load(args.context, args) if args.context else None
    try:
        t0 = time.perf_counter(); scored = pipe.score(flows, context=context); secs = time.perf_counter() - t0
    except ValueError as e:      # includes SchemaMismatchError
        raise SystemExit(f"Cannot score this input with this model: {e}")
    run_id = f"detect-{datetime.now(timezone.utc):%Y%m%dT%H%M%S}"
    alerts = build_alerts(scored, min_score=pipe.alert_threshold, run_id=run_id)
    n = db.insert_alerts(conn, alerts)
    dup = len(alerts) - n
    p99 = float((scored["anomaly_pct"] >= 0.99).mean())
    print(f"Bundle: {bundle.name} (created {read_manifest(bundle)['created_utc']}, risk method: {pipe.scorer.method})")
    print(f"Analysed {len(flows):,} flows in {secs:.2f}s; {n} new alerts stored (run {run_id}); "
          f"{dup} duplicates skipped; {len(matcher):,} indicators used {matcher.stats}")
    edge = int(scored["edge_window"].sum())
    if edge and context is None:
        print(f"WARNING: {edge} flows sit in the batch's first/last time window; their per-source aggregates may be "
              "understated if the batch cut a window. Feed continuous batches or pass --context <earlier flows>.")
    if n:
        print("Severity:", alerts["severity"].value_counts().to_dict())
    print(f"Drift check: {p99:.2%} of flows exceed the benign-baseline 99th percentile "
          "(about 1% expected for benign-like traffic; far higher suggests drift or an incident)")


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = p.add_subparsers(dest="command", required=True)
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--db", default=None, help="SQLite path (default from config)")
    common.add_argument("--models-dir", default=str(MODELS_DIR))

    g = sub.add_parser("generate"); g.add_argument("--n-benign", type=int, default=20000); g.set_defaults(fn=cmd_generate)
    i = sub.add_parser("ingest", parents=[common])
    i.add_argument("--source", choices=["sample", "file", "urlhaus", "otx"], default="sample")
    i.add_argument("--file"); i.set_defaults(fn=cmd_ingest)
    e = sub.add_parser("evaluate", parents=[common], help="labelled data: train + calibrate + measure + save bundle")
    e.add_argument("--flows", nargs="+"); e.add_argument("--train", nargs="+"); e.add_argument("--test", nargs="+")
    e.add_argument("--embargo", default=EMBARGO); e.add_argument("--keep-duplicates", action="store_true")
    e.add_argument("--benign-window-frac", type=float, default=1.0,
                   help="keep all attack windows + this fraction of benign windows (memory saver)")
    e.add_argument("--rf-max-rows", type=int, default=300_000, help="cap rows for the Random Forest baseline")
    e.add_argument("--no-timestamp-fix", action="store_true", help="disable CIC 12-hour-clock detection")
    e.add_argument("--skip-bad-lines", action="store_true")
    e.add_argument("--no-ioc", action="store_true",
                   help="disable IOC matching; recommended for historical datasets without time-valid indicators")
    e.add_argument("--seed", type=int, default=42, help="model + subsampling seed; repeat with several seeds to report variance")
    e.add_argument("--results-dir", default=str(DATA_PROCESSED)); e.set_defaults(fn=cmd_evaluate)
    d = sub.add_parser("detect", parents=[common], help="unlabelled traffic: score with a saved bundle")
    d.add_argument("--flows", nargs="+", required=True); d.add_argument("--bundle")
    d.add_argument("--strict-versions", action="store_true"); d.add_argument("--context", nargs="+")
    d.add_argument("--no-timestamp-fix", action="store_true"); d.add_argument("--skip-bad-lines", action="store_true")
    d.set_defaults(fn=cmd_detect)
    m = sub.add_parser("demo", parents=[common]); m.set_defaults(fn=None)

    args = p.parse_args(argv)
    if args.command == "demo":
        cmd_generate(argparse.Namespace(n_benign=20000))
        cmd_ingest(argparse.Namespace(source="sample", file=None, db=args.db))
        cmd_evaluate(argparse.Namespace(flows=None, train=None, test=None, embargo=EMBARGO, keep_duplicates=False,
                                        results_dir=str(DATA_PROCESSED), db=args.db, models_dir=args.models_dir,
                                        benign_window_frac=1.0, rf_max_rows=300_000, seed=42))
        print("\n--- detect on UNSEEN, UNLABELLED traffic using the saved bundle ---")
        cmd_detect(argparse.Namespace(flows=[str(UNSEEN_SAMPLE)], bundle=None, strict_versions=False, context=None,
                                      db=args.db, models_dir=args.models_dir))
    else:
        args.fn(args)


if __name__ == "__main__":
    main()
