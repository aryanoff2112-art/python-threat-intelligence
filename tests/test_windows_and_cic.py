"""Time-window consistency (weakness C) and CIC-IDS-layout handling (weakness A tooling)."""
import json

import numpy as np  # type: ignore[import-not-found]
import pandas as pd  # type: ignore[import-not-found]
import pytest  # type: ignore[import-not-found]

import main
from detection.feature_engineering import add_window_aggregates, aggregate_mode
from detection.pipeline import DetectionPipeline
from detection.preprocessing import (fix_twelve_hour_clock, load_flows_many, split_three_way, subsample_windows,
                                     temporal_split)
from detection.synthetic import generate
from intelligence.ioc_matcher import IOCMatcher
from scripts.verify_checksums import main as verify_main
from tests.test_bundle_and_cli import _fitted


# ------------------------------------------------------------------- window strategy
def test_aggregates_are_independent_of_batch_size_for_complete_windows():
    flows, _ = generate(n_benign=3000, seed=1)
    flows = flows.sort_values("timestamp").reset_index(drop=True)
    cut = flows["timestamp"].min().floor("5min") + pd.Timedelta("2h")          # window-aligned cut
    small = flows[flows["timestamp"] >= cut].reset_index(drop=True)
    full = add_window_aggregates(flows)
    part = add_window_aggregates(small)
    cols = ["src_flow_count", "src_unique_dst_ports", "src_unique_dst_ips"]
    assert np.array_equal(full[full["timestamp"] >= cut][cols].to_numpy(), part[cols].to_numpy())


def test_aggregates_are_disabled_without_timestamp_or_source_ip():
    flows, _ = generate(n_benign=500, seed=1)
    assert aggregate_mode(flows) == "src_ip+window"
    assert aggregate_mode(flows.drop(columns=["timestamp"])) == "none"
    assert aggregate_mode(flows.drop(columns=["src_ip"])) == "none"


def test_scoring_is_identical_whether_a_stream_is_one_batch_or_split_with_context():
    pipe, te, _ = _fitted()
    stream = te.sort_values("timestamp").reset_index(drop=True)
    t = stream["timestamp"].quantile(0.5)
    assert t != t.floor("5min")                                                # cut falls mid-window
    b1, b2 = stream[stream["timestamp"] < t], stream[stream["timestamp"] >= t]
    full = pipe.score(stream).iloc[len(b1):].reset_index(drop=True)
    alone, with_ctx = pipe.score(b2), pipe.score(b2, context=b1)
    assert np.allclose(full["risk_score"], with_ctx["risk_score"])             # context restores equality exactly
    differs = ~np.isclose(full["risk_score"], alone["risk_score"])
    assert (alone["edge_window"] | ~differs).all()                             # drift confined to flagged edge flows
    assert not with_ctx["edge_window"].iloc[0]                                 # context completes the first window
    first_win = pd.to_datetime(b2["timestamp"]).dt.floor("5min") == pd.to_datetime(b2["timestamp"]).dt.floor("5min").min()
    assert alone.loc[first_win.to_numpy(), "edge_window"].all()


def test_context_with_wrong_schema_is_rejected():
    pipe, te, _ = _fitted()
    with pytest.raises(ValueError):
        pipe.score(te.head(50), context=te.head(50).drop(columns=["src_ip"]))


def test_model_trained_without_timestamps_has_no_batch_dependence():
    flows, iocs = generate(n_benign=3000, seed=11)
    tr, va, te = split_three_way(flows, "10min")
    drop = ["timestamp"]
    pipe = DetectionPipeline(IOCMatcher(iocs.assign(first_seen=None))).fit(tr.drop(columns=drop))
    assert pipe.input_schema["aggregate_mode"] == "none"
    a = pipe.score(te.drop(columns=drop).head(100))["anomaly_raw"].to_numpy()
    b = pipe.score(te.drop(columns=drop).head(400))["anomaly_raw"].to_numpy()[:100]
    assert np.allclose(a, b)
    with pytest.raises(ValueError):                                            # but a timestamped batch is refused
        pipe.score(te.head(50))


def test_temporal_split_never_lets_a_window_straddle_the_cut():
    flows, _ = generate(n_benign=4000, seed=3)
    tr, te = temporal_split(flows, 0.7, embargo="10min")
    w = lambda d: set(pd.to_datetime(d["timestamp"]).dt.floor("5min"))
    assert not (w(tr) & w(te))



def test_evaluation_rejects_non_chronological_splits():
    from detection.evaluation import run_experiment
    flows, iocs = generate(n_benign=4000, seed=19)
    tr, va, te = split_three_way(flows, "10min")
    # Inject a future row into training: this used to be reported as a diagnostic only.
    bad_train = pd.concat([tr, te.tail(1)], ignore_index=True)
    with pytest.raises(ValueError, match="Chronological split violation|not strictly ordered"):
        run_experiment(matcher=IOCMatcher(iocs.assign(first_seen=None)),
                       splits=(bad_train, va, te), seed=19)


# ------------------------------------------------------------------- CIC-IDS layout
def _write_cic_layout(flows, path):
    """Re-express synthetic flows in the real CIC-IDS2017 'GeneratedLabelledFlows' layout: padded
    header names, extra columns, duplicated column name, 12-hour timestamps WITHOUT AM/PM, 'Infinity'/'NaN'."""
    f = flows.copy()
    day_secs = (f["timestamp"] - f["timestamp"].dt.normalize()).dt.total_seconds()
    f["ts24"] = pd.Timestamp("2017-07-07 09:00") + pd.to_timedelta(day_secs / 86400 * 8 * 3600, unit="s")  # 09:00-17:00
    h = f["ts24"].dt.hour
    f["ts_txt"] = (f["ts24"].dt.month.astype(str) + "/" + f["ts24"].dt.day.astype(str) + "/" + f["ts24"].dt.year.astype(str)
                   + " " + h.where(h <= 12, h - 12).astype(str) + ":" + f["ts24"].dt.minute.map("{:02d}".format))
    out = pd.DataFrame({
        "Flow ID": f["flow_id"].astype(str), " Source IP": f["src_ip"], " Source Port": 40000, " Destination IP": f["dst_ip"],
        " Destination Port": f["dst_port"], " Protocol": 6, " Timestamp": f["ts_txt"], " Flow Duration": f["flow_duration"],
        " Total Fwd Packets": f["fwd_packets"], " Total Backward Packets": f["bwd_packets"],
        "Total Length of Fwd Packets": f["fwd_bytes"], " Total Length of Bwd Packets": f["bwd_bytes"],
        " Flow Bytes/s": f["flow_bytes_s"], " Flow Packets/s": f["flow_packets_s"],
        " SYN Flag Count": f["syn_flags"], " RST Flag Count": f["rst_flags"], " Fwd Header Length": 20,
        " Label": np.where(f["label"] == 1, f["attack_type"], "BENIGN")})
    out.insert(len(out.columns), " Fwd Header Length.1", 20)
    out[" Flow Bytes/s"] = out[" Flow Bytes/s"].astype(object)
    out[" Flow Packets/s"] = out[" Flow Packets/s"].astype(object)
    out.loc[out.index[:3], " Flow Bytes/s"] = "Infinity"
    out.loc[out.index[3], " Flow Packets/s"] = "NaN"
    out.to_csv(path, index=False, encoding="latin-1")
    return f["ts24"]


def test_cic_layout_loads_and_twelve_hour_clock_is_repaired(tmp_path):
    flows, _ = generate(n_benign=2500, seed=21)
    truth = _write_cic_layout(flows, tmp_path / "Friday.csv")
    df = load_flows_many([tmp_path / "Friday.csv"])
    rep = df.attrs["clean_report"]
    assert {"src_ip", "dst_ip", "label", "attack_type", "timestamp"} <= set(df.columns)
    assert rep["twelve_hour_clock_rows_shifted"] > 0 and rep["non_numeric_or_inf_or_nan"] == 4
    assert df["timestamp"].dt.hour.between(8, 17).all()                        # afternoon is PM again, not 1-5am
    # every loaded timestamp equals the true 24-hour time truncated to the minute
    expected = set(truth.dt.floor("min"))
    assert set(df["timestamp"]) <= expected
    off = load_flows_many([tmp_path / "Friday.csv"], fix_timestamps=False)
    assert off["timestamp"].dt.hour.min() < 8                                  # the bug the fix addresses


def test_twelve_hour_fix_is_a_noop_on_genuine_24_hour_data():
    ts = pd.Series(pd.to_datetime(["2017-07-07 03:00", "2017-07-07 09:00", "2017-07-07 15:00", "2017-07-07 22:00"]))
    fixed, n = fix_twelve_hour_clock(ts)
    assert n == 0 and fixed.equals(ts)


def test_window_subsampling_keeps_attack_windows_and_reports_fraction():
    flows, _ = generate(n_benign=6000, seed=2)
    sub, frac = subsample_windows(flows, 0.3, seed=1)
    assert 0 < frac < 1 and len(sub) < len(flows)
    w = flows["timestamp"].dt.floor("5min")
    attack_windows = set(w[flows["label"] == 1])
    assert attack_windows <= set(sub["timestamp"].dt.floor("5min"))
    assert subsample_windows(flows, 1.0)[0] is flows


def test_evaluate_on_cic_layout_end_to_end_with_subsampling(tmp_path):
    flows, iocs = generate(n_benign=9000, seed=7)
    _write_cic_layout(flows, tmp_path / "Day.csv")
    dbp, mdir, rdir = str(tmp_path / "t.db"), str(tmp_path / "m"), str(tmp_path / "r")
    main.main(["evaluate", "--flows", str(tmp_path / "Day.csv"), "--db", dbp, "--models-dir", mdir, "--results-dir", rdir,
               "--benign-window-frac", "0.6", "--rf-max-rows", "4000", "--no-ioc"])
    res = json.loads((tmp_path / "r" / "results.json").read_text())
    assert res["sampling"]["benign_row_fraction"] < 1 and res["sampling"]["rf_max_train_rows"] == 4000
    rf = res["models"]["Random Forest (supervised baseline)"]
    assert rf["precision_at_original_prevalence"] <= rf["precision"] + 1e-9
    assert res["dataset"]["split"] == "temporal+embargo"
    assert res["reproducibility"]["ioc_matching_enabled"] is False
    assert res["dataset"]["iocs_loaded"] == 0


# ------------------------------------------------------------------- checksum verification
def test_verify_checksums_detects_ok_mismatch_and_missing(tmp_path):
    import hashlib
    (tmp_path / "a.zip").write_bytes(b"hello")
    good = hashlib.md5(b"hello").hexdigest()
    md5 = tmp_path / "a.md5"
    md5.write_text(f"{good}  a.zip\n")
    assert verify_main([str(md5), "--dir", str(tmp_path)]) == 0
    md5.write_text(f"{'0' * 32}  a.zip\n")
    assert verify_main([str(md5), "--dir", str(tmp_path)]) == 1
    md5.write_text(f"{good}  other.zip\n")
    assert verify_main([str(md5), "--dir", str(tmp_path)]) == 1
    md5.write_text(f"MD5 (a.zip) = {good}\n")                                   # BSD format
    assert verify_main([str(md5), "--dir", str(tmp_path)]) == 0
    md5.write_text("garbage\n")
    assert verify_main([str(md5), "--dir", str(tmp_path)]) == 2
