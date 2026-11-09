import argparse
import json

import numpy as np
import pytest

import main
from database import db
from detection.bundle import BundleError, load_bundle, save_bundle
from detection.feature_engineering import SchemaMismatchError
from detection.pipeline import DetectionPipeline
from detection.preprocessing import split_three_way
from detection.synthetic import generate
from intelligence.ioc_matcher import IOCMatcher


def _fitted(seed=11):
    flows, iocs = generate(n_benign=3000, seed=seed)
    matcher = IOCMatcher(iocs.assign(first_seen=None))
    tr, va, te = split_three_way(flows, "10min")
    pipe = DetectionPipeline(matcher).fit(tr).calibrate(va)
    return pipe, te, matcher


def test_bundle_roundtrip_gives_identical_scores_and_complete_manifest(tmp_path):
    pipe, te, matcher = _fitted()
    path = save_bundle(pipe, tmp_path / "b", evaluation={"note": "x"})
    loaded = load_bundle(path, matcher)
    a, b = pipe.score(te), loaded.score(te)
    assert np.allclose(a["risk_score"], b["risk_score"]) and (a["alert"] == b["alert"]).all()
    m = json.loads((path / "manifest.json").read_text())
    for key in ("bundle_version", "feature_set_version", "environment", "anomaly_model", "input_schema",
                "rules", "risk", "training", "files", "created_utc"):
        assert key in m
    assert m["input_schema"]["feature_columns"] == pipe.input_schema["feature_columns"]
    assert m["rules"]["thresholds"] == pipe.rules.thresholds
    assert m["risk"]["alert_threshold"] == pipe.alert_threshold


def test_bundle_detects_modified_model_file(tmp_path):
    pipe, _, _ = _fitted()
    path = save_bundle(pipe, tmp_path / "b")
    with open(path / "isolation_forest.joblib", "ab") as f:
        f.write(b"tamper")
    with pytest.raises(BundleError, match="Integrity"):
        load_bundle(path)


def test_bundle_rejects_incompatible_versions(tmp_path):
    pipe, _, _ = _fitted()
    path = save_bundle(pipe, tmp_path / "b")
    mp = path / "manifest.json"
    m = json.loads(mp.read_text()); m["bundle_version"] = "9.0.0"; mp.write_text(json.dumps(m))
    with pytest.raises(BundleError, match="Incompatible"):
        load_bundle(path)
    m["bundle_version"] = "1.0.0"; m["feature_set_version"] = "999"; mp.write_text(json.dumps(m))
    with pytest.raises(BundleError, match="Feature set"):
        load_bundle(path)


def test_schema_mismatch_fails_loudly_instead_of_silently(tmp_path):
    pipe, te, matcher = _fitted()
    loaded = load_bundle(save_bundle(pipe, tmp_path / "b"), matcher)
    with pytest.raises(SchemaMismatchError):
        loaded.score(te.drop(columns=["src_ip"]))


def test_scoring_never_needs_labels():
    pipe, te, _ = _fitted()
    unlabelled = te.drop(columns=["label", "attack_type"])
    assert np.allclose(pipe.score(unlabelled)["risk_score"], pipe.score(te)["risk_score"])


def test_cli_evaluate_then_detect_on_unlabelled_traffic(tmp_path):
    flows, iocs = generate(n_benign=3000, seed=5)
    unseen, _ = generate(n_benign=1500, seed=6)
    flows.to_csv(tmp_path / "lab.csv", index=False); iocs.to_csv(tmp_path / "iocs.csv", index=False)
    unseen.drop(columns=["label", "attack_type"]).to_csv(tmp_path / "new.csv", index=False)
    dbp, mdir = str(tmp_path / "t.db"), str(tmp_path / "models")
    main.main(["ingest", "--source", "file", "--file", str(tmp_path / "iocs.csv"), "--db", dbp])
    main.main(["evaluate", "--flows", str(tmp_path / "lab.csv"), "--db", dbp,
               "--models-dir", mdir, "--results-dir", str(tmp_path / "res")])
    assert (tmp_path / "res" / "results.json").exists() and (tmp_path / "models" / "LATEST").exists()
    main.main(["detect", "--flows", str(tmp_path / "new.csv"), "--db", dbp, "--models-dir", mdir])
    conn = db.get_conn(dbp)
    alerts = db.fetch_alerts(conn)
    assert len(alerts) > 0 and alerts["ground_truth_label"].isna().all()   # no labels were used or stored


def test_detect_without_a_bundle_exits_cleanly(tmp_path):
    (tmp_path / "f.csv").write_text("x\n1\n")
    with pytest.raises(SystemExit):
        main.main(["detect", "--flows", str(tmp_path / "f.csv"), "--db", str(tmp_path / "d.db"),
                   "--models-dir", str(tmp_path / "none")])
