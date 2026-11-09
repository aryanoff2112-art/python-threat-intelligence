import numpy as np
import pandas as pd

from alerts.alert_engine import build_alerts
from detection.anomaly_scoring import RiskScorer, compute_risk, select_alert_threshold, severity_from_score
from detection.evaluation import K_H_CAL, K_IF, compute_metrics, run_experiment
from detection.feature_engineering import build_features
from detection.leakage import keep_masks, leakage_report
from detection.preprocessing import clean, load_flows, split_three_way, standardize_columns, temporal_split
from detection.synthetic import generate
from intelligence.ioc_matcher import IOCMatcher


def _cic_frame():
    return pd.DataFrame({" Destination Port": [80, 80, 80, 1], " Flow Duration": [10, 10, np.inf, 5],
                         " Total Fwd Packets": [1, 1, 1, 1], " Total Backward Packets": [1, 1, 1, 1],
                         " Total Length of Fwd Packets": [5, 5, 5, 5], " Total Length of Bwd Packets": [5, 5, 5, 5],
                         " Flow Bytes/s": [1.0, 1.0, 1.0, 1.0], " Flow Packets/s": [1.0, 1.0, 1.0, np.nan],
                         " SYN Flag Count": [0] * 4, " RST Flag Count": [0] * 4,
                         " Label": ["BENIGN", "BENIGN", "DoS Hulk", "BENIGN"]})


def test_clean_handles_inf_nan_duplicates_and_duplicate_columns():
    df = clean(standardize_columns(_cic_frame()))
    assert len(df) == 1 and df["label"].tolist() == [0]


def test_load_flows_reads_cic_formatted_csv(tmp_path):
    raw = _cic_frame()
    raw[" Total Fwd Packets.1"] = 7           # CIC files contain duplicated column names
    raw.to_csv(tmp_path / "cic.csv", index=False)
    df = load_flows(tmp_path / "cic.csv")
    assert {"fwd_packets", "label", "attack_type"} <= set(df.columns) and len(df) == 1


def test_features_have_no_nan_or_inf_and_aggregates_present():
    flows, _ = generate(n_benign=1500, seed=1)
    X = build_features(flows)
    assert np.isfinite(X.to_numpy()).all() and "log_src_unique_dst_ports" in X.columns


def test_heuristic_risk_scoring_bands():
    assert compute_risk(0.5, 0.0, 0) == 0
    ioc_only = float(compute_risk(0.5, 0.8, 0))
    assert 40 <= ioc_only < 60 and severity_from_score(ioc_only) == "medium"
    assert severity_from_score(float(compute_risk(1.0, 0.9, 3))) == "critical"
    assert float(compute_risk(1.0, 1.0, 3)) == 100.0            # saturation is by design


def _synthetic_components(n=4000, seed=0):
    rng = np.random.default_rng(seed)
    A = rng.random(n) ** 3
    I = (rng.random(n) < 0.05) * 0.8
    R = rng.integers(0, 4, n)
    y = ((A > 0.9) | (I > 0) | ((R >= 3) & (rng.random(n) < 0.5))).astype(int)
    return A, I, R, y


def test_calibrated_scorer_learns_positive_weights_and_roundtrips():
    A, I, R, y = _synthetic_components()
    s = RiskScorer().fit(A, I, R, y)
    assert s.method == "calibrated" and all(v > 0 for v in s.coef.values())
    risk = s.score(A, I, R)
    assert risk.min() >= 0 and risk.max() <= 100
    assert np.allclose(RiskScorer.from_dict(s.to_dict()).score(A, I, R), risk)


def test_partial_calibration_adds_uncalibrated_ioc_prior():
    A, I, R, y = _synthetic_components()
    s = RiskScorer().fit(A, I, R, y, use_ioc=False)
    assert s.method == "calibrated_partial" and "ioc" not in s.coef
    assert s.score(0.5, 1.0, 0) > s.score(0.5, 0.0, 0)


def test_alert_threshold_respects_validation_fpr_cap():
    rng = np.random.default_rng(1)
    scores = np.r_[rng.random(5000) * 50, 40 + rng.random(300) * 60]
    y = np.r_[np.zeros(5000, int), np.ones(300, int)]
    thr = select_alert_threshold(scores, y, 0.01)
    assert (scores[y == 0] >= thr).mean() <= 0.01


def test_metrics():
    m = compute_metrics([0, 0, 1, 1], [0, 1, 1, 0])
    assert m["precision"] == 0.5 and m["recall"] == 0.5 and m["false_positive_rate"] == 0.5


def test_temporal_split_respects_order_and_embargo():
    flows, _ = generate(n_benign=1000, seed=3)
    tr, te = temporal_split(flows, 0.7, embargo="10min")
    assert tr["timestamp"].max() < te["timestamp"].min() - pd.Timedelta("9min")
    a, b, c = split_three_way(flows, embargo="10min")
    assert a.timestamp.max() < b.timestamp.min() and b.timestamp.max() < c.timestamp.min()


def test_leakage_report_and_masks_catch_injected_duplicates():
    flows, _ = generate(n_benign=2000, seed=2)
    tr, va, te = split_three_way(flows, "10min")
    te2 = pd.concat([te, tr.sample(20, random_state=0)], ignore_index=True)   # 20 train rows leaked into test
    rep = leakage_report(tr, va, te2)
    assert rep["train_test_exact_duplicates"] >= 20
    assert leakage_report(tr, va, te)["time_order_ok"] is True       # clean split passes
    assert rep["time_order_ok"] is False                             # injected old rows are flagged
    keep_val, keep_test = keep_masks(tr, va, te2)
    assert keep_test[-20:].sum() == 0 and keep_val.all()


def test_evaluate_rejects_unlabelled_data():
    flows, _ = generate(n_benign=1500, seed=4)
    try:
        run_experiment(flows.drop(columns=["label", "attack_type"]))
    except ValueError as e:
        assert "detect" in str(e)
    else:
        raise AssertionError("evaluate should refuse unlabelled data")


def test_evaluate_refuses_test_split_without_attacks():
    flows, _ = generate(n_benign=4000, seed=7)          # temporal test split happens to hold no attacks
    _, _, te = split_three_way(flows, "10min")
    assert te["label"].sum() == 0
    try:
        run_experiment(flows, seed=7)
    except ValueError as e:
        assert "meaningless" in str(e)
    else:
        raise AssertionError("expected a guard against a test split with no attacks")


def test_end_to_end_experiment_is_reproducible_and_sane():
    flows, iocs = generate(n_benign=8000, seed=7)
    matcher = IOCMatcher(iocs.assign(first_seen=None))
    r1, scored, pipe = run_experiment(flows, matcher, seed=7)
    r2, _, _ = run_experiment(flows, matcher, seed=7)
    assert r1["models"] == r2["models"]                                   # reproducible
    # small data -> few IOC hits in validation -> the IOC weight is not learnable; fallback must be flagged
    assert r1["calibration"]["method"] in ("calibrated", "calibrated_partial")
    if r1["calibration"]["method"] == "calibrated_partial":
        assert any("IOC weight NOT learned" in n for n in r1["calibration"]["notes"])
    assert r1["calibration"]["val_fpr_at_threshold"] <= 0.0101           # cap holds on validation
    hybrid, iforest = r1["models"][K_H_CAL], r1["models"][K_IF]
    assert hybrid["recall"] >= iforest["recall"] and hybrid["false_positive_rate"] < 0.05
    assert r1["unseen_attack_generalization"]
    alerts = build_alerts(scored, min_score=pipe.alert_threshold)
    assert len(alerts) > 0 and alerts["explanation"].str.len().min() > 0
