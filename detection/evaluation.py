
"""Labelled-data experiment (the `evaluate` workflow). Unlabelled traffic goes through `detect`.

Protocol
  * 60/20/20 temporal train/validation/test split with an embargo gap
  * IF + rule thresholds fitted on TRAIN only
  * risk weights + alert threshold calibrated on VALIDATION only
  * metrics reported on TEST, excluding rows whose feature vector also appears in train/val
  * per-attack-type recall, plus an unseen-attack-type generalisation test for the supervised baseline
"""
import json
import time

import numpy as np # type: ignore[import-not-found]
import pandas as pd  # type: ignore[import-not-found]
from sklearn.ensemble import RandomForestClassifier # type: ignore[import-not-found]
from sklearn.metrics import (average_precision_score, confusion_matrix, # type: ignore[import-not-found]
                             precision_recall_fscore_support, roc_auc_score) 

from config.config import ALERT_MAX_FPR, ALERT_MIN_SCORE, EMBARGO, RANDOM_STATE
from detection.anomaly_scoring import RiskScorer, select_alert_threshold
from detection.feature_engineering import build_features
from detection.leakage import keep_masks, leakage_report
from detection.pipeline import DetectionPipeline
from detection.preprocessing import split_three_way

K_RULES = "Rules (behavioural, calibrated)"
K_IOC = "IOC match only"
K_IF = "Isolation Forest (benign-only training)"
K_IF_UNSUP = "Isolation Forest (unsupervised)"
K_H_PRIOR = "Hybrid: prior weights, default threshold"
K_H_PRIOR_VAL = "Hybrid: prior weights, threshold tuned on validation"
K_H_CAL = "Hybrid: weights + threshold calibrated on validation"
K_RF = "Random Forest (supervised baseline)"


def compute_metrics(y_true, y_pred, y_score=None) -> dict:
    y_true, y_pred = np.asarray(y_true), np.asarray(y_pred)
    p, r, f1, _ = precision_recall_fscore_support(y_true, y_pred, average="binary", zero_division=0)
    tn, fp, fn, tp = confusion_matrix(y_true, y_pred, labels=[0, 1]).ravel()
    m = {"precision": p, "recall": r, "f1": f1,
         "false_positive_rate": fp / (fp + tn) if (fp + tn) else 0.0,
         "tp": int(tp), "fp": int(fp), "tn": int(tn), "fn": int(fn)}
    if y_score is not None and len(np.unique(y_true)) == 2:
        m["roc_auc"] = roc_auc_score(y_true, y_score)
        m["pr_auc"] = average_precision_score(y_true, y_score)
    return {k: (round(float(v), 4) if isinstance(v, (float, np.floating)) else v) for k, v in m.items()}


def recall_by_attack(test: pd.DataFrame, pred) -> dict:
    """`test` and `pred` must be aligned (positional)."""
    if "attack_type" not in test.columns:
        return {}
    pred = np.asarray(pred)
    att = test[test["label"] == 1].assign(pred=pred[test["label"].to_numpy() == 1])
    return {k: round(float(v), 4) for k, v in att.groupby("attack_type")["pred"].mean().items()}


def _cap_rows(train, max_rows, seed):
    """Cap training rows for the (expensive) supervised baseline: keep up to half the cap as attacks,
    fill the rest with random benign rows. Applied only to the Random Forest, never to the unsupervised models."""
    if max_rows is None or len(train) <= max_rows:
        return train
    att, ben = train[train["label"] == 1], train[train["label"] == 0]
    att = att.sample(min(len(att), max_rows // 2), random_state=seed)
    ben = ben.sample(min(len(ben), max_rows - len(att)), random_state=seed)
    return pd.concat([att, ben]).sort_index().reset_index(drop=True)


def _fit_rf(train, seed, max_rows=None):
    train = _cap_rows(train, max_rows, seed)
    return RandomForestClassifier(n_estimators=200, class_weight="balanced_subsample",
                                  random_state=seed, n_jobs=-1).fit(build_features(train), train["label"])


def unseen_attack_generalization(train, test, scored_test, keep_test, seed=RANDOM_STATE, rf_max_rows=None) -> dict:
    """For each attack type: recall of a supervised model that SAW it vs one that NEVER saw it,
    next to the benign-trained Isolation Forest (which never sees any attack)."""
    if "attack_type" not in test.columns:
        return {}
    Xte = build_features(test)
    seen_pred = _fit_rf(train, seed, rf_max_rows).predict(Xte)
    k, benign = np.asarray(keep_test), (test["label"] == 0).to_numpy()
    out = {}
    for t in sorted(test.loc[test["label"] == 1, "attack_type"].unique()):
        tmask = ((test["attack_type"] == t).to_numpy()) & k
        if tmask.sum() == 0:
            continue
        reduced = train[train["attack_type"] != t]
        if reduced["label"].sum() == 0:
            continue
        unseen_pred = _fit_rf(reduced, seed, rf_max_rows).predict(Xte)
        out[t] = {"support": int(tmask.sum()),
                  "rf_recall_attack_seen_in_training": round(float(seen_pred[tmask].mean()), 4),
                  "rf_recall_attack_unseen": round(float(unseen_pred[tmask].mean()), 4),
                  "isolation_forest_recall": round(float(scored_test["if_pred"].to_numpy()[tmask].mean()), 4),
                  "rf_fpr_when_unseen": round(float(unseen_pred[benign & k].mean()), 4)}
    return out


def run_experiment(df=None, matcher=None, seed=RANDOM_STATE, strict_dedup=True, embargo=EMBARGO, splits=None,
                   rf_max_rows=300_000, benign_row_fraction=1.0, sampling_note=None):
    """Returns (results, scored_test, fitted_pipeline). Requires LABELLED data."""
    train, val, test = splits if splits is not None else split_three_way(df, embargo, seed)
    for name, part in (("train", train), ("validation", val), ("test", test)):
        if "label" not in part.columns:
            raise ValueError(f"`evaluate` needs labelled data ({name} split has no 'label'). "
                             "Use `detect` for unlabelled traffic.")
        if len(part) == 0:
            raise ValueError(f"{name} split is empty; need more data or a smaller --embargo.")
    # A reported temporal split must actually be chronological. A false diagnostic is
    # not enough: future information in training/calibration invalidates the evaluation.
    if all("timestamp" in part.columns for part in (train, val, test)):
        bounds = [(name, pd.to_datetime(part["timestamp"], errors="coerce"))
                  for name, part in (("train", train), ("validation", val), ("test", test))]
        for name, ts in bounds:
            if ts.isna().any():
                raise ValueError(f"{name} split contains invalid timestamps; refusing temporal evaluation.")
        if not (bounds[0][1].max() < bounds[1][1].min()
                and bounds[1][1].max() < bounds[2][1].min()):
            raise ValueError("Chronological split violation: require max(train) < min(validation) "
                             "and max(validation) < min(test). Sort inputs and use a non-overlapping "
                             "temporal split with an embargo.")
    leak = leakage_report(train, val, test)
    if "time_order_ok" in leak and not leak["time_order_ok"]:
        raise ValueError("Leakage diagnostic failed: timestamps are not strictly ordered across splits.")
    if strict_dedup:
        keep_val, keep_test = keep_masks(train, val, test)
    else:
        keep_val, keep_test = np.ones(len(val), bool), np.ones(len(test), bool)
    leak["strict_dedup"] = strict_dedup
    leak["val_rows_excluded"], leak["test_rows_excluded"] = int((~keep_val).sum()), int((~keep_test).sum())

    if test.loc[keep_test, "label"].nunique() < 2:
        raise ValueError("The test split lacks attack flows or benign flows; metrics would be meaningless. "
                         "Use more data, a different split (e.g. --train/--test across days), or a smaller --embargo.")
    t0 = time.perf_counter(); pipe = DetectionPipeline(matcher, "semi", seed=seed).fit(train)
    fit_s = time.perf_counter() - t0
    pipe.calibrate(val, "calibrated", ALERT_MAX_FPR, mask=keep_val)
    t0 = time.perf_counter(); scored = pipe.score(test); score_s = time.perf_counter() - t0

    k = keep_test
    te_k = test[k].reset_index(drop=True)
    y = te_k["label"].to_numpy()
    if y.sum() == 0 or (y == 0).sum() == 0:
        raise ValueError(
            "The evaluated test split lacks attack flows or benign flows, so precision/recall would be "
            "meaningless. Use more data, a different split (e.g. --train/--test across days), or a smaller --embargo.")
    results = {
        "dataset": {"train_rows": len(train), "val_rows": len(val), "test_rows": len(test),
                    "test_rows_evaluated": int(k.sum()), "test_attack_rows_evaluated": int(y.sum()),
                    "attack_support": {a: int(n) for a, n in te_k[te_k.label == 1].groupby("attack_type").size().items()}
                    if "attack_type" in te_k else {},
                    "split": "temporal+embargo" if "timestamp" in test.columns else "RANDOM (no timestamps)",
                    "embargo": embargo if "timestamp" in test.columns else None, "iocs_loaded": len(matcher) if matcher else 0},
        "sampling": {"benign_row_fraction": round(float(benign_row_fraction), 4), "note": sampling_note,
                     "rf_max_train_rows": rf_max_rows,
                     "rf_train_rows_used": int(min(len(train), rf_max_rows)) if rf_max_rows else int(len(train))},
        "leakage": leak, "calibration": pipe.calibration_info,
        "performance": {"if_fit_seconds": round(fit_s, 3), "score_seconds": round(score_s, 3),
                        "throughput_flows_per_sec": int(len(test) / max(score_s, 1e-9))},
        "models": {}}

    # prior-weight hybrids for comparison (ablation of calibration vs. threshold tuning)
    prior = RiskScorer("heuristic")
    sig_te, sig_va = pipe.signals(test), pipe.signals(val)
    h_te = prior.score(sig_te.anomaly_pct, sig_te.ioc_confidence, sig_te.n_rules)
    h_va = prior.score(sig_va.anomaly_pct, sig_va.ioc_confidence, sig_va.n_rules)
    thr_h = select_alert_threshold(h_va[keep_val], val["label"].to_numpy()[keep_val], ALERT_MAX_FPR)
    results["calibration"]["prior_weights_val_threshold"] = round(float(thr_h), 4)

    entries = {
        K_RULES: (scored["rule_pred"], scored["n_rules"]),
        K_IOC: (scored["ioc_match"].astype(int), scored["ioc_confidence"]),
        K_IF: (scored["if_pred"], scored["anomaly_raw"]),
        K_H_PRIOR: (h_te >= ALERT_MIN_SCORE, h_te),
        K_H_PRIOR_VAL: (h_te >= thr_h, h_te),
        K_H_CAL: (scored["alert"], scored["risk_score"]),
    }
    unsup = DetectionPipeline(matcher, "unsupervised", seed=seed).fit(train).signals(test)
    entries[K_IF_UNSUP] = (unsup["if_pred"], unsup["anomaly_raw"])
    rf = _fit_rf(train, seed, rf_max_rows)
    Xte = build_features(test)
    entries[K_RF] = (rf.predict(Xte), rf.predict_proba(Xte)[:, 1])

    for name, (pred, sc) in entries.items():
        pred, sc = np.asarray(pred).astype(int)[k], np.asarray(sc, float)[k]
        met = compute_metrics(y, pred, sc)
        if benign_row_fraction < 1.0:   # benign windows were subsampled: undo the prevalence inflation
            met["precision_at_original_prevalence"] = round(
                met["tp"] / max(met["tp"] + met["fp"] / benign_row_fraction, 1e-12), 4)
        results["models"][name] = {**met, "recall_by_attack": recall_by_attack(te_k, pred)}
    results["unseen_attack_generalization"] = unseen_attack_generalization(train, test, scored, k, seed, rf_max_rows)
    scored["eval_included"] = k
    return results, scored, pipe


def to_markdown(results: dict) -> str:
    rows = ["| Model | Precision | Recall | F1 | FPR | ROC-AUC |", "|---|---|---|---|---|---|"]
    for name, m in results["models"].items():
        rows.append(f"| {name} | {m['precision']:.3f} | {m['recall']:.3f} | {m['f1']:.3f} | "
                    f"{m['false_positive_rate']:.4f} | {m.get('roc_auc', float('nan')):.3f} |")
    return "\n".join(rows)


def _json_default(o):
    if isinstance(o, (np.integer,)): return int(o)
    if isinstance(o, (np.floating,)): return float(o)
    if isinstance(o, (np.bool_,)): return bool(o)
    return str(o)


def save_results(results: dict, out_dir) -> None:
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "results.json").write_text(json.dumps(results, indent=2, default=_json_default))
    (out_dir / "results.md").write_text(to_markdown(results))
