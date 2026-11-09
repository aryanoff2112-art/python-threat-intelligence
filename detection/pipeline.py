"""End-to-end pipeline.

  fit(train)        learn Isolation Forest + rule thresholds (needs labels only for benign-only mode)
  calibrate(val)    learn risk weights + alert threshold on a held-out labelled validation split
  score(df)         analyse ANY traffic, labelled or not (this is what `detect` uses)
"""
import numpy as np
import pandas as pd

from config.config import (AGG_WINDOW, ALERT_MAX_FPR, ALERT_MIN_SCORE, MIN_IOC_HITS_FOR_CALIBRATION,
                           RANDOM_STATE, SEVERITY_BANDS, TARGET_FPR)
from detection.anomaly_scoring import RiskScorer, select_alert_threshold, severity_from_score
from detection.feature_engineering import SchemaMismatchError, aggregate_mode, build_features
from detection.isolation_forest import IsolationForestDetector
from detection.rules import RuleBasedDetector


class DetectionPipeline:
    def __init__(self, matcher=None, mode="semi", target_fpr=TARGET_FPR, seed=RANDOM_STATE, window=AGG_WINDOW):
        """mode='semi': train IF on benign flows only. mode='unsupervised': train on everything."""
        assert mode in ("semi", "unsupervised")
        self.matcher, self.mode, self.seed, self.window = matcher, mode, seed, window
        self.detector = IsolationForestDetector(target_fpr=target_fpr, random_state=seed)
        self.rules = RuleBasedDetector()
        self.scorer = RiskScorer("heuristic")
        self.alert_threshold = ALERT_MIN_SCORE
        self.bands = list(SEVERITY_BANDS)
        self.input_schema: dict = {}
        self.train_info: dict = {}
        self.calibration_info: dict = {"method": "heuristic", "notes": ["not calibrated"]}

    # ---------------------------------------------------------------- training
    def fit(self, train_df: pd.DataFrame):
        train_df = train_df.reset_index(drop=True)
        X = build_features(train_df, self.window)
        has_label = "label" in train_df.columns
        if self.mode == "semi":
            if not has_label:
                raise ValueError("mode='semi' needs a 'label' column; use mode='unsupervised' otherwise.")
            keep = (train_df["label"] == 0).to_numpy()
        else:
            keep = np.ones(len(X), bool)
        self.detector.fit(X[keep])
        self.rules.fit(X[keep])
        self.input_schema = {"aggregate_mode": aggregate_mode(train_df), "window": self.window,
                             "feature_columns": list(X.columns)}
        self.train_info = {
            "rows": int(len(train_df)), "rows_used_for_fit": int(keep.sum()), "mode": self.mode,
            "attack_rows_in_train": int(train_df["label"].sum()) if has_label else None,
            "time_min": str(train_df["timestamp"].min()) if "timestamp" in train_df else None,
            "time_max": str(train_df["timestamp"].max()) if "timestamp" in train_df else None}
        return self

    # ------------------------------------------------------------------ scoring
    def _check_input(self, df: pd.DataFrame):
        have, want = aggregate_mode(df), self.input_schema["aggregate_mode"]
        if have != want:
            raise SchemaMismatchError(
                f"Model was trained with aggregate mode '{want}' but input gives '{have}'. "
                "Per-source aggregates need the same columns (src_ip, and timestamp if used in training).")

    def _features(self, df, context):
        """Features for `df`. Optional `context` = earlier flows from the same stream: used ONLY to
        complete the per-source window aggregates of df's first window (not scored, not returned)."""
        if context is not None and len(context) and self.input_schema["aggregate_mode"] != "none":
            self._check_input(context)
            start = pd.to_datetime(df["timestamp"]).min().floor(self.window)
            ctx = context[pd.to_datetime(context["timestamp"]) >= start]
            if len(ctx):
                combined = pd.concat([ctx, df], ignore_index=True)
                return build_features(combined, self.window).iloc[len(ctx):].reset_index(drop=True)
        return build_features(df, self.window)

    def signals(self, df: pd.DataFrame, context: pd.DataFrame | None = None) -> pd.DataFrame:
        """Anomaly, rule and IOC evidence for each flow. Never touches labels."""
        if len(df) == 0:
            raise ValueError("No flows to score (empty batch).")
        self._check_input(df)
        df = df.reset_index(drop=True)
        X = self._features(df, context)
        raw = self.detector.raw_score(X)
        hits = self.rules.apply(X)
        names = np.array(hits.columns)
        out = df.copy()
        out["anomaly_raw"] = raw
        out["anomaly_pct"] = self.detector.percentile(raw)
        out["if_pred"] = (raw >= self.detector.threshold).astype(int)
        out["rules_triggered"] = [",".join(names[m]) for m in hits.to_numpy()]
        out["n_rules"] = hits.sum(axis=1).to_numpy()
        out["rule_pred"] = (out["n_rules"] > 0).astype(int)
        out["edge_window"] = False
        if self.input_schema["aggregate_mode"] != "none" and len(df):
            win = pd.to_datetime(df["timestamp"]).dt.floor(self.window)
            edge = win == win.max()                      # batch may end mid-window
            if context is None or not len(context):
                edge |= win == win.min()                 # ...and may start mid-window
            out["edge_window"] = edge.to_numpy()
        if self.matcher is not None:
            out = out.join(self.matcher.match_flows(df))
        else:
            out["ioc_confidence"], out["ioc_match"] = 0.0, False
            out["ioc_source"] = out["ioc_threat"] = out["ioc_indicator"] = None
        return out

    def score(self, df: pd.DataFrame, context: pd.DataFrame | None = None) -> pd.DataFrame:
        out = self.signals(df, context)
        out["risk_score"] = self.scorer.score(out["anomaly_pct"], out["ioc_confidence"], out["n_rules"])
        out["severity"] = out["risk_score"].map(lambda s: severity_from_score(s, self.bands))
        out["alert"] = out["risk_score"] >= self.alert_threshold
        return out

    # -------------------------------------------------------------- calibration
    def calibrate(self, val_df: pd.DataFrame, method="calibrated", max_fpr=ALERT_MAX_FPR, mask=None):
        """Fit risk weights and the alert threshold on labelled validation flows (never on test)."""
        val_df = val_df.reset_index(drop=True)
        if "label" not in val_df.columns:
            raise ValueError("Calibration needs a labelled validation split.")
        sig = self.signals(val_df)
        y = val_df["label"].to_numpy()
        m = np.ones(len(y), bool) if mask is None else np.asarray(mask, bool)
        A, I, R = sig["anomaly_pct"].to_numpy(), sig["ioc_confidence"].to_numpy(), sig["n_rules"].to_numpy()
        notes, scorer = [], RiskScorer("heuristic")
        n_ioc = int((I[m] > 0).sum())
        if method == "calibrated":
            if y[m].sum() == 0 or (y[m] == 0).sum() == 0:
                notes.append("validation split lacks both classes: heuristic prior weights kept")
            elif n_ioc >= MIN_IOC_HITS_FOR_CALIBRATION:
                scorer.fit(A[m], I[m], R[m], y[m], use_ioc=True)
            else:
                scorer.fit(A[m], I[m], R[m], y[m], use_ioc=False)
                notes.append(f"only {n_ioc} IOC hits in validation: IOC weight NOT learned; "
                             "heuristic IOC prior added on top (uncalibrated channel)")
        risk = scorer.score(A, I, R)
        if (y[m] == 0).sum() == 0:
            thr = ALERT_MIN_SCORE
            notes.append("no benign validation flows: default alert threshold kept")
        else:
            thr = select_alert_threshold(risk[m], y[m], max_fpr)
        self.scorer, self.alert_threshold = scorer, thr
        alert = risk >= thr
        self.calibration_info = {
            "method": scorer.method, "max_fpr_target": max_fpr, "alert_threshold": thr,
            "val_rows_used": int(m.sum()), "val_attack_rows": int(y[m].sum()), "val_ioc_hits": n_ioc,
            "val_fpr_at_threshold": round(float(alert[m & (y == 0)].mean()), 5),
            "val_recall_at_threshold": (round(float(alert[m & (y == 1)].mean()), 4) if y[m].sum() else None),
            "notes": notes}
        return self

    # -------------------------------------------------------------- persistence
    def save(self, path, evaluation=None):
        from detection.bundle import save_bundle
        return save_bundle(self, path, evaluation=evaluation)

    @classmethod
    def load(cls, path, matcher=None, strict_versions=False):
        from detection.bundle import load_bundle
        return load_bundle(path, matcher=matcher, strict_versions=strict_versions)
