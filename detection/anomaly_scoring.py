"""Threat scoring: combine anomaly strength, IOC confidence and rule hits.

Two scorers share one interface (RiskScorer):
  heuristic           fixed prior weights from config.RISK_WEIGHTS (uncalibrated; fallback/ablation)
  calibrated          logistic regression on [anomaly, ioc, rules] fitted on VALIDATION data;
                      risk = 100 * P(malicious). Weights are learned, not hand-set.
  calibrated_partial  used when validation has too few IOC hits to learn the IOC weight: logistic
                      on [anomaly, rules] plus the heuristic IOC prior added on top. The IOC channel
                      is then explicitly UNCALIBRATED and is flagged as such in the bundle.
"""
import numpy as np

from config.config import (ALERT_MIN_SCORE, ANOMALY_FLOOR, RISK_WEIGHTS, SEVERITY_BANDS)


def components(anomaly_pct, ioc_conf, n_rules):
    a = np.clip((np.asarray(anomaly_pct, float) - ANOMALY_FLOOR) / (1 - ANOMALY_FLOOR), 0, 1)
    i = np.clip(np.asarray(ioc_conf, float), 0, 1)
    r = np.clip(np.asarray(n_rules, float) / 3.0, 0, 1)
    return a, i, r


def compute_risk(anomaly_pct, ioc_conf, n_rules, weights=RISK_WEIGHTS) -> np.ndarray:
    """Heuristic risk score in [0, 100]."""
    a, i, r = components(anomaly_pct, ioc_conf, n_rules)
    return 100.0 * np.clip(weights["anomaly"] * a + weights["ioc"] * i + weights["rules"] * r, 0, 1)


def severity_from_score(score: float, bands=SEVERITY_BANDS) -> str:
    for floor, name in bands:
        if score >= floor:
            return name
    return "info"


def is_alert(score, threshold=ALERT_MIN_SCORE) -> np.ndarray:
    return np.asarray(score) >= threshold


def _sigmoid(z):
    return 1.0 / (1.0 + np.exp(-np.clip(z, -50, 50)))


class RiskScorer:
    def __init__(self, method="heuristic", weights=None, coef=None, intercept=0.0,
                 ioc_prior_weight=RISK_WEIGHTS["ioc"]):
        assert method in ("heuristic", "calibrated", "calibrated_partial")
        self.method, self.weights = method, dict(weights or RISK_WEIGHTS)
        self.coef, self.intercept = dict(coef or {}), float(intercept)
        self.ioc_prior_weight = ioc_prior_weight

    def fit(self, anomaly_pct, ioc_conf, n_rules, y, use_ioc=True, C=1.0):
        from sklearn.linear_model import LogisticRegression
        a, i, r = components(anomaly_pct, ioc_conf, n_rules)
        Z = np.column_stack([a, i, r] if use_ioc else [a, r])
        lr = LogisticRegression(C=C, max_iter=1000).fit(Z, np.asarray(y, int))
        c = lr.coef_[0]
        self.coef = ({"anomaly": c[0], "ioc": c[1], "rules": c[2]} if use_ioc
                     else {"anomaly": c[0], "rules": c[1]})
        self.coef = {k: float(v) for k, v in self.coef.items()}
        self.intercept = float(lr.intercept_[0])
        self.method = "calibrated" if use_ioc else "calibrated_partial"
        return self

    def score(self, anomaly_pct, ioc_conf, n_rules) -> np.ndarray:
        if self.method == "heuristic":
            return compute_risk(anomaly_pct, ioc_conf, n_rules, self.weights)
        a, i, r = components(anomaly_pct, ioc_conf, n_rules)
        z = self.intercept + self.coef["anomaly"] * a + self.coef["rules"] * r
        if self.method == "calibrated":
            return 100.0 * _sigmoid(z + self.coef["ioc"] * i)
        return np.clip(100.0 * _sigmoid(z) + 100.0 * self.ioc_prior_weight * i, 0, 100)

    def to_dict(self) -> dict:
        return {"method": self.method, "weights": self.weights, "coef": self.coef,
                "intercept": self.intercept, "ioc_prior_weight": self.ioc_prior_weight}

    @classmethod
    def from_dict(cls, d: dict):
        return cls(d["method"], d.get("weights"), d.get("coef"), d.get("intercept", 0.0),
                   d.get("ioc_prior_weight", RISK_WEIGHTS["ioc"]))


def select_alert_threshold(scores, y, max_fpr: float) -> float:
    """Lowest threshold (alert if score >= t) whose FPR on the given labelled scores is <= max_fpr."""
    scores, y = np.asarray(scores, float), np.asarray(y, int)
    benign = scores[y == 0]
    if len(benign) == 0:
        raise ValueError("Cannot choose an alert threshold without benign validation flows.")
    q = np.quantile(benign, 1 - max_fpr, method="higher")
    return float(np.nextafter(q, np.inf))
