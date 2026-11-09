"""Isolation Forest detector with a benign-calibrated decision threshold."""
import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest

from config.config import RANDOM_STATE, TARGET_FPR
from detection.feature_engineering import check_feature_schema


class IsolationForestDetector:
    def __init__(self, n_estimators=200, target_fpr=TARGET_FPR, random_state=RANDOM_STATE):
        self.n_estimators, self.random_state = n_estimators, random_state
        self.model = IsolationForest(n_estimators=n_estimators, random_state=random_state, n_jobs=-1)
        self.target_fpr = target_fpr
        self.columns: list[str] = []
        self.ref_scores = np.array([])
        self.threshold = 0.0

    @classmethod
    def from_parts(cls, model, columns, ref_scores, threshold, target_fpr, random_state):
        d = cls(getattr(model, "n_estimators", 200), target_fpr, random_state)
        d.model, d.columns = model, list(columns)
        d.ref_scores, d.threshold = np.asarray(ref_scores, float), float(threshold)
        return d

    def fit(self, X: pd.DataFrame):
        """Fit on X. Train on benign-only data (semi-supervised) or mixed data (unsupervised)."""
        self.columns = list(X.columns)
        self.model.fit(X)
        scores = self.raw_score(X)
        self.ref_scores = np.sort(scores)
        self.threshold = float(np.quantile(scores, 1 - self.target_fpr))
        return self

    def raw_score(self, X: pd.DataFrame) -> np.ndarray:
        """Higher = more anomalous (negated sklearn score_samples). Schema must match exactly."""
        check_feature_schema(self.columns, X)
        return -self.model.score_samples(X[self.columns])

    def percentile(self, raw: np.ndarray) -> np.ndarray:
        """Where a score falls in the training-score distribution (ECDF, 0..1)."""
        return np.searchsorted(self.ref_scores, raw, side="right") / len(self.ref_scores)

    def predict(self, X: pd.DataFrame) -> np.ndarray:
        return (self.raw_score(X) >= self.threshold).astype(int)

    def save(self, path):  # low-level; prefer detection.bundle.save_bundle for full pipelines
        joblib.dump(self, path)

    @staticmethod
    def load(path):
        return joblib.load(path)
