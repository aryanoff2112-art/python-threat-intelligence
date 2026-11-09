"""Rule-based detection baseline. Thresholds are calibrated on benign training data."""
import numpy as np
import pandas as pd

from config.config import RULE_QUANTILE
from detection.feature_engineering import SchemaMismatchError

RULES = {
    "HIGH_PACKET_RATE": "log_flow_packets_s",
    "LARGE_UPLOAD": "log_fwd_bytes",
    "HIGH_RST_RATIO": "rst_ratio",
    "PORT_SCAN": "log_src_unique_dst_ports",
    "HIGH_FLOW_COUNT": "log_src_flow_count",
}


class RuleBasedDetector:
    def __init__(self, quantile: float = RULE_QUANTILE, thresholds: dict | None = None):
        self.quantile = quantile
        self.thresholds: dict[str, float] = dict(thresholds or {})

    def fit(self, X_benign: pd.DataFrame):
        self.thresholds = {r: float(X_benign[c].quantile(self.quantile))
                           for r, c in RULES.items() if c in X_benign.columns}
        return self

    def apply(self, X: pd.DataFrame) -> pd.DataFrame:
        missing = [RULES[r] for r in self.thresholds if RULES[r] not in X.columns]
        if missing:
            raise SchemaMismatchError(f"Rule features missing from input: {missing}")
        return pd.DataFrame({r: X[RULES[r]] > t for r, t in self.thresholds.items()}, index=X.index)

    def predict(self, X: pd.DataFrame) -> np.ndarray:
        return self.apply(X).any(axis=1).to_numpy().astype(int)
