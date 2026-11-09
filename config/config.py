"""Central configuration. Secrets come from environment variables only."""
import os
from pathlib import Path

try:  # optional: load a local .env file if python-dotenv is installed
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:  # pragma: no cover
    pass

ROOT = Path(__file__).resolve().parent.parent
DATA_RAW = ROOT / "data" / "raw"
DATA_PROCESSED = ROOT / "data" / "processed"
DATA_SAMPLES = ROOT / "data" / "samples"
MODELS_DIR = ROOT / "models"

DB_PATH = Path(os.getenv("TI_DB_PATH", ROOT / "data" / "threatintel.db"))

# --- Threat-intel credentials (never hard-code; see .env.example) ---
OTX_API_KEY = os.getenv("OTX_API_KEY", "")
URLHAUS_AUTH_KEY = os.getenv("URLHAUS_AUTH_KEY", "")
ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY", "")  # reserved for future use

# --- Reproducibility ---
RANDOM_STATE = 42

# --- Detection ---
TARGET_FPR = 0.01          # Isolation Forest threshold = 99th pct of benign training scores
RULE_QUANTILE = 0.995      # rule thresholds calibrated on benign training data
AGG_WINDOW = "5min"        # window for per-source behavioural aggregates

# --- Risk scoring ---
# DEFAULT: weights are LEARNED on a held-out validation split (logistic regression over the
# three evidence channels, see detection/anomaly_scoring.py::RiskScorer). risk = 100 * P(malicious).
#
# The heuristic weights below are an UNCALIBRATED PRIOR. They are kept unchanged on purpose:
#   * used only as a fallback when no labelled validation data exists, and as an ablation baseline
#   * they intentionally sum to >1: each channel is meant to be sufficient to raise an alert on
#     its own (a high-confidence IOC hit alone -> ~44, a maximal anomaly alone -> 50), and the
#     result is clipped to 100 when channels agree. Saturation at 100 is therefore by design.
#   risk = 100 * clip(w_a*A + w_i*I + w_r*R, 0, 1)
#     A = anomaly strength in [0,1] (distance above the benign ECDF floor)
#     I = best IOC confidence in [0,1];  R = min(1, rules_triggered / 3)
RISK_WEIGHTS = {"anomaly": 0.50, "ioc": 0.55, "rules": 0.20}
ANOMALY_FLOOR = 0.95       # benign-ECDF percentile below which anomaly contributes 0
ALERT_MIN_SCORE = 40.0     # heuristic-mode alert threshold only
ALERT_MAX_FPR = 0.01       # calibrated mode: alert threshold = lowest score keeping validation FPR <= this
MIN_IOC_HITS_FOR_CALIBRATION = 5   # fewer IOC hits in validation -> IOC channel cannot be learned
SEVERITY_BANDS = [(80, "critical"), (60, "high"), (40, "medium"), (20, "low"), (0, "info")]

# --- Evaluation protocol ---
EMBARGO = "10min"          # gap dropped between train/val/test so adjacent flows cannot leak

# --- Indicator freshness ---
# Indicators older than this (by last_seen, else first_seen) are ignored at match time. Defaults are
# ASSUMPTIONS, not measured: URLhaus lists short-lived malware-distribution URLs; OTX pulses age slowly.
# Undated indicators cannot be aged and are counted separately.
IOC_MAX_AGE_DAYS = {"urlhaus": 30, "otx": 365}

# --- Feed collection safety ---
HTTP_TIMEOUT = 30
HTTP_MAX_RETRIES = 3
FEED_MAX_BYTES = 200_000_000
MAX_IOC_VALUE_LEN = 2048

# --- Source confidence defaults ---
SOURCE_CONFIDENCE = {"urlhaus": 0.9, "otx": 0.7, "sample_feed": 0.8}
