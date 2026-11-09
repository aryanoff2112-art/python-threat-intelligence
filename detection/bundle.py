"""Versioned, self-describing model bundles.

Layout (a directory):
    manifest.json          all metadata + every learned number that is not the forest itself
    isolation_forest.joblib the fitted sklearn IsolationForest (the only pickled object)
    reference_scores.npy   sorted benign training scores (anomaly percentile reference), no pickle
The manifest records sha256 of both binary files, library versions, the feature schema and
version, rule thresholds, the anomaly threshold, risk-scorer weights, alert threshold,
calibration details, training summary, and (optionally) the evaluation that produced it.

SECURITY: joblib files are pickles. The checksums detect corruption/accidental edits, NOT a
malicious bundle. Only load bundles you created or trust.
"""
import hashlib
import json
import platform
import warnings
from datetime import datetime, timezone
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
import sklearn

from config.config import ANOMALY_FLOOR, RULE_QUANTILE
from detection.anomaly_scoring import RiskScorer
from detection.feature_engineering import FEATURE_SET_VERSION
from detection.isolation_forest import IsolationForestDetector
from detection.pipeline import DetectionPipeline
from detection.rules import RuleBasedDetector

BUNDLE_FORMAT = "ti-model-bundle"
BUNDLE_VERSION = "1.0.0"          # major bump = incompatible layout
MODEL_FILE, REF_FILE, MANIFEST = "isolation_forest.joblib", "reference_scores.npy", "manifest.json"


class BundleError(RuntimeError):
    """Bundle is missing, corrupted, or incompatible with this code version."""


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def _environment() -> dict:
    return {"python": platform.python_version(), "scikit_learn": sklearn.__version__,
            "numpy": np.__version__, "pandas": pd.__version__, "joblib": joblib.__version__}


def save_bundle(pipe: DetectionPipeline, path, evaluation: dict | None = None) -> Path:
    if not pipe.input_schema:
        raise BundleError("Pipeline has not been fitted.")
    path = Path(path)
    path.mkdir(parents=True, exist_ok=True)
    joblib.dump(pipe.detector.model, path / MODEL_FILE)
    np.save(path / REF_FILE, pipe.detector.ref_scores, allow_pickle=False)
    manifest = {
        "format": BUNDLE_FORMAT, "bundle_version": BUNDLE_VERSION,
        "feature_set_version": FEATURE_SET_VERSION,
        "created_utc": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "environment": _environment(),
        "anomaly_model": {"type": "IsolationForest", "n_estimators": pipe.detector.n_estimators,
                          "random_state": pipe.detector.random_state, "training_mode": pipe.mode,
                          "target_fpr": pipe.detector.target_fpr,
                          "score_threshold": pipe.detector.threshold},
        "input_schema": pipe.input_schema,
        "rules": {"quantile": pipe.rules.quantile, "thresholds": pipe.rules.thresholds},
        "risk": {"scorer": pipe.scorer.to_dict(), "alert_threshold": pipe.alert_threshold,
                 "anomaly_floor": ANOMALY_FLOOR, "severity_bands": pipe.bands,
                 "calibration": pipe.calibration_info},
        "training": pipe.train_info,
        "evaluation": evaluation,
        "files": {MODEL_FILE: _sha256(path / MODEL_FILE), REF_FILE: _sha256(path / REF_FILE)},
    }
    (path / MANIFEST).write_text(json.dumps(manifest, indent=2, default=float))
    return path


def read_manifest(path) -> dict:
    mpath = Path(path) / MANIFEST
    if not mpath.exists():
        raise BundleError(f"No {MANIFEST} in {path}")
    try:
        m = json.loads(mpath.read_text())
    except (ValueError, UnicodeError) as e:
        raise BundleError(f"{MANIFEST} is not valid JSON: {e}") from e
    if not isinstance(m, dict):
        raise BundleError(f"{MANIFEST} must contain a JSON object")
    return m


def _finite(x, name):
    if not isinstance(x, (int, float)) or isinstance(x, bool) or not np.isfinite(x):
        raise BundleError(f"manifest field {name} must be a finite number, got {x!r}")
    return float(x)


def load_bundle(path, matcher=None, strict_versions: bool = False) -> DetectionPipeline:
    """Load and validate a bundle. ANY corruption (missing/garbled manifest or files, wrong types,
    tampered or unpicklable model, non-finite thresholds) raises BundleError, never a raw exception."""
    path = Path(path)
    if not path.is_dir():
        raise BundleError(f"Bundle directory not found: {path}")
    m = read_manifest(path)
    try:
        if m.get("format") != BUNDLE_FORMAT:
            raise BundleError(f"Not a {BUNDLE_FORMAT}: {m.get('format')!r}")
        if str(m["bundle_version"]).split(".")[0] != BUNDLE_VERSION.split(".")[0]:
            raise BundleError(f"Incompatible bundle version {m['bundle_version']} (code supports {BUNDLE_VERSION}).")
        if m["feature_set_version"] != FEATURE_SET_VERSION:
            raise BundleError(f"Feature set v{m['feature_set_version']} != code v{FEATURE_SET_VERSION}; retrain.")
        files = m["files"]
        if not isinstance(files, dict) or set(files) != {MODEL_FILE, REF_FILE}:
            raise BundleError("manifest 'files' must list exactly the model and reference-score files")
        for fname, digest in files.items():
            f = path / fname
            if not f.is_file() or _sha256(f) != digest:
                raise BundleError(f"Integrity check failed for {fname} (missing or modified).")
        trained_with = m["environment"]["scikit_learn"]
        if trained_with != sklearn.__version__:
            msg = (f"Bundle trained with scikit-learn {trained_with}, running {sklearn.__version__}. "
                   "Pickled models may behave differently; re-train for production.")
            if strict_versions:
                raise BundleError(msg)
            warnings.warn(msg, RuntimeWarning)

        am, schema = m["anomaly_model"], m["input_schema"]
        cols = schema["feature_columns"]
        if not isinstance(cols, list) or not cols or not all(isinstance(c, str) for c in cols):
            raise BundleError("input_schema.feature_columns must be a non-empty list of strings")
        if schema["aggregate_mode"] not in ("none", "src_ip+window"):
            raise BundleError(f"unknown aggregate_mode {schema['aggregate_mode']!r}")
        ref = np.load(path / REF_FILE, allow_pickle=False)
        if ref.ndim != 1 or len(ref) == 0 or not np.isfinite(ref).all():
            raise BundleError("reference_scores.npy is empty, non-1-D or contains non-finite values")
        thr = _finite(am["score_threshold"], "anomaly_model.score_threshold")
        alert_thr = _finite(m["risk"]["alert_threshold"], "risk.alert_threshold")
        rule_thr = {str(k): _finite(v, f"rules.thresholds.{k}") for k, v in m["rules"]["thresholds"].items()}
        model = joblib.load(path / MODEL_FILE)
        if not hasattr(model, "score_samples"):
            raise BundleError("model file does not contain an Isolation Forest")

        pipe = DetectionPipeline(matcher=matcher, mode=am["training_mode"], target_fpr=am["target_fpr"],
                                 seed=am["random_state"], window=schema["window"])
        pipe.detector = IsolationForestDetector.from_parts(model, cols, ref, thr, am["target_fpr"], am["random_state"])
        pipe.rules = RuleBasedDetector(m["rules"].get("quantile", RULE_QUANTILE), rule_thr)
        pipe.scorer = RiskScorer.from_dict(m["risk"]["scorer"])
        pipe.alert_threshold = alert_thr
        pipe.bands = [tuple(b) for b in m["risk"]["severity_bands"]]
        pipe.input_schema, pipe.train_info = schema, m.get("training", {})
        pipe.calibration_info = m["risk"].get("calibration", {})
        pipe.manifest = m
        return pipe
    except BundleError:
        raise
    except Exception as e:      # KeyError, TypeError, pickle/unpickling errors, bad shapes...
        raise BundleError(f"Bundle is corrupted or malformed ({type(e).__name__}: {str(e)[:200]})") from e
