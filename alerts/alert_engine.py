"""Turn scored flows into analyst-readable alerts."""
import hashlib
import uuid

import pandas as pd

from config.config import ALERT_MIN_SCORE


def _explain(r) -> str:
    parts = []
    if r["ioc_match"]:
        parts.append(f"Matched {r['ioc_source']} indicator '{r['ioc_indicator']}' ({r['ioc_threat']})")
    if r["anomaly_pct"] >= 0.95:
        parts.append(f"Flow more unusual than {r['anomaly_pct'] * 100:.1f}% of baseline traffic")
    if r["rules_triggered"]:
        parts.append("Rules: " + r["rules_triggered"].replace(",", ", "))
    return "; ".join(parts) or "Low-confidence signal"


FP_FIELDS = ("event_time", "src_ip", "dst_ip", "dst_port", "dst_domain", "flow_duration",
             "fwd_packets", "bwd_packets", "fwd_bytes", "bwd_bytes")


def fingerprint(row) -> str:
    """Stable identity of the underlying flow (independent of run id), so re-running detect on the
    same traffic, or duplicate flows within it, cannot create duplicate alerts."""
    raw = "|".join("" if row.get(k) is None or (isinstance(row.get(k), float) and row.get(k) != row.get(k))
                   else str(row.get(k)) for k in FP_FIELDS)
    return hashlib.sha256(raw.encode()).hexdigest()


def build_alerts(scored: pd.DataFrame, min_score: float = ALERT_MIN_SCORE, run_id: str | None = None) -> pd.DataFrame:
    """Filter scored flows at/above min_score and format them for storage and display."""
    run_id = run_id or uuid.uuid4().hex[:8]
    a = scored[scored["risk_score"] >= min_score].copy()
    if a.empty:
        return a.assign(run_id=run_id, explanation="")
    a["run_id"] = run_id
    a["event_time"] = a["timestamp"].astype(str) if "timestamp" in a.columns else None
    a["explanation"] = a.apply(_explain, axis=1)
    a["fingerprint"] = a.apply(fingerprint, axis=1)
    a["ioc_match"] = a["ioc_match"].astype(int)
    a["ground_truth_label"] = a["label"] if "label" in a.columns else None
    if "attack_type" not in a.columns:
        a["attack_type"] = None
    return a.sort_values("risk_score", ascending=False).reset_index(drop=True)
