"""Behavioural feature extraction from flow records."""
import numpy as np
import pandas as pd

from config.config import AGG_WINDOW

FEATURE_SET_VERSION = "1"   # bump when feature definitions change; stored in model bundles
BASE = ["flow_duration", "fwd_packets", "bwd_packets", "fwd_bytes", "bwd_bytes",
        "flow_bytes_s", "flow_packets_s", "syn_flags", "rst_flags"]
AGGREGATES = ["src_flow_count", "src_unique_dst_ports", "src_unique_dst_ips"]


class SchemaMismatchError(ValueError):
    """Input data or engineered features do not match what the model was trained on."""


def aggregate_mode(df: pd.DataFrame) -> str:
    """Per-source aggregates are computed over fixed wall-clock tumbling windows (epoch-aligned), which
    makes them independent of batch size. Without BOTH src_ip and timestamp, a window cannot be defined
    (a whole-batch aggregate would change with batch size), so aggregates are disabled entirely."""
    return "src_ip+window" if {"src_ip", "timestamp"} <= set(df.columns) else "none"


def check_feature_schema(expected: list[str], X: pd.DataFrame) -> None:
    missing = [c for c in expected if c not in X.columns]
    extra = [c for c in X.columns if c not in expected]
    if missing or extra:
        raise SchemaMismatchError(
            f"Feature mismatch. Missing: {missing or 'none'}; unexpected: {extra or 'none'}.")


def add_window_aggregates(df: pd.DataFrame, window: str = AGG_WINDOW) -> pd.DataFrame:
    """Per-source behaviour in a time window: flow count and destination fan-out.

    These capture scans/brute-force/DoS that single-flow features miss. Skipped
    when the dataset has no source IP (e.g. CIC MachineLearningCVE CSVs).
    """
    if aggregate_mode(df) == "none":
        return df
    keys = [df["src_ip"], pd.to_datetime(df["timestamp"]).dt.floor(window).rename("_win")]
    g = df.groupby(keys, sort=False)
    out = df.copy()
    out["src_flow_count"] = g["dst_port"].transform("size")
    out["src_unique_dst_ports"] = g["dst_port"].transform("nunique")
    out["src_unique_dst_ips"] = (g["dst_ip"].transform("nunique")
                                 if "dst_ip" in df.columns else 1)
    return out


def build_features(df: pd.DataFrame, window: str = AGG_WINDOW) -> pd.DataFrame:
    d = add_window_aggregates(df.reset_index(drop=True), window)
    pk = (d["fwd_packets"] + d["bwd_packets"]).clip(lower=1)
    X = pd.DataFrame(index=d.index)
    for c in BASE:
        X[f"log_{c}"] = np.log1p(d[c].clip(lower=0))
    X["log_bytes_per_packet"] = np.log1p((d["fwd_bytes"] + d["bwd_bytes"]) / pk)
    X["log_fwd_bwd_ratio"] = np.log1p(d["fwd_bytes"] / (d["bwd_bytes"] + 1))
    X["rst_ratio"] = d["rst_flags"] / pk
    X["dst_port"] = d["dst_port"]
    X["dst_port_high"] = (d["dst_port"] >= 1024).astype(int)
    for c in AGGREGATES:
        if c in d.columns:
            X[f"log_{c}"] = np.log1p(d[c])
    return X.replace([np.inf, -np.inf], 0).fillna(0)
