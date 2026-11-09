"""Leakage and duplicate diagnostics for train/validation/test splits.

CIC-IDS flow data contains many exact duplicate feature vectors (e.g. repeated DNS/scan
flows), so a random split lets near-copies of training rows land in the test set and inflates
scores. We (a) measure that, (b) EXCLUDE cross-split duplicates from validation/test metrics
(rows stay in the data so per-source window aggregates are unchanged).
"""
import numpy as np
import pandas as pd

SIG_COLS = ["dst_port", "flow_duration", "fwd_packets", "bwd_packets", "fwd_bytes", "bwd_bytes",
            "flow_bytes_s", "flow_packets_s", "syn_flags", "rst_flags"]


def signature(df: pd.DataFrame) -> pd.Series:
    cols = [c for c in SIG_COLS if c in df.columns]
    return pd.util.hash_pandas_object(df[cols].astype("float64").round(6), index=False)


def keep_masks(train, val, test):
    """Boolean masks (aligned to val/test) that drop rows duplicated in earlier splits."""
    s_tr, s_va, s_te = signature(train), signature(val), signature(test)
    keep_val = ~s_va.isin(set(s_tr)).to_numpy()
    keep_test = ~(s_te.isin(set(s_tr)) | s_te.isin(set(s_va))).to_numpy()
    return keep_val, keep_test


def leakage_report(train, val, test) -> dict:
    s_tr, s_va, s_te = signature(train), signature(val), signature(test)
    tr_set = set(s_tr)
    rep = {"rows": {"train": len(train), "val": len(val), "test": len(test)},
           "duplicates_within_train": int(s_tr.duplicated().sum()),
           "train_val_exact_duplicates": int(s_va.isin(tr_set).sum()),
           "train_test_exact_duplicates": int(s_te.isin(tr_set).sum())}
    rep["train_test_exact_duplicates_fraction"] = round(rep["train_test_exact_duplicates"] / max(len(test), 1), 4)
    if "label" in test.columns:
        dup = s_te.isin(tr_set).to_numpy()
        rep["train_test_duplicates_by_label"] = {
            "benign": int((dup & (test["label"] == 0).to_numpy()).sum()),
            "attack": int((dup & (test["label"] == 1).to_numpy()).sum())}
    if "label" in train.columns:   # identical features, different labels = ambiguous/noisy labels
        g = pd.DataFrame({"sig": s_tr.to_numpy(), "label": train["label"].to_numpy()}).groupby("sig")["label"].nunique()
        rep["conflicting_label_signatures_in_train"] = int((g > 1).sum())
    if "timestamp" in train.columns:
        rep["time_order_ok"] = bool(train["timestamp"].max() < val["timestamp"].min()
                                    and val["timestamp"].max() < test["timestamp"].min())
    if "flow_id" in train.columns:
        rep["flow_id_overlap"] = int(len(set(train["flow_id"]) & set(test["flow_id"])))
    if {"src_ip", "label"} <= set(train.columns):
        a_tr = set(train.loc[train["label"] == 1, "src_ip"]); a_te = set(test.loc[test["label"] == 1, "src_ip"])
        rep["attack_src_ips_shared_train_test"] = len(a_tr & a_te)
        rep["attack_src_ips_in_test"] = len(a_te)
    return rep
