"""Load, validate and clean flow data (synthetic or CIC-IDS2017/2018), and split it safely."""
import csv

import numpy as np
import pandas as pd

from config.config import AGG_WINDOW
from intelligence.ioc_matcher import normalize_ip

# CIC-IDS column names (after whitespace stripping) -> internal schema.
# Use the "GeneratedLabelledFlows" CIC-IDS2017 CSVs if you want IP columns
# (the MachineLearningCVE CSVs omit IPs, so IOC matching is skipped for them).
CIC_COLUMN_MAP = {
    "Flow ID": "flow_id", "Timestamp": "timestamp",
    "Source IP": "src_ip", "Src IP": "src_ip",
    "Destination IP": "dst_ip", "Dst IP": "dst_ip",
    "Destination Port": "dst_port", "Dst Port": "dst_port",
    "Flow Duration": "flow_duration",
    "Total Fwd Packets": "fwd_packets", "Tot Fwd Pkts": "fwd_packets",
    "Total Backward Packets": "bwd_packets", "Tot Bwd Pkts": "bwd_packets",
    "Total Length of Fwd Packets": "fwd_bytes", "TotLen Fwd Pkts": "fwd_bytes",
    "Total Length of Bwd Packets": "bwd_bytes", "TotLen Bwd Pkts": "bwd_bytes",
    "Flow Bytes/s": "flow_bytes_s", "Flow Byts/s": "flow_bytes_s",
    "Flow Packets/s": "flow_packets_s", "Flow Pkts/s": "flow_packets_s",
    "SYN Flag Count": "syn_flags", "SYN Flag Cnt": "syn_flags",
    "RST Flag Count": "rst_flags", "RST Flag Cnt": "rst_flags",
    "Label": "label_raw",
}
INTERNAL = set(CIC_COLUMN_MAP.values()) | {"dst_domain", "label", "attack_type", "label_raw"}
REQUIRED = ["dst_port", "flow_duration", "fwd_packets", "bwd_packets", "fwd_bytes",
            "bwd_bytes", "flow_bytes_s", "flow_packets_s", "syn_flags", "rst_flags"]


class DataFormatError(ValueError):
    """Input file is unreadable, malformed, or lacks required columns."""


def _wanted(col) -> bool:
    c = str(col).strip()
    return c in CIC_COLUMN_MAP or c in INTERNAL


def standardize_columns(df: pd.DataFrame) -> pd.DataFrame:
    df = df.rename(columns=lambda c: str(c).strip())
    df = df.rename(columns=CIC_COLUMN_MAP)
    df = df.loc[:, ~df.columns.duplicated()]      # CIC files contain duplicated columns
    if "label_raw" in df.columns and "label" not in df.columns:
        raw = df["label_raw"].astype(str).str.strip()
        df["attack_type"] = raw.where(raw.str.upper() != "BENIGN", "benign")
        df["label"] = (raw.str.upper() != "BENIGN").astype(int)
    return df


def fix_twelve_hour_clock(ts: pd.Series) -> tuple[pd.Series, int]:
    """CIC-IDS2017 timestamps are reported WITHOUT AM/PM (e.g. '7/7/2017 3:19' meaning 15:19), which
    breaks time ordering. For each calendar date that has morning hours (>=8) and early hours (<8) but
    NO hour >= 13, treat hours < 8 as PM (+12h). Heuristic: detected per day, never assumed, and the
    number of shifted rows is reported. Verify against your own files."""
    day, hour = ts.dt.normalize(), ts.dt.hour
    g = pd.DataFrame({"day": day, "early": hour < 8, "morning": hour >= 8, "pm": hour >= 13}).groupby("day").any()
    days = g.index[g["early"] & g["morning"] & ~g["pm"]]
    shift = day.isin(days) & (hour < 8)
    return ts.where(~shift, ts + pd.Timedelta(hours=12)), int(shift.sum())


def clean(df: pd.DataFrame, fix_timestamps: bool = True) -> pd.DataFrame:
    """Validate and clean. Rows are DROPPED (never silently altered) for: non-numeric/inf/NaN required
    values, negatives, ports outside 0..65535, invalid IP addresses, unparseable timestamps, and exact
    duplicates. Counts per reason are stored in `df.attrs['clean_report']`."""
    missing = [c for c in REQUIRED if c not in df.columns]
    if missing:
        raise DataFormatError(f"Missing required columns after mapping: {missing}")
    rep = {"rows_in": int(len(df))}
    df = df.copy()
    for c in REQUIRED:
        df[c] = pd.to_numeric(df[c], errors="coerce")
    bad = ~np.isfinite(df[REQUIRED].to_numpy(dtype="float64"))
    rep["non_numeric_or_inf_or_nan"] = int(bad.any(axis=1).sum())
    df = df[~bad.any(axis=1)]
    neg = (df[REQUIRED] < 0).any(axis=1) | (df["dst_port"] > 65535)
    rep["negative_or_port_out_of_range"] = int(neg.sum())
    df = df[~neg]
    for col in ("src_ip", "dst_ip"):
        if col in df.columns:
            canon = {u: normalize_ip(u) for u in df[col].dropna().unique()}
            mapped = df[col].map(canon)
            rep[f"invalid_{col}"] = int(mapped.isna().sum())
            df = df.assign(**{col: mapped})[mapped.notna()]
    rep["bad_timestamp"] = rep["twelve_hour_clock_rows_shifted"] = 0
    if "timestamp" in df.columns:
        ts = pd.to_datetime(df["timestamp"], errors="coerce", format="mixed")
        rep["bad_timestamp"] = int(ts.isna().sum())
        df, ts = df[ts.notna()], ts[ts.notna()]
        if fix_timestamps and len(ts):
            ts, rep["twelve_hour_clock_rows_shifted"] = fix_twelve_hour_clock(ts)
        df = df.assign(timestamp=ts)
    keep = [c for c in df.columns if c != "flow_id"]
    before = len(df)
    df = df.drop_duplicates(subset=keep)
    rep["exact_duplicates_dropped"] = int(before - len(df))
    rep["rows_out"] = int(len(df))
    df = df.reset_index(drop=True)
    df.attrs["clean_report"] = rep
    return df


def _scan_field_counts(path, skip_bad_lines: bool) -> list[int]:
    """Pandas silently tolerates rows with extra fields when `usecols` is given, which could misalign
    data without any error. So we verify every physical line has the header's field count first.
    Returns 0-based line numbers to skip (only when skip_bad_lines), else raises DataFormatError."""
    bad = []
    try:
        with open(path, newline="", encoding="latin-1") as f:
            header = f.readline()
            if not header.strip():
                raise DataFormatError(f"{path}: file is empty or has no header")
            n = len(next(csv.reader([header])))
            for i, line in enumerate(f, start=1):
                if not line.strip():
                    continue
                count = (len(next(csv.reader([line]))) if '"' in line else line.count(",") + 1)
                if count != n:
                    if not skip_bad_lines:
                        raise DataFormatError(f"{path}: malformed CSV (line {i + 1} has {count} fields, expected {n})")
                    bad.append(i)
    except FileNotFoundError as e:
        raise DataFormatError(f"File not found: {path}") from e
    except (csv.Error, StopIteration) as e:
        raise DataFormatError(f"{path}: malformed CSV ({type(e).__name__})") from e
    return bad


def _read(path, skip_bad_lines=False) -> pd.DataFrame:
    skip = _scan_field_counts(path, skip_bad_lines)
    try:
        return pd.read_csv(path, usecols=_wanted, low_memory=False, encoding="latin-1", skiprows=skip or None)
    except pd.errors.EmptyDataError as e:
        raise DataFormatError(f"{path}: file is empty or has no header") from e
    except (pd.errors.ParserError, ValueError, UnicodeError) as e:
        raise DataFormatError(f"{path}: malformed CSV ({type(e).__name__}: {str(e)[:150]})") from e


def load_flows_many(paths, fix_timestamps: bool = True, skip_bad_lines: bool = False) -> pd.DataFrame:
    """Load and concatenate CSVs (e.g. one CIC-IDS file per day), reading ONLY the columns the
    pipeline uses (a full CIC file has ~85) to keep memory manageable, then validate/clean once."""
    paths = [paths] if isinstance(paths, (str, bytes)) or hasattr(paths, "__fspath__") else list(paths)
    if not paths:
        raise DataFormatError("No input files given.")
    frames = [standardize_columns(_read(p, skip_bad_lines)) for p in paths]
    df = clean(pd.concat(frames, ignore_index=True), fix_timestamps)
    if len(df) == 0:
        raise DataFormatError("No valid rows remained after cleaning: " + str(df.attrs["clean_report"]))
    return df


def load_flows(path) -> pd.DataFrame:
    return load_flows_many([path])


def subsample_windows(df: pd.DataFrame, benign_frac: float, window: str = AGG_WINDOW, seed: int = 42):
    """Memory-saving subset that PRESERVES the per-source window statistics: keep every time window that
    contains an attack flow, plus a random `benign_frac` of the purely-benign windows. Returns
    (subset, effective_benign_row_fraction). Precision depends on prevalence, so callers should also
    report the prevalence-corrected precision (see evaluation)."""
    if benign_frac >= 1.0:
        return df, 1.0
    if not {"timestamp", "label"} <= set(df.columns):
        raise DataFormatError("Window subsampling needs 'timestamp' and 'label' columns.")
    w = df["timestamp"].dt.floor(window)
    attack_window = df.groupby(w)["label"].transform("max") == 1
    benign_windows = w[~attack_window].unique()
    rng = np.random.default_rng(seed)
    chosen = set(rng.choice(benign_windows, size=int(len(benign_windows) * benign_frac), replace=False)) \
        if len(benign_windows) else set()
    keep = attack_window | w.isin(chosen)
    benign = df["label"] == 0
    frac = float((benign & keep).sum() / max(benign.sum(), 1))
    return df[keep].reset_index(drop=True), frac


def temporal_split(df: pd.DataFrame, train_frac: float = 0.7, seed: int = 42, embargo=None, align=AGG_WINDOW):
    """Time-ordered split (no future leakage). The cut is aligned DOWN to a window boundary so no
    per-source window straddles train/test, and `embargo` drops flows in the gap before the cut so a
    campaign cannot straddle it. Falls back to a random split (higher leakage risk) without timestamps."""
    if "timestamp" in df.columns:
        df = df.sort_values("timestamp", kind="stable").reset_index(drop=True)
        cut = df["timestamp"].iloc[min(int(len(df) * train_frac), len(df) - 1)]
        if align:
            cut = cut.floor(align)
        gap = pd.Timedelta(embargo) if embargo else pd.Timedelta(0)
        return (df[df["timestamp"] < cut - gap].reset_index(drop=True),
                df[df["timestamp"] >= cut].reset_index(drop=True))
    shuffled = df.sample(frac=1.0, random_state=seed).reset_index(drop=True)
    cut = int(len(shuffled) * train_frac)
    return shuffled.iloc[:cut].reset_index(drop=True), shuffled.iloc[cut:].reset_index(drop=True)


def split_three_way(df: pd.DataFrame, embargo=None, seed: int = 42):
    """60% train / 20% validation / 20% test, time-ordered, window-aligned, with embargo gaps."""
    trainval, test = temporal_split(df, 0.8, seed, embargo)
    train, val = temporal_split(trainval, 0.75, seed, embargo)
    return train, val, test
