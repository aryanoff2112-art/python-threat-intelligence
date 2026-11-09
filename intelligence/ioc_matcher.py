"""IOC normalisation and matching of network flows against known indicators."""
import ipaddress
from urllib.parse import urlparse

import pandas as pd

from config.config import IOC_MAX_AGE_DAYS


def normalize_ip(value) -> str | None:
    """Canonical IP string, or None if `value` is not a valid IPv4/IPv6 address."""
    try:
        return ipaddress.ip_address(str(value).strip()).compressed
    except ValueError:
        return None


def is_ip(value) -> bool:
    return normalize_ip(value) is not None


def normalize_domain(value: str) -> str:
    return str(value).strip().lower().rstrip(".")


def host_of(url: str) -> str:
    try:
        return normalize_domain(urlparse(url).hostname or "")
    except ValueError:                      # e.g. malformed IPv6 literal in a URL
        return ""


def _ts(value):
    t = pd.to_datetime(value, utc=True, errors="coerce")
    return None if pd.isna(t) else t


class IOCMatcher:
    """In-memory lookup built from the indicators table.

    Expired indicators (expires_at <= as_of) and stale ones (older than the per-source
    max age) are dropped at load time and counted in `self.stats`.
    """

    def __init__(self, indicators: pd.DataFrame | None = None, as_of=None, max_age_days: dict | None = None):
        self.ips, self.domains, self.urls = {}, {}, {}
        self.stats = {"loaded": 0, "expired": 0, "stale": 0, "undated": 0, "invalid": 0}
        as_of = _ts(as_of) if as_of is not None else pd.Timestamp.now(tz="UTC")
        ages = IOC_MAX_AGE_DAYS if max_age_days is None else max_age_days
        if indicators is None or len(indicators) == 0:
            return
        for r in indicators.itertuples(index=False):
            value, kind = str(r.value).strip(), r.ioc_type
            if kind == "ip":
                value = normalize_ip(value)
            elif kind == "domain":
                value = normalize_domain(value)
            if not value or kind not in ("ip", "domain", "url"):
                self.stats["invalid"] += 1
                continue
            exp = _ts(getattr(r, "expires_at", None))
            if exp is not None and exp <= as_of:
                self.stats["expired"] += 1
                continue
            seen = _ts(getattr(r, "last_seen", None)) or _ts(getattr(r, "first_seen", None))
            limit = ages.get(r.source)
            if seen is None:
                self.stats["undated"] += 1
            elif limit is not None and (as_of - seen) > pd.Timedelta(days=limit):
                self.stats["stale"] += 1
                continue
            meta = (r.source, r.threat, float(r.confidence))
            target = {"ip": self.ips, "domain": self.domains, "url": self.urls}[kind]
            if value not in target or meta[2] > target[value][2]:   # keep highest-confidence record
                target[value] = meta
            self.stats["loaded"] += 1

    def __len__(self):
        return len(self.ips) + len(self.domains) + len(self.urls)

    def lookup(self, value):
        """Check any observable (IP, domain or URL). Returns (source, threat, conf) or None."""
        v = str(value).strip()
        if v.startswith(("http://", "https://")):
            host = host_of(v)
            return self.urls.get(v) or self.domains.get(host) or self.ips.get(normalize_ip(host) or "")
        ip = normalize_ip(v)
        if ip is not None:
            return self.ips.get(ip)
        return self.domains.get(normalize_domain(v))

    def match_flows(self, flows: pd.DataFrame) -> pd.DataFrame:
        """Return IOC columns aligned to `flows` (destination first, then source)."""
        n = len(flows)
        cols = {k: [None] * n for k in ("ioc_source", "ioc_threat", "ioc_indicator")}
        conf = [0.0] * n
        fields = [c for c in ("dst_ip", "dst_domain", "src_ip") if c in flows.columns]
        arrays = {c: flows[c].tolist() for c in fields}
        for i in range(n):
            for c in fields:
                val = arrays[c][i]
                if val is None or (isinstance(val, float) and pd.isna(val)):
                    continue
                hit = self.lookup(val)
                if hit:
                    cols["ioc_source"][i], cols["ioc_threat"][i], conf[i] = hit
                    cols["ioc_indicator"][i] = val
                    break
        out = pd.DataFrame(cols, index=flows.index)
        out["ioc_confidence"] = conf
        out["ioc_match"] = out["ioc_confidence"] > 0
        return out


def load_sample_iocs(path) -> list[dict]:
    df = pd.read_csv(path)
    return df.to_dict("records")
