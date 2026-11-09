"""AlienVault OTX collector (subscribed pulses). Requires OTX_API_KEY.

NOT verified against the live service by the author; field names follow the public API docs but are
read defensively (every access tolerates missing/wrong types). Use scripts/verify_live_feeds.py.
"""
from urllib.parse import urlparse

from config.config import MAX_IOC_VALUE_LEN, OTX_API_KEY, SOURCE_CONFIDENCE
from intelligence.http import FeedAuthError, FeedError, get_with_retries
from intelligence.ioc_matcher import normalize_domain, normalize_ip

API = "https://otx.alienvault.com/api/v1/pulses/subscribed"
ALLOWED_HOST = "otx.alienvault.com"
TYPE_MAP = {"IPv4": "ip", "IPv6": "ip", "domain": "domain", "hostname": "domain", "URL": "url"}


def parse_pulses(pulses, source: str = "otx", stats: dict | None = None) -> list[dict]:
    """Never raises on malformed input; rejects are counted in stats['rejected']."""
    stats = stats if stats is not None else {}
    stats.setdefault("rejected", {})
    reject = lambda why: stats["rejected"].__setitem__(why, stats["rejected"].get(why, 0) + 1)
    if not isinstance(pulses, list):
        reject("pulses_not_a_list"); return []
    conf = SOURCE_CONFIDENCE.get(source, 0.7)
    out, seen = [], set()
    for pulse in pulses:
        if not isinstance(pulse, dict):
            reject("pulse_not_object"); continue
        inds = pulse.get("indicators")
        if not isinstance(inds, list):
            reject("indicators_not_a_list"); continue
        threat = str(pulse.get("name") or "otx_pulse")[:100]
        for ind in inds:
            if not isinstance(ind, dict):
                reject("indicator_not_object"); continue
            kind = TYPE_MAP.get(ind.get("type"))
            value = ind.get("indicator")
            if not kind or not isinstance(value, str) or not value.strip():
                reject("unsupported_or_empty"); continue
            value = value.strip()
            if len(value) > MAX_IOC_VALUE_LEN:
                reject("oversized"); continue
            if ind.get("is_active") in (0, False, "0"):
                reject("inactive"); continue
            if kind == "ip":
                value = normalize_ip(value)
                if value is None:
                    reject("invalid_ip"); continue
            elif kind == "domain":
                value = normalize_domain(value)
            if (kind, value) in seen:
                continue
            seen.add((kind, value))
            created = ind.get("created") or pulse.get("created")
            out.append({"ioc_type": kind, "value": value, "source": source, "threat": threat,
                        "confidence": conf, "first_seen": created,
                        "last_seen": ind.get("modified") or pulse.get("modified") or created,
                        "expires_at": ind.get("expiration") or None})
    stats["accepted"] = len(out)
    return out


def _safe_next(url) -> str | None:
    """Only follow pagination to the same HTTPS host, so the API key cannot be sent elsewhere."""
    if not url:
        return None
    p = urlparse(str(url))
    if p.scheme != "https" or p.hostname != ALLOWED_HOST:
        raise FeedError("pagination link points outside the OTX API host; refusing to follow")
    return str(url)


def fetch_otx(max_pages: int = 3, stats: dict | None = None) -> list[dict]:
    if not OTX_API_KEY:
        raise FeedAuthError("OTX_API_KEY is not set (see .env.example).")
    headers, pulses = {"X-OTX-API-KEY": OTX_API_KEY}, []
    url, params = API, {"limit": 50}
    for _ in range(max_pages):
        resp = get_with_retries(url, headers=headers, params=params)
        try:
            data = resp.json()
        except ValueError as e:
            raise FeedError("OTX returned a non-JSON response") from e
        if not isinstance(data, dict):
            raise FeedError("OTX returned an unexpected JSON structure")
        results = data.get("results")
        if isinstance(results, list):
            pulses.extend(results)
        url, params = _safe_next(data.get("next")), None
        if not url:
            break
    return parse_pulses(pulses, stats=stats)
