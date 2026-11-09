"""URLhaus (abuse.ch) collector.

abuse.ch asks for a free Auth-Key (set URLHAUS_AUTH_KEY). Parsing is separate from fetching so it
can be unit-tested offline. NOT verified against the live service by the author; run
`python scripts/verify_live_feeds.py` with your own key to check auth, format, rate limits and age.
"""
import csv
import io
import re
from urllib.parse import urlparse

from config.config import MAX_IOC_VALUE_LEN, SOURCE_CONFIDENCE, URLHAUS_AUTH_KEY
from intelligence.http import FeedAuthError, get_with_retries
from intelligence.ioc_matcher import host_of, normalize_domain, normalize_ip

FEED_URL = "https://urlhaus.abuse.ch/downloads/csv_recent/"
FIELDS = ["id", "dateadded", "url", "url_status", "last_online",
          "threat", "tags", "urlhaus_link", "reporter"]
_CTRL = re.compile(r"[\x00-\x1f\x7f\s]")


def _date(value):
    value = (value or "").strip()
    return value or None


def parse_urlhaus_csv(text, source: str = "urlhaus", stats: dict | None = None) -> list[dict]:
    """Turn raw feed text into IOC dicts. Never raises on malformed content: bad rows are counted
    in `stats['rejected']` (by reason) and skipped."""
    stats = stats if stats is not None else {}
    stats.setdefault("rejected", {})
    reject = lambda why: stats["rejected"].__setitem__(why, stats["rejected"].get(why, 0) + 1)
    if not isinstance(text, str):
        reject("not_text"); return []
    conf = SOURCE_CONFIDENCE.get(source, 0.7)
    lines = [l for l in text.splitlines() if l.strip() and not l.startswith("#")]
    iocs, seen = [], set()
    try:
        rows = list(csv.DictReader(io.StringIO("\n".join(lines)), fieldnames=FIELDS))
    except csv.Error:
        reject("csv_error"); return []
    for row in rows:
        url = (row.get("url") or "").strip()
        if not url.startswith(("http://", "https://")):
            reject("not_http_url"); continue
        if len(url) > MAX_IOC_VALUE_LEN or _CTRL.search(url):
            reject("oversized_or_control_chars"); continue
        try:
            urlparse(url).port            # raises ValueError on an invalid port
        except ValueError:
            reject("bad_port"); continue
        host = host_of(url)
        if not host:
            reject("no_host"); continue
        added, last = _date(row.get("dateadded")), _date(row.get("last_online"))
        threat = (row.get("threat") or "malware_download").strip()[:100]
        ip = normalize_ip(host)
        for ioc_type, value in (("url", url), ("ip", ip) if ip else ("domain", normalize_domain(host))):
            if (ioc_type, value) in seen:
                continue
            seen.add((ioc_type, value))
            iocs.append({"ioc_type": ioc_type, "value": value, "source": source, "threat": threat,
                         "confidence": conf, "first_seen": added, "last_seen": last or added})
    stats["accepted"] = len(iocs)
    return iocs


def fetch_urlhaus(stats: dict | None = None) -> list[dict]:
    if not URLHAUS_AUTH_KEY:
        raise FeedAuthError("URLHAUS_AUTH_KEY is not set (see .env.example).")
    resp = get_with_retries(FEED_URL, headers={"Auth-Key": URLHAUS_AUTH_KEY})
    try:
        text = resp.content.decode("utf-8", errors="replace")
    except Exception as e:  # pragma: no cover
        raise ValueError("undecodable feed body") from e
    return parse_urlhaus_csv(text, stats=stats)
