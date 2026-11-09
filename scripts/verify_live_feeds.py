"""Live verification of the URLhaus and OTX integrations. Run this YOURSELF with real keys:

    export URLHAUS_AUTH_KEY=...   OTX_API_KEY=...
    python scripts/verify_live_feeds.py [--out docs/live_feed_verification.json]

It checks authentication, response parsing, rejected-row counts, latency, indicator-type mix and
indicator age (stale-indicator exposure), and reports honestly which checks passed. Rate-limit handling
is exercised by unit tests with mocked 429s; this script only reports what the live service did.
Exit code is non-zero if any enabled feed failed.
"""
import argparse
import json
import sys
import time
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import pandas as pd

from config.config import IOC_MAX_AGE_DAYS, OTX_API_KEY, URLHAUS_AUTH_KEY
from intelligence.http import FeedAuthError, FeedError
from intelligence.ioc_matcher import IOCMatcher
from intelligence.otx_collector import fetch_otx
from intelligence.urlhaus_collector import fetch_urlhaus


def check(name, key, fn):
    rec = {"feed": name, "key_configured": bool(key), "ok": False}
    if not key:
        rec["detail"] = "skipped: no key configured"; rec["skipped"] = True
        return rec
    stats, t0 = {}, time.perf_counter()
    try:
        iocs = fn(stats=stats)
    except FeedAuthError as e:
        rec["detail"] = f"AUTH FAILURE: {e}"; return rec
    except FeedError as e:
        rec["detail"] = f"FEED ERROR: {e}"; return rec
    except Exception as e:  # unexpected parse/runtime failure is itself a finding
        rec["detail"] = f"UNEXPECTED {type(e).__name__}: {e}"; return rec
    df = pd.DataFrame(iocs)
    rec.update(ok=len(df) > 0, seconds=round(time.perf_counter() - t0, 2), accepted=len(df),
               rejected=stats.get("rejected", {}), types=dict(Counter(df["ioc_type"])) if len(df) else {})
    if len(df):
        ages = (pd.Timestamp.now(tz="UTC") - pd.to_datetime(df["last_seen"], utc=True, errors="coerce")).dt.days
        rec["age_days"] = {"min": float(ages.min()), "median": float(ages.median()), "max": float(ages.max()),
                           "undated": int(ages.isna().sum())}
        m = IOCMatcher(df)
        rec["freshness_filter"] = {"max_age_days": IOC_MAX_AGE_DAYS.get(name), **m.stats}
    rec["detail"] = "ok" if rec["ok"] else "parsed zero indicators: inspect the raw response"
    return rec


def main():
    ap = argparse.ArgumentParser(); ap.add_argument("--out", default="docs/live_feed_verification.json")
    out = Path(ap.parse_args().out)
    report = {"run_utc": datetime.now(timezone.utc).isoformat(timespec="seconds"),
              "results": [check("urlhaus", URLHAUS_AUTH_KEY, fetch_urlhaus), check("otx", OTX_API_KEY, fetch_otx)]}
    out.parent.mkdir(parents=True, exist_ok=True); out.write_text(json.dumps(report, indent=2))
    print(json.dumps(report, indent=2))
    failed = [r for r in report["results"] if not r["ok"] and not r.get("skipped")]
    sys.exit(1 if failed else 0)


if __name__ == "__main__":
    main()
