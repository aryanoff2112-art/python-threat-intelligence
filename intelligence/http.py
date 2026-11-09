"""Defensive HTTP client for threat-intel feeds.

  * explicit timeouts, bounded retries with exponential backoff (+ Retry-After on 429/503)
  * 401/403 -> FeedAuthError (never retried), other 4xx -> FeedError
  * redirects are NOT followed (custom auth headers would be forwarded to the new host)
  * response size is capped
  * secrets are never included in exception messages
"""
import time

import requests

from config.config import FEED_MAX_BYTES, HTTP_MAX_RETRIES, HTTP_TIMEOUT


class FeedError(RuntimeError):
    """Generic feed failure."""


class FeedAuthError(FeedError):
    """Credentials missing, invalid or not authorised."""


class FeedRateLimitError(FeedError):
    """Still rate-limited after all retries."""


def get_with_retries(url, headers=None, params=None, timeout=HTTP_TIMEOUT, max_retries=HTTP_MAX_RETRIES,
                     max_bytes=FEED_MAX_BYTES, sleep=time.sleep):
    last = None
    for attempt in range(max_retries + 1):
        try:
            resp = requests.get(url, headers=headers, params=params, timeout=timeout, allow_redirects=False)
        except (requests.Timeout, requests.ConnectionError) as e:
            last = FeedError(f"network error ({type(e).__name__})")
        else:
            code = resp.status_code
            if code in (401, 403):
                raise FeedAuthError(f"HTTP {code}: credentials rejected or missing")
            if 300 <= code < 400:
                raise FeedError(f"HTTP {code}: unexpected redirect refused")
            if code == 429 or code >= 500:
                last = FeedRateLimitError("rate limited (HTTP 429)") if code == 429 else FeedError(f"HTTP {code}")
                try:
                    wait = min(float(resp.headers.get("Retry-After", "")), 60.0)
                except (TypeError, ValueError):
                    wait = None
                if attempt < max_retries:
                    sleep(wait if wait is not None else min(2 ** attempt, 30))
                    continue
            elif code >= 400:
                raise FeedError(f"HTTP {code}")
            else:
                if len(resp.content) > max_bytes:
                    raise FeedError(f"response larger than {max_bytes} bytes refused")
                return resp
        if attempt < max_retries:
            sleep(min(2 ** attempt, 30))
    raise last or FeedError("request failed")
