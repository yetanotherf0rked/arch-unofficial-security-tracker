"""HTTP with retries (stdlib only)."""

from __future__ import annotations

import time
import urllib.error
import urllib.request

HTTP_TIMEOUT = 120
HTTP_RETRIES = 3


def http_get(url: str) -> bytes:
    """GET with retry on transient failures."""
    last: Exception | None = None
    for attempt in range(HTTP_RETRIES):
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "arch-sec-tracker"})
            with urllib.request.urlopen(req, timeout=HTTP_TIMEOUT) as r:
                return r.read()
        except (urllib.error.URLError, TimeoutError) as e:
            last = e
            time.sleep(2 ** attempt)
    raise RuntimeError(f"GET failed after {HTTP_RETRIES} tries: {url}: {last}")
