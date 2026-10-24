from __future__ import annotations

import os
from pathlib import Path
from typing import Any

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

USER_AGENT = "pkgscan/0.1 (supply-chain malware scanner)"


class DownloadTooLarge(Exception):
    pass


class Http:
    """Thin requests wrapper: retries, timeouts, size-capped downloads."""

    def __init__(self, timeout: int = 20):
        self.timeout = timeout
        s = requests.Session()
        retry = Retry(total=3, backoff_factor=0.5, status_forcelist=(429, 500, 502, 503, 504),
                      allowed_methods=("GET", "HEAD"))
        adapter = HTTPAdapter(max_retries=retry, pool_maxsize=32)
        s.mount("https://", adapter)
        s.mount("http://", adapter)
        s.headers["User-Agent"] = USER_AGENT
        self.session = s
        self.github_token = os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN")
        self.vt_key = os.environ.get("VT_API_KEY")

    def get(self, url: str, **kw) -> requests.Response:
        kw.setdefault("timeout", self.timeout)
        return self.session.get(url, **kw)

    def get_json(self, url: str, headers: dict | None = None) -> tuple[int, Any]:
        try:
            r = self.get(url, headers=headers)
        except requests.RequestException:
            return 0, None
        if r.status_code != 200:
            return r.status_code, None
        try:
            return 200, r.json()
        except ValueError:
            return r.status_code, None

    def download(self, url: str, dest: Path, max_bytes: int) -> int:
        total = 0
        with self.get(url, stream=True, timeout=max(self.timeout, 60)) as r:
            r.raise_for_status()
            with open(dest, "wb") as fh:
                for chunk in r.iter_content(chunk_size=1 << 16):
                    total += len(chunk)
                    if total > max_bytes:
                        raise DownloadTooLarge(f"{url} exceeds {max_bytes} bytes")
                    fh.write(chunk)
        return total
