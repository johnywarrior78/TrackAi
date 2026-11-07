"""Restricted public HTTPS client. No endpoint can be supplied by collected text."""

import ipaddress
import random
import socket
import time
from urllib.parse import urlsplit
import httpx

HOSTS = {
    "red.anthropic.com",
    "raw.githubusercontent.com",
    "api.github.com",
    "api.first.org",
    "epss.cyentia.com",
    "codeload.github.com",
}


def validate_url(url, resolve=True):
    parsed = urlsplit(url)
    if (
        parsed.scheme != "https"
        or parsed.hostname not in HOSTS
        or parsed.username
        or parsed.password
        or parsed.port not in (None, 443)
    ):
        raise ValueError("Outbound URL must use an approved public HTTPS host")
    if resolve:
        addresses = socket.getaddrinfo(parsed.hostname, 443, type=socket.SOCK_STREAM)
        if not addresses or any(
            not ipaddress.ip_address(a[4][0]).is_global for a in addresses
        ):
            raise ValueError("Nonpublic destination forbidden")
    return url


class PublicHTTP:
    def __init__(self, settings):
        self.settings = settings
        self.client = httpx.Client(
            timeout=settings.http_timeout,
            follow_redirects=False,
            trust_env=False,
            headers={
                "User-Agent": "AI-Vulnerability-Intelligence/0.1 (public research)"
            },
        )
        self.errors = 0
        self.rate_limits = 0
        self.last = 0.0

    def close(self):
        self.client.close()

    def download(self, url, path, max_bytes):
        """Stream a public archive to disk; retain partial downloads for retries.

        This separate path never raises the small JSON response memory limit.
        Only the fixed CVEProject codeload endpoint is eligible for large files.
        """
        from pathlib import Path
        import os
        import re

        if not re.fullmatch(
            r"https://codeload\.github\.com/CVEProject/cvelistV5/tar\.gz/[0-9a-f]{40}",
            url,
        ):
            raise ValueError(
                "Large archive downloads require a pinned official CVE snapshot"
            )
        validate_url(url)
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        partial = path.with_suffix(path.suffix + ".part")
        for attempt in range(self.settings.http_retries):
            offset = partial.stat().st_size if partial.exists() else 0
            headers = {"Range": f"bytes={offset}-"} if offset else {}
            try:
                with self.client.stream(
                    "GET",
                    url,
                    headers=headers,
                    timeout=httpx.Timeout(
                        self.settings.http_timeout,
                        read=max(180, self.settings.http_timeout),
                    ),
                ) as response:
                    if response.status_code in (429, 500, 502, 503, 504):
                        if response.status_code == 429:
                            self.rate_limits += 1
                        raise httpx.HTTPStatusError(
                            "Archive temporarily unavailable",
                            request=response.request,
                            response=response,
                        )
                    response.raise_for_status()
                    append = response.status_code == 206 and offset > 0
                    if response.status_code == 206 and not response.headers.get(
                        "content-range", ""
                    ).startswith(f"bytes {offset}-"):
                        raise ValueError("Archive resume offset mismatch")
                    size = offset if append else 0
                    with partial.open("ab" if append else "wb") as handle:
                        os.chmod(partial, 0o600)
                        for chunk in response.iter_bytes(chunk_size=1024 * 1024):
                            size += len(chunk)
                            if size > max_bytes:
                                raise ValueError(
                                    "CVE archive exceeds configured download limit"
                                )
                            handle.write(chunk)
                    os.replace(partial, path)
                    return path
            except (
                httpx.NetworkError,
                httpx.TimeoutException,
                httpx.HTTPStatusError,
            ) as exc:
                self.errors += 1
                if isinstance(
                    exc, httpx.HTTPStatusError
                ) and exc.response.status_code not in (429, 500, 502, 503, 504):
                    raise
                if attempt + 1 == self.settings.http_retries:
                    raise
                time.sleep(2**attempt + random.random())
        raise RuntimeError("Archive retry budget exhausted")

    def get(self, url, params=None, binary=False):
        validate_url(url)
        headers = {}
        if urlsplit(url).hostname == "api.github.com":
            headers = {
                "Accept": "application/vnd.github+json",
                "X-GitHub-Api-Version": "2022-11-28",
            }
            if self.settings.github_token:
                headers["Authorization"] = "Bearer " + self.settings.github_token
        for attempt in range(self.settings.http_retries):
            time.sleep(
                max(0, self.settings.request_interval - (time.monotonic() - self.last))
            )
            self.last = time.monotonic()
            try:
                # Streaming bounds both compressed and expanded bytes; redirects fail closed.
                with self.client.stream(
                    "GET", url, params=params, headers=headers
                ) as response:
                    if response.status_code in (403, 429):
                        self.rate_limits += 1
                    if response.status_code in (429, 500, 502, 503, 504) or (
                        response.status_code == 403
                        and response.headers.get("x-ratelimit-remaining") == "0"
                    ):
                        try:
                            wait = min(
                                120,
                                max(
                                    1,
                                    float(
                                        response.headers.get("retry-after", 2**attempt)
                                    ),
                                ),
                            )
                        except ValueError:
                            wait = 2**attempt
                        self.errors += 1
                        if attempt + 1 == self.settings.http_retries:
                            response.raise_for_status()
                        time.sleep(wait + random.random())
                        continue
                    response.raise_for_status()
                    chunks, size = [], 0
                    for chunk in response.iter_bytes():
                        size += len(chunk)
                        if size > 32 * 1024 * 1024:
                            raise ValueError("Public response exceeded 32 MiB limit")
                        chunks.append(chunk)
                    import json

                    return b"".join(chunks) if binary else json.loads(b"".join(chunks))
            except (httpx.TimeoutException, httpx.NetworkError):
                self.errors += 1
                if attempt + 1 == self.settings.http_retries:
                    raise
                time.sleep(2**attempt + random.random())
        raise RuntimeError("Retry budget exhausted")
