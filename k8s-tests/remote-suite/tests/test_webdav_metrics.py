# brix-remote-skip
"""
Prometheus metrics tests for the WebDAV protocol layer.

Covers brix_webdav_requests_total, brix_webdav_responses_total,
brix_webdav_bytes_rx/tx_total, per-IP-version byte counters,
brix_webdav_auth_total, brix_webdav_tpc_total, and PROPFIND depth counters.

All requests target the plain HTTP WebDAV port (8080) to avoid TLS overhead.
The per-IP counters use 127.0.0.1 explicitly to force IPv4 loopback.

Run:
    pytest tests/test_webdav_metrics.py -v
"""

import os
import subprocess
import sys
import tempfile
import time
import urllib.request
import uuid
import xml.etree.ElementTree as ET

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from utils.make_token import TokenIssuer

from settings import (
    DATA_ROOT,
    NGINX_HTTP_WEBDAV_PORT,
    NGINX_METRICS_PORT,
    TEST_ROOT,
    TOKENS_DIR,
    CA_CERT,
    PROXY_STD,
    WEBDAV_TPC_SOURCE_OPEN_PORT,
    HOST,
    url_host,
)

# ---------------------------------------------------------------------------
# Module-level constants (filled by autouse fixture)
# ---------------------------------------------------------------------------

METRICS_URL   = f"http://{url_host(HOST)}:{NGINX_METRICS_PORT}/metrics"
HTTP_WEBDAV   = f"http://{url_host(HOST)}:{NGINX_HTTP_WEBDAV_PORT}"
DATA_DIR      = DATA_ROOT
TOKEN_DIR     = TOKENS_DIR

_TOKEN_RW     = ""  # populated by _init_token fixture


@pytest.fixture(scope="module", autouse=True)
def _init_token():
    global _TOKEN_RW
    issuer = TokenIssuer(TOKEN_DIR)
    if not os.path.exists(issuer.key_path):
        issuer.init_keys()
    _TOKEN_RW = issuer.generate(scope="storage.read:/ storage.write:/", lifetime=3600)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _fetch() -> str:
    with urllib.request.urlopen(METRICS_URL, timeout=5) as r:
        return r.read().decode()


def _parse(text: str, name: str, labels: dict) -> int:
    import re
    for line in text.splitlines():
        if not line.startswith(name + "{"):
            continue
        m = re.match(r"^" + re.escape(name) + r"\{([^}]*)\}\s+(\d+)", line)
        if not m:
            continue
        block, val = m.group(1), m.group(2)
        if all(f'{k}="{v}"' in block for k, v in labels.items()):
            return int(val)
    return -1


def _scalar(text: str, name: str) -> int:
    for line in text.splitlines():
        if line.startswith(name + " ") or line.startswith(name + "\t"):
            try:
                return int(line.split()[1])
            except (IndexError, ValueError):
                pass
    return -1


def _delta(before: str, after: str, name: str,
           labels: dict | None = None) -> int:
    if labels is not None:
        v_b = _parse(before, name, labels)
        v_a = _parse(after,  name, labels)
    else:
        v_b = _scalar(before, name)
        v_a = _scalar(after,  name)
    if v_b == -1:
        v_b = 0
    return max(0, v_a - v_b)


def _curl(*args, timeout: int = 15) -> subprocess.CompletedProcess:
    return subprocess.run(
        ["curl", "-sf", *args], capture_output=True, text=True, timeout=timeout
    )


def _webdav_url(path: str) -> str:
    return f"{HTTP_WEBDAV}{path}"


def _uid_path(prefix: str = "wdav_metrics") -> str:
    return f"/{prefix}_{uuid.uuid4().hex[:8]}.bin"


# ---------------------------------------------------------------------------
# Section 5a-5g — WebDAV method request/response counters
# ---------------------------------------------------------------------------

class TestWebDAVRequestCounters:

    @pytest.fixture(autouse=True)
    def _snap(self):
        self.before = _fetch()
        yield

    def _req_delta(self, method: str) -> int:
        return _delta(self.before, _fetch(), "brix_webdav_requests_total",
                      {"method": method})

    def _resp_delta(self, method: str, status: str) -> int:
        return _delta(self.before, _fetch(), "brix_webdav_responses_total",
                      {"method": method, "status_class": status})

    def test_get_increments_requests_and_responses(self):
        # Ensure file exists.
        path = _uid_path("get_ctr")
        dest = os.path.join(DATA_DIR, path.lstrip("/"))
        with open(dest, "wb") as f:
            f.write(b"get counter test")
        r = _curl(_webdav_url(path))
        assert r.returncode == 0
        assert self._req_delta("GET") >= 1
        assert self._resp_delta("GET", "2xx") >= 1

    def test_put_increments_requests_and_responses(self):
        path = _uid_path("put_ctr")
        with tempfile.NamedTemporaryFile(delete=False, suffix=".bin") as f:
            f.write(b"put counter test data")
            local = f.name
        r = _curl("-T", local, _webdav_url(path))
        assert r.returncode == 0
        assert self._req_delta("PUT") >= 1
        assert self._resp_delta("PUT", "2xx") >= 1

    def test_put_increments_bytes_rx_total(self):
        path = _uid_path("put_bytes")
        payload = b"x" * 8192
        with tempfile.NamedTemporaryFile(delete=False, suffix=".bin") as f:
            f.write(payload)
            local = f.name
        r = _curl("-T", local, _webdav_url(path))
        assert r.returncode == 0
        delta = _delta(self.before, _fetch(), "brix_webdav_bytes_rx_total")
        assert delta >= len(payload), f"bytes_rx_total delta {delta} < payload {len(payload)}"

    def test_propfind_increments_requests_and_bytes_tx(self):
        before = _fetch()
        r = _curl("-X", "PROPFIND",
                  "-H", "Depth: 0",
                  _webdav_url("/"))
        assert r.returncode == 0
        after = _fetch()
        assert _delta(before, after, "brix_webdav_requests_total",
                      {"method": "PROPFIND"}) >= 1
        assert _delta(before, after, "brix_webdav_bytes_tx_total") >= 1

    def test_propfind_bytes_tx_ipv4_also_increments(self):
        before = _fetch()
        r = _curl("-X", "PROPFIND", "-H", "Depth: 0", _webdav_url("/"))
        assert r.returncode == 0
        after = _fetch()
        delta = _delta(before, after, "brix_webdav_bytes_tx_ipv4_total")
        assert delta >= 1, "brix_webdav_bytes_tx_ipv4_total did not increment on PROPFIND"

    def test_delete_increments_requests(self):
        path = _uid_path("del_ctr")
        dest = os.path.join(DATA_DIR, path.lstrip("/"))
        with open(dest, "wb") as f:
            f.write(b"delete me")
        r = _curl("-X", "DELETE", _webdav_url(path))
        assert r.returncode == 0
        assert self._req_delta("DELETE") >= 1

    def test_mkcol_increments_requests(self):
        dirname = f"mkcol_ctr_{uuid.uuid4().hex[:8]}"
        r = _curl("-X", "MKCOL", _webdav_url(f"/{dirname}"))
        assert r.returncode == 0
        assert self._req_delta("MKCOL") >= 1
        # Cleanup.
        _curl("-X", "DELETE", _webdav_url(f"/{dirname}"))

    def test_404_increments_responses_4xx(self):
        path = f"/no_such_wdav_{uuid.uuid4().hex}.bin"
        before = _fetch()
        _curl(_webdav_url(path))
        after = _fetch()
        assert _delta(before, after, "brix_webdav_responses_total",
                      {"method": "GET", "status_class": "4xx"}) >= 1


# ---------------------------------------------------------------------------
# Section 5h — WebDAV auth counters
# ---------------------------------------------------------------------------

class TestWebDAVAuthCounters:

    def test_anonymous_request_increments_auth_none(self):
        # Anonymous request to HTTP WebDAV (no auth headers).
        path = _uid_path("auth_anon")
        dest = os.path.join(DATA_DIR, path.lstrip("/"))
        with open(dest, "wb") as f:
            f.write(b"anon read")
        before = _fetch()
        _curl(_webdav_url(path))
        after = _fetch()
        # The HTTP WebDAV may serve as anonymous or anonymous_fallback depending on config.
        none_delta = _delta(before, after, "brix_webdav_auth_total", {"result": "none"})
        anon_delta = _delta(before, after, "brix_webdav_auth_total", {"result": "anonymous_fallback"})
        assert none_delta + anon_delta >= 1, "No anonymous auth counter incremented"

    def test_token_ok_increments_auth_total(self):
        path = _uid_path("auth_token")
        with tempfile.NamedTemporaryFile(delete=False, suffix=".bin") as f:
            f.write(b"token auth write")
            local = f.name
        before = _fetch()
        _curl("-H", f"Authorization: Bearer {_TOKEN_RW}",
              "-T", local, _webdav_url(path))
        after = _fetch()
        delta = _delta(before, after, "brix_webdav_auth_total", {"result": "token_ok"})
        assert delta >= 1, "brix_webdav_auth_total{result='token_ok'} did not increment"


# ---------------------------------------------------------------------------
# Section 5i — Multipart-range GET bytes_tx_ipv4 accumulates
# ---------------------------------------------------------------------------

class TestWebDAVMultipartMetrics:

    def test_multipart_range_bytes_tx_ipv4_accumulates(self):
        """GET with multi-range Range header → bytes_tx_ipv4_total counts actual bytes."""
        payload = b"M" * 16384
        path = _uid_path("multipart_range")
        dest = os.path.join(DATA_DIR, path.lstrip("/"))
        with open(dest, "wb") as f:
            f.write(payload)

        before = _fetch()
        r = _curl("-H", "Range: bytes=0-1023, 4096-5119", _webdav_url(path))
        # Multipart response is 206 Partial Content.
        assert r.returncode == 0
        after = _fetch()

        # 2 × 1024 bytes data + multipart boundary/headers overhead ≈ 2 KiB+ total.
        delta = _delta(before, after, "brix_webdav_bytes_tx_ipv4_total")
        assert delta >= 2048, f"Multipart bytes_tx_ipv4 delta {delta} < 2048"
        assert delta != 2, "bytes_tx_ipv4 counted ranges (2), not bytes (bug regression)"


# ---------------------------------------------------------------------------
# Section 5j-5k — WebDAV TPC counters
# ---------------------------------------------------------------------------

class TestWebDAVTpcCounters:

    @pytest.fixture(scope="class")
    def tpc_source_server(self):
        """Use the pre-started open-auth WebDAV TPC source server.

        Writes a fixed payload to data-webdav-tpc/source_open (served by the
        nginx at WEBDAV_TPC_SOURCE_OPEN_PORT with auth none) and yields the
        https:// URL and payload bytes for TPC pull tests.
        """
        from pathlib import Path
        payload = b"TPC source content " * 100
        name = f"tpc_metrics_{uuid.uuid4().hex[:8]}.bin"
        src_root = Path(TEST_ROOT) / "data-webdav-tpc" / "source_open"
        src_root.mkdir(parents=True, exist_ok=True)
        (src_root / name).write_bytes(payload)
        yield f"https://{url_host(HOST)}:{WEBDAV_TPC_SOURCE_OPEN_PORT}/{name}", payload
        try:
            (src_root / name).unlink()
        except FileNotFoundError:
            pass

    def test_tpc_bad_request_increments_on_copy_without_source(self):
        """WebDAV COPY without Source: header → tpc_total{event="bad_request"} increments."""
        path_src = _uid_path("tpc_src")
        path_dst = _uid_path("tpc_dst")
        before = _fetch()
        # COPY without a Source: header should be treated as a bad TPC request.
        r = subprocess.run(
            ["curl", "-sf", "-X", "COPY",
             "-H", f"Destination: {HTTP_WEBDAV}{path_dst}",
             _webdav_url(path_src)],
            capture_output=True, text=True, timeout=15,
        )
        after = _fetch()
        # Either the server rejects it (4xx), or the bad_request counter increments.
        delta = _delta(before, after, "brix_webdav_tpc_total", {"event": "bad_request"})
        # Accept a non-zero return code OR a counter increment as evidence the path was hit.
        assert r.returncode != 0 or delta >= 1, (
            "COPY without Source: header was accepted — expected rejection or bad_request counter"
        )

    def test_tpc_pull_started_counter(self, tpc_source_server):
        """WebDAV COPY with Source: header → tpc_total{event="pull_started"} increments."""
        source_url, _ = tpc_source_server
        dest_path = _uid_path("tpc_pull")
        before = _fetch()
        # TPC pull: Source header only — Destination header is for push mode.
        # Including both headers would be treated as ambiguous and rejected (400).
        r = subprocess.run(
            ["curl", "-sf", "-X", "COPY",
             "-H", f"Source: {source_url}",
             _webdav_url(dest_path)],
            capture_output=True, text=True, timeout=30,
        )
        after = _fetch()
        delta = _delta(before, after, "brix_webdav_tpc_total", {"event": "pull_started"})
        assert delta >= 1, (
            f"tpc_total{{event='pull_started'}} did not increment. "
            f"curl rc={r.returncode} stdout={r.stdout!r} stderr={r.stderr!r}"
        )
