"""
test_metrics_coverage_webdav.py — Prometheus coverage for WebDAV file lifecycle.

The existing test_webdav_metrics.py covers GET/PUT/bytes; this suite focuses on
the FILE LIFECYCLE methods (create dir / create file / modify / rename / copy /
delete) and asserts each increments xrootd_webdav_requests_total{method} and
xrootd_webdav_responses_total{method,status_class}, plus the data-transfer byte
counters.  Methods map to the exporter's method label table
(OPTIONS/HEAD/GET/PUT/DELETE/MKCOL/COPY/PROPFIND/OTHER — MOVE falls under OTHER).

Run: PYTHONPATH=tests pytest tests/test_metrics_coverage_webdav.py -v
"""

import os
import subprocess

import pytest

from settings import NGINX_HTTP_WEBDAV_PORT, HOST, TOKENS_DIR
from metrics_helpers import Snapshot, fetch, value, scalar

try:
    from utils.make_token import TokenIssuer
except Exception:                                       # pragma: no cover
    TokenIssuer = None

WEBDAV = f"http://{HOST}:{NGINX_HTTP_WEBDAV_PORT}"
_TOKEN = ""


@pytest.fixture(scope="module", autouse=True)
def _token():
    global _TOKEN
    if TokenIssuer is None:
        pytest.skip("utils.make_token unavailable")
    issuer = TokenIssuer(TOKENS_DIR)
    if not os.path.exists(issuer.key_path):
        issuer.init_keys()
    _TOKEN = issuer.generate(scope="storage.read:/ storage.write:/",
                             lifetime=3600)
    yield


def _curl(*args, timeout=15):
    return subprocess.run(
        ["curl", "-s", "-o", "/dev/null", "-w", "%{http_code}",
         "-H", f"Authorization: Bearer {_TOKEN}", *args],
        capture_output=True, text=True, timeout=timeout,
    )


def _url(path):
    return f"{WEBDAV}/{path.lstrip('/')}"


def _req(snap, method, after=None):
    return snap.delta("xrootd_webdav_requests_total", {"method": method},
                      after=after)


def _resp2xx(snap, method, after=None):
    return snap.delta("xrootd_webdav_responses_total",
                      {"method": method, "status_class": "2xx"}, after=after)


class TestWebdavLifecycleCounters:

    def test_mkcol_create_collection(self):
        _curl("-X", "DELETE", _url("/cov_wd_dir/"))     # best-effort cleanup
        snap = Snapshot()
        r = _curl("-X", "MKCOL", _url("/cov_wd_dir/"))
        assert r.stdout in ("201", "200"), r.stdout
        after = fetch()
        assert _req(snap, "MKCOL", after) >= 1          # CREATE (collection)
        assert _resp2xx(snap, "MKCOL", after) >= 1

    def test_put_create_then_get_download(self):
        local = "/tmp/cov_wd_put.txt"
        with open(local, "wb") as fh:
            fh.write(b"webdav-create-" + b"x" * 4096)
        snap = Snapshot()
        assert _curl("-T", local, _url("/cov_wd_file.txt")).stdout in ("201", "204"), "PUT"
        after = fetch()
        assert _req(snap, "PUT", after) >= 1            # CREATE (file)
        assert _resp2xx(snap, "PUT", after) >= 1
        # GET / download
        snap = Snapshot()
        assert _curl(_url("/cov_wd_file.txt")).stdout == "200"
        after = fetch()
        assert _req(snap, "GET", after) >= 1
        assert _resp2xx(snap, "GET", after) >= 1

    def test_put_overwrite_modify(self):
        local = "/tmp/cov_wd_mod.txt"
        with open(local, "wb") as fh:
            fh.write(b"v1")
        _curl("-T", local, _url("/cov_wd_mod.txt"))
        with open(local, "wb") as fh:
            fh.write(b"v2-modified-content")
        snap = Snapshot()
        assert _curl("-T", local, _url("/cov_wd_mod.txt")).stdout in ("201", "204")
        assert _req(snap, "PUT") >= 1                   # MODIFY (overwrite)

    def test_move_rename(self):
        local = "/tmp/cov_wd_mv.txt"
        with open(local, "wb") as fh:
            fh.write(b"to-be-moved")
        _curl("-T", local, _url("/cov_wd_mv_src.txt"))
        _curl("-X", "DELETE", _url("/cov_wd_mv_dst.txt"))
        snap = Snapshot()
        r = _curl("-X", "MOVE", "-H",
                  f"Destination: {_url('/cov_wd_mv_dst.txt')}",
                  _url("/cov_wd_mv_src.txt"))
        assert r.stdout in ("201", "204"), r.stdout
        # MOVE maps to the OTHER method bucket in the exporter table.
        assert _req(snap, "OTHER") >= 1                 # RENAME

    def test_copy(self):
        local = "/tmp/cov_wd_cp.txt"
        with open(local, "wb") as fh:
            fh.write(b"to-be-copied")
        _curl("-T", local, _url("/cov_wd_cp_src.txt"))
        snap = Snapshot()
        r = _curl("-X", "COPY", "-H",
                  f"Destination: {_url('/cov_wd_cp_dst.txt')}",
                  _url("/cov_wd_cp_src.txt"))
        assert r.stdout in ("201", "204"), r.stdout
        assert _req(snap, "COPY") >= 1

    def test_delete_remove_file(self):
        local = "/tmp/cov_wd_del.txt"
        with open(local, "wb") as fh:
            fh.write(b"delete-me")
        _curl("-T", local, _url("/cov_wd_del.txt"))
        snap = Snapshot()
        assert _curl("-X", "DELETE", _url("/cov_wd_del.txt")).stdout in ("200", "204")
        after = fetch()
        assert _req(snap, "DELETE", after) >= 1         # DELETE
        assert _resp2xx(snap, "DELETE", after) >= 1

    def test_propfind(self):
        snap = Snapshot()
        r = _curl("-X", "PROPFIND", "-H", "Depth: 1", _url("/"))
        assert r.stdout in ("207", "200"), r.stdout
        assert _req(snap, "PROPFIND") >= 1


class TestWebdavByteCounters:

    def test_put_increments_bytes_rx(self):
        local = "/tmp/cov_wd_bytes.bin"
        payload = 256 * 1024
        with open(local, "wb") as fh:
            fh.write(os.urandom(payload))
        before = fetch()
        assert _curl("-T", local, _url("/cov_wd_bytes.bin")).stdout in ("201", "204")
        after = fetch()
        d = scalar(after, "xrootd_webdav_bytes_rx_total") - max(
            0, scalar(before, "xrootd_webdav_bytes_rx_total"))
        assert d >= payload, f"webdav bytes_rx delta {d} < {payload}"

    def test_get_increments_bytes_tx(self):
        local = "/tmp/cov_wd_bytes_tx.bin"
        payload = 256 * 1024
        with open(local, "wb") as fh:
            fh.write(os.urandom(payload))
        _curl("-T", local, _url("/cov_wd_bytes_tx.bin"))
        before = fetch()
        assert _curl(_url("/cov_wd_bytes_tx.bin")).stdout == "200"
        after = fetch()
        d = scalar(after, "xrootd_webdav_bytes_tx_total") - max(
            0, scalar(before, "xrootd_webdav_bytes_tx_total"))
        assert d >= payload, f"webdav bytes_tx delta {d} < {payload}"
