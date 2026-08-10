"""Operator cache-evict command — stock `xrdfs cache {evict|fevict}` (§4.11).

The programmatic evict engine (`brix_sd_cache_evict`) existed with no operator
command reaching it. The stock command travels as kXR_set with payload
"cache evict <path>" (pinned live against stock xrdfs 5.6.9 with
XRD_LOGLEVEL=Dump); the server now recognizes both spellings, gates them like
a delete (allow_write first, then the BRIX_AUTH_DELETE chain on the CONFINED
path), and drops the cached copy + cinfo through the cache decorator. Both
spellings evict; stock's in-use refusal distinguishing evict from fevict is a
documented divergence. The BriX client grew the matching `cache` verb.

Coverage (the change-class trio):
  * success      — a read-filled cache object disappears after
                   `cache evict`; the STOCK 5.6.9 client's own
                   `cache fevict` also lands (drop-in wire proof); the origin
                   file itself is untouched.
  * error        — evicting an uncached path is idempotent-OK (the engine's
                   contract); an export with NO cache tier refuses
                   (kXR_Unsupported → nonzero exit).
  * security-neg — on a read-only export the command is refused
                   (allow_write gate — invariant 3) and the cached object
                   SURVIVES; a ``..`` path operand is refused outright.

Run:
    TEST_SKIP_SERVER_SETUP=1 PYTHONPATH=tests pytest tests/test_cache_evict_cmd.py -v
"""

import os
import shutil
import subprocess

import pytest

from settings import HOST, BIND_HOST, NGINX_BIN
from server_registry import NginxInstanceSpec

pytestmark = [pytest.mark.timeout(120), pytest.mark.uses_lifecycle_harness,
              pytest.mark.xdist_group("lc-cache-evict")]

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CLIENT_DIR = os.path.join(REPO, "client")
XRDFS = os.path.join(CLIENT_DIR, "bin", "xrdfs")
XRDCP = os.path.join(CLIENT_DIR, "bin", "xrdcp")
STOCK_XRDFS = "/usr/bin/xrdfs"

PAYLOAD = b"evict-me " * 4096


@pytest.fixture(scope="module")
def _client_built():
    if shutil.which("cc") is None and shutil.which("gcc") is None:
        pytest.skip("no C compiler")
    subprocess.run(["make", "-C", CLIENT_DIR, "xrdfs", "xrdcp"],
                   capture_output=True, text=True, timeout=240)
    if not (os.path.exists(XRDFS) and os.path.exists(XRDCP)):
        pytest.skip("client build failed")


def _start(lifecycle, tmp_path, allow_write="on", cache_line=None):
    if not os.access(NGINX_BIN, os.X_OK):
        pytest.skip(f"nginx not executable: {NGINX_BIN}")
    data = tmp_path / "data"
    cache = tmp_path / "cache"
    data.mkdir(exist_ok=True)
    cache.mkdir(exist_ok=True)
    (data / "f.bin").write_bytes(PAYLOAD)
    if cache_line is None:
        cache_line = f"brix_cache_store posix:{cache};"
    ep = lifecycle.start(NginxInstanceSpec(
        name="lc-cache-evict",
        template="nginx_lc_cache_evict.conf",
        protocol="root",
        template_values={"BIND_HOST": BIND_HOST, "DATA_DIR": str(data),
                         "CACHE_LINE": cache_line,
                         "ALLOW_WRITE": allow_write},
        reason="operator cache-evict command postures"))
    return ep.port, data, cache


def _cache_objects(cache_dir):
    """Data objects in the cache tree (cinfo sidecars excluded)."""
    hits = []
    for root, _dirs, files in os.walk(cache_dir):
        for name in files:
            if not name.endswith(".cinfo"):
                hits.append(os.path.join(root, name))
    return hits


def _fill_cache(port, tmp_path, cache):
    """Read /f.bin through the cache tier and assert an object landed."""
    out = tmp_path / "out.bin"
    proc = subprocess.run([XRDCP, "-f", f"root://{HOST}:{port}//f.bin",
                           str(out)], capture_output=True, text=True,
                          timeout=60)
    assert proc.returncode == 0, f"cache-filling read failed: {proc.stderr}"
    assert out.read_bytes() == PAYLOAD
    objs = _cache_objects(cache)
    assert objs, "read did not fill the cache tier"
    return objs


def _evict(binary, port, verb, path):
    return subprocess.run([binary, f"root://{HOST}:{port}", "cache", verb,
                           path], capture_output=True, text=True, timeout=30)


def test_evict_drops_cached_object(lifecycle, tmp_path, _client_built):
    """(success) evict removes the cached copy; the origin file survives."""
    port, data, cache = _start(lifecycle, tmp_path)
    _fill_cache(port, tmp_path, cache)

    proc = _evict(XRDFS, port, "evict", "/f.bin")
    assert proc.returncode == 0, f"cache evict failed: {proc.stderr}"
    assert not _cache_objects(cache), "cached object survived evict"
    assert (data / "f.bin").read_bytes() == PAYLOAD, "origin file was touched"


def test_stock_client_fevict_lands(lifecycle, tmp_path, _client_built):
    """(success, drop-in proof) the STOCK 5.6.9 client's own cache fevict is
    accepted and drops the object — same wire, no BriX client needed."""
    if not os.path.exists(STOCK_XRDFS):
        pytest.skip("stock xrdfs not installed")
    port, _data, cache = _start(lifecycle, tmp_path)
    _fill_cache(port, tmp_path, cache)

    proc = _evict(STOCK_XRDFS, port, "fevict", "/f.bin")
    assert proc.returncode == 0, f"stock cache fevict failed: {proc.stderr}"
    assert not _cache_objects(cache), "cached object survived stock fevict"


def test_uncached_ok_but_cacheless_export_refused(lifecycle, tmp_path,
                                                  _client_built):
    """(error) evicting an uncached path is idempotent-OK; a server without a
    cache tier refuses the command."""
    port, _data, _cache = _start(lifecycle, tmp_path)
    proc = _evict(XRDFS, port, "evict", "/never-read.bin")
    assert proc.returncode == 0, \
        f"uncached evict must be idempotent-OK: {proc.stderr}"

    lifecycle.reconfigure("lc-cache-evict", CACHE_LINE="")
    lifecycle.restart("lc-cache-evict")
    proc = _evict(XRDFS, port, "evict", "/f.bin")
    assert proc.returncode != 0, "cacheless export accepted cache evict"
    assert "cache" in proc.stderr.lower(), proc.stderr


def test_readonly_export_refuses_and_object_survives(lifecycle, tmp_path,
                                                     _client_built):
    """(security-neg) allow_write off: the command is refused (invariant 3 —
    the write gate runs before anything else) and the cached object survives;
    a `..` operand is refused too."""
    port, _data, cache = _start(lifecycle, tmp_path)
    _fill_cache(port, tmp_path, cache)

    lifecycle.reconfigure("lc-cache-evict", ALLOW_WRITE="off")
    lifecycle.restart("lc-cache-evict")

    proc = _evict(XRDFS, port, "evict", "/f.bin")
    assert proc.returncode != 0, "read-only export accepted cache evict"
    assert _cache_objects(cache), "cached object lost through a refused evict"

    proc = _evict(XRDFS, port, "evict", "/../outside.bin")
    assert proc.returncode != 0, "dot-dot operand not refused"
