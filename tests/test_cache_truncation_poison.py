"""
test_cache_truncation_poison.py — a brix-cache tier must NEVER commit a
mid-stream-truncated origin fill as a COMPLETE, freshness-valid object and then
serve that permanently-short copy to every subsequent client as a good hit.

WHAT: xrdcp ─► brix-cache (nginx) ─► [ fault ] ─► xrootd origin

      The fault is the proxy's `truncate-at` lever on the ORIGIN link (down
      direction, origin→cache): the origin connection is severed after N bytes
      have flowed, exactly as an uncooperative in-path device / half-dead NIC
      would cut a transfer mid-stream while the TCP teardown still looks clean.

WHY:  a read-through cache decouples clients from a flaky origin — but only if
      it never caches a LIE.  The origin here advertises a real size (the xroot
      backend stats the object on open), so an EOF short of that size is not a
      whole file: it is a truncated transfer.  Committing those N bytes as a
      whole-file COMPLETE entry would poison the cache — every later client gets
      a short file blessed as a valid, complete hit, forever, with no way to tell
      it is wrong.  The fill spine must fail closed on a short EOF exactly like a
      mid-fill read error: abort the staged fill, never mark it COMPLETE.

      The observable contract, and the one thing that must NEVER happen:
        after a truncated cold fill, a subsequent CLEAN read must return the file
        BYTE-EXACT (the cache re-fetched from the now-healthy origin) — it must
        never hand back the short poisoned copy as a successful complete hit.

Skips cleanly when the official `xrootd` server, this repo's xrdcp, the repo
nginx (built with the truncation fix), or the fault proxy is absent.

Run:
  TEST_NGINX_BIN=/path/to/objs/nginx \\
    PYTHONPATH=tests python3 -m pytest tests/test_cache_truncation_poison.py -v
"""
import hashlib
import os
import shutil
import subprocess
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "resilience"))
from resilience.servers import XrootdAnon, FaultProxy, seed_file, FAULT_PROXY, XRDCP  # noqa: E402
from server_registry import NginxInstanceSpec  # noqa: E402

XROOTD = shutil.which("xrootd")

HOST = "127.0.0.1"
FILE_MB = 8
FILE_BYTES = FILE_MB * 1024 * 1024

pytestmark = [pytest.mark.serial, pytest.mark.uses_lifecycle_harness,
              pytest.mark.timeout(300)]

_SKIP = None
if not XROOTD:
    _SKIP = "need the official `xrootd` server on PATH"
elif not os.path.isfile(XRDCP):
    _SKIP = f"need this repo's xrdcp at {XRDCP}"
elif not os.path.isfile(FAULT_PROXY):
    _SKIP = "need the built brix-fault-proxy"


def _md5(path):
    h = hashlib.md5()
    with open(path, "rb") as f:
        for b in iter(lambda: f.read(1 << 20), b""):
            h.update(b)
    return h.hexdigest()


def _env():
    e = dict(os.environ)
    e.pop("LD_LIBRARY_PATH", None)   # keep the stock XRootD libs clean
    # Bound every wait so a severed / black-holed origin surfaces as a
    # deterministic client-side failure inside the test window rather than an
    # unbounded hang.
    e.update(XRD_REQUESTTIMEOUT="20", XRD_STREAMTIMEOUT="10",
             XRD_CONNECTIONWINDOW="6", XRD_CONNECTIONRETRY="1",
             XRD_TIMEOUTRESOLUTION="1")
    return e


def _xrdcp(url, out, timeout=60):
    """Copy through this repo's client.  A client-side hang is a delivery
    FAILURE, not a test error — return a sentinel rc so callers assert uniformly.
    A fresh cold read every time: remove any stale output first."""
    if os.path.exists(out):
        os.remove(out)
    try:
        r = subprocess.run([XRDCP, "-f", url, out],
                           env=_env(), capture_output=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        return 124, "client hung — did not deliver within the window"
    return r.returncode, r.stderr.decode(errors="replace")


def _delivered(rc, out, ref):
    return rc == 0 and os.path.exists(out) and _md5(out) == ref


def _short_file_blessed(rc, out, ref):
    """The poisoning we are hunting: the client reports SUCCESS (rc 0) yet the
    bytes on disk are not the whole file — a truncated copy the cache committed
    as COMPLETE and served as a good hit."""
    return rc == 0 and os.path.exists(out) and _md5(out) != ref


class _Link:
    def __init__(self, proxy, ref, cache_url):
        self.P = proxy
        self.ref = ref
        self.cache_url = cache_url


@pytest.fixture
def link(lifecycle, tmp_path):
    """xrootd origin ─► fault proxy ─► brix-cache (nginx).  A FRESH cache store
    per test so every read starts cold (no warm hit hiding a poisoned fill), and
    the proxy is handed back reset."""
    if _SKIP:
        pytest.skip(_SKIP)

    with XrootdAnon() as origin:
        ref = _md5(seed_file(origin.data, "/big.bin", FILE_BYTES))
        with FaultProxy(origin.port) as proxy:
            cache_dir = tmp_path / "cache"
            export_dir = tmp_path / "export"
            cache_dir.mkdir()
            export_dir.mkdir()
            cache = lifecycle.start(NginxInstanceSpec(
                name="brix-trunc-cache",
                template="nginx_lc_cache_partial_cache.conf",
                protocol="root",
                data_root=str(cache_dir),
                template_values={
                    "BIND_HOST": HOST,
                    "CACHE_ALLOW_WRITE": "",
                    "CACHE_EXPORT": f"        brix_export {export_dir};\n",
                    "CACHE_BACKEND": f"root://{HOST}:{proxy.listen}",
                    "CACHE_STORE": str(cache_dir),
                    "CACHE_SLICE_SIZE": "", "CACHE_MAX_OBJECT": "",
                    "CACHE_DENY_PREFIX": "", "CACHE_INCLUDE_REGEX": "",
                }))
            cache_url = f"root://{HOST}:{cache.port}//big.bin"
            proxy.clear()
            yield _Link(proxy, ref, cache_url)
            proxy.clear()


# --- baseline -----------------------------------------------------------------

def test_clean_fill_delivers_byte_exact(link, tmp_path):
    """SUCCESS: with the origin link healthy, a cold read fills through the cache
    and delivers byte-exact, and a second read (now a warm hit) is byte-exact
    too.  Without this the 'poison' assertions below could be an artifact of a
    broken topology rather than the fault."""
    out = str(tmp_path / "clean.bin")
    rc, err = _xrdcp(link.cache_url, out)
    assert _delivered(rc, out, link.ref), f"cold fill failed (rc={rc}): {err[-300:]}"
    rc, err = _xrdcp(link.cache_url, out)
    assert _delivered(rc, out, link.ref), f"warm hit failed (rc={rc}): {err[-300:]}"


# --- the contract: a truncated fill must not become a COMPLETE hit ------------
# NOTE: over the root protocol a mid-PDU FIN surfaces to the fill pump as a read
# ERROR (not a clean EOF), so the pre-existing r<0 abort already refuses to
# commit — this suite is the regression guard for that guarantee.  The sibling
# clean-short-EOF path (a size-lying origin: stat says N, read delivers <N and
# signals EOF) is closed by the fill spine's snap.size reconciliation.

def test_truncated_fill_never_poisons_cache(link, tmp_path):
    """ERROR + the core contract: cut the origin fill at 2 MiB of an 8 MiB file.
    The cold read must NOT deliver a short file as success.  Then, with the link
    healed, a fresh read MUST return the file byte-exact — proving the cache did
    NOT commit the truncated bytes as a COMPLETE entry and serve them as a hit."""
    # Sever the origin download after 2 MiB — well past the root handshake, far
    # short of the 8 MiB payload: a deterministic mid-stream cut.
    link.P.set_truncate(2 * 1024 * 1024, "down")
    out = str(tmp_path / "trunc.bin")
    rc, err = _xrdcp(link.cache_url, out)
    assert not _short_file_blessed(rc, out, link.ref), (
        f"CACHE POISONED: a truncated fill was served as a COMPLETE copy "
        f"(rc={rc}) — a permanently-short file blessed as a good hit. "
        f"stderr: {err[-300:]}")

    # Heal the link and read again from a fresh (cold) client.  A correct cache
    # holds NO complete object for the key, so it re-fetches and delivers the
    # whole file.  A poisoned cache would serve its resident short copy instead.
    link.P.clear()
    healed = str(tmp_path / "healed.bin")
    rc, err = _xrdcp(link.cache_url, healed)
    assert _delivered(rc, healed, link.ref), (
        f"after a truncated fill + healed origin the cache did not deliver the "
        f"whole file byte-exact (rc={rc}) — it poisoned itself with the short "
        f"copy. stderr: {err[-300:]}")


# --- security-neg: no cut point ever yields a blessed short file --------------

@pytest.mark.parametrize("cut_mib", [1, 3, 6])
def test_no_cut_point_ever_blesses_short_file(link, tmp_path, cut_mib):
    """SECURITY-NEG: across a range of truncation offsets, the cache NEVER
    reports a successful complete read while holding fewer than the advertised
    bytes, and always recovers to byte-exact once the origin is healthy.  A
    truncated fill is a fail-closed abort at every cut point — never a silent,
    short-but-'complete' object."""
    link.P.set_truncate(cut_mib * 1024 * 1024, "down")
    out = str(tmp_path / f"cut_{cut_mib}.bin")
    rc, err = _xrdcp(link.cache_url, out)
    assert not _short_file_blessed(rc, out, link.ref), (
        f"SILENT POISON at cut={cut_mib} MiB (rc={rc}): a short file reported as "
        f"a good complete copy. stderr: {err[-300:]}")

    link.P.clear()
    healed = str(tmp_path / f"healed_{cut_mib}.bin")
    rc, err = _xrdcp(link.cache_url, healed)
    assert _delivered(rc, healed, link.ref), (
        f"cut={cut_mib} MiB: cache did not recover to byte-exact after heal "
        f"(rc={rc}): {err[-300:]}")
