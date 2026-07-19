"""
test_cache_verify_require.py — `brix_cache_verify require` must have TEETH: the
read-through cache must refuse to publish (and serve) fill bytes it could not
verify against the origin's advertised digest, and must never serve an in-path
corrupted fill as a good complete hit.

WHAT: xrdcp ─► brix-cache (nginx, brix_cache_verify {off|best-effort|require})
             ─► [ fault ] ─► xrootd origin (with/without an advertised digest)

WHY:  Before this fix `brix_cache_verify` was a dead knob on the root/stream
      plane — the directive was never registered there, and even the value the
      HTTP plane wrote fed a retired engine, so `require` verified NOTHING: a
      cache told to serve only origin-verified bytes would happily publish
      unverifiable or corrupted fills. That is the exact failure mode for a
      deployment into a hostile network: a flaky NIC / in-path box mutates bytes
      past the TCP checksum, and the cache blesses the corruption as a permanent
      good hit for every later client.

      The contract this suite pins:
        1 SUCCESS   — an origin that advertises adler32 + verify=require fills,
                      the staged bytes are checked against that digest, and the
                      object is served BYTE-EXACT.
        2 TEETH     — an origin that advertises NO digest + verify=require FAILS
                      CLOSED (nothing to verify against ⇒ refuse to serve), while
                      the SAME origin under verify=best-effort still serves. The
                      contrast isolates require's new teeth from mere plumbing.
        3 NEG       — an origin that advertises adler32 + verify=require, with the
                      fill link CORRUPTED in flight, NEVER serves the corrupt
                      bytes as a good complete hit, and recovers to byte-exact
                      once the link is healed.

Skips cleanly when the official `xrootd` server, this repo's xrdcp, the repo
nginx (built with the verify wiring), or the fault proxy is absent.

Run:
  TEST_NGINX_BIN=/path/to/objs/nginx \\
    PYTHONPATH=tests python3 -m pytest tests/test_cache_verify_require.py -v
"""
import contextlib
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
    e.update(XRD_REQUESTTIMEOUT="20", XRD_STREAMTIMEOUT="10",
             XRD_CONNECTIONWINDOW="6", XRD_CONNECTIONRETRY="1",
             XRD_TIMEOUTRESOLUTION="1")
    return e


def _xrdcp(url, out, timeout=60):
    """Copy through this repo's client.  A hang is a delivery FAILURE, not a test
    error — return a sentinel rc.  Fresh cold read every time."""
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


def _bad_hit_served(rc, out, ref):
    """The poisoning we are hunting: client reports SUCCESS (rc 0) yet the bytes
    on disk are NOT the whole file — an unverifiable/corrupt fill the cache
    published as a good complete hit."""
    return rc == 0 and os.path.exists(out) and _md5(out) != ref


def _verify_line(mode):
    """A full `brix_cache_verify <mode>;` directive line for the template's
    {CACHE_VERIFY} slot — or "" for the compiled default (off)."""
    return "" if mode is None else f"        brix_cache_verify {mode};\n"


@contextlib.contextmanager
def _cache(lifecycle, tmp_path, backend_url, verify, name):
    """A brix-cache node in front of `backend_url` with the given verify mode and
    a FRESH cache store, so every read starts cold."""
    cache_dir = tmp_path / f"cache_{name}"
    export_dir = tmp_path / f"export_{name}"
    cache_dir.mkdir()
    export_dir.mkdir()
    inst = lifecycle.start(NginxInstanceSpec(
        name=f"brix-verify-{name}",
        template="nginx_lc_cache_verify.conf",
        protocol="root",
        data_root=str(cache_dir),
        template_values={
            "BIND_HOST": HOST,
            "CACHE_EXPORT": f"        brix_export {export_dir};\n",
            "CACHE_BACKEND": backend_url,
            "CACHE_STORE": str(cache_dir),
            "CACHE_VERIFY": _verify_line(verify),
        }))
    yield f"root://{HOST}:{inst.port}//big.bin"


# --- 1 SUCCESS ----------------------------------------------------------------

def test_require_with_origin_digest_delivers_byte_exact(lifecycle, tmp_path):
    """SUCCESS: an origin advertising adler32 + verify=require fills, the staged
    bytes verify against the origin digest, and the object is served byte-exact
    (cold fill + warm hit).  Proves require is not merely fail-everything."""
    if _SKIP:
        pytest.skip(_SKIP)
    with XrootdAnon(chksum="adler32") as origin:
        ref = _md5(seed_file(origin.data, "/big.bin", FILE_BYTES))
        with _cache(lifecycle, tmp_path,
                    f"root://{HOST}:{origin.port}", "require", "ok") as url:
            out = str(tmp_path / "ok.bin")
            rc, err = _xrdcp(url, out)
            assert _delivered(rc, out, ref), (
                f"verify=require rejected a digest-matching fill (rc={rc}): "
                f"{err[-300:]}")
            rc, err = _xrdcp(url, out)
            assert _delivered(rc, out, ref), (
                f"warm hit after a verified fill failed (rc={rc}): {err[-300:]}")


# --- 2 TEETH ------------------------------------------------------------------

def test_require_without_origin_digest_fails_closed(lifecycle, tmp_path):
    """TEETH (the core bug): an origin advertising NO digest under verify=require
    must FAIL CLOSED — the cache has nothing to verify the staged bytes against,
    so it must refuse to publish/serve them.  The SAME origin under
    verify=best-effort must still serve — isolating require's teeth from plumbing
    that would break every fill regardless of mode."""
    if _SKIP:
        pytest.skip(_SKIP)
    # best-effort leg: no digest, but best-effort commits what it cannot check.
    with XrootdAnon() as origin:            # no chksum ⇒ no advertised digest
        ref = _md5(seed_file(origin.data, "/big.bin", FILE_BYTES))
        with _cache(lifecycle, tmp_path,
                    f"root://{HOST}:{origin.port}", "best-effort", "be") as url:
            out = str(tmp_path / "be.bin")
            rc, err = _xrdcp(url, out)
            assert _delivered(rc, out, ref), (
                f"verify=best-effort must still serve an unverifiable fill "
                f"(rc={rc}): {err[-300:]} — if this fails the verify plumbing "
                f"breaks fills unconditionally, not just under require")

    # require leg: no digest ⇒ must refuse.  A correct cache serves NO bytes as a
    # good complete hit; the client read must NOT succeed with the whole file.
    with XrootdAnon() as origin:
        ref = _md5(seed_file(origin.data, "/big.bin", FILE_BYTES))
        with _cache(lifecycle, tmp_path,
                    f"root://{HOST}:{origin.port}", "require", "req") as url:
            out = str(tmp_path / "req.bin")
            rc, err = _xrdcp(url, out)
            assert not _delivered(rc, out, ref), (
                "verify=require served an origin fill with NO advertised digest "
                "as a good complete hit — the require knob has no teeth "
                f"(rc={rc}): {err[-300:]}")
            assert not _bad_hit_served(rc, out, ref), (
                f"verify=require served unverifiable bytes as success (rc={rc})")


# --- 3 NEG --------------------------------------------------------------------

def test_require_never_serves_corrupted_fill(lifecycle, tmp_path):
    """SECURITY-NEG: origin advertises adler32 + verify=require, and the fill link
    is CORRUPTED in flight (real bit-flips past the TCP checksum).  The cache must
    NEVER serve the corrupt bytes as a good complete hit — either the digest check
    quarantines the fill or the mangled framing aborts it — and once the link is
    healed a fresh read recovers to byte-exact."""
    if _SKIP:
        pytest.skip(_SKIP)
    with XrootdAnon(chksum="adler32") as origin:
        ref = _md5(seed_file(origin.data, "/big.bin", FILE_BYTES))
        with FaultProxy(origin.port) as proxy:
            proxy.clear()
            with _cache(lifecycle, tmp_path,
                        f"root://{HOST}:{proxy.listen}", "require", "neg") as url:
                # Flip bits in ~2% of the origin→cache payload — enough to derail
                # the adler32 (and likely the framing) on an 8 MiB fill.
                proxy.set_corrupt(2.0, "down")
                out = str(tmp_path / "corrupt.bin")
                rc, err = _xrdcp(url, out)
                assert not _bad_hit_served(rc, out, ref), (
                    f"CACHE POISONED: a corrupted fill was served as a good "
                    f"complete hit under verify=require (rc={rc}): {err[-300:]}")

                # Heal and re-read cold: a correct cache holds no complete object
                # for the key, re-fetches clean, and delivers byte-exact.
                proxy.clear()
                healed = str(tmp_path / "healed.bin")
                rc, err = _xrdcp(url, healed)
                assert _delivered(rc, healed, ref), (
                    f"after a corrupted fill + healed link, verify=require did "
                    f"not recover to byte-exact (rc={rc}): {err[-300:]}")
