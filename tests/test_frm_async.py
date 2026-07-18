"""
tests/test_frm_async.py

Nearline recall through the live frm://exec MSS surface.

Rewritten 2026-07-18.  The original exercised the kXR_waitresp -> kXR_attn
asynresp async-recall path (brix_frm_async_recall on) with xattr residency on a
posix backend and scraped brix_frm_{waitresp,asynresp}_total from /metrics.  That
async-parking path only runs for a NON-cache export whose VFS residency classifies
NEARLINE; the live nearline-serving model is the frm://exec backend composed with
a brix_cache_store recall target, where the recall runs in the cache-fill path and
the waitresp/asynresp counters are never touched.  So the metrics assertions are
dropped and the test now asserts the behaviour that surface actually guarantees:

  S  a read of a nearline object recalls it (the exec `recall` verb materialises
     it into the online buffer) and serves the true tape bytes through the cache.
  E  a nearline object whose `recall` verb FAILS returns an error to the client,
     not a hang.

Self-contained; skips cleanly without nginx or xrdcp.
"""

import os
import shutil
import subprocess

import pytest

from settings import HOST
from server_registry import NginxInstanceSpec

pytestmark = pytest.mark.uses_lifecycle_harness

XRDCP = shutil.which("xrdcp")
TAPE_BYTES = b"ASYNC-TAPE-CONTENT-" + b"y" * 256 + b"\n"


def _stagecmd(tape, failkey):
    """Exec MSS adapter: $BRIX_FRM_STAGECMD <verb> <key> <online>.

    `recall` of `failkey` exits non-zero (an object that IS on tape but whose
    recall genuinely fails) so the read errors rather than hangs; every other
    key recalls normally.  The tape dir and fail key are baked in because nginx
    rewrites its environ (a spawned command sees only argv + BRIX_FRM_STAGECMD).
    """
    return (
        "#!/bin/bash\n"
        'verb="$1"; key="${2#/}"; online="$3"\n'
        f"tape='{tape}'\n"
        f"failkey='{failkey}'\n"
        'case "$verb" in\n'
        '  exists)  [ -f "$tape/$key" ] && exit 0 || exit 1 ;;\n'
        '  recall)  [ "$key" = "$failkey" ] && exit 1\n'
        '           mkdir -p "$(dirname "$online")"; cp "$tape/$key" "$online" ;;\n'
        '  migrate) cp "$online" "$tape/$key" ;;\n'
        '  purge)   rm -f "$online" ;;\n'
        "esac\n"
    )


@pytest.fixture
def srv(lifecycle, tmp_path):
    if XRDCP is None:
        pytest.skip("xrdcp not available")

    d = tmp_path
    base = d / "base"; base.mkdir()
    tape = d / "tape"; tape.mkdir()
    cache = d / "cache"; cache.mkdir()

    # nearline object recallable from tape
    (tape / "near.dat").write_bytes(TAPE_BYTES)
    # nearline object present on tape but whose recall verb fails
    (tape / "failfile.dat").write_bytes(b"unrecallable\n")

    stagecmd = d / "stage.sh"
    stagecmd.write_text(_stagecmd(str(tape), "failfile.dat"))
    stagecmd.chmod(0o755)

    ep = lifecycle.start(NginxInstanceSpec(
        name="lc-frm-async",
        template="nginx_lc_frm_exec.conf",
        protocol="root",
        readiness="tcp",
        template_values={"STORAGE_BACKEND": f"frm://exec{base}",
                         "CACHE_DIR": str(cache)},
        env={"BRIX_FRM_STAGECMD": str(stagecmd)},
        reason="frm nearline recall (frm://exec)"))

    class S:
        pass
    s = S()
    s.port = ep.port
    s.tape_content = TAPE_BYTES
    yield s


def _xrdcp(port, path, out, timeout=30):
    return subprocess.run(
        [XRDCP, "-f", "-s", f"root://{HOST}:{port}/{path}", out],
        capture_output=True, timeout=timeout)


def test_async_recall_satisfies_open_in_place(srv, tmp_path):
    out = str(tmp_path / "near.out")
    r = _xrdcp(srv.port, "/near.dat", out)
    assert r.returncode == 0, "xrdcp failed: %s" % r.stderr.decode(errors="replace")
    assert open(out, "rb").read() == srv.tape_content, "recalled bytes mismatch"


def test_async_failed_recall_returns_error_not_hang(srv, tmp_path):
    r = _xrdcp(srv.port, "/failfile.dat", str(tmp_path / "f.out"), timeout=30)
    assert r.returncode != 0, "open of an unstageable file should fail, not hang"
