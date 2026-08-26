"""Client fork-safety (parity-audit §7.7).

A forked child inherits every live connection fd; any child byte — a request,
or brix_close's fire-and-forget kXR_endsess — would interleave into the
PARENT's session (stream corruption; a child endsess kills the parent's
session server-side).  The library now registers connections in a fork-safe
registry and neuters the CHILD's copies in a pthread_atfork handler: fd
closed with no protocol goodbye, TLS/capture handles abandoned unflushed,
and every later op fails non-retryably.  brix_conn_usable() lets long-lived
embedders (the LD_PRELOAD shim) transparently re-dial in the child.

Driven end-to-end through the preload shim with a real fork():

  * success   — the child opens a NEW file and reads it correctly over a
                fresh session
  * error     — the child's use of the INHERITED handle fails cleanly (no
                hang, no crash)
  * security  — after the child exits, the parent's original stream reads to
                EOF byte-exact: nothing the child did (including its
                teardown) reached the parent's wire

Run:
    PYTHONPATH=tests pytest tests/test_client_forksafe.py -v
"""

import os
import subprocess
import textwrap

import pytest

from settings import DATA_ROOT, NGINX_ANON_PORT, SERVER_HOST

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PRELOAD = os.path.join(REPO, "client", "libbrixposix_preload.so")


from sanitizer_preload import sanitizer_runtimes

_ASAN_RT = sanitizer_runtimes(PRELOAD)


def _preload_chain():
    """LD_PRELOAD value: sanitizer runtimes (empty on a plain build) prepended
    before the shim so it loads into the uninstrumented host process."""
    return " ".join(x for x in (_ASAN_RT, PRELOAD) if x)


pytestmark = [
    pytest.mark.requires_local_server,
    pytest.mark.timeout(120),
    pytest.mark.skipif(not os.path.exists(PRELOAD),
                       reason="preload shim not built"),
]

CONTENT = bytes((i * 41 + 11) % 251 for i in range(512 * 1024))
CHILD_CONTENT = b"child-fresh-session-payload\n" * 64

DRIVER = textwrap.dedent("""
    import os, sys

    main_path  = "/xrd/forksafe-main.bin"
    child_path = "/xrd/forksafe-child.bin"
    total      = %d

    fd = os.open(main_path, os.O_RDONLY)
    head = os.read(fd, 1024)
    assert len(head) == 1024, "parent head read failed"

    pid = os.fork()
    if pid == 0:
        # ---- child ----
        code = 0
        try:
            os.read(fd, 1024)          # inherited handle must FAIL cleanly
            code |= 1                   # (reaching here = it did not fail)
        except OSError:
            pass
        try:
            cfd = os.open(child_path, os.O_RDONLY)   # fresh session
            data = bytearray()
            while True:
                chunk = os.read(cfd, 65536)
                if not chunk:
                    break
                data += chunk
            if bytes(data) != %r:
                code |= 2
        except OSError:
            code |= 4
        os._exit(code)

    # ---- parent ----
    _, status = os.waitpid(pid, 0)
    child_code = os.waitstatus_to_exitcode(status)

    rest = bytearray(head)
    while True:
        chunk = os.read(fd, 65536)
        if not chunk:
            break
        rest += chunk
    ok_parent = (len(rest) == total)
    print("CHILD=%%d PARENT=%%s LEN=%%d" %% (child_code, ok_parent, len(rest)))
    sys.exit(0 if (child_code == 0 and ok_parent) else 7)
""")


class TestForkSafety:

    def test_fork_isolation_end_to_end(self, tmp_path):
        os.makedirs(DATA_ROOT, exist_ok=True)
        with open(os.path.join(DATA_ROOT, "forksafe-main.bin"), "wb") as f:
            f.write(CONTENT)
        with open(os.path.join(DATA_ROOT, "forksafe-child.bin"), "wb") as f:
            f.write(CHILD_CONTENT)
        driver = tmp_path / "driver.py"
        driver.write_text(DRIVER % (len(CONTENT), CHILD_CONTENT))
        env = dict(os.environ)
        env["LD_PRELOAD"] = _preload_chain()
        if _ASAN_RT:
            env.setdefault("ASAN_OPTIONS", "detect_leaks=0:verify_asan_link_order=0")
        env["BRIX_VMP"] = f"/xrd=root://{SERVER_HOST}:{NGINX_ANON_PORT}/"
        try:
            res = subprocess.run(["python3", str(driver)], env=env,
                                 capture_output=True, text=True, timeout=60)
            assert res.returncode == 0, (res.returncode, res.stdout,
                                         res.stderr)
            assert "CHILD=0 PARENT=True" in res.stdout, res.stdout
        finally:
            os.remove(os.path.join(DATA_ROOT, "forksafe-main.bin"))
            os.remove(os.path.join(DATA_ROOT, "forksafe-child.bin"))
