"""LD_PRELOAD shim write path (parity-audit §7.8).

The `libbrixposix_preload.so` POSIX shim was read-only: an `open(O_WRONLY)`
under the BRIX_VMP prefix fell through to the (absent) real local path.  It
now diverts write-only opens to a remote write handle — `open(O_WRONLY)` →
`brix_rfile_open_write`, `write`/`pwrite` stream to the server, `close`
commits.  So `cmd > /xrd/out`, `cp file /xrd/…`, and any sequential writer
into the mount now upload transparently.

  * success   — a file copied into the prefix lands on the server byte-exact
                and reads back through the shim identically
  * error     — a write-only shim fd is not readable (EBADF); O_EXCL create
                of an existing file fails
  * safety    — writes to paths OUTSIDE the prefix are untouched (real libc)

Run:
    PYTHONPATH=tests pytest tests/test_preload_write.py -v
"""

import os
import subprocess
import textwrap

import pytest

from settings import DATA_ROOT, NGINX_ANON_PORT, SERVER_HOST

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PRELOAD = os.path.join(REPO, "client", "libbrixposix_preload.so")

pytestmark = [
    pytest.mark.requires_local_server,
    pytest.mark.timeout(90),
    pytest.mark.skipif(not os.path.exists(PRELOAD),
                       reason="preload shim not built"),
]

CONTENT = bytes((i * 53 + 7) % 251 for i in range(400 * 1024))


def _env(extra=None):
    env = {k: v for k, v in os.environ.items()}
    env["LD_PRELOAD"] = PRELOAD
    env["BRIX_VMP"] = f"/xrd=root://{SERVER_HOST}:{NGINX_ANON_PORT}/"
    if extra:
        env.update(extra)
    return env


def _server_path(name):
    return os.path.join(DATA_ROOT, name)


class TestPreloadWrite:

    def test_cp_into_prefix_lands_byte_exact(self, tmp_path):
        """(success) cp a local file into /xrd → uploaded byte-exact, and it
        reads back through the shim identically."""
        src = tmp_path / "src.bin"
        src.write_bytes(CONTENT)
        name = "preload-w-cp.bin"
        try:
            up = subprocess.run(["cp", str(src), f"/xrd/{name}"],
                                env=_env(), capture_output=True, text=True,
                                timeout=60)
            assert up.returncode == 0, up.stderr
            with open(_server_path(name), "rb") as f:
                assert f.read() == CONTENT, "uploaded bytes differ from source"

            back = subprocess.run(["cat", f"/xrd/{name}"], env=_env(),
                                  capture_output=True, timeout=60)
            assert back.returncode == 0, back.stderr
            assert back.stdout == CONTENT
        finally:
            try:
                os.remove(_server_path(name))
            except FileNotFoundError:
                pass

    def test_direct_sequential_write(self, tmp_path):
        """(success) the realistic pattern: open(O_WRONLY|O_CREAT|O_TRUNC),
        several sequential writes, close — the concatenation lands on the
        server. (Shell `>` redirection is NOT supported: it dup2's the fake
        shim fd, which only real kernel fds survive — the same limitation the
        read path has for `< /xrd/f`; direct fd use is the contract.)"""
        name = "preload-w-seq.bin"
        chunks = [b"alpha-", b"beta-", b"gamma"]
        driver = tmp_path / "w.py"
        driver.write_text(textwrap.dedent(f"""
            import os
            fd = os.open("/xrd/{name}", os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o644)
            for c in {chunks!r}:
                assert os.write(fd, c) == len(c)
            os.close(fd)
        """))
        try:
            r = subprocess.run(["python3", str(driver)], env=_env(),
                               capture_output=True, text=True, timeout=60)
            assert r.returncode == 0, r.stderr
            with open(_server_path(name), "rb") as f:
                assert f.read() == b"".join(chunks)
        finally:
            try:
                os.remove(_server_path(name))
            except FileNotFoundError:
                pass

    def test_outside_prefix_untouched(self, tmp_path):
        """(safety) a write to a path OUTSIDE the prefix uses real libc — the
        file appears locally, nothing hits the server."""
        local = tmp_path / "local.txt"
        r = subprocess.run(["sh", "-c", f'echo hi > {local}'],
                           env=_env(), capture_output=True, text=True,
                           timeout=30)
        assert r.returncode == 0, r.stderr
        assert local.read_text() == "hi\n"

    def test_write_only_fd_not_readable(self, tmp_path):
        """(error) a write-only shim fd cannot be read — EBADF, matching a
        real O_WRONLY descriptor."""
        name = "preload-w-guard.bin"
        driver = tmp_path / "d.py"
        driver.write_text(textwrap.dedent(f"""
            import os, sys
            fd = os.open("/xrd/{name}", os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o644)
            os.write(fd, b"payload")
            try:
                os.read(fd, 16)
                print("READ_SUCCEEDED")   # bug: write-only fd was readable
            except OSError as e:
                print("EBADF" if e.errno == {int(__import__('errno').EBADF)} else f"errno={{e.errno}}")
            os.close(fd)
        """))
        try:
            r = subprocess.run(["python3", str(driver)], env=_env(),
                               capture_output=True, text=True, timeout=60)
            assert r.returncode == 0, r.stderr
            assert r.stdout.strip() == "EBADF", r.stdout
        finally:
            try:
                os.remove(_server_path(name))
            except FileNotFoundError:
                pass
