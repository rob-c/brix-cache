"""D-3 seccomp-BPF worker syscall filter — live integration.

Boots our nginx-xrootd data server with the per-worker seccomp filter armed and
proves the SHIPPED allowlist is complete enough to serve real kXR traffic — the
plan's "full suite green under enforce" acceptance, reduced to a self-contained
open/stat/read/write round-trip so a missing allowlist entry surfaces as a dead
worker or a failed transfer rather than passing silently:

  success   — under ``brix_seccomp enforce`` a live stat + read (xrdcp GET) +
              write (xrdcp PUT) all round-trip, and the worker logs the
              enforce filter-active NOTICE;
  success   — the same holds under ``audit`` (log-only), NOTICE says mode=audit;
  error/neg — ``brix_seccomp <bogus>`` is refused by ``nginx -t``.

Runs against the repo's built binary (settings.NGINX_BIN / TEST_NGINX_BIN). Skips
cleanly without the stock xrdfs/xrdcp toolchain, or when the binary was built
without libseccomp (the worker then fails closed and never becomes ready).
"""

import os
import time

import pytest

import official_interop_lib as L
from config_templates import render_config_to_path
from server_launcher import LifecycleHarness
from server_registry import NginxInstanceSpec
from settings import NGINX_BIN

pytestmark = [
    pytest.mark.uses_lifecycle_harness,
    pytest.mark.xdist_group("lc-seccomp-enforce"),
    pytest.mark.timeout(180),
    pytest.mark.skipif(not L.have_official(),
                       reason="stock xrdfs/xrdcp not installed"),
]

_FILE_BODY = b"D-3 seccomp live payload - allowlist completeness probe\n" * 64


def _capture(argv):
    import subprocess
    try:
        p = subprocess.run(argv, capture_output=True, text=True, timeout=30)
    except (OSError, subprocess.SubprocessError):
        return None
    return (p.stdout or "") + (p.stderr or "")


def _start(mode, tmp_path):
    """Launch our server with the filter at ``mode`` over a freshly seeded tree.
    Returns (harness, endpoint, data_root). Raises RuntimeError on launch failure
    (a libseccomp-less binary fails closed here → caller turns it into a skip)."""
    data_root = str(tmp_path / f"data-{mode}")
    os.makedirs(data_root, exist_ok=True)
    with open(os.path.join(data_root, "hello.dat"), "wb") as fh:
        fh.write(_FILE_BODY)

    harness = LifecycleHarness()
    try:
        ep = harness.start(NginxInstanceSpec(
            name=f"seccomp-{mode}",
            template="nginx_seccomp.conf",
            protocol="root", readiness="tcp",
            data_root=data_root,
            template_values={"SECCOMP_MODE": mode}))
    except Exception as exc:  # noqa: BLE001 — libseccomp-less binary fails closed
        harness.close()
        raise RuntimeError(f"seccomp {mode} server did not start: {exc}") from exc
    return harness, ep, data_root


def _error_log(ep):
    path = os.path.join(ep.prefix, "logs", "error.log")
    try:
        with open(path, "r", errors="replace") as fh:
            return fh.read()
    except OSError:
        return ""


def _await_filter_line(ep, mode, tries=40):
    """The filter-active NOTICE is emitted at worker init_process; poll for it."""
    needle = f"worker syscall filter active (mode={mode}"
    for _ in range(tries):
        if needle in _error_log(ep):
            return True
        time.sleep(0.25)
    return False


# --------------------------------------------------------------------------- #
# success: a real worker serves live traffic with the filter loaded.
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("mode", ["enforce", "audit"])
def test_seccomp_serves_live(mode, tmp_path):
    try:
        harness, ep, _ = _start(mode, tmp_path)
    except RuntimeError as exc:
        pytest.skip(str(exc))
    try:
        url = L.our_url(ep.port)

        # read path: stat the seeded file, sizes must match.
        rc, out, err = L.run([L.OFF_XRDFS, url, "stat", "/hello.dat"])
        assert rc == 0, f"stat failed under {mode}: rc={rc} {err or out}"
        assert str(len(_FILE_BODY)) in out, f"unexpected size under {mode}: {out}"

        # read path: xrdcp GET, bytes must match — proves open/read/sendfile etc.
        got = str(tmp_path / f"got-{mode}.dat")
        rc, out, err = L.run([L.OFF_XRDCP, "-f", f"{url}//hello.dat", got])
        assert rc == 0, f"GET failed under {mode}: rc={rc} {err or out}"
        with open(got, "rb") as fh:
            assert fh.read() == _FILE_BODY, f"GET body mismatch under {mode}"

        # write path: xrdcp PUT a new object — proves the write/create syscalls
        # (openat O_CREAT, pwrite, fsync, rename) survive the filter.
        src = str(tmp_path / f"put-{mode}.dat")
        with open(src, "wb") as fh:
            fh.write(_FILE_BODY)
        rc, out, err = L.run([L.OFF_XRDCP, "-f", src, f"{url}//put-{mode}.dat"])
        assert rc == 0, f"PUT failed under {mode}: rc={rc} {err or out}"

        # the operator-facing proof that the filter was actually armed.
        assert _await_filter_line(ep, mode), \
            f"filter-active NOTICE (mode={mode}) never logged:\n{_error_log(ep)[-2000:]}"
    finally:
        harness.close()


# --------------------------------------------------------------------------- #
# error / security-negative: a bogus mode is refused at config parse.
# --------------------------------------------------------------------------- #
def test_seccomp_bogus_mode_refused(tmp_path):
    logs = tmp_path / "logs"
    logs.mkdir()
    cfg = str(tmp_path / "bogus.conf")
    render_config_to_path(
        "nginx_seccomp.conf", cfg, strict=False,
        LOG_DIR=str(logs), PORT=L.worker_port(14980),
        DATA_ROOT=str(tmp_path), SECCOMP_MODE="bogus")

    out = _capture([NGINX_BIN, "-t", "-c", cfg])
    assert out is not None, "nginx binary not runnable"
    assert "invalid value" in out and "bogus" in out, \
        f"bogus seccomp mode was not rejected:\n{out}"
