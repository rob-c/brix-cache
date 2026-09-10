"""Compile + run the forwarding-proxy key parser unit suite
(tests/test_sd_xroot_fwd_key.c over src/fs/backend/xroot/sd_xroot_fwd_key.c).

A `forward://` export (2.0 F5, XrdPss forwarding mode) lets a client name the
origin INSIDE the path it opens — `/root://host:port//file` — so the parser
that turns that key into {host, port, tls, remote path} and the `permit=`
host-allowlist verdict decide which remote host the proxy will dial on a
client's say-so. Both are pure functions with no nginx coupling; this suite
proves them deterministically (wire and VFS-shaped keys, default port, IPv6
brackets, every refusal errno, the anchored `.suffix` rule shared with the TPC
egress guard, fail-closed on an empty list). The live proxy behaviour is
covered by tests/test_release20_forward_proxy.py.
"""
import os
import shutil
import subprocess

import pytest

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SRC = os.path.join(REPO, "src")
UNITS = [
    os.path.join(REPO, "tests", "test_sd_xroot_fwd_key.c"),
    os.path.join(SRC, "fs", "backend", "xroot", "sd_xroot_fwd_key.c"),
    os.path.join(SRC, "tpc", "common", "egress_guard.c"),
    os.path.join(SRC, "core", "compat", "host_split.c"),
]


def _compiler():
    cc = shutil.which("gcc") or shutil.which("cc")
    if cc is None:
        pytest.skip("no C compiler")
    return cc


def _require_units():
    missing = [u for u in UNITS if not os.path.exists(u)]
    if missing:
        pytest.skip(f"forwarding key sources missing: {missing}")


@pytest.fixture(scope="module")
def key_bin(tmp_path_factory):
    cc = _compiler()
    _require_units()
    out = str(tmp_path_factory.mktemp("fwdkey") / "ut")
    build = subprocess.run(
        [cc, "-std=c11", "-Wall", "-Wextra", "-Werror", "-DXRDPROTO_NO_NGX",
         "-D_GNU_SOURCE", "-I", SRC, "-o", out] + UNITS,
        capture_output=True, text=True, timeout=120)
    if build.returncode != 0:
        pytest.fail("sd_xroot_fwd_key suite failed to COMPILE (warnings are "
                    f"errors):\n{build.stderr}")
    return out


def test_sd_xroot_fwd_key_suite(key_bin):
    run = subprocess.run([key_bin], capture_output=True, text=True, timeout=60)
    print(run.stdout)
    assert run.returncode == 0, \
        f"sd_xroot_fwd_key suite reported failures:\n{run.stdout}\n{run.stderr}"
    assert "ALL PASS" in run.stdout, run.stdout
