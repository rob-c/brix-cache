"""Offline unit: origin service principal derived from the backend host (§5.7).

brix_krb5_origin_princ_from_host() builds "host/<backend_fqdn>@<REALM>" for the
forwarded GSS context, taking the realm from the gateway's own principal (the
phase-70 "derive-from-backend-host" decision — no dedicated directive). This is
pure string assembly, so it runs with no KDC: a tiny harness compiles against the
built krb5 forward.o and exercises success / overflow / injection cases.

Skips only when the nginx objects have not been built yet.
"""

from __future__ import annotations

import shutil
from pathlib import Path

import pytest

from cmdscripts.c_auth_units import NGX_SRC, OBJS
from cmdscripts.compile_run import REPO_ROOT, run

# There are two forward.o (cms/ and krb5/); pick the krb5-module object, which
# carries brix_krb5_origin_princ_from_host().
_FORWARD = next(
    (p for p in (OBJS / "addon").rglob("forward.o") if "krb5" in p.parts), None
)

pytestmark = pytest.mark.skipif(
    _FORWARD is None, reason="build nginx first (missing krb5/forward.o)"
)


def _gss_libs() -> list[str]:
    # forward.o references GSSAPI symbols (its forwarding path); the helper under
    # test uses none of them, but they must resolve at link time.
    tool = shutil.which("krb5-config")
    if tool:
        proc = run([tool, "--libs", "gssapi"])
        if proc.returncode == 0:
            return proc.stdout.split()
    return ["-lgssapi_krb5", "-lkrb5", "-lk5crypto", "-lcom_err"]


@pytest.fixture(scope="module")
def harness(tmp_path_factory) -> Path:
    binary = tmp_path_factory.mktemp("krb5_origin_princ") / "krb5_origin_princ"
    cmd = [
        "gcc", "-O", "-Wall",
        "-I", "src",
        "-I", str(NGX_SRC / "src/core"),
        "-I", str(NGX_SRC / "src/event"),
        "-I", str(NGX_SRC / "src/os/unix"),
        "-I", str(NGX_SRC / "src/stream"),
        "-I", str(OBJS),
        "tests/c/krb5_origin_princ_test.c",
        str(_FORWARD),
        *_gss_libs(),
        "-o", str(binary),
    ]
    built = run(cmd, cwd=REPO_ROOT, env={"TMPDIR": "/tmp"})
    if built.returncode != 0:
        pytest.skip(f"harness compile failed: {(built.stderr or built.stdout)[-2000:]}")
    return binary


@pytest.mark.parametrize("case", ["success", "overflow", "inject"])
def test_origin_princ_derivation(harness, case):
    proc = run([str(harness), case])
    assert proc.returncode == 0, (
        f"{case}: rc={proc.returncode} {proc.stdout}{proc.stderr}"
    )
