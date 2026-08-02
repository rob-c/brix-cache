"""
test_frm_lib_adapter.py — FRM nearline recall through the *library-native*
(``frm://lib`` / ``frm://libhpss`` / ``frm://libcta``) MSS adapter.

The library-native adapter (src/fs/backend/frm/sd_frm_lib.c) drives a real HSM by
dlopen()ing an operator-supplied shared object and dlsym()ing the
sd_frm_lib_abi.h symbols (brix_frm_hsm_exists / recall / migrate), so every
residency probe and recall is an in-process function call instead of a per-verb
fork+exec of a stage command — the phase-64 "library-native adapter" latency
residual (docs/refactor/phase-88-open-work-audit.md §4).

The vendor .so is stood in by tests/cmdscripts/frm_mock_hsm.c, compiled per
session; it simulates tape with a local directory named by ``$BRIX_FRM_MOCK_TAPE``
(captured in a constructor at dlopen/config-parse time, since nginx wipes a
worker's environ). The .so path is handed to the dialect via ``$BRIX_FRM_LIB``
(generic) or the per-dialect ``$BRIX_FRM_{HPSS,CTA}_LIB`` override.

Covered, on the live data plane:

  * library-native recall — the .so's ``recall`` entry point materialises the
    object into the online buffer and its bytes are served byte-exact through
    the cache tier (``libhpss`` via the per-dialect env override);
  * generic ``lib`` dialect via the generic ``$BRIX_FRM_LIB`` var;
  * a genuinely-absent object (``exists`` -> non-zero) is reported not-found and
    is never fabricated (error + security-negative);
  * graceful degradation — an unresolvable / missing library never hard-fails
    the boot: the node degrades to the stub transport and still serves.

Self-provisioned; skips cleanly when xrdcp or a C compiler is unavailable.
"""

import os
import shutil
import subprocess

import pytest

from cmdscripts import frm_mock_hsm
from settings import HOST
from server_registry import NginxInstanceSpec

# One worker: each test drives a self-contained frm://lib* server on the adapter's
# fixed ledger port, reusing it across tests (the harness closes it at teardown).
pytestmark = [pytest.mark.uses_lifecycle_harness,
              pytest.mark.xdist_group("lc-frm-lib")]

XRDCP = shutil.which("xrdcp")
TAPE_BYTES = b"REAL-LIB-HSM-CONTENT-" + b"L" * 200 + b"\n"

# The library-native transport backs three dialect names: the generic "lib" and
# the named HSM dialects "libhpss"/"libcta". All dlopen the same ABI; they differ
# only in which env var resolves the .so path — the named dialects read a
# per-dialect override so a node can front an HPSS silo and a CTA silo at once. A
# test setting ONLY the dialect override proves the resolution precedence (the
# generic $BRIX_FRM_LIB stays unset).
_LIB_ENV = {"lib": "BRIX_FRM_LIB",
            "libhpss": "BRIX_FRM_HPSS_LIB",
            "libcta": "BRIX_FRM_CTA_LIB"}


@pytest.fixture(scope="session")
def mock_hsm_so(tmp_path_factory):
    """Compile the mock HSM .so once per session (skips if no C compiler)."""
    try:
        return frm_mock_hsm.build(tmp_path_factory.mktemp("mockhsm"))
    except RuntimeError as exc:
        pytest.skip(str(exc))


@pytest.fixture
def frm(lifecycle):
    if XRDCP is None:
        pytest.skip("xrdcp not available")
    return lifecycle


def _start(harness, tmp_path, mock_so, *, adapter="libhpss", nearline=True,
           lib_path=None, seed_stub=False):
    """Start a self-contained frm://<adapter> server via the harness.

    ``lib_path`` overrides the .so path handed to the dialect (used to force a
    missing-library fallback). ``seed_stub`` also seeds the object into the base
    directory so the stub transport can serve it after a graceful degrade.
    """
    cache = tmp_path / "cache"; cache.mkdir()
    base = tmp_path / "base"; base.mkdir()
    tape = tmp_path / "tape"; tape.mkdir()
    if nearline:
        (tape / "near.dat").write_bytes(TAPE_BYTES)
    if seed_stub:
        (base / "near.dat").write_bytes(TAPE_BYTES)

    storage = f"frm://{adapter}{base}"
    env = {"BRIX_FRM_MOCK_TAPE": str(tape),
           _LIB_ENV[adapter]: lib_path if lib_path is not None else mock_so}

    endpoint = harness.start(NginxInstanceSpec(
        name=f"lc-frm-{adapter}",
        template="nginx_lc_frm_exec.conf",
        protocol="root",
        readiness="tcp",
        template_values={"STORAGE_BACKEND": storage, "CACHE_DIR": str(cache)},
        env=env,
        reason="frm library-native recall"))
    return endpoint


def _xrdcp(port, path, out, timeout=60):
    return subprocess.run(
        [XRDCP, "-f", f"root://{HOST}:{port}/{path}", out],
        capture_output=True, timeout=timeout)


def test_lib_recall_serves_nearline_object(frm, tmp_path, mock_hsm_so):
    """The library-native adapter's dlsym'd recall materialises the object into
    the online buffer and its bytes are served byte-exact through the cache tier
    — no stage command is forked."""
    ep = _start(frm, tmp_path, mock_hsm_so, adapter="libhpss")
    out = str(tmp_path / "o")
    r = _xrdcp(ep.port, "/near.dat", out)
    assert r.returncode == 0, r.stderr.decode(errors="replace")
    assert open(out, "rb").read() == TAPE_BYTES


def test_lib_generic_dialect_via_generic_env(frm, tmp_path, mock_hsm_so):
    """The generic ``lib`` dialect resolves its .so from the generic
    ``$BRIX_FRM_LIB`` var (the per-dialect overrides stay unset) and serves the
    recalled object byte-exact."""
    ep = _start(frm, tmp_path, mock_hsm_so, adapter="lib")
    out = str(tmp_path / "o")
    r = _xrdcp(ep.port, "/near.dat", out)
    assert r.returncode == 0, r.stderr.decode(errors="replace")
    assert open(out, "rb").read() == TAPE_BYTES


def test_lib_absent_object_reports_not_found(frm, tmp_path, mock_hsm_so):
    """Error + security-negative: an object not on tape (``exists`` -> non-zero)
    is reported not-found and never fabricated."""
    ep = _start(frm, tmp_path, mock_hsm_so, adapter="libhpss", nearline=False)
    out = str(tmp_path / "o")
    r = _xrdcp(ep.port, "/near.dat", out)
    assert r.returncode != 0
    assert not os.path.exists(out) or open(out, "rb").read() != TAPE_BYTES


def test_lib_missing_library_falls_back_gracefully(frm, tmp_path, mock_hsm_so):
    """Graceful degradation: an unresolvable HSM library never hard-fails the
    boot — the node degrades to the built-in stub transport (base dir = tape) and
    still serves the object. Proves the vendor .so is a runtime plug-in, not a
    boot dependency."""
    missing = str(tmp_path / "does-not-exist.so")
    ep = _start(frm, tmp_path, mock_hsm_so, adapter="libhpss",
                lib_path=missing, seed_stub=True)
    out = str(tmp_path / "o")
    r = _xrdcp(ep.port, "/near.dat", out)
    assert r.returncode == 0, r.stderr.decode(errors="replace")
    assert open(out, "rb").read() == TAPE_BYTES
