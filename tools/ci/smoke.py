#!/usr/bin/env python3
#
# WHAT: Prove the artefacts this build produced actually RUN — boot one brix
#       nginx from the repo's own config template on an ephemeral port, pull a
#       file through it with the freshly built client `xrdcp`, and verify the
#       bytes are byte-identical.
#
# WHY:  Compiling is not running. The guard lanes are all static, the analyzer
#       lanes only compile, and until this script existed the only CI job that
#       ever executed the module was `asan` — which exits 0 when the fleet does
#       not boot, so a main that compiled but could not serve a single byte
#       would have reached the branch with every check green. This is the
#       minimum "main works" gate: TCP accept → XRootD handshake → login →
#       kXR_open → kXR_read → kXR_close, driven by the client from the same
#       commit.
#
# HOW:  1. Resolve the two binaries under test (objs/nginx, client/bin/xrdcp).
#       2. Point TEST_ROOT at a private scratch tree, so this never touches or
#          collides with a fleet already running on the host.
#       3. LifecycleHarness — the harness's own throwaway-instance driver —
#          renders tests/configs/nginx_min_sec.conf (anonymous, cleartext,
#          root:// only: no PKI, no tokens, no krb5, nothing to install),
#          validates it with `nginx -t`, starts it on a free port and waits for
#          readiness. Reusing the harness means this lane exercises the same
#          render/start path every test does, not a hand-rolled config.
#       4. xrdcp the payload back out and compare SHA-256.
#       5. close() stops and unregisters whatever started, always.
#
#       There is deliberately NO silent-skip path: every prerequisite is
#       produced by the build job that runs this, so a missing one is a broken
#       build, not an unsuitable runner. A lane that skips is a lane that
#       proves nothing (see docs/09-developer-guide/history-testing-and-
#       incidents.md, field guide).
#
# USAGE:
#   tools/ci/smoke.py                     # after `make` + `make -C client`
#
# Env: NGINX_SRC (default /tmp/nginx-1.28.3) or TEST_NGINX_BIN to name the
#      binary directly; TEST_XRDCP_BIN to override the client under test;
#      BRIX_SMOKE_KEEP=1 to leave the scratch tree behind for debugging.

import hashlib
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
TESTS = REPO / "tests"

TEMPLATE = "nginx_min_sec.conf"
PAYLOAD_NAME = "smoke.bin"
XRDCP_TIMEOUT = 60


def _resolve_binaries() -> tuple[str, str]:
    """Locate the nginx and xrdcp binaries this lane is supposed to exercise.

    WHAT: returns (nginx, xrdcp) as absolute paths, or exits 1 naming the one
    that is missing.
    WHY: both are outputs of the build job that runs this script, so absence is
    a build failure to report, never a reason to skip.
    HOW: TEST_NGINX_BIN / TEST_XRDCP_BIN win when set (the operator is pointing
    the lane at a specific artefact); otherwise the conventional locations —
    $NGINX_SRC/objs/nginx and the in-repo client/bin/xrdcp.
    """
    nginx = os.environ.get("TEST_NGINX_BIN") or str(
        Path(os.environ.get("NGINX_SRC", "/tmp/nginx-1.28.3")) / "objs" / "nginx"
    )
    xrdcp = os.environ.get("TEST_XRDCP_BIN") or str(REPO / "client" / "bin" / "xrdcp")
    for label, path in (("nginx", nginx), ("xrdcp", xrdcp)):
        if not os.access(path, os.X_OK):
            print(
                f"smoke: FAIL — {label} is not executable at {path}\n"
                f"        this lane runs AFTER the build; a missing artefact "
                f"means the build did not produce it",
                file=sys.stderr,
            )
            sys.exit(1)
    return nginx, xrdcp


def _scratch_root() -> Path:
    """Give this run a private TEST_ROOT and export it before settings loads.

    WHAT: creates a temp tree and sets TEST_ROOT/TEST_NGINX_BIN-adjacent env.
    WHY: `tests/settings.py` freezes every path from TEST_ROOT at import time,
    so the export has to happen before the first tests-module import. A private
    root also means this lane cannot disturb — or be disturbed by — a fleet
    already running on the same host, which is the normal state of a developer
    box and would otherwise collide on the shared registry.
    HOW: mkdtemp + os.environ, returned so the caller can clean it up.
    """
    root = Path(tempfile.mkdtemp(prefix="brix-smoke-"))
    os.environ["TEST_ROOT"] = str(root)
    os.environ["TEST_REGISTRY_ROOT"] = str(root / "registry")
    return root


def _serve_and_fetch(nginx: str, xrdcp: str, root: Path) -> None:
    """Boot one instance, pull the payload through it, verify the bytes.

    WHAT: the actual gate — raises on any failure, returns None on success.
    WHY: byte comparison, not just an exit code: a handshake that succeeds and
    transfers nothing would otherwise pass.
    HOW: the harness renders/validates/starts (so `nginx -t` failure surfaces
    as a start failure here), an explicit free port keeps the instance clear of
    the port ladder, and close() reaps it whatever happens.
    """
    sys.path.insert(0, str(TESTS))
    os.environ["TEST_NGINX_BIN"] = nginx

    from ephemeral_port import free_port                    # noqa: PLC0415
    from server_launcher import LifecycleHarness            # noqa: PLC0415
    from server_registry import NginxInstanceSpec           # noqa: PLC0415
    from settings import BIND_HOST, HOST                    # noqa: PLC0415

    data = root / "data"
    data.mkdir(parents=True, exist_ok=True)
    payload = b"brix-ci-smoke\n" + os.urandom(64 * 1024)
    (data / PAYLOAD_NAME).write_bytes(payload)

    port = free_port(BIND_HOST)
    print(f"smoke: 2/3 starting one brix nginx on {BIND_HOST}:{port} (nginx -t + boot)…", flush=True)
    harness = LifecycleHarness()
    try:
        endpoint = harness.start(
            NginxInstanceSpec(
                name=f"ci-smoke-{os.getpid()}",
                template=TEMPLATE,
                port=port,
                protocol="root",
                data_root=str(data),
                readiness="root",
                template_values={"TLS_LINES": "", "AUTH": "none", "MIN_SEC": "none"},
                reason="CI smoke — the built module must serve one real read.",
            )
        )
        url = f"root://{HOST}:{endpoint.port}//{PAYLOAD_NAME}"
        dest = root / "got.bin"
        print(f"smoke: 3/3 pulling {url} with {xrdcp}…", flush=True)
        proc = subprocess.run(
            [xrdcp, "-f", url, str(dest)],
            capture_output=True, text=True, timeout=XRDCP_TIMEOUT,
        )
        if proc.returncode != 0:
            raise RuntimeError(
                f"xrdcp exited {proc.returncode}\n"
                f"stdout: {proc.stdout}\nstderr: {proc.stderr}"
            )
        want = hashlib.sha256(payload).hexdigest()
        got = hashlib.sha256(dest.read_bytes()).hexdigest()
        if want != got:
            raise RuntimeError(
                f"transfer corrupted the payload: sha256 {got} != {want} "
                f"({dest.stat().st_size} of {len(payload)} bytes)"
            )
    finally:
        harness.close()


def main() -> int:
    """Run the smoke and report a single verdict line."""
    print("smoke: 1/3 resolving the binaries under test…", flush=True)
    nginx, xrdcp = _resolve_binaries()
    print(f"          nginx = {nginx}\n          xrdcp = {xrdcp}", flush=True)
    root = _scratch_root()
    try:
        _serve_and_fetch(nginx, xrdcp, root)
    except Exception as exc:  # noqa: BLE001 — the verdict is the exit code
        print(f"smoke: FAIL — {type(exc).__name__}: {exc}", file=sys.stderr)
        errlog = root / "registry"
        for log in sorted(errlog.glob("*/logs/error.log")):
            print(f"---- {log} (tail) ----\n{log.read_text()[-4000:]}", file=sys.stderr)
        return 1
    finally:
        if os.environ.get("BRIX_SMOKE_KEEP") != "1":
            shutil.rmtree(root, ignore_errors=True)
        else:
            print(f"smoke: scratch tree kept at {root}")
    print("smoke: OK — the built module served a byte-exact root:// read")
    return 0


if __name__ == "__main__":
    sys.exit(main())
