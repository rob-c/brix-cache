#!/usr/bin/env python3
#
# WHAT: Fail CI when the GridFTP interop lab's client-image / runner / matrix
#       contract drifts out of agreement — the `gridftp-client` Dockerfile
#       dropping one of the three reference client stacks, the combined local
#       gateway config losing a listener, or the containerised matrix and the
#       local runner disagreeing on an env-var name.
#
# WHY:  The phase-82 interop matrix
#       (k8s-tests/remote-suite/tests/test_gridftp_interop.py) proves the brix
#       gateway against the *reference* grid clients (globus-url-copy, gfal-copy,
#       a VOMS proxy) — not brix's own client code. Each stack lives only in the
#       image; if a Dockerfile edit drops gfal2 or voms-clients, the matching
#       matrix cell degrades to a silent pytest skip and the interop guarantee
#       quietly evaporates. This guard makes that failure loud. The single source
#       of truth is tests/cmdscripts/gridftp_interop_local.py (imported here), so
#       the guard, the runner, and the matrix can never disagree.
#
# USAGE:
#   tools/ci/check_gridftp_interop_image.py            # check (CI mode); non-zero on drift
#   tools/ci/check_gridftp_interop_image.py --root DIR # check a copy of the tree
#
# --root exists so the guard's own negative tests can damage a throwaway copy
# instead of the tracked files: an interrupted test that never reached its
# restore step used to leave the real config mutated (and once committed it).

import importlib.util
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
RUNNER_REL = "tests/cmdscripts/gridftp_interop_local.py"
DOCKERFILE_REL = "k8s-tests/Dockerfiles/gridftp-client/Dockerfile"
GATEWAY_CONF_REL = "tests/configs/nginx_gridftp_interop.conf"
S3_CONF_REL = "tests/configs/nginx_gridftp_interop_s3.conf"

# The files a --root copy must carry for the guard to reach every check.
CONTRACT_FILES = (RUNNER_REL, DOCKERFILE_REL, GATEWAY_CONF_REL, S3_CONF_REL)


def _load_runner(runner: Path):
    spec = importlib.util.spec_from_file_location("gridftp_interop_local", runner)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def check(root: Path = ROOT) -> list[str]:
    runner = root / RUNNER_REL
    if not runner.exists():
        return [f"missing interop runner: {runner}"]
    contract = _load_runner(runner)
    problems = _dockerfile_problems(root / DOCKERFILE_REL, contract)
    problems.extend(_gateway_problems(root / GATEWAY_CONF_REL))
    problems.extend(_s3_gateway_problems(root / S3_CONF_REL))
    problems.extend(_matrix_problems(root, contract))
    return problems


def _dockerfile_problems(path: Path, contract) -> list[str]:
    if not path.exists():
        return [f"missing grid-client Dockerfile: {path}"]
    text = path.read_text()
    problems = []
    for package in contract.INTEROP_CLIENT_PACKAGES:
        if package not in text:
            problems.append(
                f"{path.name} no longer installs {package!r} — the matrix "
                f"cell driven by it would silently skip"
            )
    if "pytest" not in text:
        problems.append(f"{path.name} does not install pytest — the "
                        f"image cannot host the interop matrix")
    return problems


def _gateway_problems(path: Path) -> list[str]:
    if not path.exists():
        return [f"missing combined gateway config: {path}"]
    text = path.read_text()
    problems = _missing_listener_problems(
        path, text, ("{GSIFTP_PORT}", "{FTP_PORT}", "{PBLOCK_GSIFTP_PORT}"),
        "the matrix needs gsiftp, ftp AND a pblock backend export",
    )
    if "brix_gridftp_storage_backend pblock" not in text:
        problems.append(f"{path.name} no longer wires "
                        f"brix_gridftp_storage_backend pblock — the "
                        f"non-posix backend interop cell would test posix")
    return problems


def _missing_listener_problems(path, text, placeholders, impact):
    return [
        f"{path.name} dropped the {placeholder} listener — {impact}"
        for placeholder in placeholders if placeholder not in text
    ]


def _s3_gateway_problems(path: Path) -> list[str]:
    if not path.exists():
        return [f"missing s3-backend gateway config: {path}"]
    text = path.read_text()
    problems = _missing_listener_problems(
        path, text, ("{S3_GSIFTP_PORT}", "{S3_ORIGIN_PORT}"),
        "the object-store backend interop cell needs the gsiftp leg AND its "
        "embedded brix_s3 origin",
    )
    if "brix_gridftp_storage_backend    s3://" not in text:
        problems.append(f"{path.name} no longer wires an s3:// gridftp "
                        f"storage backend — the object-store backend interop "
                        f"cell would test posix (or silently skip)")
    if "brix_s3 on;" not in text:
        problems.append(f"{path.name} no longer embeds a brix_s3 origin — "
                        f"the s3 leg would have no object store to target")
    return problems


def _matrix_problems(root: Path, contract) -> list[str]:
    test_file = root / contract.INTEROP_TEST
    if not test_file.exists():
        return [f"interop matrix test missing: {test_file}"]
    matrix = test_file.read_text()
    return [
        f"env var {var!r} is in the runner contract but the matrix "
        f"test never reads it — runner/matrix wiring drifted"
        for var in contract.INTEROP_ENV_VARS if var not in matrix
    ]


def main() -> int:
    argv = sys.argv[1:]
    root = ROOT
    if "--root" in argv:
        i = argv.index("--root")
        if i + 1 >= len(argv):
            print("check_gridftp_interop_image: --root needs a directory",
                  file=sys.stderr)
            return 2
        root = Path(argv[i + 1]).resolve()
        if not root.is_dir():
            print(f"check_gridftp_interop_image: no such root: {root}",
                  file=sys.stderr)
            return 2

    problems = check(root)
    if problems:
        print("gridftp interop image/runner contract drift:", file=sys.stderr)
        for p in problems:
            print(f"  - {p}", file=sys.stderr)
        return 1
    print("gridftp interop image/runner/matrix contract OK")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
