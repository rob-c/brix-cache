#!/usr/bin/env python3
import sys as _brix_log_sys
from pathlib import Path as _BrixLogPath
_brix_log_sys.path.insert(0, str(_BrixLogPath(__file__).resolve().parents[2]))
from tools.logging_support import diagnostic as _brix_diagnostic

#
# WHAT: Fail CI when the GridFTP interop lab's client-image / runner / matrix
#       contract drifts out of agreement. In `evidence` mode, require an exact
#       9/9 external-door JUnit result and emit a credential-free JSON summary.
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
#   tools/ci/check_gridftp_interop_image.py evidence --junit FILE \
#     --implementation dcache --server-version 9.2.17 \
#     --endpoint door.example.org --output evidence.json
#
# --root exists so the guard's own negative tests can damage a throwaway copy
# instead of the tracked files: an interrupted test that never reached its
# restore step used to leave the real config mutated (and once committed it).

import argparse
from datetime import datetime, timezone
import hashlib
import importlib.util
import json
import re
import sys
from pathlib import Path
import tempfile
import xml.etree.ElementTree as ET

ROOT = Path(__file__).resolve().parents[2]
RUNNER_REL = "tests/cmdscripts/gridftp_interop_local.py"
DOCKERFILE_REL = "k8s-tests/Dockerfiles/gridftp-client/Dockerfile"
GATEWAY_CONF_REL = "tests/configs/nginx_gridftp_interop.conf"
S3_CONF_REL = "tests/configs/nginx_gridftp_interop_s3.conf"

# The files a --root copy must carry for the guard to reach every check.
CONTRACT_FILES = (RUNNER_REL, DOCKERFILE_REL, GATEWAY_CONF_REL, S3_CONF_REL)

EXPECTED_OUTBOUND_TESTS = frozenset({
    "test_the_front_round_trips_byte_exact[plain]",
    "test_the_front_round_trips_byte_exact[mode-e]",
    "test_the_front_round_trips_byte_exact[prot-p]",
    "test_the_front_round_trips_byte_exact[streams]",
    "test_a_ranged_read_returns_the_window_and_not_the_head",
    "test_a_same_origin_copy_is_served_by_the_gateway",
    "test_striping_agrees_with_the_unstriped_front_byte_for_byte",
    "test_a_missing_object_is_a_404",
    "test_the_protected_front_never_falls_back_to_cleartext",
})
_ENDPOINT = re.compile(
    r"(?=.{1,253}\Z)(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)*"
    r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\Z"
)
_SAFE_VERSION = re.compile(r"[\x20-\x7e]{1,128}\Z")


class EvidenceError(ValueError):
    """The report cannot certify the external GridFTP release gate."""


def _bounded(label, value, pattern):
    if not pattern.fullmatch(value):
        raise EvidenceError(f"invalid {label}: use bounded printable metadata")
    return value


def _outbound_cases(root):
    cases = list(root.iter("testcase"))
    selected = [case for case in cases
                if "test_gridftp_outbound_interop" in case.get("classname", "")
                or case.get("file", "").endswith(
                    "test_gridftp_outbound_interop.py")]
    # Some JUnit writers omit both location attributes. Exact names still make
    # this safe; the inventory comparison below rejects every unrelated cell.
    return selected or cases


def _read_junit(report):
    """Read and parse one size-bounded JUnit report."""
    try:
        raw = Path(report).read_bytes()
    except OSError as exc:
        raise EvidenceError(f"cannot read JUnit report: {exc}") from exc
    if len(raw) > 16 * 1024 * 1024:
        raise EvidenceError("JUnit report exceeds the 16 MiB release limit")
    try:
        root = ET.fromstring(raw)
    except ET.ParseError as exc:
        raise EvidenceError(f"malformed JUnit XML: {exc}") from exc
    return raw, root


def _unique_case_names(cases):
    """Return case names after rejecting duplicate matrix cells."""
    names = [case.get("name", "") for case in cases]
    duplicates = sorted({name for name in names if names.count(name) > 1})
    if duplicates:
        raise EvidenceError("duplicate GridFTP cells: " + ", ".join(duplicates))
    return names


def _validated_inventory(names):
    """Return the exact expected cell inventory or explain its drift."""
    observed = set(names)
    if observed == EXPECTED_OUTBOUND_TESTS:
        return observed
    missing = sorted(EXPECTED_OUTBOUND_TESTS - observed)
    unexpected = sorted(observed - EXPECTED_OUTBOUND_TESTS)
    detail = []
    if missing:
        detail.append("missing=" + ",".join(missing))
    if unexpected:
        detail.append("unexpected=" + ",".join(unexpected))
    raise EvidenceError("GridFTP cell inventory mismatch: " + "; ".join(detail))


def _require_passing_cases(cases):
    """Reject every failed, errored, or skipped interoperability cell."""
    nonpassing = []
    for case in cases:
        outcome = next((kind for kind in ("failure", "error", "skipped")
                        if case.find(kind) is not None), None)
        if outcome:
            nonpassing.append(f"{case.get('name')}={outcome}")
    if nonpassing:
        raise EvidenceError("GridFTP certification requires 9/9 passes: "
                            + ", ".join(sorted(nonpassing)))


def validate_outbound_junit(report):
    """Return the passing inventory and digest; reject partial/skip results."""
    raw, root = _read_junit(report)

    cases = _outbound_cases(root)
    observed = _validated_inventory(_unique_case_names(cases))
    _require_passing_cases(cases)
    return sorted(observed), hashlib.sha256(raw).hexdigest()


def _parse_timestamp(timestamp):
    """Require ISO-8601 syntax and an explicit timezone."""
    try:
        parsed = datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
    except ValueError as exc:
        raise EvidenceError("observed-at must be an ISO-8601 timestamp") from exc
    if parsed.tzinfo is None:
        raise EvidenceError("observed-at must include a timezone")


def _validated_timestamp(observed_at):
    """Return one bounded, timezone-bearing ISO-8601 timestamp."""
    timestamp = observed_at or datetime.now(timezone.utc).isoformat()
    printable = timestamp.isascii() and timestamp.isprintable()
    if len(timestamp) > 64 or not printable:
        raise EvidenceError("observed-at must be a bounded printable timestamp")
    _parse_timestamp(timestamp)
    return timestamp


def build_outbound_evidence(report, implementation, server_version, endpoint,
                            observed_at=None):
    """Build credential-free JSON evidence from the raw site report."""
    tests, digest = validate_outbound_junit(report)
    endpoint = _bounded("endpoint hostname", endpoint, _ENDPOINT)
    server_version = _bounded("server version", server_version, _SAFE_VERSION)
    timestamp = _validated_timestamp(observed_at)
    return {
        "schema": "org.brix-cache.gridftp-interop-evidence/v1",
        "status": "validated",
        "implementation": implementation,
        "server_version": server_version,
        "endpoint": endpoint,
        "observed_at": timestamp,
        "results": {"passed": len(tests), "failed": 0, "errors": 0,
                    "skipped": 0, "tests": tests},
        "junit_sha256": digest,
    }


def _write_evidence(path, evidence):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = (json.dumps(evidence, indent=2, sort_keys=True) + "\n").encode()
    with tempfile.NamedTemporaryFile(dir=path.parent, prefix=path.name + ".",
                                     delete=False) as handle:
        temporary = Path(handle.name)
        handle.write(payload)
    temporary.replace(path)


def _evidence_main(argv):
    parser = argparse.ArgumentParser(
        description="Validate external GridFTP JUnit release evidence")
    parser.add_argument("--junit", required=True, type=Path)
    parser.add_argument("--implementation", required=True,
                        choices=("globus", "dcache"))
    parser.add_argument("--server-version", required=True)
    parser.add_argument("--endpoint", required=True,
                        help="door hostname only; URLs and credentials refused")
    parser.add_argument("--observed-at")
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args(argv)
    try:
        evidence = build_outbound_evidence(
            args.junit, args.implementation, args.server_version,
            args.endpoint, args.observed_at)
        _write_evidence(args.output, evidence)
    except EvidenceError as exc:
        parser.error(str(exc))
    print(f"GridFTP interoperability validated: 9/9 passed; {args.output}")
    return 0


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
    if "brix_storage_backend pblock" not in text:
        problems.append(f"{path.name} no longer wires "
                        f"brix_storage_backend pblock — the "
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
    if "brix_storage_backend    s3://" not in text:
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
    if argv[:1] == ["evidence"]:
        return _evidence_main(argv[1:])
    root = ROOT
    if "--root" in argv:
        i = argv.index("--root")
        if i + 1 >= len(argv):
            _brix_diagnostic('ERROR', 'tools/ci/check_gridftp_interop_image.py', 'main', "check_gridftp_interop_image: --root needs a directory",
                  file=sys.stderr)
            return 2
        root = Path(argv[i + 1]).resolve()
        if not root.is_dir():
            _brix_diagnostic('ERROR', 'tools/ci/check_gridftp_interop_image.py', 'main', f"check_gridftp_interop_image: no such root: {root}",
                  file=sys.stderr)
            return 2

    problems = check(root)
    if problems:
        _brix_diagnostic('ERROR', 'tools/ci/check_gridftp_interop_image.py', 'main', "gridftp interop image/runner contract drift:", file=sys.stderr)
        for p in problems:
            _brix_diagnostic('ERROR', 'tools/ci/check_gridftp_interop_image.py', 'main', f"  - {p}", file=sys.stderr)
        return 1
    print("gridftp interop image/runner/matrix contract OK")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
