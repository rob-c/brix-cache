"""
Golden non-TTY CLI baseline harness (spec §12).

Purpose
-------
Captures and enforces the exact non-TTY behaviour (exit code + stdout + stderr
content hashes) of every client binary so that later refactoring tasks can
prove they did not accidentally change observable CLI output.

Usage
-----
Capture baseline once on current main::

    python tests/test_cli_golden.py --capture-baseline

Then verify on every subsequent run::

    PYTHONPATH=tests pytest tests/test_cli_golden.py -v

Skipping rules
--------------
* Unknown binary (in client/bin/ but not in the stored baseline): reported as
  a skip with the note "new binary, no baseline".
* Fleet-dependent entries when the fleet is unreachable: clean pytest.skip.
* A baseline entry that was itself skipped at capture time (fleet was down
  then): clean pytest.skip with a note.

Determinism
-----------
Output hashes are SHA-256 of the raw bytes, with exactly one normalization:
the absolute invocation path (argv[0]) is collapsed to its basename before
hashing (see _normalize_argv0), because a handful of tools echo argv[0]
verbatim in usage text, which would otherwise bake the checkout location into
the hash.  No timestamp/pid/other stripping is performed.  If a tool's output
is genuinely non-deterministic across identical invocations it must be listed
in NON_DETERMINISTIC_BINS below with a brief explanation; those binaries are
excluded from the no-arg matrix.

All commands use run_pipe (subprocess pipes, stdin=/dev/null, 30 s timeout).
"""

import hashlib
import json
import os
import pathlib
import socket
import subprocess
import sys
from typing import Dict, List, Optional, Tuple

import pytest

from cli_pty import run_pipe, TIMEOUT_S

# ---------------------------------------------------------------------------
# Paths and constants
# ---------------------------------------------------------------------------

REPO_ROOT = pathlib.Path(__file__).parent.parent
BIN_DIR = REPO_ROOT / "client" / "bin"
GOLDEN_DIR = pathlib.Path(__file__).parent / "golden"
GOLDEN_FILE = GOLDEN_DIR / "cli_baseline.json"

# Fleet connection parameters (mirror conftest / settings.py defaults).
_HOST = os.environ.get("TEST_HOST", "127.0.0.1")
_ANON_PORT = int(os.environ.get("TEST_NGINX_ANON_PORT", "11094"))
FLEET_ADDR = f"{_HOST}:{_ANON_PORT}"

# ---------------------------------------------------------------------------
# Binaries excluded from the no-arg matrix because their output is not
# reproducible across identical invocations.
#
# Format: {binary_name: "reason for exclusion"}
# ---------------------------------------------------------------------------
NON_DETERMINISTIC_BINS: Dict[str, str] = {
    # (none identified so far — all no-arg outputs are stable)
}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _fleet_up() -> bool:
    """Return True if the anonymous XRootD port answers a TCP connect."""
    try:
        conn = socket.create_connection((_HOST, _ANON_PORT), timeout=2)
        conn.close()
        return True
    except OSError:
        return False


def _sha256(data: bytes) -> str:
    """Return the hex-encoded SHA-256 digest of *data*."""
    return hashlib.sha256(data).hexdigest()


def _list_binaries() -> List[str]:
    """Return a sorted list of user-facing CLI binary names in client/bin/.

    Excludes ``*.d`` dependency files, non-executables, AND compiled unit-test
    binaries (``*_unit`` / ``*_unittest`` / ``*_test``).  ``make -C client test``
    builds those into client/bin/, but they are unit-test harnesses, not user
    CLI tools — their output changes whenever a unit test is edited, which would
    spuriously break this golden CLI matrix (a real occurrence: editing
    relsafe_unit's test cases flipped its no-arg output hash).  The result is
    deterministic (sorted).
    """
    if not BIN_DIR.is_dir():
        return []

    def _is_unit_test_bin(name: str) -> bool:
        return (name.endswith("_unit") or name.endswith("_unittest")
                or name.endswith("_test"))

    return sorted(
        p.name
        for p in BIN_DIR.iterdir()
        if p.is_file() and not p.name.endswith(".d") and os.access(p, os.X_OK)
        and not _is_unit_test_bin(p.name)
    )


def _normalize_argv0(output: bytes, argv0: str) -> bytes:
    """Replace the absolute invocation path (argv[0]) with its basename.

    Several tools (xrdadler32/xrdcrc32c/xrdcrc64/xrdckverify/xrdprep/xrdqstats/
    wait41) echo ``argv[0]`` verbatim in their usage/error text.  Because the
    harness invokes each binary by its ABSOLUTE path (``BIN_DIR / name``), that
    text embeds the checkout location — output that is byte-identical in content
    but differs across machines/checkouts.  Well-behaved tools (xrdcp, xrdfs)
    already print only the basename, so they are unaffected by this pass.

    Normalizing the single non-deterministic element (the invocation path) to
    the basename makes the stored golden hashes checkout-independent while
    leaving every other byte of the output under exact-match scrutiny.
    """
    basename = os.path.basename(argv0)
    return output.replace(argv0.encode(), basename.encode())


def _run_entry(argv: List[str], env_extra: Optional[Dict[str, str]] = None):
    """Run one matrix entry; return (exit_code, stdout_sha256, stderr_sha256).

    Args:
        argv:      Full argv for the command (first element is the binary path).
        env_extra: Optional extra environment variables to overlay.

    Returns:
        Tuple of (exit_code: int, stdout_sha: str, stderr_sha: str).

    Raises:
        subprocess.TimeoutExpired: if the command exceeds TIMEOUT_S seconds.
    """
    env = dict(os.environ)
    if env_extra:
        env.update(env_extra)
    exit_code, stdout, stderr = run_pipe(argv, env=env, timeout=TIMEOUT_S)
    stdout = _normalize_argv0(stdout, argv[0])
    stderr = _normalize_argv0(stderr, argv[0])
    return exit_code, _sha256(stdout), _sha256(stderr)


# ---------------------------------------------------------------------------
# Command matrix builder
# ---------------------------------------------------------------------------

def _build_matrix() -> List[Tuple]:
    """Build the full test matrix as a list of (key, argv, needs_fleet, env_extra).

    No-arg entries are built dynamically from client/bin/ contents at import
    time.  Fleet-dependent entries are appended with static keys.

    The *key* string is what gets stored in the JSON baseline and compared at
    test time.  It must be stable across runs (not depend on runtime state).
    """
    entries: List[Tuple[str, List[str], bool, Optional[Dict[str, str]]]] = []

    for name in _list_binaries():
        if name in NON_DETERMINISTIC_BINS:
            continue
        entries.append((
            f"noarg:{name}",
            [str(BIN_DIR / name)],
            False,
            None,
        ))

    # Fleet-dependent entries — skip cleanly when the fleet is down.
    # NOTE: `xrdfs ls /` is intentionally NOT a golden target — the export root
    # listing is non-deterministic in a parallel run (concurrent tests create
    # and delete files in the shared data dir), so its output hash is unstable.
    # The fleet entries below exercise deterministic error paths instead.
    entries.append((
        "fleet:xrdcp_missing",
        [str(BIN_DIR / "xrdcp"),
         f"root://{FLEET_ADDR}//missing",
         "/tmp/x"],
        True,
        None,
    ))
    entries.append((
        "fleet:xrdfs_staat",
        [str(BIN_DIR / "xrdfs"), FLEET_ADDR, "staat"],
        True,
        None,
    ))

    return entries


# Build at module import so pytest can collect the parametrized IDs.
_MATRIX = _build_matrix()


# ---------------------------------------------------------------------------
# Baseline capture (CLI mode)
# ---------------------------------------------------------------------------

def _capture_baseline() -> None:
    """Write tests/golden/cli_baseline.json with current output hashes.

    Called by ``python tests/test_cli_golden.py --capture-baseline``.

    The JSON structure is::

        {
          "_meta": {
            "binaries": ["xrdcp", ...],   # resolved at capture time
            "fleet_captured": true|false
          },
          "noarg:xrdcp": {"exit": 50, "stdout_sha": "...", "stderr_sha": "..."},
          "noarg:xrdfs": {"exit": 50, "stdout_sha": "...", "stderr_sha": "..."},
          "fleet:xrdfs_ls_root": {"exit": 0, "stdout_sha": "...", "stderr_sha": "..."},
          ...
        }

    A matrix entry that cannot be captured (fleet down, timeout) is stored
    with a ``"skipped"`` or ``"error"`` sentinel so the test skips cleanly.
    """
    GOLDEN_DIR.mkdir(parents=True, exist_ok=True)
    fleet = _fleet_up()

    baseline: Dict = {
        "_meta": {
            "binaries": _list_binaries(),
            "fleet_captured": fleet,
        }
    }

    for key, argv, needs_fleet, env_extra in _MATRIX:
        if needs_fleet and not fleet:
            print(f"  SKIP   {key}  (fleet down)")
            baseline[key] = {"skipped": "fleet_down"}
            continue

        print(f"  run    {key} ...", end="", flush=True)
        try:
            exit_code, stdout_sha, stderr_sha = _run_entry(argv, env_extra)
        except subprocess.TimeoutExpired:
            print(f"  TIMEOUT")
            baseline[key] = {"error": "timeout"}
            continue

        print(f"  exit={exit_code}")
        baseline[key] = {
            "exit": exit_code,
            "stdout_sha": stdout_sha,
            "stderr_sha": stderr_sha,
        }

    GOLDEN_FILE.write_text(json.dumps(baseline, indent=2) + "\n")
    print(f"\nBaseline written to {GOLDEN_FILE}")
    print(f"  {len([k for k in baseline if not k.startswith('_')])} entries captured")


# ---------------------------------------------------------------------------
# Pytest test
# ---------------------------------------------------------------------------

def _load_baseline() -> Optional[Dict]:
    """Load the stored JSON baseline, or None if it does not exist."""
    if not GOLDEN_FILE.exists():
        return None
    return json.loads(GOLDEN_FILE.read_text())


# Load once at collection time.
_BASELINE = _load_baseline()

# We parametrize over the live matrix so that:
#   * new binaries (not in baseline) appear as test nodes and skip with a
#     clear "new binary, no baseline" message;
#   * the matrix is always built from actual client/bin/ contents.
@pytest.mark.parametrize(
    "key,argv,needs_fleet,env_extra",
    _MATRIX,
    ids=[e[0] for e in _MATRIX],
)
def test_cli_golden(key: str, argv: List[str], needs_fleet: bool, env_extra: Optional[Dict[str, str]]):
    """Assert that *key*'s exit code + output hashes match the stored baseline.

    What/Why/How
    ------------
    Each parametrized case re-executes the command via run_pipe and compares
    the SHA-256 digests of stdout and stderr against the values stored in
    tests/golden/cli_baseline.json.  A mismatch means the tool's observable
    non-TTY output changed — intentional changes require a baseline re-capture.

    Skip conditions (never fail, skip cleanly):
    * Baseline file missing — instructs the user to run --capture-baseline.
    * Key not in baseline — new binary added after the last capture.
    * Baseline entry was skipped at capture time (fleet was down then).
    * Fleet-dependent entry and fleet currently unreachable.
    """
    if _BASELINE is None:
        pytest.skip(
            "No baseline file. Run: python tests/test_cli_golden.py --capture-baseline"
        )

    if key not in _BASELINE:
        pytest.skip(f"new binary, no baseline: {key}")

    stored = _BASELINE[key]

    if "skipped" in stored:
        pytest.skip(f"baseline captured with fleet down — re-capture with fleet up: {key}")

    if "error" in stored:
        pytest.skip(f"baseline had capture error ({stored['error']}): {key}")

    if needs_fleet and not _fleet_up():
        pytest.skip(f"fleet unavailable: {key}")

    try:
        exit_code, stdout_sha, stderr_sha = _run_entry(argv, env_extra)
    except subprocess.TimeoutExpired:
        pytest.fail(f"TIMEOUT (>{TIMEOUT_S}s): {' '.join(argv)}")

    assert exit_code == stored["exit"], (
        f"exit code changed: got {exit_code}, baseline {stored['exit']}"
    )
    assert stdout_sha == stored["stdout_sha"], (
        f"stdout changed (SHA-256 mismatch) for {key}"
    )
    assert stderr_sha == stored["stderr_sha"], (
        f"stderr changed (SHA-256 mismatch) for {key}"
    )


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    if "--capture-baseline" in sys.argv:
        _capture_baseline()
    else:
        print(
            "usage: python tests/test_cli_golden.py --capture-baseline\n"
            "       (pytest mode): PYTHONPATH=tests pytest tests/test_cli_golden.py -v"
        )
        sys.exit(1)
