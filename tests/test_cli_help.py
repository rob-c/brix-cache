"""
test_cli_help.py — Task 2 (WS-2): --help / --version contract tests.

Tests every client binary for three properties (spec §C1–C5):
  1. --help exits 0, writes non-empty text to stdout (not stderr).
  2. --version exits 0, stdout matches the canonical format:
       <argv0-basename> (BriX-Cache client) <version-token>
     where <version-token> contains no '/' (not a path).
  3. Security-neg: the --version line contains no path, hostname,
     or username-shaped strings (no '/', '@', backslash, or space
     inside the version token itself).

C1 invariant — existing -h semantics are NOT tested here because they
are tool-specific (e.g. `xrdfs ls -h` humanises; `mpxstats -h` is a
legacy stderr alias). Only NEW spellings (--help / --version) are
covered.
"""

import os
import re
import subprocess
import pytest

_REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_BIN  = os.path.join(_REPO, "client", "bin")

# Every binary that must support --help and --version (symlinks included).
TOOLS = [
    "xrdcp",
    "xrdfs",
    "xrddiag",
    "xrd",
    "xrdcksum",
    "xrdcrc32c",
    "xrdcrc64",
    "xrdadler32",
    "xrdckverify",
    "xrdcinfo",
    "xrdmapc",
    "xrdstorascan",
    "brixMount",
    "xrootdfs",
    "xrdprep",
    "xrdsssadmin",
    "xrdgsiproxy",
    "xrdgsitest",
    "wait41",
    "mpxstats",
    "xrdqstats",
]

# Canonical version-line pattern (spec §2 C4):
#   <basename> (BriX-Cache client) <token>
# <token> must be non-empty and must not contain a '/'.
_VERSION_RE = re.compile(
    r'^(\S+) \(BriX-Cache client\) ([^\s/]+)\s*$'
)


def _run(tool: str, *args, timeout: int = 10):
    """Run client/bin/<tool> with *args; return (rc, stdout, stderr)."""
    exe = os.path.join(_BIN, tool)
    result = subprocess.run(
        [exe] + list(args),
        capture_output=True, text=True, timeout=timeout,
    )
    return result.returncode, result.stdout, result.stderr


@pytest.mark.parametrize("tool", TOOLS)
def test_help_exits_0_stdout_nonempty(tool):
    """--help exits 0 and writes usage text to stdout."""
    rc, out, _err = _run(tool, "--help")
    assert rc == 0, f"{tool} --help exited {rc}"
    assert out.strip(), f"{tool} --help produced empty stdout"


@pytest.mark.parametrize("tool", TOOLS)
def test_version_format(tool):
    """--version exits 0 and matches '<basename> (BriX-Cache client) <ver>'."""
    rc, out, _err = _run(tool, "--version")
    assert rc == 0, f"{tool} --version exited {rc}"
    line = out.strip()
    m = _VERSION_RE.match(line)
    assert m, (
        f"{tool} --version output does not match canonical format.\n"
        f"  got: {line!r}\n"
        f"  want: r'<basename> (BriX-Cache client) <version-token>'"
    )
    ver_token = m.group(2)
    assert "/" not in ver_token, (
        f"{tool} --version token looks like a path: {ver_token!r}"
    )


@pytest.mark.parametrize("tool", TOOLS)
def test_version_no_sensitive_data(tool):
    """--version output must not leak paths, hostnames, or usernames."""
    _rc, out, _err = _run(tool, "--version")
    line = out.strip()
    # The version token (3rd field) must contain no suspicious chars.
    m = _VERSION_RE.match(line)
    if m is None:
        pytest.skip(f"version line not parseable (covered by test_version_format)")
    ver_token = m.group(2)
    for bad in ("/", "@", "\\"):
        assert bad not in ver_token, (
            f"{tool}: version token {ver_token!r} contains {bad!r}"
        )


@pytest.mark.parametrize("tool", ["xrdcp", "xrdfs", "xrddiag", "wait41"])
def test_help_extra_arg_exits_0(tool):
    """--help with a trailing extra arg exits 0 (help fires before remaining
    args are parsed) and writes non-empty text to stdout.  Confirmed against
    current binaries: all four exit 0 with usage on stdout."""
    rc, out, _err = _run(tool, "--help", "extra")
    assert rc == 0, f"{tool} --help extra exited {rc} (current behavior)"
    assert out.strip(), f"{tool} --help extra produced empty stdout"


def test_xrdcp_help_stdout_golden():
    """xrdcp --help writes to stdout (not stderr) and contains key flags."""
    rc, out, err = _run("xrdcp", "--help")
    assert rc == 0
    assert "usage: xrdcp" in out, "xrdcp --help usage line missing from stdout"
    # Footer must be present (spec §2 C5)
    assert "brix-env(7)" in out, "xrdcp --help missing brix-env(7) footer"
    assert "man xrdcp" in out, "xrdcp --help missing man page footer"
    # Nothing should go to stderr for --help
    assert not err.strip(), f"xrdcp --help wrote to stderr: {err!r}"
