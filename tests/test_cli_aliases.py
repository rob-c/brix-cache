"""
test_cli_aliases.py — Task 4 (WS-4): long-form flag aliases.

For each row in the WS-4 alias table, three assertion classes:

  EQUIVALENCE  — short flag and its new long alias produce identical
                 exit-code + output (--help text checks and live remote ops).
  ERROR-GOLDEN — each tool's existing unknown-option behaviour is unchanged;
                 '--nonsense' keeps the current exit code (golden-pinned).
  SECURITY-NEG — value-taking aliases reject bad input identically to the
                 short form (same exit code; never crashes).

Fleet-free by default; live remote operations run when
  ss -tlnp | grep 11094  succeeds (fleet already up) and
  TEST_SKIP_FLEET is unset.
"""

import os
import re
import socket
import subprocess

import pytest

_REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_BIN  = os.path.join(_REPO, "client", "bin")

_TEST_HOST = os.environ.get("TEST_HOST", "127.0.0.1")
_ANON_PORT = int(os.environ.get("TEST_NGINX_ANON_PORT", "11094"))
_FLEET_URL = f"root://{_TEST_HOST}:{_ANON_PORT}/"


def _run(tool: str, *args: str, timeout: int = 10):
    """Run client/bin/<tool> with *args; return (rc, stdout, stderr)."""
    exe = os.path.join(_BIN, tool)
    r = subprocess.run(
        [exe] + list(args),
        capture_output=True, text=True, timeout=timeout,
    )
    return r.returncode, r.stdout, r.stderr


def _fleet_up() -> bool:
    if os.environ.get("TEST_SKIP_FLEET"):
        return False
    try:
        s = socket.create_connection((_TEST_HOST, _ANON_PORT), timeout=1)
        s.close()
        return True
    except OSError:
        return False


# ---------------------------------------------------------------------------
# Alias table: (tool, short_args, long_args, description)
# short_args and long_args each produce the SAME logical result.
# For flags that take a value the args include a safe value.
# ---------------------------------------------------------------------------

#
# Help-parse equivalence: both spellings accepted with no error when the
# flag is the ONLY argument (only meaningful for boolean flags that don't
# require a connection).  We test via 'xrdcp --posc' which needs no args
# but will fail because there's no source — that's fine: both short and long
# produce the same "no source" error and exit code.
#
_XRDCP_BOOL_ALIASES = [
    # (short, long, meaning)
    ("-P", "--posc"),
    ("-v", "--verbose"),
    ("-d", "--debug"),
    ("-N", "--no-progress"),
]

_XRDPREP_BOOL_ALIASES = [
    ("-s", "--stage"),
    ("-c", "--cancel"),
    ("-w", "--wmode"),
    ("-f", "--fresh"),
    ("-e", "--evict"),
]


# ---------------------------------------------------------------------------
# 1. EQUIVALENCE: help text contains each long alias
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("tool,alias", [
    ("xrdcp",       "--posc"),
    ("xrdcp",       "--verbose"),
    ("xrdcp",       "--debug"),
    ("xrdcp",       "--no-progress"),
    ("xrdprep",     "--stage"),
    ("xrdprep",     "--cancel"),
    ("xrdprep",     "--wmode"),
    ("xrdprep",     "--fresh"),
    ("xrdprep",     "--evict"),
    ("xrdprep",     "--priority"),
    ("xrdgsiproxy", "--valid"),
    ("xrdgsiproxy", "--cert"),
    ("xrdgsiproxy", "--key"),
    ("xrdgsiproxy", "--out"),
    ("xrdgsiproxy", "--bits"),
    ("xrdgsiproxy", "--file"),
    ("xrdsssadmin", "--keytab"),
])
def test_alias_in_help(tool, alias):
    """Every new long alias must appear in --help output."""
    rc, out, _ = _run(tool, "--help")
    assert rc == 0, f"{tool} --help exited {rc}"
    assert alias in out, (
        f"{tool} --help does not mention {alias!r}.\n"
        f"  help output: {out[:400]!r}"
    )


# ---------------------------------------------------------------------------
# 2. EQUIVALENCE: short flag and long alias exit with the same code
#    when given the same (incomplete) invocation (no-source / no-endpoint).
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("short_flag,long_flag", _XRDCP_BOOL_ALIASES)
def test_xrdcp_alias_same_exit(short_flag, long_flag):
    """xrdcp <short> and xrdcp <long> produce the same exit code (no-source path)."""
    rc_short, _, _ = _run("xrdcp", short_flag)
    rc_long,  _, _ = _run("xrdcp", long_flag)
    assert rc_short == rc_long, (
        f"xrdcp {short_flag} exited {rc_short} but xrdcp {long_flag} exited {rc_long}"
    )


@pytest.mark.parametrize("short_flag,long_flag", _XRDPREP_BOOL_ALIASES)
def test_xrdprep_alias_same_exit(short_flag, long_flag):
    """xrdprep <short> and xrdprep <long> produce the same exit code (no-endpoint path)."""
    rc_short, _, _ = _run("xrdprep", short_flag)
    rc_long,  _, _ = _run("xrdprep", long_flag)
    assert rc_short == rc_long, (
        f"xrdprep {short_flag} exited {rc_short} but xrdprep {long_flag} exited {rc_long}"
    )


def test_xrdprep_priority_alias_same_exit():
    """-p and --priority produce the same exit code on an incomplete invocation."""
    rc_s, _, _ = _run("xrdprep", "-p", "2")
    rc_l, _, _ = _run("xrdprep", "--priority", "2")
    assert rc_s == rc_l


def test_xrdsssadmin_keytab_alias_same_exit(tmp_path):
    """-k and --keytab produce the same exit code on 'list' with a non-existent keytab."""
    fake = str(tmp_path / "fake.keytab")
    rc_s, _, _ = _run("xrdsssadmin", "-k", fake, "list")
    rc_l, _, _ = _run("xrdsssadmin", "--keytab", fake, "list")
    assert rc_s == rc_l, (
        f"xrdsssadmin -k exited {rc_s} but --keytab exited {rc_l}"
    )


def test_xrdgsiproxy_valid_alias_same_exit(tmp_path):
    """-valid and --valid produce the same exit code (no cert → same auth error)."""
    fake_cert = str(tmp_path / "cert.pem")
    fake_key  = str(tmp_path / "key.pem")
    rc_s, _, _ = _run("xrdgsiproxy", "init", "-valid", "1",
                      "-cert", fake_cert, "-key", fake_key)
    rc_l, _, _ = _run("xrdgsiproxy", "init", "--valid", "1",
                      "--cert", fake_cert, "--key", fake_key)
    assert rc_s == rc_l, (
        f"xrdgsiproxy -valid exited {rc_s} but --valid exited {rc_l}"
    )


def test_xrdgsiproxy_file_alias_same_exit(tmp_path):
    """-file and --file produce the same exit code on info (absent proxy)."""
    fake = str(tmp_path / "proxy.pem")
    rc_s, _, _ = _run("xrdgsiproxy", "info", "-file", fake)
    rc_l, _, _ = _run("xrdgsiproxy", "info", "--file", fake)
    assert rc_s == rc_l, (
        f"xrdgsiproxy info -file exited {rc_s} but --file exited {rc_l}"
    )


# ---------------------------------------------------------------------------
# 3. EQUIVALENCE: live remote ops (fleet-gated)
#    ls -h vs --human, tree -d vs --dirs-only, tree -L vs --depth
# ---------------------------------------------------------------------------

def _skip_no_fleet():
    if not _fleet_up():
        pytest.skip("test fleet not reachable")


def _xrdfs(*args: str, timeout: int = 15):
    return _run("xrdfs", *args, timeout=timeout)


def test_ls_human_alias_live():
    """xrdfs ls -h and ls --human produce identical stdout+exit on the fleet root."""
    _skip_no_fleet()
    url = f"{_TEST_HOST}:{_ANON_PORT}"
    rc_s, out_s, _ = _xrdfs(url, "ls", "-h", "/")
    rc_l, out_l, _ = _xrdfs(url, "ls", "--human", "/")
    assert rc_s == rc_l, f"ls -h exited {rc_s}, ls --human exited {rc_l}"
    assert out_s == out_l, "ls -h and ls --human produced different output"


def test_du_human_alias_live():
    """xrdfs du -h and du --human produce identical stdout+exit on the fleet root."""
    _skip_no_fleet()
    url = f"{_TEST_HOST}:{_ANON_PORT}"
    rc_s, out_s, _ = _xrdfs(url, "du", "-h", "/")
    rc_l, out_l, _ = _xrdfs(url, "du", "--human", "/")
    assert rc_s == rc_l, f"du -h exited {rc_s}, du --human exited {rc_l}"
    assert out_s == out_l, "du -h and du --human produced different output"


def test_tree_dirs_only_alias_live():
    """xrdfs tree -d and tree --dirs-only produce identical output on the fleet root."""
    _skip_no_fleet()
    url = f"{_TEST_HOST}:{_ANON_PORT}"
    rc_s, out_s, _ = _xrdfs(url, "tree", "-d", "-L", "1", "/")
    rc_l, out_l, _ = _xrdfs(url, "tree", "--dirs-only", "--depth", "1", "/")
    assert rc_s == rc_l, f"tree -d exited {rc_s}, tree --dirs-only exited {rc_l}"
    assert out_s == out_l, "tree -d and tree --dirs-only produced different output"


def test_tree_depth_alias_live():
    """xrdfs tree -L 1 and tree --depth 1 produce identical output."""
    _skip_no_fleet()
    url = f"{_TEST_HOST}:{_ANON_PORT}"
    rc_s, out_s, _ = _xrdfs(url, "tree", "-L", "1", "/")
    rc_l, out_l, _ = _xrdfs(url, "tree", "--depth", "1", "/")
    assert rc_s == rc_l, f"tree -L exited {rc_s}, tree --depth exited {rc_l}"
    assert out_s == out_l, "tree -L and tree --depth produced different output"


def test_df_human_alias_live():
    """xrdfs df -h and df --human produce identical stdout+exit on the fleet root."""
    _skip_no_fleet()
    url = f"{_TEST_HOST}:{_ANON_PORT}"
    rc_s, out_s, _ = _xrdfs(url, "df", "-h")
    rc_l, out_l, _ = _xrdfs(url, "df", "--human")
    assert rc_s == rc_l, f"df -h exited {rc_s}, df --human exited {rc_l}"
    assert out_s == out_l, "df -h and df --human produced different output"


def test_rm_verbose_alias_live():
    """xrdfs rm -v and rm --verbose produce identical exit+stderr on a nonexistent path."""
    _skip_no_fleet()
    url = f"{_TEST_HOST}:{_ANON_PORT}"
    rc_s, _, err_s = _xrdfs(url, "rm", "-v", "/no-such-path-alias-test")
    rc_l, _, err_l = _xrdfs(url, "rm", "--verbose", "/no-such-path-alias-test")
    assert rc_s == rc_l, f"rm -v exited {rc_s}, rm --verbose exited {rc_l}"
    assert err_s == err_l, "rm -v and rm --verbose stderr differs"


# ---------------------------------------------------------------------------
# 3b. EQUIVALENCE: xrdfs subcommand --help mentions long aliases (WS-2)
#     Fleet-gated: xrdfs subcommand --help requires a live connection.
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("sub,alias", [
    ("ls",    "--human"),
    ("du",    "--human"),
    ("df",    "--human"),
    ("tree",  "--dirs-only"),
    ("tree",  "--depth"),
    ("rm",    "--verbose"),
    ("touch", "--timestamp"),
])
def test_xrdfs_subcommand_help_has_long_alias(sub, alias):
    """xrdfs <sub> --help output must contain the long alias (WS-2).

    xrdfs subcommand --help requires a live connection (parse + dispatch
    happen after connect); uses the local fleet when available.
    """
    _skip_no_fleet()
    url = f"{_TEST_HOST}:{_ANON_PORT}"
    rc, out, _ = _xrdfs(url, sub, "--help")
    assert rc == 0, f"xrdfs {sub} --help exited {rc}"
    assert alias in out, (
        f"xrdfs {sub} --help does not mention {alias!r}.\n"
        f"  help output: {out!r}"
    )


# ---------------------------------------------------------------------------
# 4. ERROR-GOLDEN: unknown --nonsense keeps current error+exit code per tool
# ---------------------------------------------------------------------------

# Expected exit codes for unknown options (current behaviour, frozen by C5).
_UNKNOWN_OPT_RC = {
    "xrdcp":       50,
    "xrdprep":     50,
    "xrdgsiproxy": 50,
    "xrdsssadmin": 2,   # xrdsssadmin uses exit 2 for bad args
}


@pytest.mark.parametrize("tool,expected_rc", _UNKNOWN_OPT_RC.items())
def test_unknown_option_exit_code_unchanged(tool, expected_rc):
    """--nonsense option keeps the tool's pre-existing unknown-option exit code."""
    rc, _, _ = _run(tool, "--nonsense-xyzzy")
    assert rc == expected_rc, (
        f"{tool} --nonsense-xyzzy exited {rc}; expected {expected_rc} "
        f"(current golden; spec C5)"
    )


@pytest.mark.parametrize("tool,expected_rc", _UNKNOWN_OPT_RC.items())
def test_unknown_option_writes_stderr(tool, expected_rc):
    """Unknown option writes a diagnostic to stderr, never to stdout (C4)."""
    _, out, err = _run(tool, "--nonsense-xyzzy")
    assert err.strip(), (
        f"{tool} --nonsense-xyzzy produced no diagnostic on stderr"
        + (f" (stdout had: {out.strip()!r})" if out.strip() else "")
    )


# ---------------------------------------------------------------------------
# 5. SECURITY-NEG: value-taking aliases reject garbage identically to short form
# ---------------------------------------------------------------------------

def test_touch_timestamp_garbage_matches_short():
    """xrdfs touch --timestamp garbage errors the same way as -t garbage.

    Security-neg: the alias must not change error-handling for a bad timestamp.
    We use a clearly invalid timestamp string (no null byte — subprocess can't
    pass argv with embedded nulls; the tool's NUL-safety is tested separately
    at the C level in xrdfs_meta.c).
    """
    _skip_no_fleet()
    url = f"{_TEST_HOST}:{_ANON_PORT}"
    garbage = "not-a-valid-timestamp-value"
    rc_s, out_s, _ = _xrdfs(url, "touch", "-t",          garbage, "/tmp/.test_touch")
    rc_l, out_l, _ = _xrdfs(url, "touch", "--timestamp", garbage, "/tmp/.test_touch")
    assert rc_s == rc_l, (
        f"touch -t garbage exited {rc_s} but --timestamp garbage exited {rc_l}"
    )
    assert out_s == out_l, "touch -t and --timestamp stdout differs on garbage input"


def test_xrdprep_priority_garbage_matches_short():
    """xrdprep --priority with a non-numeric value behaves like -p (atoi → 0, still runs)."""
    # atoi("abc") returns 0 — both short and long accept it as priority 0
    rc_s, _, _ = _run("xrdprep", "-p", "abc")
    rc_l, _, _ = _run("xrdprep", "--priority", "abc")
    assert rc_s == rc_l, (
        f"xrdprep -p abc exited {rc_s} but --priority abc exited {rc_l}"
    )


def test_xrdgsiproxy_bits_garbage_matches_short(tmp_path):
    """--bits garbage matches -bits on the same error path (no cert)."""
    fake = str(tmp_path / "x.pem")
    rc_s, _, _ = _run("xrdgsiproxy", "init", "-bits", "notanumber",
                      "-cert", fake, "-key", fake)
    rc_l, _, _ = _run("xrdgsiproxy", "init", "--bits", "notanumber",
                      "--cert", fake, "--key", fake)
    assert rc_s == rc_l, (
        f"xrdgsiproxy -bits garbage exited {rc_s} but --bits garbage exited {rc_l}"
    )


def test_xrdsssadmin_keytab_not_writable(tmp_path):
    """--keytab and -k both error the same way on an unwritable path."""
    rodir = tmp_path / "readonly"
    rodir.mkdir(mode=0o555)
    fake = str(rodir / "sss.keytab")
    rc_s, _, _ = _run("xrdsssadmin", "-k", fake, "add")
    rc_l, _, _ = _run("xrdsssadmin", "--keytab", fake, "add")
    assert rc_s == rc_l, (
        f"xrdsssadmin -k on ro path exited {rc_s} but --keytab exited {rc_l}"
    )
