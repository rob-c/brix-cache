"""
test_cli_hints.py — PTY and pipe tests for the brix_env_resolve divergence note
(spec WS-1 change 1.3, P1 test triple).

WHAT:  Three test classes covering the required triple:
         success  — divergence note fires exactly once on a fake TTY (pty)
                    when two chain members are set to different values.
         error    — the note is ABSENT on a pipe (non-TTY stderr); exit code
                    is unaffected.
         security — the note line contains no bytes < 0x20 (no terminal escape
                    injection through env var names that we control).

WHY:   Spec C3: "non-TTY output is byte-identical"; the divergence note must
       never appear in scripts, pipelines, or cron jobs.
       Security: only variable NAMES (from our const chain[]) appear in the
       note, never values — but we validate this property anyway.

HOW:   A tiny C probe binary is compiled on-the-fly against the client lib
       to call brix_env_resolve with a known chain; the probe exits 0 and
       writes nothing to stdout.  run_pty attaches a PTY to stderr so
       isatty(STDERR_FILENO) returns 1; run_pipe uses a regular pipe.
"""
import os
import pathlib
import subprocess
import sys
import tempfile

import pytest

# ---------------------------------------------------------------------------
# Fixture: compile the probe binary once per session
# ---------------------------------------------------------------------------

CLIENT_DIR = pathlib.Path(__file__).parent.parent / "client"
PROBE_SRC = pathlib.Path(__file__).parent / "helpers" / "envalias_probe.c"
PROBE_BIN = None  # set by the fixture


def _compile_probe(tmp_dir: pathlib.Path) -> pathlib.Path:
    """Compile the helper probe that calls brix_env_resolve and exits.

    WHAT: builds a minimal binary that exercises the divergence-note path so
          we can observe it through a PTY or pipe without involving any real
          server or authentication.
    WHY:  the library's brix_env_resolve() is a pure C function; compiling a
          standalone probe is the fastest, most direct way to drive it.
    HOW:  mirrors the make test recipe — link against CLIENT_LIB + PROTO_LIB
          so the probe picks up the full resolved dependencies.
    """
    client_lib  = CLIENT_DIR / "libbrix.a"
    proto_lib   = CLIENT_DIR / ".." / "shared" / "xrdproto" / "libxrdproto.a"
    probe_out   = tmp_dir / "envalias_probe"

    if not client_lib.exists():
        pytest.skip("client/libbrix.a not built; run `make -C client lib` first")
    if not proto_lib.exists():
        pytest.skip("shared/xrdproto/libxrdproto.a not built")
    if not PROBE_SRC.exists():
        pytest.skip(f"probe source not found: {PROBE_SRC}")

    result = subprocess.run(
        [
            "cc", "-std=c11", "-Wall",
            f"-I{CLIENT_DIR / 'lib'}",
            f"-I{CLIENT_DIR / '..' / 'src'}",
            f"-I{CLIENT_DIR / '..' / 'shared'}",
            "-DXRDPROTO_NO_NGX",
            str(PROBE_SRC),
            str(client_lib),
            str(proto_lib),
            "-lssl", "-lcrypto", "-lz",
            "-o", str(probe_out),
        ],
        capture_output=True,
        text=True,
        timeout=30,
    )
    if result.returncode != 0:
        pytest.skip(
            f"could not compile envalias_probe: {result.stderr[:500]}"
        )
    return probe_out


@pytest.fixture(scope="session")
def probe_binary(tmp_path_factory):
    """Return path to the compiled probe binary (compiled once per session)."""
    tmp = tmp_path_factory.mktemp("envalias_probe")
    return _compile_probe(tmp)


# ---------------------------------------------------------------------------
# Import run_pty / run_pipe from the helpers module
# ---------------------------------------------------------------------------
sys.path.insert(0, str(pathlib.Path(__file__).parent))
from cli_pty import run_pipe, run_pty  # noqa: E402


# ---------------------------------------------------------------------------
# Helper: build an env dict with BRIX_NO_HINTS cleared
# ---------------------------------------------------------------------------

def _base_env(**extra):
    """Return os.environ copy with BRIX_NO_HINTS removed plus any extras."""
    env = dict(os.environ)
    env.pop("BRIX_NO_HINTS", None)
    env.update(extra)
    return env


# ---------------------------------------------------------------------------
# success tests
# ---------------------------------------------------------------------------

class TestHintFiredOnPty:
    """Divergence note appears exactly once when stderr is a TTY."""

    def test_note_fires_once_on_pty(self, probe_binary):
        """WHAT: two chain vars set to different values + PTY stderr → one note.
        WHY:  core C3 behaviour: hints appear on interactive terminals.
        HOW:  run_pty attaches a PTY slave to stderr; the probe calls
              brix_env_resolve with both vars set; the master drain collects
              the note line.
        """
        env = _base_env(
            TEST_ENVALIAS_CANON="canon_value",
            TEST_ENVALIAS_LEGACY="different_value",
        )
        rc, _stdout, stderr = run_pty(
            [str(probe_binary), "diverge"], env=env, timeout=10
        )
        assert rc == 0, f"probe exited {rc}"
        stderr_text = stderr.decode("utf-8", errors="replace")
        note_lines = [l for l in stderr_text.splitlines() if "note:" in l]
        assert len(note_lines) == 1, (
            f"expected exactly 1 note line, got {len(note_lines)}:\n{stderr_text}"
        )
        line = note_lines[0]
        assert "TEST_ENVALIAS_CANON"  in line
        assert "TEST_ENVALIAS_LEGACY" in line

    def test_note_absent_when_same_value(self, probe_binary):
        """WHAT: same value in both vars → no note even on a TTY.
        WHY:  spec: 'same values set twice ⇒ silent'.
        """
        env = _base_env(
            TEST_ENVALIAS_CANON="shared_val",
            TEST_ENVALIAS_LEGACY="shared_val",
        )
        rc, _stdout, stderr = run_pty(
            [str(probe_binary), "diverge"], env=env, timeout=10
        )
        assert rc == 0
        stderr_text = stderr.decode("utf-8", errors="replace")
        assert "note:" not in stderr_text, (
            f"unexpected note line with same values:\n{stderr_text}"
        )

    def test_legacy_only_no_note_on_pty(self, probe_binary):
        """WHAT: only the legacy var is set → canonical value returned, no note.
        WHY:  C2: legacy-only environment behaves identically.
        """
        env = _base_env(TEST_ENVALIAS_LEGACY="only_legacy")
        env.pop("TEST_ENVALIAS_CANON", None)
        rc, _stdout, stderr = run_pty(
            [str(probe_binary), "diverge"], env=env, timeout=10
        )
        assert rc == 0
        stderr_text = stderr.decode("utf-8", errors="replace")
        assert "note:" not in stderr_text, (
            f"unexpected note with legacy-only env:\n{stderr_text}"
        )


# ---------------------------------------------------------------------------
# error test (non-TTY: note must be absent)
# ---------------------------------------------------------------------------

class TestHintAbsentOnPipe:
    """Divergence note must NOT appear when stderr is a pipe (C3)."""

    def test_no_note_on_pipe(self, probe_binary):
        """WHAT: two differing vars set, stderr piped → zero note lines.
        WHY:  C3 compliance — byte-identical output for scripts/cron.
        HOW:  run_pipe uses subprocess.run with capture_output=True; isatty
              returns 0 on the child's stderr.
        """
        env = _base_env(
            TEST_ENVALIAS_CANON="canon_value",
            TEST_ENVALIAS_LEGACY="different_value",
        )
        rc, _stdout, stderr = run_pipe(
            [str(probe_binary), "diverge"], env=env, timeout=10
        )
        assert rc == 0, f"probe exited {rc}"
        stderr_text = stderr.decode("utf-8", errors="replace")
        assert "note:" not in stderr_text, (
            f"note leaked to pipe stderr:\n{stderr_text}"
        )

    def test_brix_no_hints_suppresses_on_pty(self, probe_binary):
        """WHAT: BRIX_NO_HINTS=1 suppresses hints even on a TTY.
        WHY:  C3 opt-out: scripts that set BRIX_NO_HINTS must get no hints.
        """
        env = _base_env(
            TEST_ENVALIAS_CANON="canon_value",
            TEST_ENVALIAS_LEGACY="different_value",
            BRIX_NO_HINTS="1",
        )
        rc, _stdout, stderr = run_pty(
            [str(probe_binary), "diverge"], env=env, timeout=10
        )
        assert rc == 0
        stderr_text = stderr.decode("utf-8", errors="replace")
        assert "note:" not in stderr_text, (
            f"note appeared with BRIX_NO_HINTS=1:\n{stderr_text}"
        )


# ---------------------------------------------------------------------------
# security-negative test
# ---------------------------------------------------------------------------

class TestNoteNoControlBytes:
    """The note line must contain no terminal-escape-capable bytes < 0x20."""

    def test_control_bytes_in_values_do_not_appear_in_note(self, probe_binary):
        """WHAT: env VALUES with embedded control bytes / escape sequences do
               NOT appear in the note (note prints only variable NAMES).
        WHY:   secret + terminal-escape protection: a password stored in
               XrdSecCREDS containing \\x1b]0;pwn\\x07 must not appear in
               terminal output.  The note format is:
                 note: both NAME_A and NAME_B are set and differ; using NAME_A
               Variable NAMES from our chain[] are plain ASCII, so the note
               itself is control-byte-free.
        HOW:   set the values to strings with control bytes; run via PTY so
               the note fires (isatty=1, BRIX_NO_HINTS unset); decode the
               note line and assert no byte < 0x20 other than newline.
        """
        evil_value = "secret\x1b]0;pwn\x07end"

        env = _base_env(
            TEST_ENVALIAS_CANON=evil_value,
            TEST_ENVALIAS_LEGACY="other\x01garbage",
        )
        rc, _stdout, stderr = run_pty(
            [str(probe_binary), "diverge"], env=env, timeout=10
        )
        assert rc == 0

        # Find the note line(s) in the raw bytes.
        for line_bytes in stderr.split(b"\n"):
            if b"note:" not in line_bytes:
                continue
            # The note line must not contain any byte < 0x20 (except the
            # line itself which ends before the split).  \r from PTY is OK
            # (0x0d >= 0x0d — actually 0x0d < 0x20 so strip it first).
            clean = line_bytes.rstrip(b"\r")
            bad_bytes = [b for b in clean if b < 0x20]
            assert not bad_bytes, (
                f"note line contains control bytes {bad_bytes!r}:\n"
                f"  {clean!r}"
            )
            # The evil values must not appear literally in the note.
            assert b"\x1b" not in clean, "ESC in note line"
            assert b"\x07" not in clean, "BEL in note line"
            # The note contains only the NAMES, not the values.
            assert b"secret" not in clean, "value leaked into note line"
            assert b"garbage" not in clean, "value leaked into note line"
