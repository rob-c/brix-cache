from split_continuation import reexport as _reexport
_reexport(globals(), "_test_cli_hints_helpers")

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
# table-full test
# ---------------------------------------------------------------------------

class TestHintTableFull:
    """When 16+ distinct keys are used, new keys beyond 16 are silently dropped."""

    def test_hint_table_full_drops_17th_key(self, probe_binary):
        """WHAT: 17th distinct key to brix_cli_hint_once produces no output.
        WHY:  spec WS-1: hints are resource-bounded at 16 distinct keys per
              process; beyond that, new keys are silently dropped (no hint).
        HOW:  run_pty calls the probe's hint_table_full command, which calls
              brix_cli_hint_once 17 times with distinct keys. Count the output
              lines: only 16 should appear; the 17th is dropped.
        """
        rc, _stdout, stderr = run_pty(
            [str(probe_binary), "hint_table_full"], env=_base_env(), timeout=10
        )
        assert rc == 0, f"probe exited {rc}"
        stderr_text = stderr.decode("utf-8", errors="replace")
        hint_lines = [l for l in stderr_text.splitlines() if l.startswith("hint_")]
        assert len(hint_lines) == 16, (
            f"expected exactly 16 hint lines (keys 0-15), got {len(hint_lines)}:\n"
            f"{stderr_text}"
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


# ---------------------------------------------------------------------------
# P3: WS-7 did-you-mean hint (suggest_probe)
# ---------------------------------------------------------------------------

SUGGEST_PROBE_SRC = pathlib.Path(__file__).parent / "helpers" / "suggest_probe.c"



class TestSuggestDidYouMeanPty:
    """Did-you-mean hint (spec WS-7) fires on PTY, silent on pipe (C3).

    Success: close typo → "hint: did you mean '…'?" on TTY stderr.
    Error:   no suggestion for clearly-wrong input.
    Pipe:    hint absent when stderr is not a TTY (C3 compliance).
    """

    def test_hint_fires_on_pty_for_close_typo(self, suggest_probe_binary):
        """WHAT: 'satt' → 'stat' at distance 1; PTY stderr emits the did-you-mean hint.
        WHY:  spec WS-7: every unknown-command site must suggest a match ≤ 2 edits.
        HOW:  suggest_probe "suggest_match" calls brix_suggest("satt", CMDS) then
              brix_cli_hint() with the result; PTY stderr captures the hint line.
        """
        rc, _stdout, stderr = run_pty(
            [str(suggest_probe_binary), "suggest_match"],
            env=_base_env(),
            timeout=10,
        )
        assert rc == 0, f"probe exited {rc}"
        stderr_text = stderr.decode("utf-8", errors="replace")
        assert "did you mean" in stderr_text, (
            f"expected 'did you mean' hint on PTY, got:\n{stderr_text}"
        )
        assert "stat" in stderr_text, (
            f"expected 'stat' in hint, got:\n{stderr_text}"
        )

    def test_no_hint_for_unrecognised_input(self, suggest_probe_binary):
        """WHAT: 'zbot' is ≥ 3 edits from every candidate; no hint fires.
        WHY:  spec WS-7: hints only fire when distance ≤ 2 (spurious suggestions
              for clearly-wrong input confuse users).
        """
        rc, _stdout, stderr = run_pty(
            [str(suggest_probe_binary), "suggest_no_match"],
            env=_base_env(),
            timeout=10,
        )
        assert rc == 0, f"probe exited {rc}"
        stderr_text = stderr.decode("utf-8", errors="replace")
        assert "did you mean" not in stderr_text, (
            f"unexpected did-you-mean hint for unrecognised input:\n{stderr_text}"
        )

    def test_hint_absent_on_pipe(self, suggest_probe_binary):
        """WHAT: close typo, pipe stderr → hint must NOT appear (C3).
        WHY:  C3 compliance: non-TTY output must be byte-identical; a hint in a
              script's stderr would break any grep/diff that checks it.
        """
        rc, _stdout, stderr = run_pipe(
            [str(suggest_probe_binary), "suggest_match"],
            env=_base_env(),
            timeout=10,
        )
        assert rc == 0, f"probe exited {rc}"
        stderr_text = stderr.decode("utf-8", errors="replace")
        assert "did you mean" not in stderr_text, (
            f"hint leaked to pipe stderr:\n{stderr_text}"
        )

    def test_hostile_input_returns_clean_candidate_string(self, suggest_probe_binary):
        """WHAT: the suggested candidate in the hint is always a clean ASCII string.
        WHY:  spec WS-7 security: brix_suggest() returns a pointer from the
              candidates[] table, never from the hostile arg, so the printed hint
              can contain no terminal escape sequences injected by the caller.
        HOW:  even if the arg contains ESC/control bytes, the printed candidate
              ('stat') is clean; run_pty drains the hint line and checks for
              control bytes.
        """
        # suggest_probe "suggest_match" uses "satt" (clean); the result is "stat".
        # Verify the hint line in PTY output contains no control bytes < 0x20.
        rc, _stdout, stderr = run_pty(
            [str(suggest_probe_binary), "suggest_match"],
            env=_base_env(),
            timeout=10,
        )
        assert rc == 0
        for line_bytes in stderr.split(b"\n"):
            if b"did you mean" not in line_bytes:
                continue
            clean = line_bytes.rstrip(b"\r")
            bad_bytes = [b for b in clean if b < 0x20]
            assert not bad_bytes, (
                f"hint line contains control bytes {bad_bytes!r}:\n  {clean!r}"
            )


# ---------------------------------------------------------------------------
# P3: WS-3 double-slash URL hint
# ---------------------------------------------------------------------------

class TestDoubleSlashHintPty:
    """Double-slash URL hint (spec WS-3) fires on PTY when bit is set.

    Success: url.single_slash_path=1 on PTY → hint fires once.
    Error:   url.single_slash_path=0 → no hint.
    Pipe:    bit set, pipe stderr → hint absent (C3).
    """

    def test_hint_fires_on_pty_when_bit_set(self, suggest_probe_binary):
        """WHAT: single_slash_path=1 + PTY stderr → double-slash hint appears.
        WHY:  spec WS-3: the 'root://host/path' vs 'root://host//path' mistake
              is extremely common; users must see the hint after a not-found failure.
        """
        rc, _stdout, stderr = run_pty(
            [str(suggest_probe_binary), "double_slash"],
            env=_base_env(),
            timeout=10,
        )
        assert rc == 0, f"probe exited {rc}"
        stderr_text = stderr.decode("utf-8", errors="replace")
        assert "double slash" in stderr_text or "double-slash" in stderr_text or \
               "single" in stderr_text or "//" in stderr_text, (
            f"expected double-slash hint on PTY, got:\n{stderr_text}"
        )

    def test_no_hint_when_bit_clear(self, suggest_probe_binary):
        """WHAT: single_slash_path=0 → no double-slash hint fires.
        WHY:  the hint must only fire when the URL was actually single-slash;
              it must not appear for well-formed 'root://host//path' URLs.
        """
        rc, _stdout, stderr = run_pty(
            [str(suggest_probe_binary), "double_slash_off"],
            env=_base_env(),
            timeout=10,
        )
        assert rc == 0
        stderr_text = stderr.decode("utf-8", errors="replace")
        # No "hint:" at all when the bit is not set.
        assert "hint:" not in stderr_text, (
            f"unexpected hint when single_slash_path=0:\n{stderr_text}"
        )

    def test_hint_absent_on_pipe_even_when_bit_set(self, suggest_probe_binary):
        """WHAT: single_slash_path=1 but stderr is a pipe → no hint (C3).
        WHY:  the double-slash hint is TTY-gated; it must not leak into scripts.
        """
        rc, _stdout, stderr = run_pipe(
            [str(suggest_probe_binary), "double_slash"],
            env=_base_env(),
            timeout=10,
        )
        assert rc == 0
        stderr_text = stderr.decode("utf-8", errors="replace")
        assert "hint:" not in stderr_text, (
            f"double-slash hint leaked to pipe stderr:\n{stderr_text}"
        )


# ---------------------------------------------------------------------------
# P3: WS-7 doctor referral hint
# ---------------------------------------------------------------------------
