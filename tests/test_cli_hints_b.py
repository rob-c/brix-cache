from split_continuation import reexport as _reexport
_reexport(globals(), "_test_cli_hints_helpers")

class TestDoctorReferralPty:
    """Doctor-referral hint (spec WS-7) fires on PTY for auth failures.

    Success: kXR_NotAuthorized on PTY → 'xrddiag check' hint appears.
    Error:   kXR_NotFound on PTY → no doctor hint.
    Pipe:    auth failure, pipe stderr → no hint (C3).
    """

    def test_hint_fires_on_pty_for_auth_failure(self, suggest_probe_binary):
        """WHAT: kXR_NotAuthorized + PTY stderr → 'xrddiag check' hint fires.
        WHY:  spec WS-7: auth errors are opaque; the user needs a concrete
              next step (xrddiag check walks the full auth handshake).
        """
        # run_pty returns (rc, combined_pty_output, b"") — the PTY child has one
        # terminal fd for stdout+stderr, so hint text is in the SECOND element.
        rc, stderr, _ = run_pty(
            [str(suggest_probe_binary), "doctor_auth"],
            env=_base_env(),
            timeout=10,
        )
        assert rc == 0, f"probe exited {rc}"
        stderr_text = stderr.decode("utf-8", errors="replace")
        assert "xrddiag" in stderr_text, (
            f"expected xrddiag referral hint on PTY, got:\n{stderr_text}"
        )
        assert "check" in stderr_text, (
            f"expected 'check' in doctor hint, got:\n{stderr_text}"
        )

    def test_no_hint_for_non_auth_error(self, suggest_probe_binary):
        """WHAT: kXR_NotFound (not an auth error) → no doctor hint fires.
        WHY:  the doctor hint targets auth-class failures only; not-found
              errors are diagnosed by other means (path typos, namespace).
        """
        rc, stderr, _ = run_pty(
            [str(suggest_probe_binary), "doctor_noauth"],
            env=_base_env(),
            timeout=10,
        )
        assert rc == 0
        stderr_text = stderr.decode("utf-8", errors="replace")
        assert "xrddiag" not in stderr_text, (
            f"unexpected xrddiag hint for non-auth error:\n{stderr_text}"
        )

    def test_hint_absent_on_pipe_for_auth_failure(self, suggest_probe_binary):
        """WHAT: auth failure, stderr piped → no doctor hint (C3).
        WHY:  C3 compliance: doctor referral is interactive-only; scripts
              that test for error strings must not see extra lines.
        """
        rc, _stdout, stderr = run_pipe(
            [str(suggest_probe_binary), "doctor_auth"],
            env=_base_env(),
            timeout=10,
        )
        assert rc == 0
        stderr_text = stderr.decode("utf-8", errors="replace")
        assert "xrddiag" not in stderr_text, (
            f"doctor hint leaked to pipe stderr:\n{stderr_text}"
        )
