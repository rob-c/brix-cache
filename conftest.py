"""Pytest compatibility helpers for optional plugins.

This project prefers pytest-timeout, but test runs should stay warning-free
when that plugin is not present in the active environment.
"""


def pytest_addoption(parser):
    """Register timeout ini keys when pytest-timeout is unavailable."""
    parser.addoption(
        "--first-percent",
        type=float,
        default=None,
        metavar="PERCENT",
        help="run only the first PERCENT of the final deterministic collection",
    )
    try:
        parser.addini(
            "timeout",
            "Default per-test timeout in seconds (pytest-timeout).",
            default="30",
        )
    except ValueError:
        # Already provided by pytest-timeout.
        pass

    try:
        parser.addini(
            "timeout_method",
            "Timeout backend (pytest-timeout).",
            default="thread",
        )
    except ValueError:
        # Already provided by pytest-timeout.
        pass


def _disable_leak_detection_when_ptrace_is_restricted():
    """Default ASAN_OPTIONS to detect_leaks=0 where LeakSanitizer cannot run.

    LSan stops threads and walks memory through ptrace.  Where
    kernel.yama.ptrace_scope is restricted, an unprivileged process (the
    documented TEST USER == SERVER USER posture) aborts at exit with
    "LeakSanitizer has encountered a fatal error ... does not work under
    ptrace".  Every instrumented binary the suite runs then exits non-zero for a
    reason that has nothing to do with the code under test.

    setdefault, so an operator or a test that sets ASAN_OPTIONS itself still
    wins; runs in the controller AND in each xdist worker, because the child
    binaries inherit whichever process spawns them.
    """
    import os

    if os.environ.get("ASAN_OPTIONS"):
        return
    if os.geteuid() == 0:
        return                           # root keeps CAP_SYS_PTRACE
    try:
        with open("/proc/sys/kernel/yama/ptrace_scope", encoding="ascii") as fh:
            restricted = fh.read().strip() != "0"
    except OSError:
        return                           # no yama, or unreadable -> assume fine
    if restricted:
        os.environ["ASAN_OPTIONS"] = "detect_leaks=0"


def pytest_configure(config):
    # Keep marker warnings quiet when pytest-timeout is not installed.
    config.addinivalue_line(
        "markers",
        "timeout(seconds): per-test timeout (handled by pytest-timeout when installed)",
    )
    _disable_leak_detection_when_ptrace_is_restricted()
