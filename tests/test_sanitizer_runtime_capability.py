"""Only demonstrated runtime limitations may disable optional leak detection."""

import subprocess

import pytest

import sanitizer_preload as sanitizer


@pytest.mark.parametrize("returncode,stderr,expected", [
    (0, "", True),
    (-6, "AddressSanitizer: detect_leaks is not supported on this platform.", False),
    (1, "LeakSanitizer has encountered a fatal error", False),
    (1, "unrelated runtime failure", True),
])
def test_empty_program_recognizes_only_specific_runtime_limitations(
        monkeypatch, returncode, stderr, expected):
    """A failed real test cannot be excused as an unsupported sanitizer."""
    results = iter([subprocess.CompletedProcess([], 0, "", ""),
                    subprocess.CompletedProcess([], returncode, "", stderr)])
    monkeypatch.setattr(sanitizer.subprocess, "run", lambda *a, **kw: next(results))
    assert sanitizer._leak_runtime_supported() is expected


def test_failed_compile_does_not_turn_off_a_real_test(monkeypatch):
    """A broken compiler must remain a failure, not remove coverage."""
    monkeypatch.setattr(sanitizer.subprocess, "run", lambda *a, **kw:
                        subprocess.CompletedProcess([], 1, "", "compile failed"))
    assert sanitizer._leak_runtime_supported()


def test_unsupported_runtime_retains_other_requested_sanitizer_options(monkeypatch):
    """Only the unavailable LSan switch changes; ASan still halts on errors."""
    monkeypatch.setattr(sanitizer, "leak_detection_available", lambda: False)
    assert sanitizer.asan_options("detect_leaks=1", "halt_on_error=1") == (
        "detect_leaks=0:halt_on_error=1")
