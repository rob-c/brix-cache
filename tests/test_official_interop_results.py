"""The interop wrapper must preserve failures from every nested pytest lane."""

import pytest

from cmdscripts import official_interop


@pytest.mark.parametrize("child_status, expected", [(0, 0), (1, 1), (-15, 1)])
def test_http_child_result_reaches_top_level(
    monkeypatch, tmp_path, child_status, expected,
):
    """Exercise actual lane orchestration with only subprocess execution replaced."""
    monkeypatch.setenv("TEST_ROOT", str(tmp_path))
    calls = []
    failing_file = official_interop.XRDHTTP_TESTS[0]

    def child_pytest(argv, *, cwd, env):
        assert cwd == str(official_interop.REPO_ROOT)
        assert env["TEST_SKIP_SERVER_SETUP"] == "1"
        assert env["TEST_OWN_FLEET"] == "0"
        calls.append((list(argv), env["TEST_CROSS_BACKEND"]))
        if failing_file in argv and env["TEST_CROSS_BACKEND"] == "xrootd":
            return child_status
        return 0

    monkeypatch.setattr(official_interop.subprocess, "call", child_pytest)
    assert official_interop.cross_compatible(["--tb=short"]) == expected
    assert len(calls) == 2 + 2 * len(official_interop.XRDHTTP_TESTS)
    assert all("--tb=short" in argv for argv, _ in calls)
    for path in official_interop.XRDHTTP_TESTS:
        assert {backend for argv, backend in calls if path in argv} == {"nginx", "xrootd"}
