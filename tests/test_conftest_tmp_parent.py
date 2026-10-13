"""Regression coverage for the controller-to-xdist temp-parent handoff."""

import importlib.util
from pathlib import Path

import pytest


_CONFTEST_PATH = Path(__file__).with_name("conftest.py")
_SPEC = importlib.util.spec_from_file_location("tmp_parent_conftest", _CONFTEST_PATH)
assert _SPEC is not None and _SPEC.loader is not None
conftest = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(conftest)


class _Options:
    numprocesses = None
    collectonly = False


class _Config:
    option = _Options()
    args = ["test_conftest_tmp_parent.py"]


class _Session:
    config = _Config()
    items = []


@pytest.fixture
def sessionstart_tmp_env(monkeypatch, tmp_path):
    """Run sessionstart without touching a real fleet or its watchdog."""
    tmp_dir = tmp_path / "lane" / "tmp"
    monkeypatch.setattr(conftest, "TMP_DIR", str(tmp_dir))
    monkeypatch.setattr(conftest, "REMOTE_SERVER", False)
    monkeypatch.setattr(conftest, "_validate_requested_paths", lambda config: None)
    monkeypatch.setattr(conftest, "_should_skip_local_lifecycle", lambda config: False)
    monkeypatch.setattr(conftest, "_start_sentinel_watchdog", lambda session: None)
    monkeypatch.setattr(conftest, "_setup_session", lambda **kwargs: None)
    return tmp_dir


def test_sessionstart_recreates_tmp_parent_after_setup(sessionstart_tmp_env):
    conftest.pytest_sessionstart(_Session())
    assert sessionstart_tmp_env.is_dir()


def test_sessionstart_tmp_parent_reassertion_is_idempotent(sessionstart_tmp_env):
    sessionstart_tmp_env.mkdir(parents=True)
    sentinel = sessionstart_tmp_env / "active-worker"
    sentinel.write_text("keep", encoding="utf-8")
    conftest.pytest_sessionstart(_Session())
    assert sentinel.read_text(encoding="utf-8") == "keep"


def test_sessionstart_tmp_parent_non_directory_fails_closed(sessionstart_tmp_env):
    sessionstart_tmp_env.parent.mkdir(parents=True)
    sessionstart_tmp_env.write_text("not-a-directory", encoding="utf-8")
    with pytest.raises(FileExistsError):
        conftest.pytest_sessionstart(_Session())
