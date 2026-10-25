"""Portable EXDEV fixtures must use a real second device or fail explicitly."""
import os
from pathlib import Path
from types import SimpleNamespace

import pytest

import test_stage_cross_device_commit as stage


def _separate_device(monkeypatch, export):
    """Inject only device identity; directory allocation remains real."""
    native_stat = os.stat
    device = native_stat(export).st_dev

    def observed(path, *args, **kwargs):
        if Path(path) == export:
            return SimpleNamespace(st_dev=device + 1)
        return native_stat(path, *args, **kwargs)

    monkeypatch.setattr(stage.os, "stat", observed)


def test_explicit_second_device_allocates_unique_owned_directories(tmp_path, monkeypatch):
    export = tmp_path / "export"
    export.mkdir()
    root = tmp_path / "stage"
    root.mkdir()
    monkeypatch.setenv("TEST_STAGE_DEVICE_ROOT", str(root))
    _separate_device(monkeypatch, export)
    first = Path(stage._stage_dir(export))
    second = Path(stage._stage_dir(export))
    assert first.parent == second.parent == root
    assert first != second and first.is_dir() and second.is_dir()


@pytest.mark.parametrize("problem", ["missing", "same-device", "unwritable"])
def test_bad_explicit_stage_device_is_a_failure_not_a_skip(tmp_path, monkeypatch, problem):
    export = tmp_path / "export"
    export.mkdir()
    root = tmp_path / "stage"
    if problem != "missing":
        root.mkdir()
    monkeypatch.setenv("TEST_STAGE_DEVICE_ROOT", str(root))
    if problem == "unwritable":
        monkeypatch.setattr(stage.os, "access", lambda *args: False)
    with pytest.raises(pytest.fail.Exception):
        stage._stage_dir(export)
    assert not list(tmp_path.glob("stage/xrd-xdev-*"))


def test_unconfigured_missing_device_retains_an_honest_skip(tmp_path, monkeypatch):
    monkeypatch.delenv("TEST_STAGE_DEVICE_ROOT", raising=False)
    monkeypatch.setattr(stage.os.path, "isdir", lambda _path: False)
    with pytest.raises(pytest.skip.Exception, match="second device"):
        stage._stage_dir(tmp_path)


def test_stage_allocation_never_reuses_or_removes_a_preexisting_path(tmp_path, monkeypatch):
    export = tmp_path / "export"
    export.mkdir()
    root = tmp_path / "stage"
    root.mkdir()
    existing = root / f"xrd-xdev-{os.getpid()}"
    existing.symlink_to(export, target_is_directory=True)
    sentinel = export / "untouched"
    sentinel.write_bytes(b"private export content")
    monkeypatch.setenv("TEST_STAGE_DEVICE_ROOT", str(root))
    _separate_device(monkeypatch, export)
    allocated = Path(stage._stage_dir(export))
    assert allocated != existing and not allocated.is_symlink()
    assert existing.is_symlink() and sentinel.read_bytes() == b"private export content"


def test_native_workflow_provisions_a_bounded_private_second_device():
    from test_native_target_runners import _freebsd_workflow_step

    step = _freebsd_workflow_step()
    assert "size=512m,nosuid,uid=2100,gid=2100,mode=0700" in step["prepare"]
    assert "tmpfs /var/tmp/brix-cross-device-stage" in step["prepare"]
    assert "TEST_STAGE_DEVICE_ROOT=/var/tmp/brix-cross-device-stage" in step["run"]
