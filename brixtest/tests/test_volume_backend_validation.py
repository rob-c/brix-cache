"""Strict pre-mutation and access contracts for built-in volumes."""

import sys

import pytest

from brixtest import case, mount, task, volume
from brixtest.errors import SpecError
from brixtest.runtime.manager import CaseManager


def _definition(*resources, **options):
    @case(*resources, observe=(), **options)
    def declared(run):
        return None

    return declared.__brixtest_case__


def test_local_volume_options_fail_before_case_directory_creation(tmp_path):
    data = volume("data", options={"storage_class": "fast"})
    target = tmp_path / "run"
    with pytest.raises(SpecError, match="local backend has no volume options"):
        CaseManager(_definition(data), "managed::volume-options", root=target)
    assert not target.exists()


def test_builtin_volume_rejects_unintegrated_provider_before_mutation(tmp_path):
    data = volume("data", provider="site-storage")
    target = tmp_path / "run"
    with pytest.raises(SpecError, match="installed volume adapter"):
        CaseManager(_definition(data), "managed::volume-provider", root=target)
    assert not target.exists()


def test_builtin_volume_rejects_ignored_source_before_mutation(tmp_path):
    data = volume("data", source=tmp_path / "source")
    target = tmp_path / "run"
    with pytest.raises(SpecError, match="do not consume a source"):
        CaseManager(_definition(data), "managed::volume-source", root=target)
    assert not target.exists()


def test_local_read_only_volume_access_is_enforced_for_consumers(tmp_path):
    data = volume("data", kind="shared", access="read-only-many")
    inspect = task(
        "inspect", mounts=(mount(data, "data", read_only=False),),
        command=(
            sys.executable, "-c",
            "import os,stat; mode=os.stat(os.environ['MOUNT_DATA']).st_mode; "
            "assert not mode & (stat.S_IWUSR|stat.S_IWGRP|stat.S_IWOTH)",
        ),
    )
    manager = CaseManager(
        _definition(data, inspect, keep="always"),
        "managed::read-only-volume", root=tmp_path / "run",
    )
    run = manager.start()
    assert run.task(inspect).ok
    manager.set_outcome("passed")
    manager.close()
