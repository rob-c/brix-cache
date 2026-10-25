"""Positive dstat fixtures neither enumerate nor remove unrelated export data."""

from pathlib import Path

import pytest

import test_interop_query_b as dstat


@pytest.fixture
def export(tmp_path, monkeypatch):
    """Use only pytest-owned files; avoid changing unrelated directory modes."""
    monkeypatch.setattr(dstat, "DATA_DIR", str(tmp_path))
    monkeypatch.setattr(dstat, "open_tree_for_worker", lambda _: None)
    return tmp_path


def test_dstat_directory_contains_only_the_three_known_sizes(export):
    """The reference compares a private directory, not the busy export root."""
    with dstat._dstat_files() as (remote, names):
        directory = export / remote.lstrip("/")
        assert remote != "//"
        assert {entry.name: entry.stat().st_size for entry in directory.iterdir()} == dict(names)
        assert sorted(dict(names).values()) == [128, 256, 384]
    assert not directory.exists()


def test_dstat_directory_is_cleaned_after_a_failed_comparison(export):
    """Error unwinding removes only the fixture it created."""
    with pytest.raises(RuntimeError, match="comparison failed"):
        with dstat._dstat_files() as (remote, _):
            directory = export / remote.lstrip("/")
            raise RuntimeError("comparison failed")
    assert not directory.exists()


def test_hostile_sibling_names_never_enter_the_positive_oracle(export):
    """Security-negative: a sibling with embedded newlines stays out of dstat."""
    hostile = export / "unrelated\nmetadata\nname"
    hostile.write_bytes(b"keep me")
    with dstat._dstat_files() as (remote, names):
        directory = export / remote.lstrip("/")
        assert all(Path(name).name == name for name, _ in names)
        assert hostile not in directory.iterdir()
    assert hostile.read_bytes() == b"keep me"
