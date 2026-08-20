"""Shared factories for the isolated BriXTest internal unit catalogue."""

from pathlib import Path

import pytest

from brixtest.runtime.artifacts import ArtifactStore


@pytest.fixture
def artifact_store(tmp_path):
    return ArtifactStore(tmp_path / "artifacts", tmp_path)


@pytest.fixture
def source_file(tmp_path):
    path = tmp_path / "source.secret"
    path.write_text("source value\n")
    return path


def pytest_collection_modifyitems(items):
    for item in items:
        if Path(__file__).parent in Path(str(item.path)).parents:
            item.add_marker("unit")
