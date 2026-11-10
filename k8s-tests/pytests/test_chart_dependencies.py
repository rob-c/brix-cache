"""Nested chart packaging must use current local configuration."""

import pytest
import yaml

from labtools.chart_dependencies import dependency_build_plan


def _chart(root, name, dependencies=()):
    path = root / name
    path.mkdir()
    (path / "Chart.yaml").write_text(yaml.safe_dump({
        "name": name, "dependencies": [
            {"name": child, "repository": repository}
            for child, repository in dependencies
        ],
    }))
    return path


def test_nested_dependencies_build_before_parent_and_aliases_are_deduplicated(tmp_path):
    _chart(tmp_path, "leaf")
    branch = _chart(tmp_path, "branch", [("leaf", "file://../leaf")])
    parent = _chart(tmp_path, "parent", [
        ("first", "file://../branch"), ("second", "file://../branch"),
    ])
    assert dependency_build_plan(parent) == [
        ["helm", "dependency", "build", str(branch)],
        ["helm", "dependency", "build", str(parent)],
    ]


def test_local_chart_cycles_are_rejected(tmp_path):
    parent = _chart(tmp_path, "parent", [("child", "file://../child")])
    _chart(tmp_path, "child", [("parent", "file://../parent")])
    with pytest.raises(ValueError, match="cyclic"):
        dependency_build_plan(parent)


def test_local_dependency_cannot_escape_the_chart_tree(tmp_path):
    parent = _chart(tmp_path, "parent", [("outside", "file://../../outside")])
    with pytest.raises(ValueError, match="escapes"):
        dependency_build_plan(parent)
