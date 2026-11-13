"""Build local Helm dependencies from leaves to the umbrella chart."""

from pathlib import Path

import yaml


def dependency_build_plan(chart):
    """Refresh nested file dependencies before Helm packages their parents."""
    chart = Path(chart).resolve()
    root = chart.parent
    visited, active, commands = set(), set(), []

    _visit_chart(chart, root, visited, active, commands)
    return commands


def _local_dependencies(path, root, dependencies):
    for dependency in dependencies:
        repository = dependency.get("repository", "")
        if repository.startswith("file://"):
            child = (path / repository[len("file://"):]).resolve()
            if not child.is_relative_to(root):
                raise ValueError(f"local chart dependency escapes chart tree: {child}")
            yield child


def _visit_chart(path, root, visited, active, commands):
    if path in active:
        raise ValueError(f"cyclic local chart dependency: {path}")
    if path in visited:
        return
    active.add(path)
    manifest = yaml.safe_load((path / "Chart.yaml").read_text())
    dependencies = manifest.get("dependencies", [])
    for child in _local_dependencies(path, root, dependencies):
        _visit_chart(child, root, visited, active, commands)
    if dependencies:
        commands.append(["helm", "dependency", "build", str(path)])
    active.remove(path)
    visited.add(path)
