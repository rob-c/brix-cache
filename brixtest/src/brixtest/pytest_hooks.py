"""Public pytest hook specifications for cooperative BriXTest plugins."""

from __future__ import annotations

from pluggy import HookspecMarker

hookspec = HookspecMarker("pytest")


class BriXTestHookSpecs:
    """Optional hooks for planning, helper plugin selection, and result export."""

    @hookspec
    def pytest_brixtest_plan(self, item, definition) -> None:
        """Observe one validated managed-case plan during collection."""

    @hookspec
    def pytest_brixtest_helper_plugins(self, config, item) -> object:
        """Return an iterable of trusted pytest plugin modules for a helper."""

    @hookspec
    def pytest_brixtest_result(self, item, record) -> None:
        """Observe one complete secret-free case record before publication."""

    @hookspec
    def pytest_brixtest_server_ready(self, run, server) -> None:
        """Observe a backend-neutral server after successful readiness."""

    @hookspec
    def pytest_brixtest_server_stopped(self, run, server, error) -> None:
        """Observe server teardown; ``error`` is empty on success."""

    @hookspec
    def pytest_brixtest_tool_result(self, run, tool, result) -> None:
        """Observe one completed shell-free tool invocation in the helper."""

    @hookspec
    def pytest_brixtest_artifact_materialized(self, run, artifact) -> None:
        """Observe one checksum-backed input after materialization."""


def register_hooks(pluginmanager) -> None:
    """Register BriXTest's cooperative hook specifications exactly once."""
    pluginmanager.add_hookspecs(BriXTestHookSpecs)
