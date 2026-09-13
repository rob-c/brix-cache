"""Make xdist group markers authoritative for the load-group scheduler."""

from __future__ import annotations

import tempfile
from pathlib import Path

import pytest


class GroupFailFast:
    """Stop local workers between tests, not after their entire queued group.

    xdist's shutdown message goes to the end of each worker's queue.  A group
    here may contain thousands of tests, so share a session-private stop flag
    when the controller reaches --maxfail.  Running tests and their fixture
    teardown still complete normally; no failures are hidden or reclassified.
    """

    def __init__(self, config):
        self.maxfail = config.option.maxfail
        self.failures = 0
        self.directory = None
        marker = getattr(config, "workerinput", {}).get("brix_failfast")
        self.marker = Path(marker) if marker else None
        self.worker = hasattr(config, "workerinput")

    @pytest.hookimpl(optionalhook=True)
    def pytest_configure_node(self, node):
        if self.directory is None:
            # Called after fleet setup has wiped/recreated the scratch root.
            self.directory = tempfile.TemporaryDirectory(prefix="brix-failfast-")
            self.marker = Path(self.directory.name) / "stop"
        node.workerinput["brix_failfast"] = str(self.marker)

    def pytest_runtest_logreport(self, report):
        if self.worker or not report.failed or hasattr(report, "wasxfail"):
            return
        self.failures += 1
        if self.failures >= self.maxfail and self.marker is not None:
            self.marker.touch()

    @pytest.hookimpl(hookwrapper=True)
    def pytest_runtest_protocol(self, item, nextitem):
        yield
        if self.worker and self.marker is not None and self.marker.exists():
            item.session.shouldstop = "stopping workers after --maxfail"

    def pytest_unconfigure(self, config):
        if self.directory is not None:
            self.directory.cleanup()


def configure_group_failfast(config) -> None:
    """Opt in only for fail-fast runs with local xdist workers."""
    worker = "brix_failfast" in getattr(config, "workerinput", {})
    local = getattr(config.option, "numprocesses", None)
    if config.option.maxfail and (worker or local):
        config.pluginmanager.register(GroupFailFast(config), "brix-group-failfast")


def _marker_name(marker) -> str:
    if marker.args:
        return str(marker.args[0])
    return str(marker.kwargs.get("name", "default"))


def materialize_xdist_group(item) -> None:
    """Write the final xdist group set into the node id used by the scheduler.

    xdist normally performs this rewrite itself.  A conftest can add or replace
    groups after xdist's hook has run, though, and changing ``dist`` from
    ``load`` to ``loadgroup`` during configuration is also too late for some
    workers.  Rewriting once after this suite's collection policy has settled
    makes the marker effective in both cases.
    """
    forced = getattr(item, "_brix_xdist_group_override", None)
    names = ({forced} if forced else {
        _marker_name(marker) for marker in item.iter_markers("xdist_group")
    })
    names.discard(None)
    if not names:
        return
    base = item.nodeid.split("@", 1)[0]
    item._nodeid = f"{base}@{'_'.join(sorted(names))}"
