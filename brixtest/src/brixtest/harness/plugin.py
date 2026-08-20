"""The pytest plugin (feature F11) — the only core module that imports
pytest besides the testing kits.

An adapter builds a ``HarnessConfig`` (its catalogue, kinds, prep
steps, declaration maps) and calls ``activate(pytest_config, hc)``
from its ``conftest.py``'s ``pytest_configure``.  The session then
follows the charter's §7.9 timeline: lane → catalogue → prep → gate →
selective start → sentinel → tests → conservation → release.  The
fleet is **left running** at session end — the next session's start is
idempotent, which is what makes back-to-back runs cost ~nothing.

Run intelligence rides the same timeline (F21–F25): the controller
opens a run in the store at session start, captures every test's
reports through the ``logstart``/``logreport``/``logfinish`` stream
(which xdist forwards, so capture works in both modes), samples every
fleet pid — static and dynamic — through the resource watch, and at
session end folds the run into the store, the static report, and the
runs index.

Under xdist only the controller manages the fleet; workers see servers
that already answer.  Double activation is a hard error: two harnesses
in one process means two lane owners, and that never ends well.
"""

from __future__ import annotations

import dataclasses
import os
import socket
import time
from pathlib import Path
from typing import Callable, Dict, List, Optional, Sequence, Set

import pytest

from brixtest import events
from brixtest.config.lanes import Lane
from brixtest.deploy.local import LocalBackend
from brixtest.errors import (
    ConservationError, GateViolation, PluginActivationError, QuiescenceError,
    SpecError,
)
from brixtest.fleet.declares import DECLARE_MARKERS, DeclarationMap
from brixtest.fleet.dynamic import DEFAULT_DYNAMIC_OFFSET, DynamicFleet
from brixtest.fleet.launcher import FleetLauncher, StartReport
from brixtest.fleet.prep import FleetPrep, PrepStep
from brixtest.fleet.registry import Registry, ServerEndpoint
from brixtest.harness.gate import UndeclaredServerGate
from brixtest.harness.resources import ResourcePolicy, ResourceWatch
from brixtest.harness.sentinel import FleetSentinel, StabilityPolicy
from brixtest.results.collector import ResultCollector, new_run_id
from brixtest.results.model import RunInfo
from brixtest.results.report import write_index, write_report
from brixtest.results.store import ResultStore
from brixtest.evidence.legacy import publish as publish_evidence
from brixtest.services.artifacts import ArtifactCatalog
from brixtest.services.logs import LogView
from brixtest.services.workspace import WorkspaceAllocator
from brixtest.util.net import pids_on_port
from brixtest.util.testprobe import TestResourceProbe

__all__ = ["HarnessConfig", "FleetHandle", "activate"]

_ACTIVATION_ATTR = "_brixtest_plugin"


@dataclasses.dataclass
class HarnessConfig:
    """Everything the adapter tells the core.  Constructor > env > default
    is the adapter's job to honour inside these callables (contract C2)."""

    lane: Lane
    register_kinds: Callable[[], None]
    register_catalogue: Callable[[Registry], None]
    prep_steps: Callable[[Lane], Sequence[PrepStep]] = lambda lane: ()
    declaration_map: Callable[[], DeclarationMap] = DeclarationMap
    stability: StabilityPolicy = StabilityPolicy()
    gate_mode: str = "enforce"
    manage_fleet: bool = True     # start what the selection needs; leave it up
    workers: Optional[int] = None
    session_name: str = ""
    capture_results: bool = True          # F21/F22: record every test's run
    watch_resources: bool = True          # F25: sample fleet pids all run
    resources: ResourcePolicy = ResourcePolicy()
    dynamic_port_offset: int = DEFAULT_DYNAMIC_OFFSET   # F24 block start
    spec_validation: str = "warn"         # F1 strict validation: off|warn|refuse
    strict_templates: bool = False        # F13: unresolved placeholder = error
    file_linear: bool = True              # each file's tests = one ordered stream
                                          # (xdist: loadfile scheduling)


@dataclasses.dataclass
class FleetHandle:
    """What the ``fleet`` fixture hands to a test — one addressed surface
    for every service a test consumes (F16–F18 and F24 ride along)."""

    registry: Registry
    backend: LocalBackend
    lane: Lane
    launcher: FleetLauncher
    dynamic: DynamicFleet
    artifacts: ArtifactCatalog = dataclasses.field(init=False)
    workspaces: WorkspaceAllocator = dataclasses.field(init=False)
    on_dynamic: Optional[Callable[[str, Path], None]] = dataclasses.field(
        init=False, default=None
    )

    def __post_init__(self) -> None:
        self.artifacts = ArtifactCatalog(self.lane.artifacts_dir)
        self.workspaces = WorkspaceAllocator(self.lane)

    def endpoint(self, name: str) -> ServerEndpoint:
        return self.backend.endpoint(name)

    def logs(self, name: str) -> Path:
        return self.backend.logs(name)

    def log_view(self, name: str) -> LogView:
        return LogView(name, self.backend.logs(name))

    def url(self, name: str, scheme: str = "http", *, role: str = "primary",
            path: str = "/") -> str:
        return self.endpoint(name).url(scheme, role=role, path=path)

    def request_server(self, kind: str, **kwargs) -> ServerEndpoint:
        """Launch a dynamic server with this test's config (F24); the
        framework allocates its port, proves readiness, watches it, and
        tears it down when its scope ends."""
        endpoint = self.dynamic.request(kind, **kwargs)
        if self.on_dynamic is not None:
            self.on_dynamic(endpoint.name, endpoint.log_path)
        return endpoint


class BrixTestPlugin:
    def __init__(self, hc: HarnessConfig) -> None:
        self.hc = hc
        hc.register_kinds()
        self.registry = Registry()
        hc.register_catalogue(self.registry)
        self.registry.freeze()
        self.lane = hc.lane
        if hc.spec_validation not in ("off", "warn", "refuse"):
            raise SpecError(
                "spec_validation", hc.spec_validation, "one of: off, warn, refuse"
            )
        self._spec_warnings: List[str] = (
            self.registry.validate(self.lane)
            if hc.spec_validation != "off" else []
        )
        if self._spec_warnings and hc.spec_validation == "refuse":
            raise SpecError(
                "catalogue", "%d finding(s)" % len(self._spec_warnings),
                "; ".join(self._spec_warnings),
            )
        self.backend = LocalBackend(
            self.registry, self.lane, strict_templates=hc.strict_templates
        )
        self.launcher = FleetLauncher(
            self.registry, self.backend, self.lane, workers=hc.workers
        )
        self.gate = UndeclaredServerGate(
            self.registry, hc.declaration_map(), mode=hc.gate_mode
        )
        self.sentinel = FleetSentinel(self.registry, self.lane, hc.stability)
        self.handle = FleetHandle(
            self.registry, self.backend, self.lane, self.launcher,
            DynamicFleet(
                self.lane, port_offset=hc.dynamic_port_offset,
                strict_templates=hc.strict_templates,
            ),
        )
        self.start_report: Optional[StartReport] = None
        self._conservation_delta: str = ""
        self.store: Optional[ResultStore] = None
        self.collector: Optional[ResultCollector] = None
        self.resources: Optional[ResourceWatch] = None
        self._booted: Set[str] = set()
        self._xdist_prepared = False
        self._item_meta: Dict[str, Dict[str, object]] = {}
        self._file_servers: Dict[Path, List[str]] = {}
        self._dynamic_leaks: List[str] = []
        self._report_path: Optional[Path] = None
        self._probe = TestResourceProbe()   # runs in the test's own process
        self._file_linear_note = ""
        self._pending_dynamic: List[str] = []
        # dynamic requests are noted wherever they happen: straight into
        # the collector serially, or held for the teardown report's
        # user_properties on an xdist worker (no collector there)
        self.handle.on_dynamic = self._note_dynamic

    # -- role ------------------------------------------------------------

    @staticmethod
    def is_controller() -> bool:
        return "PYTEST_XDIST_WORKER" not in os.environ

    # -- run intelligence helpers ----------------------------------------

    def _open_run(self) -> None:
        self.store = ResultStore(self.lane.root / "results" / "brixtest.db")
        info = RunInfo(
            run_id=new_run_id(),
            started_at=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            lane_root=str(self.lane.root),
            port_base=self.lane.port_base,
            hostname=socket.gethostname(),
            meta={"session": self.hc.session_name},
        )
        self.collector = ResultCollector(self.store, self.lane, info)
        self.collector.begin_run()
        self.handle.artifacts.observer = self.collector.note_artifact

    def _note_dynamic(self, name: str, log_path: Path) -> None:
        if self.collector is not None:
            self.collector.note_dynamic(name, log_path)
        else:
            self._pending_dynamic.append(name)

    def _pid_provider(self) -> Dict[str, int]:
        """name → pid for every watched process: booted static specs
        (pidfile first — a stale one whose pid is gone IS the crash —
        else the primary-port holder) overlaid with everything the
        backends spawned themselves, dynamic servers included."""
        pids: Dict[str, int] = {}
        for name in sorted(self._booted):
            endpoint = self.backend.endpoint(name)
            pid: Optional[int] = None
            if endpoint.pidfile is not None:
                try:
                    pid = int(endpoint.pidfile.read_text().strip())
                except (OSError, ValueError):
                    pid = None
            if pid is None and endpoint.primary_port is not None:
                holders = pids_on_port(endpoint.primary_port) - {os.getpid()}
                pid = min(holders) if holders else None
            if pid is not None:
                pids[name] = pid
        pids.update(self.backend.process_pids())
        pids.update(self.handle.dynamic.process_pids())
        return pids

    # -- hooks -----------------------------------------------------------

    def pytest_sessionstart(self, session: pytest.Session) -> None:
        events.configure(self.lane.log_dir, lane=str(self.lane.port_base))
        if self.is_controller():
            self.lane.acquire(self.hc.session_name or None)
            self.backend.prepare(self.lane, None)
            if self.hc.capture_results:
                self._open_run()

    def _controller_prepare(self, files: List[Path], config) -> None:
        """Warnings, the gate verdict, and the per-file boot map — the
        controller-side work every run shape shares."""
        writer = config.get_terminal_writer()
        for warning in self._spec_warnings:   # F1 warn-only strict validation
            writer.line("brixtest spec warning: %s" % warning)
        try:
            gate_lines = self.gate.check(files)   # raises in enforce mode
        except GateViolation as exc:
            # UsageError, not a traceback: the message already names the
            # files and ends with the marker to add (C1)
            raise pytest.UsageError(str(exc)) from None
        for line in gate_lines:
            writer.line("brixtest: %s" % line)
        for path in files:
            self._file_servers[path] = sorted(self.gate.specs_to_boot([path]))

    def _controller_boot(self, files: List[Path]) -> None:
        steps = self.hc.prep_steps(self.lane)
        artifacts = FleetPrep(self.lane, steps).run() if steps else None
        self.backend.prepare(self.lane, artifacts)
        needed = self.gate.specs_to_boot(files)
        self.start_report = self.launcher.start_registered(needed)
        if not self.start_report.ok:
            failed = ", ".join(o.name for o in self.start_report.by_status("failed"))
            pytest.exit(
                "brixtest: fleet start failed (%s) — see %s"
                % (failed, self.lane.log_dir),
                returncode=1,
            )
        self._booted = {
            o.name for o in self.start_report.outcomes
            if o.status in ("started", "already-running")
        }
        self.sentinel.start(self._booted)   # watch what booted, not the catalogue
        if self.hc.watch_resources and self.collector is not None:
            self.resources = ResourceWatch(
                self._pid_provider, self.store, self.collector.info.run_id,
                self.hc.resources,
            )
            self.resources.start()

    def pytest_collection_finish(self, session: pytest.Session) -> None:
        if not self.is_controller():
            return
        if session.config.pluginmanager.hasplugin("dsession"):
            return  # xdist controller never collects; see the node hook below
        files = sorted({Path(str(item.fspath)) for item in session.items})
        self._controller_prepare(files, session.config)
        for item in session.items:
            callspec = getattr(item, "callspec", None)
            self._item_meta[item.nodeid] = {
                "markers": sorted({mark.name for mark in item.iter_markers()}),
                "params": {key: repr(value) for key, value in callspec.params.items()}
                if callspec is not None else {},
                "file": Path(str(item.fspath)),
            }
        if not self.hc.manage_fleet or not session.items:
            return
        self._controller_boot(files)

    @pytest.hookimpl(optionalhook=True)
    def pytest_xdist_node_collection_finished(self, node, ids) -> None:
        """xdist: workers collect, the controller boots.  This hook is the
        controller's only view of the collected set (its own
        pytest_collection_finish sees no items), so the first worker's
        report drives the same prepare→gate→boot path a serial run takes.
        Item markers/params are not reconstructible from bare ids — those
        capture columns stay empty under xdist (noted in charter §7.12)."""
        if not self.is_controller() or self._xdist_prepared:
            return
        self._xdist_prepared = True
        rootpath = Path(str(node.config.rootpath))
        files = sorted({rootpath / nodeid.split("::", 1)[0] for nodeid in ids})
        for nodeid in ids:
            self._item_meta[nodeid] = {
                "file": rootpath / nodeid.split("::", 1)[0],
            }
        self._controller_prepare(files, node.config)
        if self.hc.manage_fleet and ids:
            self._controller_boot(files)

    def pytest_runtest_logstart(self, nodeid: str, location) -> None:
        self.handle.dynamic.note_test(nodeid)
        if self.resources is not None:
            self.resources.note_test(nodeid)
        if self.collector is None:
            return
        meta = self._item_meta.get(nodeid, {})
        servers = self._file_servers.get(meta.get("file"), [])
        self.collector.start_test(
            nodeid,
            servers=list(servers),
            log_paths={name: self.backend.logs(name) for name in servers},
            markers=meta.get("markers"),
            params=meta.get("params"),
        )

    def pytest_runtest_setup(self, item: pytest.Item) -> None:
        self._probe.begin()   # in the process that runs the test (worker or serial)
        self.sentinel.note_test(item.nodeid)
        verdict = self.sentinel.verdict
        if verdict is not None:
            pytest.exit(str(verdict), returncode=1)

    @pytest.hookimpl(wrapper=True)
    def pytest_runtest_makereport(self, item: pytest.Item, call):
        # teardown is the last phase: close this test's resource probe
        # before the report is built, so the verdict rides its
        # user_properties home (xdist serializes those to the controller)
        if call.when == "teardown":
            item.user_properties.extend(self._probe.end())
            if self._pending_dynamic:
                item.user_properties.append(
                    ("brixtest_dynamic", ",".join(self._pending_dynamic))
                )
                self._pending_dynamic = []
        return (yield)

    @pytest.hookimpl(optionalhook=True)
    def pytest_xdist_make_scheduler(self, config, log):
        """File-linearity under xdist (the charter's stream semantics):
        every file's tests stay one ordered stream on one worker, so
        state an earlier test built is present for the later ones.  Only
        the implicit default ``--dist load`` is upgraded — an explicit
        operator choice of dist mode wins, and serial runs are already
        file-ordered by collection."""
        if not self.hc.file_linear or config.getoption("dist", "no") != "load":
            return None
        from xdist.scheduler import LoadFileScheduling
        self._file_linear_note = (
            "file-linear scheduling (loadfile): each file's tests stream "
            "in order on one worker"
        )
        return LoadFileScheduling(config, log)

    def pytest_runtest_logreport(self, report) -> None:
        if self.collector is not None:
            self.collector.record_report(report)

    def pytest_runtest_logfinish(self, nodeid: str, location) -> None:
        if self.collector is not None:
            self.collector.finish_test(nodeid)
        if self.resources is not None:
            self.resources.note_test("")
        try:
            self.handle.dynamic.release_test_scope()
        except QuiescenceError as exc:
            self._dynamic_leaks.append("%s: %s" % (nodeid, exc))

    def pytest_sessionfinish(self, session: pytest.Session) -> None:
        if self.resources is not None:   # stop sampling BEFORE teardown,
            self.resources.stop()        # or releases read as crashes
        try:
            self.handle.dynamic.release_all()
        except QuiescenceError as exc:
            self._dynamic_leaks.append("session: %s" % exc)
        if not self.is_controller():
            return
        self.sentinel.stop()
        try:
            if self.start_report is not None:
                self.sentinel.conservation_check()
        except ConservationError as exc:
            self._conservation_delta = str(exc)
            # F6: the delta is also a write-only artifact + an event, so a
            # leaked listener survives scrollback and lands in dashboards
            report = self.lane.log_dir / "conservation-report.txt"
            report.write_text(self._conservation_delta + "\n")
            events.emit("conservation.delta", detail=self._conservation_delta)
        if self.collector is not None and self.store is not None:
            info = self.collector.finish_run()
            publish_evidence(self.store, info, self.collector.run_dir)
            self._report_path = write_report(
                self.store, info.run_id, self.collector.run_dir / "report.html"
            )
            write_index(self.store, self.lane.root / "results" / "index.html")
            self.store.close()
        self.lane.release()
        events.emit("session.finished", exitstatus=int(getattr(session, "exitstatus", 0)))

    def pytest_terminal_summary(self, terminalreporter) -> None:
        if self.start_report is not None:
            terminalreporter.line("brixtest fleet: %s" % self.start_report.summary())
        if self._file_linear_note:
            terminalreporter.line("brixtest: %s" % self._file_linear_note)
        if self._conservation_delta:
            terminalreporter.line("brixtest WARNING: %s" % self._conservation_delta)
        if self.resources is not None:
            for finding in self.resources.findings:
                terminalreporter.line(
                    "brixtest FINDING [%s] %s: %s"
                    % (finding.kind, finding.instance, finding.detail)
                )
        for leak in self._dynamic_leaks:
            terminalreporter.line("brixtest WARNING: dynamic server leak — %s" % leak)
        if self._report_path is not None:
            terminalreporter.line("brixtest report: %s" % self._report_path)

    # -- fixtures --------------------------------------------------------

    @pytest.fixture(scope="session", name="fleet")
    def fleet_fixture(self) -> FleetHandle:
        return self.handle

    @pytest.fixture(name="workspace")
    def workspace_fixture(self, request: pytest.FixtureRequest) -> Path:
        """A fresh lane-scoped scratch directory named for this test —
        never pytest basetemp, never /tmp (F18)."""
        path = self.handle.workspaces.for_test(request.node.nodeid)
        if self.collector is not None:
            self.collector.note_workspace(path)
        return path


def activate(pytest_config, hc: HarnessConfig) -> BrixTestPlugin:
    """Register the harness on this pytest run.  Call once, from the
    adapter conftest's ``pytest_configure``."""
    existing = getattr(pytest_config, _ACTIVATION_ATTR, None)
    if existing is not None:
        raise PluginActivationError(
            [repr(existing.hc), repr(hc)]
        )
    for marker in DECLARE_MARKERS:
        pytest_config.addinivalue_line(
            "markers",
            "%s(name, ...): declares the fleet server(s) this file uses" % marker,
        )
    plugin = BrixTestPlugin(hc)
    pytest_config.pluginmanager.register(plugin, name="brixtest-harness")
    setattr(pytest_config, _ACTIVATION_ATTR, plugin)
    return plugin
