"""Run server processes on the local host using unprivileged ports.

The only place in BriXTest that spawns, signals, or ``/proc``-walks.
Everything an instance is — its config, argv, pidfile, stop strategy —
comes from its specification and kind profile.
"""

from __future__ import annotations

import contextlib
import os
import signal
import subprocess
import time
from pathlib import Path
from typing import Dict, Mapping, Optional, Set

from brixtest.config.lanes import Lane
from brixtest.errors import StartError
from brixtest.fleet.kinds import KindProfile, get_kind
from brixtest.fleet.prep import ArtifactSet
from brixtest.fleet.probes import NoProbe, TcpProbe, probe_from_alias, probe_from_declaration
from brixtest.fleet.registry import InstanceSpec, Registry, ServerEndpoint, endpoint_for
from brixtest.runtime.logcapture import BoundedLogPump
from brixtest.util.configtext import render_cfg, render_cfg_strict
from brixtest.util.net import port_holders, tcp_answering

__all__ = ["LocalBackend"]

_LOG_TAIL_LINES = 15


class LocalBackend:
    def __init__(
        self,
        registry: Registry,
        lane: Lane,
        *,
        extra_values: Optional[Mapping[str, object]] = None,
        strict_templates: bool = False,
    ) -> None:
        self.registry = registry
        self.lane = lane
        self.extra_values = dict(extra_values or {})
        self.strict_templates = strict_templates
        self._procs: Dict[str, subprocess.Popen] = {}
        self._log_pumps: Dict[str, BoundedLogPump] = {}
        self._artifacts: Optional[ArtifactSet] = None

    def prepare(self, lane: Lane, artifacts: Optional[ArtifactSet]) -> None:
        for path in (lane.log_dir, lane.instances_dir, lane.artifacts_dir, lane.tmp_dir):
            path.mkdir(parents=True, exist_ok=True)
        self._artifacts = artifacts

    def endpoint(self, name: str) -> ServerEndpoint:
        return self.registry.endpoint_for(name, self.lane)

    def logs(self, name: str) -> Path:
        return self.endpoint(name).log_path

    def is_ready(self, spec: InstanceSpec) -> bool:
        port = spec.primary_port
        if port is None:
            return False
        return tcp_answering(spec.host, port)

    def process_snapshot(self) -> Mapping[int, Set[int]]:
        declared = self.registry.declared_ports()
        return port_holders(declared)

    def process_pids(self) -> Dict[str, int]:
        """Return PIDs for processes this backend spawned and has not
        stopped.  A dead child of a non-daemonizing kind stays claimed:
        the crash detector works by asking whether a vanished /proc
        pid is *still claimed*, so filtering the dead here would hide
        every backend-spawned crash (``poll()`` also reaps the zombie,
        which is what makes the /proc vanish observable).  Children of
        daemonizing kinds (profile carries a pidfile) exit by design
        and are dropped; their real pid resolves via that pidfile."""
        out: Dict[str, int] = {}
        for name, proc in self._procs.items():
            if proc.poll() is not None:
                profile = get_kind(self.registry.get_spec(name).kind)
                if profile.pidfile is not None:
                    continue    # the launcher pid; its exit is normal
            out[name] = proc.pid
        return out

    def signal(self, name: str, signal_name: str = "TERM") -> None:
        """Send one validated signal to the supervised process group."""
        selected = {
            "TERM": signal.SIGTERM, "INT": signal.SIGINT,
            "QUIT": signal.SIGQUIT, "KILL": signal.SIGKILL,
            "HUP": signal.SIGHUP, "USR1": signal.SIGUSR1,
            "USR2": signal.SIGUSR2,
        }.get(signal_name)
        if selected is None:
            raise StartError(name, "signal", log_tail="unknown signal %r" % signal_name)
        proc = self._procs.get(name)
        if proc is None:
            raise StartError(name, "signal", log_tail="server is not supervised")
        try:
            os.killpg(proc.pid, selected)
        except OSError as exc:
            raise StartError(name, "signal", log_tail=str(exc)) from exc

    def wait(self, name: str, timeout: Optional[float] = None) -> Optional[int]:
        """Wait for one supervised process, returning ``None`` on timeout."""
        proc = self._procs.get(name)
        if proc is None:
            raise StartError(name, "wait", log_tail="server is not supervised")
        try:
            return int(proc.wait(timeout=timeout))
        except subprocess.TimeoutExpired:
            return None

    def _template_values(self, spec: InstanceSpec, endpoint: ServerEndpoint) -> Dict[str, object]:
        values: Dict[str, object] = {
            "name": spec.name,
            "host": spec.host,
            "workdir": endpoint.workdir,
            "logfile": endpoint.log_path,
            "lane_root": self.lane.root,
            "artifacts": self.lane.artifacts_dir,
        }
        for role, port in spec.ports.items():
            values["port" if role == "primary" else "%s_port" % role] = port
        for role, host in spec.hosts.items():
            values["host" if role == "primary" else "%s_host" % role] = host
        values.update(self.extra_values)
        values.update(spec.config_values)
        return values

    def _render_config(
        self, spec: InstanceSpec, endpoint: ServerEndpoint, values: Mapping[str, object]
    ) -> Optional[Path]:
        if spec.config_template is None:
            return None
        template_path = Path(spec.config_template)
        try:
            text = template_path.read_text()
        except OSError as exc:
            raise StartError(
                spec.name, "config",
                log_tail="template %s unreadable: %s" % (template_path, exc),
            ) from exc
        rendered = endpoint.workdir / template_path.name
        if self.strict_templates:
            rendered.write_text(
                render_cfg_strict(text, values, template=str(template_path))
            )
        else:
            rendered.write_text(render_cfg(text, values))
        return rendered

    def _argv(
        self,
        spec: InstanceSpec,
        profile: KindProfile,
        values: Mapping[str, object],
        config_path: Optional[Path],
    ):
        if spec.command is not None:
            return [render_cfg(part, dict(values, config=config_path or "")) for part in spec.command]
        if profile.command is not None:
            return list(profile.command(spec, self.lane, dict(values, config=config_path or "")))
        raise StartError(
            spec.name, "spawn",
            log_tail="neither the spec nor kind %r provides a command" % spec.kind,
        )

    def _log_tail(self, endpoint: ServerEndpoint) -> str:
        try:
            return "\n".join(
                endpoint.log_path.read_text(errors="replace").splitlines()[-_LOG_TAIL_LINES:]
            )
        except OSError:
            return ""

    def start(self, spec: InstanceSpec) -> ServerEndpoint:
        profile = get_kind(spec.kind)
        endpoint = endpoint_for(spec, self.lane)
        endpoint.workdir.mkdir(parents=True, exist_ok=True)
        endpoint.log_path.parent.mkdir(parents=True, exist_ok=True)
        values = self._template_values(spec, endpoint)
        config_path = self._render_config(spec, endpoint, values)
        argv = self._argv(spec, profile, values, config_path)
        env = dict(os.environ)
        # Stub servers use these values to validate their binding lane.
        env["BRIXTEST_LANE_ROOT"] = str(self.lane.root)
        env["BRIXTEST_PORT_BASE"] = str(self.lane.port_base)
        env["BRIXTEST_PORT_SPAN"] = str(self.lane.port_span)
        # spec env values are templates over the same names the config uses,
        # so `env={"BRIXTEST_PORT": "{port}"}` follows an allocated port
        env.update({
            key: render_cfg(str(val), values) for key, val in spec.env.items()
        })
        env["TMPDIR"] = str(self.lane.tmp_dir)  # the lane tmp pin
        try:
            proc = subprocess.Popen(
                argv,
                cwd=str(endpoint.workdir),
                env=env,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                start_new_session=True,
            )
        except OSError as exc:
            raise StartError(
                spec.name, "spawn", command=argv, log_tail=str(exc)
            ) from exc
        self._procs[spec.name] = proc
        assert proc.stdout is not None
        pump = BoundedLogPump(proc.stdout, endpoint.log_path, spec.log_max_bytes)
        self._log_pumps[spec.name] = pump
        pump.start()
        self._wait_ready(spec, profile, endpoint, proc, argv)
        return endpoint

    def _wait_ready(self, spec, profile, endpoint, proc, argv) -> None:
        probe = self._readiness_probe(spec, profile)
        if not spec.background:
            self._wait_foreground(spec, endpoint, proc, argv)
            return
        self._wait_background(spec, endpoint, proc, argv, probe)

    @staticmethod
    def _readiness_probe(spec, profile):
        if spec.probe is not None:
            probe = probe_from_declaration(spec.probe)
        else:
            probe = probe_from_alias(
                spec.readiness or profile.default_probe,
                timeout=spec.readiness_timeout,
            )
        if isinstance(probe, TcpProbe) and spec.primary_port is None:
            return NoProbe()
        return probe

    def _wait_background(self, spec, endpoint, proc, argv, probe) -> None:
        try:
            probe.wait(endpoint, spec.readiness_timeout)
        except Exception:
            if self._handle_early_exit(spec, endpoint, proc, argv):
                return
            raise

    def _wait_foreground(self, spec, endpoint, proc, argv) -> None:
        try:
            returncode = proc.wait(timeout=spec.readiness_timeout)
        except subprocess.TimeoutExpired as exc:
            raise StartError(
                spec.name, "startup", command=argv,
                log_tail="foreground command did not exit within %.3fs"
                % spec.readiness_timeout,
            ) from exc
        if returncode != 0:
            raise StartError(
                spec.name, "startup", command=argv, returncode=returncode,
                log_tail=self._log_tail(endpoint),
            )

    def _handle_early_exit(self, spec, endpoint, proc, argv) -> bool:
        returncode = proc.poll()
        if returncode is None:
            return False
        if spec.expected_exit and returncode == 0:
            return True
        raise StartError(
            spec.name, "startup", command=argv, returncode=returncode,
            log_tail=self._log_tail(endpoint),
        ) from None

    @staticmethod
    def _pid_running(pid: int) -> bool:
        """Alive and not a zombie.  ``os.kill(pid, 0)`` succeeds for a
        zombie, and our own children stay zombies until the post-kill
        ``wait()`` reaps them — a kill loop that can't tell the
        difference waits out its whole timeout on every child."""
        try:
            stat = Path("/proc/%d/stat" % pid).read_text()
        except OSError:
            return False
        return stat.rpartition(")")[2].split()[0] != "Z"

    def term_then_kill(self, pids: Set[int], timeout: float) -> None:
        """SIGTERM, wait out ``timeout``, then SIGKILL whatever is left.

        Public because a kind may supply a *callable* stop strategy, and
        such a callable is written by an adapter that has no business
        reimplementing the escalation — or reaching into a private name
        to reuse it.  Same reason for ``pidfile_pid`` below.
        """
        self._signal_pids(pids, signal.SIGTERM)
        pending = self._wait_running(pids, timeout)
        self._signal_pids(pending, signal.SIGKILL)

    @staticmethod
    def _signal_pids(pids: Set[int], selected: signal.Signals) -> None:
        for pid in pids:
            with contextlib.suppress(OSError):
                os.kill(pid, selected)

    def _wait_running(self, pids: Set[int], timeout: float) -> Set[int]:
        deadline = time.monotonic() + timeout
        pending = set(pids)
        while pending and time.monotonic() < deadline:
            pending = {pid for pid in pending if self._pid_running(pid)}
            if pending:
                time.sleep(0.1)
        return pending

    def pidfile_pid(self, endpoint: ServerEndpoint) -> Optional[int]:
        if endpoint.pidfile is None:
            return None
        try:
            return int(endpoint.pidfile.read_text().strip())
        except (OSError, ValueError):
            return None

    def _shutdown_command(self, spec: InstanceSpec, endpoint: ServerEndpoint) -> None:
        if not spec.shutdown_command:
            return
        env = dict(os.environ)
        env.update(spec.env)
        try:
            with endpoint.log_path.open("ab") as log:
                subprocess.run(
                    list(spec.shutdown_command), cwd=str(endpoint.workdir), env=env,
                    stdout=log, stderr=subprocess.STDOUT, check=False,
                    timeout=spec.stop_timeout,
                )
        except (OSError, subprocess.TimeoutExpired):
            pass

    def _stop_process_group(self, spec: InstanceSpec, proc: subprocess.Popen) -> None:
        selected = {
            "TERM": signal.SIGTERM, "INT": signal.SIGINT,
            "QUIT": signal.SIGQUIT, "KILL": signal.SIGKILL,
        }.get(spec.shutdown_signal)
        if selected is not None:
            with contextlib.suppress(OSError):
                os.killpg(proc.pid, selected)
        try:
            proc.wait(timeout=spec.stop_timeout)
        except subprocess.TimeoutExpired:
            with contextlib.suppress(OSError):
                os.killpg(proc.pid, signal.SIGKILL)

    def _stop_strategy(self, strategy, spec, endpoint, proc) -> None:
        if callable(strategy):
            strategy(self, spec)
            return
        handlers = {
            "signal-pidfile": self._stop_pidfile,
            "process-group": self._stop_group,
            "port-kill": self._stop_ports,
        }
        handler = handlers.get(strategy)
        if handler is not None:
            handler(spec, endpoint, proc)

    def _stop_pidfile(self, spec, endpoint, proc) -> None:
        pid = self.pidfile_pid(endpoint)
        if pid is not None:
            self.term_then_kill({pid}, spec.stop_timeout)

    def _stop_group(self, spec, endpoint, proc) -> None:
        if proc is not None:
            self._stop_process_group(spec, proc)

    def _stop_ports(self, spec, endpoint, proc) -> None:
        pids: Set[int] = set()
        for holders in port_holders(spec.ports.values()).values():
            pids |= holders
        pids.discard(os.getpid())
        if pids:
            self.term_then_kill(pids, spec.stop_timeout)

    def _reap_process(self, proc, timeout: float) -> None:
        if proc is None:
            return
        try:
            proc.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait()

    def stop(self, name: str) -> None:
        spec = self.registry.get_spec(name)
        profile = get_kind(spec.kind)
        endpoint = endpoint_for(spec, self.lane)
        # Withdraw the pid claim BEFORE any signal: process_pids keeps
        # dead children claimed so crashes are observable, which means a
        # deliberate stop must stop claiming first or a resource sweep
        # racing this window reads the kill as a crash.
        proc = self._procs.pop(name, None)
        self._shutdown_command(spec, endpoint)
        self._stop_strategy(profile.stop, spec, endpoint, proc)
        self._reap_process(proc, spec.stop_timeout)
        pump = self._log_pumps.pop(name, None)
        if pump is not None:
            pump.join(timeout=min(1.0, spec.stop_timeout))
