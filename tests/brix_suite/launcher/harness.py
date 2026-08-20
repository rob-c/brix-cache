"""``LifecycleHarness`` — the per-test facade over the launcher.

Moved verbatim out of ``tests/server_launcher_part3.py`` by TS-4 item 4.  Bodies are
unchanged; the import block is the one part that is not a copy — each of
the four launcher modules carried the *same* 45-line header regardless of
what it used, so the block here is exactly this module's measured free
names (AST, not eyeball).
"""

from __future__ import annotations

from dataclasses import replace
from pathlib import Path
from typing import Sequence
import os
import shutil
import signal
import subprocess

from brix_suite.registry import (
    NginxInstanceSpec,
    endpoint_for,
    register_nginx,
    registered_specs,
    replace_spec,
    unregister,
)
from fleet_lifecycle_ports import lifecycle_ports_for

class LifecycleHarness:
    """Per-test driver for throwaway registry instances.

    Lifecycle-subject tests (reload/reopen/restart/crash semantics) need their
    own short-lived nginx rather than the session fleet.  The harness registers
    uniquely-named specs so xdist workers and sequential tests never collide on
    registry prefixes, exposes the launcher's lifecycle primitives, and
    ``close()`` stops and unregisters everything it created — leaving the
    session registry exactly as it found it, even when a test body fails.
    """

    def __init__(self, launcher: "RegistryLauncher | None" = None):
        # Imported inside the body, not at module scope: ``RegistryLauncher``
        # is composed in this package's ``__init__`` out of three modules,
        # one of which is imported before this one.  A module-level import
        # here would close that loop.  The annotation stays a string for the
        # same reason; ``from __future__ import annotations`` makes it free.
        from brix_suite.launcher import RegistryLauncher  # noqa: PLC0415

        self.launcher = launcher or RegistryLauncher()
        self._names: list[str] = []

    def register(self, spec: NginxInstanceSpec) -> NginxInstanceSpec:
        fixed_port, fixed_extra = lifecycle_ports_for(spec.name)
        if fixed_port is not None:
            # Fixed-port lifecycle-subject (Bucket 2): keep the stable name — the
            # owning test serialises with @pytest.mark.xdist_group(name) so the
            # fixed exclusive-band port never has two concurrent drivers — and
            # take the port from the ledger, not a per-pid dynamic allocation.
            unique = replace(
                spec,
                port=fixed_port,
                extra_ports={**spec.extra_ports, **fixed_extra},
            )
        elif spec.port is not None:
            # The spec already carries an explicit fixed port — the parse-only
            # helpers pass SHARED_PARSE_PLACEHOLDER_PORT (nginx -t never binds
            # it), so many uniquely-named throwaway instances can share it.  Keep
            # the caller's unique name, suffixed per-pid for on-disk prefix
            # isolation across worker processes.
            suffix = f"-{os.getpid()}"
            unique = spec if spec.name.endswith(suffix) else replace(spec, name=spec.name + suffix)
        else:
            # Phase 5: the dynamic per-pid + free_port fallback is gone.  A
            # lifecycle spec with no port must either be on the ledger (by name)
            # or pass an explicit port.
            raise RuntimeError(
                f"lifecycle spec {spec.name!r} has no fixed port: add it to the "
                f"lifecycle ledger (fleet_ports_shared_phase5 — or "
                f"fleet_ports_exclusive for a mutation subject) and serialise with "
                f"@pytest.mark.xdist_group, or pass an explicit port (e.g. "
                f"SHARED_PARSE_PLACEHOLDER_PORT for a parse-only nginx -t check)."
            )
        register_nginx(unique)
        self._names.append(unique.name)
        # Throwaway prefixes accumulate under REGISTRY_ROOT across runs; a
        # stale error.log from a dead prior instance must not satisfy this
        # test's log assertions.  Only wipe when nothing is running there.
        endpoint = endpoint_for(unique)
        if Path(endpoint.prefix).exists() and not Path(endpoint.pidfile).exists():
            shutil.rmtree(endpoint.prefix, ignore_errors=True)
        return unique

    def start(self, spec: NginxInstanceSpec):
        registered = self.register(spec)
        self.launcher.start(registered)
        return endpoint_for(registered)

    def endpoint(self, name: str):
        return endpoint_for(self._spec(name))

    def spec(self, name: str) -> NginxInstanceSpec:
        return self._spec(name)

    def start_registered(self, name: str):
        """Start an instance previously prepared via register()/reconfigure()."""
        spec = self._spec(name)
        self.launcher.start(spec)
        return endpoint_for(spec)

    def nginx_test(self, name: str, check: bool = True) -> subprocess.CompletedProcess:
        return self.launcher.nginx_test(self._spec(name), check=check)

    def reconfigure(self, name: str, template: str | None = None, **template_values):
        """Re-render the instance's config with updated values (or a new template).

        The endpoint (ports, prefix) stays stable; callers follow up with
        ``reload()`` or ``restart()`` to make the new config live.
        """
        spec = self._spec(name)
        changes: dict = {"template_values": {**spec.template_values, **template_values}}
        if template is not None:
            changes["template"] = template
        updated = replace_spec(replace(spec, **changes))
        return self.launcher.render_nginx(updated)

    def reload(self, name: str, check: bool = True) -> subprocess.CompletedProcess:
        return self.launcher.reload(self._spec(name).name, check=check)

    def reopen(self, name: str) -> None:
        self.launcher.reopen(self._spec(name).name)

    def restart(self, name: str) -> None:
        self.launcher.restart(self._spec(name).name)

    def stop(self, name: str) -> None:
        self.launcher.stop(self._spec(name).name)

    def kill_worker(self, name: str, sig: int | signal.Signals = signal.SIGTERM) -> int:
        return self.launcher.kill_worker(self._spec(name).name, sig)

    def process_snapshot(self, name: str):
        return self.launcher.process_snapshot(self._spec(name).name)

    def expect_config_failure(self, spec: NginxInstanceSpec) -> subprocess.CompletedProcess:
        registered = self.register(spec)
        return self.launcher.expect_config_failure(registered)

    def run_cmd(self, argv: Sequence[str], **kwargs) -> subprocess.CompletedProcess:
        return self.launcher.run_cmd(argv, **kwargs)

    def run_privileged_step(self, argv: Sequence[str], **kwargs) -> subprocess.CompletedProcess:
        return self.launcher.run_privileged_step(argv, **kwargs)

    def close(self) -> None:
        for name in reversed(self._names):
            try:
                self.launcher.stop(name)
            except Exception:
                pass
            unregister(name)
        self._names.clear()

    def _spec(self, name: str) -> NginxInstanceSpec:
        suffix = f"-{os.getpid()}"
        candidates = {name, name + suffix}
        for spec in registered_specs():
            if spec.name in candidates:
                return spec
        raise KeyError(f"lifecycle harness does not own a server named {name}")
