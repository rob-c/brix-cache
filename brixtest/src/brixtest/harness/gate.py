"""The undeclared-server gate (feature F5, second half).

Selective fleet boot only works if every test's server needs are
declared; the gate is what makes an omission a *named finding* instead
of a mystery hang.  Three modes:

- ``enforce`` — an undeclared reach fails collection with the report;
- ``warn``    — the report prints, the run continues (migration mode);
- ``off``     — analysis is skipped entirely.

The report's shape is inherited from the grown suite's gate output,
which already met the C1 bar: name the file, name the servers, name
the channel that caught each, end with the action.
"""

from __future__ import annotations

from pathlib import Path
from typing import Dict, Iterable, List, Sequence, Set

from brixtest.errors import GateViolation, SpecError
from brixtest.fleet.declares import DeclarationMap, TestUsage, analyze_source
from brixtest.fleet.registry import Registry

__all__ = ["UndeclaredServerGate"]

_MODES = ("enforce", "warn", "off")


class UndeclaredServerGate:
    def __init__(
        self,
        registry: Registry,
        declaration_map: DeclarationMap,
        *,
        mode: str = "enforce",
    ) -> None:
        if mode not in _MODES:
            raise SpecError("gate mode", mode, "one of: %s" % ", ".join(_MODES))
        self.registry = registry
        self.map = declaration_map
        self.mode = mode
        self._violations: Dict[str, Set[str]] = {}

    # -- analysis --------------------------------------------------------

    def usage_for(self, path: Path) -> TestUsage:
        return analyze_source(path)

    def specs_to_boot(self, files: Iterable[Path]) -> List[str]:
        """The minimal fleet for this selection: every spec any file
        reaches, closed over ``depends_on``, in registry order."""
        needed: Set[str] = set()
        for path in files:
            usage = self.usage_for(path)
            if usage.parse_error:
                # an unanalyzable file needs everything — honesty over optimism
                return [spec.name for spec in self.registry.all_specs()]
            needed |= self.map.specs_for(usage)
        needed &= {spec.name for spec in self.registry.all_specs()}
        closed: Set[str] = set()
        frontier = list(needed)
        while frontier:
            name = frontier.pop()
            if name in closed:
                continue
            closed.add(name)
            frontier.extend(self.registry.get_spec(name).depends_on)
        return [spec.name for spec in self.registry.all_specs() if spec.name in closed]

    # -- the gate itself -------------------------------------------------

    def check(self, files: Iterable[Path]) -> Sequence[str]:
        """Analyze the selection; returns report lines (empty = clean).
        In ``enforce`` mode a dirty selection raises ``GateViolation``."""
        if self.mode == "off":
            return ()
        self._violations = {}
        for path in files:
            usage = self.usage_for(path)
            if usage.parse_error:
                continue
            undeclared = self.map.undeclared(usage) & {
                spec.name for spec in self.registry.all_specs()
            }
            if undeclared:
                self._violations[str(path)] = undeclared
        if not self._violations:
            return ()
        report = self.report_lines()
        if self.mode == "enforce":
            first_file = sorted(self._violations)[0]
            raise GateViolation(
                first_file,
                sorted(self._violations[first_file]),
                "\n".join(report),
            )
        return report

    def report_lines(self) -> List[str]:
        lines = ["undeclared server usage — the selective boot would strand these tests:"]
        for path in sorted(self._violations):
            servers = ", ".join(sorted(self._violations[path]))
            lines.append("  %s reaches [%s] without declaring them" % (path, servers))
        lines.append(
            "— try: add @pytest.mark.registry_server(\"<name>\") "
            "(or registry_servers([...])) to each file above"
        )
        return lines

    def explain(self, path: Path) -> str:
        """The CLI's ``gate explain <file>``: every channel, narrated."""
        usage = self.usage_for(Path(path))
        if usage.parse_error:
            return "%s: unanalyzable (%s) — treated as needing every spec" % (
                path, usage.parse_error,
            )
        known = {spec.name for spec in self.registry.all_specs()}
        lines = [str(path)]
        lines.append("  declared (markers):   %s" % (", ".join(sorted(usage.declared)) or "—"))
        via_fixture = sorted(
            {s for f in usage.fixtures_used for s in self.map.fixture_specs.get(f, ())} & known
        )
        lines.append("  reached via fixtures: %s" % (", ".join(via_fixture) or "—"))
        via_ports = sorted(
            {self.map.port_name_specs[n] for n in usage.names_used
             if n in self.map.port_name_specs} & known
        )
        lines.append("  reached via ports:    %s" % (", ".join(via_ports) or "—"))
        lines.append("  backbone (always):    %s" % (", ".join(sorted(self.map.backbone)) or "—"))
        undeclared = sorted(self.map.undeclared(usage) & known)
        lines.append(
            "  verdict: %s"
            % ("undeclared: %s" % ", ".join(undeclared) if undeclared else "clean")
        )
        return "\n".join(lines)
