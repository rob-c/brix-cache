"""Detect tests that use servers they did not declare."""

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

    def usage_for(self, path: Path) -> TestUsage:
        return analyze_source(path)

    def specs_to_boot(self, files: Iterable[Path]) -> List[str]:
        """The minimal fleet for this selection: every spec any file
        reaches, closed over ``depends_on``, in registry order."""
        needed, parse_error = self._needed_specs(files)
        if parse_error:
            return [spec.name for spec in self.registry.all_specs()]
        known = {spec.name for spec in self.registry.all_specs()}
        closed = self._dependency_closure(needed & known)
        return [spec.name for spec in self.registry.all_specs() if spec.name in closed]

    def _needed_specs(self, files: Iterable[Path]) -> tuple[Set[str], bool]:
        needed: Set[str] = set()
        for path in files:
            usage = self.usage_for(path)
            if usage.parse_error:
                return needed, True
            needed |= self.map.specs_for(usage)
        return needed, False

    def _dependency_closure(self, needed: Set[str]) -> Set[str]:
        closed: Set[str] = set()
        frontier = list(needed)
        while frontier:
            name = frontier.pop()
            if name in closed:
                continue
            closed.add(name)
            frontier.extend(self.registry.get_spec(name).depends_on)
        return closed

    def check(self, files: Iterable[Path]) -> Sequence[str]:
        """Analyze the selection; returns report lines (empty = clean).
        In ``enforce`` mode a dirty selection raises ``GateViolation``."""
        if self.mode == "off":
            return ()
        self._violations = self._find_violations(files)
        if not self._violations:
            return ()
        report = self.report_lines()
        self._raise_enforced(report)
        return report

    def _find_violations(self, files: Iterable[Path]) -> Dict[str, Set[str]]:
        violations = {}
        known = {spec.name for spec in self.registry.all_specs()}
        for path in files:
            usage = self.usage_for(path)
            if usage.parse_error:
                continue
            undeclared = self.map.undeclared(usage) & known
            if undeclared:
                violations[str(path)] = undeclared
        return violations

    def _raise_enforced(self, report: Sequence[str]) -> None:
        if self.mode == "enforce":
            first_file = min(self._violations)
            raise GateViolation(
                first_file,
                sorted(self._violations[first_file]),
                "\n".join(report),
            )

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
        """Describe how one test file reaches server declarations."""
        usage = self.usage_for(Path(path))
        if usage.parse_error:
            return "%s: unanalyzable (%s) — treated as needing every spec" % (
                path, usage.parse_error,
            )
        known = {spec.name for spec in self.registry.all_specs()}
        via_fixture = self._fixture_servers(usage, known)
        via_ports = self._port_servers(usage, known)
        undeclared = sorted(self.map.undeclared(usage) & known)
        lines = [
            str(path),
            "  declared (markers):   %s" % (", ".join(sorted(usage.declared)) or "—"),
            "  reached via fixtures: %s" % (", ".join(via_fixture) or "—"),
            "  reached via ports:    %s" % (", ".join(via_ports) or "—"),
            "  backbone (always):    %s" % (", ".join(sorted(self.map.backbone)) or "—"),
            "  verdict: %s"
            % ("undeclared: %s" % ", ".join(undeclared) if undeclared else "clean"),
        ]
        return "\n".join(lines)

    def _fixture_servers(self, usage: TestUsage, known: Set[str]) -> List[str]:
        return sorted(
            {s for f in usage.fixtures_used for s in self.map.fixture_specs.get(f, ())} & known
        )

    def _port_servers(self, usage: TestUsage, known: Set[str]) -> List[str]:
        return sorted(
            {self.map.port_name_specs[n] for n in usage.names_used
             if n in self.map.port_name_specs} & known
        )
