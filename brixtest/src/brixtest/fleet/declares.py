"""Static analysis of the server instances used by each test module.

Four channels tell BriXTest which instances a test file needs, in
priority order:

1. **markers**   — ``@pytest.mark.registry_server("name")`` /
   ``registry_servers([...])`` on tests, classes, or ``pytestmark``.
2. **fixtures**  — the adapter maps fixture names to the specs they
   reach (``fixture_specs``).
3. **port names**— the adapter maps named-port constants to the spec
   that listens there (``port_name_specs``); a file that references
   ``WEBDAV_PORT`` needs that server even without a marker.
4. **backbone**  — specs every session needs regardless (``backbone``).

The adapter supplies the maps for project-specific fixtures and constants.
Analysis uses the AST without importing the test file and is cached on
``(st_mtime_ns, st_size)`` plus a schema stamp so an analyzer upgrade
invalidates every cached row at once.
"""

from __future__ import annotations

import ast
import dataclasses
import threading
from pathlib import Path
from typing import Dict, FrozenSet, Mapping, Sequence, Set, Tuple

__all__ = ["DECLARE_MARKERS", "DeclarationMap", "TestUsage", "analyze_source"]

DECLARE_MARKERS: Tuple[str, ...] = ("registry_server", "registry_servers")
_ANALYSIS_SCHEMA = 1

_cache: Dict[str, Tuple[Tuple[int, int, int], "TestUsage"]] = {}
_cache_lock = threading.Lock()


@dataclasses.dataclass(frozen=True)
class TestUsage:
    """What one test file was seen to reference, channel by channel."""

    path: str
    declared: FrozenSet[str]        # channel 1: marker arguments
    fixtures_used: FrozenSet[str]   # channel 2 input: test-function parameters
    names_used: FrozenSet[str]      # channel 3 input: bare/attribute identifiers
    parse_error: str = ""           # non-empty: fall back to "needs everything"


def _marker_names(call: ast.Call) -> Set[str]:
    names: Set[str] = set()
    for arg in call.args:
        names.update(_literal_names(arg))
    return names


def _literal_names(node: ast.AST) -> Set[str]:
    if isinstance(node, ast.Constant):
        return {node.value} if isinstance(node.value, str) else set()
    if isinstance(node, (ast.List, ast.Tuple)):
        return {value.value for value in node.elts if _is_string_literal(value)}
    return set()


def _is_string_literal(node: ast.AST) -> bool:
    return isinstance(node, ast.Constant) and isinstance(node.value, str)


def _is_declare_marker(node: ast.expr) -> bool:
    # matches pytest.mark.<m>(...) and mark.<m>(...) for m in DECLARE_MARKERS
    if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
        return node.func.attr in DECLARE_MARKERS
    return False


class _Visitor(ast.NodeVisitor):
    def __init__(self) -> None:
        self.declared: Set[str] = set()
        self.fixtures: Set[str] = set()
        self.names: Set[str] = set()

    def _harvest_decorators(self, node) -> None:
        for decorator in node.decorator_list:
            if _is_declare_marker(decorator):
                self.declared |= _marker_names(decorator)  # type: ignore[arg-type]

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        self._harvest_decorators(node)
        if node.name.startswith("test") or node.name.endswith("fixture"):
            for arg in node.args.args + node.args.kwonlyargs:
                self.fixtures.add(arg.arg)
        self.generic_visit(node)

    visit_AsyncFunctionDef = visit_FunctionDef  # type: ignore[assignment]

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        self._harvest_decorators(node)
        self.generic_visit(node)

    def visit_Assign(self, node: ast.Assign) -> None:
        targets = [t.id for t in node.targets if isinstance(t, ast.Name)]
        if "pytestmark" in targets:
            for candidate in ast.walk(node.value):
                if _is_declare_marker(candidate):
                    self.declared |= _marker_names(candidate)  # type: ignore[arg-type]
        self.generic_visit(node)

    def visit_Name(self, node: ast.Name) -> None:
        self.names.add(node.id)

    def visit_Attribute(self, node: ast.Attribute) -> None:
        self.names.add(node.attr)
        self.generic_visit(node)


def analyze_source(path: Path) -> TestUsage:
    """AST-scan one test file; cached on (mtime_ns, size, schema)."""
    path = Path(path)
    try:
        stat = path.stat()
        key = (stat.st_mtime_ns, stat.st_size, _ANALYSIS_SCHEMA)
    except OSError as exc:
        return TestUsage(str(path), frozenset(), frozenset(), frozenset(), str(exc))
    with _cache_lock:
        cached = _cache.get(str(path))
        if cached is not None and cached[0] == key:
            return cached[1]
    try:
        tree = ast.parse(path.read_text(), filename=str(path))
    except (OSError, SyntaxError) as exc:
        usage = TestUsage(str(path), frozenset(), frozenset(), frozenset(), str(exc))
    else:
        visitor = _Visitor()
        visitor.visit(tree)
        usage = TestUsage(
            str(path),
            frozenset(visitor.declared),
            frozenset(visitor.fixtures),
            frozenset(visitor.names),
        )
    with _cache_lock:
        _cache[str(path)] = (key, usage)
    return usage


class DeclarationMap:
    """The adapter's three maps, resolved against a file's ``TestUsage``."""

    def __init__(
        self,
        *,
        fixture_specs: Mapping[str, Sequence[str]] = (),
        port_name_specs: Mapping[str, str] = (),
        backbone: Sequence[str] = (),
    ) -> None:
        self.fixture_specs = dict(fixture_specs)
        self.port_name_specs = dict(port_name_specs)
        self.backbone = tuple(backbone)

    def specs_for(self, usage: TestUsage) -> Set[str]:
        """Every spec the file reaches, across all four channels."""
        needed: Set[str] = set(self.backbone)
        needed |= usage.declared
        for fixture in usage.fixtures_used:
            needed.update(self.fixture_specs.get(fixture, ()))
        for name in usage.names_used:
            spec = self.port_name_specs.get(name)
            if spec:
                needed.add(spec)
        return needed

    def undeclared(self, usage: TestUsage) -> Set[str]:
        """Specs reached through channels 2-3 but not declared via markers.

        This is what the gate reports: the test *touches* the server
        (fixture or port constant) yet never declared it, so a
        selective fleet boot would strand it.
        """
        reached: Set[str] = set()
        for fixture in usage.fixtures_used:
            reached.update(self.fixture_specs.get(fixture, ()))
        for name in usage.names_used:
            spec = self.port_name_specs.get(name)
            if spec:
                reached.add(spec)
        return reached - set(usage.declared) - set(self.backbone)
