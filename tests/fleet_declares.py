"""Static attribution of fleet-server usage to individual test functions.

One source of truth for two consumers:

  * the codemod (``tools/add_registry_markers.py``) that writes the per-test
    ``@pytest.mark.registry_server(...)`` declarations, and
  * the collection-time gate (``conftest._enforce_server_declarations``) that
    hard-fails a test which *uses* a fleet server it did not declare.

Both must agree on "which specs does this test use", so the analysis lives here.

Usage is detected from the ``settings.py`` port constants a test references,
mapped to the owning spec via ``fleet_ports.CONST_TO_SPEC``.  Attribution flows
the way a test actually reaches a port:

  * a constant referenced at MODULE scope is used by every test in the module;
  * a constant referenced inside a fixture is used by every test that names that
    fixture (transitively through fixtures the fixture itself requests);
  * a constant referenced inside a module-level helper is used by every test (or
    fixture) that calls that helper (transitively);
  * a constant referenced in a test's own body / its class body is used by it.

Exempt constants (``fleet_ports.EXEMPT_PORTS`` — synthetic payload ports, dead
upstreams, fixture-launched non-fleet servers) never create a requirement.
"""

from __future__ import annotations

import ast
from dataclasses import dataclass, field

import fleet_ports


DECLARE_MARKERS = ("registry_server", "registry_servers")
LIFECYCLE_MARKER = "uses_lifecycle_harness"


@dataclass
class TestUsage:
    """Per-test attribution result."""

    name: str                       # test function name (bare method name)
    lineno: int                     # def line (1-based)
    col: int                        # def column (for decorator indentation)
    required: set[str] = field(default_factory=set)   # spec names it uses
    declared: set[str] = field(default_factory=set)   # spec names it declares
    is_lifecycle: bool = False
    qualname: str = ""              # "Class::method" for methods, else == name

    def __post_init__(self) -> None:
        if not self.qualname:
            self.qualname = self.name

    @property
    def undeclared(self) -> set[str]:
        return self.required - self.declared


def backbone_specs() -> frozenset[str]:
    """The always-on fleet backbone: specs tagged ``core``.

    These shared servers (the main nginx, the reference xrootd variants, the
    XrdHttp gateway, the pss/tpc bridges) boot every session and are reached
    through session fixtures, so a test never has to declare them.  Only
    *dedicated* specs require a ``registry_server`` marker.  Kept here, beside the
    attribution, so the gate and the codemod share one definition of "free".
    """
    import fleet_specs

    return frozenset(s.name for s in fleet_specs._all_specs() if "core" in s.tags)


def _is_fixture(node) -> bool:
    """True when a def carries a ``@pytest.fixture`` (called or bare) decorator."""
    for dec in node.decorator_list:
        target = dec.func if isinstance(dec, ast.Call) else dec
        if isinstance(target, ast.Attribute) and target.attr == "fixture":
            return True
        if isinstance(target, ast.Name) and target.id == "fixture":
            return True
    return False


def _fixture_reachable_specs(source: str, is_root) -> frozenset[str]:
    """Dedicated specs reachable from every fixture ``is_root`` accepts.

    Resolves each root fixture's settings-constant references transitively
    through the helpers and fixtures it in turn calls or requests, then maps
    the constants to owning specs and drops the always-on backbone.

    Note: this deliberately over-approximates — a kitchen-sink fixture that
    merely builds a URL lookup table pulls in every port it lists — which is the
    safe direction for a boot set (spurious extra server ≫ a missing one).
    """
    try:
        tree = ast.parse(source)
    except SyntaxError:
        return frozenset()
    direct, aliases = _settings_bindings(tree)
    defs: dict[str, object] = {}
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            defs.setdefault(node.name, node)

    def resolve(name: str, seen: set[str]) -> set[str]:
        if name in seen or name not in defs:
            return set()
        seen.add(name)
        node = defs[name]
        scanner = _RefScanner(direct, aliases)
        for child in node.body:
            scanner.visit(child)
        consts = set(scanner.consts)
        for nxt in scanner.calls | _function_params(node):
            consts |= resolve(nxt, seen)
        return consts

    specs: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and is_root(node):
            specs |= _const_specs(resolve(node.name, set()))
    return frozenset(specs) - backbone_specs()


def conftest_fixture_specs(source: str) -> frozenset[str]:
    """Dedicated specs reached through a conftest's session fixtures.

    A test whose file names no port constant can still touch a fleet server
    through a shared fixture (``test_env``, ``ref_xrootd``) that references the
    port itself.  Those fixtures are session infrastructure, so the boot must
    keep their servers up even under subset selection.
    """
    return _fixture_reachable_specs(source, _is_fixture)


def _is_autouse_fixture(node) -> bool:
    """True when a def carries ``@pytest.fixture(..., autouse=True)``."""
    for dec in node.decorator_list:
        if not isinstance(dec, ast.Call):
            continue
        target = dec.func
        if not ((isinstance(target, ast.Attribute) and target.attr == "fixture")
                or (isinstance(target, ast.Name) and target.id == "fixture")):
            continue
        for kw in dec.keywords:
            if (kw.arg == "autouse" and isinstance(kw.value, ast.Constant)
                    and kw.value.value is True):
                return True
    return False


def module_autouse_specs(source: str) -> frozenset[str]:
    """Dedicated specs an ``autouse`` fixture in a test module depends on.

    An autouse fixture makes every collected test in its module (or class)
    depend on the servers it touches, yet no test names the fixture as a
    parameter — so per-test attribution cannot see the dependency and a subset
    boot built purely from declarations would omit the spec, erroring the whole
    module at the fixture's port wait.  The boot set unions these in for every
    module a subset collects from (the gate itself is unaffected: declarations
    still describe what the *test* uses).
    """
    return _fixture_reachable_specs(source, _is_autouse_fixture)


def _settings_bindings(tree: ast.AST) -> tuple[set[str], set[str]]:
    """Return (direct_names, module_aliases).

    ``direct_names``  — names bound by ``from settings import X`` (or ``as Y``).
    ``module_aliases`` — names bound to the settings module itself, so that
    ``<alias>.X`` attribute access resolves (``import settings`` → ``settings``,
    ``import settings as S`` → ``S``).
    """
    direct: set[str] = set()
    aliases: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom):
            mod = (node.module or "").split(".")[-1]
            if mod == "settings":
                for a in node.names:
                    direct.add(a.asname or a.name)
        elif isinstance(node, ast.Import):
            for a in node.names:
                if a.name == "settings" or a.name.endswith(".settings"):
                    aliases.add(a.asname or a.name.split(".")[0])
    return direct, aliases


def _const_specs(names: set[str]) -> set[str]:
    """Map referenced settings-constant names to owning spec names (non-exempt)."""
    return {
        fleet_ports.CONST_TO_SPEC[n]
        for n in names
        if n in fleet_ports.CONST_TO_SPEC and n not in fleet_ports.EXEMPT_PORTS
    }


class _RefScanner(ast.NodeVisitor):
    """Collect, within a subtree, the settings constants referenced and the
    module-level callables (helpers/fixtures) invoked or requested by name."""

    def __init__(self, direct: set[str], aliases: set[str]):
        self.direct = direct
        self.aliases = aliases
        self.consts: set[str] = set()
        self.calls: set[str] = set()

    def visit_Name(self, node: ast.Name) -> None:
        if isinstance(node.ctx, ast.Load) and node.id in self.direct:
            self.consts.add(node.id)
        self.generic_visit(node)

    def visit_Attribute(self, node: ast.Attribute) -> None:
        val = node.value
        if isinstance(val, ast.Name) and val.id in self.aliases:
            self.consts.add(node.attr)
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call) -> None:
        func = node.func
        if isinstance(func, ast.Name):
            self.calls.add(func.id)
        self.generic_visit(node)


def _function_params(node) -> set[str]:
    a = node.args
    return {p.arg for p in (*a.posonlyargs, *a.args, *a.kwonlyargs)
            if p.arg not in ("self", "cls")}


def analyze_source(source: str) -> list[TestUsage]:
    """Attribute fleet-server usage to each test function in a module source.

    Returns one ``TestUsage`` per ``test_*`` function (module-level or inside a
    ``Test*`` class).  Robust to syntax it does not recognise: an unparseable
    module yields an empty list (the caller decides how to treat that).
    """
    try:
        tree = ast.parse(source)
    except SyntaxError:
        return []

    direct, aliases = _settings_bindings(tree)

    # --- module-level callables (helpers + fixtures) and their local refs ----
    # A callable's *own* referenced constants and the callables it in turn calls
    # / requests as fixtures, so requirements can be resolved transitively.
    callable_defs: dict[str, object] = {}
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            callable_defs.setdefault(node.name, node)

    scan_cache: dict[str, _RefScanner] = {}

    def scan(node) -> _RefScanner:
        s = _RefScanner(direct, aliases)
        for child in node.body:
            s.visit(child)
        return s

    def resolve_callable(name: str, seen: set[str]) -> set[str]:
        """Transitive constants a module-level callable pulls in (via its body,
        the helpers it calls, and the fixtures it requests)."""
        if name in seen or name not in callable_defs:
            return set()
        seen.add(name)
        node = callable_defs[name]
        sc = scan_cache.get(name)
        if sc is None:
            sc = scan_cache[name] = scan(node)
        consts = set(sc.consts)
        for nxt in sc.calls | _function_params(node):
            consts |= resolve_callable(nxt, seen)
        return consts

    # --- module-scope references (outside any def/class) apply to every test --
    module_scanner = _RefScanner(direct, aliases)
    for node in tree.body:
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            module_scanner.visit(node)
    module_consts = set(module_scanner.consts)
    for called in set(module_scanner.calls):
        module_consts |= resolve_callable(called, set())

    results: list[TestUsage] = []

    def marker_specs(decorators, module_declared: set[str]) -> set[str]:
        specs = set(module_declared)
        for dec in decorators:
            call = dec if isinstance(dec, ast.Call) else None
            target = call.func if call else dec
            attr = target.attr if isinstance(target, ast.Attribute) else None
            if attr in DECLARE_MARKERS and call:
                for arg in call.args:
                    if isinstance(arg, ast.Constant) and isinstance(arg.value, str):
                        specs.add(arg.value)
        return specs

    def has_lifecycle(decorators) -> bool:
        for dec in decorators:
            target = dec.func if isinstance(dec, ast.Call) else dec
            if isinstance(target, ast.Attribute) and target.attr == LIFECYCLE_MARKER:
                return True
        return False

    # module-level pytestmark = [...] declarations / lifecycle
    module_declared: set[str] = set()
    module_lifecycle = False
    for node in tree.body:
        if isinstance(node, ast.Assign) and any(
            isinstance(t, ast.Name) and t.id == "pytestmark" for t in node.targets
        ):
            marks = node.value.elts if isinstance(node.value, (ast.List, ast.Tuple)) else [node.value]
            module_declared |= marker_specs(marks, set())
            module_lifecycle = module_lifecycle or has_lifecycle(marks)

    def handle_function(node, class_consts: set[str], class_declared: set[str],
                        class_lifecycle: bool, class_name: str | None) -> None:
        if not node.name.startswith("test"):
            return
        sc = scan(node)
        consts = set(sc.consts) | module_consts | class_consts
        for called in sc.calls | _function_params(node):
            consts |= resolve_callable(called, set())
        declared = marker_specs(node.decorator_list, module_declared | class_declared)
        results.append(TestUsage(
            name=node.name,
            lineno=node.lineno,
            col=node.col_offset,
            required=_const_specs(consts),
            declared=declared,
            is_lifecycle=module_lifecycle or class_lifecycle or has_lifecycle(node.decorator_list),
            qualname=f"{class_name}::{node.name}" if class_name else node.name,
        ))

    for node in tree.body:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            handle_function(node, set(), set(), False, None)
        elif isinstance(node, ast.ClassDef):
            # class-body constant refs + class-level markers apply to its methods
            cls_scanner = _RefScanner(direct, aliases)
            cls_declared: set[str] = set()
            cls_lifecycle = False
            for stmt in node.body:
                if isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    continue
                cls_scanner.visit(stmt)
            cls_consts = set(cls_scanner.consts)
            for called in set(cls_scanner.calls):
                cls_consts |= resolve_callable(called, set())
            cls_declared = marker_specs(node.decorator_list, set())
            cls_lifecycle = has_lifecycle(node.decorator_list)
            for stmt in node.body:
                if isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    handle_function(stmt, cls_consts, cls_declared, cls_lifecycle, node.name)

    return results
