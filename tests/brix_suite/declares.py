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

# Still the flat module: the ports consolidation is TS-4 item 8, deferred
# to its own mini-design.  Until then this package member needs the flat
# `tests/` tree on `sys.path`, which every suite entry point already puts
# there.  Named here so the coupling is a recorded debt, not a surprise.
import fleet_ports


DECLARE_MARKERS = ("registry_server", "registry_servers")
LIFECYCLE_MARKER = "uses_lifecycle_harness"


@dataclass
class TestUsage:
    """Per-test attribution result."""

    name: str  # test function name (bare method name)
    lineno: int  # def line (1-based)
    col: int  # def column (for decorator indentation)
    required: set[str] = field(default_factory=set)  # spec names it uses
    declared: set[str] = field(default_factory=set)  # spec names it declares
    is_lifecycle: bool = False
    qualname: str = ""  # "Class::method" for methods, else == name

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


def _parse_source(source: str):
    try:
        return ast.parse(source)
    except SyntaxError:
        return None


def _function_definitions(tree) -> dict[str, object]:
    definitions: dict[str, object] = {}
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            definitions.setdefault(node.name, node)
    return definitions


def _scan_body(node, direct: set[str], aliases: set[str]):
    scanner = _RefScanner(direct, aliases)
    for child in node.body:
        scanner.visit(child)
    return scanner


def _resolve_definition(
    name: str,
    seen: set[str],
    definitions: dict[str, object],
    direct: set[str],
    aliases: set[str],
) -> set[str]:
    if name in seen or name not in definitions:
        return set()
    seen.add(name)
    node = definitions[name]
    scanner = _scan_body(node, direct, aliases)
    constants = set(scanner.consts)
    for dependency in scanner.calls | _function_params(node):
        constants |= _resolve_definition(dependency, seen, definitions, direct, aliases)
    return constants


def _root_fixture_specs(tree, is_root, definitions, direct, aliases) -> set[str]:
    specs: set[str] = set()
    for node in ast.walk(tree):
        is_function = isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
        if is_function and is_root(node):
            constants = _resolve_definition(
                node.name, set(), definitions, direct, aliases
            )
            specs |= _const_specs(constants)
    return specs


def _fixture_reachable_specs(
    source: str, is_root, drop_backbone: bool = True
) -> frozenset[str]:
    """Dedicated specs reachable from every fixture ``is_root`` accepts.

    Resolves each root fixture's settings-constant references transitively
    through the helpers and fixtures it in turn calls or requests, then maps
    the constants to owning specs.  With ``drop_backbone`` (default) the
    always-on backbone is subtracted; boot-set callers pass ``drop_backbone=
    False`` because — since the forced always-on backbone was retired (zero-boot
    default) — a core server reached only through a fixture must still be booted.

    Note: this deliberately over-approximates — a kitchen-sink fixture that
    merely builds a URL lookup table pulls in every port it lists — which is the
    safe direction for a boot set (spurious extra server ≫ a missing one).
    """
    tree = _parse_source(source)
    if tree is None:
        return frozenset()
    direct, aliases = _settings_bindings(tree)
    definitions = _function_definitions(tree)
    specs = _root_fixture_specs(tree, is_root, definitions, direct, aliases)
    result = frozenset(specs)
    return result - backbone_specs() if drop_backbone else result


def conftest_fixture_specs(source: str) -> frozenset[str]:
    """Dedicated specs reached through a conftest's session fixtures.

    A test whose file names no port constant can still touch a fleet server
    through a shared fixture (``test_env``, ``ref_xrootd``) that references the
    port itself.  Those fixtures are session infrastructure, so the boot must
    keep their servers up even under subset selection.
    """
    return _fixture_reachable_specs(source, _is_fixture)


def conftest_fixture_spec_map(source: str) -> dict[str, frozenset[str]]:
    """Map each conftest fixture name to the specs it reaches (backbone KEPT).

    Unlike :func:`conftest_fixture_specs` (which unions every fixture together
    and drops the always-on backbone), this keeps the attribution *per fixture*
    and *keeps* the backbone.  With the forced always-on backbone removed
    (Phase 3, zero-boot default), this is how the boot set discovers that a test
    reaches a server only through a session fixture it requests — including a
    core server it never names by port.  A test's boot contribution is then the
    union over the fixtures in its fixture closure (``item._fixtureinfo``), so a
    test that requests no server fixture (and names no port) boots nothing.

    Fixtures reaching no fleet server are omitted (empty entries carry no boot
    signal).  Attribution flows transitively through the helpers and fixtures a
    root fixture calls/requests, exactly as :func:`_fixture_reachable_specs`.
    """
    tree = _parse_source(source)
    if tree is None:
        return {}
    direct, aliases = _settings_bindings(tree)
    definitions = _function_definitions(tree)
    out: dict[str, frozenset[str]] = {}
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and _is_fixture(
            node
        ):
            constants = _resolve_definition(
                node.name, set(), definitions, direct, aliases
            )
            specs = _const_specs(constants)
            if specs:
                out[node.name] = frozenset(specs)
    return out


def _is_fixture_target(target) -> bool:
    attribute = isinstance(target, ast.Attribute) and target.attr == "fixture"
    name = isinstance(target, ast.Name) and target.id == "fixture"
    return attribute or name


def _is_true_keyword(keyword, name: str) -> bool:
    return (
        keyword.arg == name
        and isinstance(keyword.value, ast.Constant)
        and keyword.value.value is True
    )


def _is_autouse_fixture(node) -> bool:
    """True when a def carries ``@pytest.fixture(..., autouse=True)``."""
    for decorator in node.decorator_list:
        if not isinstance(decorator, ast.Call):
            continue
        if _is_fixture_target(decorator.func):
            return any(
                _is_true_keyword(keyword, "autouse") for keyword in decorator.keywords
            )
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

    Backbone is KEPT here (unlike :func:`conftest_fixture_specs`): with the
    forced always-on backbone retired, an autouse fixture that binds its module
    to a *core* server (e.g. the reference root-TPC xrootd) is the only static
    signal that the boot set must start it, so it must not be subtracted.
    """
    return _fixture_reachable_specs(source, _is_autouse_fixture, drop_backbone=False)


def _add_direct_settings(node: ast.ImportFrom, direct: set[str]) -> None:
    module = (node.module or "").split(".")[-1]
    if module == "settings":
        direct.update(alias.asname or alias.name for alias in node.names)


def _add_settings_aliases(node: ast.Import, aliases: set[str]) -> None:
    for alias in node.names:
        is_settings = alias.name == "settings" or alias.name.endswith(".settings")
        if is_settings:
            aliases.add(alias.asname or alias.name.split(".")[0])


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
            _add_direct_settings(node, direct)
        elif isinstance(node, ast.Import):
            _add_settings_aliases(node, aliases)
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
    return {
        p.arg
        for p in (*a.posonlyargs, *a.args, *a.kwonlyargs)
        if p.arg not in ("self", "cls")
    }


def _cached_scan(
    name: str,
    definitions: dict[str, object],
    direct: set[str],
    aliases: set[str],
    cache: dict[str, _RefScanner],
) -> _RefScanner:
    scanner = cache.get(name)
    if scanner is None:
        scanner = _scan_body(definitions[name], direct, aliases)
        cache[name] = scanner
    return scanner


def _resolve_callable(
    name: str,
    seen: set[str],
    definitions: dict[str, object],
    direct: set[str],
    aliases: set[str],
    cache: dict[str, _RefScanner],
) -> set[str]:
    if name in seen or name not in definitions:
        return set()
    seen.add(name)
    node = definitions[name]
    scanner = _cached_scan(name, definitions, direct, aliases, cache)
    constants = set(scanner.consts)
    for dependency in scanner.calls | _function_params(node):
        constants |= _resolve_callable(
            dependency, seen, definitions, direct, aliases, cache
        )
    return constants


def _resolve_calls(
    calls: set[str],
    definitions: dict[str, object],
    direct: set[str],
    aliases: set[str],
    cache: dict[str, _RefScanner],
) -> set[str]:
    constants: set[str] = set()
    for called in calls:
        constants |= _resolve_callable(
            called, set(), definitions, direct, aliases, cache
        )
    return constants


def _module_constants(
    tree,
    direct: set[str],
    aliases: set[str],
    definitions: dict[str, object],
    cache: dict[str, _RefScanner],
) -> set[str]:
    scanner = _RefScanner(direct, aliases)
    definitions_types = (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)
    for node in tree.body:
        if not isinstance(node, definitions_types):
            scanner.visit(node)
    constants = set(scanner.consts)
    constants |= _resolve_calls(set(scanner.calls), definitions, direct, aliases, cache)
    return constants


def _decorator_call_and_target(decorator):
    if isinstance(decorator, ast.Call):
        return decorator, decorator.func
    return None, decorator


def _attribute_name(target):
    if isinstance(target, ast.Attribute):
        return target.attr
    return None


def _marker_call(decorator):
    call, target = _decorator_call_and_target(decorator)
    attribute = _attribute_name(target)
    if attribute in DECLARE_MARKERS:
        return call
    return None


def _marker_values(call) -> set[str]:
    if call is None:
        return set()
    return {
        argument.value
        for argument in call.args
        if isinstance(argument, ast.Constant) and isinstance(argument.value, str)
    }


def _marker_specs(decorators, inherited: set[str]) -> set[str]:
    specs = set(inherited)
    for decorator in decorators:
        specs |= _marker_values(_marker_call(decorator))
    return specs


def _has_lifecycle(decorators) -> bool:
    for decorator in decorators:
        target = decorator.func if isinstance(decorator, ast.Call) else decorator
        if isinstance(target, ast.Attribute) and target.attr == LIFECYCLE_MARKER:
            return True
    return False


def _is_pytestmark_assignment(node) -> bool:
    if not isinstance(node, ast.Assign):
        return False
    return any(
        isinstance(target, ast.Name) and target.id == "pytestmark"
        for target in node.targets
    )


def _assignment_marks(node):
    if isinstance(node.value, (ast.List, ast.Tuple)):
        return node.value.elts
    return [node.value]


def _module_declarations(tree) -> tuple[set[str], bool]:
    declared: set[str] = set()
    lifecycle = False
    for node in tree.body:
        if not _is_pytestmark_assignment(node):
            continue
        marks = _assignment_marks(node)
        declared |= _marker_specs(marks, set())
        lifecycle = lifecycle or _has_lifecycle(marks)
    return declared, lifecycle


def _function_constants(
    node,
    inherited: set[str],
    direct: set[str],
    aliases: set[str],
    definitions: dict[str, object],
    cache: dict[str, _RefScanner],
) -> set[str]:
    scanner = _scan_body(node, direct, aliases)
    constants = set(scanner.consts) | inherited
    calls = scanner.calls | _function_params(node)
    constants |= _resolve_calls(calls, definitions, direct, aliases, cache)
    return constants


def _test_usage(
    node,
    class_name: str | None,
    inherited_constants: set[str],
    class_declared: set[str],
    class_lifecycle: bool,
    direct: set[str],
    aliases: set[str],
    definitions: dict[str, object],
    cache: dict[str, _RefScanner],
    module_declared: set[str],
    module_lifecycle: bool,
):
    if not node.name.startswith("test"):
        return None
    constants = _function_constants(
        node, inherited_constants, direct, aliases, definitions, cache
    )
    declared = _marker_specs(node.decorator_list, module_declared | class_declared)
    lifecycle = (
        module_lifecycle or class_lifecycle or _has_lifecycle(node.decorator_list)
    )
    qualname = f"{class_name}::{node.name}" if class_name else node.name
    return TestUsage(
        name=node.name,
        lineno=node.lineno,
        col=node.col_offset,
        required=_const_specs(constants),
        declared=declared,
        is_lifecycle=lifecycle,
        qualname=qualname,
    )


def _class_constants(
    node,
    direct: set[str],
    aliases: set[str],
    definitions: dict[str, object],
    cache: dict[str, _RefScanner],
) -> set[str]:
    scanner = _RefScanner(direct, aliases)
    for statement in node.body:
        if not isinstance(statement, (ast.FunctionDef, ast.AsyncFunctionDef)):
            scanner.visit(statement)
    constants = set(scanner.consts)
    constants |= _resolve_calls(set(scanner.calls), definitions, direct, aliases, cache)
    return constants


def _append_usage(results: list[TestUsage], usage) -> None:
    if usage is not None:
        results.append(usage)


def _append_module_function_usage(
    node,
    results,
    module_constants,
    direct,
    aliases,
    definitions,
    cache,
    module_declared,
    module_lifecycle,
) -> None:
    usage = _test_usage(
        node,
        None,
        module_constants,
        set(),
        False,
        direct,
        aliases,
        definitions,
        cache,
        module_declared,
        module_lifecycle,
    )
    _append_usage(results, usage)


def _append_class_usages(
    node,
    results,
    module_constants,
    direct,
    aliases,
    definitions,
    cache,
    module_declared,
    module_lifecycle,
) -> None:
    constants = module_constants | _class_constants(
        node, direct, aliases, definitions, cache
    )
    declared = _marker_specs(node.decorator_list, set())
    lifecycle = _has_lifecycle(node.decorator_list)
    function_types = (ast.FunctionDef, ast.AsyncFunctionDef)
    for statement in node.body:
        if not isinstance(statement, function_types):
            continue
        usage = _test_usage(
            statement,
            node.name,
            constants,
            declared,
            lifecycle,
            direct,
            aliases,
            definitions,
            cache,
            module_declared,
            module_lifecycle,
        )
        _append_usage(results, usage)


def analyze_source(source: str) -> list[TestUsage]:
    """Attribute fleet-server usage to each test function in a module source.

    Returns one ``TestUsage`` per ``test_*`` function (module-level or inside a
    ``Test*`` class).  Robust to syntax it does not recognise: an unparseable
    module yields an empty list (the caller decides how to treat that).
    """
    tree = _parse_source(source)
    if tree is None:
        return []
    direct, aliases = _settings_bindings(tree)
    callable_defs = _function_definitions(tree)
    scan_cache: dict[str, _RefScanner] = {}
    module_consts = _module_constants(tree, direct, aliases, callable_defs, scan_cache)
    module_declared, module_lifecycle = _module_declarations(tree)
    results: list[TestUsage] = []
    for node in tree.body:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            _append_module_function_usage(
                node,
                results,
                module_consts,
                direct,
                aliases,
                callable_defs,
                scan_cache,
                module_declared,
                module_lifecycle,
            )
            continue
        if isinstance(node, ast.ClassDef):
            _append_class_usages(
                node,
                results,
                module_consts,
                direct,
                aliases,
                callable_defs,
                scan_cache,
                module_declared,
                module_lifecycle,
            )
    return results
