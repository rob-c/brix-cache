#!/usr/bin/env python3
"""Guard #14 — a lifecycle spec that reaches the harness names a ledger row.

``LifecycleHarness.register`` (``tests/server_launcher_part3.py``) takes the
port for a spec from the lifecycle ledger BY NAME (``fleet_lifecycle_ports``).
A spec whose name has no row and that carries no explicit ``port=`` raises
``RuntimeError`` -- at its first start, in the fleet, at fixture setup, which
is where race-hunt run 34 halted 9,133 tests in on a new CMS suite whose
manager name had no row.  ``--collect-only`` cannot see it: the name is a
string until the harness looks it up.  ``tests/test_fleet_ports.py`` proves the
ledger consistent with itself; nothing proved the CONSUMERS consistent with
the ledger.

The guard judges statically what ``register`` judges at runtime:

  - a ``NginxInstanceSpec(...)`` constructed inline in ``X.start(...)`` or
    ``X.register(...)``, or bound to a name and handed to one of those later in
    the same function;
  - a wrapper: a top-level function whose started spec takes ``name=`` from one
    of its own parameters.  Every bare-name call of it -- its own module's def
    first, else the tests module it is imported from -- is judged by the
    argument at that slot, positional or keyword; a function that hands its own
    parameter to a wrapper's slot is a wrapper too;
  - names read through module-level string constants.  Any other name
    expression (an f-string, a call, an attribute) is dynamic and left alone:
    the guard cannot prove what it cannot read, so it does not guess.

Not its business: ``port=`` on the spec (the harness's own exemption); a spec
constructed but never started (registry unit tests); a start inside ``with
pytest.raises(...)`` (a negative asserting the very error); a wrapper whose
name is fixed inside it -- ``_mgr(lifecycle, reason, ...)`` in
``test_audit15f_cluster_tuning.py`` passes reasons, not names.

The ledger is always the tree's own (``tests/fleet_lifecycle_ports.py``);
``--root`` moves only the consumers, so the negatives scan a scratch copy.

Fix, when it fires: add a row to ``fleet_ports_shared_phase5`` (or
``fleet_ports_exclusive`` for a mutation subject) and serialise the owning
module with ``@pytest.mark.xdist_group``, or pass an explicit port.
"""
from __future__ import annotations

import argparse
import ast
import sys
from dataclasses import dataclass
from pathlib import Path

TESTS = Path(__file__).resolve().parents[2] / "tests"
sys.path.insert(0, str(TESTS))
from fleet_lifecycle_ports import lifecycle_ports_for  # noqa: E402

SPEC = "NginxInstanceSpec"
#: The harness entry points a spec reaches: `lifecycle.start(spec)`,
#: `harness.register(spec)`.  Anything else `.start(...)` is a thread.
SINKS = {"start", "register"}
_FUNCS = (ast.FunctionDef, ast.AsyncFunctionDef)


# ---------------------------------------------------------------------------
# one module: its constants, top-level defs and `from <tests module> import`s


@dataclass
class Module:
    path: Path
    tree: ast.Module
    consts: dict
    funcs: dict
    imports: dict

    @classmethod
    def load(cls, path: Path, root: Path) -> "Module":
        tree = ast.parse(path.read_text(errors="replace"), str(path))
        funcs = {n.name: n for n in tree.body if isinstance(n, _FUNCS)}
        return cls(path, tree, _consts(tree), funcs, _imports(tree, root))


def _consts(tree: ast.Module) -> dict:
    """`NAME = "literal"` at module scope."""
    out = {}
    for node in tree.body:
        if isinstance(node, ast.Assign) and len(node.targets) == 1 \
                and isinstance(node.targets[0], ast.Name) \
                and isinstance(node.value, ast.Constant) \
                and isinstance(node.value.value, str):
            out[node.targets[0].id] = node.value.value
    return out


def _imports(tree: ast.Module, root: Path) -> dict:
    """bare name -> (module path, original name) for every `from X import y`
    that lands on a module under the scanned root."""
    out = {}
    for node in tree.body:
        if not isinstance(node, ast.ImportFrom) or node.module is None:
            continue
        target = (root / (node.module.replace(".", "/") + ".py")).resolve()
        if target.exists():
            for alias in node.names:
                out[alias.asname or alias.name] = (target, alias.name)
    return out


def _literal(node, consts: dict):
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    if isinstance(node, ast.Name):
        return consts.get(node.id)
    return None


# ---------------------------------------------------------------------------
# one function: the specs it starts, and where their names come from


def _is_spec(node) -> bool:
    if not isinstance(node, ast.Call):
        return False
    fn = node.func
    return (isinstance(fn, ast.Name) and fn.id == SPEC) \
        or (isinstance(fn, ast.Attribute) and fn.attr == SPEC)


def _name_expr(spec: ast.Call):
    """The expression a spec's name comes from; None when `port=` exempts it
    or no name is given."""
    kw = {k.arg: k.value for k in spec.keywords}
    if "port" in kw:
        return None
    if "name" in kw:
        return kw["name"]
    return spec.args[0] if spec.args else None


def _own(fn):
    """fn's own nodes: a nested def is its own scope and is not descended."""
    todo = list(ast.iter_child_nodes(fn))
    while todo:
        node = todo.pop()
        yield node
        if not isinstance(node, _FUNCS):
            todo.extend(ast.iter_child_nodes(node))


def _slot(fn, expr):
    """(positional index or None, name) of the parameter `expr` reads."""
    if not isinstance(expr, ast.Name):
        return None
    positional = [a.arg for a in fn.args.posonlyargs + fn.args.args]
    if expr.id in positional:
        return positional.index(expr.id), expr.id
    if expr.id in {a.arg for a in fn.args.kwonlyargs}:
        return None, expr.id
    return None


def _is_raises(expr) -> bool:
    return isinstance(expr, ast.Call) and isinstance(expr.func, ast.Attribute) \
        and expr.func.attr == "raises"


def _under_raises(fn) -> set:
    """ids of every node inside a `with pytest.raises(...)` block."""
    found = set()
    for node in _own(fn):
        if isinstance(node, ast.With) and any(_is_raises(i.context_expr) for i in node.items):
            found |= {id(n) for n in ast.walk(node)}
    return found


def _bound_specs(fn) -> dict:
    """`spec = NginxInstanceSpec(...)` bindings in fn's own scope."""
    found = {}
    for node in _own(fn):
        if isinstance(node, ast.Assign) and len(node.targets) == 1 \
                and isinstance(node.targets[0], ast.Name) and _is_spec(node.value):
            found[node.targets[0].id] = node.value
    return found


def _is_sink(node) -> bool:
    return isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) \
        and node.func.attr in SINKS and bool(node.args)


def _sunk_arg(mod: Module, node, spec_sinks: dict):
    """The spec `node` hands to the harness, or None.

    Either `X.start(spec)` / `X.register(spec)` directly, or a bare-name call to
    a SPEC SINK — a module-level function that takes a whole spec and hands it
    on.  The second form is not a niceness: `_start_webdav()` in
    `test_impersonation_gridmap_root.py` builds its spec and passes it to a
    local `_render_and_launch(harness, spec)`, so nothing in the name-wrapper
    model above ever saw the construction, and two unledgered names reached the
    fleet with the guard reporting OK.
    """
    if _is_sink(node):
        return node.args[0]
    if not isinstance(node, ast.Call):
        return None
    slot = spec_sinks.get(_target(mod, node))
    return _arg_at(node, slot) if slot else None


def _sunk(fn, mod: Module, spec_sinks: dict):
    """Spec constructions fn hands to the harness, outside any `pytest.raises`
    block — directly or through a spec sink."""
    bound, negated = _bound_specs(fn), _under_raises(fn)
    for node in _own(fn):
        if id(node) in negated:
            continue
        arg = _sunk_arg(mod, node, spec_sinks)
        if _is_spec(arg):
            yield arg
        elif isinstance(arg, ast.Name) and arg.id in bound:
            yield bound[arg.id]


# --- spec sinks: functions that take a whole spec and hand it to the harness --


def _spec_slot(fn):
    """The slot of fn's own parameter that fn hands straight to a sink."""
    for node in _own(fn):
        if _is_sink(node):
            slot = _slot(fn, node.args[0])
            if slot:
                return slot
    return None


def _forwarded_spec_slot(mod: Module, fn, spec_sinks: dict):
    """The slot of fn's own parameter that fn hands to a spec sink's slot."""
    for call in _own(fn):
        if not isinstance(call, ast.Call):
            continue
        slot = spec_sinks.get(_target(mod, call))
        inner = _slot(fn, _arg_at(call, slot)) if slot else None
        if inner:
            return inner
    return None


def _promote_spec_sinks(mods: list, spec_sinks: dict) -> bool:
    """A function that forwards its own parameter into a spec sink's slot is a
    spec sink too.  Returns whether the set grew."""
    grew = False
    for mod in mods:
        for fn in mod.funcs.values():
            if (mod.path, fn.name) in spec_sinks:
                continue
            slot = _forwarded_spec_slot(mod, fn, spec_sinks)
            if slot:
                spec_sinks[(mod.path, fn.name)] = slot
                grew = True
    return grew


def _spec_sink_pass(mods: list) -> dict:
    """{(module path, funcname): slot} for every spec-forwarding function.

    Seeded from the ones that call a sink on their own parameter, then closed
    the same way the name-wrapper set is: one hop is as arbitrary a limit here
    as it was there.  Only module-level defs qualify, so the harness's own
    ``register``/``start`` methods are never mistaken for one.
    """
    sinks = {}
    for mod in mods:
        for fn in mod.funcs.values():
            slot = _spec_slot(fn)
            if slot:
                sinks[(mod.path, fn.name)] = slot
    while _promote_spec_sinks(mods, sinks):
        pass
    return sinks


# ---------------------------------------------------------------------------
# the tree: direct starts, wrappers, and calls through wrappers


def _direct(mod: Module, spec_sinks: dict) -> tuple:
    """(judged (lineno, name, via), wrappers {funcname: slot}) from the specs
    the module's own functions start."""
    judged, wrappers = [], {}
    for fn in (n for n in ast.walk(mod.tree) if isinstance(n, _FUNCS)):
        for spec in _sunk(fn, mod, spec_sinks):
            expr = _name_expr(spec)
            lit = _literal(expr, mod.consts)
            if lit is not None:
                judged.append((spec.lineno, lit, ""))
            elif mod.funcs.get(fn.name) is fn and _slot(fn, expr):
                wrappers[fn.name] = _slot(fn, expr)
    return judged, wrappers


def _target(mod: Module, call: ast.Call):
    """(module path, function name) a bare-name call targets, or None."""
    if not isinstance(call.func, ast.Name):
        return None
    if call.func.id in mod.funcs:
        return (mod.path, call.func.id)
    return mod.imports.get(call.func.id)


def _arg_at(call: ast.Call, slot):
    idx, pname = slot
    if idx is not None and len(call.args) > idx:
        return call.args[idx]
    for kw in call.keywords:
        if kw.arg == pname:
            return kw.value
    return None


def _forwarded_slot(mod: Module, fn, wrappers: dict):
    """The slot of fn's own parameter that fn hands to a wrapper's name slot."""
    for call in _own(fn):
        if not isinstance(call, ast.Call):
            continue
        slot = wrappers.get(_target(mod, call))
        inner = _slot(fn, _arg_at(call, slot)) if slot else None
        if inner:
            return inner
    return None


def _promote(mods: list, wrappers: dict) -> bool:
    """A top-level function that forwards its own parameter into a wrapper's
    name slot is a wrapper too.  Returns whether the set grew."""
    grew = False
    for mod in mods:
        for fn in mod.funcs.values():
            if (mod.path, fn.name) in wrappers:
                continue
            slot = _forwarded_slot(mod, fn, wrappers)
            if slot:
                wrappers[(mod.path, fn.name)] = slot
                grew = True
    return grew


def _through(mod: Module, wrappers: dict) -> list:
    """(lineno, name, via) for every literal name this module passes into a
    wrapper's name slot."""
    judged = []
    for call in ast.walk(mod.tree):
        if not isinstance(call, ast.Call):
            continue
        target = _target(mod, call)
        slot = wrappers.get(target)
        lit = _literal(_arg_at(call, slot), mod.consts) if slot else None
        if lit is not None:
            judged.append((call.lineno, lit, f" via {target[1]}() in {target[0].name}"))
    return judged


def _located(mod: Module, hits: list) -> list:
    return [(mod.path, ln, name, via) for ln, name, via in hits]


def _direct_pass(mods: list, spec_sinks: dict) -> tuple:
    """(judged, wrappers) from every module's own starts."""
    judged, wrappers = [], {}
    for mod in mods:
        direct, own = _direct(mod, spec_sinks)
        judged += _located(mod, direct)
        wrappers.update({(mod.path, f): slot for f, slot in own.items()})
    return judged, wrappers


def _wrapper_pass(mods: list, wrappers: dict) -> list:
    """Judged names passed into wrappers, once the wrapper set is closed."""
    while _promote(mods, wrappers):
        pass
    judged = []
    for mod in mods:
        judged += _located(mod, _through(mod, wrappers))
    return judged


def _audit(root: Path) -> tuple:
    """(every judged (path, lineno, name, via), wrappers)."""
    mods = [Module.load(p, root) for p in sorted(root.rglob("*.py"))]
    judged, wrappers = _direct_pass(mods, _spec_sink_pass(mods))
    judged += _wrapper_pass(mods, wrappers)
    return judged, wrappers


# ---------------------------------------------------------------------------
# verdict


def _report(root: Path, found: list) -> None:
    print("check_lifecycle_spec_ledger: FAIL — a lifecycle spec reaches "
          "LifecycleHarness.register with no ledger row and no port= (a "
          "RuntimeError at its first start, in the fleet, not at collection):")
    for path, lineno, name, via in found:
        print(f"  {path.relative_to(root.parent)}:{lineno} spec {name!r}{via}")
    print("Add a row to fleet_ports_shared_phase5 (fleet_ports_exclusive for a "
          "mutation subject) and serialise the owning module with "
          "@pytest.mark.xdist_group, or pass an explicit port "
          "(SHARED_PARSE_PLACEHOLDER_PORT for a parse-only nginx -t check).  "
          "See this file's docstring.")


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--root", type=Path, default=TESTS,
                    help="tree of consumers to scan (the negative tests point "
                         "this at a scratch copy; the ledger is always the "
                         "real tree's; damaging the real tree to prove a guard "
                         "fires is never acceptable)")
    args = ap.parse_args(argv)
    root = args.root.resolve()
    judged, wrappers = _audit(root)
    found = [hit for hit in judged if lifecycle_ports_for(hit[2])[0] is None]
    if found:
        _report(root, found)
        return 1
    print(f"check_lifecycle_spec_ledger: OK ({len(judged)} spec name(s) judged, "
          f"{len(wrappers)} wrapper(s), every name has a ledger row)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
