#!/usr/bin/env python3
"""Guard #13 — an exec-composed shard is never imported as a module.

``tests/split_continuation.py`` composes a module from shards by compiling each
one into the parent's globals (``load``, ``load_numbered`` and, in ~300 test
modules, ``reexport``).  A shard written for that arrangement may lean on names
the PARENT binds: ``_test_gsi_handshake_helpers_b.py`` calls ``_have``, which
only ``_test_gsi_handshake_helpers.py`` defines.  Composed, that resolves.
Imported as a module, every function in the shard binds the shard's own
globals, and the first call raises ``NameError`` -- at fixture setup, which is
where race-hunt run 33 halted, 9,289 tests in, on a new suite that imported
``pki`` from the shard instead of from its parent.  A collection-only check
cannot see it: the import succeeds, the call fails.

The guard pins the pairing, not the practice.  What an importer pulls out of a
composed shard must not reach -- through the shard's OWN definitions -- a name
the shard resolves at module scope but never binds.  Pulling a self-sufficient
helper out of ``conftest_part3`` is fine and three suites do it; pulling
``pki`` out of a continuation whose ``_have`` is the parent's is a latent
NameError.  A whole-module import is judged by the attributes read through its
alias; a §10.2 self-replacement shim (``sys.modules[__name__] = alias``) uses
nothing.  Modules no parent composes are not the guard's business (ask the
tree, not the name), and a shard that star-imports cannot be proved either
way, so it is left alone.

Guard #10 (``check_shard_entrypoints.py``) owns the census of the ``load``,
``load_numbered`` and inline-exec spellings; this guard reuses it and adds the
``reexport`` spelling that census does not see.

Fix, when it fires: import from the parent named in the report -- it
re-exports everything the shard defines, private helpers included.
"""
from __future__ import annotations

import argparse
import ast
import builtins
import re
import symtable
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from check_shard_entrypoints import _composed_shards  # noqa: E402

TESTS = Path(__file__).resolve().parents[2] / "tests"

#: `from split_continuation import reexport as <alias>`.  Resolve the alias
#: from the import that created it, then look for calls to THAT name.
_REEXPORT_ALIAS = re.compile(
    r"^\s*from\s+split_continuation\s+import\s+reexport\s+as\s+(\w+)", re.M)
#: Cheap prefilter: the module an import line pulls in.
_IMPORT_LINE = re.compile(r"^\s*(?:from\s+([.\w]+)\s+import\b|import\s+([\w.]+))")
_MODULE_DUNDERS = {"__file__", "__name__", "__doc__", "__spec__", "__loader__",
                   "__package__", "__builtins__", "__path__"}
_BUILTINS = set(dir(builtins)) | _MODULE_DUNDERS
_SCOPES = (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)
_COMPOUND = (ast.If, ast.For, ast.While, ast.With, ast.Try)
_BLOCKS = ("body", "orelse", "finalbody")
#: The whole surface of a module: `from x import *`, or an alias used opaquely.
EVERYTHING = "*"


# ---------------------------------------------------------------------------
# census: which files are exec-composed, and by whom


def _reexport_re(alias: str) -> "re.Pattern":
    """`<alias>(globals(), "module_name")`"""
    return re.compile(re.escape(alias) + r'\(\s*globals\(\)\s*,\s*"([^"]+)"\s*\)')


def _reexported_modules(text: str) -> list:
    names = []
    for alias in sorted(set(_REEXPORT_ALIAS.findall(text))):
        names += _reexport_re(alias).findall(text)
    return names


def _reexport_owners(root: Path) -> dict:
    """Map shard path -> the parent that re-exports it."""
    owners = {}
    for parent in sorted(root.rglob("*.py")):
        for name in _reexported_modules(parent.read_text(errors="replace")):
            shard = parent.parent / (name.replace(".", "/") + ".py")
            owners[shard.resolve()] = parent
    return owners


def _all_owners(root: Path) -> dict:
    owners = _composed_shards(root)
    owners.update(_reexport_owners(root))
    return owners


# ---------------------------------------------------------------------------
# the shard: what each top-level name depends on, and which names it never binds


def _has_star_import(tree: ast.Module) -> bool:
    return any(isinstance(node, ast.ImportFrom) and node.names[0].name == "*"
               for node in ast.walk(tree))


def _bound_at_module_scope(table) -> set:
    return {sym.get_name() for sym in table.get_symbols()
            if sym.is_assigned() or sym.is_imported()}


def _declared_globals(table, found: set) -> set:
    """`global x` + assignment anywhere binds x at module scope at runtime."""
    for sym in table.get_symbols():
        if sym.is_declared_global() and sym.is_assigned():
            found.add(sym.get_name())
    for child in table.get_children():
        _declared_globals(child, found)
    return found


def _global_references(table, found: set) -> set:
    """Names this table and every nested one resolve at module scope."""
    for sym in table.get_symbols():
        if sym.is_global() and sym.is_referenced():
            found.add(sym.get_name())
    for child in table.get_children():
        _global_references(child, found)
    return found


def _unbound(table) -> set:
    bound = _bound_at_module_scope(table) | _declared_globals(table, set())
    return _global_references(table, set()) - bound - _BUILTINS


def _names_loaded(*nodes) -> set:
    """Every Name read anywhere under these ast nodes."""
    found = set()
    for node in filter(None, nodes):
        found |= {sub.id for sub in ast.walk(node)
                  if isinstance(sub, ast.Name) and isinstance(sub.ctx, ast.Load)}
    return found


def _header_refs(node) -> set:
    """What a def/class header evaluates at module scope: decorators,
    defaults, annotations, bases."""
    if isinstance(node, ast.ClassDef):
        return _names_loaded(*node.decorator_list, *node.bases, *node.keywords)
    return _names_loaded(*node.decorator_list, node.args, node.returns)


def _body_refs(table, name: str) -> set:
    """Names the scope(s) bound to `name` resolve at module scope."""
    found = set()
    for namespace in table.lookup(name).get_namespaces():
        _global_references(namespace, found)
    return found


def _targets(node) -> set:
    """Names one simple top-level statement binds."""
    if isinstance(node, (ast.Import, ast.ImportFrom)):
        return {(alias.asname or alias.name).split(".")[0] for alias in node.names}
    return {sub.id for sub in ast.walk(node)
            if isinstance(sub, ast.Name) and isinstance(sub.ctx, ast.Store)}


def _statements(nodes):
    """Top-level statements, descending into if/for/while/with/try blocks but
    never into a def or class."""
    for node in nodes:
        yield node
        if isinstance(node, _SCOPES):
            continue
        for field in _BLOCKS:
            yield from _statements(getattr(node, field, []))
        for handler in getattr(node, "handlers", []):
            yield from _statements(handler.body)


def _deps_of(table, node) -> tuple:
    """(names this statement binds, module-scope names they depend on)."""
    if isinstance(node, _SCOPES):
        return {node.name}, _header_refs(node) | _body_refs(table, node.name)
    if isinstance(node, _COMPOUND):
        return set(), set()          # its statements are visited on their own
    return _targets(node), _names_loaded(node)


def _analyse(path: Path):
    """(deps, unbound) for a shard; None when a star-import makes it unprovable."""
    src = path.read_text(errors="replace")
    tree = ast.parse(src, str(path))
    if _has_star_import(tree):
        return None
    table = symtable.symtable(src, str(path), "exec")
    deps = {}
    for node in _statements(tree.body):
        bound, refs = _deps_of(table, node)
        for name in bound:
            deps.setdefault(name, set()).update(refs)
    return deps, _unbound(table)


def _reaches(deps: dict, unbound: set, start) -> set:
    """Unbound names reachable from `start` through the shard's definitions."""
    seen, todo, found = set(), list(start), set()
    while todo:
        name = todo.pop()
        if name in seen:
            continue
        seen.add(name)
        if name in unbound:
            found.add(name)
        todo.extend(deps.get(name, ()))
    return found


# ---------------------------------------------------------------------------
# the importer: which composed shards it pulls in, and what it takes from them


def _landing(importer: Path, root: Path, module: str, level: int) -> list:
    """Where an import of `module` from this file would land: relative to the
    importer for a dotted-from import, else sibling-first, then root."""
    rest = module.replace(".", "/") + ".py"
    if level:
        return [(importer.parents[level - 1] / rest).resolve()]
    return list(dict.fromkeys([(importer.parent / rest).resolve(),
                               (root / rest).resolve()]))


def _candidate(importer: Path, root: Path, owners: dict) -> bool:
    """Regex prefilter so only files that name a composed shard are parsed."""
    for line in importer.read_text(errors="replace").splitlines():
        match = _IMPORT_LINE.match(line)
        if not match:
            continue
        module = match.group(1) or match.group(2)
        level = len(module) - len(module.lstrip("."))
        if any(t in owners for t in _landing(importer, root, module.lstrip("."), level)):
            return True
    return False


def _is(node, name: str) -> bool:
    return isinstance(node, ast.Name) and node.id == name


def _self_replacement(node, alias: str) -> bool:
    """`sys.modules[__name__] = alias` -- a §10.2 shim handing its name over."""
    return (isinstance(node, ast.Assign) and _is(node.value, alias)
            and any(isinstance(t, ast.Subscript) and _is(t.slice, "__name__")
                    for t in node.targets))


def _held(tree: ast.Module, alias: str) -> tuple:
    """(attributes read through the alias, ids of the Name nodes that do so or
    that a shim's self-replacement consumes)."""
    attrs, held = set(), set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Attribute) and _is(node.value, alias):
            attrs.add(node.attr)
            held.add(id(node.value))
        elif _self_replacement(node, alias):
            held.add(id(node.value))
    return attrs, held


def _uses_of(tree: ast.Module, alias: str):
    """What a whole-module import takes: the attributes read through its
    alias, or EVERYTHING once the module object is used any other way."""
    attrs, held = _held(tree, alias)
    opaque = any(_is(node, alias) and id(node) not in held
                 for node in ast.walk(tree))
    return EVERYTHING if opaque else attrs


def _shards_of(node, importer: Path, root: Path, owners: dict) -> list:
    """(alias binding, shard path) for every module this statement imports
    that is a composed shard."""
    if isinstance(node, ast.ImportFrom):
        if node.module is None:
            return []
        return [(None, t) for t in _landing(importer, root, node.module, node.level)
                if t in owners]
    return [(alias.asname or alias.name, t) for alias in node.names
            for t in _landing(importer, root, alias.name, 0) if t in owners]


def _surface(node, tree: ast.Module, binding):
    """The names an import statement takes from the shard."""
    if isinstance(node, ast.ImportFrom):
        names = {alias.name for alias in node.names}
        return EVERYTHING if "*" in names else names
    if "." in binding:
        return EVERYTHING        # `import a.b.c` with no alias: used by path
    return _uses_of(tree, binding)


def _imports_in(importer: Path, root: Path, owners: dict) -> list:
    """(lineno, shard, surface) for every import statement that lands on a
    composed shard."""
    tree = ast.parse(importer.read_text(errors="replace"), str(importer))
    found = []
    for node in ast.walk(tree):
        if not isinstance(node, (ast.Import, ast.ImportFrom)):
            continue
        for binding, shard in _shards_of(node, importer, root, owners):
            if shard != importer.resolve():
                found.append((node.lineno, shard, _surface(node, tree, binding)))
    return found


# ---------------------------------------------------------------------------
# verdict


def _reached(analysed: dict, shard: Path, surface) -> set:
    """Parent-bound names the imported surface reaches inside the shard."""
    if shard not in analysed:
        analysed[shard] = _analyse(shard) if shard.exists() else None
    if analysed[shard] is None:
        return set()
    deps, unbound = analysed[shard]
    start = set(deps) | unbound if surface == EVERYTHING else set(surface)
    return _reaches(deps, unbound, start)


def _offending(root: Path, owners: dict) -> tuple:
    """(offending hits, number of direct imports judged)."""
    analysed, found, judged = {}, [], 0
    for importer in sorted(root.rglob("*.py")):
        if not _candidate(importer, root, owners):
            continue
        for lineno, shard, surface in _imports_in(importer, root, owners):
            judged += 1
            reached = _reached(analysed, shard, surface)
            if reached:
                found.append((importer, lineno, shard, surface, reached))
    return found, judged


def _spell(surface) -> str:
    return "*" if surface == EVERYTHING else ", ".join(sorted(surface))


def _report(root: Path, owners: dict, found: list) -> None:
    print("check_shard_direct_imports: FAIL — an exec-composed shard is imported "
          "as a module, and what is taken from it reaches names only its parent "
          "binds (a NameError on first call):")
    for importer, lineno, shard, surface, reached in found:
        print(f"  {importer.relative_to(root.parent)}:{lineno} imports "
              f"{_spell(surface)} from {shard.relative_to(root.parent)}")
        print(f"    composed by {owners[shard].relative_to(root.parent)}; "
              f"reaches unbound: {', '.join(sorted(reached))}")
    print("Import from the parent instead: it re-exports everything the shard "
          "defines, private helpers included.  See this file's docstring.")


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--root", type=Path, default=TESTS,
                    help="tree to scan (the negative tests point this at a "
                         "scratch copy; damaging the real tree to prove a "
                         "guard fires is never acceptable)")
    args = ap.parse_args(argv)
    root = args.root.resolve()
    owners = _all_owners(root)
    found, judged = _offending(root, owners)
    if found:
        _report(root, owners, found)
        return 1
    print(f"check_shard_direct_imports: OK ({len(owners)} composed shard(s), "
          f"{judged} direct import(s) judged, none reaches a parent-bound name)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
