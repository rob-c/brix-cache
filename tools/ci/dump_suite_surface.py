#!/usr/bin/env python3
"""Emit the flat-import surface of tests/ infra as JSON + markdown.

TS-0 of docs/refactor/testsuite-modernization-plan.md: before any shim
exists, freeze (a) every public name each flat infra module defines and
(b) every `import X` / `from X import y` of a flat infra name across the
whole suite, keyed by importer.  The JSON sidecar is the ground truth the
shim-completeness guard (TS-3, guard #3) verifies shims against; the
markdown is the human summary.

Names a shard module *uses* at top level but never defines or imports
(the `fleet_specs.py:405` exec pattern — e.g. `fleet_specs_part2._data`)
are reported as ``shard_implicit``, never as public surface.

A §10.2 shim (`sys.modules[__name__] = <canonical>`) has no surface of its
own: what `import <flat name>` yields is the canonical module's namespace.
For those the surface is taken by importing the canonical module in a
SUBPROCESS (isolating its import-time side effects from this tool) and
introspecting it — which is also migration-proof, since it does not care
how many files the canonical body was split across.

Output is deterministic (sorted, no timestamps): re-running is a no-op
diff, and ``--check`` verifies exactly that without writing.
"""

from __future__ import annotations

import argparse
import ast
import builtins
import json
import subprocess
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
PACKAGES = ("lib_py", "cmdscripts", "lib")
SRC = REPO / "brixtest" / "src"
_BUILTINS = frozenset(dir(builtins)) | {
    "__file__", "__name__", "__doc__", "__spec__", "__loader__",
    "__package__", "__builtins__",
}


def infra_module_names(tests_root: Path) -> list:
    """Flat stems (non-test top-level .py) plus package submodules."""
    flat = [path.stem for path in tests_root.glob("*.py") if _flat_infra(path)]
    nested = [name for package in PACKAGES for name in _package_modules(tests_root, package)]
    return sorted(flat) + sorted(nested)


def _flat_infra(path):
    return path.stem.isidentifier() and not path.stem.startswith(("test_", "_test_"))


def _package_modules(tests_root, package):
    directory = tests_root / package
    if not directory.is_dir():
        return []
    return [
        f"{package}.{path.stem}" for path in directory.glob("*.py")
        if path.stem.isidentifier() and path.stem != "__init__"
    ]


def _module_path(tests_root: Path, name: str) -> Path:
    return tests_root.joinpath(*name.split(".")).with_suffix(".py")


def public_surface(path: Path) -> dict:
    tree = ast.parse(path.read_text(), filename=str(path))
    out = {"functions": [], "classes": [], "constants": [],
           "variables": [], "shard_implicit": []}
    defined = set()
    for node in tree.body:
        _record_public_node(node, out, defined)
    used, bound = _used_and_bound(tree, defined)
    out["shard_implicit"] = sorted(used - bound - _BUILTINS)
    for key in ("functions", "classes", "constants", "variables"):
        out[key] = sorted(set(out[key]))
    return out


def _record_public_node(node, surface, defined):
    if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
        surface["functions"].append(node.name)
        defined.add(node.name)
    elif isinstance(node, ast.ClassDef):
        surface["classes"].append(node.name)
        defined.add(node.name)
    elif isinstance(node, (ast.Assign, ast.AnnAssign)):
        _record_assignments(node, surface, defined)
    elif isinstance(node, (ast.Import, ast.ImportFrom)):
        defined.update(_alias_names(node.names))


def _record_assignments(node, surface, defined):
    targets = node.targets if isinstance(node, ast.Assign) else [node.target]
    for target in targets:
        if isinstance(target, ast.Name):
            bucket = "constants" if target.id.isupper() else "variables"
            surface[bucket].append(target.id)
            defined.add(target.id)


def _alias_names(aliases):
    return {(alias.asname or alias.name).split(".")[0] for alias in aliases}


def _used_and_bound(tree, defined):
    used, bound = set(), set(defined)
    for sub in ast.walk(tree):
        _record_usage(sub, used, bound)
    return used, bound


def _record_usage(node, used, bound):
    if isinstance(node, ast.Name):
        target = used if isinstance(node.ctx, ast.Load) else bound
        target.add(node.id)
    elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
        bound.add(node.name)
    elif isinstance(node, ast.arg):
        bound.add(node.arg)
    elif isinstance(node, ast.ExceptHandler) and node.name:
        bound.add(node.name)
    elif isinstance(node, (ast.Global, ast.Nonlocal)):
        bound.update(node.names)
    elif isinstance(node, (ast.Import, ast.ImportFrom)):
        bound.update(_alias_names(node.names))


def shim_target(path: Path) -> str | None:
    """The canonical dotted module a §10.2 shim replaces itself with.

    Recognises ``sys.modules[__name__] = <name>`` where ``<name>`` was
    bound by ``import a.b as <name>`` or ``from a import <name>``.
    Returns None for an ordinary module.
    """
    try:
        tree = ast.parse(path.read_text(), filename=str(path))
    except SyntaxError:
        return None
    bindings = _import_bindings(tree)
    for node in ast.walk(tree):
        target = _shim_assignment(node, bindings)
        if target:
            return target
    return None


def _import_bindings(tree):
    bindings = {}
    for node in ast.walk(tree):
        _record_import_binding(node, bindings)
    return bindings


def _record_import_binding(node, bindings):
    if isinstance(node, ast.Import):
        for alias in node.names:
            bindings[alias.asname or alias.name.split(".")[0]] = alias.name
    elif isinstance(node, ast.ImportFrom) and node.module and node.level == 0:
        for alias in node.names:
            bindings[alias.asname or alias.name] = f"{node.module}.{alias.name}"


def _shim_assignment(node, bindings):
    if not isinstance(node, ast.Assign) or not isinstance(node.value, ast.Name):
        return None
    for target in node.targets:
        if _is_modules_subscript(target):
            return bindings.get(node.value.id)
    return None


def _is_modules_subscript(target):
    return (isinstance(target, ast.Subscript)
            and isinstance(target.value, ast.Attribute)
            and target.value.attr == "modules")


# Introspect the canonical module in a child process: its import-time side
# effects (env republish, TMPDIR pin) must not leak into this tool, and a
# crash there must not be silently read as "no surface".
_INTROSPECT = r"""
import json, sys, types
sys.path.insert(0, %(src)r)
sys.path.insert(0, %(tests)r)
mod = __import__(%(name)r, fromlist=["*"])
out = {"functions": [], "classes": [], "constants": [],
       "variables": [], "shard_implicit": []}
pkg = %(name)r.split(".")[0]
for key, value in vars(mod).items():
    if key.startswith("__") and key.endswith("__"):
        continue
    if isinstance(value, types.ModuleType):
        continue
    owner = getattr(value, "__module__", None)
    if owner is not None and owner.split(".")[0] not in (pkg, "builtins"):
        continue          # re-exported from elsewhere; not this module's surface
    if isinstance(value, type):
        out["classes"].append(key)
    elif callable(value):
        out["functions"].append(key)
    elif key.isupper():
        out["constants"].append(key)
    else:
        out["variables"].append(key)
for k in out:
    out[k] = sorted(set(out[k]))
print(json.dumps(out))
"""


def canonical_surface(name: str, tests_root: Path) -> dict:
    """Runtime surface of a shim's canonical module (subprocess-isolated)."""
    code = _INTROSPECT % {"src": str(SRC), "tests": str(tests_root), "name": name}
    proc = subprocess.run([sys.executable, "-c", code],
                          capture_output=True, text=True)
    if proc.returncode != 0:
        raise SystemExit("dump_suite_surface: cannot introspect shim target %s:\n%s"
                         % (name, proc.stderr.strip()))
    return json.loads(proc.stdout)


def importers(tests_root: Path, infra: list) -> dict:
    """{infra_name: {importer_relpath: [imported_names]}}."""
    roots = {name.split(".")[0] for name in infra} | set(PACKAGES)
    known = set(infra) | set(PACKAGES)
    edges: dict = {}
    for path in sorted(tests_root.rglob("*.py")):
        _record_importer(path, tests_root, roots, known, edges)
    _sort_edges(edges)
    return edges


def _record_importer(path, tests_root, roots, known, edges):
    try:
        tree = ast.parse(path.read_text(), filename=str(path))
    except SyntaxError:
        return
    relative = path.relative_to(tests_root).as_posix()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            _record_direct_imports(node, relative, roots, known, edges)
        elif isinstance(node, ast.ImportFrom):
            _record_from_imports(node, relative, roots, known, edges)


def _record_direct_imports(node, relative, roots, known, edges):
    for alias in node.names:
        if alias.name.split(".")[0] in roots and alias.name in known:
            bucket = edges.setdefault(alias.name, {}).setdefault(relative, [])
            _add(bucket, "<module>")


def _record_from_imports(node, relative, roots, known, edges):
    if node.level != 0 or not node.module:
        return
    root = node.module.split(".")[0]
    if root not in roots:
        return
    target = _known_import_target(node.module, root, known)
    if target is None:
        return
    bucket = edges.setdefault(target, {}).setdefault(relative, [])
    for alias in node.names:
        _add(bucket, alias.name)


def _known_import_target(module, root, known):
    if module in known:
        return module
    return root if root in known else None


def _sort_edges(edges):
    for module in edges.values():
        for relative in module:
            module[relative] = sorted(set(module[relative]))


def _add(bucket: list, name: str) -> None:
    if name not in bucket:
        bucket.append(name)


def build_inventory(tests_root: Path) -> dict:
    infra = infra_module_names(tests_root)
    surface = {}
    for name in infra:
        path = _module_path(tests_root, name)
        target = shim_target(path)
        if target is not None:
            surface[name] = canonical_surface(target, tests_root)
            continue
        try:
            surface[name] = public_surface(path)
        except SyntaxError as err:
            raise SystemExit("dump_suite_surface: cannot parse %s: %s"
                             % (path, err))
    return {"surface": surface, "importers": importers(tests_root, infra)}


def render_md(inventory: dict) -> str:
    surface, edges = inventory["surface"], inventory["importers"]
    total_refs = sum(len(names) for module in edges.values()
                     for names in module.values())
    lines = [
        "# Test-Suite Surface Inventory (TS-0)",
        "",
        "Generated by `tools/ci/dump_suite_surface.py` — do not edit;",
        "re-run the script. Machine authority: the JSON sidecar",
        "`testsuite-surface-inventory.json` (consumed by the",
        "shim-completeness guard, plan §12 #3). Narrative and targets:",
        "`testsuite-modernization-plan.md` §10–§11 + Appendix A.",
        "",
        "%d infra modules · %d imported-from modules · %d importer→name"
        % (len(surface), len(edges), total_refs),
        "references.",
        "",
        "| Module | fn | cls | const | var | shard-implicit | importers | name refs |",
        "|---|---|---|---|---|---|---|---|",
    ]
    for name in sorted(surface):
        lines.append(_module_row(name, surface[name], edges.get(name, {})))
    lines.append("")
    return "\n".join(lines)


def _module_row(name, surface, edges):
    refs = sum(len(values) for values in edges.values())
    implicit = ", ".join(f"`{value}`" for value in surface["shard_implicit"]) or "—"
    return "| `%s` | %d | %d | %d | %d | %s | %d | %d |" % (
        name, len(surface["functions"]), len(surface["classes"]),
        len(surface["constants"]), len(surface["variables"]), implicit,
        len(edges), refs,
    )


def main(argv=None) -> int:
    parser, args = _parse_args(argv)
    if not args.tests_root.is_dir():
        parser.error("not a directory: %s" % args.tests_root)
    inventory = build_inventory(args.tests_root)
    texts = _inventory_texts(inventory)
    if args.check:
        return _check_inventory(args, texts)
    return _write_inventory(args, inventory, texts)


def _parse_args(argv):
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--tests-root", type=Path, default=REPO / "tests")
    parser.add_argument("--json", type=Path,
                        default=REPO / "docs/refactor/testsuite-surface-inventory.json")
    parser.add_argument("--md", type=Path,
                        default=REPO / "docs/refactor/testsuite-surface-inventory.md")
    parser.add_argument("--check", action="store_true",
                        help="verify on-disk outputs match a fresh run")
    return parser, parser.parse_args(argv)


def _inventory_texts(inventory):
    return json.dumps(inventory, indent=1, sort_keys=True) + "\n", render_md(inventory)


def _check_inventory(args, texts):
    stale = [
        str(path) for path, text in zip((args.json, args.md), texts)
        if not path.exists() or path.read_text() != text
    ]
    if stale:
        print("dump_suite_surface: stale inventory, re-run to refresh: %s"
              % ", ".join(stale))
        return 1
    print("dump_suite_surface: inventory up to date")
    return 0


def _write_inventory(args, inventory, texts):
    args.json.write_text(texts[0])
    args.md.write_text(texts[1])
    print("dump_suite_surface: wrote %s + %s (%d modules)"
          % (args.json.name, args.md.name, len(inventory["surface"])))
    return 0


if __name__ == "__main__":
    sys.exit(main())
