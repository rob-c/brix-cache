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
    flat = [p.stem for p in tests_root.glob("*.py")
            if p.stem.isidentifier()
            and not p.stem.startswith(("test_", "_test_"))]
    nested = []
    for pkg in PACKAGES:
        pkg_dir = tests_root / pkg
        if pkg_dir.is_dir():
            nested += ["%s.%s" % (pkg, p.stem) for p in pkg_dir.glob("*.py")
                       if p.stem.isidentifier() and p.stem != "__init__"]
    return sorted(flat) + sorted(nested)


def _module_path(tests_root: Path, name: str) -> Path:
    return tests_root.joinpath(*name.split(".")).with_suffix(".py")


def public_surface(path: Path) -> dict:
    tree = ast.parse(path.read_text(), filename=str(path))
    out = {"functions": [], "classes": [], "constants": [],
           "variables": [], "shard_implicit": []}
    defined = set()
    for node in tree.body:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            out["functions"].append(node.name)
            defined.add(node.name)
        elif isinstance(node, ast.ClassDef):
            out["classes"].append(node.name)
            defined.add(node.name)
        elif isinstance(node, (ast.Assign, ast.AnnAssign)):
            targets = node.targets if isinstance(node, ast.Assign) else [node.target]
            for target in targets:
                if isinstance(target, ast.Name):
                    bucket = "constants" if target.id.isupper() else "variables"
                    out[bucket].append(target.id)
                    defined.add(target.id)
        elif isinstance(node, (ast.Import, ast.ImportFrom)):
            for alias in node.names:
                defined.add((alias.asname or alias.name).split(".")[0])
    # names loaded anywhere but bound nowhere in this file: the module
    # only works exec'd into a parent namespace (shard-implicit) — the
    # call-time NameError class, e.g. fleet_specs_part2's `_data`
    used, bound = set(), set(defined)
    for sub in ast.walk(tree):
        if isinstance(sub, ast.Name):
            (used if isinstance(sub.ctx, ast.Load) else bound).add(sub.id)
        elif isinstance(sub, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            bound.add(sub.name)
        elif isinstance(sub, ast.arg):
            bound.add(sub.arg)
        elif isinstance(sub, ast.ExceptHandler) and sub.name:
            bound.add(sub.name)
        elif isinstance(sub, (ast.Global, ast.Nonlocal)):
            bound.update(sub.names)
        elif isinstance(sub, (ast.Import, ast.ImportFrom)):
            for alias in sub.names:
                bound.add((alias.asname or alias.name).split(".")[0])
    out["shard_implicit"] = sorted(used - bound - _BUILTINS)
    for key in ("functions", "classes", "constants", "variables"):
        out[key] = sorted(set(out[key]))
    return out


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
    bindings: dict = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                bindings[alias.asname or alias.name.split(".")[0]] = alias.name
        elif isinstance(node, ast.ImportFrom) and node.module and node.level == 0:
            for alias in node.names:
                bindings[alias.asname or alias.name] = \
                    "%s.%s" % (node.module, alias.name)
    for node in ast.walk(tree):
        if not isinstance(node, ast.Assign):
            continue
        for target in node.targets:
            if (isinstance(target, ast.Subscript)
                    and isinstance(target.value, ast.Attribute)
                    and target.value.attr == "modules"
                    and isinstance(node.value, ast.Name)):
                return bindings.get(node.value.id)
    return None


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
        rel = path.relative_to(tests_root).as_posix()
        try:
            tree = ast.parse(path.read_text(), filename=str(path))
        except SyntaxError:
            continue  # importer side: unparseable files carry no edges
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    if alias.name.split(".")[0] in roots and alias.name in known:
                        edges.setdefault(alias.name, {}).setdefault(rel, [])
                        _add(edges[alias.name][rel], "<module>")
            elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
                root = node.module.split(".")[0]
                if root not in roots:
                    continue
                target = node.module if node.module in known else None
                if target is None and root in known:
                    target = root
                if target is None:
                    continue
                bucket = edges.setdefault(target, {}).setdefault(rel, [])
                for alias in node.names:
                    _add(bucket, alias.name)
    for module in edges.values():
        for rel in module:
            module[rel] = sorted(set(module[rel]))
    return edges


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
        s = surface[name]
        module_edges = edges.get(name, {})
        refs = sum(len(v) for v in module_edges.values())
        lines.append("| `%s` | %d | %d | %d | %d | %s | %d | %d |" % (
            name, len(s["functions"]), len(s["classes"]),
            len(s["constants"]), len(s["variables"]),
            ", ".join("`%s`" % n for n in s["shard_implicit"]) or "—",
            len(module_edges), refs))
    lines.append("")
    return "\n".join(lines)


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--tests-root", type=Path, default=REPO / "tests")
    parser.add_argument("--json", type=Path,
                        default=REPO / "docs/refactor/testsuite-surface-inventory.json")
    parser.add_argument("--md", type=Path,
                        default=REPO / "docs/refactor/testsuite-surface-inventory.md")
    parser.add_argument("--check", action="store_true",
                        help="verify on-disk outputs match a fresh run")
    args = parser.parse_args(argv)
    if not args.tests_root.is_dir():
        parser.error("not a directory: %s" % args.tests_root)
    inventory = build_inventory(args.tests_root)
    json_text = json.dumps(inventory, indent=1, sort_keys=True) + "\n"
    md_text = render_md(inventory)
    if args.check:
        stale = [str(p) for p, text in ((args.json, json_text), (args.md, md_text))
                 if not p.exists() or p.read_text() != text]
        if stale:
            print("dump_suite_surface: stale inventory, re-run to refresh: %s"
                  % ", ".join(stale))
            return 1
        print("dump_suite_surface: inventory up to date")
        return 0
    args.json.write_text(json_text)
    args.md.write_text(md_text)
    print("dump_suite_surface: wrote %s + %s (%d modules)"
          % (args.json.name, args.md.name, len(inventory["surface"])))
    return 0


if __name__ == "__main__":
    sys.exit(main())
