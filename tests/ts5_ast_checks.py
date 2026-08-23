"""Reusable AST checks for TS-5 package-move regression tests."""

from __future__ import annotations

import ast
import builtins
import hashlib
from pathlib import Path


DEFINITIONS = (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)
MODULE_NAMES = {
    "__file__", "__name__", "__doc__", "__package__", "__spec__",
    "__loader__", "__builtins__", "__path__", "__annotations__",
}


def _definition_rows(node, prefix):
    rows = []
    for child in node.body:
        if not isinstance(child, DEFINITIONS):
            continue
        name = prefix + child.name
        body = "".join(
            ast.dump(item, include_attributes=False) for item in child.body
        )
        rows.append((name, hashlib.sha256(body.encode()).hexdigest()))
        if isinstance(child, ast.ClassDef):
            rows.extend(_definition_rows(child, name + "."))
    return rows


def body_hashes(path: Path) -> dict[str, str]:
    tree = ast.parse(path.read_text(encoding="utf-8"))
    return dict(_definition_rows(tree, ""))


def top_level_body_hashes(path: Path) -> dict[str, str]:
    tree = ast.parse(path.read_text(encoding="utf-8"))
    rows = []
    for node in tree.body:
        if not isinstance(node, DEFINITIONS):
            continue
        body = "".join(
            ast.dump(item, include_attributes=False) for item in node.body
        )
        rows.append((node.name, hashlib.sha256(body.encode()).hexdigest()))
    return dict(rows)


def _named_call_argument(node, function_name):
    if not isinstance(node, ast.Call):
        return None
    if not isinstance(node.func, ast.Name):
        return None
    if node.func.id != function_name or not node.args:
        return None
    return node.args[0]


def _allowed_literal(node, allowed):
    if not isinstance(node, ast.Constant) or not isinstance(node.value, str):
        return False
    return node.value in allowed


def literal_call_problems(paths, function_name, allowed):
    problems = []
    for raw_path in paths:
        path = Path(raw_path)
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            argument = _named_call_argument(node, function_name)
            if argument is not None and not _allowed_literal(argument, allowed):
                problems.append(f"{path.name}:{node.lineno}")
    return problems


def assigned_literal(path, variable):
    tree = ast.parse(Path(path).read_text(encoding="utf-8"))
    for node in tree.body:
        if not isinstance(node, ast.Assign):
            continue
        names = [getattr(target, "id", None) for target in node.targets]
        if variable in names:
            return ast.literal_eval(node.value)
    return None


def substring_matches(paths, needles):
    return {
        Path(path).name: sorted(needle for needle in needles if needle in Path(path).stem)
        for path in paths
        if any(needle in Path(path).stem for needle in needles)
    }


def _first_problem(checks):
    for check in checks:
        problem = check()
        if problem is not None:
            return problem
    return None


def _shape_problem(before, expected_shape):
    if expected_shape is None:
        return None
    names = (name[-1] if isinstance(name, tuple) else name for name in before)
    top_level = sum("." not in name for name in names)
    actual = (len(before), top_level)
    if actual != expected_shape:
        return f"archive shape is {actual}, expected {expected_shape}"
    return None


def _lost_problem(before, after):
    lost = sorted(set(before) - set(after))
    if lost:
        return f"definitions lost in the move: {lost}"
    return None


def _invented_problem(before, after, additions):
    invented = sorted(set(after) - set(before) - additions)
    if invented:
        return f"definitions invented by the move: {invented}"
    return None


def _differing_problem(before, after):
    differing = sorted(
        name for name in before
        if name in after and before[name] != after[name]
    )
    if differing:
        return f"bodies changed: {differing}"
    return None


def move_problem(before, after, expected_shape=None, additions=None):
    additions = additions or set()
    checks = (
        lambda: _shape_problem(before, expected_shape),
        lambda: _lost_problem(before, after),
        lambda: _invented_problem(before, after, additions),
        lambda: _differing_problem(before, after),
    )
    return _first_problem(checks)


def _import_names(node):
    return {
        (alias.asname or alias.name).split(".")[0]
        for alias in node.names
    }


def _stored_names(tree):
    return {
        node.id for node in ast.walk(tree)
        if isinstance(node, ast.Name) and isinstance(node.ctx, ast.Store)
    }


def _argument_names(tree):
    return {
        node.arg for node in ast.walk(tree)
        if isinstance(node, ast.arg)
    }


def bound_names(tree, include_builtins=True):
    names = set(MODULE_NAMES)
    if include_builtins:
        names.update(dir(builtins))
    names.update(_stored_names(tree))
    names.update(_argument_names(tree))
    for node in ast.walk(tree):
        if isinstance(node, (ast.Import, ast.ImportFrom)):
            names.update(_import_names(node))
        elif isinstance(node, DEFINITIONS):
            names.add(node.name)
        elif isinstance(node, ast.ExceptHandler) and node.name:
            names.add(node.name)
        elif isinstance(node, ast.Global):
            names.update(node.names)
    return names


def _loaded_names(tree):
    return {
        (node.id, node.lineno) for node in ast.walk(tree)
        if isinstance(node, ast.Name) and isinstance(node.ctx, ast.Load)
    }


def _parsed_files(paths):
    return {
        Path(path): ast.parse(Path(path).read_text(encoding="utf-8"))
        for path in paths
    }


def _shared_bound_names(trees, union_scope):
    if not union_scope:
        return None
    shared = set()
    for tree in trees.values():
        shared.update(bound_names(tree))
    return shared


def _file_missing_names(path, tree, shared):
    available = bound_names(tree) if shared is None else shared
    return sorted(
        f"{path.name}:{line} {name}"
        for name, line in _loaded_names(tree)
        if name not in available
    )


def missing_names(paths, union_scope=False):
    trees = _parsed_files(paths)
    shared = _shared_bound_names(trees, union_scope)
    rows = {
        path.name: _file_missing_names(path, tree, shared)
        for path, tree in trees.items()
    }
    return {name: problems for name, problems in rows.items() if problems}


def missing_name_groups(groups):
    problems = {}
    for group in groups:
        report = missing_names(group, union_scope=len(group) > 1)
        problems.update(report)
    return problems


def _settings_imports(path):
    source = path.read_text(encoding="utf-8")
    tree = ast.parse(source)
    modules = [
        node.module for node in ast.walk(tree)
        if isinstance(node, ast.ImportFrom)
        and node.module
        and node.module.endswith("settings")
    ]
    return modules, "sys.path.insert" in source


def _settings_seen(paths):
    seen = {}
    self_locating = []
    for raw_path in paths:
        path = Path(raw_path)
        modules, modifies_path = _settings_imports(path)
        if modules:
            seen[path.name] = modules[-1]
        if modifies_path:
            self_locating.append(path.name)
    return seen, self_locating


def _wrong_settings_problem(seen, expected_module):
    wrong = {name: module for name, module in seen.items() if module != expected_module}
    if wrong:
        return f"modules import the wrong settings package: {wrong}"
    return None


def settings_import_problem(paths, expected_module):
    seen, self_locating = _settings_seen(paths)
    if not seen:
        return "no module imports settings"
    wrong = _wrong_settings_problem(seen, expected_module)
    if wrong is not None:
        return wrong
    if self_locating:
        return f"modules still modify sys.path: {self_locating}"
    return None


def _server_address(node):
    if not isinstance(node, ast.Call):
        return None
    name = getattr(node.func, "attr", getattr(node.func, "id", ""))
    if not name.endswith("HTTPServer"):
        return None
    if not node.args:
        return None
    return node.args[0]


def _address_host(address):
    if not isinstance(address, ast.Tuple) or not address.elts:
        return None
    host = address.elts[0]
    if isinstance(host, ast.Constant):
        return host.value
    if isinstance(host, ast.Name):
        return host.id
    if isinstance(host, ast.Attribute):
        return host.attr
    return None


def _server_call_host(node):
    address = _server_address(node)
    if address is None:
        return None
    return _address_host(address)


def server_bindings(paths):
    bindings = []
    for path in paths:
        path = Path(path)
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            host = _server_call_host(node)
            if host is not None:
                bindings.append((path.name, host))
    return bindings


def binding_problem(bindings, allowed):
    if not bindings:
        return "no server construction found"
    invalid = [binding for binding in bindings if binding[1] not in allowed]
    if invalid:
        return f"non-lane server bindings: {invalid}"
    return None
