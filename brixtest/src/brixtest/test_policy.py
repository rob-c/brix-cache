"""Pre-import safety policy for declarative BriXTest modules."""

from __future__ import annotations

import ast
import importlib.machinery
import sys
import sysconfig
from pathlib import Path


class TestPolicyError(Exception):
    pass


def _stdlib() -> set[str]:
    known = getattr(sys, "stdlib_module_names", None)
    if known is not None:
        return set(known)
    root = Path(sysconfig.get_paths()["stdlib"])
    modules = set(sys.builtin_module_names) | {
        path.stem if path.is_file() else path.name
        for path in root.iterdir() if path.suffix == ".py" or path.is_dir()
    }
    modules.update(_shared_stdlib_modules())
    return modules


def _shared_stdlib_modules() -> set[str]:
    shared = sysconfig.get_config_var("DESTSHARED")
    if not shared:
        return set()
    shared_root = Path(str(shared))
    if not shared_root.is_dir():
        return set()
    suffixes = tuple(importlib.machinery.EXTENSION_SUFFIXES)
    return {
        path.name.partition(".")[0]
        for path in shared_root.iterdir()
        if path.is_file() and path.name.endswith(suffixes)
    }


_ALLOWED_IMPORTS = _stdlib() | {"__future__", "brixtest", "pytest"}
_FORBIDDEN_IMPORTS = {"XRootD", "xrootd", "pyxrootd"}
_BLOCKED_CALLS = {
    "__import__", "compile", "eval", "exec", "importlib.import_module",
    "ctypes.CDLL", "ctypes.PyDLL", "ctypes.WinDLL", "ctypes.cdll.LoadLibrary",
    "os.popen", "os.system", "pytest.importorskip", "socket.create_connection",
    "socket.socket", "subprocess.Popen", "subprocess.call", "subprocess.check_call",
    "subprocess.check_output", "subprocess.run", "time.sleep",
}


def _call_name(node: ast.Call) -> str:
    parts = []
    current = node.func
    while isinstance(current, ast.Attribute):
        parts.append(current.attr)
        current = current.value
    if isinstance(current, ast.Name):
        parts.append(current.id)
    return ".".join(reversed(parts))


def _managed(tree: ast.Module) -> bool:
    direct, modules = _managed_imports(tree)
    return any(_managed_node(node, direct, modules) for node in ast.walk(tree))


def _managed_imports(tree: ast.Module) -> tuple[set[str], set[str]]:
    direct = set()
    modules = set()
    for node in ast.walk(tree):
        direct.update(_direct_managed_imports(node))
        modules.update(_module_imports(node))
    return direct, modules


def _direct_managed_imports(node: ast.AST) -> set[str]:
    if not isinstance(node, ast.ImportFrom) or not node.module:
        return set()
    if node.module.split(".", 1)[0] != "brixtest":
        return set()
    return {
        alias.asname or alias.name for alias in node.names
        if alias.name in ("case", "native_test")
    }


def _module_imports(node: ast.AST) -> set[str]:
    if not isinstance(node, ast.Import):
        return set()
    return {alias.asname or alias.name for alias in node.names if alias.name == "brixtest"}


def _managed_function(node: ast.AST, direct: set[str], modules: set[str]) -> bool:
    if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
        return False
    return any(_managed_decorator(decorator, direct, modules) for decorator in node.decorator_list)


def _managed_node(node: ast.AST, direct: set[str], modules: set[str]) -> bool:
    if _managed_function(node, direct, modules):
        return True
    value = getattr(node, "value", None)
    return isinstance(node, (ast.Assign, ast.AnnAssign)) and _native_call(
        value, direct, modules,
    )


def _native_call(node: object, direct: set[str], modules: set[str]) -> bool:
    if not isinstance(node, ast.Call):
        return False
    target = node.func
    if isinstance(target, ast.Name):
        return target.id in direct and target.id != "case"
    return (
        isinstance(target, ast.Attribute) and target.attr == "native_test"
        and isinstance(target.value, ast.Name) and target.value.id in modules
    )


def _managed_decorator(node: ast.expr, direct: set[str], modules: set[str]) -> bool:
    target = node.func if isinstance(node, ast.Call) else node
    if isinstance(target, ast.Name):
        return target.id in direct
    return _module_case_decorator(target, modules)


def _module_case_decorator(target: ast.expr, modules: set[str]) -> bool:
    return (
        isinstance(target, ast.Attribute)
        and target.attr == "case"
        and isinstance(target.value, ast.Name)
        and target.value.id in modules
    )


class _ModulePolicy(ast.NodeVisitor):
    def __init__(self, allowed_imports=()) -> None:
        self.errors: list[tuple[int, str]] = []
        self.allowed_imports = _ALLOWED_IMPORTS | set(allowed_imports)

    def _error(self, node: ast.AST, detail: str) -> None:
        self.errors.append((getattr(node, "lineno", 0), detail))

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        for value in [*node.decorator_list, *node.args.defaults, *node.args.kw_defaults]:
            if value is not None:
                self.visit(value)

    visit_AsyncFunctionDef = visit_FunctionDef

    def visit_Import(self, node: ast.Import) -> None:
        for alias in node.names:
            root = alias.name.split(".", 1)[0]
            if root in _FORBIDDEN_IMPORTS:
                self._error(node, "module-level import %r is a forbidden native client" % root)
            elif root not in self.allowed_imports:
                self._error(node, "module-level import %r is not stdlib/pytest/brixtest" % root)

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        root = (node.module or "").split(".", 1)[0]
        if root in _FORBIDDEN_IMPORTS:
            self._error(node, "module-level import %r is a forbidden native client" % root)
        elif node.level or root not in self.allowed_imports:
            label = "." * node.level + (node.module or "")
            self._error(node, "module-level import %r is not stdlib/pytest/brixtest" % label)

    def visit_Call(self, node: ast.Call) -> None:
        name = _call_name(node)
        if name in _BLOCKED_CALLS:
            self._error(node, "module-level call %s() can block or load native code" % name)
        self.generic_visit(node)

    def visit_While(self, node: ast.While) -> None:
        self._error(node, "module-level while loops are forbidden")

    def visit_For(self, node: ast.For) -> None:
        self._error(node, "module-level loops are forbidden")

    visit_AsyncFor = visit_For

    def visit_With(self, node: ast.With) -> None:
        self._error(node, "module-level context managers are forbidden")

    visit_AsyncWith = visit_With

    def visit_Try(self, node: ast.Try) -> None:
        self._error(node, "module-level try blocks are forbidden")

    def visit_ListComp(self, node: ast.ListComp) -> None:
        self._error(node, "module-level comprehensions are forbidden")

    visit_SetComp = visit_ListComp
    visit_DictComp = visit_ListComp
    visit_GeneratorExp = visit_ListComp


def enforce(path: Path, *, allowed_imports=()) -> None:
    """Reject dangerous module-scope behavior before pytest imports the file."""
    candidate = Path(path)
    try:
        tree = ast.parse(candidate.read_text(), filename=str(candidate))
    except (OSError, SyntaxError):
        return
    if not _managed(tree):
        return
    allowed = tuple(allowed_imports)
    if any(
        not isinstance(name, str) or not name.isidentifier() or name in _FORBIDDEN_IMPORTS
        for name in allowed
    ):
        raise TestPolicyError("safe imports must be module roots and cannot include native clients")
    policy = _ModulePolicy(allowed)
    policy.visit(tree)
    if policy.errors:
        detail = "; ".join("line %d: %s" % row for row in policy.errors)
        raise TestPolicyError(
            "%s: unsafe managed-test module scope: %s. Move optional/native imports "
            "and executable code inside the test function; it runs in the isolated worker."
            % (candidate, detail)
        )
