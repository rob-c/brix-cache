"""Executable size and complexity contracts for the complete sub-project."""

from __future__ import annotations

import ast
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Iterable

from quality_paths import NPathScorer

ROOT = Path(__file__).resolve().parents[1]
PYTHON_TREES = ("src", "tests", "examples", "compat_tests", "tools")
COGNITIVE_LIMIT = 10
NPATH_LIMIT = 15
HALSTEAD_DIFFICULTY_LIMIT = 5.0
NESTING_LIMIT = 10


@dataclass(frozen=True)
class Score:
    """One function-level quality score with an actionable source location."""

    path: Path
    line: int
    symbol: str
    value: float

    @property
    def location(self) -> str:
        return f"{self.path.relative_to(ROOT).as_posix()}:{self.line}:{self.symbol}"


def _python_files() -> list[Path]:
    files = list(ROOT.glob("*.py"))
    for name in PYTHON_TREES:
        files.extend((ROOT / name).rglob("*.py"))
        files.extend((ROOT / name).rglob("*.pyi"))
    return sorted(set(files))


def _functions(path: Path) -> Iterable[ast.AST]:
    module = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    return (
        node
        for node in ast.walk(module)
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
    )


def _score_functions(
    files: Iterable[Path], scorer: Callable[[Any], float]
) -> list[Score]:
    scores: list[Score] = []
    for path in files:
        scores.extend(
            Score(path, node.lineno, node.name, scorer(node)) for node in _functions(path)
        )
    return scores


def _violations(scores: Iterable[Score], maximum: float) -> dict[str, float]:
    failed = (score for score in scores if score.value > maximum)
    ordered = sorted(failed, key=lambda score: (-score.value, score.location))
    return {score.location: round(score.value, 3) for score in ordered}


def _require(module: str, install_name: str) -> Any:
    try:
        return __import__(module, fromlist=("*",))
    except ImportError as error:
        raise AssertionError(
            f"install BriXTest's dev dependencies ({install_name} is required)"
        ) from error


def _cognitive_scores(files: Iterable[Path]) -> list[Score]:
    complexipy = _require("complexipy", "complexipy")
    scores: list[Score] = []
    for path in files:
        result = complexipy.file_complexity(str(path), no_ignore=True)
        scores.extend(
            Score(path, item.line_start, item.name, float(item.complexity))
            for item in result.functions
        )
    return scores


def _halstead_scores(files: Iterable[Path]) -> list[Score]:
    metrics = _require("radon.metrics", "radon")
    return _score_functions(files, lambda node: float(metrics.h_visit_ast(node).total.difficulty))


class _NestingScorer(ast.NodeVisitor):
    """Measure maximum lexical control-flow nesting within one function."""

    def __init__(self) -> None:
        self.depth = 0
        self.maximum = 0

    def score(self, node: Any) -> int:
        for statement in node.body:
            self.visit(statement)
        return self.maximum

    def _nested(self, statements: Iterable[ast.AST]) -> None:
        nodes = tuple(statements)
        if not nodes:
            return
        self.depth += 1
        self.maximum = max(self.maximum, self.depth)
        for node in nodes:
            self.visit(node)
        self.depth -= 1

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        return None

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        return None

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        return None

    def visit_If(self, node: ast.If) -> None:
        self.visit(node.test)
        self._nested(node.body)
        if len(node.orelse) == 1 and isinstance(node.orelse[0], ast.If):
            self.visit(node.orelse[0])
        else:
            self._nested(node.orelse)

    def visit_For(self, node: ast.For) -> None:
        self.visit(node.iter)
        self._nested(node.body)
        self._nested(node.orelse)

    def visit_AsyncFor(self, node: ast.AsyncFor) -> None:
        self.visit_For(node)  # type: ignore[arg-type]

    def visit_While(self, node: ast.While) -> None:
        self.visit(node.test)
        self._nested(node.body)
        self._nested(node.orelse)

    def _visit_try(self, node: Any) -> None:
        self._nested(node.body)
        for handler in node.handlers:
            self._nested(handler.body)
        self._nested(node.orelse)
        self._nested(node.finalbody)

    def visit_Try(self, node: ast.Try) -> None:
        self._visit_try(node)

    def visit_TryStar(self, node: Any) -> None:
        self._visit_try(node)

    def visit_With(self, node: ast.With) -> None:
        for item in node.items:
            self.visit(item.context_expr)
        self._nested(node.body)

    def visit_AsyncWith(self, node: ast.AsyncWith) -> None:
        self.visit_With(node)  # type: ignore[arg-type]

    def visit_IfExp(self, node: ast.IfExp) -> None:
        self.visit(node.test)
        self._nested((node.body, node.orelse))

    def visit_Match(self, node: Any) -> None:
        self.visit(node.subject)
        for case in node.cases:
            if case.guard is not None:
                self.visit(case.guard)
            self._nested(case.body)

    def _comprehension(self, generators: Iterable[Any], values: Iterable[ast.AST]) -> None:
        entered = 0
        for generator in generators:
            self.visit(generator.iter)
            self.depth += 1
            entered += 1
            self.maximum = max(self.maximum, self.depth)
            for condition in generator.ifs:
                self.visit(condition)
        for value in values:
            self.visit(value)
        self.depth -= entered

    def visit_ListComp(self, node: ast.ListComp) -> None:
        self._comprehension(node.generators, (node.elt,))

    def visit_SetComp(self, node: ast.SetComp) -> None:
        self._comprehension(node.generators, (node.elt,))

    def visit_GeneratorExp(self, node: ast.GeneratorExp) -> None:
        self._comprehension(node.generators, (node.elt,))

    def visit_DictComp(self, node: ast.DictComp) -> None:
        self._comprehension(node.generators, (node.key, node.value))


def _nesting_score(node: ast.AST) -> float:
    return float(_NestingScorer().score(node))


def _npath_score(node: ast.AST) -> float:
    return float(NPathScorer().block(node.body))  # type: ignore[attr-defined]


def _function_score(source: str, scorer: Callable[[ast.AST], float]) -> float:
    module = ast.parse(source)
    function = next(node for node in module.body if isinstance(node, ast.FunctionDef))
    return scorer(function)


def test_every_python_file_is_strictly_below_500_lines() -> None:
    oversized = {
        path.relative_to(ROOT).as_posix(): len(path.read_bytes().splitlines())
        for path in _python_files()
        if len(path.read_bytes().splitlines()) >= 500
    }
    assert oversized == {}, "split files at cohesive module boundaries: %r" % oversized


def test_python_complexity_stays_within_ccn_10() -> None:
    executable = shutil.which("lizard")
    assert executable is not None, "install BriXTest's dev dependencies (lizard is required)"
    result = subprocess.run(
        [executable, "-l", "python", "-C", "10", *PYTHON_TREES],
        cwd=ROOT,
        capture_output=True,
        text=True,
        timeout=60.0,
        check=False,
    )
    assert result.returncode == 0, result.stdout + result.stderr


def test_python_cognitive_complexity_stays_within_10() -> None:
    failed = _violations(_cognitive_scores(_python_files()), COGNITIVE_LIMIT)
    assert failed == {}, "reduce cognitive complexity: %r" % failed


def test_python_npath_complexity_stays_within_15() -> None:
    failed = _violations(_score_functions(_python_files(), _npath_score), NPATH_LIMIT)
    assert failed == {}, "split combinatorial execution paths: %r" % failed


def test_python_halstead_difficulty_stays_within_5() -> None:
    failed = _violations(_halstead_scores(_python_files()), HALSTEAD_DIFFICULTY_LIMIT)
    assert failed == {}, "simplify difficult expressions: %r" % failed


def test_python_control_flow_nesting_stays_within_10() -> None:
    failed = _violations(_score_functions(_python_files(), _nesting_score), NESTING_LIMIT)
    assert failed == {}, "flatten nested control flow: %r" % failed


def test_npath_scorer_counts_sequential_and_boolean_branches() -> None:
    source = """\
def sample(a, b):
    if a:
        pass
    if a and b:
        pass
"""
    assert _function_score(source, _npath_score) == 6


def test_npath_scorer_stops_paths_at_return() -> None:
    source = "def sample(a, b):\n    if a:\n        return 1\n    if b:\n        return 2\n    return 3\n"
    assert _function_score(source, _npath_score) == 3


def test_npath_scorer_counts_loops_and_exception_routes() -> None:
    source = """\
def sample(items):
    for item in items:
        use(item)
    try:
        load()
    except ValueError:
        recover()
"""
    assert _function_score(source, _npath_score) == 4


def test_nesting_scorer_treats_elif_as_a_peer_branch() -> None:
    source = """\
def sample(value):
    if value == 1:
        return 1
    elif value == 2:
        return 2
    return 0
"""
    assert _function_score(source, _nesting_score) == 1


def test_nesting_scorer_counts_lexically_nested_control_flow() -> None:
    source = """\
def sample(items):
    for item in items:
        if item:
            with open(item) as stream:
                return stream.read()
"""
    assert _function_score(source, _nesting_score) == 3
