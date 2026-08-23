"""Function-level Python complexity scoring for the repository test suite."""

from __future__ import annotations

import ast
import subprocess
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Union

from python_quality_paths import NPathScorer
from python_quality_structural import NestingScorer

ROOT = Path(__file__).resolve().parents[1]
SCAN_ROOTS = (
    "tests",
    "client",
    "shared",
    "src",
    "tools",
    "utils",
    "k8s-tests",
    "docs",
)
# Deliberately absent: brixtest/. It is a self-contained distributable with its
# own packaging, its own tox lane and its own copy of this contract
# (brixtest/tests/test_code_quality.py, run by `tox -e quality`) at limits that
# are equal or tighter — CCN 10 against the 15 here, and the same 10/15/5/10 for
# cognitive, NPath, Halstead and nesting. Scoring it from here as well makes one
# package answer to two gates that can drift apart, and the sub-project is the
# one that ships its own wheel, so the sub-project's gate is the authority.
LIMITS = {
    "ccn": 15.0,
    "cognitive": 10.0,
    "npath": 15.0,
    "halstead": 5.0,
    "nesting": 10.0,
}

Number = Union[int, float]


@dataclass(frozen=True)
class Function:
    line: int
    symbol: str
    node: Any


@dataclass(frozen=True)
class Score:
    metric: str
    path: str
    line: int
    symbol: str
    value: Number

    @property
    def location(self) -> str:
        return f"{self.path}:{self.line}:{self.symbol}"


@dataclass(frozen=True)
class Report:
    scores: tuple[Score, ...]
    errors: tuple[str, ...]


def _git_files(root: Path) -> list[Path]:
    result = subprocess.run(
        ["git", "-C", str(root), "ls-files", "--cached", "--others", "--exclude-standard", "-z"],
        capture_output=True,
        timeout=30.0,
        check=False,
    )
    if result.returncode != 0:
        return []
    paths = result.stdout.decode(errors="surrogateescape").split("\0")
    return [root / value for value in paths if value]


def _walk_files(root: Path) -> list[Path]:
    files = list(root.glob("*.py")) + list(root.glob("*.pyi"))
    for name in SCAN_ROOTS:
        base = root / name
        if base.is_dir():
            files.extend(base.rglob("*.py"))
            files.extend(base.rglob("*.pyi"))
    return files


def python_files(root: Path = ROOT) -> list[Path]:
    candidates = _git_files(root) or _walk_files(root)
    accepted = [path for path in candidates if _is_python_candidate(path, root)]
    return sorted(set(accepted))


def _is_python_candidate(path: Path, root: Path) -> bool:
    relative = path.relative_to(root)
    if len(relative.parts) > 1 and relative.parts[0] not in SCAN_ROOTS:
        return False
    if not path.is_file():
        return False
    return path.suffix in {".py", ".pyi"}


class _FunctionCollector(ast.NodeVisitor):
    def __init__(self) -> None:
        self.scope: list[str] = []
        self.functions: list[Function] = []
        self.occurrences: dict[str, int] = {}

    def _unique_name(self, name: str) -> str:
        key = "::".join((*self.scope, name))
        occurrence = self.occurrences.get(key, 0) + 1
        self.occurrences[key] = occurrence
        return name if occurrence == 1 else f"{name}#{occurrence}"

    def _visit_function(self, node: Any) -> None:
        unique_name = self._unique_name(node.name)
        symbol = "::".join((*self.scope, unique_name))
        self.functions.append(Function(node.lineno, symbol, node))
        self.scope.append(unique_name)
        self.generic_visit(node)
        self.scope.pop()

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        self._visit_function(node)

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        self._visit_function(node)

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        self.scope.append(self._unique_name(node.name))
        self.generic_visit(node)
        self.scope.pop()


def _functions(path: Path) -> list[Function]:
    source = path.read_text(encoding="utf-8")
    module = ast.parse(source, filename=str(path))
    collector = _FunctionCollector()
    collector.visit(module)
    return collector.functions


def _score_file(path: Path, root: Path) -> list[Score]:
    import complexipy
    import lizard
    from radon.metrics import h_visit_ast

    functions = _functions(path)
    relative = path.relative_to(root).as_posix()
    source = path.read_text(encoding="utf-8")
    scores = []
    for function in functions:
        npath = NPathScorer().block(function.node.body)
        nesting = NestingScorer().score(function.node)
        scores.extend(
            (
                Score("npath", relative, function.line, function.symbol, npath),
                Score("nesting", relative, function.line, function.symbol, float(nesting)),
                Score(
                    "halstead",
                    relative,
                    function.line,
                    function.symbol,
                    float(h_visit_ast(function.node).total.difficulty),
                ),
            )
        )
    lizard_result = lizard.analyze_file.analyze_source_code(relative, source)
    scores.extend(
        Score("ccn", relative, item.start_line, item.name, item.cyclomatic_complexity)
        for item in lizard_result.function_list
    )
    cognitive = complexipy.code_complexity(source, no_ignore=True)
    scores.extend(
        Score("cognitive", relative, item.line_start, item.name, item.complexity)
        for item in cognitive.functions
    )
    return scores


def score_repository(root: Path = ROOT) -> Report:
    scores: list[Score] = []
    errors: list[str] = []
    for path in python_files(root):
        try:
            scores.extend(_score_file(path, root))
        except (ImportError, OSError, SyntaxError, ValueError) as error:
            errors.append(f"{path.relative_to(root).as_posix()}: {error}")
    return Report(tuple(scores), tuple(errors))


def source_scores(source: str) -> dict[str, Number]:
    import complexipy
    import lizard
    from radon.metrics import h_visit_ast

    module = ast.parse(source)
    function = next(node for node in module.body if isinstance(node, ast.FunctionDef))
    lizard_functions = lizard.analyze_file.analyze_source_code(
        "quality_sample.py", source
    ).function_list
    cognitive_functions = complexipy.code_complexity(source, no_ignore=True).functions
    return {
        "ccn": float(lizard_functions[0].cyclomatic_complexity),
        "cognitive": float(cognitive_functions[0].complexity),
        "npath": NPathScorer().block(function.body),
        "halstead": float(h_visit_ast(function).total.difficulty),
        "nesting": float(NestingScorer().score(function)),
    }


def _normalized(value: Number) -> Number:
    return value if isinstance(value, int) else round(value, 3)


def violations(
    scores: Iterable[Score], limits: dict[str, float] = LIMITS
) -> list[str]:
    messages = []
    for score in sorted(scores, key=lambda item: (item.metric, item.path, item.symbol)):
        value = _normalized(score.value)
        limit = limits[score.metric]
        if value <= limit:
            continue
        messages.append(f"{score.metric} limit: {score.location} ({value:g} > {limit:g})")
    return messages
