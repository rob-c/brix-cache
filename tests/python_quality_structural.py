"""Repository-local lexical nesting metric.

CCN, cognitive complexity, and Halstead difficulty come from Lizard,
Complexipy, and Radon respectively. Nesting has no common analyzer in the
project's toolchain, so this AST visitor is the only local implementation.
"""

from __future__ import annotations

import ast
from collections.abc import Iterable
from typing import Any


class NestingScorer(ast.NodeVisitor):
    """Measure maximum lexical control-flow nesting within one function."""

    def __init__(self) -> None:
        self.depth = 0
        self.maximum = 0

    def score(self, node: Any) -> int:
        for statement in node.body:
            self.visit(statement)
        return self.maximum

    def _nested(self, nodes: Iterable[ast.AST]) -> None:
        statements = tuple(nodes)
        if not statements:
            return
        self.depth += 1
        self.maximum = max(self.maximum, self.depth)
        for node in statements:
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
        self.visit_For(node)

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
        self.visit_With(node)

    def visit_IfExp(self, node: ast.IfExp) -> None:
        self.visit(node.test)
        self._nested((node.body, node.orelse))

    def visit_Match(self, node: Any) -> None:
        self.visit(node.subject)
        for case in node.cases:
            if case.guard is not None:
                self.visit(case.guard)
            self._nested(case.body)

    def _comprehension(
        self, generators: Iterable[Any], values: Iterable[ast.AST]
    ) -> None:
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
