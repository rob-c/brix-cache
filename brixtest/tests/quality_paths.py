"""Acyclic path counting with terminal control-flow awareness."""

from __future__ import annotations

import ast
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from typing import Any


def _expression_decisions(node: Any) -> int:
    if node is None:
        return 0
    own = _decision_weight(node)
    return own + sum(_expression_decisions(child) for child in ast.iter_child_nodes(node))


def _decision_weight(node: ast.AST) -> int:
    if isinstance(node, ast.BoolOp):
        return len(node.values) - 1
    if isinstance(node, ast.IfExp):
        return 1
    if isinstance(node, ast.comprehension):
        return 1 + len(node.ifs)
    return 0


@dataclass(frozen=True)
class _Flow:
    normal: int = 0
    returned: int = 0
    broken: int = 0
    continued: int = 0

    @property
    def total(self) -> int:
        return self.normal + self.returned + self.broken + self.continued

    def plus(self, other: _Flow) -> _Flow:
        return _Flow(
            self.normal + other.normal,
            self.returned + other.returned,
            self.broken + other.broken,
            self.continued + other.continued,
        )


class NPathScorer:
    """Count executable acyclic paths without extending terminated paths."""

    def __init__(self) -> None:
        self.handlers: dict[type[ast.AST], Callable[[Any], _Flow]] = {
            ast.If: self._if,
            ast.For: self._loop,
            ast.AsyncFor: self._loop,
            ast.While: self._loop,
            ast.Try: self._try,
            ast.With: self._with,
            ast.AsyncWith: self._with,
            ast.Return: self._return,
            ast.Raise: self._return,
            ast.Break: self._break,
            ast.Continue: self._continue,
            ast.Assert: self._assert,
        }
        self._add_optional("Match", self._match)
        self._add_optional("TryStar", self._try)

    def _add_optional(self, name: str, handler: Callable[[Any], _Flow]) -> None:
        node_type = getattr(ast, name, None)
        if node_type is not None:
            self.handlers[node_type] = handler

    def block(self, statements: Iterable[ast.stmt]) -> int:
        return self._flow_block(statements).total

    def statement(self, node: ast.stmt) -> int:
        return self._flow(node).total

    def _flow_block(self, statements: Iterable[ast.stmt]) -> _Flow:
        active = 1
        returned = broken = continued = 0
        for statement in statements:
            flow = self._flow(statement)
            returned += active * flow.returned
            broken += active * flow.broken
            continued += active * flow.continued
            active *= flow.normal
        return _Flow(active, returned, broken, continued)

    def _flow(self, node: ast.stmt) -> _Flow:
        return self.handlers.get(type(node), self._simple)(node)

    def _if(self, node: ast.If) -> _Flow:
        body = self._flow_block(node.body)
        alternate = self._flow_block(node.orelse) if node.orelse else _Flow(normal=1)
        decisions = _expression_decisions(node.test)
        return body.plus(alternate).plus(_Flow(normal=decisions))

    def _loop(self, node: Any) -> _Flow:
        condition = getattr(node, "test", getattr(node, "iter", None))
        body = self._flow_block(node.body)
        normal = 1 + _expression_decisions(condition)
        normal += body.normal + body.broken + body.continued
        flow = _Flow(normal=normal, returned=body.returned)
        if not node.orelse:
            return flow
        return self._compose(flow, self._flow_block(node.orelse))

    def _try(self, node: Any) -> _Flow:
        flow = self._flow_block(node.body)
        for handler in node.handlers:
            flow = flow.plus(self._flow_block(handler.body))
        if node.orelse:
            flow = self._compose(flow, self._flow_block(node.orelse))
        if node.finalbody:
            flow = self._compose(flow, self._flow_block(node.finalbody))
        return flow

    def _with(self, node: Any) -> _Flow:
        decisions = sum(_expression_decisions(item.context_expr) for item in node.items)
        return self._flow_block(node.body).plus(_Flow(normal=decisions))

    def _match(self, node: Any) -> _Flow:
        flow = _Flow(normal=_expression_decisions(node.subject))
        for case in node.cases:
            case_flow = self._flow_block(case.body)
            flow = flow.plus(case_flow).plus(_Flow(normal=_expression_decisions(case.guard)))
        return flow

    def _simple(self, node: ast.stmt) -> _Flow:
        declarations = (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)
        decisions = 0 if isinstance(node, declarations) else _expression_decisions(node)
        return _Flow(normal=1 + decisions)

    def _return(self, node: Any) -> _Flow:
        return _Flow(returned=1 + _expression_decisions(getattr(node, "value", None)))

    def _break(self, node: ast.Break) -> _Flow:
        return _Flow(broken=1)

    def _continue(self, node: ast.Continue) -> _Flow:
        return _Flow(continued=1)

    def _assert(self, node: ast.Assert) -> _Flow:
        return _Flow(normal=1, returned=1 + _expression_decisions(node.test))

    @staticmethod
    def _compose(first: _Flow, second: _Flow) -> _Flow:
        return _Flow(
            normal=first.normal * second.normal,
            returned=first.returned + first.normal * second.returned,
            broken=first.broken + first.normal * second.broken,
            continued=first.continued + first.normal * second.continued,
        )
