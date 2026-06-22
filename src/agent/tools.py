"""Built-in tools for the reference guarded agent. Deterministic and side-effect-free (sims), so the
whole stack runs in CI. Real tools plug in by matching the same name/args shape."""

from __future__ import annotations

import ast
import operator
from collections.abc import Callable
from dataclasses import dataclass

_OPS = {
    ast.Add: operator.add,
    ast.Sub: operator.sub,
    ast.Mult: operator.mul,
    ast.Div: operator.truediv,
    ast.Mod: operator.mod,
    ast.Pow: operator.pow,
    ast.USub: operator.neg,
}


def _safe_calc(expr: str) -> float:
    def ev(node: ast.AST) -> float:
        if isinstance(node, ast.Constant) and isinstance(node.value, (int, float)):
            return node.value
        if isinstance(node, ast.BinOp) and type(node.op) in _OPS:
            return _OPS[type(node.op)](ev(node.left), ev(node.right))
        if isinstance(node, ast.UnaryOp) and type(node.op) in _OPS:
            return _OPS[type(node.op)](ev(node.operand))
        raise ValueError("unsupported expression")

    return ev(ast.parse(expr, mode="eval").body)


@dataclass
class Tool:
    name: str
    run: Callable[[dict], str]


def default_tools() -> dict[str, Tool]:
    return {
        "calc": Tool("calc", lambda a: str(_safe_calc(str(a.get("expr", "0"))))),
        "echo": Tool("echo", lambda a: str(a.get("text", ""))),
        "bash": Tool("bash", lambda a: f"ran: {a.get('cmd', '')}"),
        "sql": Tool("sql", lambda a: f"executed: {a.get('query', '')}"),
        "http_fetch": Tool("http_fetch", lambda a: f"fetched {a.get('url', '')} -> 200 OK"),
    }
