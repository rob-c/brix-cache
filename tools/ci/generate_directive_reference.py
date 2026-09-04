#!/usr/bin/env python3
"""Generate the complete nginx directive registry in ``directives.md``.

The detailed prose in that document remains curated.  This index owns the
structural facts that source can state without interpretation: registered
name, accepted context, argument shape, and registration owner.  It expands
the same fragment headers and X-macros as the directive drift guard.
"""

from __future__ import annotations

import os
import sys
from dataclasses import dataclass
from pathlib import Path

import check_directive_registry as registry


START = "<!-- BEGIN GENERATED DIRECTIVE REGISTRY -->"
END = "<!-- END GENERATED DIRECTIVE REGISTRY -->"
DOC = Path(os.environ.get("BRIX_DIRECTIVE_DOC", registry.DOCS))


@dataclass(frozen=True)
class Registration:
    name: str
    plane: str
    arguments: str
    owner: str


def _argument_shape(context: str) -> str:
    shapes = (
        ("NGX_CONF_NOARGS", "none"),
        ("NGX_CONF_FLAG", "`on|off`"),
        ("NGX_CONF_TAKE1", "`<value>`"),
        ("NGX_CONF_TAKE2", "`<value> <value>`"),
        ("NGX_CONF_TAKE3", "`<value> <value> <value>`"),
        ("NGX_CONF_1MORE", "`<value>...`"),
        ("NGX_CONF_2MORE", "`<value> <value>...`"),
        ("NGX_CONF_ANY", "`[value ...]`"),
    )
    for token, shape in shapes:
        if token in context:
            return shape
    return "source-defined"


def _relative_owner(path: str) -> str:
    return os.path.relpath(path, registry.ROOT).replace(os.sep, "/")


def _literal_registrations(path: str, text: str) -> list[Registration]:
    rows = []
    for match in registry._ENTRY.finditer(text):
        if "offsetof" in match.group(3) or "\\\n" in match.group(0):
            continue
        context = match.group(2)
        rows.append(Registration(
            match.group(1),
            registry._plane(context, path) or "unknown",
            _argument_shape(context),
            _relative_owner(path),
        ))
    return rows


def _macro_registrations(path: str, text: str, bodies) -> list[Registration]:
    rows = []
    for macro, prefix, use_context in registry._macro_sites(text):
        for token, body_context in bodies.get(macro, []):
            context = f"{use_context} {body_context}"
            rows.append(Registration(
                prefix + token,
                registry._plane(context, path) or "unknown",
                _argument_shape(body_context),
                _relative_owner(path),
            ))
    return rows


def collect() -> list[Registration]:
    """Return every expanded directive registration in deterministic order."""
    bodies = registry._macro_bodies()
    rows = []
    for path, source in registry._walk_src(".c", ".h"):
        rows.extend(_literal_registrations(path, source))
        rows.extend(_macro_registrations(path, source, bodies))
    return sorted(rows, key=lambda row: (row.name, row.plane, row.owner))


def _collapse(rows: list[Registration]):
    grouped = {}
    for row in rows:
        item = grouped.setdefault(row.name, {
            "planes": set(), "arguments": set(), "owners": set()})
        item["planes"].add(row.plane)
        item["arguments"].add(row.arguments)
        item["owners"].add(row.owner)
    return grouped


def render(rows: list[Registration]) -> str:
    """Render the fenced generated section."""
    grouped = _collapse(rows)
    lines = [
        START,
        "",
        "### Complete directive registry (generated)",
        "",
        "This table is generated from the live `ngx_command_t` registrations, "
        "including directive fragments and X-macro families. Context and "
        "argument shape are authoritative; exact defaults and validation "
        "constraints remain in the curated sections below and in the linked "
        "registration owner. Run `cmake --build build --target "
        "docs-directives` after changing the surface.",
        "",
        "| Directive | Plane | Arguments | Registration owner |",
        "|---|---|---|---|",
    ]
    for name, item in sorted(grouped.items()):
        planes = ", ".join(sorted(item["planes"]))
        arguments = ", ".join(sorted(item["arguments"]))
        owners = "<br>".join(f"`{owner}`" for owner in sorted(item["owners"]))
        lines.append(f"| `{name}` | {planes} | {arguments} | {owners} |")
    lines.extend(["", END])
    return "\n".join(lines)


def _updated_document(current: str, generated: str) -> str:
    if START in current and END in current:
        before, tail = current.split(START, 1)
        _old, after = tail.split(END, 1)
        return before + generated + after
    anchor = "## Directives\n"
    if anchor not in current:
        raise ValueError(f"{DOC} has no '## Directives' insertion anchor")
    return current.replace(anchor, f"{anchor}\n{generated}\n", 1)


def main(argv: list[str]) -> int:
    current = DOC.read_text()
    expected = _updated_document(current, render(collect()))
    if "--check" in argv:
        if current == expected:
            print(f"directive reference: current ({len(collect())} registrations)")
            return 0
        print("directive reference: generated registry is stale", file=sys.stderr)
        return 1
    DOC.write_text(expected)
    print(f"directive reference: wrote {DOC}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
