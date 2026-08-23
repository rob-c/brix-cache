"""Render declared or observed test-to-server relationships.

Both sources produce file-to-server rows and optional dynamic-request counts.
Terminal, Mermaid, and HTML renderers consume that common representation.
"""

from __future__ import annotations

import html
import re
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Sequence, Set, Tuple

__all__ = [
    "as_payload",
    "declared_rows",
    "matrix_html",
    "matrix_lines",
    "mermaid_lines",
    "observed_rows",
]

Rows = Dict[str, List[str]]
_MERMAID_SAFE = re.compile(r"[^A-Za-z0-9_]+")


def declared_rows(gate, files: Iterable[Path]) -> Tuple[Rows, None]:
    """file → the servers a selective boot would start for it (closure
    included).  Dynamic servers are a runtime fact, so this view has none."""
    rows = {str(path): gate.specs_to_boot([Path(path)]) for path in files}
    return {path: rows[path] for path in sorted(rows)}, None


def observed_rows(records) -> Tuple[Rows, Dict[str, int]]:
    """file → the servers its tests actually used in one catalogued run,
    plus file → how many dynamic servers its tests requested."""
    static: Dict[str, Set[str]] = {}
    dynamic: Dict[str, int] = {}
    for record in records:
        fname = record.nodeid.split("::", 1)[0]
        static.setdefault(fname, set()).update(record.servers)
        dynamic[fname] = dynamic.get(fname, 0) + len(record.dynamic_servers)
    return {f: sorted(names) for f, names in sorted(static.items())}, dynamic


def _columns(rows: Rows) -> List[str]:
    return sorted({name for names in rows.values() for name in names})


def matrix_lines(rows: Rows, dynamic: Optional[Dict[str, int]] = None) -> List[str]:
    """The terminal matrix: one row per file, one column per server."""
    if not rows:
        return ["no test files to map"]
    columns = _columns(rows)
    file_width = max(len(_short(path)) for path in rows)
    widths = [max(len(name), 3) for name in columns]
    lines = [_matrix_header(columns, widths, file_width, dynamic is not None)]
    lines.extend(
        _matrix_row(path, names, columns, widths, file_width, dynamic)
        for path, names in rows.items()
    )
    return lines


def _matrix_header(columns, widths, file_width: int, include_dynamic: bool) -> str:
    header = "%-*s" % (file_width, "FILE")
    for name, width in zip(columns, widths):
        header += "  %-*s" % (width, name)
    if include_dynamic:
        header += "  DYNAMIC"
    return header


def _matrix_row(path, names, columns, widths, file_width: int, dynamic) -> str:
    line = "%-*s" % (file_width, _short(path))
    used = set(names)
    for name, width in zip(columns, widths):
        line += "  %-*s" % (width, "●" if name in used else "·")
    if dynamic is not None:
        count = dynamic.get(path, 0)
        line += "  %s" % (count or "·")
    return line


def mermaid_lines(rows: Rows, dynamic: Optional[Dict[str, int]] = None) -> List[str]:
    """Render the map as a Mermaid graph."""
    lines = ["graph LR", *_mermaid_files(rows), *_mermaid_servers(rows)]
    lines.extend(_mermaid_dynamic_node(dynamic))
    lines.extend(_mermaid_edges(rows))
    lines.extend(_mermaid_dynamic_edges(rows, dynamic))
    return lines


def _mermaid_files(rows: Rows) -> list[str]:
    return ['  F%d["%s"]' % (index, _short(path)) for index, path in enumerate(rows)]


def _mermaid_servers(rows: Rows) -> list[str]:
    return [
        '  S_%s(("%s"))' % (_mermaid_id(name), name)
        for name in _columns(rows)
    ]


def _mermaid_dynamic_node(dynamic: Optional[Dict[str, int]]) -> list[str]:
    if dynamic and any(dynamic.values()):
        return ['  DYN(("dynamic"))']
    return []


def _mermaid_edges(rows: Rows) -> list[str]:
    lines = []
    for index, (path, names) in enumerate(rows.items()):
        lines.extend(
            "  F%d --> S_%s" % (index, _mermaid_id(name)) for name in names
        )
    return lines


def _mermaid_dynamic_edges(
    rows: Rows, dynamic: Optional[Dict[str, int]],
) -> list[str]:
    if not dynamic:
        return []
    return [
        '  F%d -- "%d requested" --> DYN' % (index, dynamic[path])
        for index, path in enumerate(rows)
        if dynamic.get(path)
    ]


def matrix_html(rows: Rows, dynamic: Optional[Dict[str, int]] = None) -> str:
    """The report's map section: same matrix, colored dots."""
    if not rows:
        return "<p class='meta'>no test ↔ server usage recorded.</p>"
    columns = _columns(rows)
    head = "<tr><th>file</th>%s%s</tr>" % (
        "".join("<th class='rot'>%s</th>" % html.escape(c) for c in columns),
        "<th class='rot'>dynamic</th>" if dynamic is not None else "",
    )
    body = [_html_row(path, names, columns, dynamic) for path, names in rows.items()]
    return (
        "<div class='scroller'><table class='map'><thead>%s</thead>"
        "<tbody>%s</tbody></table></div>" % (head, "".join(body))
    )


def _server_cells(names: Sequence[str], columns: Sequence[str]) -> str:
    used = set(names)
    return "".join(
        "<td class='dot %s'>%s</td>"
        % (("on", "●") if name in used else ("off", "·"))
        for name in columns
    )


def _dynamic_cell(path: str, dynamic: Optional[Dict[str, int]]) -> str:
    if dynamic is None:
        return ""
    count = dynamic.get(path, 0)
    style, value = ("dyn", count) if count else ("off", "·")
    return "<td class='dot %s'>%s</td>" % (style, value)


def _html_row(
    path: str, names: Sequence[str], columns: Sequence[str],
    dynamic: Optional[Dict[str, int]],
) -> str:
    cells = _server_cells(names, columns) + _dynamic_cell(path, dynamic)
    return "<tr><td title='%s'>%s</td>%s</tr>" % (
        html.escape(path), html.escape(_short(path)), cells,
    )


def as_payload(rows: Rows, dynamic: Optional[Dict[str, int]] = None) -> dict:
    return {
        "servers": _columns(rows),
        "files": {
            path: {
                "servers": names,
                **({"dynamic_requested": dynamic.get(path, 0)}
                   if dynamic is not None else {}),
            }
            for path, names in rows.items()
        },
    }


def _short(path: str) -> str:
    return Path(path).name


def _mermaid_id(name: str) -> str:
    return _MERMAID_SAFE.sub("_", name)
