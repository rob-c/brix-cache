"""The test ↔ server map — the operator's "who uses what" view.

Two sources, one shape.  The **declared** map reads the contract: the
gate's per-file analysis (markers, fixtures, port names) closed over
``depends_on`` — what a selective boot would start, computed without
running anything.  The **observed** map reads a catalogued run: which
servers each test actually rode, dynamic requests included.  Both
collapse to ``file → servers`` rows plus a per-file dynamic-request
count, and every view renders from those rows — an ASCII matrix for
the terminal, a Mermaid graph for docs and tickets, and the HTML
matrix embedded in the run report.
"""

from __future__ import annotations

import html
import re
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Set, Tuple

__all__ = [
    "declared_rows", "observed_rows", "matrix_lines", "mermaid_lines",
    "matrix_html", "as_payload",
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
    header = "%-*s" % (file_width, "FILE")
    for name, width in zip(columns, widths):
        header += "  %-*s" % (width, name)
    if dynamic is not None:
        header += "  DYNAMIC"
    lines = [header]
    for path, names in rows.items():
        line = "%-*s" % (file_width, _short(path))
        used = set(names)
        for name, width in zip(columns, widths):
            line += "  %-*s" % (width, "●" if name in used else "·")
        if dynamic is not None:
            count = dynamic.get(path, 0)
            line += "  %s" % (count if count else "·")
        lines.append(line)
    return lines


def mermaid_lines(rows: Rows, dynamic: Optional[Dict[str, int]] = None) -> List[str]:
    """The same map as a Mermaid graph — paste-ready for docs/tickets."""
    lines = ["graph LR"]
    for index, path in enumerate(rows):
        lines.append('  F%d["%s"]' % (index, _short(path)))
    for name in _columns(rows):
        lines.append('  S_%s(("%s"))' % (_mermaid_id(name), name))
    if dynamic and any(dynamic.values()):
        lines.append('  DYN(("dynamic"))')
    for index, (path, names) in enumerate(rows.items()):
        for name in names:
            lines.append("  F%d --> S_%s" % (index, _mermaid_id(name)))
        if dynamic and dynamic.get(path):
            lines.append('  F%d -- "%d requested" --> DYN' % (index, dynamic[path]))
    return lines


def matrix_html(rows: Rows, dynamic: Optional[Dict[str, int]] = None) -> str:
    """The report's map section: same matrix, colored dots."""
    if not rows:
        return "<p class='meta'>no test ↔ server usage recorded.</p>"
    columns = _columns(rows)
    head = "<tr><th>file</th>%s%s</tr>" % (
        "".join("<th class='rot'>%s</th>" % html.escape(c) for c in columns),
        "<th class='rot'>dynamic</th>" if dynamic is not None else "",
    )
    body = []
    for path, names in rows.items():
        used = set(names)
        cells = "".join(
            "<td class='dot %s'>%s</td>"
            % (("on", "●") if name in used else ("off", "·"))
            for name in columns
        )
        if dynamic is not None:
            count = dynamic.get(path, 0)
            cells += "<td class='dot %s'>%s</td>" % (
                ("dyn", count) if count else ("off", "·")
            )
        body.append(
            "<tr><td title='%s'>%s</td>%s</tr>"
            % (html.escape(path), html.escape(_short(path)), cells)
        )
    return (
        "<div class='scroller'><table class='map'><thead>%s</thead>"
        "<tbody>%s</tbody></table></div>" % (head, "".join(body))
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
