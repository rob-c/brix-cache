#!/usr/bin/env python3
"""Codemod: add per-test ``@pytest.mark.registry_server(...)`` declarations.

The collection-time gate (``tests/conftest._enforce_server_declarations``)
hard-fails any test that *uses* a dedicated fleet server it did not *declare*.
"Uses" is detected statically by ``tests/fleet_declares`` from the settings.py
port constants a test references; this tool writes the matching declaration so
the fleet can boot only the declared union instead of all ~120 instances.

Rules (identical to the gate, so applying this drives the gate to zero):
  * the always-on backbone (``fleet_declares.backbone_specs()`` — the core specs)
    is free and never declared;
  * a test that references one dedicated spec gets
    ``@pytest.mark.registry_server("name")``; several get
    ``@pytest.mark.registry_servers("a", "b")``;
  * only the specs not already declared are added, so the codemod is idempotent
    — re-running it is a no-op and it never disturbs a hand-written marker.

The marker is inserted directly above the ``def`` line (below any existing
decorators), at the function's own indentation, so class methods stay valid.

Usage::

    python3 tools/add_registry_markers.py            # dry-run: print the diff plan
    python3 tools/add_registry_markers.py --apply    # rewrite the files in place
    python3 tools/add_registry_markers.py --apply tests/test_vo_acl.py   # subset
"""

from __future__ import annotations

import argparse
import os
import sys

_TESTS = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "tests")
sys.path.insert(0, _TESTS)

import fleet_declares  # noqa: E402  (path set above)


def _marker_line(specs: list[str], indent: int) -> str:
    pad = " " * indent
    if len(specs) == 1:
        return f'{pad}@pytest.mark.registry_server("{specs[0]}")\n'
    joined = ", ".join(f'"{s}"' for s in specs)
    return f'{pad}@pytest.mark.registry_servers({joined})\n'


def plan_file(path: str, backbone: frozenset[str]):
    """Return a list of (lineno, col, specs) insertions for one module.

    ``lineno`` is the 1-based ``def`` line in the *current* source; the caller
    inserts bottom-to-top so earlier line numbers stay valid."""
    with open(path, encoding="utf-8") as fh:
        source = fh.read()
    edits = []
    for usage in fleet_declares.analyze_source(source):
        need = usage.required - backbone - usage.declared
        if need:
            edits.append((usage.lineno, usage.col, sorted(need)))
    return edits, source


def apply_file(path: str, edits, source: str) -> None:
    lines = source.splitlines(keepends=True)
    for lineno, col, specs in sorted(edits, reverse=True):
        lines.insert(lineno - 1, _marker_line(specs, col))
    with open(path, "w", encoding="utf-8") as fh:
        fh.write("".join(lines))


def _iter_targets(paths):
    import pathlib

    if paths:
        for p in paths:
            yield p
        return
    for p in sorted(pathlib.Path(_TESTS).rglob("test_*.py")):
        if ".pytest_cache" not in p.parts:
            yield str(p)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("paths", nargs="*", help="test files (default: whole tree)")
    ap.add_argument("--apply", action="store_true", help="rewrite in place (default: dry-run)")
    args = ap.parse_args()

    backbone = fleet_declares.backbone_specs()
    total_edits = total_files = 0
    for path in _iter_targets(args.paths):
        edits, source = plan_file(path, backbone)
        if not edits:
            continue
        total_files += 1
        total_edits += len(edits)
        rel = os.path.relpath(path)
        for lineno, col, specs in sorted(edits):
            print(f"{rel}:{lineno}  + {_marker_line(specs, 0).strip()}")
        if args.apply:
            apply_file(path, edits, source)

    verb = "applied" if args.apply else "planned (dry-run)"
    print(f"\n{verb}: {total_edits} marker(s) across {total_files} file(s)")
    if not args.apply and total_edits:
        print("re-run with --apply to write the declarations")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
