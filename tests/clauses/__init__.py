"""Clause registry — aggregates every family module's CLAUSES into ALL_CLAUSES.

Each sibling module (except _helpers) exports `CLAUSES: list[x509forge.Clause]`.
Importing this package concatenates them and asserts globally-unique ids.
"""

from __future__ import annotations

import importlib
import pkgutil

ALL_CLAUSES = []


def _load():
    seen = set()
    out = []
    for mod in pkgutil.iter_modules(__path__):
        if mod.name.startswith("_"):
            continue
        m = importlib.import_module(f"{__name__}.{mod.name}")
        for c in getattr(m, "CLAUSES", []):
            if c.id in seen:
                raise ValueError(f"duplicate clause id: {c.id} (in {mod.name})")
            seen.add(c.id)
            out.append(c)
    return sorted(out, key=lambda c: c.id)


ALL_CLAUSES = _load()
