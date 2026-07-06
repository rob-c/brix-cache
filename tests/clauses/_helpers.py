"""Shared shortcuts for authoring clause-indexed conformance tests.

A family module (chain.py, proxy.py, …) imports these and exports a `CLAUSES`
list of `x509forge.Clause`.  The helpers keep each row a one-liner while the
heavy lifting stays in x509forge's builders.
"""

from __future__ import annotations

import x509forge
from x509forge import Clause

# Re-export for family modules.
__all__ = ["Clause", "clause", "ns_globs", "eec_kw"]

# The namespace every "in-namespace" CA grants by default.
NS = "/DC=test/DC=x509conf/*"


def clause(id, clause_ref, title, expected, build, *,
           surface="davs", group="sp_on_crl_off", reason=""):
    """Factory: a Clause with sensible defaults."""
    return Clause(id=id, clause=clause_ref, title=title, expected=expected,
                  build=build, surface=surface, group=group, reason=reason)


def ns_globs(*extra):
    """The default in-namespace glob list (plus any extras)."""
    return [NS, *extra]


def leaf_dn(ctx, cn="leaf"):
    """A DN inside the default namespace for this clause's CA."""
    return f"/DC=test/DC=x509conf/CN={cn}-{ctx.clause.id}"
