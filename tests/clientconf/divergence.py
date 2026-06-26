"""
divergence — the sanctioned-divergence registry.

WHAT
    The single source of truth for every place our client INTENTIONALLY differs
    from stock.  Each entry is labelled, reasoned, and carries a pinned
    expectation so the difference is asserted *positively* rather than ignored.

WHY
    "Compatible with stock, but with clearly-labelled extra features" only holds
    if every difference is reviewed and pinned.  A difference that is not in this
    registry is treated as a bug and fails the parity assertion.  When we add a
    knob, the surface test forces a matching ``superset`` entry here, so new
    features cannot silently erode stock compatibility.

HOW
    Data lives in ``divergence.yaml`` (loaded once).  ``lookup(tool, case_id,
    dim)`` returns the entry governing a comparison, or None.
    ``assert_expectation(entry, stock, ours, dim)`` enforces the entry's ``kind``:

      superset        — ours ⊇ stock; the EXTRA content matches a pinned regex.
      replaced        — ours matches a pinned regex; stock's exact text not required.
      extra-exit-code — ours may use a registered rc where stock used another.
      format          — same information, intentionally different rendering
                        (validated by a pinned regex on ours).
"""

import os
import re

import yaml

_YAML = os.path.join(os.path.dirname(os.path.abspath(__file__)), "divergence.yaml")

_registry = None


def _load():
    global _registry
    if _registry is None:
        with open(_YAML, "r") as fh:
            data = yaml.safe_load(fh) or []
        _registry = list(data)
    return _registry


def all_entries():
    """The full registry (list of dicts)."""
    return list(_load())


def entries_for(tool):
    """All registry entries scoped to ``tool``."""
    return [e for e in _load() if e.get("tool") == tool]


def _matches_case(entry, case_id):
    """An entry applies to a case when its ``case`` is '*' or equals case_id,
    or when the entry is keyed by a ``trigger`` arg signature (case-agnostic)."""
    want = entry.get("case", "*")
    if want in ("*", case_id):
        return True
    return False


def lookup(tool, case_id, dim):
    """Return the registry entry governing (tool, case_id, dim), or None."""
    for e in _load():
        if e.get("tool") != tool:
            continue
        if e.get("dim") != dim:
            continue
        if _matches_case(e, case_id):
            return e
    return None


class DivergenceError(AssertionError):
    pass


def assert_expectation(entry, stock, ours, dim):
    """Enforce a registered divergence between ``stock`` and ``ours`` on ``dim``."""
    kind = entry.get("kind")
    expect = entry.get("expect", {}) or {}
    s = stock.facet(dim)
    o = ours.facet(dim)

    if kind == "superset":
        # Every stock line must still be present in ours (compat preserved)...
        if expect.get("stock_subset_of_ours", True) and dim in ("stdout", "stderr"):
            s_lines = [ln for ln in str(s).splitlines() if ln.strip()]
            o_text = str(o)
            missing = [ln for ln in s_lines if ln not in o_text]
            if missing:
                raise DivergenceError(
                    "superset %s: ours dropped stock line(s) %r\nOURS=%r"
                    % (entry["id"], missing[:3], o))
        # ...and the EXTRA content must match the pinned pattern, so new extras
        # cannot sneak in unreviewed.
        pat = expect.get("new_lines_must_match")
        if pat and dim in ("stdout", "stderr"):
            extra = [ln for ln in str(o).splitlines()
                     if ln.strip() and ln not in str(s)]
            rx = re.compile(pat)
            bad = [ln for ln in extra if not rx.search(ln)]
            if bad:
                raise DivergenceError(
                    "superset %s: extra line(s) not matching %r: %r"
                    % (entry["id"], pat, bad[:3]))
        return

    if kind == "replaced":
        pat = expect.get("ours_must_match")
        if not pat:
            raise DivergenceError("replaced %s: missing expect.ours_must_match"
                                  % entry["id"])
        if not re.search(pat, str(o)):
            raise DivergenceError(
                "replaced %s: ours %r does not match %r" % (entry["id"], o, pat))
        return

    if kind == "extra-exit-code":
        allowed = set(expect.get("ours_rc_in", []))
        if allowed and o not in allowed:
            raise DivergenceError(
                "extra-exit-code %s: ours rc=%r not in %r"
                % (entry["id"], o, sorted(allowed)))
        return

    if kind == "format":
        pat = expect.get("ours_must_match")
        if pat and not re.search(pat, str(o)):
            raise DivergenceError(
                "format %s: ours %r does not match %r" % (entry["id"], o, pat))
        return

    raise DivergenceError("unknown divergence kind %r in %s"
                          % (kind, entry.get("id")))
