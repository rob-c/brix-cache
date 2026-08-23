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
    handlers = {
        "superset": _assert_superset,
        "replaced": _assert_replaced,
        "extra-exit-code": _assert_extra_exit_code,
        "format": _assert_format,
    }
    handler = handlers.get(kind)
    if handler is None:
        raise DivergenceError("unknown divergence kind %r in %s"
                              % (kind, entry.get("id")))
    handler(entry, expect, s, o, dim)


def _assert_superset(entry, expect, stock, ours, dim):
    if expect.get("stock_subset_of_ours", True) and dim in ("stdout", "stderr"):
        _assert_stock_lines_present(entry, stock, ours)
    pattern = expect.get("new_lines_must_match")
    if pattern and dim in ("stdout", "stderr"):
        _assert_extra_lines_match(entry, stock, ours, pattern)


def _assert_stock_lines_present(entry, stock, ours):
    missing = _missing_stock_lines(stock, ours)
    if missing:
        raise DivergenceError(
            "superset %s: ours dropped stock line(s) %r\nOURS=%r"
            % (entry["id"], missing[:3], ours))


def _missing_stock_lines(stock, ours):
    stock_lines = [line for line in str(stock).splitlines() if line.strip()]
    return [line for line in stock_lines if line not in str(ours)]


def _assert_extra_lines_match(entry, stock, ours, pattern):
    regex = re.compile(pattern)
    bad = [line for line in _extra_lines(stock, ours) if not regex.search(line)]
    if bad:
        raise DivergenceError(
            "superset %s: extra line(s) not matching %r: %r"
            % (entry["id"], pattern, bad[:3]))


def _extra_lines(stock, ours):
    return [line for line in str(ours).splitlines()
            if line.strip() and line not in str(stock)]


def _assert_replaced(entry, expect, _stock, ours, _dim):
    pattern = expect.get("ours_must_match")
    if not pattern:
        raise DivergenceError("replaced %s: missing expect.ours_must_match"
                              % entry["id"])
    if not re.search(pattern, str(ours)):
        raise DivergenceError(
            "replaced %s: ours %r does not match %r"
            % (entry["id"], ours, pattern))


def _assert_extra_exit_code(entry, expect, _stock, ours, _dim):
    allowed = set(expect.get("ours_rc_in", []))
    if allowed and ours not in allowed:
        raise DivergenceError(
            "extra-exit-code %s: ours rc=%r not in %r"
            % (entry["id"], ours, sorted(allowed)))


def _assert_format(entry, expect, _stock, ours, _dim):
    pattern = expect.get("ours_must_match")
    if pattern and not re.search(pattern, str(ours)):
        raise DivergenceError(
            "format %s: ours %r does not match %r"
            % (entry["id"], ours, pattern))
