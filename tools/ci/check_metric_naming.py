#!/usr/bin/env python3
#
# WHAT: phase-110 W12 — governance for the Prometheus metric surface. Two rules
#       over the families the exporter declares (its `# HELP`/`# TYPE` lines):
#
#         M1  a latency HISTOGRAM must be named `_seconds` (one unit across the
#             whole latency surface — phase-110 W11); a `_usec`/`_ms` latency
#             histogram is a finding unless it is a registered deprecation.
#         M2  self-deleting pin (the R14 idea, for metric NAMES): a deprecated
#             family whose `removal:` phase is marked IMPLEMENTED in
#             docs/refactor/ but is STILL emitted fails the build — so a
#             forgotten deprecated family is caught exactly when its removal is
#             due.
#
# WHY:  The metric surface grew per-protocol families with inconsistent units
#       and spellings (the phase-110 Part II deep-dive). W11 unified the latency
#       unit; without a lint, a new `*_usec` histogram silently re-fragments it,
#       and a deprecated family lingers past its window. This guard makes both
#       structurally impossible.
#
# USAGE:
#   tools/ci/check_metric_naming.py            # report, exit 0 (WARN)
#   tools/ci/check_metric_naming.py --fail     # gate: exit 1 on any finding
#
# The deprecated-family registry is DEPRECATED_METRICS below (name -> removal
# phase). The metric emitters are the src/observability/metrics/*.c files.

import glob
import os
import re
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
METRICS_DIR = os.environ.get("BRIX_METRIC_SRC") or \
    os.path.join(ROOT, "src", "observability", "metrics")
REFACTOR_DOCS = os.environ.get("BRIX_METRIC_REFACTOR_DOCS") or \
    os.path.join(ROOT, "docs", "refactor")

# Deprecated metric families: name -> removal phase (the self-deleting pin, M2).
# A family listed here is expected to still be emitted UNTIL its phase lands.
DEPRECATED_METRICS = {
    # EMPTY, and that is the correct state: phase 112 removed every family this
    # registry held (the µs latency histogram brix_io_latency_usec and the eight
    # per-plane/per-server byte counters that duplicated
    # brix_io_bytes_read/written{proto}), so M2 has nothing left to pin. A new
    # entry belongs here ONLY while a family is deliberately emitted alongside
    # its replacement, and it must name the phase that will delete it — that
    # phase's doc going IMPLEMENTED is what makes M2 fire.
    #
    # NB for whoever adds the next one: the genuinely DIFFERENT byte families
    # are not deprecations — brix_cvmfs_bytes_served (client egress by cache
    # disposition), brix_storage_io_bytes_* (per driver), brix_vo_bytes_* (per
    # VO) and brix_tpc_bytes_total measure other facts, not the storage-I/O
    # total, so they are complementary rather than duplicates.
}

# Latency histograms are exempt from the `_seconds` rule only if deprecated.
# A family is "latency" if its name carries one of these stems AND its type is
# a histogram (a gauge threshold like brix_io_slowop_threshold_usec is a config
# VALUE in µs, not a latency measurement, so it is not a histogram and is fine).
_LATENCY_STEMS = ("latency", "duration")

_HELP_RE = re.compile(r"#\s*HELP\s+(brix_[a-z0-9_]+)\b")
_TYPE_RE = re.compile(r"#\s*TYPE\s+(brix_[a-z0-9_]+)\s+(\w+)")
# ANCHORED at line start, and character-for-character the twin of the copy in
# directive_registry_w5.py (R14/R15 key off the same sentence). Unanchored it
# also matched a doc that merely QUOTES the trigger while explaining the pin,
# so a still-PLANNED doc documenting the mechanism would arm it immediately.
_IMPLEMENTED_RE = re.compile(r"^\*\*Status:\*\*\s*IMPLEMENTED",
                             re.IGNORECASE | re.MULTILINE)


def _metric_types():
    """{family: type} from every `# TYPE brix_X <type>` in the emitter source."""
    types = {}
    for path in glob.glob(os.path.join(METRICS_DIR, "*.c")):
        text = open(path, errors="replace").read()
        for m in _TYPE_RE.finditer(text):
            types[m.group(1)] = m.group(2)
    return types


def _is_latency(name):
    return any(stem in name for stem in _LATENCY_STEMS)


def _m1_offending(name, mtype):
    """True if `name` is a latency histogram that must be `_seconds` but is not
    (and is not a registered deprecation)."""
    if mtype != "histogram" or not _is_latency(name):
        return False
    return not name.endswith("_seconds") and name not in DEPRECATED_METRICS


def _rule_m1(types):
    """M1 — a latency histogram must be `_seconds` unless registered deprecated."""
    return [("M1", name,
             "latency histogram is not named `_seconds` — the uniform latency "
             "unit (phase-110 W11); rename it or, for a deprecation window, add "
             "it to DEPRECATED_METRICS")
            for name, mtype in sorted(types.items())
            if _m1_offending(name, mtype)]


def _phase_is_implemented(phase_tag):
    for path in glob.glob(os.path.join(REFACTOR_DOCS, phase_tag + "-*.md")):
        try:
            if _IMPLEMENTED_RE.search(open(path, errors="replace").read()):
                return True
        except OSError:
            continue
    return False


_NAME_LITERAL_RE = re.compile(
    r'"(brix_[a-z0-9_]+_(?:total|seconds|usec|ratio|bytes|info))"')


def _emitted_families():
    """Set of families the exporter emits: HELP-line families PLUS quoted
    metric-name string literals (the SRV_COUNTER_HDR / macro-constructed
    families whose HELP line is assembled at compile time, e.g. the deprecated
    stream byte counters), so the M2 pin sees every family a scraper would."""
    fams = set()
    for path in glob.glob(os.path.join(METRICS_DIR, "*.c")):
        text = open(path, errors="replace").read()
        fams |= set(_HELP_RE.findall(text))
        fams |= set(_NAME_LITERAL_RE.findall(text))
    return fams


def _rule_m2(emitted):
    """M2 — self-deleting pin: a deprecated family whose removal phase is
    IMPLEMENTED must no longer be emitted."""
    out = []
    for name, phase in sorted(DEPRECATED_METRICS.items()):
        if name in emitted and _phase_is_implemented(phase):
            out.append(("M2", name,
                        f"deprecated metric family is still emitted but its "
                        f"removal phase ({phase}) is marked IMPLEMENTED — "
                        "delete the family; the deprecation window has closed"))
    return out


def main(argv):
    fail = "--fail" in argv
    types = _metric_types()
    emitted = _emitted_families()
    findings = _rule_m1(types) + _rule_m2(emitted)

    print(f"check_metric_naming: {len(types)} typed families, "
          f"{len(DEPRECATED_METRICS)} deprecated-registered")
    if not findings:
        print("check_metric_naming: OK — no findings")
        return 0
    for rule, name, msg in findings:
        print(f"  [{rule}] {name}: {msg}")
    if fail:
        print(f"\ncheck_metric_naming: FAIL — {len(findings)} finding(s)",
              file=sys.stderr)
        return 1
    print("\ncheck_metric_naming: WARN — findings reported (run --fail to gate)")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
