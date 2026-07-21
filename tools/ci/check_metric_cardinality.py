#!/usr/bin/env python3
#
# check_metric_cardinality.py — enforce INVARIANT #8 (low-cardinality metric
# labels) at CI time (hyper-hardening-plan §E-3, CWE-770 metric explosion).
#
# WHAT: Fails (exit 1) when a Prometheus exporter emits a label whose VALUE is
#       string-interpolated (label="%s" / "%.*s" / "%d" …) under a label NAME
#       that is not in the curated low-cardinality vocabulary below.
#
# WHY:  Prometheus creates one time-series per distinct label-value tuple. A
#       label whose value is per-request unbounded — a path, a username, a DN,
#       a client IP, an object key, a request URI — turns one metric into
#       millions of series and OOMs the scrape target and the TSDB. INVARIANT
#       #8 confines label values to a fixed enum-like vocabulary (protocol,
#       op, status, auth mechanism …) or a small config-bounded set (configured
#       export/backend/upstream/repo/VO/listen-port names). This guard makes
#       that invariant a gate instead of a code-review hope.
#
# HOW:  scan every `<name>="%…"` interpolated label token in the exporter
#       sources, drop the ones whose NAME is on APPROVED (or that carry a
#       per-line `metric-cardinality-allow: <reason>` marker), and fail on
#       anything left. LITERAL-valued labels (source="hit", plane="http") are
#       inherently cardinality-1 and are never flagged.
#
# This is the faithful Python twin of check_metric_cardinality.sh: same verdict,
# same vocabulary, same message wording, same exit codes. (A second in-tree twin
# lives in tests/source_guards_lib.py::metric_cardinality for the pytest lane.)
#
# USAGE:
#   tools/ci/check_metric_cardinality.py            # scan the exporter tree
#   tools/ci/check_metric_cardinality.py <dir>      # scan an alternate dir
#                                                   # (used by the guard's test)

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]

DEFAULT_SCAN_DIR = "src/observability/metrics"

# Curated low-cardinality label vocabulary. Two justified classes:
#   ENUM      — value drawn from a fixed compile-time set (a brix_*_t enum
#               string, an HTTP method/status class, a histogram bucket bound).
#   CONFIG-N  — value is a configured/observed NAME whose cardinality is bounded
#               by deployment config (a handful of exports, backends, upstreams,
#               cvmfs repos, grid VOs, listen ports) — never per-request.
APPROVED = (
    "proto op status status_class method direction class le "  # ENUM
    "auth plane action source result state surface "           # ENUM
    "reason staging "                                          # ENUM (reap reason; 0/1 staging flag)
    "export backend origin upstream zone repo vo "             # CONFIG-N (named resources)
    "server port"                                              # CONFIG-N (cluster member host:port / listen port)
)
_APPROVED = set(APPROVED.split())
_N_APPROVED = len(APPROVED.split())

# The interpolated-label token as it appears in a C format string: a label name
# preceded by `{` (first label) or `,` (subsequent), an `=`, an ESCAPED quote
# (\"), then a printf conversion (%). Matches %s, %.*s, %d, %.3f, %lu, ….
_LABEL_RE = re.compile(r'[{,]([a-z_]+)=\\"%')


def _read(path: Path) -> str:
    """Byte-tolerant read (grep is byte-based; .c may carry stray bytes)."""
    return path.read_text(errors="ignore")


def _is_comment_line(code: str) -> bool:
    """True for a comment continuation (``*``) or a ``//`` / ``/*`` line — the
    same drop the shell guard does with its ``:[0-9]+:\\s*(\\*|//|/\\*)`` filter."""
    s = code.lstrip()
    return s.startswith(("*", "//", "/*"))


def run(scan_dir=None, root: Path = ROOT) -> tuple[bool, list[str]]:
    """Verdict for INVARIANT #8. Returns (ok, messages) where each message is a
    ``file:line: label`` violation site (empty ⇒ ok). Mirrors the shell guard's
    site collection: interpolated-label tokens in ``*.c`` under scan_dir, minus
    ``metric-cardinality-allow`` lines and comment lines, minus APPROVED names."""
    scan = scan_dir if scan_dir is not None else DEFAULT_SCAN_DIR
    base = root / scan  # absolute scan_dir replaces root (pathlib join semantics)
    messages: list[str] = []
    if not base.exists():
        return (True, messages)

    for path in sorted(base.rglob("*.c")):
        loc_path = f"{scan}/{path.relative_to(base)}"
        for lineno, line in enumerate(_read(path).splitlines(), 1):
            if "metric-cardinality-allow" in line or _is_comment_line(line):
                continue
            names = _LABEL_RE.findall(line)
            if not names:
                continue
            loc = f"{loc_path}:{lineno}"
            for n in names:
                if n not in _APPROVED:
                    messages.append(f"{loc}: {n}")

    return (not messages, messages)


def main() -> int:
    # Run from the repo root so the relative scan dir — and the paths reported in
    # violation lines — line up with the shell guard regardless of cwd.
    import os

    os.chdir(ROOT)

    scan_dir = sys.argv[1] if len(sys.argv) > 1 else None
    ok, messages = run(scan_dir)

    if not ok:
        print("ERROR: metric label with UNBOUNDED (non-enum) value — INVARIANT #8.", file=sys.stderr)
        print("       A string-interpolated label value that is not a fixed enum or a", file=sys.stderr)
        print("       config-bounded name creates one Prometheus series per distinct", file=sys.stderr)
        print("       value (path/user/DN/IP/URI/key → cardinality explosion, CWE-770):", file=sys.stderr)
        for m in messages:
            print(f"    {m}", file=sys.stderr)
        print("", file=sys.stderr)
        print("If the value is genuinely low-cardinality (a fixed enum string, or a", file=sys.stderr)
        print("configured/observed resource name bounded by deployment config), add its", file=sys.stderr)
        print("label name to APPROVED in this script with a one-line justification. For a", file=sys.stderr)
        print("one-off bounded gauge, add a per-line '/* metric-cardinality-allow:", file=sys.stderr)
        print("<reason> */' marker instead.", file=sys.stderr)
        return 1

    scan = scan_dir if scan_dir is not None else DEFAULT_SCAN_DIR
    print(
        f"check_metric_cardinality: OK — every interpolated metric label in {scan} "
        f"draws from the {_N_APPROVED}-name low-cardinality vocabulary (INVARIANT #8)"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
