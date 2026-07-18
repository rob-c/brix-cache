#!/usr/bin/env bash
#
# check_metric_cardinality.sh — enforce INVARIANT #8 (low-cardinality metric
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
# HOW:  grep every `<name>="%…"` interpolated label token in the exporter
#       sources, drop the ones whose NAME is on APPROVED (or that carry a
#       per-line `metric-cardinality-allow: <reason>` marker), and fail on
#       anything left. LITERAL-valued labels (source="hit", plane="http") are
#       inherently cardinality-1 and are never flagged.
#
# The vocabulary is CURATED, not a shrinking backlog: adding a new label is a
# deliberate, reviewed act (extend APPROVED with a justification, exactly like
# adding a value to the label enum in src/observability/metrics/unified.h), so
# the friction is intentional. A genuinely bounded value that does not warrant a
# permanent vocabulary entry (a one-off gauge) carries a per-line marker instead.
#
# USAGE:
#   tools/ci/check_metric_cardinality.sh            # scan the exporter tree
#   tools/ci/check_metric_cardinality.sh <dir>      # scan an alternate dir
#                                                   # (used by the guard's test)
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT"

SCAN_DIR="${1:-src/observability/metrics}"

# Curated low-cardinality label vocabulary. Two justified classes:
#   ENUM      — value drawn from a fixed compile-time set (a brix_*_t enum
#               string, an HTTP method/status class, a histogram bucket bound).
#   CONFIG-N  — value is a configured/observed NAME whose cardinality is bounded
#               by deployment config (a handful of exports, backends, upstreams,
#               cvmfs repos, grid VOs, listen ports) — never per-request.
# NB: every entry below is present in the tree today; `check_metric_cardinality
# --list` (below) prints the live label set to reconcile against this list.
APPROVED='proto op status status_class method direction class le'   # ENUM
APPROVED="$APPROVED auth plane action source result state surface"   # ENUM
APPROVED="$APPROVED reason staging"                                  # ENUM (reap reason; 0/1 staging flag)
APPROVED="$APPROVED export backend origin upstream zone repo vo"     # CONFIG-N (named resources)
APPROVED="$APPROVED server port"                                     # CONFIG-N (cluster member host:port / listen port)

# The interpolated-label token as it appears in a C format string: a label name
# preceded by `{` (first label) or `,` (subsequent), an `=`, an ESCAPED quote
# (\"), then a printf conversion (%). Matches %s, %.*s, %d, %.3f, %lu, ….
LABEL_RE='[{,][a-z_]+=\\"%'

# Every interpolated-label site, comment/marker-filtered.
current_label_sites() {
  grep -rnE "$LABEL_RE" "$SCAN_DIR" --include=*.c 2>/dev/null \
    | grep -v 'metric-cardinality-allow' \
    | grep -vE ':[0-9]+:[[:space:]]*(\*|//|/\*)' \
    || true
}

# --list: print the distinct interpolated label NAMES in the tree (vocabulary
# reconciliation aid; not part of the gate).
if [ "${1:-}" = "--list" ]; then
  SCAN_DIR="src/observability/metrics"
  current_label_sites \
    | grep -oE "$LABEL_RE" \
    | sed -E 's/[{,]([a-z_]+)=\\"%/\1/' \
    | sort | uniq -c | sort -rn
  exit 0
fi

# A site is a violation iff its label name is not on APPROVED. Emit "file:line:
# label" for each offending token (a single line may carry several labels).
violations=""
while IFS= read -r line; do
  [ -n "$line" ] || continue
  loc="${line%%:*}:$(printf '%s' "$line" | cut -d: -f2)"
  # Pull each interpolated label name on this line.
  names="$(printf '%s' "$line" | grep -oE "$LABEL_RE" \
             | sed -E 's/[{,]([a-z_]+)=\\"%/\1/')"
  for n in $names; do
    case " $APPROVED " in
      *" $n "*) : ;;                       # approved — bounded
      *) violations="${violations}${loc}: ${n}"$'\n' ;;
    esac
  done
done <<EOF
$(current_label_sites)
EOF

if [ -n "$violations" ]; then
  echo "ERROR: metric label with UNBOUNDED (non-enum) value — INVARIANT #8." >&2
  echo "       A string-interpolated label value that is not a fixed enum or a" >&2
  echo "       config-bounded name creates one Prometheus series per distinct" >&2
  echo "       value (path/user/DN/IP/URI/key → cardinality explosion, CWE-770):" >&2
  printf '%s' "$violations" | sed '/^$/d; s/^/    /' >&2
  echo "" >&2
  echo "If the value is genuinely low-cardinality (a fixed enum string, or a" >&2
  echo "configured/observed resource name bounded by deployment config), add its" >&2
  echo "label name to APPROVED in this script with a one-line justification. For a" >&2
  echo "one-off bounded gauge, add a per-line '/* metric-cardinality-allow:" >&2
  echo "<reason> */' marker instead." >&2
  exit 1
fi

n_approved="$(printf '%s' "$APPROVED" | wc -w)"
echo "check_metric_cardinality: OK — every interpolated metric label in $SCAN_DIR" \
     "draws from the $n_approved-name low-cardinality vocabulary (INVARIANT #8)"
