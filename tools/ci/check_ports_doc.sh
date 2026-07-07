#!/usr/bin/env bash
#
# check_ports_doc.sh — every named port constant is in the ports registry doc.
#
# WHAT: Fails (exit 1) when a *_PORT* constant assigned in tests/settings.py
#       does not appear (by name) in docs/10-reference/test-fleet-ports.md.
#
# WHY:  settings.py is the machine source of truth; the registry doc is the
#       human map. A constant added without a registry row is undocumented
#       infrastructure — exactly the drift this doc exists to prevent.
#
# HOW:  Extract assigned ALL-CAPS names containing PORT from settings.py,
#       grep each in the doc.
#
# USAGE:
#   tools/ci/check_ports_doc.sh
#
set -euo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
DOC="$REPO/docs/10-reference/test-fleet-ports.md"
SRC="$REPO/tests/settings.py"

[ -f "$DOC" ] || { echo "FAIL registry doc missing: ${DOC#"$REPO"/}"; exit 1; }

viol=0
while IFS= read -r name; do
    if ! grep -q "$name" "$DOC"; then
        echo "FAIL undocumented port constant: $name (add a row to ${DOC#"$REPO"/})"
        viol=1
    fi
done < <(grep -oE '^[A-Z][A-Z0-9_]*PORT[A-Z0-9_]*[[:space:]]*=' "$SRC" | tr -d ' =' | sort -u)

[ "$viol" -eq 0 ] && echo "check_ports_doc: OK"
exit "$viol"
