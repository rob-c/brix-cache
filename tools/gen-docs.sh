#!/usr/bin/env bash
# Generate the browsable Doxygen API docs for the C codebase (src/ + client/).
# Output: docs/doxygen/html/index.html  (git-ignored).
# Landing page: docs/09-developer-guide/nginx-idioms-for-cpp-reviewers.md
set -euo pipefail

cd "$(dirname "$0")/.."

if ! command -v doxygen >/dev/null 2>&1; then
    echo "error: doxygen not found (install: dnf install doxygen graphviz)" >&2
    exit 1
fi

echo "Running doxygen…"
doxygen Doxyfile

out="docs/doxygen/html/index.html"
if [[ -f "$out" ]]; then
    echo "Docs generated: $out"
    echo "Open with:      xdg-open $out"
else
    echo "error: doxygen finished but $out was not produced" >&2
    exit 1
fi
