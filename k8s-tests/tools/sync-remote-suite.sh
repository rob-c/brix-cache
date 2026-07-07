#!/usr/bin/env bash
# Thin wrapper — logic lives in labtools/sync.py (Python). Tests call it directly.
LAB="$(cd "$(dirname "$0")/.." && pwd)"
export PYTHONPATH="$LAB:${PYTHONPATH:-}"
exec python3 -m labtools.sync "$@"
