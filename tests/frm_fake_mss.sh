#!/bin/bash
# frm_fake_mss.sh — a fake tape-MSS copycmd for FRM staging tests.
#
# The FRM stage worker execv()s this with one argument: the absolute destination
# path to stage into (the file on the export root, currently a nearline stub).
# It "recalls" by copying the real bytes from $FRM_TAPE_DIR into place. The FRM
# worker clears the residency xattr on success, so this script only copies.
#
# Env knobs (set by the test in nginx's environment, inherited via fork):
#   FRM_DATA_DIR   export root (prefix stripped to derive the relative path)
#   FRM_TAPE_DIR   the "tape" — real bytes live at $FRM_TAPE_DIR/<relpath>
#   FRM_LATENCY_MS injected recall latency in milliseconds (default 0)
#   FRM_FAIL_MODE  "permanent" → always exit 1 (a never-stageable file)
#   FRM_AUDIT_LOG  append one "stage <dest>" line per invocation (dedup proof)
set -u

dest="${1:-}"
[ -n "$dest" ] || exit 64

[ -n "${FRM_AUDIT_LOG:-}" ] && echo "stage $dest" >> "$FRM_AUDIT_LOG"

ms="${FRM_LATENCY_MS:-0}"
if [ "$ms" -gt 0 ] 2>/dev/null; then
    sleep "$(awk "BEGIN{printf \"%.3f\", $ms/1000}")"
fi

case "${FRM_FAIL_MODE:-}" in
    permanent) exit 1 ;;
esac

data="${FRM_DATA_DIR:-}"
tape="${FRM_TAPE_DIR:-}"

# Derive the relative tape path from the EXPORT path of the object being recalled.
# That is $FRM_LFN (the worker exports the export path the agent is staging) — use
# it rather than $dest, because under materialize-to-scratch $dest is a scratch
# temp that does not encode the object. Fall back to $dest (legacy in-place).
ref="${FRM_LFN:-$dest}"
rel="${ref#"$data"/}"
src="$tape/$rel"

[ -f "$src" ] || exit 2
cp -- "$src" "$dest" || exit 3
exit 0
