#!/usr/bin/env bash
#
# config_rename_2026_07.sh — one-shot migration of every in-repo config/doc to
# the unified brix config grammar (the 2026-07-05 "flip"). Kept in-repo like
# tools/refactor/p66_apply.py so the mechanical rename is reproducible/auditable.
#
# The C directive table already dropped the old spellings; this brings the tree
# of test/deploy/doc/k8s configs onto the new names so `nginx -t` stops failing
# with "unknown directive".
#
# ORDERING IS LOAD-BEARING — do not reorder:
#   1. brix_cache_root            -> brix_cache_export   (before any brix_root pass;
#      the "brix_root" substring never appears inside "brix_*_cache_root", so the
#      per-proto legacy read-caches brix_{webdav,s3}_cache_root are left intact).
#   2. per-proto tier + preamble names -> bare unified names (longest first, so
#      brix_<p>_stage_store/_stage_flush resolve before the bare brix_<p>_stage).
#   3. brix_webdav_root / brix_s3_root -> brix_export.
#   4. brix_root <path>           -> brix_export        (every remaining brix_root
#      token is the stream export-path directive at this point; there is no
#      brix_root flag form in the tree yet — verified pre-flight).
#   5. directive-position `xrootd on|off;` -> brix_root on|off;  (LAST, so it
#      cannot collide with step 4). Boundary-anchored on the `xrootd <on|off>;`
#      directive shape — matches inline occurrences (`server { ... xrootd on; ...`)
#      as well as indented ones, but never prose "xrootd" or a foo_xrootd token.
#
# Every edited path is recorded to $MANIFEST so the caller can commit exactly the
# files this script changed (and nothing a concurrent session is editing).

set -euo pipefail

ROOT=$(cd "$(dirname "$0")/../.." && pwd)
TARGETS=(tests deploy docs k8s-tests site)
MANIFEST=${CONFIG_RENAME_MANIFEST:-"$ROOT/.config_rename_manifest.txt"}
: > "$MANIFEST"

# sed_all <sed-expr> <grep-pattern>
#   Find candidate files with an (over-inclusive) extended-regex grep, then apply
#   the precise sed -E expression. grep over-matching is harmless — the sed's own
#   word boundaries do the exact selection. NUL-safe for odd paths; tolerant of
#   "no match" under `set -e`.
#   docs/superpowers/ is sweep-exempt: the rename spec/plan intentionally carry old names.
sed_all() {
    local expr="$1" pat="$2"
    local -a files=()
    mapfile -d '' -t files < <(
        grep -rlZE --exclude-dir=superpowers \
            --exclude='migration-unified-grammar.md' \
            -e "$pat" "${TARGETS[@]/#/$ROOT/}" 2>/dev/null || true)
    [ "${#files[@]}" -eq 0 ] && return 0
    sed -i -E "$expr" "${files[@]}"
    printf '%s\n' "${files[@]}" >> "$MANIFEST"
}

# 1. legacy stream read-cache export path
sed_all 's/\bbrix_cache_root\b/brix_cache_export/g' 'brix_cache_root'

# 2. per-proto tier + preamble de-prefixing (exact names only, longest first).
#    Only names that were per-proto duplicates of a unified directive appear
#    here; anything else (auth/CORS/bucket/tpc/token/cvmfs knobs, and the legacy
#    per-proto brix_*_cache_root) is deliberately absent and left untouched.
for p in webdav s3 cvmfs; do
    for d in cache_store stage_store stage_flush stage \
             cache_max_object cache_evict_at cache_evict_to \
             cache_index_cache cache_meta cache_slice_size \
             storage_backend storage_credential thread_pool \
             allow_write read_only compress; do
        sed_all "s/\\bbrix_${p}_${d}\\b/brix_${d}/g" "brix_${p}_${d}"
    done
done

# 3. per-proto export roots -> brix_export
sed_all 's/\bbrix_webdav_root\b/brix_export/g' 'brix_webdav_root'
sed_all 's/\bbrix_s3_root\b/brix_export/g'     'brix_s3_root'

# 4. stream export-path directive -> brix_export
sed_all 's/\bbrix_root\b/brix_export/g' 'brix_root'

# 5. stream enable directive (directive position only) -> brix_root
sed_all 's/\bxrootd([[:space:]]+(on|off)[[:space:]]*;)/brix_root\1/g' \
        'xrootd[[:space:]]+(on|off)[[:space:]]*;'

sort -u "$MANIFEST" -o "$MANIFEST"
echo "done — edited $(wc -l < "$MANIFEST") files; manifest: $MANIFEST"
echo "review with: git diff --stat"
