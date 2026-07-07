#!/usr/bin/env bash
#
# check_http_helper_reimpl.sh — protocols must not regrow private copies of
# the shared HTTP helpers in src/core/http/.
#
# WHAT: Fails (exit 1) when a protocol/observability handler contains one of
#       the idioms that historically preceded a private helper copy:
#         1. the raw headers_in scan loop (`&r->headers_in.headers.part`) —
#            that is brix_http_find_header()'s job;
#         2. precondition-header decision logic (reading
#            r->headers_in.if_match / if_none_match) — that is
#            brix_http_eval_preconditions() / _check_etag_preconditions()'s
#            job (the s3_eval_preconditions duplicate lived for a year);
#         3. hand-rolled ETag strings (printf'ing a "%lx-%llx"-shaped
#            validator) — that is brix_http_etag_str()'s job.
#
# WHY:  These duplications are invisible in review (each copy looks locally
#       fine) and dangerous in aggregate: conditionals gate overwrites and
#       304s, header lookup feeds auth. One engine, one behaviour.
#
# HOW:  grep the idioms across the HTTP-consuming trees, drop comment lines,
#       subtract the ALLOWLIST of reviewed legitimate sites, fail on the rest.
#       Companion of tests/test_cross_protocol_shared_helpers.py (positive
#       markers); this guard is the negative space (new offenders anywhere).
#
# USAGE:
#   tools/ci/check_http_helper_reimpl.sh    # exit 0 = clean, exit 1 = offender

set -euo pipefail
cd "$(git rev-parse --show-toplevel)"

# Trees that consume the shared HTTP helpers (the engine itself is exempt).
SCOPE=(src/protocols src/observability src/net/ratelimit src/net/mirror
       src/net/httpguard src/fs/scan)

# --- ALLOWLIST: reviewed legitimate sites (file:reason, keep sorted) ---------
# A site belongs here only when it is an adapter over the shared helper or a
# fast-path presence check, NOT an independent decision engine.
ALLOWLIST=(
    # Presence-only fast path + If-None-Match:* exclusive-create flag; the
    # verdicts come from brix_http_eval_preconditions().
    "src/protocols/s3/conditional.c"
    # Forwarding proxy: iterates ALL request headers to relay them verbatim —
    # enumeration, not lookup.
    "src/protocols/webdav/proxy_request.c"
    # XrdHttp compat filter: enumerates headers to rewrite hop-by-hop fields.
    "src/protocols/webdav/xrdhttp_filter.c"
    # HTTP-TPC: enumerates the TransferHeader* prefix family — prefix
    # enumeration, not exact-name lookup.
    "src/protocols/webdav/tpc_headers.c"
    # S3 user metadata: enumerates the x-amz-meta-* prefix family.
    "src/protocols/s3/usermeta.c"
    # Shadow mirror: enumerates ALL request headers to replay them verbatim
    # (its former private find_header was folded into the shared helper).
    "src/net/mirror/http_mirror.c"
)

is_allowed() {
    local f=$1 a
    for a in "${ALLOWLIST[@]}"; do
        [ "$f" = "$a" ] && return 0
    done
    return 1
}

fail=0

report() {
    # $1 = check name; stdin = "file:line:code" hits (comment lines dropped).
    local line f
    while IFS= read -r line; do
        [ -z "$line" ] && continue
        f=${line%%:*}
        if ! is_allowed "$f"; then
            echo "REIMPLEMENTATION ($1): $line" >&2
            echo "  → use the shared helper in src/core/http/ (or allowlist with a reason)" >&2
            fail=1
        fi
    done < <(grep -vE '^\S+:[0-9]+:\s*(\*|/\*|//)' || true)
}

scan() {
    # $1 = extended regex; hits or empty, never a failing status.
    grep -rnE "$1" "${SCOPE[@]}" --include='*.c' || true
}

# 1. Raw headers_in scan loop (brix_http_find_header's job).
report "raw header scan" < <(scan '&r->headers_in\.headers\.part')

# 2. Local precondition decisions (the shared evaluators' job).
report "precondition logic" < <(scan 'headers_in\.(if_match|if_none_match|if_modified_since|if_unmodified_since)')

# 3. Hand-rolled ETag validator strings (brix_http_etag_str's job).
report "hand-rolled etag" < <(scan '"\\?"?%l?lx-%l?lx')

if [ "$fail" -ne 0 ]; then
    echo "check_http_helper_reimpl: FAIL" >&2
    exit 1
fi
echo "check_http_helper_reimpl: OK"
