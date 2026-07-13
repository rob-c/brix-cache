#!/usr/bin/env bash
# phase-71 guard: the VFS layer (src/fs/vfs/*.c) must branch on capabilities
# (brix_sd_caps / brix_sd_supports / brix_sd_cred_accept), never on a concrete
# backend or protocol identity. A new backend becomes primary by setting .caps
# in src/fs/backend/, with zero edits here. Backlog target = 0.
set -euo pipefail
repo="$(cd "$(dirname "$0")/../.." && pwd)"
vfs="$repo/src/fs/vfs"
backlog="$repo/tools/ci/vfs_identity_backlog.txt"

# Identity-branch smells: comparing/strcmp'ing a backend name or hard-coding a
# protocol/driver token inside a conditional. Doc comments (lines starting with
# * or //) are ignored; only real code is flagged.
#
# The config-time factory that maps a `backend "<name>"` config string to a
# driver instance is EXEMPT: vfs_backend_config.c / vfs_backend_registry.c are
# the ONE intended place backend identity is named (once, at registration). The
# ban applies to the runtime op path — every other src/fs/vfs/*.c must dispatch
# on capabilities, never on which backend it happens to be talking to.
pattern='(strcmp\([^)]*(backend|driver|proto)|== *"(posix|s3|http|webdav|remote|ceph|cvmfs)"|sd_(http|s3|remote|ceph)_driver)'

hits="$(grep -REn "$pattern" "$vfs"/*.c 2>/dev/null \
        | grep -vE '/vfs_backend_(config|registry)\.c:' \
        | grep -vE '^\S+:[0-9]+: *(\*|//)' || true)"

count="$(printf '%s' "$hits" | grep -c . || true)"
allowed=0
[ -f "$backlog" ] && allowed="$(grep -cE '^[^#]' "$backlog" || true)"

if [ "$count" -gt "$allowed" ]; then
    echo "check_vfs_identity_branch: $count backend/proto identity branch(es) in src/fs/vfs (allowed $allowed):"
    printf '%s\n' "$hits"
    echo "Route the decision through brix_sd_caps()/brix_sd_supports()/brix_sd_cred_accept() instead."
    exit 1
fi
echo "check_vfs_identity_branch: OK ($count <= $allowed)"
