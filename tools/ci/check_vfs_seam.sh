#!/usr/bin/env bash
#
# check_vfs_seam.sh — enforce "the VFS is the sole source of data-plane truth".
#
# WHAT: Fails (exit 1) on a NEW seam bypass of either class
#       (docs/refactor/phase-56-...-perf-audit.md §9 / §4.3):
#         tier-2   — a handler calls the confined POSIX-helper layer directly
#                    (brix_*_confined_canon / _beneath / brix_ns_* / brix_staged_*)
#                    instead of an brix_vfs_* entry point;
#         tier-1.5 — a byte loop calls the SD driver vtable directly
#                    (brix_sd_posix_driver.<pread|pwrite|preadv|copy_range>)
#                    instead of the VFS primitives (brix_vfs_pread_full/pwrite_full).
#
# WHY:  Every such bypass is unmetered, uncached, and POSIX-pinned (a non-POSIX
#       Storage Driver backend cannot serve it). The ~105 pre-existing sites are
#       grandfathered in vfs_seam_backlog.txt and shrink as Pillar F (§9.10 F0-F7)
#       migrates them; this guard only rejects regressions and new files.
#
# HOW:  grep the bypass symbols across src/, drop (a) comment/doc-block lines,
#       (b) the permanent helper/implementation layer (ALLOW), and (c) the
#       shrinking backlog allowlist. Anything left is a new bypass → fail.
#
# USAGE:
#   tools/ci/check_vfs_seam.sh            # check; exit 1 on a new bypass
#   tools/ci/check_vfs_seam.sh --regen    # rewrite the backlog from the current tree
#                                         # (only after a deliberate migration/addition)
#
# NOTE: this guards THREE classes:
#         tier-1   — raw libc POSITIONAL file syscalls (pread/pwrite/preadv/.../
#                    copy_file_range/sendfile) outside src/fs/backend/. HARD rule,
#                    no backlog: data byte I/O must route through the SD driver so
#                    the syscall stays in the backend. (read()/write() are not
#                    matched — too overloaded with socket/pipe/IPC to flag safely.)
#         tier-2   — confined-helper calls (above), backlog-grandfathered.
#         tier-1.5 — SD-direct byte loops (above), backlog-grandfathered.
#
set -euo pipefail

# Repo root = two levels up from this script (tools/ci/).
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT"

BACKLOG="tools/ci/vfs_seam_backlog.txt"
# Tier-3 (raw namespace/metadata syscalls) has its OWN backlog: a file may be
# grandfathered for a raw open()/stat() while still being rejected for a new
# tier-2 confined-helper call, so the two allowlists must be independent.
BACKLOG_NS="tools/ci/vfs_seam_backlog_ns.txt"

# Confined-helper symbols a handler must reach only through brix_vfs_*.
SYMS='brix_open_beneath|brix_open_confined_canon'
SYMS="$SYMS"'|brix_lstat_beneath|brix_lstat_confined_canon|brix_stat_confined_canon'
SYMS="$SYMS"'|brix_opendir_confined_canon'
SYMS="$SYMS"'|brix_unlink_beneath|brix_mkdir_recursive_confined_canon'
SYMS="$SYMS"'|brix_ns_delete|brix_ns_mkdir|brix_ns_rename|brix_ns_local_copy'
# NOTE: the brix_staged_* atomic-write family is NOT tracked here. It is the
# below-seam crash-safe staging PRIMITIVE (defined in compat/staged_file.c, which
# is in ALLOW) — the async upload paths (s3/put*, webdav/put, webdav/tpc) hold the
# self-contained brix_staged_file_t BY VALUE with no request-ctx dependency,
# which is deliberately more robust off the event loop than the ctx-holding
# brix_vfs_staged_t wrapper; they already emit the unified brix_xfer_finish
# audit line themselves. Same class as brix_copy_range / fs_walk (also not in
# SYMS). The metered brix_vfs_staged_* wrapper remains for synchronous handlers
# (e.g. s3 POST). Reclassified 2026-06-28 after the vfs_staged async verification.
SYMS="$SYMS"'|brix_getxattr_confined_canon|brix_setxattr_confined_canon'
SYMS="$SYMS"'|brix_listxattr_confined_canon|brix_removexattr_confined_canon'

# Permanent non-targets (§9.8): the helper DEFINITIONS, the layer sd_posix
# delegates to, the privileged broker, the dashboard browse-root, the VFS-internal
# cache, and the FRM private journal. These are correctly below/beside the seam.
# src/fs/path/ holds the confinement/canonicalisation primitives the VFS
# namespace layer is built on (beneath, resolve_confined, recursive mkdir) —
# covered by the ^src/fs/ prefix since phase-66 moved them there.
ALLOW='^src/fs/'
ALLOW="$ALLOW"'|^src/core/compat/namespace_ops|^src/core/compat/staged_file|^src/core/compat/fs_walk'
ALLOW="$ALLOW"'|^src/auth/impersonate/|^src/observability/dashboard/'

# Tier-1.5: byte loops that call the SD driver vtable directly
# (brix_sd_posix_driver.<byteop>) instead of routing through the VFS primitives
# (brix_vfs_pread_full / pwrite_full / io-core). Post-A-1, src/fs/ no longer does
# this (the VFS primitives call pread/pwrite directly; sd_posix.c only DEFINES the
# slots, matched as ".pread =" not ".pread("), so the only hits are the A-3 backlog.
BYTEOPS='brix_sd_posix_driver\.(pread|pwrite|preadv|preadv2|pwritev|copy_range)'

# All current direct calls to the confined-helper layer (tier-2) AND SD-direct byte
# loops (tier-1.5), outside the allowed layer, comment-filtered.
current_bypasses() {
  { grep -rnE "\b(${SYMS})\s*\(" src/ --include=*.c
    grep -rnE "${BYTEOPS}\s*\(" src/ --include=*.c
  } \
    | grep -vE ':[0-9]+:[[:space:]]*(\*|//|/\*)' \
    | grep -vE "$ALLOW" \
    | sort -u \
    || true
}

# ---------------------------------------------------------------------------
# Tier-1: RAW libc positional file-byte syscalls outside the backend driver.
#
# These ops are unambiguously file DATA I/O (they never apply to a socket or a
# pipe), so a raw one anywhere but src/fs/backend/ means data POSIX leaked above
# the storage seam — a non-POSIX (block/object/S3) backend could not serve it.
# This is a HARD rule (no backlog): the data plane MUST route byte I/O through
# the SD driver (obj->driver-><op> / brix_sd_posix_driver.<op>, which the
# regex skips via the '.'/'->'/'_' lookbehind) so the syscall stays in the
# backend.  read()/write() are intentionally NOT matched — too overloaded with
# socket/pipe/IPC use to flag without false positives; the positional ops are the
# common, unambiguous regression.
RAWOPS='pread|pwrite|preadv|pwritev|preadv2|pwritev2|copy_file_range|sendfile'

# Allowed to make raw positional syscalls: the POSIX backend driver itself, and a
# few documented NON-data exclusions:
#   - zip_dir_unittest.c: a standalone ZIP-parser unit test, not in the module
#     build (no SD seam linked) — it parses a fixture file directly.
#   - zip_kernel.c: pure, ngx-free archive bounds-checker; its `pread` is a
#     CALLBACK parameter (zip_pread_fn), not a syscall — the real export-data
#     read is the caller's obj->driver->pread (zip_member.c / zip_dir.c).
#   - xmeta_path.c: the raw-PATH carrier for the unified metadata record — the
#     ".cinfo" sidecar (and its "user.xrd.cinfo" xattr twin). This is the cache
#     block-present bitmap + CSI integrity metadata, NOT export data; it rides
#     next to the data file on a svc-owned cache tree (below the VFS seam). Its
#     header names it the POSIX-path twin of the driver-routed SD-instance carrier
#     (xmeta_carrier.h). Kept raw + ngx-free so it stays standalone-unit-testable
#     (src/fs/meta/xmeta_unittest.c, no SD seam linked). This is where the .cinfo
#     I/O moved TO: cinfo.c now delegates load/save/lock here and no longer makes
#     a raw syscall itself (its entry below is retained only so a future raw op in
#     cinfo.c is a conscious re-add, not a silent one). Same class as meta.c/lock.c.
RAW_ALLOW='^src/fs/backend/'
RAW_ALLOW="$RAW_ALLOW"'|^src/protocols/root/zip/zip_dir_unittest'
RAW_ALLOW="$RAW_ALLOW"'|^src/protocols/root/zip/zip_kernel\.c'
RAW_ALLOW="$RAW_ALLOW"'|^src/fs/meta/xmeta_path\.c'
RAW_ALLOW="$RAW_ALLOW"'|^src/fs/cache/cinfo\.c'
#   - http_body.c: reads nginx's INBOUND request-body buffers (r->request_body,
#     buffered to client_body_temp when large) to stream a PUT/POST upload into a
#     staged export file. The source is nginx's own request-body temp, NOT export
#     storage — the export WRITE side goes through brix_vfs_staged. Same class
#     as cinfo.c (a non-export file the SD seam does not own).
RAW_ALLOW="$RAW_ALLOW"'|^src/core/http/http_body\.c'
#   - clone.c: post-clone CSI integrity fold — after brix_copy_range (backend)
#     writes the cloned bytes, the handler re-reads the dst handle-table fd to
#     feed brix_csi_write_update with per-block CRCs.  The dst fd was opened
#     through the handle table (proper mechanism); this pread is for internal
#     integrity accounting only, not user-data serving.  Ideally brix_copy_range
#     would emit CRCs inline (eliminating the readback), but that is a separate
#     refactor.  Same class as http_body.c (non-export-serving read on a
#     server-managed fd).
RAW_ALLOW="$RAW_ALLOW"'|^src/protocols/root/read/clone\.c'

# Raw positional ops outside the backend, with /*...*/ + //... comments and
# "..." string literals stripped first so a mention of an op NAME in a comment or
# a log message is not mistaken for a call.
current_raw_tier1() {
  grep -rnE "(^|[^._>a-zA-Z])(${RAWOPS})[[:space:]]*\(" src/ --include=*.c \
    | sed -E 's#/\*[^*]*\*/##g; s#//.*##g; s#"([^"\\]|\\.)*"##g' \
    | grep -E "(^|[^._>a-zA-Z])(${RAWOPS})[[:space:]]*\(" \
    | grep -vE ':[0-9]+:[[:space:]]*(\*|//|/\*)' \
    | grep -vE "$RAW_ALLOW" \
    | sort -u \
    || true
}

# ---------------------------------------------------------------------------
# Tier-3: RAW namespace/metadata syscalls (phase-2 full VFS seam, 2026-06-28).
#
# Beyond tier-1's positional DATA ops, an export handler must also reach the
# storage backend's NAMESPACE and METADATA through brix_vfs_* — never a raw
# open/openat/creat, stat/lstat/fstatat, opendir/readdir/fdopendir, unlink/
# rmdir/rename/mkdir (+ *at), truncate/ftruncate, chmod/chown, symlink/readlink,
# or the xattr family. The VFS routes these through the confinement cascade
# (openat2 RESOLVE_BENEATH / impersonation broker) and meters them.
#
# Two unavoidable realities make this a backlog tier (like tier-2), not a hard
# rule like tier-1:
#   (a) FALSE-DOMAIN uses are legitimate and pervasive — config/cert/token/keytab
#       readers (fopen/open), /tmp credential temps, /dev/null, /proc fd hygiene,
#       sockets — none of which touch the export backend.
#   (b) SEPARATE storage domains (the read-through cache, the upload stage dir,
#       the FRM control/journal store, S3 multipart staging, checkpoint journals)
#       are svc-owned roots OTHER than the export, so they are opened AS THE
#       WORKER and must NOT go through the export-confined, impersonation-aware
#       VFS (which resolves under the export rootfd / mapped user).
#
# So tier-3 (1) drops the ALLOW dirs (below-seam layer + config/auth + the
# separate-domain stores), (2) skips any line carrying a `vfs-seam-allow` marker
# (a deliberate, justified raw call — see the markers in open_resolved_file.c),
# and (3) grandfathers the remaining current sites in BACKLOG_NS, rejecting only
# NEW raw namespace/metadata syscalls in files not already on that backlog.
TIER3_FAM='getxattr|setxattr|listxattr|removexattr|fgetxattr|fsetxattr|flistxattr|fremovexattr'
TIER3_FAM="$TIER3_FAM"'|opendir|fdopendir|readdir|openat|creat|unlinkat|renameat|mkdirat'
TIER3_FAM="$TIER3_FAM"'|fstatat|ftruncate|fchmod|fchown|symlinkat|readlinkat|linkat'
TIER3_FAM="$TIER3_FAM"'|open|stat|lstat|unlink|rmdir|rename|mkdir|truncate|chmod|chown'
TIER3_FAM="$TIER3_FAM"'|symlink|readlink|mknod|link'

# Permanent non-targets for tier-3: the VFS + path-resolution layer, the broker,
# config/cert/token/keytab readers (never the export backend), and the SEPARATE
# server-managed storage domains (cache, dashboard browse, FRM control+journal,
# checkpoint journal, slice cache). Anything export-facing is NOT here — it must
# route through brix_vfs_* or carry a per-line vfs-seam-allow marker.
TIER3_ALLOW='^src/fs/|^src/core/compat/|^src/auth/impersonate/'
TIER3_ALLOW="$TIER3_ALLOW"'|^src/observability/dashboard/'
TIER3_ALLOW="$TIER3_ALLOW"'|^src/protocols/root/write/chkpoint|^src/protocols/root/read/slice_read'
TIER3_ALLOW="$TIER3_ALLOW"'|^src/auth/crypto/|^src/auth/gsi/|^src/auth/sss/|^src/auth/pwd/|^src/auth/token/'
TIER3_ALLOW="$TIER3_ALLOW"'|^src/core/config/|^src/auth/krb5/|^src/auth/authz/|^src/auth/voms/|^src/protocols/ssi/'
TIER3_ALLOW="$TIER3_ALLOW"'|^src/protocols/dig/|^src/core/aio/|unittest|_test'

# Symbols that are NOT raw syscalls even though they contain a family name: the
# VFS API, the confined-helper layer (caught by tier-2), the impersonation broker,
# and the namespace primitive layer. Dropped so tier-3 flags only RAW libc calls.
TIER3_EXCL='brix_vfs_|_confined_canon|_beneath|brix_imp_|brix_ns_'
TIER3_EXCL="$TIER3_EXCL"'|brix_open_confined|brix_staged_|brix_mkdir_recursive'

current_raw_tier3() {
  # The vfs-seam-allow marker lives in a comment, so it is checked on the RAW
  # line BEFORE comment/string stripping; the family match is checked AFTER
  # stripping so an op name in a comment/log string is never a false hit.
  grep -rnE "(^|[^._>a-zA-Z])(${TIER3_FAM})[[:space:]]*\(" src/ --include=*.c \
    | grep -v 'vfs-seam-allow' \
    | grep -vE "$TIER3_ALLOW" \
    | grep -vE "$TIER3_EXCL" \
    | sed -E 's#/\*[^*]*\*/##g; s#//.*##g; s#"([^"\\]|\\.)*"##g' \
    | grep -E "(^|[^._>a-zA-Z])(${TIER3_FAM})[[:space:]]*\(" \
    | grep -vE ':[0-9]+:[[:space:]]*(\*|//|/\*)' \
    | sort -u \
    || true
}

# ---------------------------------------------------------------------------
# CLIENT tier: the native client/ ships its OWN VFS (client/lib/fs/vfs.h →
# fs/vfs_posix / fs/vfs_block / fs/backend/s3/vfs_s3) whose byte I/O dispatches through the SAME
# shared SD driver as the server (src/fs/core/vfs_core.c, xvfs_pread_once /
# xvfs_pwrite_full → brix_sd_posix_driver). So a copy/transfer endpoint's data
# bytes must route through xrdc_vfs_* — never a raw positional syscall on a local
# storage file. The op set is tier-1's RAWOPS; like tier-2/3 this is a
# backlog-grandfathered tier (not a hard rule) because the client keeps a few
# legitimate raw byte loops outside the export data plane:
#   - vfs.c / vfs_posix.c / vfs_block.c / vfs_s3*.c — the VFS backends THEMSELVES
#     (the client's equivalent of src/fs/backend/; they ARE the seam), ALLOWed.
#   - copy_zip.c / zip_write.c — local ZIP-ARCHIVE assembly (a container builder,
#     not an export object): all four pread/pwrite calls carry per-line
#     'vfs-seam-allow: local zip-archive assembly, not export data' markers;
#     these files are no longer in the backlog.
#   - cks_verify.c — the xrdckverify on-disk checksum tool; the client VFS vtable
#     has no read-by-name or xattr op, so there is no seam to route through yet —
#     backlog (NOT marked permanent; should migrate when the vtable gains those ops).
# A permanently non-storage raw call (e.g. an anonymous tmpfile diagnostic) instead
# carries a per-line 'vfs-seam-allow' marker, exactly like the server tiers.
BACKLOG_CLIENT="tools/ci/vfs_seam_backlog_client.txt"

# Below-seam client layer: the VFS backend implementations (ALLOW).
# (phase-69: client/lib reorganized into concept buckets — the VFS impls live
# under client/lib/fs/ and the S3 backend under client/lib/fs/backend/s3/.)
CLIENT_ALLOW='^client/lib/fs/vfs\.c|^client/lib/fs/vfs_posix\.c|^client/lib/fs/vfs_block\.c'
CLIENT_ALLOW="$CLIENT_ALLOW"'|^client/lib/fs/backend/s3/vfs_s3'

current_raw_client() {
  grep -rnE "(^|[^._>a-zA-Z])(${RAWOPS})[[:space:]]*\(" client/lib client/apps --include=*.c \
    | grep -v 'vfs-seam-allow' \
    | sed -E 's#/\*[^*]*\*/##g; s#//.*##g; s#"([^"\\]|\\.)*"##g' \
    | grep -E "(^|[^._>a-zA-Z])(${RAWOPS})[[:space:]]*\(" \
    | grep -vE ':[0-9]+:[[:space:]]*(\*|//|/\*)' \
    | grep -vE "$CLIENT_ALLOW" \
    | sort -u \
    || true
}

if [ "${1:-}" = "--regen" ]; then
  {
    echo "# vfs_seam_backlog.txt — grandfathered tier-2 seam bypasses (phase-56 §9, App C)."
    echo "# Each entry is a 'path:' prefix; a migrated file's line is DELETED here so the"
    echo "# guard then rejects any regression in it. When this file holds only comments the"
    echo "# seam is closed. Regenerate ONLY after a deliberate migration: --regen."
    current_bypasses | sed -E 's/^([^:]+):.*/\1:/' | sort -u
  } > "$BACKLOG"
  {
    echo "# vfs_seam_backlog_ns.txt — grandfathered tier-3 raw namespace/metadata"
    echo "# syscalls (phase-2 full VFS seam, 2026-06-28). Same rules as the tier-2"
    echo "# backlog: each entry is a 'path:' prefix; a migrated file's line is DELETED"
    echo "# so the guard then rejects any regression in it. A deliberate raw call to a"
    echo "# SEPARATE storage domain (cache/stage/journal) should instead carry a"
    echo "# per-line 'vfs-seam-allow' marker. Regenerate ONLY after a migration."
    current_raw_tier3 | sed -E 's/^([^:]+):.*/\1:/' | sort -u
  } > "$BACKLOG_NS"
  {
    echo "# vfs_seam_backlog_client.txt — grandfathered raw positional byte syscalls"
    echo "# in the native client (client/lib + client/apps) outside the client VFS"
    echo "# backends. Same rules as the other backlogs: each entry is a 'path:' prefix;"
    echo "# a file migrated onto xrdc_vfs_* is DELETED here so the guard then rejects any"
    echo "# regression in it. A permanently non-storage raw call carries a per-line"
    echo "# 'vfs-seam-allow' marker instead. Regenerate ONLY after a migration."
    current_raw_client | sed -E 's/^([^:]+):.*/\1:/' | sort -u
  } > "$BACKLOG_CLIENT"
  echo "check_vfs_seam: regenerated $BACKLOG ($(grep -cvE '^#' "$BACKLOG") files)," \
       "$BACKLOG_NS ($(grep -cvE '^#' "$BACKLOG_NS") files)," \
       "and $BACKLOG_CLIENT ($(grep -cvE '^#' "$BACKLOG_CLIENT") files)"
  exit 0
fi

if [ ! -f "$BACKLOG" ]; then
  echo "check_vfs_seam: missing $BACKLOG (run with --regen to seed it)" >&2
  exit 2
fi

# Tier-1 (HARD rule, no backlog): raw positional file syscalls outside the backend.
raw_violations="$(current_raw_tier1)"
if [ -n "$raw_violations" ]; then
  echo "ERROR: raw data-plane POSIX outside the storage backend (src/fs/backend/)." >&2
  echo "       Route file byte I/O through the SD driver (obj->driver-><op>) so the" >&2
  echo "       syscall stays in the backend and a non-POSIX driver can serve it:" >&2
  echo "$raw_violations" | sed 's/^/    /' >&2
  echo "" >&2
  echo "If a hit is genuinely NOT export data (IPC pipe/socket, a control/marker" >&2
  echo "file, or a standalone test outside the module build), add its path prefix to" >&2
  echo "RAW_ALLOW in this script with a one-line justification." >&2
  exit 1
fi

# Subtract the grandfathered files (fixed-string 'path:' prefixes; comments ignored).
violations="$(current_bypasses | grep -vFf <(grep -vE '^[[:space:]]*#' "$BACKLOG") || true)"

if [ -n "$violations" ]; then
  echo "ERROR: new VFS-seam bypass — route export data/namespace ops through brix_vfs_*" >&2
  echo "       (see docs/refactor/phase-56-vfs-storage-driver-perf-audit.md §9):" >&2
  echo "$violations" | sed 's/^/    /' >&2
  echo "" >&2
  echo "If this is a deliberate, reviewed addition to an already-bypassing file, run" >&2
  echo "    tools/ci/check_vfs_seam.sh --regen" >&2
  echo "and justify it in the PR. New files should call brix_vfs_* instead." >&2
  exit 1
fi

# Tier-3: new RAW namespace/metadata syscall in a file not already grandfathered.
if [ ! -f "$BACKLOG_NS" ]; then
  echo "check_vfs_seam: missing $BACKLOG_NS (run with --regen to seed it)" >&2
  exit 2
fi
ns_violations="$(current_raw_tier3 | grep -vFf <(grep -vE '^[[:space:]]*#' "$BACKLOG_NS") || true)"
if [ -n "$ns_violations" ]; then
  echo "ERROR: new RAW namespace/metadata syscall — route export open/stat/opendir/" >&2
  echo "       unlink/rename/mkdir/xattr through brix_vfs_* (phase-2 full VFS seam):" >&2
  echo "$ns_violations" | sed 's/^/    /' >&2
  echo "" >&2
  echo "If this touches a SEPARATE storage domain (cache/stage/journal) or a" >&2
  echo "non-export file (config/cert/token/tmp/socket), add a per-line" >&2
  echo "'/* vfs-seam-allow: <reason> */' marker. For a reviewed addition to an" >&2
  echo "already-bypassing file, run: tools/ci/check_vfs_seam.sh --regen" >&2
  exit 1
fi

# CLIENT tier: new raw positional byte syscall in a client file not already
# grandfathered (and not carrying a per-line vfs-seam-allow marker).
if [ ! -f "$BACKLOG_CLIENT" ]; then
  echo "check_vfs_seam: missing $BACKLOG_CLIENT (run with --regen to seed it)" >&2
  exit 2
fi
client_violations="$(current_raw_client | grep -vFf <(grep -vE '^[[:space:]]*#' "$BACKLOG_CLIENT") || true)"
if [ -n "$client_violations" ]; then
  echo "ERROR: new raw data-plane POSIX in the native client — route a copy/transfer" >&2
  echo "       endpoint's bytes through xrdc_vfs_* (client/lib/vfs.h), which dispatches" >&2
  echo "       to the shared SD driver, instead of a raw pread/pwrite on a local file:" >&2
  echo "$client_violations" | sed 's/^/    /' >&2
  echo "" >&2
  echo "If this is NOT export storage (an anonymous temp / diagnostic / non-export" >&2
  echo "container file), add a per-line '/* vfs-seam-allow: <reason> */' marker. For a" >&2
  echo "reviewed addition to an already-bypassing file, run --regen and justify it." >&2
  exit 1
fi

allow_n="$(grep -cvE '^[[:space:]]*#' "$BACKLOG" || true)"
ns_allow_n="$(grep -cvE '^[[:space:]]*#' "$BACKLOG_NS" || true)"
client_allow_n="$(grep -cvE '^[[:space:]]*#' "$BACKLOG_CLIENT" || true)"
echo "check_vfs_seam: OK — no raw data POSIX outside the backend (tier-1), no new" \
     "tier-2/1.5 bypass ($allow_n files on the migration backlog), no new" \
     "tier-3 raw namespace/metadata syscall ($ns_allow_n files on the ns backlog)," \
     "and no new raw client data POSIX ($client_allow_n files on the client backlog)"
