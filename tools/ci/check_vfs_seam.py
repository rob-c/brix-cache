#!/usr/bin/env python3
#
# check_vfs_seam.py — enforce "the VFS is the sole source of data-plane truth".
#
# Faithful Python port of check_vfs_seam.sh (byte-identical stdout/stderr/exit).
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
#   tools/ci/check_vfs_seam.py            # check; exit 1 on a new bypass
#   tools/ci/check_vfs_seam.py --regen    # rewrite the backlog from the current tree
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

import os
import re
import sys
from pathlib import Path

# Repo root = two levels up from this script (tools/ci/).
ROOT = Path(__file__).resolve().parents[2]

BACKLOG = "tools/ci/vfs_seam_backlog.txt"
# Tier-3 (raw namespace/metadata syscalls) has its OWN backlog: a file may be
# grandfathered for a raw open()/stat() while still being rejected for a new
# tier-2 confined-helper call, so the two allowlists must be independent.
BACKLOG_NS = "tools/ci/vfs_seam_backlog_ns.txt"
# CLIENT tier backlog: grandfathered raw positional byte syscalls in the native
# client outside the client VFS backends.
BACKLOG_CLIENT = "tools/ci/vfs_seam_backlog_client.txt"

# POSIX [[:space:]] in the C locale: HT, LF, VT, FF, CR, space.
_SP = r"[ \t\n\v\f\r]"

# --- tier-2 / tier-1.5 -------------------------------------------------------
# Confined-helper symbols a handler must reach only through brix_vfs_*.
_SYMS = (
    "brix_open_beneath|brix_open_confined_canon"
    "|brix_lstat_beneath|brix_lstat_confined_canon|brix_stat_confined_canon"
    "|brix_opendir_confined_canon"
    "|brix_unlink_beneath|brix_mkdir_recursive_confined_canon"
    "|brix_ns_delete|brix_ns_mkdir|brix_ns_rename|brix_ns_local_copy"
    "|brix_getxattr_confined_canon|brix_setxattr_confined_canon"
    "|brix_listxattr_confined_canon|brix_removexattr_confined_canon"
)
SYMS_RE = re.compile(r"\b(" + _SYMS + r")\s*\(")

# Permanent non-targets (§9.8): helper DEFINITIONS + below-seam layers.
_ALLOW = (
    r"^src/fs/"
    r"|^src/core/compat/namespace_ops|^src/core/compat/staged_file|^src/core/compat/fs_walk"
    r"|^src/auth/impersonate/|^src/observability/dashboard/"
)
ALLOW_RE = re.compile(_ALLOW)

# Tier-1.5: byte loops that call the SD driver vtable directly.
BYTEOPS_RE = re.compile(
    r"brix_sd_posix_driver\.(pread|pwrite|preadv|preadv2|pwritev|copy_range)\s*\("
)

# --- tier-1 ------------------------------------------------------------------
# RAW libc positional file-byte syscalls outside the backend driver.
_RAWOPS = "pread|pwrite|preadv|pwritev|preadv2|pwritev2|copy_file_range|sendfile"
RAW_RE = re.compile(r"(^|[^._>a-zA-Z])(" + _RAWOPS + r")" + _SP + r"*\(")

_RAW_ALLOW = (
    r"^src/fs/backend/"
    r"|^src/protocols/root/zip/zip_dir_unittest"
    r"|^src/protocols/root/zip/zip_kernel\.c"
    r"|^src/fs/meta/xmeta_path\.c"
    r"|^src/fs/cache/cinfo\.c"
    r"|^src/core/http/http_body\.c"
    r"|^src/fs/vfs/vfs_writer\.c"
    r"|^src/protocols/root/read/clone\.c"
)
RAW_ALLOW_RE = re.compile(_RAW_ALLOW)

# --- tier-3 ------------------------------------------------------------------
# RAW namespace/metadata syscalls (phase-2 full VFS seam).
_TIER3_FAM = (
    "getxattr|setxattr|listxattr|removexattr|fgetxattr|fsetxattr|flistxattr|fremovexattr"
    "|opendir|fdopendir|readdir|openat|creat|unlinkat|renameat|mkdirat"
    "|fstatat|ftruncate|fchmod|fchown|symlinkat|readlinkat|linkat"
    "|open|stat|lstat|unlink|rmdir|rename|mkdir|truncate|chmod|chown"
    "|symlink|readlink|mknod|link"
)
TIER3_RE = re.compile(r"(^|[^._>a-zA-Z])(" + _TIER3_FAM + r")" + _SP + r"*\(")

_TIER3_ALLOW = (
    r"^src/fs/|^src/core/compat/|^src/auth/impersonate/"
    r"|^src/observability/dashboard/"
    r"|^src/protocols/root/write/chkpoint|^src/protocols/root/read/slice_read"
    r"|^src/auth/crypto/|^src/auth/gsi/|^src/auth/sss/|^src/auth/pwd/|^src/auth/token/"
    r"|^src/core/config/|^src/auth/krb5/|^src/auth/authz/|^src/auth/voms/|^src/protocols/ssi/"
    r"|^src/protocols/dig/|^src/core/aio/|unittest|_test"
)
TIER3_ALLOW_RE = re.compile(_TIER3_ALLOW)

_TIER3_EXCL = (
    r"brix_vfs_|_confined_canon|_beneath|brix_imp_|brix_ns_"
    r"|brix_open_confined|brix_staged_|brix_mkdir_recursive"
)
TIER3_EXCL_RE = re.compile(_TIER3_EXCL)

# --- C9 typed storage domains (phase-107 W9) ---------------------------------
# Every real src/ marker leads with a domain constant:
#     /* vfs-seam-allow: DOMAIN_CACHE — <reason for humans> */
# The guard checks the half a machine can check — the constant exists, is
# known, and its file is entitled to claim it — and never judges the prose.
# Client-tier markers (client/) are out of scope: the client has its own
# xrdc_vfs storage model, not the server's domain table.
#
# The two non-domain classifications keep pass 1 honest (Appendix G.4):
#   NOT_STORAGE  — the waived call is not a filesystem object at all (probe
#                  socket, admin unix socket, /proc fd hygiene, fd forensics);
#                  entitled everywhere, granting nothing, and COUNTED in the
#                  success line so it cannot quietly become the default.
#   SEAM_CORRECT — the call is already on the right side of the seam (fstat-
#                  class on a VFS-opened fd, an openat inside a VFS-opened dir
#                  stream, a stat of the confinement anchor itself, or compat
#                  code that IS the posix storage plane); annotated, then left
#                  alone. Entitled everywhere, also counted.
DOMAIN_CONSTANTS = frozenset((
    "DOMAIN_CACHE", "DOMAIN_STAGE", "DOMAIN_REGISTRY", "DOMAIN_CREDENTIAL",
    "DOMAIN_CONFIG", "DOMAIN_JOURNAL",
    "NOT_STORAGE", "SEAM_CORRECT",
))
# DOMAIN_EXPORT deliberately absent: an export mutation takes the phase-105
# policy gate, never a waiver (Appendix G.1 row 1).

# The entitlement table (normative source: phase-107 Appendix G.1, extended by
# the W9 census — every extension is recorded in the W9 landed notes).
# DIRECTORY or file-stem prefixes, never full path:line, so a shard or an
# archived copy does not invalidate the table; the LONGEST matching prefix
# decides (the fs/cache origin_auth and net/cms blacklist bends need it).
DOMAIN_ENTITLE = (
    # (prefix, frozenset of domains the prefix may claim)
    ("src/fs/cache/origin_auth",                  frozenset(("DOMAIN_CONFIG",))),
    ("src/fs/cache/",                             frozenset(("DOMAIN_CACHE",))),
    ("src/fs/backend/cache/",                     frozenset(("DOMAIN_CACHE",))),
    ("src/fs/backend/stage/",                     frozenset(("DOMAIN_STAGE",))),
    ("src/fs/backend/cred_mint",                  frozenset(("DOMAIN_CREDENTIAL",))),
    ("src/fs/meta/",                              frozenset(("DOMAIN_CACHE",))),
    ("src/fs/vfs/vfs_deleg",                      frozenset(("DOMAIN_CREDENTIAL",))),
    ("src/fs/vfs/vfs_writer_spill",               frozenset(("DOMAIN_STAGE",))),
    ("src/fs/xfer/stage_",                        frozenset(("DOMAIN_JOURNAL",))),
    ("src/fs/xfer/",                              frozenset(("DOMAIN_STAGE",))),
    ("src/fs/tier/",                              frozenset(("DOMAIN_JOURNAL",))),
    ("src/tpc/",                                  frozenset(("DOMAIN_STAGE", "DOMAIN_CREDENTIAL"))),
    ("src/protocols/oci/",                        frozenset(("DOMAIN_REGISTRY",))),
    ("src/protocols/webdav/tpc_cred_exchange.c",  frozenset(("DOMAIN_CREDENTIAL",))),
    ("src/protocols/webdav/tpc_user_proxy.c",     frozenset(("DOMAIN_CREDENTIAL",))),
    ("src/protocols/webdav/tpc_",                 frozenset(("DOMAIN_STAGE",))),
    ("src/protocols/webdav/put_body_digest.c",    frozenset(("DOMAIN_STAGE",))),
    ("src/protocols/webdav/delegation.c",         frozenset(("DOMAIN_CREDENTIAL",))),
    ("src/protocols/shared/http_serve_offload.c", frozenset(("DOMAIN_STAGE",))),
    ("src/protocols/root/read/",                  frozenset(("DOMAIN_CACHE", "DOMAIN_STAGE"))),
    ("src/protocols/root/connection/",            frozenset(("DOMAIN_CACHE", "DOMAIN_STAGE"))),
    ("src/protocols/cvmfs/attest.c",              frozenset(("DOMAIN_CONFIG",))),
    ("src/protocols/gridftp/ftp_module_gsi.c",    frozenset(("DOMAIN_CONFIG",))),
    ("src/auth/",                                 frozenset(("DOMAIN_CREDENTIAL",))),
    ("src/net/proxy/",                            frozenset(("DOMAIN_CREDENTIAL",))),
    ("src/net/cms/blacklist_file.c",              frozenset(("DOMAIN_CONFIG",))),
    ("src/net/cms/",                              frozenset(("DOMAIN_JOURNAL",))),
    ("src/core/config/",                          frozenset(("DOMAIN_CONFIG",))),
    ("src/core/compat/cred_stage",                frozenset(("DOMAIN_CREDENTIAL",))),
)

# A doc-comment line (leading '*', '//' or a full-line '/*') that merely
# MENTIONS the convention is not a marker — the marker form is a trailing
# comment on a code line (Appendix G.2's 108-not-117 rule).
DOC_LINE_RE = re.compile(r"^[ \t]*(\*|//|/\*)")
DOMAIN_TOKEN_RE = re.compile(r"vfs-seam-allow:\s*([A-Za-z_][A-Za-z0-9_]*)")


def _src_ch_files():
    for dirpath, dirnames, filenames in os.walk("src"):
        dirnames.sort()
        for name in sorted(filenames):
            if name.endswith(".c") or name.endswith(".h"):
                yield os.path.join(dirpath, name)


def _file_domain_markers(path):
    """One file's real markers as (path, lineno, token-or-None)."""
    try:
        with open(path, "r", encoding="latin-1") as fh:
            data = fh.read()
    except OSError:
        return []
    out = []
    for lineno, content in enumerate(data.split("\n"), 1):
        if "vfs-seam-allow" not in content or DOC_LINE_RE.match(content):
            continue
        m = DOMAIN_TOKEN_RE.search(content)
        out.append((path, lineno, m.group(1) if m else None))
    return out


def domain_markers():
    """Every real src/ marker as (path, lineno, token-or-None)."""
    return [marker
            for path in _src_ch_files()
            for marker in _file_domain_markers(path)]


def domain_entitled(path):
    """The domain set the longest matching table prefix entitles `path` to."""
    best = None
    for prefix, domains in DOMAIN_ENTITLE:
        if path.startswith(prefix) and (best is None or len(prefix) > len(best[0])):
            best = (prefix, domains)
    return best[1] if best is not None else frozenset()


def domain_violation(path, lineno, token):
    """One marker's verdict: None when in order, else the failure line."""
    if token is None or token not in DOMAIN_CONSTANTS:
        kind = "unknown domain constant" if token else "missing domain constant"
        known = ", ".join(sorted(DOMAIN_CONSTANTS))
        return (f"{path}:{lineno}: {kind}"
                f"{' ' + repr(token) if token else ''} — a marker reads"
                f" '/* vfs-seam-allow: <DOMAIN> — <reason> */' with <DOMAIN>"
                f" one of: {known}")
    if token in ("NOT_STORAGE", "SEAM_CORRECT"):
        return None            # entitled everywhere, granting nothing
    entitled = domain_entitled(path)
    if token not in entitled:
        have = ", ".join(sorted(entitled)) if entitled else "(none)"
        return (f"{path}:{lineno}: {token} is not entitled here — this path"
                f" may claim: {have}. Extend DOMAIN_ENTITLE only as a reviewed"
                f" change (it is an allowlist).")
    return None


# --- client tier -------------------------------------------------------------
_CLIENT_ALLOW = (
    r"^client/lib/fs/vfs\.c|^client/lib/fs/vfs_posix\.c|^client/lib/fs/vfs_block\.c"
    r"|^client/lib/fs/backend/s3/vfs_s3"
)
CLIENT_ALLOW_RE = re.compile(_CLIENT_ALLOW)

# Drop full-line comments: ':<lineno>:' followed by optional space then a
# comment marker (mirrors `grep -vE ':[0-9]+:[[:space:]]*(\*|//|/\*)'`).
COMMENT_DROP_RE = re.compile(r":[0-9]+:" + _SP + r"*(\*|//|/\*)")


def _c_files(roots):
    """Every *.c file under each root, recursively (mirrors `grep -r --include=*.c`)."""
    for root in roots:
        for dirpath, dirnames, filenames in os.walk(root):
            dirnames.sort()
            for name in sorted(filenames):
                if name.endswith(".c"):
                    yield os.path.join(dirpath, name)


def _grep(roots, pattern):
    """`grep -rnE pattern roots --include=*.c` → list of 'path:lineno:content'.

    Files are read as latin-1 so arbitrary bytes round-trip 1:1 (grep is
    byte-oriented); the pattern is matched against the file line only, then the
    'path:lineno:' prefix is prepended exactly as grep -n does."""
    out = []
    for path in _c_files(roots):
        try:
            with open(path, "r", encoding="latin-1") as fh:
                data = fh.read()
        except OSError:
            continue
        for lineno, content in enumerate(data.split("\n"), 1):
            if pattern.search(content):
                out.append(f"{path}:{lineno}:{content}")
    return out


def _strip_comments_strings(line):
    """`sed -E 's#/\\*[^*]*\\*/##g; s#//.*##g; s#"([^"\\\\]|\\\\.)*"##g'` — strip
    /*...*/ block comments, //... line comments, then "..." string literals,
    in that order."""
    line = re.sub(r"/\*[^*]*\*/", "", line)
    line = re.sub(r"//.*", "", line)
    line = re.sub(r'"([^"\\]|\\.)*"', "", line)
    return line


def current_bypasses():
    """tier-2 confined-helper calls + tier-1.5 SD-direct byte loops, outside the
    allowed layer, comment-filtered (mirrors the shell's current_bypasses)."""
    lines = _grep(["src"], SYMS_RE) + _grep(["src"], BYTEOPS_RE)
    kept = [
        line for line in lines
        if not COMMENT_DROP_RE.search(line) and not ALLOW_RE.search(line)
    ]
    return sorted(set(kept))


def current_raw_tier1():
    """RAW positional file-byte syscalls outside the backend (HARD rule)."""
    kept = []
    for line in _grep(["src"], RAW_RE):
        stripped = _strip_comments_strings(line)
        if not RAW_RE.search(stripped):
            continue
        if COMMENT_DROP_RE.search(stripped):
            continue
        if RAW_ALLOW_RE.search(stripped):
            continue
        kept.append(stripped)
    return sorted(set(kept))


def current_raw_tier3():
    """RAW namespace/metadata syscalls outside the allowed/excluded layers."""
    kept = filter(None, map(_raw_tier3_violation, _grep(["src"], TIER3_RE)))
    return sorted(set(kept))


def _raw_tier3_violation(line):
    if "vfs-seam-allow" in line:
        return None
    if TIER3_ALLOW_RE.search(line) or TIER3_EXCL_RE.search(line):
        return None
    stripped = _strip_comments_strings(line)
    if not TIER3_RE.search(stripped) or COMMENT_DROP_RE.search(stripped):
        return None
    return stripped


def current_raw_client():
    """RAW positional byte syscalls in the native client outside its VFS backends."""
    kept = []
    for line in _grep(["client/lib", "client/apps"], RAW_RE):
        if "vfs-seam-allow" in line:
            continue
        stripped = _strip_comments_strings(line)
        if not RAW_RE.search(stripped):
            continue
        if COMMENT_DROP_RE.search(stripped):
            continue
        if CLIENT_ALLOW_RE.search(stripped):
            continue
        kept.append(stripped)
    return sorted(set(kept))


def _prefixes(lines):
    """`sed -E 's/^([^:]+):.*/\\1:/' | sort -u` — reduce each hit to its 'path:'."""
    return sorted(set(line.split(":", 1)[0] + ":" for line in lines))


def _noncomment_lines(path, pattern):
    """Count file lines NOT matching `pattern` at the start (mirrors grep -cvE)."""
    try:
        with open(path, "r", encoding="utf-8") as fh:
            data = fh.read()
    except OSError:
        return 0
    return sum(1 for line in data.splitlines() if not pattern.match(line))


# `grep -cvE '^#'` (regen summary) vs `grep -cvE '^[[:space:]]*#'` (check counts).
_HASH_RE = re.compile(r"#")
_WS_HASH_RE = re.compile(_SP + r"*#")


def _subtract_backlog(violations, backlog_path):
    """`current | grep -vFf <(grep -vE '^[[:space:]]*#' backlog)` — drop any
    violation line that CONTAINS a (non-comment) backlog entry as a substring."""
    patterns = _backlog_patterns(backlog_path)
    if patterns is None:
        return list(violations)
    if not patterns:
        return list(violations)
    return [v for v in violations if not any(p in v for p in patterns)]


def _backlog_patterns(path):
    try:
        with open(path, "r", encoding="utf-8") as fh:
            data = fh.read()
    except OSError:
        return None
    return [line for line in data.splitlines() if not _WS_HASH_RE.match(line)]


def regen():
    with open(BACKLOG, "w", encoding="utf-8") as fh:
        fh.write("# vfs_seam_backlog.txt — grandfathered tier-2 seam bypasses (phase-56 §9, App C).\n")
        fh.write("# Each entry is a 'path:' prefix; a migrated file's line is DELETED here so the\n")
        fh.write("# guard then rejects any regression in it. When this file holds only comments the\n")
        fh.write("# seam is closed. Regenerate ONLY after a deliberate migration: --regen.\n")
        for entry in _prefixes(current_bypasses()):
            fh.write(entry + "\n")
    with open(BACKLOG_NS, "w", encoding="utf-8") as fh:
        fh.write("# vfs_seam_backlog_ns.txt — grandfathered tier-3 raw namespace/metadata\n")
        fh.write("# syscalls (phase-2 full VFS seam, 2026-06-28). Same rules as the tier-2\n")
        fh.write("# backlog: each entry is a 'path:' prefix; a migrated file's line is DELETED\n")
        fh.write("# so the guard then rejects any regression in it. A deliberate raw call to a\n")
        fh.write("# SEPARATE storage domain (cache/stage/journal) should instead carry a\n")
        fh.write("# per-line 'vfs-seam-allow' marker. Regenerate ONLY after a migration.\n")
        for entry in _prefixes(current_raw_tier3()):
            fh.write(entry + "\n")
    with open(BACKLOG_CLIENT, "w", encoding="utf-8") as fh:
        fh.write("# vfs_seam_backlog_client.txt — grandfathered raw positional byte syscalls\n")
        fh.write("# in the native client (client/lib + client/apps) outside the client VFS\n")
        fh.write("# backends. Same rules as the other backlogs: each entry is a 'path:' prefix;\n")
        fh.write("# a file migrated onto xrdc_vfs_* is DELETED here so the guard then rejects any\n")
        fh.write("# regression in it. A permanently non-storage raw call carries a per-line\n")
        fh.write("# 'vfs-seam-allow' marker instead. Regenerate ONLY after a migration.\n")
        for entry in _prefixes(current_raw_client()):
            fh.write(entry + "\n")
    n = _noncomment_lines(BACKLOG, _HASH_RE)
    ns = _noncomment_lines(BACKLOG_NS, _HASH_RE)
    nc = _noncomment_lines(BACKLOG_CLIENT, _HASH_RE)
    print(f"check_vfs_seam: regenerated {BACKLOG} ({n} files), "
          f"{BACKLOG_NS} ({ns} files), "
          f"and {BACKLOG_CLIENT} ({nc} files)")
    return 0


def check():
    if not os.path.isfile(BACKLOG):
        print(f"check_vfs_seam: missing {BACKLOG} (run with --regen to seed it)", file=sys.stderr)
        return 2
    for checker in (_check_raw_tier1, _check_bypasses, _check_raw_tier3,
                    _check_raw_client, _check_domains):
        result = checker()
        if result:
            return result
    _print_success()
    return 0


def _check_raw_tier1():
    raw_violations = current_raw_tier1()
    if not raw_violations:
        return 0
    _print_violation(
        raw_violations,
        "ERROR: raw data-plane POSIX outside the storage backend (src/fs/backend/).",
        ("       Route file byte I/O through the SD driver (obj->driver-><op>) so the",
         "       syscall stays in the backend and a non-POSIX driver can serve it:"),
        ("If a hit is genuinely NOT export data (IPC pipe/socket, a control/marker",
         "file, or a standalone test outside the module build), add its path prefix to",
         "RAW_ALLOW in this script with a one-line justification."),
    )
    return 1


def _check_bypasses():
    violations = _subtract_backlog(current_bypasses(), BACKLOG)
    if not violations:
        return 0
    _print_violation(
        violations,
        "ERROR: new VFS-seam bypass — route export data/namespace ops through brix_vfs_*",
        ("       (see docs/refactor/phase-56-vfs-storage-driver-perf-audit.md §9):",),
        ("If this is a deliberate, reviewed addition to an already-bypassing file, run",
         "    tools/ci/check_vfs_seam.py --regen",
         "and justify it in the PR. New files should call brix_vfs_* instead."),
    )
    return 1


def _check_raw_tier3():
    if not os.path.isfile(BACKLOG_NS):
        print(f"check_vfs_seam: missing {BACKLOG_NS} (run with --regen to seed it)", file=sys.stderr)
        return 2
    ns_violations = _subtract_backlog(current_raw_tier3(), BACKLOG_NS)
    if not ns_violations:
        return 0
    _print_violation(
        ns_violations,
        "ERROR: new RAW namespace/metadata syscall — route export open/stat/opendir/",
        ("       unlink/rename/mkdir/xattr through brix_vfs_* (phase-2 full VFS seam):",),
        ("If this touches a SEPARATE storage domain (cache/stage/journal) or a",
         "non-export file (config/cert/token/tmp/socket), add a per-line",
         "'/* vfs-seam-allow: <reason> */' marker. For a reviewed addition to an",
         "already-bypassing file, run: tools/ci/check_vfs_seam.py --regen"),
    )
    return 1


def _check_raw_client():
    if not os.path.isfile(BACKLOG_CLIENT):
        print(f"check_vfs_seam: missing {BACKLOG_CLIENT} (run with --regen to seed it)", file=sys.stderr)
        return 2
    client_violations = _subtract_backlog(current_raw_client(), BACKLOG_CLIENT)
    if not client_violations:
        return 0
    _print_violation(
        client_violations,
        "ERROR: new raw data-plane POSIX in the native client — route a copy/transfer",
        ("       endpoint's bytes through xrdc_vfs_* (client/lib/vfs.h), which dispatches",
         "       to the shared SD driver, instead of a raw pread/pwrite on a local file:"),
        ("If this is NOT export storage (an anonymous temp / diagnostic / non-export",
         "container file), add a per-line '/* vfs-seam-allow: <reason> */' marker. For a",
         "reviewed addition to an already-bypassing file, run --regen and justify it."),
    )
    return 1


def _check_domains():
    violations = [
        v for v in (domain_violation(p, n, t) for p, n, t in domain_markers())
        if v is not None
    ]
    if not violations:
        return 0
    _print_violation(
        violations,
        "ERROR: vfs-seam-allow marker without a valid, entitled storage domain",
        ("       (phase-107 C9 — the typed storage domain; Appendix G.1 is the",
         "       normative table):",),
        ("Every src/ marker leads with a domain constant. Assigning one is a",
         "SECURITY decision — a wrong domain here becomes a false entitlement.",
         "NOT_STORAGE (not a filesystem object) and SEAM_CORRECT (already on the",
         "right side of the seam) exist so a marker never has to lie."),
    )
    return 1


def _print_violation(violations, heading, explanation, guidance):
    print(heading, file=sys.stderr)
    for line in explanation:
        print(line, file=sys.stderr)
    for line in violations:
        print("    " + line, file=sys.stderr)
    print("", file=sys.stderr)
    for line in guidance:
        print(line, file=sys.stderr)


def _print_success():
    allow_n = _noncomment_lines(BACKLOG, _WS_HASH_RE)
    ns_allow_n = _noncomment_lines(BACKLOG_NS, _WS_HASH_RE)
    client_allow_n = _noncomment_lines(BACKLOG_CLIENT, _WS_HASH_RE)
    markers = domain_markers()
    not_storage = sum(1 for _, _, t in markers if t == "NOT_STORAGE")
    seam_correct = sum(1 for _, _, t in markers if t == "SEAM_CORRECT")
    print("check_vfs_seam: OK — no raw data POSIX outside the backend (tier-1), no new "
          f"tier-2/1.5 bypass ({allow_n} files on the migration backlog), no new "
          f"tier-3 raw namespace/metadata syscall ({ns_allow_n} files on the ns backlog), "
          f"no new raw client data POSIX ({client_allow_n} files on the client backlog), "
          f"and every domain claim entitled ({len(markers)} markers: "
          f"{not_storage} NOT_STORAGE, {seam_correct} SEAM_CORRECT)")


def main():
    # Run from the repo root so the 'src'/'client'/'tools/ci/...' relative paths
    # — and the file column reported — line up regardless of cwd.
    os.chdir(ROOT)
    if len(sys.argv) > 1 and sys.argv[1] == "--regen":
        return regen()
    return check()


if __name__ == "__main__":
    sys.exit(main())
