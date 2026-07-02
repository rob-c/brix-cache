# path — untrusted-path confinement, resolution, ACL/auth gating, and access logging

## Overview

This subsystem is the security boundary between an untrusted client path (arriving on the
XRootD `root://` wire, a WebDAV/HTTP URL, or an S3 `/<bucket>/<key>`) and any syscall the
gateway makes against the local POSIX export root. Every namespace and file operation in the
module — open, stat, read, write, mkdir, rm, rename, dirlist, checksum, TPC staging — passes
its path through here first. The cardinal invariant of the whole project lives in this folder:
**no raw `open`/`stat`/`unlink` on a client path; the kernel, not nginx code, enforces that a
path cannot escape the export root.**

Confinement is implemented with Linux `openat2(2)` + `RESOLVE_BENEATH` (`beneath.c`), anchored
to a persistent O_PATH "rootfd" opened once per worker (stream `conf->rootfd`, HTTP
`conf->common.rootfd`). The historical design canonicalised paths with `realpath(3)` and then
string-compared against the root; Phase 8 retired that for runtime client paths. Today the
runtime flow is: extract the path from the wire payload (`extract.c`), validate it lexically
(length, depth limit, reject `.`/`..` segments — `op_path.c`, `helpers.c`), build a lexical
`root_canon + reqpath` join used only for ACL prefix-matching and logging
(`xrootd_beneath_full_path` in `beneath.h`), and let `openat2(RESOLVE_BENEATH)` reject any
actual escape (`EXDEV`) at the moment of the syscall. `realpath(3)` survives only for
**config-time** canonicalisation of trusted, admin-configured policy-rule paths (`canonical.c`,
`helpers.c`, `unified.c`, `resolve_path_variants.c`) — never for a client request path.

On top of confinement, this folder owns the authorization layer that sits between a
resolved path and the operation: the three-tier `auth_gate.c` (authdb → VO ACL → token
scope) plus its supporting rule databases (`authdb.c`, `acl.c`, `find_rule.c`), the
parent-group ownership policy applied to newly created files/dirs (`group_policy.c`), an
optional cross-worker decision cache (`auth_cache.c`), and the per-request access log
(`access_log.c`). It also provides small shared utilities every protocol needs: wire-string
sanitization for safe logging, the `kXR_stat` ASCII body formatter, recursive mkdir,
policy-path normalization, and config-array merging.

Entry into this subsystem is almost always one of two convenience front-doors used by stream
handlers: `xrootd_resolve_op_path()` (extract + validate + per-mode existence gate, sending the
kXR error itself on failure) and `xrootd_auth_gate()` (the three-tier authz check, sending
`kXR_NotAuthorized` itself on failure). HTTP/S3 handlers reach the same primitives through the
`compat/` adapter layer.

## Files

| File | Responsibility |
|---|---|
| `path.h` | Public API: sanitize/normalize/merge helpers, rule finalize + longest-prefix lookups, VO/authdb checks, group-policy appliers, confined namespace syscalls, `xrootd_resolve_path_noexist` (config-time), recursive mkdir, `xrootd_extract_path`, `xrootd_strip_cgi`, `xrootd_count_path_depth`, stat-body formatter, access-log writer/flush. |
| `path_internal.h` | Folder-private declarations: `xrootd_path_component_forbidden`, `xrootd_log_path_warning`, `xrootd_path_within_root`, `xrootd_resolved_relative_to_root`, `xrootd_get_canonical_root`, `xrootd_finalize_path_rules`. |
| **Kernel confinement** | |
| `beneath.h` / `beneath.c` | The `openat2(RESOLVE_BENEATH \| RESOLVE_NO_MAGICLINKS)` confinement API, anchored to a per-worker O_PATH rootfd: `xrootd_open_beneath`, `xrootd_stat_beneath`, `xrootd_unlink/mkdir/rename/link_beneath`. Mutating `*at()` ops resolve the **parent** under `RESOLVE_BENEATH` (`beneath_open_parent`) then act on the final component only (SECURITY note at `beneath.c:64`). Inline helpers `xrootd_beneath_rel`/`_strip_root`/`_full_path` strip/join root-relative tails. `#error`s at compile if kernel headers predate 5.6. `how.mode` is masked to `07777` (`beneath.c:91`) because `openat2` rejects `S_IFMT` type bits. |
| `op_path.h` / `op_path.c` | Runtime path front-door for stream handlers. `xrootd_resolve_op_path` = extract + depth-check + per-mode existence gate (emits the kXR error, sets `ctx->write_rc`, returns `NGX_DONE`); `xrootd_path_resolve_beneath` is the realpath-free core (also called directly by two-path `kXR_mv`); `xrootd_op_path_forbidden_component` rejects any `.`/`..` segment. Existence verified with `xrootd_stat_beneath`, not `realpath`; WRITE mode also confirms the parent dir exists. Defines `xrootd_path_mode_t` (EXISTING/WRITE/NOEXIST/EITHER). |
| **Auth & ACL** | |
| `auth_gate.h` / `auth_gate.c` | Three-tier gate run by every namespace handler: `xrootd_check_authdb` → `xrootd_check_vo_acl_identity` → `xrootd_check_token_scope`. First failing tier sends `kXR_NotAuthorized`, stores `ctx->write_rc`, returns `NGX_DONE`. Builds the auth-cache key (SHA-256 over level+write+resolved+reqpath+DN+VO+raw scope, `auth_gate.c:22`) and consults/populates the result cache around the scans. |
| `auth_cache.h` / `auth_cache.c` | Cross-worker SHM cache of the combined gate verdict (`xrootd_kv_t`-backed, short TTL, default 30 s). `auth_cache.c` only parses the `xrootd_auth_cache zone=… [ttl=…]` directive and validates the zone is large enough (key≥32, val≥`sizeof(xrootd_auth_cache_val_t)`); the lookup/store is inline in `auth_gate.c` where every key input is in scope. Stream-only. |
| `authdb.c` | XRootD-style authdb: parse `[u\|g\|p\|a] <id> <path> <privs>` file (≤1 MiB) into rules, `privs` chars (`rlwadmk`) → `XROOTD_AUTH_*` bits; longest-prefix rule match with identity filter (ALL / user-DN / group-VO `*`-wildcard / host CIDR or IP) and privilege-bitmask check; `xrootd_check_authdb[_identity]` returns NGX_OK or logs a sanitized deny + NGX_ERROR. Empty rule array ⇒ allow-all. |
| `acl.c` | VO (Virtual Organization) ACL: `xrootd_finalize_vo_rules` canonicalises rule paths at startup; `xrootd_vo_list_contains` tests a VO against a comma-separated client VO list (empty `required_vo` ⇒ allow-all, empty `vo_list` ⇒ deny); `xrootd_check_vo_acl[_identity]` does longest-prefix lookup + membership check, logs sanitized deny. No matching rule ⇒ allow. |
| `find_rule.c` | Boundary-aware longest-prefix matcher (`/data` matches `/data/x` but not `/data-x`) for VO rules, group-policy rules, and the manager-map (`xrootd_find_manager_map`, cluster routing). All inputs must be canonical before matching; on length ties the later rule wins (`>=`). |
| `group_policy.c` | Parent-directory group inheritance for newly created files/dirs: find matching group rule, derive group mode bits from the parent's `st_mode` (`S_IRWXG` for dirs; `S_IRGRP\|S_IWGRP` plus inherited `S_IXGRP` for files), propagate GID via `chown/fchown`, propagate `S_ISGID` on directories, apply mode via `chmod/fchmod`. Both fd-based (`_fd`) and path-based (`_path`) entry points. |
| **Helpers & formatting** | |
| `helpers.c` | Core utilities: `xrootd_path_component_forbidden` (`.`/`..`), `xrootd_sanitize_log_string` (printable ASCII 0x21–0x7e except `"`/`\` pass through; everything else → `\xNN`; NULL → `"-"`), `xrootd_count_path_depth` (≤ `XROOTD_MAX_WALK_DEPTH` = 32, DoS guard), and the generic `xrootd_finalize_path_rules` config-time canonicaliser used by the three rule databases (a `/`-only rule resolves to the canonical root directly). |
| `extract.c` | `xrootd_extract_path`: pull a NUL-terminated path out of a raw wire payload — reject oversize (> `XROOTD_MAX_PATH`) and *embedded* NULs (a single trailing NUL is allowed/trimmed), optionally truncate a `?cgi` suffix. |
| `strip_cgi.c` | `xrootd_strip_cgi`: standalone (no module include) truncate-at-`?` so the resolver never tries to open `file?checksum=md5` on disk (wire-path invariant #4). |
| `normalize.c` | `xrootd_normalize_policy_path`: directive-time canonical form for policy paths (collapse `//`, reject `.`/`..` segments, ensure `/`-prefix) so longest-prefix matching is correct. |
| `merge.c` | `xrootd_merge_arrays`: concatenate parent+child `ngx_array_t` (parent first) for main→srv→loc config inheritance of rule lists. |
| `mkdir.c` | Recursive directory creation (one level per `/` segment) with optional parent-group-policy inheritance applied to each newly-created level: `xrootd_mkdir_recursive` (plain `mkdir`, no policy), `xrootd_mkdir_recursive_policy` (plain `mkdir` + policy), and the confined variants `xrootd_mkdir_recursive_confined_canon` (via `xrootd_mkdir_confined_canon`) and `xrootd_mkdir_recursive_beneath` (via `xrootd_mkdir_beneath` under a per-worker rootfd). Policy is applied only on a successful `mkdir`, not on `EEXIST`. |
| `stat_body.c` | `xrootd_make_stat_body`: format the XRootD `kXR_stat`/`kXR_statx` ASCII body `"<id> <size> <flags> <mtime>"`, OR-ing in caller `extra_flags` (e.g. `kXR_cachersp`); separate VFS (block-count) vs real-fs (inode + permission flags) modes. |
| `access_log.c` | Per-request access-log line (client IP, authmethod gsi/sss/unix/krb5/anon, DN, Apache-style timestamp, verb/path/detail, OK/ERR, bytes, duration ms), all fields sanitized. Phase 33 per-worker 64 KiB batch buffer flushed on full / fd-switch / 1 s timer / disconnect (`xrootd_access_log_flush`). |
| `canonical.c` | `xrootd_get_canonical_root`: `realpath(3)` the configured export root into a canonical string (config/startup; the anchor for everything else). |
| **Legacy realpath resolver (config-time only)** | |
| `unified.h` / `unified.c` | The fixed-buffer `realpath`-based resolver `xrootd_path_resolve_cstr` with `xrootd_path_opts_t`/`xrootd_path_result_t`/`xrootd_path_status_t`. Builds a candidate, `realpath`s it, and handles missing-tail (create) and missing-parents (ancestor-walk realpath) with `xrootd_path_within_root` re-checks at every step. Runtime client callers were migrated to the beneath path; this now backs only config-time canonicalisation. |
| `resolve_path_variants.c` | `xrootd_resolve_path_noexist` — the one surviving public realpath resolver (sets `allow_missing_parents`), used only by `xrootd_finalize_path_rules` to canonicalise trusted VO/group/authdb rule paths at startup. Comments document the Phase 8 removal of the EXISTING/WRITE runtime variants. |
| `resolve_confined_helpers.c` | Defence-in-depth confinement primitives: `xrootd_path_within_root` (prefix-attack-proof boundary check), `xrootd_resolved_relative_to_root` (strip root, `EXDEV` on escape), `xrootd_open_root_fd` (O_PATH opener), `xrootd_openat2_confined` wrapper + `xrootd_openat2_runtime_available` probe, `xrootd_split_relative_parent`, and the O_NOFOLLOW segment-by-segment parent-walk fallback (`xrootd_open_confined_parent_fallback`/`_canon`) for pre-5.6 kernels. |
| `resolve_confined_ops.c` | Legacy `*_confined_canon` namespace ops (`open`/`unlink`/`mkdir`/`rename`/`link`) layering canonical resolution + `openat2 RESOLVE_BENEATH` (or O_NOFOLLOW fallback). Used by callers that hold a `root_canon` string but no per-worker rootfd; the beneath API supersedes these on hot paths. |

## Key types & data structures

- **`xrootd_path_mode_t`** (`op_path.h`) — per-operation existence policy: `EXISTING` (target must
  exist: stat/locate/open-read/rm/chmod), `WRITE` (parent dir must exist, target may not, trailing
  slash rejected: create), `NOEXIST` (no existence gate: recursive mkdir), `EITHER` (parent-exists OR
  target-exists: truncate/rmdir). Embedded in the write-layer op-table descriptors.
- **`xrootd_authdb_rule_t`** (module header) — one authdb line: `type` (`xrootd_auth_type_t`:
  `'u'`/`'g'`/`'p'`/`'a'` → user/group/host/all), `id` (DN, VO, `*`, or CIDR/IP), `path`, `privs`
  bitmask, and `resolved` (canonical path filled at finalize). Matched longest-prefix.
- **`xrootd_vo_rule_t` / `xrootd_group_rule_t` / `xrootd_manager_map_t`** — prefix→policy entries;
  each carries a `resolved` (rules) or `prefix` (manager-map) string for boundary-aware
  longest-prefix matching in `find_rule.c`.
- **`XROOTD_AUTH_*` privilege bits** — `READ`/`LOOKUP`/`UPDATE`/`DELETE`/`MKDIR`/`ADMIN`, parsed
  from authdb `rlwadmk` chars and passed as `needed_privs` (the `auth_level`) into the gate.
- **`xrootd_auth_cache_conf_t` / `xrootd_auth_cache_val_t`** (`auth_cache.h`) — directive config
  (`kv` zone + `ttl_secs`) and the 3-byte cached verdict (`allowed`, `auth_level`, `pad`).
- **`xrootd_path_opts_t` / `xrootd_path_result_t` / `xrootd_path_status_t`** (`unified.h`) — option
  flags (`allow_missing_tail`/`_parents`, `require_directory`, `allow_root`, …), result
  (resolved/type/depth/confined), and status enum for the config-time realpath resolver.
- **per-worker rootfd** — a persistent O_PATH fd on the canonical root (`conf->rootfd` for stream,
  `conf->common.rootfd` for HTTP), the anchor every beneath-API call needs. Not a struct in this
  folder but the load-bearing piece of state the API assumes.

## Control & data flow

**Stream (`root://`) namespace op (the common path):**
1. A handler in [../read/](../read/README.md), [../write/](../write/README.md),
   [../dirlist/](../dirlist/README.md), [../query/](../query/README.md), or
   [../fattr/](../fattr/README.md) calls `xrootd_resolve_op_path(ctx, c, OP, "VERB", conf, MODE,
   reqpath, …, resolved, …)`.
2. That runs `xrootd_extract_path` (`extract.c`) → `xrootd_path_resolve_beneath` (`op_path.c`):
   `xrootd_count_path_depth` + `xrootd_op_path_forbidden_component` (`helpers.c`), per-mode
   existence via `xrootd_stat_beneath` (`beneath.c`), and the lexical `xrootd_beneath_full_path`
   join. On failure it emits the kXR error (`ArgMissing`/`ArgInvalid`/`NotFound`) and returns
   `NGX_DONE`.
3. The handler then calls `xrootd_auth_gate(ctx, c, OP, "VERB", reqpath, resolved, conf,
   AUTH_LEVEL, need_write)` (`auth_gate.c`): auth-cache fast path, then `xrootd_check_authdb`
   (`authdb.c`) → `xrootd_check_vo_acl_identity` (`acl.c`, via `find_rule.c`) →
   `xrootd_check_token_scope` ([../token/](../token/README.md)).
4. The actual syscall runs through the beneath API (`xrootd_open_beneath` etc.) anchored to
   `conf->rootfd`; an escape returns `EXDEV` → mapped to `kXR_NotAuthorized` by
   `xrootd_kxr_from_errno`. File data then flows out via [../aio/](../aio/README.md) +
   [../response/](../response/README.md) / [../fs/](../fs/README.md).
5. `xrootd_log_access` (`access_log.c`) records the result; `xrootd_access_log_flush` is called
   on disconnect.

**HTTP / S3:** WebDAV ([../webdav/](../webdav/README.md)) and S3 ([../s3/](../s3/README.md))
handlers reach the same primitives — `xrootd_beneath_full_path`, the beneath ops, and the
confined `*_canon` ops — through the [../compat/](../compat/README.md) adapter
(`namespace_ops.c`). They use `xrootd_get_canonical_root` / `xrootd_open_confined_canon` and
`xrootd_sanitize_log_string` directly.

**Config / startup:** `canonical.c` canonicalises the export root; `xrootd_finalize_path_rules`
(`helpers.c`) canonicalises every VO/authdb/group rule path via the surviving
`xrootd_resolve_path_noexist` (`resolve_path_variants.c` → `unified.c`); `merge.c` merges
inherited rule arrays; `normalize.c` canonicalises directive policy paths; `auth_cache.c` binds
the gate cache to an `xrootd_kv` SHM zone ([../shm/](../shm/README.md)).

**Cluster:** `xrootd_find_manager_map` (`find_rule.c`) feeds path→server routing used by the
[../manager/](../manager/README.md) / [../cms/](../cms/README.md) redirector.

## Invariants, security & gotchas

- **Confinement is the kernel's job, not the resolver's.** Runtime client paths are *not*
  `realpath`-canonicalised. The `resolved` string from `xrootd_path_resolve_beneath` is a
  *lexical* join used only for ACL prefix-matching and logging — it is **not** a confinement
  boundary. The boundary is `openat2(RESOLVE_BENEATH)` at the operation (`beneath.c`). Anything
  that escapes returns `EXDEV`; callers must map it to `kXR_NotAuthorized`/403, never fall through
  to a raw syscall (`beneath.h` header contract; `xrootd_beneath_strip_root` returns NULL on
  out-of-root).
- **`*at()` is not confined; `openat2` is.** `mkdirat`/`unlinkat`/`renameat`/`linkat` do *not*
  honour `RESOLVE_BENEATH`. A symlink in an intermediate component would escape. Mutating ops
  therefore resolve the **parent** under `RESOLVE_BENEATH` (`beneath_open_parent` in `beneath.c`)
  and operate on the final component name only — SECURITY block at `beneath.c:64`.
- **`realpath(3)` only for trusted config paths.** It is deliberately *not* migrated to the
  beneath API for VO/group/authdb rule finalization (`helpers.c:168`, `resolve_path_variants.c`):
  those are admin-configured, non-client, and there is no rootfd at config-parse time.
- **`.`/`..` rejected even within-root.** `xrootd_op_path_forbidden_component` rejects any `.`/`..`
  segment up front (preserving historical behaviour), and a detected traversal is logged to the
  error log with control bytes escaped (`op_path.c:216`). `RESOLVE_BENEATH` would block an
  *escaping* `..` anyway, but a within-root `/a/../b` is still refused.
- **Depth limit before any syscall.** `xrootd_count_path_depth` rejects > 32 components
  (`XROOTD_MAX_WALK_DEPTH`) at string-scan cost to prevent CPU/traversal DoS.
- **Prefix-attack-proof boundary checks.** `xrootd_path_within_root` (`resolve_confined_helpers.c`),
  `xrootd_beneath_strip_root` (`beneath.h`), and every authdb/VO/group/manager-map matcher require
  the byte after the prefix to be `'\0'` or `'/'`, so `/export` never matches `/exportdata`.
- **Fail-closed auth ordering.** The gate denies on the first failing tier (authdb → VO → token
  scope) and returns access only on explicit `NGX_OK`. Empty rule arrays — and, for VO/manager,
  "no matching rule" — mean "unrestricted" by design (`acl.c`, `authdb.c`); be deliberate when
  adding rules. The global `allow_write` check is enforced by callers *before* token scope (project
  invariant), not inside this folder.
- **Auth-cache key folds in every verdict input.** SHA-256 over `auth_level + need_write +
  resolved + reqpath + DN + VO list + raw token scope` (`auth_gate.c:22`), so a cached grant can
  never be replayed for a different token/path/level. Both grants and denies are cached. Short TTL
  (default 30 s) lets reloads and rule changes converge; a config reload zeroes the zone.
- **Embedded-NUL / oversize / CGI payloads rejected at extraction.** `extract.c` refuses a payload
  with an *interior* NUL (a single trailing NUL is trimmed) or longer than `XROOTD_MAX_PATH`, and
  strips `?cgi` so the resolver never stats `file?...` (`strip_cgi.c`, invariant #4).
- **All wire-derived log strings must be sanitized.** Use `xrootd_sanitize_log_string`
  (control/quote/backslash/non-ASCII → `\xNN`) before logging any path/DN/errmsg — every site in
  `access_log.c`, `acl.c`, `authdb.c`, `resolve_confined_helpers.c` does. Prevents log injection.
- **`openat2` argument-order trap.** `xrootd_open_confined_canon(…, flags, mode)` — never pass
  permission bits in the `flags` slot (`0644` collides with `O_EXCL`); `mode` is honoured only with
  `O_CREAT`, and the beneath wrapper masks it to `07777` because `openat2` (unlike `open`) rejects
  `S_IFMT` type bits (`beneath.c:91`).
- **Access log is batched per worker (single-threaded loop, no lock).** A line ≥ buffer size is
  written directly; the log fd is `O_APPEND` so multi-line writes stay atomic. `xrootd_access_log_flush`
  must be wired into connection close, or a session's tail lines can be lost (`access_log.c`). The
  buffer/timer are file-static per worker, not per-connection.
- **Kernel floor is 5.6.** `beneath.c` `#error`s without `RESOLVE_BENEATH`/`SYS_openat2`. The
  legacy `resolve_confined_*` path keeps an O_NOFOLLOW fallback for pre-5.6 kernels; the primary
  beneath API does not — call `xrootd_openat2_runtime_available()` once at init to warn on
  degraded systems.
- **Known minor mismatch.** `resolve_confined_ops.c` declares `extern char *
  xrootd_split_relative_parent(...)` while the definition in `resolve_confined_helpers.c` returns
  `int`. Harmless on LP64 (the return value is only tested for truthiness) but should be corrected
  to `int` when these legacy ops are next touched.

## Entry points / extending

- **New namespace operation (stream):** call `xrootd_resolve_op_path(ctx, c, XROOTD_OP_<X>,
  "<VERB>", conf, <MODE>, reqpath, sizeof, resolved, sizeof)`; on `!= NGX_OK` `return ctx->write_rc`.
  Then `xrootd_auth_gate(ctx, c, XROOTD_OP_<X>, "<VERB>", reqpath, resolved, conf,
  XROOTD_AUTH_<LEVEL>, need_write)`; on `!= NGX_OK` `return ctx->write_rc`. Pick the right
  `xrootd_path_mode_t`. Do the syscall with `xrootd_*_beneath(conf->rootfd, …)`.
- **New confined syscall primitive:** add the wrapper to `beneath.c`/`beneath.h` following the
  `beneath_open_parent` pattern for any *mutating* op (resolve parent under `RESOLVE_BENEATH`,
  act on final component); register the file in the top-level `config` script (the
  module's `ngx_module_srcs` / `NGX_ADDON_SRCS` list) and re-run `./configure`.
- **New ACL/policy rule type:** add the rule struct + a `xrootd_finalize_<type>_rules` wrapper over
  `xrootd_finalize_path_rules` (see `acl.c`/`authdb.c`/`group_policy.c`), a `xrootd_find_<type>_rule`
  in `find_rule.c`, and a `xrootd_check_<type>` returning NGX_OK/deny. Wire it into `auth_gate.c`
  in the correct fail-closed order.
- **New authdb privilege char:** extend `xrootd_parse_privs` (`authdb.c`) and add the
  `XROOTD_AUTH_*` bit; pass it as `needed_privs` at the relevant gate call sites.
- **HTTP/S3 caller:** go through [../compat/](../compat/README.md) (`namespace_ops.c`) rather than
  duplicating extraction/confinement; reuse `xrootd_get_canonical_root` + `xrootd_open_confined_canon`
  / `xrootd_beneath_full_path`.

## See also

- [../README.md](../README.md) — master subsystem index.
- [../read/README.md](../read/README.md), [../write/README.md](../write/README.md),
  [../dirlist/README.md](../dirlist/README.md), [../query/README.md](../query/README.md),
  [../fattr/README.md](../fattr/README.md) — handlers that call `xrootd_resolve_op_path` + `xrootd_auth_gate`.
- [../aio/README.md](../aio/README.md) / [../fs/README.md](../fs/README.md) — where the confined fd is
  read/written off the event loop.
- [../token/README.md](../token/README.md) / [../gsi/README.md](../gsi/README.md) /
  [../voms/README.md](../voms/README.md) — identity sources feeding the auth gate (scope, DN, VO list).
- [../compat/README.md](../compat/README.md) — HTTP/S3 adapter that reuses these primitives.
- [../shm/README.md](../shm/README.md) — `xrootd_kv` zone backing the auth-result cache.
- [../manager/README.md](../manager/README.md) / [../cms/README.md](../cms/README.md) — consumers of
  `xrootd_find_manager_map` for cluster routing.
- [../response/README.md](../response/README.md) — wire framing for stat bodies and errors.
