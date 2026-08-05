# Phase 95 — parity-audit dead-code burndown + CLI hygiene

Source: `docs/refactor/xrootd-feature-parity-audit-2026-08-04.md` §9.2 (verified
dead code) and §9.3 (stale docs). Five scoped workstreams, all owner-selected:

| WS | Item | Verdict |
|----|------|---------|
| W1 | Dormant HTTP redirect path (`xrdhttp_send_redirect`, zero call sites) | **REMOVE** |
| W2 | Unwired throttle engines (max_active_connections, userconfig INI, IO-load) | **WIRE UP** (recommended; per-engine detail below) |
| W3 | xrdfs multi-path commands silently act on last path only | **WIRE UP** multi-path properly; hard-error where single-path |
| W4 | Preload `fill_stat` under-filled duplicate of `posix_map.c` helper | **FIX** (delete duplicate, call shared helper) |
| W5 | `xrootdfs_usage.c:46-47` claims utimens/chown/symlink unsupported — they are implemented | **FIX** usage text |

Every line citation below was re-verified against the working tree on 2026-08-04.

Standing rules that apply to all workstreams: no git write commands without OP
approval in-conversation; 3 tests per change (success + error + security-neg);
no `goto`; helpers over reimplementation; CCN ≤15 and 600-line file cap are live
ratchets (extract helpers rather than grandfather); new `src/` TUs → `./config`
(then `bash -n config`), new `client/` TUs → `client/Makefile`
(`check_config_coverage.py` / `check_client_build_coverage.py` enforce).

---

## W1 — Remove the dormant HTTP redirect path

### Current state
- `xrdhttp_send_redirect()` — `src/protocols/webdav/xrdhttp_response.c:279-317`.
  **Zero call sites** repo-wide (definition + header decl only). HTTP clients
  are never 30x-redirected to peer data servers; the root:// plane does this via
  `brix_send_redirect` (response/control.c), which is live and unrelated.
- Redirect-only static helpers in the same file: `xrdhttp_build_redirect_location`
  (:184), `xrdhttp_set_location_header` (:229), `xrdhttp_set_redir_target_headers`
  (:250-276, emits `X-Xrootd-Redir-Host/Port`).
- Shared helper `xrdhttp_add_response_headers` (:116) is **live** — used by
  `xrdhttp_multipart.c`, `xrdhttp_stats.c`, `get.c`, `xrdhttp_filter.c`. Keep.
- Declaration + contract comment: `src/protocols/webdav/xrdhttp.h:120-133`.
- File-header comments advertising the "Redirect dialect": `xrdhttp_response.c:9`,
  `xrdhttp.c:9`, `xrdhttp.h:8`.

### Why remove rather than wire
Parity audit §6.1 keeps HTTP redirect-to-dataserver as a *future feature*, but a
real implementation needs a mesh-selection call site, `http.secretkey`-style
signed-CGI handoff, and client-capability negotiation — none of which this
scaffolding provides. Keeping never-called code contradicts the repo's dead-code
posture (same class as the §9.2 findings). Removal loses nothing: the function is
in git history if a future phase wants the header-emission shape back.

### Steps
1. Delete `xrdhttp_send_redirect` + the three redirect-only statics from
   `xrdhttp_response.c`. Check `loc_buf` constants (`XRDHTTP_TPC_URL_MAX`,
   `XRDHTTP_OPAQUE_MAX`) — if the last users in this TU go away, drop the
   now-unused includes too.
2. Delete the decl + doc block from `xrdhttp.h` (:120-133) and scrub the three
   file-header "Redirect dialect" mentions.
3. Grep guard: `grep -rn "xrdhttp_send_redirect\|X-Xrootd-Redir" src/` must
   return nothing.
4. TRAP (memory: webdav offset skew): after ANY `xrdhttp.h` edit, delete all
   webdav `.o` before rebuilding (`rm src/protocols/webdav/*.o` equivalent in
   the build tree) — stale objects with skewed offsets have previously produced
   phantom auth failures.
5. Rebuild + `objs/nginx -t`.
6. Update the parity audit: §6.1 note "dormant scaffolding removed in phase-95;
   future implementation starts fresh", strike the §9.2 bullet.

### Tests
- Success: full webdav suite green (incl. `tests/test_xrdhttp_wait_retry_digest_range.py`,
  multipart/stats users of the surviving `xrdhttp_add_response_headers`).
- Error: none needed beyond compile (pure deletion) — but keep one assertion that
  a GET against a mesh-fronted path still returns 200-or-proxied, never a stray
  307 (pins "no accidental redirect emission" behavior).
- Security-neg: N/A (removal); the grep guard in step 3 is the regression pin —
  add it to the doc-drift checker or as a tiny pytest asserting the symbol is
  absent from the tree.

### Acceptance
Symbol gone, webdav suite green, parity audit updated.

---

## W2 — Throttle engines: wire up (recommended) — per-engine plan

### Current state (`src/net/ratelimit/throttle_compat.{c,h}`)
Four engines share the file; only one is alive:

| Engine | Symbols | State |
|--------|---------|-------|
| Per-user open-files cap | `brix_throttle_open_inc/dec` | **LIVE** — inc at `open_resolved_file_finalize.c:139`, dec at close.c / disconnect.c. Keep as-is. |
| Per-user active-connections cap | directive `brix_throttle_max_active_connections` (`directives_auth.inc:284`, default at `server_conf.c:53`, merge at `server_conf_merge_security.c:155`) | **PARSED, NEVER READ** — `conf->throttle.max_active_conn` has zero readers. |
| userconfig INI (per-user maxconn override) | `brix_throttle_userconfig_load/match` (:43/:51) | **ZERO call sites**; no directive even exposes a path. Precedence engine (exact > longest-glob > `*`) fully implemented + commented. |
| IO-load concurrency | `brix_throttle_charge_io` (:97), `brix_throttle_ioload_over` (:120) | **ZERO call sites**; no directives for interval/concurrency. |

Upstream contract being reproduced: XrdThrottle `throttle.max_conn`,
`throttle.userconfig`, and the `-concurrency` IO-service-time load metric.

### Recommendation
Wire all three. They are small, already unit-shaped, and complete the
XrdThrottle contract the file's own header promises; parity audit §8 counts them
as gaps either way, and `source-verified-xrootd-comparison.md:265` currently
claims "Parity" that only becomes true once these run. Fallback (if the IO-load
gate is judged not worth a new admission point): wire max-active-conn +
userconfig, **delete** `charge_io`/`ioload_over` + their header decls — do not
leave them dead a second time. Decision point for OP at implementation start.

### W2a — max_active_connections enforcement
1. Add an `active_conns` counter to the per-user SHM node (`brix_rl_node_t` in
   `ratelimit.h`). TRAPs: struct growth ⇒ clean rebuild of every TU touching the
   type (`struct_field_abi_clean_rebuild`); SHM mutation stays under the
   existing zone mutex, spin+yield only (INVARIANT 10); zones are created via
   `brix_shm_table_*` — no new shm plumbing needed, the throttle zone already
   resolves at postconfig (`server_conf_merge_security.c:168` validates it).
2. Increment after successful authentication in root:// session establishment
   (same identity string the open-files cap uses — one identity derivation,
   don't invent a second); decrement on disconnect (`disconnect.c` /
   `disconnect_report.c` already include `throttle_compat.h` for the open-files
   release — extend that path).
3. Over-cap verdict: refuse the login with `kXR_Overloaded` (binary
   grant/refuse matches the file's documented collapsed semantics; no queue).
   Slab-OOM ⇒ fail-open, matching `open_inc`'s documented behavior.
4. Metric: reuse the existing ratelimit refusal family with a `reason` label
   value (low-cardinality, INVARIANT 8) — no new family.

### W2b — userconfig INI
1. New directive `brix_throttle_userconfig <path>` (add to
   `directives_auth.inc` next to :270-291 block; field in
   `brix_throttle_conf_t`, `conf_structs.h:233-242`).
2. Load at postconfiguration into a per-server `brix_throttle_uc_t`; parse
   failure ⇒ config error (fails `nginx -t`), matching the loader's errbuf
   contract. Reload = config reload (nginx-native; no SIGUSR1 hot path needed).
3. At the W2a enforcement point: `brix_throttle_userconfig_match(uc, user)`
   result, when non-zero, **overrides** `max_active_conn` for that user
   (upstream semantics: userconfig maxconn is the per-user connection cap).
4. `bash -n config` not needed (no new TU) unless a setter lands in a new file.

### W2c — IO-load concurrency gate
1. New directives `brix_throttle_ioload_interval <msec>` (default off=0) and
   `brix_throttle_ioload_concurrency <num>` (float, 0=off). NOTE the msec-slot
   TRAP: `ngx_conf_set_msec_slot` parses bare numbers as SECONDS — document the
   unit in the directive comment and tests.
2. Charge: call `brix_throttle_charge_io` at read/write completion where per-op
   service time is already measured (the unified-metrics latency record path —
   single-owner rule: charge in exactly one place, `unified_record.c`'s
   completion hook, never per-protocol). Stream-plane reads book no latency rows
   (cachemx TRAP) — root:// plane only for this phase; document that.
3. Gate: at read-open admission (`open_resolved_file_dispatch.c`, beside the
   open-files check) — `ioload_over()` ⇒ `kXR_wait` (delay-not-reject, closest
   to upstream shed behavior on the request plane), with a bounded retry hint.
4. Cache-fill I/O remains un-throttled this phase (audit §8 residual); note it.

### Tests (per engine, 3-rule)
- W2a success: cap=2, third concurrent login same DN refused `kXR_Overloaded`;
  disconnect frees a slot. Error: refusal carries correct code; slab-OOM
  fail-open unit. Security-neg: second identity unaffected by first identity's
  saturation (no cross-user bleed); zone unset ⇒ directive rejected at
  `nginx -t` (existing :168 validation covers).
- W2b success: `*`+glob+exact precedence e2e (exact user gets 1, others get
  global); C-unit for `userconfig_match` precedence (engine currently has zero
  tests). Error: malformed INI fails `nginx -t` with errbuf text.
  Security-neg: pattern from INI cannot widen another user's cap (longest-glob
  tie-break pinned).
- W2c success: saturating reader trips `kXR_wait` under tiny interval/
  concurrency; window reset after idle interval verified. Error: interval=0 or
  concurrency=0 ⇒ engine inert. Security-neg: charged identity is the
  authenticated user, not client-supplied (no header/CGI influence).
- SHM cross-worker: engines are zone-backed so multi-worker is fine, but reuse
  the phase-92 reservation TRAP discipline (`xdist_group`) for deterministic
  counts in e2e.

### Doc/cleanup
- Fix `docs/10-reference/comparison/.../source-verified-xrootd-comparison.md:265`
  (throttle row) to describe what is now actually enforced.
- Update parity audit §8 + §9.2 (strike "dead engines" bullets; ioload bullet
  becomes either "wired" or "removed").
- Out of scope (explicitly): upstream `throttle.data`/`throttle.iops` byte/IOPS
  pacing, loadshed, fairness; `brix_resv_status` zero-callers (BWM — separate
  audit item, not in this phase's mandate).

### Acceptance
No function in `throttle_compat.{c,h}` without a live call site; every
`brix_throttle_*` directive observably changes behavior in an e2e test;
comparison doc row truthful.

---

## W3 — xrdfs multi-path commands: real multi-path, no silent last-wins

### Current state
The `arg = argv[i]` overwrite idiom (last positional silently wins) appears at
~18 sites across the verb tables: `xrdfs_meta.c` (:25 stat, :213 mkdir?, :243,
:286 rm, :467), `xrdfs_data.c` (:110 cat, :208, :484), `xrdfs_attr.c` (:48,
:250), `xrdfs_data_content.c` (:183, :314), `xrdfs_data_wc.c` (:74),
`xrdfs_web.c` (:157). Confirmed shapes: `do_stat` (`xrdfs_meta.c:13-37`),
`do_rm` (:273-317), `do_cat` (`xrdfs_data.c:96`). `xrdfs host stat a b c`
silently stats only `c` — worst-case for `rm` (user deletes the wrong file with
no diagnostic).

### Design
1. **Shared collector**: one helper (new small TU `client/apps/fs/xrdfs_args.c`
   + header, added to `client/Makefile` — build-coverage guard) that walks
   argv once, dispatches flags via a per-verb flag table, and appends
   positionals to a bounded list (`XRDFS_MAX_PATHS` 64; overflow = usage error,
   never truncation). This kills the overwrite idiom pattern-wide instead of
   patching 18 sites individually.
2. **Multi-path verbs** (loop over the list, aggregate exit = first non-zero,
   keep going — coreutils semantics): `stat`, `rm`, `cat`, `ls`, `mkdir`,
   `rmdir`, `checksum`/query-cksum, xattr get/list. `rm -r` keeps its
   export-root refusal and per-path `-v` reporting per path.
   - `stat -j` with >1 path emits a JSON **array** (single path keeps the
     current bare-object output for backward compat).
   - Cross-check against stock `XrdClFS.cc` first and extend the machine parity
     gate (`tests/test_clientconf_surface.py`) to assert arity per verb: mirror
     stock where stock is multi-path; superset (multi-path) where coreutils
     makes it natural; never less than stock.
3. **Single-path verbs** (`mv`, `truncate`, `locate`, `statvfs`, `cmp`
   fixed-arity, etc.): a second positional beyond the declared arity is now a
   **usage error (exit 50)** — the silent-drop class is eliminated everywhere,
   not just where multi-path was added.
4. Complexity budget: `xrdfs_meta.c` and `xrdfs_data.c` are near the ratchet
   caps — the per-verb loops should call tiny `do_<verb>_one(c, path, opts)`
   helpers (most verb bodies already factor this way) so no function crosses
   CCN 15 and no file crosses 600 lines.

### Tests
- Success: e2e vs fleet — `stat a b` prints two records; `rm a b` removes both;
  `cat a b` concatenates in argument order; `mkdir`/`rmdir` multi; `stat -j`
  array shape parsed with a real JSON parser (substring-assert TRAP).
- Error: nonexistent middle path ⇒ processing continues, exit is non-zero,
  both surviving paths acted on; single-path verb given two paths ⇒ usage
  error and **no server call issued** (assert via fleet logs or a count metric).
- Security-neg: each path independently goes through `build_path` canon
  (no `..` escape via the second positional; mirrors existing canon tests).
- Parity gate: `test_clientconf_surface.py` extended per step 2.

### Acceptance
`grep -n "arg = argv\[i\]" client/apps/fs/xrdfs*.c` returns zero overwrite
sites; every verb either loops all paths or hard-errors on extras; parity gate
green.

---

## W4 — Preload: delete under-filled duplicate `fill_stat`

### Current state
`client/preload/brixposix_preload.c:189-202` — local static `fill_stat` builds
`struct stat` with hardcoded modes (0755/0644), and **omits** `st_ino`,
`st_blksize`, `st_blocks`. The canonical helper
`brix_statinfo_to_stat(si, allow_symlink, stbuf)` at
`client/lib/posix/posix_map.c:16-42` (header `posix_map.h:22`) fills real mode
bits from shared stat-flags semantics, stable `st_ino` from the server file id
(inode-tracking tools: `find -samefile`, rsync, tar), 1 MiB `st_blksize` hint,
and 512-byte `st_blocks`. The file-header of posix_map.c even says it was
lifted "so both (FUSE drivers) and the preload shim share one implementation" —
the preload never adopted it. This is a HELPERS-invariant violation, not just
polish.

### Steps
1. Delete the static `fill_stat`; replace its call sites (`:416` + any others in
   the TU) with `brix_statinfo_to_stat(si, 0, stbuf)` — `allow_symlink=0`
   because the shim interposes `stat`/`fstat` only (no `lstat` interpose), so
   kXR_other must not surface as `S_IFLNK`.
2. Include `posix_map.h`; link check: the preload `.so` link line in
   `client/Makefile` must carry `posix_map.pic.o` (PIC object already exists in
   the tree — verify it's on the preload link list, add if not;
   `check_client_build_coverage.py` will police the TU listing).
3. Three-build-system TRAP (memory `split_files_three_build_systems` /
   phase-86): stale preload `.so` in the other build trees — rebuild all three,
   and beware `LD_PRELOAD` picking up an old copy in e2e.

### Tests
- Success: e2e through the shim — `stat(2)` on a remote file yields non-zero
  `st_ino` stable across two calls, `st_blksize == 1 MiB`, plausible
  `st_blocks`, and mode bits derived from wire flags (not hardcoded 0644).
- Error: directory stat via shim keeps `S_IFDIR`+nlink 2 (regression pin on the
  helper's dir branch).
- Security-neg: a server reporting the symlink/`kXR_other` flag combination
  must still present `S_IFREG`/dir through the shim (allow_symlink=0 pinned) —
  no fake symlink surfacing to code that would then `readlink` a non-interposed
  path.

### Acceptance
No `fill_stat` symbol in the preload TU; shared helper is the single stat
translator across both FUSE drivers and the shim (grep-provable); tests green.

---

## W5 — xrootdfs usage text: stale unsupported-claims

### Current state
`client/apps/fs/xrootdfs_usage.c:46-47` claims: "utimens/chown are no-ops (no
XRootD wire op); symlinks are unsupported." The **modern** driver contradicts
this: `.chown = xfs_chown`, `.utimens = xfs_utimens`, `.symlink = xfs_symlink`
are wired (`xrootdfs.c:96-98`), backed by the vendor-extension probe
(`brix_ext_probe` → `g_ext_setattr`/`g_ext_symlink`/`g_ext_readlink`/
`g_ext_link`, `xrootdfs.c:448`): real operations against a BriX server that
advertises the extensions, graceful no-op/ENOTSUP fallback against stock. The
**legacy** driver's identical claim (`xrootdfs_legacy_ext.c:213-214`,
`xrootdfs_legacy.c:28-29`) is genuinely TRUE for that driver and stays.

### Steps
1. Rewrite `xrootdfs_usage.c:44-48` to state the extension-gated truth, e.g.:
   utimens/chown/symlink/readlink/hardlink are live when the server advertises
   the BriX setattr/symlink extensions (probed at mount, see startup log line at
   `xrootdfs.c:503`), and degrade to cp-p-friendly no-ops / ENOTSUP against
   stock servers.
2. Make the legacy text self-identify ("legacy driver: …") so the two usage
   blocks can't be confused again.
3. Sweep `client/man/*.1` (xrootdfs man page) for the same stale sentence.
4. Update parity audit §9.2 (strike the bullet).

### Tests
Doc-only change; pin it with one trivial assertion in an existing xrootdfs test:
usage output (`--help`) must mention the extension-gated behavior and must NOT
contain the string "symlinks are unsupported" outside the legacy block. (Guards
against the text regressing when usage is next edited.)

### Acceptance
Usage/man text matches the ops tables; audit updated.

---

## Ordering & risk

Recommended order: **W5 → W4 → W1 → W3 → W2** (doc fix and helper dedup are
zero-risk warmups; W1 is pure deletion; W3 is client-only; W2 touches SHM ABI +
login admission and lands last with the most test surface). W1/W4/W5 are
independent and can run in one slice; W3 and W2 are independent of each other.

Global risks:
- SHM node struct growth (W2a) forces clean rebuilds — do it in one commit slice
  with the rebuild, never split across sessions
  (`concurrent_session_build_contention`).
- `xrdhttp.h` edits (W1) ⇒ delete all webdav objects first (offset-skew TRAP).
- Fleet e2e: kill stale prior-day nginx/xrootd before restart; lane flakes
  listed in memory pass serially.
- CHANGELOG: one entry per workstream under the pending version, per
  release-process.md.

## Exit criteria (phase gate)
1. Zero dead symbols: every function in `throttle_compat.{c,h}` and
   `xrdhttp_response.c` has a live caller (or is deleted).
2. Zero silent last-path-wins sites in `client/apps/fs/xrdfs*.c`.
3. One `statinfo→stat` translator repo-wide.
4. Parity audit §9.2 items for these five bullets struck with phase-95 refs;
   §9.3 comparison-doc row corrected.
5. Full guard fleet + affected suites green; `objs/nginx -t` clean.
