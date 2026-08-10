# Phase 101 — config-surface unification: one grammar, two owners, zero drift

Source: full directive-surface audit of 2026-08-09 (artifact:
<https://claude.ai/code/artifact/1e1dd7de-949a-48fc-b012-e6f3ac7c2c41>), building
on `docs/superpowers/plans/2026-07-05-unified-brix-config-grammar.md` (Tasks 1–5
landed 2026-07; Tasks 6–7 still open — absorbed here as W9.3). Every line
citation below was verified against the working tree on 2026-08-09 (`main`
@ d2ddfcd + local edits; none of the cited files are among the locally modified
set in `git status`). Reader inventories in W2/W4/W6/W8 were produced by
tracing each conf field to its request-path consumers, not just its
registration — see the grep protocol in Appendix C (and its warning about
`_canon`-style derived fields).

**Goal.** Finish the unification the 2026-07 phase started: every shared concept
has exactly ONE directive name, registered by exactly ONE owner per plane,
flowing through the shared preamble — and a CI guard that makes regression
structurally impossible. Net effect: ~533 unique names → ~490, four sharing
mechanisms → two, one silent-no-op bug fixed (S3 SciTags), and "learn once,
works on every protocol" for operators.

| WS | Item | Verdict | Size |
|----|------|---------|------|
| W1 | S3 `brix_pmark*` registrations are dead (first-module-wins); SciTags on S3 is a silent no-op | ✅ **DONE 2026-08-09** — 13-entry family moved to `http_common` at `BRIX_HTTP_ALL_CONF` scope; webdav + s3 tables deleted; `brix_shared_adopt_unified()` extended with the 13 config-time pmark fields; `tests/test_pmark_s3.py` (4 cases) green | S |
| W2 | Dual-conf-poking setters (`brix_ktls`, `brix_cache_store_endpoint`, XrdAcc family) hardwire webdav+s3, exclude cvmfs | ✅ **DONE 2026-08-09** — all 13 → `http_common` generic slots; `brix_acc_http_t acc` promoted into the shared preamble (ABI-dirty rebuild), adopted into every HTTP protocol incl. cvmfs; `module_acc_directives.{c,h}` deleted; `test_acc_unification.py` (4) green + acc/authdb suites green; checker R4 26→14, R1=0 | M |
| W3 | No common owner on the stream plane → gridftp grew 11 prefixed copies | ✅ **DONE (variant A) 2026-08-10** — new `ngx_stream_brix_common_module` (`stream_common.{c,h}`) owns all 11 shared bare names (storage + x509-trust + require_vo); root and gridftp ADOPT at merge (GSI-trust strings via `brix_stream_common_adopt_gsi`, VO-ACL rules deep-copied via `brix_stream_common_adopt_vo_rules` and finalized per-plane; readers/postconfig unchanged). **R2 11→0 — the phase's headline goal reached (R1=0, R2=0 across the whole codebase).** Verified: full gridftp suite (173 incl. GSI handshake/security-neg/VO-ACL-over-GSI/pblock/s3/mode-E/PASV/delegation) + root:// GSI green. | M–L |
| W4 | HTTP twins de-prefixed onto the preamble+common module | **DONE 2026-08-10** — **14 families**: zip, pwd_file, upload_resume, macaroon, stage_dir, pblock, x509-crl, voms, token-trust-quartet, require_vo, protbind, HTTP-TPC SSRF policy (all 6 TPC twins), token_config; **tpc_verify_checksum unified** (stream flag + webdav `<alg>` → one `on\|off\|<alg>` grammar, `on`→adler32). With W5's `brix_webdav_authdb` de-prefix landed, the last HTTP twin is gone (R2 44→11; the 11 remaining are all W3 gridftp; R1=0). | L |
| W5 | `brix_authdb` (XrdAcc) vs `brix_webdav_authdb` (u/g/p rules) — different engines, near-identical names | ✅ **DONE 2026-08-10 (variant A)** — HTTP XrdAcc entry+tuners → `brix_acc_authdb`/`brix_acc_format`/`_audit`/`_refresh`; `brix_webdav_authdb` → bare `brix_authdb` (native, webdav-scoped). Prefix == engine on HTTP, matching stream. Security-neg pin: pre-W5 XrdAcc HTTP config fails `nginx -t` loudly (dead selection spelling). Harness unblocked (static/dynamic build separation fixed); `test_authdb.py` 9/9 (stream native baseline) + new `test_authdb_engine_split.py` (12) + acc/authdb suites green (46 total). **W5.2 DONE 2026-08-10**: `authdb_rules` moved to the shared preamble (`common.authdb_rules`, mirroring `common.vo_rules`) + `brix_authdb` registered once on `http_common` at `BRIX_HTTP_ALL_CONF` (was webdav-scoped); webdav rebased. **s3 access phase now ENFORCES the native READ ACL** (`handler_dispatch.c` after key resolution, GET/HEAD, on the confined fs_path) — closing the W5 accepted-but-inert gap. Each enforcing plane **deep-copies** `common.authdb_rules` + finalizes the copy against its OWN root (`brix_authdb_rules_finalize_copy`), because the shared array is pointer-inherited across sibling protocol locations and two in-place finalizes against different roots would silently mis-resolve rule paths. Verified: new `test_s3_native_authz.py` (3: grant rule-covered, grant host-rule, deny-uncovered→403) + regression-free (`test_mu_webdav_authz` 6, s3 24, root 9). **cvmfs deliberately NOT gated**: its read-through/proxy `root` is the upstream URL and objects are content-addressed, so a path-prefix ACL against a local realpath is the wrong model (peer/URI-based cvmfs authz is a separate design). Does not affect R2 (0). Also fixed pre-existing stale-W4-name configs (`nginx_mu_webdav_authz.conf` et al.). | S |
| W6 | Naming-grammar outliers | **DONE 2026-08-10** — `brix_ocsp_enable`→`brix_ocsp` (Rule 1); `brix_scan_root`/`brix_scan_max_files`→`brix_dashboard_scan_*` (Rule 2); impersonation 4-prefix→one `brix_idmap` (11 directives, name-only); CA/trust quartet→role names (`brix_trusted_ca`/`_dir`, `brix_client_ca_store`, `brix_backend_ca_dir`; `brix_client_certificate_folder` kept). Grammar codified in coding-standards.md §2. Tests: `test_w6_renames`, `test_idmap_rename`, `test_ca_rename_unification`. | M |
| W7 | Value-syntax drift | WIP 2026-08-10 — DONE: `brix_s3_mpu_max_age` + `brix_backend_s3_sts_ttl` num→sec (`test_w7_sec_slots.py`); ratelimit size-parser dedup (`test_w7_ratelimit_size.py`; corrected the plan — `ngx_parse_size` lacks `g`, did the additive direction); **`brix_kv_zone` → `zone=name:size` grammar (Commit B, breaking; `test_w7_kv_zone_grammar.py`, 7 configs swept)**. also DONE: `brix_webdav_cors_max_age` + `brix_webdav_lock_timeout` + `brix_storage_credential_mint_ttl` `ngx_uint_t`→`time_t`/`sec_slot` (mint_ttl's ~9 readers all feed brix_vfs_ctx_bind_backend_mint(); its param + the vfs field storage_cred_mint_ttl moved to time_t in the same pass). **W7 fully done** except `brix_token_clock_skew` — deliberately NOT converted: its `[0,300]` security clamp means `10m`=600 would be rejected (a unit-confusion footgun; keep as num_slot until an OP decides the clamp/units interaction). | S |
| W8 | Legacy HTTP cache grammar | **DONE 2026-08-10** — behavior diff (see analysis note) showed the legacy `cache_root` (`cache_storage_inst`) is a DISTINCT live mechanism the tier `cache_store` (sd_cache decorator) does not subsume → **option B**: unified `brix_{webdav,s3}_cache_root` → bare `brix_cache_root` (field → shared preamble; pure relocation, ~36 readers rebased; `test_cache_root_unification.py`). Stream `brix_cache_export` (fd-based) left as-is. | M |
| W9 | Guardrails: `check_directive_registry.py`, doc-drift closure, stale X-macro header comment, 2026-07 plan Tasks 6–7 | **W9.1 DONE** (checker + allowlist + 6 tests; R1=0 confirms no same-plane dups) · **W9.2 DONE** (tier_directives.h comment) · **W9.3 DONE 2026-08-10** — Task 6 docs (directives.md: all 40 cvmfs directives documented + unified-grammar intro extended with cache_root/W4-bare-families/W6-renames + migration pointer; examples.md 3-line config; quick-reference cvmfs rows) + Task 7 scripts (`run_cvmfs_minimal.sh` green, `run_cvmfs_evict.sh` fill-proven/band-gated) | M |

Standing rules for all workstreams: no git write commands without explicit OP
approval in-conversation; 3 tests per change-class (success + error +
security-neg); no `goto`; HELPERS over reimplementation; CCN ≤15 / 600-line
file cap are live ratchets (extract helpers rather than grandfather); new
`src/` TUs → repo-root `./config` then `bash -n config`
(`check_config_coverage.py` enforces); **hard rename means NO alias code and NO
"renamed to X" hint strings anywhere** — stock `unknown directive` is the
correct failure mode (convention established by the 2026-07 plan and re-argued
in phase-95 W2: for a security-relevant knob, failing loudly beats silently
ignoring what the admin believes is enforced). Every rename lands its row in
`docs/03-configuration/migration-unified-grammar.md` in the SAME commit.

**ABI trap** (memory: `struct_field_abi_clean_rebuild`, bitten before): any
edit to `ngx_http_brix_shared_conf_t` or a protocol conf struct requires
deleting the affected module `.o` files before rebuild — stale objects with
skewed offsets have previously produced phantom auth failures. W1, W2, W4 and
W8 all grow/shrink the preamble or a protocol conf; treat EVERY commit in
those workstreams as an ABI-dirty rebuild.

---

## Census (2026-08-09) — the measured baseline

Method: extract every `ngx_command_t` entry across `src/`, **including** the
`#include`d fragment headers (`directives_*.h`) and the X-macro expansions of
`BRIX_TIER_DIRECTIVES` / `BRIX_BACKEND_ASYNC_DIRECTIVES`. A naive scan over
`ngx_command_t foo[] = { … };` arrays finds only 226 of the 592 entries — the
stream module alone pulls ~260 entries in via eight `#include`d fragments
(`stream/module.c:411` includes `directives_tier.h`, which chains the rest),
and cvmfs declares everything in `directives_core.h` /
`directives_resilience.h`. Any tooling built on this census (W9) MUST scan
`.h` files and expand the macros or it undercounts by 62%. Reproduction
script: Appendix C.

| Metric | Value |
|--------|------:|
| Unique directive names | **533** (515 literal + 18 macro-generated bare names) |
| Command-table registrations | **592** |
| Files declaring entries | **27** (10 `.c` command tables + 17 fragment headers) |
| Entries on generic `ngx_conf_set_*` slots | 444 |
| Entries on custom setters | 149 (via **114** distinct functions) |
| Same-concept two-name pairs | **44** (27 webdav↔bare, 6 s3↔bare, 11 gridftp↔bare) |
| Names appearing nowhere under `docs/` | 17 (list in W9.1-R3) |

Registration count by declaring file (top of the distribution; full table in
the audit artifact):

| File | Entries |
|---|---:|
| `protocols/webdav/module_commands.c` | 65 |
| `protocols/root/stream/directives_auth.h` | 53 |
| `protocols/root/stream/directives_net.h` | 47 |
| `protocols/root/stream/directives_cms.h` | 43 |
| `core/config/http_common.c` (+ tier/async macros) | 36 + 20 |
| `protocols/s3/module.c` | 32 |
| `protocols/root/stream/module.c` | 32 |
| `protocols/root/stream/directives_cache.h` / `directives_tpc.h` | 28 + 28 |
| `protocols/cvmfs/directives_resilience.h` / `directives_core.h` | 27 + 19 |
| …16 more files… | ≤21 each |

Cross-plane duplicate *registrations* of the SAME name (http + stream) are
intentional and good — one spelling, both planes (e.g. `brix_storage_backend`
at `http_common.c:73` and `stream/module.c:248`). The problem classes are
(a) same-plane duplicates — W1 — and (b) prefixed twins of an existing bare
name — W3/W4.

### The four sharing mechanisms found (target end-state: only the first two)

1. **Common module + adopt-at-merge.** `ngx_http_brix_common_module`
   (`src/core/config/http_common.c`; command table :64, context macro
   `BRIX_HTTP_ALL_CONF` :61 = main|srv|loc) registers a bare name once for
   the whole HTTP plane into its own loc-conf — a bare
   `ngx_http_brix_shared_conf_t` preamble (`http_common.h:24-26`, sole
   member). Its own merge is inheritance-only:
   `brix_http_common_merge_loc_conf` (:399) calls
   `brix_shared_adopt_unified(&conf->common, &prev->common)` (:405), whose
   implementation lives at :417 — UNSET-respecting field-by-field copy.
   Protocol modules then copy the merged values via `brix_http_common_adopt()`
   at their merge_loc_conf: webdav `config_merge.c:54`, s3
   `module_merge.c:58`, cvmfs `cvmfs_module_merge.c:73`. Module emission
   order in `./config` guarantees the common module merges first
   (`http_common.h:12-14`). **Keep; extend.** Note the leverage: because
   BOTH inheritance and protocol adoption flow through
   `brix_shared_adopt_unified`, adding a field to that ONE function wires it
   end-to-end.
2. **X-macro grammar headers.** `src/core/config/tier_directives.h` defines
   `BRIX_TIER_DIRECTIVES(pfx, conf_t, ctx, conf_off)` (17 entries) and
   `BRIX_BACKEND_ASYNC_DIRECTIVES` (3 entries); instantiated with the bare
   `"brix_"` prefix at `http_common.c:345`/`:350` (HTTP) and
   `stream/directives_tier.h:11` (stream). Grammar parity across planes is
   guaranteed by construction. **Keep; extend to more families (W4).**
3. **Dual-conf-poking setters.** `src/protocols/webdav/module_acc_directives.c`
   — registered once on webdav, each setter hand-fetches BOTH the webdav and
   s3 loc-confs via `ngx_http_conf_get_module_loc_conf()` and writes both.
   The file's own header comment (:14-19) documents this as a deliberate
   workaround for first-module-wins. **Retire (W2)** — it hardwires the
   protocol list (cvmfs silently excluded), is invisible from the command
   table, and the same hazard it works around produced the W1 bug where the
   workaround was NOT applied.
4. **Hand-copied parallel tables.** The token/zip families in webdav + s3;
   gridftp's whole storage/x509 family. This is the exact "cross-protocol
   parity bug magnet and triple audit surface" that `tier_directives.h:13-16`
   names as the reason the tier macro exists. **Retire (W3/W4).**

### nginx first-module-wins, precisely

`ngx_conf_handler` walks `cycle->modules` in emission order; the FIRST module
whose command entry matches the directive name and context type has its
setter invoked, and the walk stops on success. HTTP emission order (repo-root
`./config`, both static and dynamic branches): `metrics → srr → guard →
common → webdav → header_filter → xrdhttp_filter → s3 → cvmfs → dashboard`.
Stream order: `brix (root) → cms_srv → ftp`. Consequences exploited/violated:

- `common` precedes every protocol → its registrations win everywhere: the
  intended design (mechanism 1).
- `webdav` precedes `s3` → any name BOTH register is silently webdav-only:
  the W1 bug.
- root precedes `ftp` → gridftp could never register the bare storage names:
  the W3 gap.

---

## W1 — Fix the dead S3 pmark table (user-visible bug); establish the pattern

### Current state — the full evidence chain

1. **webdav registers the family**: `src/protocols/webdav/directives_zones.h:72-121`
   — 13 entries at `NGX_HTTP_LOC_CONF`, all writing
   `ngx_http_brix_webdav_loc_conf_t.common.pmark.*`:

   | Directive | Args/slot | Target field (`brix_pmark_conf_t`, `pmark.h`) |
   |---|---|---|
   | `brix_pmark` | FLAG / flag_slot | `.enable` |
   | `brix_pmark_firefly` | FLAG / flag_slot | `.firefly` |
   | `brix_pmark_flowlabel` | FLAG / flag_slot | `.flowlabel` (default on) |
   | `brix_pmark_scitag_cgi` | FLAG / flag_slot | `.scitag_cgi` |
   | `brix_pmark_firefly_origin` | FLAG / flag_slot | `.firefly_origin` |
   | `brix_pmark_http_plain` | FLAG / flag_slot | `.http_plain` (default off) |
   | `brix_pmark_echo` | TAKE1 / msec_slot | `.echo` |
   | `brix_pmark_appname` | TAKE1 / str_slot | `.appname` |
   | `brix_pmark_defsfile` | TAKE1 / str_slot | `.defsfile` |
   | `brix_pmark_domain` | TAKE1 / custom `brix_pmark_set_domain` | `.domain` (any\|local\|remote) |
   | `brix_pmark_firefly_dest` | TAKE1 / custom, repeatable | `.firefly_dest` (array of "host[:port]") |
   | `brix_pmark_map_experiment` | TAKE23 / custom | `.exp_rules` |
   | `brix_pmark_map_activity` | TAKE3\|TAKE4 / custom | `.act_rules` |

2. **s3 registers the SAME 13 names**: `src/protocols/s3/module.c:326-371`,
   byte-parallel entries writing `ngx_http_s3_loc_conf_t.common.pmark.*`.
3. **webdav precedes s3** in module order → every `brix_pmark*` occurrence in
   any http context is handled by webdav's entry. **S3's 13 entries are dead
   code — they can never fire.**
4. **Nothing bridges the confs.** `brix_shared_adopt_unified()` copies "only
   the fields the common module owns a directive for" (`http_common.h:33-36`)
   — pmark is not among them (http_common registers no pmark directive).
   `s3/module_merge.c` contains no pmark reference (verified by grep).
5. **The S3 request path reads its own conf**: `s3_pmark_begin_if_enabled()`
   at `src/protocols/s3/handler.c:304-321` tests
   `cf->common.pmark.enable && cf->common.pmark.http_plain` on the
   `ngx_http_s3_loc_conf_t` (called from the GET/PUT path at :494).
6. **Net effect**: `brix_pmark on; brix_pmark_http_plain on;` in an S3-only
   location writes the *webdav* module's conf for that location; S3 reads its
   own untouched conf; SciTags marking on S3 traffic silently does nothing.
   No config-time diagnostic exists or is possible under this arrangement.
7. The stream registration (`stream/directives_pmark.h:7`, 13 parallel
   entries at `Sm|Ss` into the stream srv-conf preamble) is a separate plane
   and is unaffected — it stays.

### Why this fix shape (and why it costs almost nothing)

- The config lives in the shared preamble already:
  `brix_pmark_conf_t pmark` at `shared_conf_types.h:357`.
- The four custom setters are ALREADY conf-struct-agnostic: `pmark_conf()`
  (`src/observability/pmark/config.c:74-78`) is literally
  `return &((ngx_http_brix_shared_conf_t *) conf)->pmark;` — valid for ANY
  struct that embeds the preamble as its first member, which
  `ngx_http_brix_common_conf_t` does. The setters move with ZERO changes.
- Init/merge helpers exist: `brix_pmark_conf_init` (`pmark/config.c:26`) and
  `brix_pmark_conf_merge` (:40) define the per-field UNSET sentinels.
- `brix_pmark_conf_t` splits cleanly (`pmark.h`): 13 config-time fields
  (`enable … act_rules`) vs a runtime tail behind the "Resolved at first use
  … never merged" comment (`rt_ready`, `rt_ok`, `dest_sa`, `exp_rules_r`,
  `act_rules_r`) — per-worker lazily-built state that MUST NOT be adopted.

### Steps

- [ ] 1. Move the 13-entry block into `brix_http_common_commands[]`
  (`http_common.c:64`, before the tier-macro instantiation at :345).
  Contexts: `BRIX_HTTP_ALL_CONF` (deliberate upgrade from webdav's loc-only —
  pmark at `server{}`/`http{}` scope is meaningful, matches the stream
  plane's `Sm|Ss`, and one site-wide `brix_pmark on` is the "simple first"
  spelling). Generic-slot offsets rebase to
  `offsetof(ngx_http_brix_common_conf_t, common.pmark.<field>)`; the four
  custom-setter entries keep offset 0 (they resolve via `pmark_conf()`).
- [ ] 2. Delete `webdav/directives_zones.h:72-121` and `s3/module.c:326-371`.
- [ ] 3. `brix_http_common_create_loc_conf` (:379): add
  `brix_pmark_conf_init(&conf->common.pmark)` beside the existing preamble
  init.
- [ ] 4. Extend `brix_shared_adopt_unified()` (:417) with the 13 config-time
  pmark fields: scalars UNSET-respecting
  (`enable, firefly, flowlabel, scitag_cgi, firefly_origin, http_plain,
  echo, domain`), strings when dst empty (`appname, defsfile`), pointers
  when dst NULL/UNSET_PTR (`firefly_dest, exp_rules, act_rules`). Because
  http_common's own merge (:399→:405) routes through this same function, one
  edit covers BOTH location inheritance and protocol adoption. Do NOT touch
  the `rt_*` runtime tail.
- [ ] 5. webdav/s3 keep their existing `brix_pmark_conf_merge` calls (they
  now merge adopted values — verify each still runs after
  `brix_http_common_adopt` in their merge order).
- [ ] 6. ABI-dirty clean rebuild (common + webdav + s3 objects),
  `objs/nginx -t` on a config exercising pmark at webdav-loc, s3-loc, and
  server scope; full build.

### Tests

- Success — `tests/test_pmark_s3.py` (new): S3-only location with
  `brix_pmark on; brix_pmark_http_plain on; brix_pmark_firefly on;
  brix_pmark_firefly_dest 127.0.0.1:<udp-sink>;` — a plain GET emits a
  firefly datagram (reuse the UDP-collector fixture from the stream pmark
  tests). Same assertions for a webdav location (regression) and for the
  directives at `server{}` scope (new capability, previously impossible on
  HTTP).
- Error: `brix_pmark_domain bogus;` fails `nginx -t` with the existing
  message (`pmark/config.c:124-127`, "use any|local|remote") — pins that the
  custom setters survived the move verbatim.
- Security-neg: pmark OFF (default) in an S3 location adjacent to an enabled
  webdav location emits nothing for S3 traffic — pins the default AND that
  adopt-at-merge doesn't leak an enable across sibling locations.

### Acceptance

`grep -rn 'ngx_string("brix_pmark' src/protocols/webdav src/protocols/s3`
returns nothing; the three tests green; stream pmark suite untouched and
green; census re-run shows the pmark family single-registered per plane.

---

## W2 — Retire the dual-conf-poking setters

### Current state — complete inventory

Command entries (all in `webdav/module_commands.c`):

| Line | Directive | Setter (`module_acc_directives.c`) | Writes |
|---:|---|---|---|
| :54 | `brix_ktls` | `brix_http_set_ktls` :26 | `wc->common.ktls` + `sc->common.ktls`; hand-parses on/off |
| :66 | `brix_cache_store_endpoint` | `brix_http_set_cache_store_endpoint` :59 | dual-poke, hand-parsed flag |
| :75 | `brix_authdb` | `brix_acc_http_set_authdb` :85 | `wc->acc.authdb` + `sc->acc.authdb` (bare string store — no extra parsing; verified :85-96) |
| :79–:117 | `brix_authdb_format`, `_audit`, `_refresh`, `brix_acc_gidlifetime`, `_pgo`, `_nisdomain`, `_resolve_hosts`, `_spacechar`, `_encoding`, `_gidretran` | `brix_acc_http_set_*` (enum multiplexer :98) | dual-poke into `wc->acc.*` + `sc->acc.*` |

Target struct `brix_acc_http_t` (`src/auth/authz/acc/acc.h:198-213`) —
complete field split:

| Kind | Fields |
|---|---|
| Settings (move + adopt) | `format` (uint enum), `audit` (uint enum), `authdb` (str path), `refresh` (int secs), `gidlifetime` (int), `pgo` (flag), `nisdomain` (str), `resolve_hosts` (flag), `spacechar` (str), `encoding` (flag), `gidretran` (str) |
| Per-worker runtime (NEVER adopt) | `tables` (lazy-built generation ptr), `timer` (embedded ngx_event_t), `timer_armed:1` — per acc.h:193-196 these COW-privatise after fork; copying an embedded `ngx_event_t` between confs would be actively wrong |

Readers of `->acc.` outside the engine (complete list, 4 lines):
`s3/handler.c:83` (format gate), `:97` (resolve_hosts),
`webdav/access.c:75` (format gate), `:93` (resolve_hosts). The engine
helpers (`auth/authz/acc/config.c`, `auth_gate.c`) take
`brix_acc_http_t *` — signature-stable under the move.

Defects: (a) cvmfs embeds the same preamble but is not in the poke list — a
cvmfs location cannot enable kTLS and cannot receive XrdAcc settings, with no
diagnostic; (b) every future HTTP protocol must be hand-added to every
setter; (c) the mechanism is invisible — the command table says these belong
to webdav; (d) the flag setters reimplement `ngx_conf_set_flag_slot`
(HELPERS-rule violation). The stream plane's own `brix_ktls`
(`stream/directives_security.h`) and `brix_cache_store_endpoint`
(`stream/module.c`) registrations are plane-local and correct — untouched.

### Steps

- [ ] 1. **Flags commit.** Move `brix_ktls` + `brix_cache_store_endpoint` to
  `http_common.c` as `BRIX_HTTP_ALL_CONF|NGX_CONF_FLAG` +
  `ngx_conf_set_flag_slot` + offsets into `common.ktls` /
  `common.cache_store_endpoint` (`shared_conf_types.h:330` / `:338` — fields
  already in the preamble). Add both to `brix_shared_adopt_unified()`.
  Delete the two setters + the two `module_commands.c` entries. No scope
  change (webdav already registered both `Hm|Hs|Hl`).
- [ ] 2. **Acc-family commit.** Add `brix_acc_http_t acc;` to
  `ngx_http_brix_shared_conf_t` (after `pmark`; ABI-dirty). Delete the
  member from the webdav and s3 loc-confs. Rebase the 4 reader lines to
  `->common.acc.*`. Registration → `http_common.c`: `brix_authdb` becomes
  `ngx_conf_set_str_slot` (the setter was a bare store); `format`/`audit`
  become `ngx_conf_set_enum_slot` with enum tables exported from
  `acc/acc.h`; `refresh`/`gidlifetime` num slots; `pgo`/`resolve_hosts`/
  `encoding` flag slots; `nisdomain`/`spacechar`/`gidretran` str slots.
  Adopt copies the 11 settings fields ONLY (table above) — the lazy build
  keyed off `common.acc.authdb` runs per consuming protocol conf exactly as
  it ran per webdav/s3 conf before; behavior pinned by the acc suites.
- [ ] 3. Delete `module_acc_directives.{c,h}`; remove the TU from `./config`
  (`bash -n config`); remove the 13 entries from `module_commands.c`; run
  `check_config_coverage.py`.
- [ ] 4. ABI-dirty clean rebuild; `objs/nginx -t`.
- [ ] 5. Sweep tests for pins on the hand-rolled error text
  ("must be \"on\" or \"off\"") — stock flag-slot wording replaces it.

### Tests

- Success: existing `tests/test_acc.py`, `test_acc_residual.py`,
  `test_authdb.py`, `test_authdb_auth_scheme_gate.py`,
  `test_authdb_mechanism_scope.py` green unmodified (they exercise webdav+s3
  XrdAcc through the directives — the strongest behavior pin for the
  mechanism swap). New: `brix_ktls on;` at `http{}` scope observed in a
  cvmfs location's merged conf (new capability — assert via the conf-dump
  test helper or a debug header).
- Error: `brix_ktls maybe;` → stock flag-slot error (see step 5).
- Security-neg: an XrdAcc deny rule denies the same DN identically on webdav
  AND s3 (the parity the dual-poke existed to provide must survive its
  removal), and — new — on cvmfs where the acc gate applies.

### Acceptance

`module_acc_directives.c` gone; no cross-module conf writes from directive
setters in `src/protocols/` (becomes W9.1-R4); acc/authdb suites green;
census: `brix_ktls`, `brix_cache_store_endpoint`, `brix_authdb*`,
`brix_acc_*` each registered exactly once on the HTTP plane, owner
`http_common.c`.

---

## W3 — Stream-plane common owner + gridftp de-prefixing

### Current state

gridftp (`src/protocols/gridftp/ftp_module.c`, commands :206) is a separate
stream module; first-module-wins routes bare names to the root module, so it
registered 11 prefixed copies (:208-246) backed by flat fields in
`ftp_gateway.h:29-40` (`export` :31, `allow_write` :32, `storage_backend`
:33, `storage_credential` :35, + verify_write and the x509 set), merged in
`ftp_module_merge.c`. cms-server (`net/cms/server_module.c:217`) has one
shared-concept spelling, `brix_cms_server_sss_keytab` — deliberately NOT
renamed (Appendix B).

Disposition of the root stream module's current registrations (what moves to
the common owner vs what stays protocol-specific). MOVE = shared-concept
family a second stream protocol legitimately needs; KEEP = root://-wire
semantics:

| Entry block (cite) | Names | Disposition |
|---|---|---|
| `stream/module.c:248-…` | `brix_storage_backend`, `brix_storage_credential` (+`_dir`, `_fallback`, `_mint_ca` :`brix_conf_set_stream_mint_ca`, `_mint_ttl`) | **MOVE** |
| `stream/module.c:288-…` | `brix_backend_delegation`, `brix_backend_sss_keytab`, `brix_backend_s3_sts_{endpoint,role,access_key,secret_key,region,ttl,flavor}`, `brix_backend_krb5_forwardable` | **MOVE** |
| `stream/module.c:395` | `brix_credential` block (`Sm\|BLOCK`, `brix_conf_credential_block` — the named-credential registry §14) | **MOVE** (it is the referent of `brix_storage_credential`) |
| `stream/directives_tier.h:11` | `BRIX_TIER_DIRECTIVES("brix_", …)` + async triple | **MOVE** (re-instantiate against the common conf type) |
| `stream/module.c` | `brix_session_log` | **MOVE** (http_common owns the same name on HTTP) |
| `stream/module.c` | `brix_pblock_block_size` | **MOVE** (bare twin of the W4 family) |
| `stream/module.c` | `brix_cache_store_endpoint` | **MOVE** |
| `stream/directives_auth.h:31-145` | `brix_certificate` :31, `brix_certificate_key`, `brix_trusted_ca` :47, `brix_vomsdir` :95, `brix_voms_cert_dir`, `brix_crl` :110, `brix_crl_mode`, `brix_signing_policy`, `brix_require_vo` :145 | **MOVE** (x509 family — gridftp needs every one) |
| `stream/module.c` | `brix_data_substreams`, `brix_pipeline_depth`, `brix_session_slots`, `brix_manager_map`, `brix_manager_mode`, `brix_ocsp_*` | **KEEP** (root:// wire) |
| `stream/directives_{net,cms,cache,tpc,caps,security,writethrough,zones,pmark}.h` remainder | mirror/ratelimit/cms/cache-admission/tpc/caps/seccomp/zones/pmark | **KEEP** for this phase (candidates for later waves; pmark stream-side already bare + single-owner) |

### Variant choice — OP-DECIDE

**Variant A (recommended): extract `ngx_stream_brix_common_module`.**
New TU `src/core/config/stream_common.{c,h}`, exact mirror of `http_common`.
Skeleton:

```c
/* stream_common.h */
typedef struct { ngx_http_brix_shared_conf_t common; } ngx_stream_brix_common_conf_t;
extern ngx_module_t ngx_stream_brix_common_module;
void brix_stream_common_adopt(ngx_conf_t *cf, ngx_http_brix_shared_conf_t *dst);

/* stream_common.c — command table = the MOVE rows above at Sm|Ss, offsets
 * offsetof(ngx_stream_brix_common_conf_t, common.*), plus
 * BRIX_TIER_DIRECTIVES("brix_", ngx_stream_brix_common_conf_t,
 *                      NGX_STREAM_SRV_CONF, NGX_STREAM_SRV_CONF_OFFSET),
 * BRIX_BACKEND_ASYNC_DIRECTIVES(...);
 * create_srv_conf = shared init (reuse ngx_http_brix_shared_init);
 * merge_srv_conf  = brix_shared_adopt_unified(child, parent);   */
```

(The preamble type is plane-neutral despite its `http_` name — the stream
srv conf already embeds it for the tier grammar. If the name grates, a
`brix_shared_conf_t` typedef alias is a one-line follow-up, NOT a rename
sweep in this phase.) `./config`: emit the module BEFORE
`ngx_stream_brix_module` (`config:416` region) in BOTH the static and
dynamic branches — emission order IS the ownership mechanism.

Pros: exact symmetry with HTTP; the W3 bug class becomes unrepresentable; a
future stream protocol (phase-82 successors) onboards with 3 lines. Cons:
touches the root module's merge ordering; largest single-commit surface
after W4.

**Variant B (cheap): adopt-from-root.** Root stays owner; gridftp fetches
`ngx_stream_conf_get_module_srv_conf(cf, ngx_stream_brix_module)` at merge
and adopts the already-merged fields. No new module, ~half a day; but the
owner is implicit, gridftp couples to root's conf layout, and W9.1 must
special-case "root = stream owner". Materially safer than the W2 pattern
(adopt-at-merge, not setter-poke) but strictly worse than A for the phase
goal.

Either variant enables the identical rename table (Appendix A table 3).

### Status & blocker (2026-08-10): undecided variant + core-config rewiring

**Not started — the two reasons it is not a safe autonomous change:**

1. **The variant is undecided (OP-DECIDE).** The disposition above recommends A,
   but the decisions ledger (Appendix, "W3 | Variant A vs B | A") is a *proposal*,
   not a ratified choice: A creates a whole new `ngx_stream_brix_common_module` and
   re-homes the root module's storage/x509/tier families onto it; B keeps root as
   owner and has gridftp adopt-from-root (implicit ownership, a W9.1 special-case).
   The two produce materially different module topologies and different long-term
   maintenance contracts. Picking wrong is expensive to reverse (it moves ~30
   directive registrations and the merge ordering). This needs an explicit OP
   ratification before any code moves.

2. **It is core-config rewiring, not a leaf de-prefix.** Confirmed by reading the
   tree: gridftp (`ftp_module.c`) is a *separate* nginx stream module with its own
   flat conf `ngx_stream_brix_ftp_srv_conf_t` (fields `export`/`allow_write`/
   `storage_backend`/… in `ftp_gateway.h`), NOT the shared preamble. nginx's
   first-module-wins directive routing means a naive de-prefix (gridftp registers
   bare `brix_export`) is **silently wrong** — the directive routes to the root
   module and gridftp's field never gets set, with no error. So the twins can only
   collapse by moving the bare names to a single stream owner and having BOTH root
   and gridftp *adopt* — which relocates root's `brix_export` / `brix_allow_write` /
   `brix_storage_backend` / the whole x509 family (`directives_auth.h`) and the tier
   X-macro. Those are THE core directives used in essentially every fleet config and
   every root:// test. A mistake here (a mis-moved offset, a merge-ordering slip)
   is not a config-parse error — it silently mis-binds a core field.

**Unblock criteria:** (a) OP ratifies variant A or B; (b) the full root:// + gridftp
fleet suites are runnable (they exercise the core `brix_export`/`brix_allow_write`
binding end-to-end — the only way to prove the adopt path binds identically to the
current direct registration). Until both hold, the 11 `brix_gridftp_*` twins stay
allowlisted (R2) with the `# W4/W3 backlog` reason. The mechanical rename table and
step list below are ready to execute the moment the gate opens.

**Execution-detail findings (2026-08-10, deep scope of variant A — OP ratified A):**

- **Adopt-function linkage is a NON-issue.** The dynamic build combines every brix
  module into ONE `.so` named `ngx_stream_brix_module.so` (per `./config` ~L1927:
  "the stream + http modules coexist in a single .so … its symbols back the HTTP
  modules via RTLD_GLOBAL"); the static build is one binary. So a new
  `stream_common.c` can call `brix_shared_adopt_unified()` (defined in
  `http_common.c`) directly — no need to move it to a shared TU.

- **Field-home census of the 11 gridftp twins on the root module:** already
  preamble-backed (`offsetof(…, common.X)`) — `brix_export`→`common.root`,
  `brix_allow_write`, `brix_verify_write`, `brix_storage_backend`,
  `brix_storage_credential`. Stream-LOCAL (must relocate to the preamble first) —
  `brix_certificate`→`certificate` (an `ngx_str_t` PATH, distinct from the built
  `X509 *gsi_cert`), `brix_certificate_key`→`certificate_key`, `brix_trusted_ca`→
  `trusted_ca`, `brix_vomsdir`→`vomsdir`, `brix_voms_cert_dir`→`voms_cert_dir`,
  `brix_require_vo`→`vo_rules` (array; note the preamble already has a SEPARATE
  `common.vo_rules` from W4 — the stream one must be consolidated onto it, not
  left as a duplicate). Relocating `certificate`/`_key`/`trusted_ca` means rebasing
  the GSI postconfig that reads those paths to build `gsi_cert`/`gsi_key`/the
  X509_STORE — SECURITY-CRITICAL cert wiring.

- **gridftp conf does NOT embed the preamble.** `ngx_stream_brix_ftp_srv_conf_t`
  (`ftp_gateway.h`) has flat fields, not a `common` member. Variant A requires
  adding `ngx_http_brix_shared_conf_t common;` to it (+ `ngx_http_brix_shared_init`
  in create, + rebasing every gridftp reader `->export`/`->allow_write`/… to
  `->common.*`), then `brix_stream_common_adopt()` at gridftp merge.

- **The two blockers config-parse CANNOT catch (why runtime verification is
  mandatory, not merely convenient):**
  1. **Merge-order / main→srv inheritance.** `http_common` works because it emits
     BEFORE the HTTP protocols, so its merge (which folds main→srv) runs first and
     the protocols adopt already-merged values. On the stream plane, keeping the
     `.so` name `ngx_stream_brix_module.so` (required — every deployment's
     `load_module` line + the RTLD_GLOBAL symbol-backing depend on it) means
     `stream_common` is NOT first, so root's/gridftp's merge may run BEFORE
     `stream_common`'s — and `ngx_stream_conf_get_module_srv_conf()` then returns a
     srv conf whose `main→srv` inheritance has not happened yet. A `brix_storage_backend`
     set at `stream{}` main would silently fail to reach the servers. `nginx -t`
     passes either way; only a functional fill test catches it. The fix (adopt from
     `stream_common`'s MAIN conf for still-unset fields, or reorder + rename the
     `.so` and sweep every `load_module`) must be chosen and PROVEN with a running
     server, not inferred.
  2. **GSI/auth binding.** After relocating `certificate`/`_key`/`trusted_ca` to the
     preamble and rebasing the GSI postconfig, the only proof that the server cert,
     key, and trust store still load and verify identically is an actual GSI
     handshake — a silent mis-bind here is an auth-integrity regression, the same
     failure class as W5.

  Both are exactly the kind of "parses clean, misbehaves at runtime" defect this
  phase's other families do NOT have. So variant A is **not** in the safely-
  config-verifiable class; it is gated on a runnable root://+gridftp+GSI fleet.

### Steps (variant A)

- [ ] 1. Create `stream_common.{c,h}` per the skeleton; MOVE (not copy) the
  table rows per the disposition table; root module deletes them.
- [ ] 2. Root merge_srv_conf calls `brix_stream_common_adopt()` first, then
  its protocol merges (mirror of the webdav pattern at `config_merge.c:54`).
- [ ] 3. gridftp: delete the 11 prefixed entries and the duplicated flat
  fields (`ftp_gateway.h:31-40`); rebase readers (enumerate:
  `grep -rn '\->export\|\->allow_write\|\->storage_\|\->certificate\|\->trusted_ca\|\->voms' src/protocols/gridftp`);
  adopt in `ftp_module_merge.c`. gridftp keeps: `brix_gridftp` toggle,
  `brix_gridftp_pasv_port_range`, `brix_gridftp_require_allo_size`,
  `brix_gridftp_gsi`.
- [ ] 4. `./config`: add TU in the correct position, `bash -n config`,
  `check_config_coverage.py`.
- [ ] 5. Migration table: 11 gridftp rows.
- [ ] 6. ABI-dirty rebuild; `objs/nginx -t` on a `stream{}` mixing a root://
  server and a gridftp server.

### Stage progress (2026-08-10)

- **Stage 1 — scaffold DONE + verified.** `src/core/config/stream_common.{c,h}`
  (`ngx_stream_brix_common_module`): conf `{ngx_http_brix_shared_conf_t common}`,
  create/merge_srv_conf, and `brix_stream_common_adopt(cf, dst)` which reads THIS
  server's srv conf (`ngx_stream_conf_get_module_srv_conf`, cf->ctx is the current
  server during merge — confirmed against nginx core `ngx_stream.c`) and fills
  still-UNSET dst slots via `brix_shared_adopt_unified`.  Emitted in `./config`
  AFTER `ngx_stream_brix_module` (static block + dynamic combined list) so the
  `.so` name is preserved; reconfigure re-derived all `-march`/`BRIX_HAVE_*`
  flags (grep brix in objs/ngx_modules.c +3 = one module).  Verified INERT: root
  + gridftp suites byte-identical (37 green with the empty command table).
  Because the adopt reads parse-time srv values (not stream_common's merged
  output), it is correct regardless of stream_common's merge order vs root/gridftp
  — sidestepping blocker 1 for the server-level convention every config uses.
- **Stage 2 — storage group DONE + verified.** Moved `brix_export` (→common.root),
  `brix_storage_backend`, `brix_storage_credential`, `brix_allow_write`,
  `brix_verify_write` from the root module (`module.c` / `directives_tpc.h`) into
  stream_common's command table (same stock slots, offsets into the common conf's
  preamble).  Root's `merge_srv_conf` calls `brix_stream_common_adopt(&conf->common)`
  BEFORE `brix_merge_srv_storage` (so root_canon/backend derive from the adopted
  values).  gridftp adopts into its FLAT fields in `brix_ftp_merge_conf` (and
  realpath()s the adopted export into root_canon, replacing the deleted
  `brix_ftp_set_export` parse-time setter byte-for-byte).  18 configs + the interop
  guard swept to bare names.  **Verified: full gridftp suite (170 tests incl.
  pblock/s3/verify-write/VO-ACL/GSI/evil/mode-E/PASV/delegation) + root:// (authdb
  9, acc 13, scheme-gate 6) all green.**  Checker R2 11→6 (allowlist 22→17); the 5
  storage twins removed from the allowlist.
- **Stage 3 — x509 trust group + require_vo DONE + verified.** Rather than
  relocating the stream-LOCAL GSI fields into the preamble + rebasing the root
  GSI postconfig (the high-risk path the plan feared), used the same low-risk
  ADOPT-INTO-EXISTING-FIELDS shape as the storage group: stream_common holds the
  5 GSI-trust strings (`certificate`/`_key`/`trusted_ca`/`vomsdir`/`voms_cert_dir`)
  as its OWN conf fields and `brix_stream_common_adopt_gsi()` copies them into
  root's `xcf->certificate…` and gridftp's `conf->certificate…` at merge — so
  every GSI reader (`tls_config.c`, `auth/gsi/*`, gridftp's `brix_ftp_build_gsi`)
  is byte-for-byte unchanged and no postconfig moved.  `require_vo` (stage 3b):
  stream_common parses the VO-ACL rules (reusing `brix_vo_rules_append`); root and
  gridftp DEEP-COPY them (`brix_stream_common_adopt_vo_rules`) into their own array
  and finalize the copy against their own `root_canon` — never a shared pointer,
  so no plane mutates another's resolved paths (root's finalize is also gated on
  `brix_root` enabled, so a gridftp-only server never finalizes root's copy).
  **Verified: full gridftp suite 173 (incl. GSI handshake, `gsi_evil`
  security-neg, `vo_acl_gsi`) + root:// GSI green.  Checker R2 6→0.**  The GSI-cert
  auth-integrity pin is direct: `nginx_authdb.conf` drives root:// GSI with bare
  `brix_certificate`/`brix_trusted_ca`/`brix_vomsdir` and `test_authdb.py` 9/9
  passes (handshake succeeds on the adopted cert + trust store).

### Tests

- Success: gridftp server configured entirely with bare names
  (`brix_gridftp on; brix_export /data; brix_allow_write on;
  brix_storage_backend posix; brix_certificate …; brix_trusted_ca …;`)
  serves RETR/STOR — extend `tests/test_gridftp_gsiftp.py` /
  `test_gridftp_interop_local.py` rather than a parallel harness; root://
  server in the same `stream{}` unaffected (fleet suite is the pin).
- Error: `brix_gridftp_storage_backend` → stock `unknown directive`.
- Security-neg: gridftp with `brix_allow_write off` refuses STOR before
  credential evaluation (INVARIANT 3 ordering must hold identically through
  the adopted path — `test_gridftp_evil.py` family is the template).

### Acceptance

Root module tables contain no MOVE-row entries;
`grep -c 'ngx_string("brix_gridftp_' src/protocols/gridftp/ftp_module.c`
= 4; gridftp + root fleet suites green; migration table updated; census:
every storage-family name single-registered on the stream plane, owner
`stream_common.c` (or root under variant B, with the checker exception
recorded).

---

## W4 — De-prefix the 35 HTTP twins via family X-macro headers

### Current state — field homes AND readers (all verified)

| Family | Directive homes | Conf fields | Request-path readers (rebase targets) |
|---|---|---|---|
| token verify | webdav `module_commands.c:311+`; s3 `s3/module.c:382+`; stream bare `directives_auth.h:238-250` | webdav `webdav_loc_conf.h:146-152`; s3 `s3.h:113-116`; stream flat srv fields | webdav: `auth_token.c`, `auth_token_verify.c`, `config_proxy.c:51-56` (jwks handed to the proxy/TPC verifier config); s3: `auth_bearer.c:128-132` (issuer/audience/skew into `va`); **cross-family**: `macaroon_endpoint.c:245-247` uses `token_issuer` as the macaroon `location` fallback — the macaroon family commit must keep reading the SHARED issuer field or the fallback silently breaks |
| token introspect | webdav `directives_zones.h` (quad) | webdav conf (`introspect_*`) | webdav token verify path (introspection client) |
| TPC guard | webdav `directives_tpc.h:8-38+`; stream bare `stream/directives_tpc.h` | `webdav_loc_conf.h:79-88` | `tpc.c`, `tpc_config.c`, `tpc_curl_setup.c`, `tpc_curl.c`, `tpc_verify.c`, `tpc_thread.c`, `tpc_marker_start.c` (7 files — largest rebase of the phase; do LAST) |
| x509/VOMS | webdav `module_commands.c:146-206`; stream bare `directives_auth.h:31-145` | `webdav_loc_conf.h:23` + siblings | `auth_cert.c:306-319` (vomsdir + voms_cert_dir → VOMS AC validation), `pki.c:21-25` (cafile/cadir → PKI check), `auth_cert.c:400-410` (cafile/cadir consistency vs nginx `ssl_client_certificate`/`ssl_trusted_certificate`), `tpc_curl_setup.c` (CA material on TPC legs) |
| macaroon | webdav `module_commands.c` (4 names) | `webdav_loc_conf.h:155+` | `access_auth.c`, `auth_token.c`, `auth_token_verify.c`, `macaroon_endpoint.c`, `macaroon_endpoint_oauth2.c`, `macaroon_endpoint_request.c` |
| zip | webdav + s3 tables; stream bare | `webdav_loc_conf.h:183-188`; s3 conf | webdav `get.c`; s3 `object.c` |
| stage/upload | webdav table; stream bare | `webdav_loc_conf.h:66, :73-76` (+ canon) | `put_setup.c` (stage-dir path build + resume) |
| pwd_file | webdav table; stream bare | webdav conf | `auth_basic.c` |
| protbind | webdav `module_commands.c` (2MORE, shared engine `auth/protbind/`); stream bare | webdav conf | `access_auth.c` (grammar + errors come from the SAME shared engine — `module_directives.c:49-57` says so explicitly) |
| pblock | webdav table; stream bare | webdav conf | (pblock backend selection path) |

### Design

One family = one X-macro header = one preamble fragment = one
`brix_shared_adopt_unified` extension. Full skeleton for the largest family
(the others follow the same shape):

```c
/* core/config/token_directives.h — X-macro for the unified token-verify
 * grammar. Instantiated by http_common (bare, preamble offsets) and by the
 * stream owner (bare, flat-field offsets — the pfx/conf_t/offsets
 * parameterization is exactly why stream field homes need not move). */
#define BRIX_TOKEN_DIRECTIVES(pfx, conf_t, ctx, off_jwks, off_issuer,        \
                              off_aud, off_skew, off_cfg, off_refresh,       \
                              off_iurl, off_iloc, off_ittl, off_ifail)       \
    { ngx_string(pfx "token_jwks"),      (ctx)|NGX_CONF_TAKE1,               \
      ngx_conf_set_str_slot,  NGX_HTTP_LOC_CONF_OFFSET_OR_STREAM, off_jwks, NULL }, \
    { ngx_string(pfx "token_issuer"),    (ctx)|NGX_CONF_TAKE1, /* … */ },    \
    { ngx_string(pfx "token_audience"),  (ctx)|NGX_CONF_TAKE1, /* … */ },    \
    { ngx_string(pfx "token_clock_skew"),(ctx)|NGX_CONF_TAKE1,               \
      ngx_conf_set_sec_slot,  /* W7 rides here */ off_skew, NULL },          \
    { ngx_string(pfx "token_config"),    (ctx)|NGX_CONF_TAKE1, /* … */ },    \
    { ngx_string(pfx "token_jwks_refresh_interval"), /* … */ },              \
    { ngx_string(pfx "token_introspect_url"),  /* … */ },                    \
    { ngx_string(pfx "token_introspect_loc"),  /* … */ },                    \
    { ngx_string(pfx "token_introspect_ttl"),  /* … */ },                    \
    { ngx_string(pfx "token_introspect_fail_open"), /* … */ }
```

(Exact slot/offset spelling per entry is mechanical; the tier macro at
`tier_directives.h:46-160` is the reference for comment style and layout.
If the two planes' offset conventions can't share one macro signature
cleanly, prefer TWO macros in one header — `_HTTP` and `_STREAM` variants
sharing a name list — over contorting a single signature; the checker (W9)
verifies name-list equality between them.)

**Field moves (HTTP plane only).** http_common owns the directive ⇒ the
backing field must live in the preamble it adopts from. Per family: move the
webdav/s3 fields into `ngx_http_brix_shared_conf_t` (collapsing webdav/s3
parallel pairs into ONE field), extend `brix_shared_adopt_unified()` +
defaults in the shared merge, delete the protocol fields, rebase the readers
listed in the table above (per-family `grep -rn '<field>'
src/protocols/{webdav,s3}` immediately before each commit to catch drift
since this writeup). The `storage_credential` family (phase-70) is the
worked precedent for every one of these moves.

**Stream plane**: names are already correct; flat srv-conf field homes
(`token_jwks` at `directives_auth.h:242` etc.) DO NOT move in this phase —
the macro parameterization exists precisely so field-home convergence can be
deferred.

**Deliberately NOT unified**: the auth-mode *selectors* `brix_webdav_auth`
(how DAV chooses gsi/token/pwd) and `brix_s3_token` (SigV4 vs bearer), plus
`brix_s3_allow_unsigned_session_token`, `brix_s3_verify_chunk_signatures`
(wire-format handling). How a protocol decides to consult tokens is
protocol-specific; what the token trust config IS, is not.

### Worked example — the zip family (smallest; lands first as the template)

Before: `brix_webdav_zip_access` (flag → `webdav_loc_conf.h:188`, read in
`get.c`), `brix_webdav_zip_cd_max_bytes` (size), `brix_s3_zip_access` +
`brix_s3_zip_cd_max_bytes` (s3 conf, read in `object.c`), stream
`brix_zip_access`/`brix_zip_cd_max_bytes` (already bare).

After: preamble gains `ngx_flag_t zip_access; size_t zip_cd_max_bytes;`;
`http_common.c` registers `brix_zip_access`
(`BRIX_HTTP_ALL_CONF|NGX_CONF_FLAG`, flag_slot) and `brix_zip_cd_max_bytes`
(TAKE1, size_slot); adopt + merge extended (READ the current webdav/s3
merge defaults before deleting them and preserve each — if they differ
between protocols, the stricter default wins and the migration row says so);
`get.c` + `object.c` rebase to `common.zip_*`; four prefixed entries + both
protocol field pairs deleted; migration rows added;
`test_compression_zip.py` flips spelling and gains an s3-location case
proving ONE `http{}`-level `brix_zip_access on;` covers both protocols.

### Steps

- [ ] 1. Land families in ascending reader-surface order, one commit each:
  **zip** (2 readers) → **macaroon** (6 readers; keep the
  `token_issuer`-fallback read pointed at the shared field) →
  **stage/upload + pwd + pblock** (3 readers) → **protbind** (1 reader,
  shared engine) → **x509** (+W6 quintet rows; 4 reader files) → **token**
  (+W7 skew slot; 5 reader files + introspect) → **TPC** (7 reader files).
  Each commit = header (or direct entries) + preamble fields + adopt/merge
  + table deletions + field deletions + reader rebase + migration rows +
  tests. Tree green after every commit.
- [ ] 2. Post-sweep:
  `grep -rn 'ngx_string("brix_webdav_\|ngx_string("brix_s3_' src/` — every
  survivor must appear in the Appendix B ledger (expected webdav: locks,
  CORS, dig, open_file_cache*, checksum family, require_digest, tape_rest,
  auth selector; expected s3: bucket/SigV4/list/MPU/session-token surface).
  Any name not in the ledger is an escaped rename — fix before closing.
- [ ] 3. `contrib/brix-cache.conf.example`: §6/§7 prose teaches the split
  spellings (`brix_upload_resume` vs `brix_webdav_upload_resume`,
  `brix_stage_dir` vs `brix_webdav_stage_dir`) — collapse to the single
  spelling; re-run the 2026-07 plan Task 6 Step 6 doc grep extended with the
  retired names.

### Tests (per family — the 3-class rule applied family-wise)

- Success: bare name configures the feature on webdav AND s3 (AND cvmfs
  where applicable) from a single `http{}`-level line; stream behavior
  byte-identical. The behavior pins are the EXISTING suites with spellings
  flipped in the same commit: `test_wlcg_token_conformance_*` +
  `_test_token_auth_helpers.py` / `_test_token_security_helpers.py`
  consumers (token), `_test_webdav_tpc_helpers.py` + `_test_ipv6_tpc_helpers.py`
  consumers (TPC), `test_compression_zip.py` (zip), the macaroon endpoint
  suite, `test_https_webdav_token_status_codes` helpers (auth surface).
- Error: each retired prefixed name → stock `unknown directive`; each
  family's custom-setter validation errors preserved verbatim (TPC
  source-allow parse errors; protbind grammar errors from the shared
  engine).
- Security-neg (one per family, migrated not rewritten): token — expired JWT
  rejected on BOTH protocols under the shared config; TPC — private-range
  source refused unless `brix_tpc_allow_private on`; x509 — missing VOMS
  attribute refused where `brix_require_vo` demands it; macaroon —
  old-secret rotation window honored, garbage secret refused; zip —
  crafted central directory bounded by the shared `cd_max_bytes` cap;
  stage/upload — stage dir outside export rejected at config time.

### Acceptance

Appendix A tables 1–2 fully applied; step-2 sweep clean against the ledger;
migration table complete; webdav/s3/stream + token/TPC/acc suites green;
census re-run: zero R2 violations on the HTTP plane outside the ledger.

---

## W5 — Resolve the authdb name collision (decision gate)

### Current state

- `brix_authdb <file>` (HTTP) → `brix_acc_http_set_authdb`
  (`module_acc_directives.c:85`) → **XrdAcc engine** (`auth/authz/acc/`);
  tuned by `brix_authdb_format/audit/refresh` + seven `brix_acc_*`
  directives. After W2 this family is owned by http_common.
- `brix_webdav_authdb <file>` → `webdav_conf_authdb`
  (`module_directives.c:25-46`) → **native u/g/p rule parser**
  (`brix_parse_authdb`, `fs/path/path.h`) into `wlcf->authdb_rules`,
  enforced for READ methods in the webdav access phase; the block comment
  states: "Reuses the stream authdb parser; the same file format works for
  both protocols."
- Stream `brix_authdb` (`directives_auth.h`) → the SAME native u/g/p engine.

The bare name means XrdAcc on HTTP and native-rules on stream, and webdav
carries both engines under near-identical names. This is the one rename in
the phase that is not mechanical.

### Options — OP-DECIDE

- **A (recommended): bare `brix_authdb` = the native u/g/p engine on BOTH
  planes** (matches stream — the reference spelling plane). W4's machinery
  then renames `brix_webdav_authdb` → `brix_authdb` (registration moves to
  http_common; `authdb_rules` field → preamble; s3/cvmfs gain native-rule
  READ authorization for free — a real feature, changelog it). XrdAcc's
  entry point renames to `brix_acc_authdb`, and its three `brix_authdb_*`
  tuners consolidate under the prefix the other seven already use:
  `brix_authdb_format` → `brix_acc_format`, `_audit` → `brix_acc_audit`,
  `_refresh` → `brix_acc_refresh`. End state: `brix_authdb*` = native rules
  everywhere; `brix_acc_*` = XrdAcc everywhere; prefix = engine.
- **B:** bare name = XrdAcc (HTTP status quo); stream's `brix_authdb` and
  webdav's `brix_webdav_authdb` both rename. Rejected-by-default: breaks the
  reference plane and renames two spellings instead of one.
- **C:** unify the engines behind one directive with a `format=` selector.
  Rejected-by-default: engine unification is an authorization project with
  its own security review, not a config-surface one. Do not couple.

### Steps (option A)

- [x] 1. **DONE 2026-08-10.** Renamed the four XrdAcc spellings in http_common's
  table: `brix_authdb`→`brix_acc_authdb`, `brix_authdb_format`→`brix_acc_format`,
  `_audit`→`brix_acc_audit`, `_refresh`→`brix_acc_refresh`. Migration rows +
  doc rows (`authorization-xrdacc.md`, `identity-mapping.md`) landed. 4 HTTP
  XrdAcc test configs + `test_acc_unification.py` swept to `brix_acc_*`.
- [x] 2. **DONE 2026-08-10 (webdav-scoped, NOT ALL_CONF).** `brix_webdav_authdb`
  → bare `brix_authdb` on the webdav command table; the setter (`webdav_conf_authdb`)
  and field (`wlcf->authdb_rules`) and webdav access-phase enforcement are
  unchanged — this is a pure de-prefix, behaviour-preserving. **Deviation from
  the original step-2 plan:** the field was NOT moved to the preamble and the
  directive was NOT registered at `BRIX_HTTP_ALL_CONF`, because s3/cvmfs do not
  yet enforce `authdb_rules`, so registering the bare name there would be a SILENT
  authz bypass (a config sets it, the access phase ignores it, deny rules never
  fire). Extending native-rule READ authz to the s3/cvmfs access phases — each
  needs its own identity plumbing, not a copy of `webdav/access.c` — is the
  additive follow-up **W5.2**. Until then, `brix_authdb` at a non-webdav HTTP
  location is accepted-but-inert exactly as `brix_webdav_authdb` was (LOC_CONF
  context accepts it everywhere; only webdav enforces). Not a regression.
- [x] 3. **DONE 2026-08-10.** Swept `docs/06-authentication/` (W5 plane-split
  callouts + directive-table fixes in both `authorization-xrdacc.md` and
  `identity-mapping.md`).

### Implementation notes (2026-08-10) — landed

- **The security-neg pin is config-time, not parser-rejection.** The doc's
  original premise ("an XrdAcc file under bare `brix_authdb` is rejected loudly by
  the native parser") does NOT hold: `brix_parse_authdb`
  (`src/auth/authz/authdb_parse.c`) is deliberately LENIENT — it *skips*
  unrecognized/truncated lines (`if (!line.valid) continue;`) and only errors on
  file-read / alloc failure. So an XrdAcc-format file is silently partial-matched,
  not rejected. The real guarantee W5 delivers is the **dead HTTP selection
  spelling**: `brix_authdb_format` is stream-context-only now, so a pre-W5 XrdAcc
  HTTP recipe (`brix_authdb <file>; brix_authdb_format xrdacc;`) FAILS `nginx -t`
  loudly on the `brix_authdb_format` line → the engine can't be silently carried
  forward. Pinned in `test_authdb_engine_split.py::test_legacy_xrdacc_http_config_fails_loudly`.
  (A stricter fail-closed native parser is a separate security-hardening
  candidate, out of this config-surface phase's scope.)
- **Harness unblock (the W5 gate).** The "fleet harness dies at `load_module` with
  `undefined symbol: ngx_stat_active`" blocker was root-caused as static/dynamic
  build MIXING (injecting a stock/dynamic stream module into the static brix
  binary that lacks the symbol) and FIXED with a build-separation guard
  (`operator_runtime.py` + `live_common.py`). The auth baseline is now runnable:
  `test_authdb.py` **9/9** (stream native authorized/denied GSI integration — the
  unchanged reference plane) via a targeted `start-dedicated authdb` on the
  rebased port ladder + `TEST_SKIP_SERVER_SETUP=1` (see the test-fleet notes).
- **Tests.** New `test_authdb_engine_split.py` (12, fast `nginx -t` matrix incl.
  the security-neg pin — lives here, not in the KDC-gated
  `test_authdb_mechanism_scope.py`, so CI always runs it). Full W5 batch: 46
  passed (engine-split 12 + acc-unification 4 + acc-residual 12 + scheme-gate 6 +
  p805 3 + authdb 9). Allowlist: `brix_webdav_authdb` twin removed (R2 12→11).

### Tests

- Success: each engine reachable under its final name on each plane
  (`test_authdb*.py` native rules; `test_acc*.py` XrdAcc — spellings
  flipped).
- Error: `brix_webdav_authdb` and `brix_authdb_format` → stock
  `unknown directive`.
- Security-neg: a deny rule in EACH engine still denies after the rename —
  and specifically: a config that used bare `brix_authdb` for XrdAcc now
  FAILS at `nginx -t` (the native parser rejects the XrdAcc file format
  loudly) rather than silently authorizing under the wrong engine. This
  scenario is the entire reason W5 exists; pin it explicitly in
  `test_authdb_mechanism_scope.py`.

---

### W5 — analysis (2026-08-10): why the authdb reorg must run WITH the auth integration suite

Current wiring (confirmed by reading the code, not doing the rename):
- **Stream** `brix_authdb <file>` (`policy.c brix_conf_set_authdb`) stores `xcf->authdb` **and** parses native u/g/p into `xcf->authdb_rules`. The XrdAcc engine (`acc/config.c brix_acc_init_server`) reads the SAME `xcf->authdb` path to build `xcf->acc.tables`. `brix_authdb_format native|xrdacc` (`common.acc.format`) picks the engine at RUNTIME in `auth_gate.c:225` (`brix_acc_gate_engine` vs `brix_check_authdb`). So on stream one `brix_authdb` path feeds both engines — polymorphic by format.
- **HTTP** is INCONSISTENT: W2 registered bare `brix_authdb` → `common.acc.authdb` (XrdAcc path only, str slot, no native parse), while `brix_webdav_authdb` (`webdav_conf_authdb`) parses native u/g/p into the webdav-local `authdb_rules`. Two directives, two fields, one concept.

Variant A ("bare = native; `brix_acc_*` = XrdAcc") therefore requires, on the HTTP planes: (1) bare `brix_authdb` set a unified `common.authdb` path + parse `common.authdb_rules` (like stream); (2) the HTTP acc init read `common.authdb` instead of `common.acc.authdb`; (3) the W2 `brix_authdb`→`common.acc.authdb` registration retire (or become `brix_acc_authdb`); (4) `brix_webdav_authdb` de-prefix onto the unified bare name.

**This changes runtime authorization dispatch** (`auth_gate.c` + acc init), not just config parsing — a mistake is a SILENT allow/deny error. It MUST land with the acc/authdb + native-authz integration suites runnable (they cannot run in the current sandbox: the fleet harness dies at `load_module` with `undefined symbol: ngx_stat_active`, a binary/stock-module mismatch unrelated to any directive). Deferred until that harness is green. `brix_webdav_authdb` stays the sole allowlisted R2 twin until then.

**Why config-parse verification is NOT sufficient here (unlike every other W-family in this phase).** The W4/W6/W7/W8 unifications are safe to land config-verified because their failure mode is *loud*: a mis-wired directive fails `nginx -t`, or the old name is a stock `unknown directive`. W5 is the opposite — the same file path (`brix_authdb`) is handed to two different engines chosen at *runtime* by `acc.format`, so a wrong wiring produces a config that parses cleanly and then authorizes under the wrong engine (native u/g/p rules silently ignored, or an XrdAcc file mis-read as native and either rejected or — worse — partially matched). No `nginx -t` and no directive-registry check can catch that; only an integration test that actually issues authorized/denied requests against each engine can. That is exactly the security-neg pin the Steps call for (`test_authdb_mechanism_scope.py`: "a config that used bare `brix_authdb` for XrdAcc now FAILS at `nginx -t` … rather than silently authorizing under the wrong engine").

**Unblock criteria (all three):**
1. The fleet integration harness runs (fix the `undefined symbol: ngx_stat_active` `load_module` mismatch — the harness must load the brix stream module against a binary that exports the symbol; this is the same freeze/binary-selection class documented in the test-fleet notes, not a directive problem).
2. The auth suites are green on the CURRENT tree first (establish the baseline: `test_authdb*.py`, `test_acc*.py`, `test_authdb_auth_scheme_gate.py`) — so a post-rename regression is attributable.
3. The security-neg scenario is written and RED before the rename, GREEN after: an XrdAcc-format file under bare `brix_authdb` must be *rejected loudly* by the native parser at config time (proving the engine can't be silently mis-selected). Only then execute Steps 1–3 of option A.

## W6 — Codify the naming grammar; rename the outliers

### The grammar (three rules — land verbatim in `docs/09-developer-guide/coding-standards.md`, referenced by W9.1)

1. `brix_<feature>` is the feature toggle (flag or mode enum). No `_enable`.
2. `brix_<feature>_<param>` for feature-scoped params; ONE prefix per
   feature.
3. Cross-protocol families use bare `brix_<family>_*` names, registered only
   by a plane's common owner, spelled identically on both planes.

### The CA/trust quintet — reader analysis (RESOLVED; supersedes "verify first" hedges)

| Directive | Reader(s) | Actual mechanism |
|---|---|---|
| `brix_webdav_cafile` / `brix_webdav_cadir` (`module_commands.c:146/:153`) | `pki.c:21-25` (CA source for the PKI validity check), `auth_cert.c:400-410` (consistency-checked against nginx's `ssl_client_certificate`/`ssl_trusted_certificate`) | **Auth-layer verify source** for the GSI/VOMS chain — file vs dir forms of ONE source |
| `brix_ssl_client_capath` (:231) | `postconfig.c:143-193` (hashed dir loaded into the server `SSL_CTX` cert store at postconfiguration) | **Front-leg TLS client-CA store** — a different object entirely |
| `brix_proxy_ssl_capath` (:253) | `module_directives_cert.c:366, :434`, `postconfig_proxy_capath.c` | **Backend-leg CA dir** for proxied/TPC connections |
| `brix_client_certificate_folder` (:242) | `module_directives_cert.c` (probe/pick/load helpers, phase-38 note `module_directives.c:10-16`) | **Server-side folder of acceptable client certs** — distinct again |

Conclusion: these are FOUR mechanisms, not one — do NOT merge them. The fix
is names that say the role, folded into the W4-x509 commit:

| Current | New | Role |
|---|---|---|
| `brix_webdav_cafile` | `brix_trusted_ca` | verify-source file (bare twin exists on stream, `directives_auth.h:47` — same role there; confirm at rebase) |
| `brix_webdav_cadir` | `brix_trusted_ca_dir` | verify-source dir |
| `brix_ssl_client_capath` | `brix_client_ca_store` | front-leg SSL_CTX client-CA store |
| `brix_proxy_ssl_capath` | `brix_backend_ca_dir` | backend-leg CA dir |
| `brix_client_certificate_folder` | keep name; document | acceptable-client-cert folder |

### Other outlier renames (all hard renames; migration rows each)

| Current (cite) | New | Rationale / notes |
|---|---|---|
| `brix_ocsp_enable` (`stream/module.c:509`) | `brix_ocsp` | Rule 1. Siblings `_soft_fail` (:516), `_require_nonce` (:524), `_stapling` (:531) already conform. |
| `brix_impersonation` off\|single\|map, `_user`, `_socket`, `_export`, `_broker_user`, `brix_gridmap`, `brix_idmap_default_user`, `_min_uid`, `_cache_ttl`, `_forbidden_users`, `_forbidden_groups` (`stream/directives_tier.h:22-97`) | ONE prefix — `brix_idmap` (toggle `off\|single\|map`) + `brix_idmap_{user,socket,export,broker_user,gridmap,default_user,min_uid,cache_ttl,forbidden_users,forbidden_groups}` | 4 prefixes → 1. These setters write a process-global settings block via `BRIX_IMP_F_*` selectors (`directives_tier.h:15-21`) — renames touch ONLY the `ngx_string` names, zero setter changes. OP may prefer `impersonation` as the prefix; either satisfies rule 2 — pick once. |
| `brix_scan_root` (`dashboard/module.c:405`), `brix_scan_max_files` (:423) | `brix_dashboard_scan_root`, `brix_dashboard_scan_max_files` | Rule 2, and it disambiguates from `brix_dashboard_browse_root` (:397) — a DIFFERENT confinement root (interactive browse endpoints vs the metrics scanner; `dashboard_http.h:83` vs `:90`). |
| `brix_admin_{allow,secret,require_both,proxy_allow,rate_limit}` (`dashboard/module.c:430+`) | KEEP prefix; document `brix_admin` as its own feature | The admin write-API surface is consumed beyond the dashboard. Rule 2 satisfied once "admin ≠ dashboard" is documented in directives.md. |

### Tests

Per rename: success under the new name (existing feature suite, spelling
flipped), stock `unknown directive` under the old, plus ONE family-level
security-neg: the identity deny-list still enforced under
`brix_idmap_forbidden_users` (the rename must not skip the
`auth/impersonate/lifecycle.c` forbidden-user check — extend
`impersonation_gridmap_helpers.py` consumers). For the CA renames: a client
chain that validated before validates after, and a chain trusted ONLY by the
front-leg store still fails the auth-layer verify (pins that the four
mechanisms stayed distinct through the rename).

---

## W7 — Normalize value syntax

### Conversion table

| Directive (cite) | Today | Change | Operator impact |
|---|---|---|---|
| `brix_webdav_lock_timeout` (`module_commands.c:212`) | `num_slot` (raw seconds) | `sec_slot` | none for existing configs — `ngx_parse_time` accepts bare integers as seconds; `5m` becomes legal |
| `brix_storage_credential_mint_ttl` (`http_common.c:139` + stream twin) | `num_slot` | `sec_slot` | additive |
| `brix_backend_s3_sts_ttl` (both planes) | `num_slot` | `sec_slot` (STS client still clamps 900..43200 AFTER parse — unchanged) | additive |
| `brix_{webdav,s3}_token_clock_skew` → `brix_token_clock_skew` | `num_slot` | `sec_slot` — rides the W4 token commit, one migration row | additive |
| `brix_s3_mpu_max_age` (`s3.h:89-92`, unit = seconds, confirmed) | `num_slot` | `sec_slot` | recommended `604800` becomes writable as `7d` |
| `brix_webdav_cors_max_age` (`module_commands.c:376`, the `Access-Control-Max-Age` seconds) | `num_slot` | `sec_slot` | additive |
| `brix_authdb_refresh` → `brix_acc_refresh` (post-W5; `acc.h` int secs) | custom/num | `sec_slot` — rides the W5 commit | additive |
| `brix_webdav_verify_depth` (:206) | `num_slot` | **keep** — a chain-depth count, not a time | — |
| `brix_dashboard_session_ttl` (custom setter) | custom | keep custom (validates a floor) but parse via `ngx_parse_time` internally | `30m` becomes legal |
| ratelimit size parsing (`ratelimit_keys_parse.c:78-91` hand-rolled k/K/m/M/g/G vs `rl_parse_size` :95-99 = `ngx_parse_size`) | TWO parsers, one file | delete the hand-rolled one; all callers → `ngx_parse_size` | superset (both suffix cases accepted); pin with a parse unit test |
| zone grammars: `brix_rate_limit_zone zone=NAME:SIZE` (:103) vs `brix_kv_zone <name> <size> key=N val=N` (`kv_config.c:276`) vs `brix_token_cache zone=` | three shapes | ONE nginx-conventional shape: `zone=name:size` everywhere → `brix_kv_zone zone=name:size key=N val=N` | **breaking** for `brix_kv_zone` → hard-rename discipline: migration row + the directive's own EMERG error names the new shape |
| dual-poke on/off hand-parsers | deleted by W2 | — | stock flag-slot error text (W2 step 5) |

### Steps

- [ ] 1. Commit A: the num→sec slot swaps (pure table edits — every listed
  conf field is already an integer-seconds type) + the ratelimit parser
  dedup + parse unit test.
- [ ] 2. Commit B: the `brix_kv_zone` grammar change (`kv_config.c:276+` arg
  walk) + migration row + its EMERG text.
- [ ] (clock_skew and acc_refresh ride their W4/W5 commits.)

### Tests

- Success: each converted directive accepts BOTH the legacy bare integer and
  a suffixed value, with the same effective seconds observed behaviorally
  (e.g. lock expiry at `2` vs `2s`).
- Error: `brix_webdav_lock_timeout banana;` → stock time-parse EMERG;
  old-shape `brix_kv_zone` → its new EMERG naming `zone=name:size`.
- Security-neg: `brix_token_clock_skew 10m` yields a 600-second verifier
  skew, not 10 — assert a token near the boundary is accepted/rejected
  accordingly in the wlcg-conformance suite (unit-confusion pin).

---

## W8 — Legacy HTTP cache grammar: migrate onto the tier grammar or keep-and-document (decision on evidence)

### Current state — inventory (corrected; the feature is LIVE)

- The debt marker: `shared_conf_types.h:168-172` — the phase-64 tier grammar
  deliberately avoided colliding with "the legacy cache directives … until
  the P2 legacy-removal big-bang".
- `brix_webdav_cache_root` — entry `webdav/directives_storage.h:38-42`,
  field `webdav_loc_conf.h:19` (+ `cache_root_canon`), merge + validation
  `config_merge.c:63` and `:289-300` (`brix_prepare_export_root` +
  `brix_assert_dir_outside_export`).
- `brix_s3_cache_root` — entry `s3/module.c:236-240`, field `s3.h:74`
  (+ canon), merge + validation `module_merge.c:100`, `:282-297`.
- `brix_prepare_export_root` (`core/config/root_prepare.c`) is pure
  validation + canonicalization (stat/access/realpath into the canon
  buffer) — **no engine-registration side effects** (read in full).
- **The canon field IS read on every request.** `cache_root_canon` is the
  third argument to `brix_vfs_ctx_init()` at: `webdav/namespace.c:37`,
  `webdav/put_setup.c:49`, `webdav/move.c:79` and `:142`, `s3/util.c:41` —
  i.e. the legacy read-through-cache root is threaded into the VFS context
  on the webdav namespace/PUT/MOVE paths and the s3 request path. The
  earlier "no readers" impression came from grepping `cache_root` while
  excluding the derived `cache_root_canon` — a trap now recorded in
  Appendix C so no future sweep repeats it.
- So: TWO live cache systems share the config namespace — the legacy VFS
  read-through root (`brix_*_cache_root` → `brix_vfs_ctx_init`) and the
  phase-64 composable tier (`brix_cache_store` → sd_cache decorator). This
  is the single most confusing thing a new operator meets in the HTTP
  storage section, and exactly what the P2 note promised to resolve.

### Options — OP-DECIDE (on the evidence above, not before reading it)

- **A (recommended): migrate.** Make the tier grammar the only spelling:
  a posix `brix_cache_store file:/…` composes the same read-through
  semantics via the sd_cache decorator, and the VFS ctx takes its cache
  root from the tier registration instead of the legacy field. Requires a
  behavior diff first: enumerate what `brix_vfs_ctx_init`'s cache path DOES
  on webdav namespace/PUT/MOVE (write-through? read-only shadow? rename
  interplay?) vs what sd_cache provides; any gap becomes a tier feature or
  a documented loss. Then delete directive + fields + validation blocks,
  migration rows mapping to `brix_cache_store`, and extend
  `tests/test_deadcode_removed.py` (phase-95 pattern).
- **B: keep, but rename + document.** If the VFS-level root turns out
  semantically distinct from sd_cache (e.g. it also gates MOVE/DELETE
  behavior), keep it as ONE bare directive (`brix_vfs_cache_root`,
  registered by http_common, field in the preamble — killing the
  webdav/s3 twin pair at least), and directives.md explains when to use
  which cache. Smaller, honest, still rule-3 conformant.
- Either way the current state — two per-protocol spellings of a legacy knob
  beside the unified tier grammar — does not survive the phase.

### Steps

- [ ] 1. Behavior diff (the decision input): trace `brix_vfs_ctx_init`'s
  use of the cache path through `fs/vfs/` (what ops consult it, what
  writes land there, interplay with resolve_path / INVARIANT 4) and diff
  against the sd_cache read-fill path. Write the findings INTO this
  section.
- [ ] 2. OP decision A/B on that evidence.
- [ ] 3. Execute per option: (A) tier-migration + deletion + deadcode pins;
  (B) single bare directive + preamble field + adopt + deletion of the
  twins + docs.
- [ ] 4. Sweep `tests/` + fleet specs for either directive; port any user
  to the surviving spelling in the same commit.

### Tests

- Success: (A) a config previously using `brix_webdav_cache_root` rewritten
  per the migration row serves the same read-through workload byte-exact;
  (B) the bare directive works identically on webdav and s3 from one line.
- Error: retired spelling(s) → stock `unknown directive`.
- Security-neg: cache path outside the export still rejected at config time
  (`brix_assert_dir_outside_export` behavior preserved wherever the value
  ends up); reserved-sidecar-name 404 guard unaffected
  (`brix_cache_store_endpoint off` default).

---

### W8 — behavior-diff (2026-08-10) and decision: option B

The MIGRATE-OR-KEEP decision required a behavior diff first. Reading the code (cache_storage.c:197-244) settles it: the legacy `brix_{webdav,s3}_cache_root` builds `cache_storage_inst` (a simple posix cache), while the tier `brix_cache_store` builds a composable **sd_cache decorator** — the reaper/eviction enumerate through DIFFERENT instances depending on which is set (`brix_cache_storage()` returns the decorator's store when `cache_store` is set, else `cache_storage_inst`). They are distinct, live mechanisms; the tier does NOT subsume the legacy read-through cache. The stream plane's cache root (`brix_cache_export`) is a THIRD, fd-based mechanism again.

Therefore migrating (A) would remove a live, distinct mechanism — unverifiable without the cache integration suite and against the "no silent behavior loss" bar. **Decision: option B** — keep the mechanism, unify the two byte-parallel HTTP twins into one bare `brix_cache_root`. Executed as a pure field-relocation (cache_root + cache_root_canon → the shared preamble; registered once on the common module; adopted into webdav+s3; each protocol still canonicalizes + enforces the outside-export guard). No cache-logic change; compile-verified across ~36 readers + config-parse verified (`test_cache_root_unification.py`). The stream `brix_cache_export` (separate fd-based mechanism) is intentionally untouched.

## W9 — Guardrails: make drift structurally impossible

### 9.1 `tools/ci/check_directive_registry.py`

Sits beside `check_config_coverage.py` / `check_vfs_seam.py` in the CI lane
and the `--pr` gate. Implementation seed: Appendix C. Required capabilities
beyond the seed:

- **Fragment + macro awareness**: scan `.h` as well as `.c`; expand every
  `BRIX_*_DIRECTIVES` instantiation by reading the pfx argument at each
  site and parsing that header's `ngx_string(pfx "…")` tokens for the name
  list (robust to family growth — no hand-maintained lists).
- **Plane classification**: stream if context flags contain `NGX_STREAM_*`
  or the file lives under `stream/`, `net/cms/`, `protocols/gridftp/`;
  http if `NGX_HTTP_*` / `BRIX_HTTP_ALL_CONF`. Neither → error (malformed
  table).

Rules (each with a rule-id in the failure output):

- **R1 same-plane duplicate name.** Would have caught the W1 pmark bug at
  its introducing commit. Post-W1/W2 allowlist: empty.
- **R2 prefixed twin** — `brix_<proto>_X` registered while bare `brix_X`
  exists on either plane. Allowlist: checked-in
  `tools/ci/directive_registry_allowlist.txt`, seeded from Appendix B, one
  name per line with a mandatory `# reason`; shrinks as W3–W6 land; every
  survivor is a documented decision.
- **R3 undocumented name** — absent from
  `docs/03-configuration/directives.md`. Current offenders (17 — all
  documented as part of LANDING the checker, so it starts green, never
  grandfathered-red): `brix_frm_control_dir`, `brix_frm_copy_timeout`,
  `brix_frm_force_scratch`, `brix_frm_stage_dir`, `brix_frm_stage_wait`,
  `brix_backend_s3_sts_access_key`, `_region`, `_role`, `_secret_key`,
  `_ttl`, `brix_backend_async_batch`, `brix_backend_async_wait`,
  `brix_cache_cold_max_age`, `brix_cache_only_if_cached`,
  `brix_gridftp_vomsdir` + `brix_gridftp_voms_cert_dir` (moot after W3),
  `brix_signing_required`.
- **R4 cross-module conf-poke** — `ngx_http_conf_get_module_loc_conf(cf,
  <foreign module>)` (or stream analogue) inside a directive setter; grep +
  allowlist for legitimate read-only lookups. Post-W2 allowlist: empty.

Checker's own tests: success (tree passes), error (fixture with a
same-plane dup fails citing R1; a prefixed twin fails citing R2), tamper pin
(R2 cannot be silenced without an allowlist line, and an allowlist line
without a `# reason` is itself a failure).

Rollout: WARN mode in the same commit as W2's completion; flip to FAIL when
the W6 renames empty the transitional allowlist entries.

### 9.2 Stale self-documentation

`tier_directives.h:2-23` still says protocol modules instantiate the macro
with per-protocol prefixes ("The including module writes e.g.
`BRIX_TIER_DIRECTIVES(\"brix_s3_\", …)`") and calls it "the twelve
ngx_command_t initializers" — only bare-prefix instantiations exist
(`http_common.c:345`, `stream/directives_tier.h:11`) and the macro emits 17
entries. Rewrite the WHAT/HOW block; note "17 entries — the registry checker
parses this header for the authoritative list".

### 9.3 Close the 2026-07 plan (Tasks 6–7, absorbed verbatim)

- Task 6 (docs): **DONE 2026-08-10.** `directives.md` unified-grammar intro + full cvmfs table;
  `examples.md` 3-line cvmfs config; `quick-reference.md` cvmfs rows;
  `deploy/cvmfs/README.md` shrink; migration table — EXTENDED with every
  W3–W8 rename row (the table is cumulative and sweep-exempt per its own
  header note).
- Task 7 (tests): **DONE 2026-08-10.** `tests/run_cvmfs_minimal.sh` (3-line-config e2e) and
  `tests/run_cvmfs_evict.sh` per the plan's specs — the acceptance tests
  for this phase's "simple first" claim, unchanged.

### 9.4 Docs-from-source (stretch — OP-DECIDE)

The checker already extracts name/context/arg-shape per directive; emitting
the `directives.md` reference TABLES from that extraction (defaults and
prose stay hand-written) removes R3's failure mode permanently. Only worth
it if generated tables preserve the current doc's per-directive prose
quality — decide after reviewing the checker's extraction on the real tree.

---

## Sequencing, commit plan, and effort

```
W1 (pmark fix)                    1 commit   — first; small, real bug, proves the pattern
 └→ W2 (retire dual-poke)         2 commits  — flags, then acc-family move
     ├→ W3 (stream owner)         2 commits  — module extraction, then gridftp flip   ─┐ parallel
     ├→ W4 (family renames)       7 commits  — zip, macaroon, stage+, protbind,        │ tracks
     │                                          x509(+W6 CA rows), token(+W7 skew), TPC┘
     │    └→ W5 (authdb)          1 commit   — decision gate BEFORE its rename lands
     ├→ W6 (naming outliers)      2 commits  — stream renames (ocsp+idmap), dashboard
     └→ W7 (value syntax)         2 commits  — slot swaps + parser dedup; kv_zone grammar
         └→ W8 (legacy cache)     1–2 commits — behavior diff, decision, execute
             └→ W9 (guardrails)   2 commits  — checker WARN→FAIL; docs Tasks 6–7
```

### Commit-by-commit file map

| # | Commit | Files touched (primary) |
|--:|---|---|
| 1 | W1 pmark→common | `http_common.c`, `webdav/directives_zones.h`, `s3/module.c`, `tests/test_pmark_s3.py` |
| 2 | W2 flags→common | `http_common.c`, `module_commands.c`, `module_acc_directives.c` (shrink) |
| 3 | W2 acc→common | `shared_conf_types.h`, `http_common.c`, `module_commands.c`, `module_acc_directives.{c,h}` (delete), `webdav_loc_conf.h`, `s3.h`, `access.c`, `s3/handler.c`, `./config` |
| 4 | W3 stream_common | `core/config/stream_common.{c,h}` (new), `stream/module.c`, `stream/directives_{auth,tier}.h`, `./config` |
| 5 | W3 gridftp flip | `ftp_module.c`, `ftp_gateway.h`, `ftp_module_merge.c`, gridftp readers, migration table, `test_gridftp_*.py` configs |
| 6–12 | W4 families (zip → … → TPC) | per-family: `core/config/<family>_directives.h` (new), `shared_conf_types.h`, `http_common.c`, protocol tables/fields/readers per the W4 inventory table, migration table, family suite |
| 13 | W5 authdb | `http_common.c`, `module_directives.c`, migration + docs, `test_authdb_mechanism_scope.py` |
| 14 | W6 stream outliers | `stream/module.c` (ocsp), `stream/directives_tier.h` (idmap), migration, idmap suite |
| 15 | W6 dashboard | `dashboard/module.c`, migration, dashboard suite |
| 16 | W7 slots+parser | listed tables, `ratelimit_keys_parse.c`, parse unit test |
| 17 | W7 kv_zone | `kv_config.c`, migration, kv tests |
| 18(–19) | W8 per decision | per option A/B lists above |
| 19 | W9 checker | `tools/ci/check_directive_registry.py` (new), allowlist, fixtures, CI lane wiring, `tier_directives.h` comment |
| 20 | W9 docs close-out | `docs/03-configuration/*`, `deploy/cvmfs/README.md`, `run_cvmfs_minimal.sh`, `run_cvmfs_evict.sh`, CLAUDE.md OP→FILE rows |

Every commit: tree green (`objs/nginx -t` + `check_config_coverage.py` +
pytest `--pr` gate), migration rows + three tests ride the commit they
belong to, ABI-dirty rebuild where flagged. No commits without OP approval
in-conversation. Fleet impact: config templates in `tests/` flip spellings
inside the renaming commits; the fleet
(`python3 -m cmdscripts.manage_test_servers restart` from `tests/`) restarts
per rename wave, not per commit.

### OP decisions required before the affected commit (summary)

| Gate | Decision | Recommendation |
|---|---|---|
| W3 | Variant A (stream_common module) vs B (adopt-from-root) | A |
| W5 | authdb bare-name semantics (A/B/C) | A — bare = native rules; `brix_acc_*` = XrdAcc |
| W6 | identity prefix `idmap` vs `impersonation` | `idmap` |
| W8 | migrate legacy cache_root onto tier (A) vs keep-as-one-bare-directive (B) | A, pending the behavior diff in W8 step 1 |
| W9.4 | docs-from-source generation | defer until checker output reviewed |

### Risk register

| Risk | Mitigation |
|---|---|
| Preamble growth changes struct offsets across 4 modules | ABI-dirty clean rebuild EVERY W1/W2/W4/W8 commit (memory: phantom auth failures from stale `.o`) |
| A family rename misses a reader and a feature silently reverts to defaults | the W4 reader-inventory table IS the checklist; re-grep per family immediately before its commit; flipped behavior suites are the backstop |
| Cross-family coupling breaks silently (macaroon `location` falls back to `token_issuer`, `macaroon_endpoint.c:245-247`) | called out in the W4 inventory; macaroon commit's tests include the issuer-fallback case |
| Site configs break on hard renames | intended and loud (`unknown directive` at `nginx -t`); migration table is the operator path; no silent aliases by convention |
| W3-A reorders stream merges and perturbs root:// init | fleet stream suite + the mixed root+gridftp `stream{}` test in the same commit |
| W8 option A loses a legacy-cache behavior sd_cache lacks | the behavior diff is a REQUIRED step before the decision; option B is the honest fallback |
| Checker false-positives on unusual tables | fixture tests + allowlist-with-reason escape hatch; WARN-mode soak before FAIL |
| `ngx_parse_size`/`ngx_parse_time` edge behavior differs from hand parsers | superset property pinned by parse unit tests before the swap commit |

### End-state acceptance for the phase

Census re-run reports ≤ ~490 unique names; zero R1 same-plane duplicates;
zero non-allowlisted R2 prefixed twins; zero R3 undocumented names; zero R4
cross-module pokes; mechanisms 3 and 4 absent from the tree
(`module_acc_directives.c` deleted; no parallel token/zip/x509 tables); at
most ONE cache-root spelling surviving W8, bare and single-owner if it
survives; `check_directive_registry.py` in FAIL mode in CI;
`run_cvmfs_minimal.sh` green proving the 3-line config; migration table
covers every rename in this file.

---

## Appendix A — Rename tables (hard renames, no aliases)

### Table 1 — webdav → bare (34 rows; 30 mechanical, 2 W6-resolved, authdb via W5, cache_root via W8)

| Current | Unified name | Wave |
|---|---|---|
| `brix_webdav_token_jwks` | `brix_token_jwks` | W4-token |
| `brix_webdav_token_issuer` | `brix_token_issuer` | W4-token |
| `brix_webdav_token_audience` | `brix_token_audience` | W4-token |
| `brix_webdav_token_clock_skew` | `brix_token_clock_skew` | W4-token (+W7 sec_slot) |
| `brix_webdav_token_config` | `brix_token_config` | W4-token |
| `brix_webdav_token_introspect_url` | `brix_token_introspect_url` | W4-token (no bare twin yet) |
| `brix_webdav_token_introspect_loc` | `brix_token_introspect_loc` | W4-token |
| `brix_webdav_token_introspect_ttl` | `brix_token_introspect_ttl` | W4-token |
| `brix_webdav_token_introspect_fail_open` | `brix_token_introspect_fail_open` | W4-token |
| `brix_webdav_tpc_allow_local` | `brix_tpc_allow_local` | W4-tpc |
| `brix_webdav_tpc_allow_private` | `brix_tpc_allow_private` | W4-tpc |
| `brix_webdav_tpc_require_source_size` | `brix_tpc_require_source_size` | W4-tpc |
| `brix_webdav_tpc_source_allow` | `brix_tpc_source_allow` | W4-tpc |
| `brix_webdav_tpc_source_guard` | `brix_tpc_source_guard` | W4-tpc |
| `brix_webdav_tpc_verify_checksum` | `brix_tpc_verify_checksum` | W4-tpc |
| `brix_webdav_vomsdir` | `brix_vomsdir` | W4-x509 |
| `brix_webdav_voms_cert_dir` | `brix_voms_cert_dir` | W4-x509 |
| `brix_webdav_require_vo` | `brix_require_vo` | W4-x509 |
| `brix_webdav_crl` | `brix_crl` | W4-x509 |
| `brix_webdav_crl_mode` | `brix_crl_mode` | W4-x509 |
| `brix_webdav_signing_policy` | `brix_signing_policy` | W4-x509 |
| `brix_webdav_cafile` | `brix_trusted_ca` | W6 (with W4-x509 commit) |
| `brix_webdav_cadir` | `brix_trusted_ca_dir` | W6 (with W4-x509 commit) |
| `brix_webdav_macaroon_secret` | `brix_macaroon_secret` | W4-macaroon |
| `brix_webdav_macaroon_secret_old` | `brix_macaroon_secret_old` | W4-macaroon |
| `brix_webdav_macaroon_max_validity` | `brix_macaroon_max_validity` | W4-macaroon |
| `brix_webdav_macaroon_location` | `brix_macaroon_location` | W4-macaroon |
| `brix_webdav_zip_access` | `brix_zip_access` | W4-zip |
| `brix_webdav_zip_cd_max_bytes` | `brix_zip_cd_max_bytes` | W4-zip |
| `brix_webdav_stage_dir` | `brix_stage_dir` | W4-stage |
| `brix_webdav_upload_resume` | `brix_upload_resume` | W4-stage |
| `brix_webdav_protbind` | `brix_protbind` | W4-protbind |
| `brix_webdav_pwd_file` | `brix_pwd_file` | W4-stage |
| `brix_webdav_pblock_block_size` | `brix_pblock_block_size` | W4-stage |
| `brix_webdav_authdb` | per W5 (rec: `brix_authdb`) | W5 |
| `brix_webdav_cache_root` | per W8 (rec: retired → `brix_cache_store`) | W8 |

### Table 2 — s3 → bare (7)

| Current | Unified name | Wave |
|---|---|---|
| `brix_s3_token_jwks` | `brix_token_jwks` | W4-token |
| `brix_s3_token_issuer` | `brix_token_issuer` | W4-token |
| `brix_s3_token_audience` | `brix_token_audience` | W4-token |
| `brix_s3_token_clock_skew` | `brix_token_clock_skew` | W4-token |
| `brix_s3_zip_access` | `brix_zip_access` | W4-zip |
| `brix_s3_zip_cd_max_bytes` | `brix_zip_cd_max_bytes` | W4-zip |
| `brix_s3_cache_root` | per W8 (rec: retired → `brix_cache_store`) | W8 |

### Table 3 — gridftp → bare (11, gated on W3)

| Current | Unified name |
|---|---|
| `brix_gridftp_export` | `brix_export` |
| `brix_gridftp_allow_write` | `brix_allow_write` |
| `brix_gridftp_verify_write` | `brix_verify_write` |
| `brix_gridftp_storage_backend` | `brix_storage_backend` |
| `brix_gridftp_storage_credential` | `brix_storage_credential` |
| `brix_gridftp_certificate` | `brix_certificate` |
| `brix_gridftp_certificate_key` | `brix_certificate_key` |
| `brix_gridftp_trusted_ca` | `brix_trusted_ca` |
| `brix_gridftp_vomsdir` | `brix_vomsdir` |
| `brix_gridftp_voms_cert_dir` | `brix_voms_cert_dir` |
| `brix_gridftp_require_vo` | `brix_require_vo` |

### Table 4 — W5/W6 stream+outlier renames

| Current | New |
|---|---|
| `brix_ocsp_enable` | `brix_ocsp` |
| `brix_impersonation` | `brix_idmap` |
| `brix_impersonation_user` | `brix_idmap_user` |
| `brix_impersonation_socket` | `brix_idmap_socket` |
| `brix_impersonation_export` | `brix_idmap_export` |
| `brix_impersonation_broker_user` | `brix_idmap_broker_user` |
| `brix_gridmap` | `brix_idmap_gridmap` |
| `brix_scan_root` | `brix_dashboard_scan_root` |
| `brix_scan_max_files` | `brix_dashboard_scan_max_files` |
| `brix_authdb` (HTTP, XrdAcc) | `brix_acc_authdb` (W5-A) |
| `brix_authdb_format` / `_audit` / `_refresh` | `brix_acc_format` / `brix_acc_audit` / `brix_acc_refresh` (W5-A) |
| `brix_ssl_client_capath` | `brix_client_ca_store` (reader-resolved: front-leg SSL_CTX store) |
| `brix_proxy_ssl_capath` | `brix_backend_ca_dir` (reader-resolved: backend leg) |

## Appendix B — Deliberately NOT renamed (seeds the R2 allowlist, one `# reason` each)

| Name(s) | Why it stays |
|---|---|
| `brix_cms_server_sss_keytab` | Different trust role than `brix_backend_sss_keytab`: authenticates inbound cmsd logins vs signs delegation-gate identity injection. Same material, different decision — merging the names would hide that. |
| `brix_cms_server_*` (interval, allow, timeouts, max_connections*, tcp_*) + `brix_cms_blacklist_file` | Feature-scoped cms-server tuning; rule-2 conformant. |
| `brix_webdav_auth`, `brix_s3_token` (toggles), `brix_s3_allow_unsigned_session_token`, `brix_s3_verify_chunk_signatures` | Auth-mode SELECTION and wire-format handling are genuinely per-protocol; only trust material unifies (W4). |
| `brix_client_certificate_folder` | Reader-resolved (W6): acceptable-client-cert folder, distinct from all four other CA knobs; keep + document. |
| `brix_webdav_lock_*`, `brix_webdav_cors_*`, `brix_webdav_dig*`, `brix_webdav_open_file_cache*`, `brix_webdav_checksum_*`, `brix_webdav_require_digest`, `brix_webdav_tape_rest` | WebDAV-verb semantics with no cross-protocol meaning today. `open_file_cache*` becomes a bare-family candidate IF S3/cvmfs grow the same cache — note in directives.md, do not pre-rename. |
| `brix_s3_*` bucket/SigV4/list/MPU surface | S3-wire-specific. |
| `brix_cvmfs_*` / `brix_scvmfs_*` | Protocol-specific by design; the 2026-07 plan deliberately exposes only the shared tier grammar to cvmfs. |
| `brix_guard_*`, `brix_srr_*`, `brix_dashboard_*`, `brix_admin_*`, `brix_pmark_*` (post-W1), `brix_acc_*` (post-W5) | Single-feature families; rule-2 conformant after W6. |
| `brix_gridftp` toggle + `pasv_port_range`, `require_allo_size`, `gsi` | FTP-wire-specific (survives W3). |

## Appendix C — Census reproduction + grep protocol (seed for W9.1)

```python
# tools/ci/check_directive_registry.py starts from this extractor (run at repo root)
import re, os
entry = re.compile(
    r'\{\s*ngx_string\("([a-z0-9_]+)"\)\s*,\s*'
    r'((?:[^,{}]|\n)*?(?:CONF|ALL_CONF)(?:[^,{}]|\n)*?)\s*,\s*([A-Za-z0-9_]+)\s*,', re.S)
regs = []
for dp, _, fs in os.walk('src'):
    for f in fs:
        if f.endswith(('.c', '.h')):
            t = open(os.path.join(dp, f), errors='replace').read()
            for m in entry.finditer(t):
                if 'offsetof' not in m.group(3):        # skip struct-init false positives
                    regs.append((m.group(1), m.group(2), m.group(3), os.path.join(dp, f)))
# Then: (1) expand every BRIX_*_DIRECTIVES instantiation — read the pfx argument
# at the site and parse that header's `ngx_string(pfx "...")` tokens for the
# name list, so family growth is picked up automatically; (2) classify plane
# from context flags / path; (3) apply R1–R4 with the allowlist.
```

2026-08-09 baseline: 592 registrations, 515 literal names (+18
macro-generated bare names = 533 unique), 27 declaring files. A plain-array
scan finds only 226 entries — fragment headers and macros are NOT optional
for any tooling touching this surface.

**Reader-tracing protocol** (how the W2/W4/W6/W8 inventories were produced,
and the trap to avoid): a directive's liveness is proven at its FIELD's
request-path readers, not its registration. Trace
`directive → conf field → every reader of that field AND of every derived
field`. The concrete trap hit during this audit: `brix_webdav_cache_root`
looks reader-less if you grep `cache_root` and exclude matches on the
derived `cache_root_canon` — but the canon buffer is what the request path
consumes (`brix_vfs_ctx_init` at `namespace.c:37` etc.). Rule: canonicalized
(`*_canon`), resolved (`*_r`, `dest_sa`), and generation-swapped (`tables`)
companions of a conf field are part of that field's read graph; sweep them
before declaring anything dead.
