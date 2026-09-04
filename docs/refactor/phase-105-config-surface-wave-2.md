# Phase 105 — config-surface wave 2: finish the ownership thesis, kill the drift R2 cannot see

**Status:** COMPLETE (2026-09-03). W1–W8 and the W9 implementation are
complete. The attach-probe cleanup hardening described in the final addendum
is complete (Phase 111 B111-010).

Source: post-phase-101 directive-surface survey of 2026-08-10, run against the
working tree (`main` @ a3f1e500 + local edits) with
`tools/ci/check_directive_registry.py` plus a strict command-entry census
(Appendix C — including the SHM-zone-name false-positive trap that census
uncovered). Builds directly on
`docs/refactor/phase-101-config-surface-unification.md`, which closed with
R1=0 and R2=0. Every line citation below was verified against the working
tree on 2026-08-10; field homes were traced to request-path readers per the
101-Appendix-C protocol (directive → conf field → every reader of that field
and its `*_canon`/`*_r` derivatives), and each workstream's "Current state"
lists the reader inventory it verified.

**Goal.** Phase 101 proved the mechanism (common owner + adopt-at-merge,
X-macro families) and reached its measured targets. This wave finishes the
*thesis* the mechanism exists for:

- (a) one live instance of the W1 silent-no-op bug class remains — **25 bare
  HTTP names still registered by the webdav module**, including the
  rate-limiting family, which parses cleanly in an S3 location and enforces
  nothing;
- (b) **cross-plane spelling drift** R2 is structurally blind to (same
  concept, two spellings — `brix_webdav_maxdelay` vs `brix_max_delay`);
- (c) **six Table-1 renames that escaped W4** plus ~13 unledgered
  `brix_webdav_tpc_*` survivors the 101 step-2 sweep never reconciled;
- (d) the checker is still **WARN-mode with 322 R3 findings** and 4
  un-allowlisted R4 findings;
- (e) the **structural debt** the low-risk W3/W4 shapes deliberately deferred
  (dual field homes, adopt shims, plane-local `acc`).

Net effect: bare name ⇒ common owner becomes TRUE (not just R2-clean) on the
HTTP plane; "learn once, works on every protocol" extends to rate limiting,
mirroring and token caching; and two new checker rules (R5/R6) make both
residual classes structurally impossible.

| WS | Item | Verdict | Size |
|----|------|---------|------|
| W1 | Rate-limit/zones family: webdav-owned bare names, enforcement absent on s3/cvmfs (live W1-class silent no-op on a DoS-protection knob) | ✅ **DONE 2026-08-10** — all 7 registrations → http_common; fields → preamble; s3 gate + s3 bearer token-cache + cvmfs gate landed; shaping engine rules-source decoupled; `tests/test_rate_limit_s3.py` (4) + phase-20/25 suites green. See the implementation log. | M |
| W2 | Remaining 18 webdav-owned bare HTTP names — per-name disposition | ✅ **DONE 2026-08-10 (session 2)** — class (ii): credential block, delegation_endpoint, client_ca_store relocated; class (i): the 8 mirror settings → preamble + http_common (offset-based setters, merges → shared_merge); class (iii): trusted_ca pair + tcp_congestion (reader-trace verdict: shared file-serve engine → MOVE) + verify_depth → preamble; `brix_http_query_token`/`brix_http_secretkey` → `brix_webdav_*`; `brix_backend_ca_dir` LEDGERED (deviation, logged); `client_certificate_folder` ledgered. R5 allowlist carries the keeps. | M–L |
| W3 | Cross-plane spelling drift: `maxdelay`, TPC outbound-token quartet, XrdAcc tuner prefixes, `brix_stream_mirror_url`, verify-depth pair (semantics RESOLVED — see W3.5) | ✅ **DONE 2026-08-10 (clusters 1–4)** — maxdelay de-prefixed + preamble-homed; TPC quartet renamed (name-only); stream tuners → `brix_acc_*`, selector → `brix_authdb_engine` (W3.3-c) with the duplicate enum tables deduped to one definition; `brix_mirror_url` unified. Cluster 5 (verify-depth) rides the W2 x509 commit as planned. | S–M |
| W4 | Close Table 1 | ✅ **DONE 2026-09-03** — introspect quad → bare `brix_token_introspect_*` on http_common (+sec_slot ttl; the GLOBAL introspection handler now reads honestly-shared settings); macaroon pair decided (b): ledgered + Table-1 correction row; TPC-tuner near-miss VERIFIED; W4.3 exposes one generic refresh specification and gives WebDAV/S3 the same timer worker and last-known-good semantics as stream. | S–M |
| W5 | Checker hardening | ✅ **DONE 2026-08-10 (session 2)** — R5 (bare⇒common-owner, HTTP plane, feature-family/toggle aware) + R6 (normalized-stem near-miss; found `brix_s3_secret_key`≈`brix_webdav_secretkey` on its own — allowlisted as distinct mechanisms) + fixtures (10/10) + CI lane flipped to `--fail` (R1/R2/R4/R5/R6 gate; R3 WARN until W6). Real tree passes `--fail`. | S |
| W6 | R3 closure via docs-from-source (phase-101 W9.4, no longer optional at 322 findings) | ✅ **DONE 2026-09-03** — the source registry generates and checks the committed directive tables; R3 is armed in fail mode and the real tree has zero gating findings. | M |
| W7 | Field-home convergence: stream token/x509/TPC/acc flat fields → preamble; gridftp embeds preamble; delete the W3 adopt shims | ✅ **DONE 2026-09-03** — all fields have one shared home, GridFTP embeds the preamble, the adopt shims are gone, and the full self-contained GSI plus isolated authdb acceptance lanes pass. | L |
| W8 | Small leftovers | ✅ **DONE 2026-08-10** — skew sec_slot + shared clamp; wt-stage renamed; typedef landed; flag-setter audit CLOSED (session 2): `brix_conf_set_wt_enable` → stock flag_slot (was a pure hand-parse); cms/ftp enable wrappers KEEP (they delegate to the stock slot, then arm handlers — HELPERS-conformant). | S |
| W9 | Cache-grammar convergence | ✅ **DONE 2026-09-03** — `brix_cache_store` is the one runtime entry; HTTP `brix_cache_root` validates under its public name and lowers to `posix:<canonical-root>` before tier registration. Ambiguous dual configuration is rejected. State and write-staging roles remain distinct. | M |

Standing rules — identical to phase 101, restated because they bind every
workstream here: no git write commands without explicit OP approval
in-conversation; 3 tests per change-class (success + error + security-neg);
no `goto`; HELPERS over reimplementation; CCN ≤15 / 600-line ratchets live
(extract helpers rather than grandfather); new `src/` TUs → repo-root
`./config` + `bash -n config` (`check_config_coverage.py` enforces); **hard
rename means NO alias code and NO "renamed to X" hint strings anywhere** —
stock `unknown directive` is the correct failure mode; every rename lands
its row in `docs/03-configuration/migration-unified-grammar.md` in the SAME
commit.

**ABI trap** (memory: `struct_field_abi_clean_rebuild`): W1, W2, W4 and W7
grow the shared preamble or shrink protocol confs — treat EVERY commit in
those workstreams as an ABI-dirty rebuild (delete the affected module `.o`
files before rebuild; stale objects with skewed offsets have previously
produced phantom auth failures).

**The W5-precedent trap (binding on W1/W2/W4).** Phase-101 W5 established:
do NOT register a security-relevant bare name at `BRIX_HTTP_ALL_CONF` while
only one protocol enforces it — that manufactures an accepted-but-inert
authz/limit config (the admin believes it is enforced; it is not). The
lawful orders are (i) extend enforcement first, then widen registration
(the W5.2 s3-native-authz shape), or (ii) keep the registration
protocol-scoped and document the scoping (the pre-W5.2 `brix_authdb`
shape). Every "move to http_common" step below states which order it takes.

---

## Census (2026-08-10) — the measured baseline

`tools/ci/check_directive_registry.py` (WARN mode): **642 registrations,
531 unique names**, 11 allowlisted (all R4 read-only lookups). R1 = 0.
R2 = 0. **R3 = 322 undocumented names** (offender count at checker landing:
17 — documentation lost the race by 305 names in one development wave).
**R4 = 4 un-allowlisted findings** — all four are the phase-101 W3 adopt
helpers themselves (`src/core/config/stream_common.c` ×3,
`src/protocols/gridftp/ftp_module_merge.c` ×1), i.e. the sanctioned
adopt-at-merge pattern flagged by its own guard.

Strict command-entry census (Appendix C regex — brace + context flags, NOT
bare `ngx_string(` matching; see the trap note): the HTTP plane has **33
bare names registered outside `http_common`**. Eight are legitimate
single-feature toggles owned by their feature module (`brix_webdav`,
`brix_s3`, `brix_cvmfs`, `brix_scvmfs`, `brix_dashboard`, `brix_guard`,
`brix_health`, `brix_srr`). The remaining **25 are all owned by the webdav
module** and (except `brix_kv_zone`, which fills a global registry) write
`ngx_http_brix_webdav_loc_conf_t`:

| Group | Names (registration cite) |
|---|---|
| zones/limits (W1) | `brix_kv_zone`, `brix_token_cache`, `brix_rate_limit` (`webdav/directives_zones.h:9-30`); `brix_rate_limit_zone` :147, `brix_rate_limit_rule` :154, `brix_bandwidth_limit` :161, `brix_concurrency_limit` :168 (`webdav/directives_net.h`) |
| mirror (W2) | `brix_mirror_url` :88, `_methods` :95, `_sample` :102, `_strip_auth` :109, `_writes` :119, `_log_diverge` :126, `_timeout` :133, `_token` :140 (`webdav/directives_net.h`) |
| x509/CA + TLS (W2) | `brix_trusted_ca` :79, `brix_trusted_ca_dir` :72, `brix_client_ca_store` :126, `brix_client_certificate_folder` :137, `brix_backend_ca_dir` :148, `brix_tcp_congestion` :63 (`webdav/module_commands.c`) |
| auth/misc (W2) | `brix_http_query_token` (`module_commands.c:242`), `brix_http_secretkey` (`directives_net.h:81`), `brix_delegation_endpoint` (`module_commands.c:180`), `brix_credential` block (`webdav/directives_storage.h:14-17`) |

Cross-plane parity (command-entry census): **92 names registered
identically on both planes** — the phase-101 win, preserved. The drift this
wave targets is the set of concepts spelled DIFFERENTLY per plane —
invisible to R2 by construction (R2 fires only when `brix_<proto>_X` and
bare `brix_X` BOTH exist somewhere) — enumerated exhaustively in W3.

Custom setters: **138 entries via 106 functions** (101 baseline: 149/114 —
W2/W5/W7-of-101 deleted eleven). Three are flag-shaped (`*_set_enable`) —
W8 audits them against the HELPERS rule.

### Sharing-mechanism status (the 101 end-state, re-measured)

Mechanisms 3 (dual-conf-poking setters) and 4 (hand-copied parallel tables)
remain absent — confirmed by R1=0/R2=0 and the R4 scan (the 4 findings are
adopt-pattern, not poke-pattern; W5.1 formalizes that distinction). The
residue this phase attacks is not a fifth mechanism but an OWNERSHIP gap in
mechanism 1: bare names registered by a protocol module instead of the
plane's common owner, which mechanism 1's own first-module-wins rule then
turns into silent no-ops on sibling protocols.

---

## W1 — Rate-limit/zones family: fix the live silent no-op; extend enforcement

### Current state — the full evidence chain

1. **webdav registers the family bare.** Seven entries, two fragments, all
   webdav-owned:

   | Directive | Cite | Context / args | Setter | Target |
   |---|---|---|---|---|
   | `brix_kv_zone` | `directives_zones.h:9-14` | http-main, `zone=name:size key=N val=N` (101-W7 grammar) | `brix_kv_zone_directive` | global zone registry (offset 0) |
   | `brix_token_cache` | `:17-22` | loc, `zone=<name>` | `brix_token_cache_directive` | `offsetof(…webdav_loc_conf_t, token_cache_kv)` |
   | `brix_rate_limit` | `:25-30` | loc, `zone= rate=<N>r/s burst=<N> [key=dn\|ip]` | `brix_rate_limit_directive` | `offsetof(…, rate_limit)` |
   | `brix_rate_limit_zone` | `directives_net.h:147` | http-main, `zone=NAME:SIZE` | (zone decl) | shaping-zone registry |
   | `brix_rate_limit_rule` | `:154` | loc, request-rate rule | rule parser | `rl_rules` array |
   | `brix_bandwidth_limit` | `:161` | loc, bandwidth rule | rule parser | `rl_rules` array |
   | `brix_concurrency_limit` | `:168` | loc, per-principal in-flight cap | rule parser | `rl_rules` array |

2. **The engines are ALREADY shared, conf-agnostic TUs** — exactly the
   pmark situation from 101-W1 (conf-struct-coupled registration in front
   of conf-agnostic machinery):
   - `src/core/shm/rate_limit.c` — `brix_rate_limit_directive` (:316)
     resolves its target by RAW OFFSET ARITHMETIC:
     `(brix_rate_limit_conf_t *) ((char *) conf + cmd->offset)` — valid
     against ANY conf struct; the settings type is 4 fields
     (`rate_limit.h:19-24`: `kv` (NULL = disabled), `rate`, `burst`,
     `key_ip`); `brix_rate_limit_check()` (:47) is a pure token-bucket
     admission test taking `(conf substruct, identity)`.
   - `src/auth/token/token_cache.c` — `brix_token_cache_directive` (:78)
     same raw-offset resolution (:80); `brix_token_cache_lookup`/`_store`
     (:19/:45) key by SHA-256 fingerprint of the token — caller-agnostic.
   - `src/core/shm/kv_config.c` — `brix_kv_zone_directive` (`kv.h:104-108`)
     fills the global zone registry; no per-protocol conf at all.
   The three setters therefore move with ZERO changes, exactly as the four
   pmark custom setters did in 101-W1.

3. **Enforcement is webdav-only — two distinct loci, both verified:**
   - Token-bucket gate: `access_rate_limit` (`webdav/access.c:177-199`)
     reads `conf->rate_limit` off the WEBDAV loc-conf, fails open when
     `kv == NULL` (:193), calls `brix_rate_limit_check` (:199); invoked
     from the webdav access phase at `access.c:434`.
   - Shaping rules: `src/net/ratelimit/ratelimit_http.c` — a SHARED TU
     that nonetheless hard-fetches the WEBDAV conf:
     `ngx_http_get_module_loc_conf(r, ngx_http_brix_webdav_module)` at
     :212 and :263, then walks `lcf->rl_rules` (:213-233). **An engine
     living in `src/net/` does not make enforcement cross-protocol; the
     conf fetch does** — this is the trap recorded in Appendix C.3.
     (`ratelimit_stream.c:276-289` is the stream-plane parallel reading
     its own srv conf — plane-local, correct, untouched.)
   - `grep -rln 'rate_limit\|rl_rules\|bw_rule' src/protocols/s3
     src/protocols/cvmfs` → **zero matches.** No s3/cvmfs enforcement
     exists for ANY of the seven directives.

4. **first-module-wins consequence.** webdav precedes s3 and cvmfs in the
   `./config` HTTP emission order (`… common → webdav → … → s3 → cvmfs …`,
   101 §first-module-wins). `brix_rate_limit zone=rl rate=10r/s burst=20;`
   inside an s3 location — or at `server{}` scope covering s3 and cvmfs
   locations — parses cleanly into webdav's conf for those locations, and
   s3/cvmfs traffic is **not rate limited**. Same accepted-but-inert
   behavior for `brix_token_cache` and the shaping trio. No config-time
   diagnostic exists or is possible under this arrangement.

5. **The s3 cost is concrete.** `s3_verify_bearer`
   (`s3/auth_bearer.c:88`) fully re-validates the JWT on EVERY request
   (`va.keys = cf->jwks_keys` :126-127); webdav amortizes identical
   verifications through the token cache. An operator who sets
   `brix_token_cache zone=tc;` at `http{}` scope gets caching on webdav
   and silent full-price verification on s3.

6. The stream plane's own bare registrations of these names
   (`stream/directives_zones.h` — e.g. `brix_token_cache` :17 — and the
   stream shaping entries) are plane-local and correct — untouched, as the
   stream pmark table was in 101-W1.

### Why this fix shape (and what it costs)

The registration move is CHEAP (conf-agnostic setters, mechanism-1
machinery all in place: `brix_http_common_adopt` + one
`brix_shared_adopt_unified` extension). The enforcement extension is REAL
WORK but small per protocol: the gates are engine calls, not logic —
`brix_rate_limit_check(&conf->common.rate_limit, id)` from an access-phase
hook, and two 10-line cache consult/store calls around the existing s3
verify. Per the W5-precedent trap the two land in enforce-then-widen order
per name class:

- `key=ip` rate limiting and the token cache have NO identity dependency —
  enforcement extends mechanically; move + extend land together.
- `key=dn` keying needs each protocol's authenticated principal (s3: SigV4
  access key or bearer `sub`; cvmfs: no client identity today). The webdav
  DN-extraction is already principal-based, not DAV-specific; s3 reuses its
  resolved principal; cvmfs documents `key=dn` as config-rejected
  (EMERG at merge when a cvmfs-enabled location has `key_ip == 0`) rather
  than silently inert — the loud-failure convention.

### Steps

- [ ] 1. **Move commit (ABI-dirty).** Fields → `ngx_http_brix_shared_conf_t`:
  `brix_kv_t *token_cache_kv`, `brix_rate_limit_conf_t rate_limit`,
  `ngx_array_t *rl_rules` (from `webdav_loc_conf.h:182/:187/:206`).
  Registrations → `http_common.c` at `BRIX_HTTP_ALL_CONF` for the five
  loc-scoped names (scope upgrade from webdav's loc-only is deliberate —
  one site-wide `brix_rate_limit` is the "simple first" spelling, same
  argument as 101-W1 step 1); the two http-main zone declarations keep
  main-scope. Offsets rebase to
  `offsetof(ngx_http_brix_common_conf_t, common.<field>)` — the setters'
  raw-offset arithmetic needs nothing else. Extend
  `brix_shared_adopt_unified()`: `token_cache_kv`/`rl_rules` pointer-when-
  dst-NULL, `rate_limit` struct-when-dst-kv-NULL. Delete the seven webdav
  table entries. Rebase webdav readers (`access.c:193/:199/:434`,
  `config.c`, `config_merge.c`) to `common.*`.
- [ ] 2. **Shared-TU decouple commit.** `ratelimit_http.c:212/:263`: fetch
  the COMMON module's loc conf (`ngx_http_brix_common_module`) instead of
  webdav's; the ctx stash at :64 moves to a common-module ctx or a
  request-pool struct (verify which at commit — the ctx carries per-request
  shaping state, `wctx`). After this commit the shaping engine is
  genuinely protocol-neutral. Guard: this closes the Appendix-C.3 trap for
  this engine; W5's R5 fixture cites it.
- [ ] 3. **s3 gate commit.** s3 access path: `key=ip` bucket check BEFORE
  auth evaluation; `key=dn` check after principal resolution (mirror
  webdav's ordering exactly — the INVARIANT-3 analogue: reject cheap
  before evaluating credentials where possible, but a DN key needs the
  principal). Wire `s3_verify_bearer` to
  `brix_token_cache_lookup`/`_store` around the existing `va` validation
  (`auth_bearer.c:126-132`), TTL semantics identical to webdav's use.
- [ ] 4. **cvmfs commit.** `key=ip` gate in the cvmfs access path; the
  `key=dn` config-reject EMERG at merge; `directives.md` scoping note
  (same pattern as the 101-W5.2 cvmfs carve-out — the reasoning written
  down, not implied).
- [ ] 5. **Shaping-rule extension.** `brix_bandwidth_limit` /
  `brix_concurrency_limit` / `brix_rate_limit_rule` enforcement for s3
  rides the step-2 decouple automatically IF the rules engine hooks a
  shared phase (verify: `ratelimit_http.c` registration point — if it's a
  webdav-phase call, add the s3 call site; if it's an http-filter-level
  hook, step 2 already covered it). Write the finding into this section
  at commit time.
- [ ] 6. ABI-dirty clean rebuild (common + webdav + s3 + cvmfs objects);
  `objs/nginx -t` on a config exercising all seven directives at webdav-loc,
  s3-loc, and `http{}` scope; full build; `check_config_coverage.py`.

### Tests

- Success: `brix_rate_limit zone=rl rate=2r/s burst=2 key=ip;` at `http{}`
  scope → 429 after burst on a webdav location AND an s3 location (new
  `tests/test_rate_limit_s3.py`, reusing the phase-20 helpers);
  `brix_token_cache` — repeated identical bearer GETs on s3 show cache
  hits (assert via the kv metrics counter, INVARIANT-8-conformant);
  existing webdav rate-limit + token suites green UNMODIFIED (spellings
  don't change — only owner and reach).
- Error: `brix_rate_limit zone=rl;` (missing rate/burst) → the existing
  EMERG from `rate_limit.c` ("requires zone=<name> rate=<N>r/s
  burst=<N>") verbatim — pins that the setters moved unchanged; cvmfs +
  `key=dn` → the new merge-time EMERG.
- Security-neg: (a) rate limit configured ONLY in a webdav location does
  not leak enforcement into an adjacent s3 location (adopt-at-merge
  respects location scoping — the 101-W1 sibling pin, replayed); (b) a
  request rejected by `key=ip` rate limiting never reaches credential
  evaluation (ordering pin); (c) token-cache poisoning guard — a token
  REJECTED by verification is never served from cache on a later request
  (pins that only positive verdicts are stored, on both protocols).

### Acceptance

`grep -rn 'ngx_string("brix_rate_limit\|ngx_string("brix_kv_zone\|ngx_string("brix_token_cache\|ngx_string("brix_bandwidth_limit\|ngx_string("brix_concurrency_limit' src/protocols/`
→ stream-plane hits only; `ratelimit_http.c` contains no
`ngx_http_brix_webdav_module` reference; the three test classes green on
webdav+s3(+cvmfs ip-key); checker R5 (W5) reports zero webdav-owned bare
names in this family.

---

## W2 — The remaining 18 webdav-owned bare names: per-name disposition

Not one mechanism — three classes, and the classification IS the work.
Verified starting points below; each name gets a fresh reader-trace
immediately before its commit (Appendix C protocol — the inventory is the
seed, not the checklist).

### Class (i) — inert-on-siblings (the W1 shape): the mirror family (8 names)

**Evidence.** `brix_mirror_conf_t` (`src/net/mirror/mirror.h:143`; the
header's own HOW note at :18: "embedded in both the WebDAV location conf
and …") is embedded at `webdav_loc_conf.h:198` (`mirror`), with the shadow
upstream conf at :199 and the TLS ctx for https targets at :201. The
engine is the shared TU family `src/net/mirror/` (`http_mirror.h` for the
HTTP side; `stream_mirror*.c` for the stream side). webdav call sites:
`access.c:131-148` (`access_is_mirror_subrequest` — mirror subrequests
carry an `is_mirror` module ctx and skip re-authorization at :420-421),
`postconfig.c` (upstream/SSL setup), `config_proxy.c`. No s3/cvmfs file
references the mirror engine — s3 traffic cannot be mirrored though all
eight directives parse in an s3 location.

**Fix shape.** Move+extend, W1 order: registration + `mirror`,
`mirror_upstream_conf`, `mirror_ssl_ctx` fields → preamble/http_common;
adopt extension; webdav readers rebase. Extension: the mirror launch is a
subrequest fired from the access/precontent path — add the equivalent call
site in the s3 (and cvmfs) request path, plus the `is_mirror`
skip-reauthorization guard in their access phases. **Verify at commit**:
whether the launch point is a phase handler (needs per-protocol call
sites) or a filter-level hook (extension may be nearly free) — write the
finding into this section. `brix_mirror_methods` matches HTTP methods, not
DAV verbs — already protocol-neutral grammar.

### Class (ii) — effective-globally-already or engine-shared; ownership relocation only

| Name | Verified mechanism | Move |
|---|---|---|
| `brix_client_ca_store` | Loads a hashed client-CA dir into the SERVER `SSL_CTX` at postconfiguration (`webdav/postconfig.c:143-193`, per the 101-W6 reader table). The listener SSL_CTX is shared by every protocol on that server — behavior is ALREADY server-wide; only the registration owner and the postconfig hook's home move. | registration → http_common; postconfig hook relocates to the common module's postconfiguration (or is invoked from it); field → preamble |
| `brix_credential` (block) | `directives_storage.h:14-17` — `NGX_HTTP_MAIN_CONF\|NGX_CONF_BLOCK\|NGX_CONF_TAKE1`, setter `brix_conf_credential_block` — the SAME setter the stream plane registers on `stream_common` since 101-W3 (§14 named-credential registry, main-scope, global). It is the referent of `brix_storage_credential`, which already lives on http_common — the declaration belongs beside it. | registration → http_common; zero field/reader changes (global registry) |
| `brix_backend_ca_dir` | Back-leg CA dir for proxied/TPC connections (`module_directives_cert.c:329-437`; writes location-exact, never-merged `wlcf->proxy_ssl_capath` :341, :434). Meaningful wherever an HTTP protocol proxies; today only webdav does. No inert hazard (it *configures* an engine only webdav runs), but the bare name + webdav owner is exactly what R5 exists to flag. | registration → http_common; field → preamble; the never-merged location-exact semantics move with it (documented in the entry comment) |
| `brix_delegation_endpoint` | Gates the GSI-delegation well-known path (`dispatch.c:186`, `delegation.c:31`). HTTP-TPC delegation is a webdav-COPY mechanism today; cross-protocol only if another protocol grows TPC. | registration → http_common with the scoping documented (order-(ii) of the W5 precedent), OR ledger as webdav-scoped — fold into the W2 OP decision below |

### Class (iii) — auth-verify source and webdav-wire names; W5-precedent applies

| Name | Verified mechanism | Disposition |
|---|---|---|
| `brix_trusted_ca` / `brix_trusted_ca_dir` | `module_commands.c:79/:72` → `cafile`/`cadir` (`webdav_loc_conf.h:25-26`); readers `pki.c:21-25` (PKI validity source) + `auth_cert.c:400-410` (consistency check vs nginx ssl_* directives) — the GSI/VOMS verify source (101-W6 reader table). Only webdav does HTTP cert-auth today: widening to ALL_CONF without enforcement manufactures accepted-but-inert AUTH TRUST config. | The 101-W5 step-2 shape: field → preamble, registration → http_common but **webdav-scope-documented**; the day s3/cvmfs grow cert-auth they adopt for free. Security-neg pins the four-CA-mechanism distinction (101-W6) survives the move. |
| `brix_http_query_token` | `module_commands.c:242` → `http_query_token` flag (`webdav_loc_conf.h:133`, default ON — accepts `?authz=<token>`); readers `access_auth.c`, `auth_token.c`, `redirect.c` (the xrdhttp-compat query-string auth + the redirect-token flow). | OP-DECIDE (rename vs ledger). Recommendation: **rename** to `brix_webdav_query_token` — a bare `brix_http_*` name for a query-string AUTH ACCEPTANCE toggle actively invites the "applies to S3 too, right?" misread, and default-ON makes the misread dangerous. |
| `brix_http_secretkey` | `directives_net.h:81` → `http_secretkey` (`webdav_loc_conf.h:248`; signs/validates the redirect token per the field-block comment :236-248). | Same OP-DECIDE. Recommendation: **rename** `brix_webdav_secretkey` (it pairs with the redirect_* family, which is webdav-prefixed). |
| `brix_tcp_congestion` | `module_commands.c:63` → `tcp_congestion` (`webdav_loc_conf.h:223-224`, per-connection congestion-alg override). Reader NOT yet traced to its setsockopt site — **trace at commit** (candidate: connection-accept or upstream-connect path). | If the sockopt applies to the listener/connection (protocol-agnostic): class (ii) move. If applied only on webdav data paths: rename `brix_webdav_tcp_congestion`. Decided by the trace, not by taste. |
| `brix_client_certificate_folder` | 101-Appendix-B documented keep (acceptable-client-cert folder, distinct from all four CA-source knobs — phase-38). | Keep name; becomes an R5 ledger row (reason already written in 101). |

### Steps

- [ ] 1. Class-(ii) relocation commits first (cheap, zero behavior):
  credential block, client_ca_store (+postconfig hook home),
  backend_ca_dir, delegation_endpoint per OP decision. One commit, ABI-dirty
  (preamble grows `proxy_ssl_capath`).
- [ ] 2. Class-(i) mirror commit(s): move (ABI-dirty), then extend per the
  launch-point finding; s3 first, cvmfs after.
- [ ] 3. Class-(iii): trusted_ca pair field-move commit (with the four-CA
  security-neg suite); query_token/secretkey/tcp_congestion per OP
  decisions + trace results; migration rows for every rename; R5 ledger
  rows for every keep.
- [ ] 4. Post-sweep: strict census (Appendix C) → the webdav-owned bare
  count must be ZERO; anything remaining is either a new R5 allowlist row
  with a reason or an escaped move.

### Tests

- Success: mirror — one `http{}`-level `brix_mirror_url` mirrors webdav
  AND s3 traffic (extend the phase-24 suite; assert the shadow upstream
  receives both); class-(ii) — existing suites green unmodified (owner
  moves are invisible to behavior); renames — feature suites flipped.
- Error: each renamed name → stock `unknown directive` under the old
  spelling; `brix_mirror_url` with a garbage URL → existing parse EMERG
  verbatim.
- Security-neg: (a) `brix_mirror_strip_auth on` strips Authorization on
  the s3 mirror leg identically to webdav (the reason strip_auth exists
  must survive the extension); (b) mirror subrequests skip
  re-authorization on s3 exactly as on webdav (`is_mirror` guard) but a
  FORGED is_mirror ctx cannot be induced from the wire (existing pin,
  re-run); (c) trusted-CA move — a chain trusted ONLY by the front-leg
  store still fails the auth-layer verify (101-W6 four-mechanism pin).

### Acceptance

Strict census reports ZERO webdav-owned bare names: every bare HTTP name
is owned by http_common, a feature-module toggle (R5 allowlist class), or
an R5 ledger row with a reason. Mirror demonstrably active on s3 from one
`http{}` line.

---

## W3 — Cross-plane spelling drift: one concept, one spelling

R2 fires only when `brix_<proto>_X` and bare `brix_X` BOTH exist. These
five clusters are one concept spelled differently per plane — R2-invisible,
found by normalized-name diffing (the R6 seed):

### W3.1 `brix_webdav_maxdelay` → `brix_max_delay`

- HTTP: `directives_net.h:47-52`, sec_slot →
  `time_t maxdelay` (`webdav_loc_conf.h:85-86` — "§6.11 http.maxdelay
  analog: CAP on the Retry-After seconds a 202 staging (tape-recall)
  response tells the client"); merge `config_merge.c:109-110`
  (`ngx_conf_merge_sec_value(…, 0)` — 0 = off); reader `get.c:320-325`
  (tightens, never lengthens, the staging poll wait).
- Stream: `directives_cms.h:408-414`, sec_slot → `max_delay`
  ("ofs.maxdelay analog: clamp on the seconds any kXR_wait may tell a
  client to stall (default 60…; 0 disables)"). Reader: the kXR_wait
  emission path — trace at commit (the directive comment + default are
  the semantic anchor).
- Same upstream concept (xrootd's `maxdelay`), same unit, same
  clamp-the-advertised-wait role. **Different defaults (0=off vs 60) are
  plane-appropriate and KEEP** — the rename unifies the spelling, not the
  default; the migration row states both defaults explicitly.
- Change: HTTP side de-prefixes onto http_common + preamble
  (`common.max_delay`), rides a W2-batch ABI-dirty rebuild.

### W3.2 TPC outbound-token quartet

| HTTP (all `webdav/directives_tpc.h`) | Field (webdav conf) | Stream (all `stream/directives_tpc.h`) | Field (stream srv conf) |
|---|---|---|---|
| `brix_webdav_tpc_token_endpoint` :108 | `tpc_cred.token_endpoint` :112 | `brix_tpc_outbound_token_endpoint` :188 | `tpc_outbound_token_endpoint` :192 |
| `brix_webdav_tpc_token_client_id` :115 | `tpc_cred.token_client_id` :119 | `brix_tpc_outbound_client_id` :196 | `tpc_outbound_client_id` :200 |
| `brix_webdav_tpc_token_client_secret` :122 | `tpc_cred.token_client_secret` :126 | `brix_tpc_outbound_client_secret` :204 | `tpc_outbound_client_secret` :208 |
| `brix_webdav_tpc_token_scope` :129 | `tpc_cred.token_scope` :133 | `brix_tpc_outbound_scope` :212 | `tpc_outbound_scope` :216 |

Same concept per row: OAuth client-credentials acquisition for the
OUTBOUND TPC leg. Unified spelling: **`brix_tpc_outbound_*`** (stream is
the reference plane per the 101-W5 precedent, and "outbound" names the
role where "token" names a mechanism). This is a NAME-ONLY change on the
HTTP side — the `tpc_cred.*` field homes and their seven reader files
(`tpc_cred.c`, `tpc_cred_oidc.c`, `tpc_cred_parse.c`,
`tpc_cred_exchange.c`, `tpc_config.c`, `tpc_copy.c`, `tpc_push.c`) are
untouched. Stream-only members with no HTTP counterpart
(`_bearer_file` :168, `_passthrough` :180, `_tls` :106) stay stream-only —
candidates for HTTP adoption only if the curl TPC engine grows the
feature; note in `directives.md`, do not pre-register.

### W3.3 XrdAcc tuner prefixes (stream-internal rule-2 violation + cross-plane drift)

- Stream registers the XrdAcc family under TWO prefixes in ONE fragment:
  `brix_acc_{encoding,gidlifetime,gidretran,nisdomain,pgo,resolve_hosts,spacechar}`
  (bare parity with HTTP) BUT `brix_authdb_format` :143 → `acc.format`,
  `brix_authdb_audit` :150 → `acc.audit`, `brix_authdb_refresh` :157 →
  `acc.refresh` (all `stream/directives_auth.h`, with enum tables
  `brix_authdb_format_modes` / `brix_authdb_audit_modes`).
- HTTP (post-101-W5) spells the same three `brix_acc_format` /
  `brix_acc_audit` / `brix_acc_refresh` (`http_common.c`).
- The complication, verified: on stream, `acc.format` is not a tuner but
  the RUNTIME ENGINE SELECTOR — `brix_authz_check`
  (`auth/authz/auth_gate.c:220-225`) dispatches
  `conf->acc.format == BRIX_AUTHDB_FORMAT_XRDACC` → XrdAcc gate, else the
  native u/g/p engine. On HTTP the engine is selected by DIRECTIVE NAME
  (`brix_authdb` = native, `brix_acc_authdb` = XrdAcc — the 101-W5 design)
  and `brix_acc_format` is a value tuner.

**OP-DECIDE (W3.3):**

- (a) stream renames the selector to `brix_acc_format` too — one name,
  two meanings across planes (selector vs tuner). Rejected-by-default:
  recreates the exact confusion W5-of-101 killed.
- (b) rename only `_audit`/`_refresh` (mechanical); `brix_authdb_format`
  stays as the stream selector; R6 stem-map entry documents
  selector-vs-tuner. Cheapest; leaves the near-miss standing, documented.
- (c) the selector gets a role-true name — `brix_authdb_engine
  native|xrdacc` — and `brix_authdb_format` dies; `_audit`/`_refresh`
  rename to `brix_acc_*`. End state: `brix_authdb*` = native-rules entry +
  engine selection; `brix_acc_*` = XrdAcc everywhere; prefix = engine on
  BOTH planes with zero near-misses.

Recommendation: **(c)**. One extra hard rename over (b); the enum table
and setter are untouched (name-only); `test_authdb_engine_split.py`
extends to pin the stream selector under its new name, and the 101-W5
security-neg (`test_legacy_xrdacc_http_config_fails_loudly`) must stay
green untouched.

### W3.4 `brix_stream_mirror_url` → `brix_mirror_url`

`stream/directives_net.h:58` — the ONLY `stream_`-prefixed name in its own
otherwise-bare family (`brix_mirror_opcodes` :65,
`brix_mirror_exclude_opcodes` :72, `_sample` :79, `_strip_auth` :86,
`_writes` :96, `_log_diverge` :103, `_timeout` :110). Plane-local rename,
name-only (the stream mirror engine `src/net/mirror/stream_mirror*.c` is
untouched). Note `_opcodes`/`_exclude_opcodes` (stream, wire opcodes) vs
`_methods` (HTTP, methods) are plane-appropriate parameters of the same
family — same name would be WRONG; they stay.

### W3.5 verify-depth pair — semantics RESOLVED: unify

- HTTP: `brix_webdav_verify_depth` (`module_commands.c:101-105`) →
  `verify_depth` (`webdav_loc_conf.h:28` — "max proxy chain depth for
  VOMS proxies"); readers `access.c:534`
  (`brix_vfs_deleg_set_ca_store(vctx, conf->ca_store, conf->verify_depth)`
  — the delegated-credential verify), `delegation.c:235` (proxy-delegation
  verify, RFC-3820 accepted), `auth_cert.c:36` (depth recorded in the
  verify result).
- Stream: `brix_gsi_verify_depth` (`stream/directives_auth.h:55-57` —
  "§5.10 xrd.tlsca verdepth analog: cap the accepted X.509 chain depth
  for a client's GSI proxy/cert at root:// login; 0 = unlimited");
  reader `auth/gsi/auth_cert.c:161-162`.
- **Verdict: same role on both planes** — the cap on the accepted CLIENT
  proxy-chain depth in the plane's GSI/VOMS auth path (webdav's
  additionally bounds the delegation re-verify — same trust decision,
  same knob). Unify as bare **`brix_verify_depth`** on both planes; the
  HTTP field moves to the preamble in the W2 class-(iii) x509 commit (one
  ABI-dirty rebuild, not two). Confirm the 0-default equivalence at
  commit (stream 0 = unlimited; webdav default UNSET→? — read
  `config_merge.c` for the merge default and state it in the migration
  row).

### Steps

- [ ] 1. One commit per cluster, 101-W6 discipline: rename + migration
  row + suite spelling flip + stock-unknown-directive error pin. Clusters
  1 and 5 ride W2 commits that already relocate their fields.
- [ ] 2. W3.3 waits for its OP decision; land (c) as: stream table edit
  (3 renames, enum tables untouched) + config sweep + docs
  (`authorization-xrdacc.md` engine-selection section).
- [ ] 3. Seed the R6 stem map (W5) from this section's table — every
  cluster resolved here becomes an R6 test fixture (must NOT fire after
  the renames), every deliberate residual (`_opcodes` vs `_methods`,
  stream-only outbound members) becomes an allowlist row.

### Tests

Per cluster — success: existing behavior suite under the unified name
(tape-staging Retry-After for .1; TPC pull acquiring an outbound token for
.2 — the webdav TPC suite consumers; XrdAcc audit modes + refresh interval
behavior for .3; stream mirror suite for .4; VOMS-proxy depth acceptance
boundary for .5). Error: retired spelling → stock `unknown directive`.
Security-neg: .2 — `client_secret` never appears in logs/error output
after the rename (existing pin re-run); .3(c) — a pre-W5 XrdAcc HTTP
recipe still fails `nginx -t` loudly, and a stream config selecting
`brix_authdb_engine xrdacc` with a native-rules file behaves exactly as
`brix_authdb_format xrdacc` did (engine dispatch pinned by
authorized+denied integration pairs); .5 — a chain ONE hop deeper than the
cap is refused on BOTH planes.

### Acceptance

The five clusters each have ONE spelling; R6 green with the seeded map;
`grep -rn 'ngx_string("brix_webdav_tpc_token_\|ngx_string("brix_authdb_format\|ngx_string("brix_authdb_audit\|ngx_string("brix_authdb_refresh\|ngx_string("brix_stream_mirror_url\|ngx_string("brix_webdav_maxdelay\|ngx_string("brix_webdav_verify_depth' src/`
returns nothing.

---

## W4 — Close Table 1: escaped renames, the TPC-tuner ledger, and jwks parity

Phase-101 W4's own step-2 rule: "any surviving `brix_webdav_*`/`brix_s3_*`
name not in the Appendix B ledger is an escaped rename — fix before
closing." The current survivor sweep against the 101 ledger finds three
groups it never reconciled:

### W4.1 Token-introspect quad (escaped Table-1 rows)

`brix_webdav_token_introspect_{url,loc,ttl,fail_open}`
(`directives_zones.h:35-60`) → `introspect_url`/`_loc`/`_ttl`/`_fail_open`
(`webdav_loc_conf.h:191-194`). Readers: `webdav/introspect.c` (the
dedicated introspection TU — subrequest to the operator-defined internal
`introspect_loc` which proxy_passes to the IdP), `postconfig.c`,
`config.c`/`config_merge.c`. 101 Table 1 planned bare
`brix_token_introspect_*` (W4-token wave, noted "no bare twin yet") — the
family simply never landed.

Disposition: **land the de-prefix** (registration → http_common, fields →
preamble, adopt extension). Enforcement note per the W5-precedent: the
introspection check is consulted by the webdav token-verify path; s3's
verifier does not consult it today, so EITHER (a) s3's bearer path gains
the same revocation consult in this commit (it shares the verdict
machinery — small), or (b) `directives.md` states webdav-only scope
explicitly. Decide (a)/(b) inside the commit on the evidence of s3's
verify structure (`auth_bearer.c:88-132`); (a) is preferred — revocation
is exactly the check an operator assumes is global. `_ttl` converts
num→sec_slot in the same commit (101-W7 discipline).

### W4.2 Macaroon endpoint pair (escaped Table-1 rows) — OP-DECIDE

`brix_webdav_macaroon_max_validity` (`module_commands.c:249`) and
`brix_webdav_macaroon_location` (:256) → `macaroon_max_validity` /
`macaroon_location` (`webdav_loc_conf.h:134-135`). Reader:
`macaroon_endpoint.c:233-256` (the `location:` caveat source, with the
conf value preferred over the request path) — plus the 101-flagged
cross-family coupling: the macaroon endpoint falls back to the SHARED
`token_issuer` (101 W4 inventory, `macaroon_endpoint.c:245-247` at the
time) — any change here re-verifies that fallback still reads the
preamble field.

- (a) finish Table 1: de-prefix both; document that the minting endpoint
  itself exists only on webdav (the secrets are already bare/shared:
  `brix_macaroon_secret*` at `http_common.c:465-469` + stream
  `directives_auth.h:335-342`).
- (b) ledger both with the reason "macaroon MINTING-endpoint params — the
  endpoint is a DAV POST; trust material is already bare" and correct
  Table 1 with an annotation row.

Recommendation: **(b)** — it mirrors the `brix_webdav_auth` /
`brix_s3_token` selector precedent (how a protocol EXPOSES a feature is
per-protocol; what the shared trust config IS, is not), and an
honest Table-1 correction beats a rename whose only consumer is one
protocol's endpoint.

### W4.3 `brix_token_jwks_refresh_interval` HTTP parity

Stream-only today: `directives_auth.h:229` → srv-conf
`token_jwks_refresh_interval` (msec). The refresh machinery is a SHARED TU
already: `src/auth/token/refresh.c` — `brix_token_jwks_schedule_refresh`
(:111) arms a cycle-pool timer; `brix_token_jwks_refresh_handler` (:82)
re-fetches and re-arms (:91). BUT it is typed to
`ngx_stream_brix_srv_conf_t` (:112), and the HTTP plane loads JWKS ONCE at
config time with no refresh path (`s3/auth_bearer.c:11` — "keys are loaded
once at config time into cf->jwks_keys"; webdav equivalent). Parity =
(1) register the bare name on http_common (msec slot, preamble field);
(2) parameterize `refresh.c`'s conf coupling (conf-agnostic key-store swap
— the same raw-offset/callback shape the other shared engines use) or add
a thin HTTP twin invoking the shared fetch; (3) call the schedule from the
HTTP init-worker path. Size S–M. Security-neg: a key REMOVED from the JWKS
at the IdP stops validating within one interval on BOTH planes (the reason
the directive exists).

### W4.4 The `brix_webdav_tpc_*` tuner family — ledger reconciliation (13 names)

Survivors: `brix_webdav_tpc` (toggle), `_cadir`, `_cafile`, `_cert`,
`_key`, `_credential_forward`, `_curl`, `_low_speed_bytes`,
`_low_speed_secs`, `_marker_interval`, `_max_streams`, `_timeout`, `_xfr`.
None are in the 101 Appendix-B ledger; none were in the 101 step-2
expected-survivor list — they are unreconciled, though NOT accidental:
INVARIANT 11 (native TPC = SHM registry; WebDAV TPC = curl COPY) makes the
tuners per-ENGINE knobs (`tpc_cafile`/`tpc_cadir` — the curl-leg CA
source, `webdav_loc_conf.h:69-70`, read at `tpc_curl_setup.c:190-195`;
low-speed/timeout/streams — curl transfer knobs). Disposition: **ledger
all 13** with the engine reason (rows in Appendix B below), plus R6
stem-map entries for the near-misses that must NOT unify:
`brix_webdav_tpc_timeout` (curl leg op timeout) vs stream
`brix_tpc_max_transfer_secs` / `brix_tpc_transfer_max_age` (registry entry
lifetimes) — verify the distinction once at commit and write it into the
ledger reason.

### Tests

- Success: introspect quad — the introspection flow green under bare
  spellings (`introspect.c` suite / phase-21 tests flipped); s3 revocation
  consult if (a); jwks refresh — key rotation picked up on HTTP within the
  interval (new test, UDP-sink-style IdP stub).
- Error: retired prefixed introspect names → stock `unknown directive`;
  `brix_token_jwks_refresh_interval 0` = disabled (documented), garbage →
  stock msec parse error.
- Security-neg: a REVOKED token (introspection says inactive) is rejected
  on webdav — and on s3 if (a) — under the bare config;
  `_fail_open off` (default) fails CLOSED when the introspection
  subrequest errors (existing pin, spelling flipped); macaroon
  issuer-fallback still mints valid location caveats after whatever W4.2
  decides (the 101 cross-family coupling pin).

### Acceptance

Step-2-of-101 sweep (`grep -rn 'ngx_string("brix_webdav_\|ngx_string("brix_s3_' src/`)
returns ONLY names present in the (updated) Appendix-B ledger; Table 1
carries correction annotations for every (b) decision; jwks refresh
registered and live on both planes.

---

## W5 — Checker hardening: make W1–W3 recurrence structurally impossible

The checker's current shape (verified): rule pipeline in `main()` —
R1 same-plane dup at :173-179 (incl. the `R1?` unknown-plane variant),
R2 prefixed-twin :183-191, R3 undocumented :193-196, R4 conf-poke
:198-210 — fed by `collect()` (:107, fragment- and macro-aware per the
101 62%-undercount lesson), `_plane()` (:73), `_macro_bodies()` (:88),
`_load_allowlist()` (:133), `_documented()` (:152). R5/R6 slot in after
:210 reusing `collect()`'s per-registration file provenance.

- [ ] 1. **R4 hygiene commit.** Four allowlist lines with reasons for the
  W3-of-101 adopt helpers (`stream_common.c` ×3 — `brix_stream_common_adopt`
  / `_gsi` / `_vo_rules` merge-time reads; `ftp_module_merge.c` ×1 —
  gridftp adopt), reason text: "sanctioned adopt-at-merge read of own-plane
  parse-time values (101-W3); NOT the dual-poke pattern (reads, never
  writes a foreign conf)". Keeps the tamper pin (a reasonless line already
  fails).
- [ ] 2. **R5 — bare ⇒ common owner.** For every bare name (no protocol
  prefix per the R2 prefix list), the registering file must be the plane's
  common owner (`core/config/http_common.c`, `core/config/stream_common.c`,
  `core/config/tier_directives.h` instantiation sites) OR carry an R5
  allowlist row. Allowlist classes seeded in Appendix B: the 8 feature
  toggles; main-conf SHM zone-size declarations owned by their engine TU;
  every W2-(iii) keep. Fixture: a copy of the pre-W1 `brix_rate_limit`
  registration must fail citing R5 (the rule's reason-to-exist, pinned).
- [ ] 3. **R6 — near-miss spellings.** Normalize each name (strip `_`,
  strip plane tokens `stream_`/`gsi_`, strip protocol prefixes) and flag
  cross-plane pairs whose normalized stems collide, plus an explicit stem
  map for non-mechanical pairs (seeded from W3:
  `maxdelay≡max_delay`, `tpc_token_*≡tpc_outbound_*`,
  `authdb_{audit,refresh}≡acc_{audit,refresh}`). Allowlist-with-reason for
  deliberate residuals (`mirror_methods` vs `mirror_opcodes`;
  `acc_format` (HTTP tuner) vs `authdb_engine` (stream selector) post-W3.3;
  `webdav_tpc_timeout` vs `tpc_max_transfer_secs` per W4.4). Ships with
  false-positive fixtures; WARN-soak before FAIL.
- [ ] 4. **FAIL flip.** R1/R2/R4/R5/R6 gate as soon as steps 1-3 land and
  W1 clears R5's biggest block; R3 stays WARN until W6 lands, then gates.
  Checker self-tests per new rule: success (tree passes), error (fixture
  fails citing the rule id), tamper (allowlist line without reason fails).

### Acceptance

Checker FAIL-mode in CI on R1/R2/R4/R5/R6 (R3 after W6); fixtures green;
every allowlist line carries a reason; the W1 fixture proves R5 catches
the exact bug class this phase fixed.

---

## W6 — R3 closure: docs-from-source (101-W9.4, promoted from stretch to required)

R3 went 17 → 322 in one development wave: hand-maintained reference tables
lose the race, permanently, and 322 findings cannot gate. `collect()`
already extracts name/context/arg-shape per registration — including
fragment headers and X-macro expansions (the tooling that undercounts by
62% without them). Design:

- Generator emits the `directives.md` reference TABLES (name, context,
  args, default, owning module) from `collect()` output, per section;
  DEFAULTS and PROSE stay hand-written in per-name stub blocks keyed by
  directive name.
- A registered name with no prose stub is a GENERATOR ERROR — new
  directives fail CI until someone writes the two sentences (this is the
  R3 failure mode, moved to the only place it can't drift).
- A CMake `docs-directives` target regenerates; a guard in the CI lane
  diffs committed tables vs regenerated (the `check_config_coverage.py`
  pattern: drift fails loudly).
- OP-DECIDE carried from 101-W9.4: adopt per-section after reviewing
  generator output on the real tree — start with the sections covering
  the 322-name gap (stream cache/FRM/idmap families dominate the list),
  keep hand-written sections where the prose quality argument wins.

Acceptance: R3 = 0 in FAIL mode; the 322 names documented (generated
table + stub each); regeneration idempotent on a clean tree.

---

## W7 — Field-home convergence: retire the deliberate deferrals

Phase-101 chose low-risk shapes to reach R2=0 without moving
security-critical wiring. Those shapes are debt, and their stated gate —
"a runnable root://+gridftp+GSI fleet" — is now OPEN (101-W3 stage 3 ran
the full 173-test gridftp suite incl. GSI handshake, `gsi_evil`,
VO-ACL-over-GSI, plus root:// GSI, all green).

### Current dual homes — the verified inventory

1. **stream_common's own-copy GSI shim** (`stream_common.h:10-22`,
   verified): `ngx_stream_brix_common_conf_t` = `{ common preamble;
   certificate; certificate_key; trusted_ca; vomsdir; voms_cert_dir;
   vo_rules }` — the five GSI-trust strings and the VO-ACL rules live in
   stream_common's OWN conf and are copied into root's `xcf->certificate…`
   and gridftp's flat fields by `brix_stream_common_adopt_gsi()` /
   `brix_stream_common_adopt_vo_rules()` at merge. Two extra field homes
   plus a hand-maintained copy list per field.
2. **gridftp flat conf** (`ftp_gateway.h:28-44`, verified):
   `ngx_stream_brix_ftp_srv_conf_t` carries flat `enable`, `export`,
   `allow_write`, `storage_backend`, `storage_credential`, `verify_write`,
   `root_canon[PATH_MAX]` — NOT the preamble; values arrive by
   adopt-into-flat. (The header comments still name the RETIRED
   `brix_gridftp_*` spellings — fix rides commit (a).)
3. **stream token/TPC flat fields**: `token_jwks` →
   `offsetof(ngx_stream_brix_srv_conf_t, token_jwks)`
   (`directives_auth.h:225`) and siblings; the `tpc_outbound_*` flat
   fields (`directives_tpc.h:106-216`). The 101-W4 macro parameterization
   exists precisely because these did not move.
4. **stream plane-local `acc`**: `offsetof(ngx_stream_brix_srv_conf_t,
   acc.format)` (`directives_auth.h:147`) — while HTTP's `acc` lives IN
   the preamble since 101-W2. The same `brix_acc_http_t` in two homes
   across planes; `brix_authz_check` (`auth_gate.c:222`) reads the
   stream-local one.

### End-state

The preamble (aliased `brix_shared_conf_t`, W8) is the single field home
on both planes; root/gridftp/stream_common read `common.*`; the GSI
postconfig rebases onto preamble paths; `brix_stream_common_adopt_gsi` and
`_adopt_vo_rules` DELETE (`brix_shared_adopt_unified` covers everything);
the VO-rules deep-copy collapses to the shared-array + finalize-copy
pattern 101-W5.2 established on HTTP (each enforcing plane deep-copies and
finalizes against its OWN root — that invariant survives the move).

### Steps — three commits, each gated on the GSI suites

- [x] (a) **gridftp embeds the preamble**: add `common` to the ftp srv
  conf + `ngx_http_brix_shared_init` in create; rebase every reader
  (`grep -rn '\->export\|\->allow_write\|\->storage_\|\->verify_write'
  src/protocols/gridftp` — the 101-W3 enumeration, re-run); its adopt
  collapses to `brix_stream_common_adopt()` alone; `root_canon` stays
  (per-plane derived value, the 101 finalize-copy rule). Fix the stale
  header comments. ABI-dirty.
- [x] (b) **root x509 → preamble**: `certificate`/`_key`/`trusted_ca`/
  `vomsdir`/`voms_cert_dir` move from `xcf` (and from stream_common's own
  conf) into the preamble; the GSI postconfig that builds
  `gsi_cert`/`gsi_key`/the X509_STORE rebases to `common.*` paths — the
  SECURITY-CRITICAL step 101 deliberately avoided; delete
  `brix_stream_common_adopt_gsi`. The only accepted proof is the GSI
  handshake: full gridftp 173 + root:// GSI + `test_authdb.py` 9/9 (the
  adopted-cert handshake pin) per commit — no config-parse-only
  verification (101-W3 blocker-2 rule, still binding).
- [x] (c) **stream token/TPC/acc + vo_rules → preamble**: flat fields
  relocate; the 101-W4 dual-macro variants collapse to one signature
  where offsets now agree; `_adopt_vo_rules` deletes into the shared
  pattern; `auth_gate.c` reads `common.acc.*`. ABI-dirty; token +
  TPC + authdb suites are the pins.

OP-DECIDE: sequencing only — W7 can run parallel to W1–W6 (different
files) but MUST NOT share a commit window with W3 renames touching
`directives_auth.h`/`directives_tpc.h` (merge-conflict-prone fragments;
coordinate the order OP-side).

### Tests

Success: full gridftp + root:// + token + acc/authdb suites green after
each commit (they exercise every moved field end-to-end). Error: none new
(no grammar changes). Security-neg: the 101-W3 pins re-run per commit —
GSI handshake on adopted cert+trust store; `gsi_evil` refused;
VO-ACL-over-GSI denies without the required VO; `brix_allow_write off`
refuses STOR before credential evaluation through the new field homes.

### Acceptance

`stream_common.h`'s conf is `{ common }` alone;
`grep -rn 'brix_stream_common_adopt_gsi\|brix_stream_common_adopt_vo_rules' src/`
returns nothing; gridftp conf embeds the preamble; one `acc` home per
binary; all suites green.

Acceptance recorded 2026-09-03: an ABI-clean configured `-Werror` build
completed; `tests/test_gsi_handshake.py` plus its WebDAV/root continuation
passed 77/77; the complete GridFTP family passed 123 tests with 41
dependency skips; and `tests/test_authdb.py` passed 9/9 against a separately
provisioned `TEST_ROOT=/tmp/phase111-authdb`, `TEST_PORT_START=32000` lane.
The consolidation exposed an absolute-vs-export-relative checksum open; the
shared POSIX VFS seam now normalizes the name before the rootfd driver/openat2
call, its regression contract is pinned in
`test_vfs_consolidation_parity.py`, and the three live Qcksum policies pass.

---

## W8 — Small leftovers (one commit each)

| Item | Current (verified) | Change |
|---|---|---|
| `brix_token_clock_skew` | num_slot; the `[0,300]` clamp is a merge-time EMERG at `webdav/config_merge.c:158-160` ("must be >= 0 and <= 300") on the post-101-W4 `common.token_clock_skew` field — the deliberate 101-W7 holdout | sec_slot + the clamp EMERG reworded to name the unit trap explicitly ("clock skew is capped at 300s (security clamp); got 600 (from `10m`)"). Keeps the footgun protection, gains suffix syntax, resolves the held OP question via the loud-failure convention. Verify at commit whether s3's merge needs the same clamp (the field is shared; ONE clamp in the shared merge is the right home — move it there). Security-neg: `brix_token_clock_skew 10m` is REJECTED at `nginx -t` — never silently truncated or accepted. |
| wt-stage prefix split | one feature, two prefixes, ONE fragment: `brix_cache_wt_stage_root` :144, `_backend` :151, `_block_size` :158 vs `brix_wt_stage_high_watermark` :170, `_low_watermark` :177 (`stream/directives_cache.h`); the sibling family is `brix_wt_{mode,origin,credential,deny_prefix,allow_prefix}` (`directives_writethrough.h:29-62`) | ONE prefix: `brix_wt_stage_{root,backend,block_size}` (matches the `brix_wt_*` family). 3 hard renames, name-only, + migration rows + config sweep. |
| preamble type name | `ngx_http_brix_shared_conf_t` embedded by stream srv conf, stream_common, (post-W7a) gridftp — a plane-neutral type with an http_ name | `typedef ngx_http_brix_shared_conf_t brix_shared_conf_t;` in `shared_conf_types.h`; NEW code uses the alias; NO sweep of existing uses (a rename sweep is not this phase — same call 101 made). |
| flag-shaped custom setters | `brix_conf_set_wt_enable` (`fs/cache/directives_wt.c:28` — hand-parses on/off into the srv conf, verified), `brix_cms_srv_set_enable`, `brix_ftp_set_enable`; census 138 custom entries via 106 fns | Audit each against the HELPERS rule: if it ONLY parses a flag → `ngx_conf_set_flag_slot` (and sweep tests pinned on hand-rolled error text, the 101-W2 step-5 lesson); if it arms listeners/handlers or validates cross-field state, KEEP + a one-line comment saying why it cannot be a stock slot. |

---

## W9 — Cache-grammar convergence study (decision input, not execution)

Three-and-a-half config surfaces still describe "where cached bytes live":

1. `brix_cache_root` — HTTP legacy read-through root (101-W8 option B:
   kept, unified to one bare name, preamble-homed; builds
   `cache_storage_inst`, `cache_storage.c:197-244`).
2. `brix_cache_store` — the phase-64 composable tier (sd_cache decorator),
   both planes via the tier X-macro; `brix_cache_storage()` returns the
   decorator's store when set, else `cache_storage_inst` (the dual-path
   101-W8 documented).
3. `brix_cache_export` + the ~20-name stream `brix_cache_*` family
   (`stream/directives_cache.h`: high/low watermarks, eviction threshold,
   reap interval, max_bytes/max_file_size, cold/dirty max ages,
   allow/deny/include admission prefixes, `state_root`, origin_family,
   passthrough, global CAS, peers) — the fd-based stream cache — plus the
   wt-staging block (W8 renames it internally; W9 asks the bigger
   question).
4. (adjacent) `brix_cache_store_endpoint`, `brix_cache_peers`,
   `brix_cache_global_cas` — tier-adjacent knobs.

101-W8's behavior diff proved 1 ≠ 2 (distinct live mechanisms); it did NOT
ask whether the tier can GROW the missing semantics. This study answers
exactly that, with the cache integration suite as the harness:

- [ ] 1. Behavior matrix for all three mechanisms: read-fill,
  write-through, eviction/reaper enumeration, MOVE/DELETE interplay,
  INVARIANT-4 confinement, sidecar handling
  (`brix_cache_store_endpoint`), crash-recovery (`state_root`).
- [ ] 2. Gap list = tier features or documented losses (the 101-W8 bar:
  no silent behavior loss).
- [ ] 3. Operator-facing target grammar sketch: how many directives does
  each deployment archetype need today vs proposed (the "3-line config"
  standard from 101-W9.3 is the benchmark).
- [ ] 4. Sizing + risk for the execution phase; OP go/no-go ON the
  matrix, not before.

Deliverable: findings land IN THIS FILE as a dated subsection. Explicitly
out of scope: touching any cache directive in this phase.

---

## Sequencing, commit plan, and effort

```
W5.1 (R4 hygiene)                 1 commit   — first; unblocks the FAIL-mode ratchet
W1  (rate-limit family)           4–6 commits — move → decouple → s3 → cvmfs → shaping
 ├→ W2 (ownership sweep)          4–6 commits — class (ii) → (i) mirror → (iii) per-OP
 │    └→ W3 (drift renames)       5 commits  — clusters; .1/.5 ride W2 field moves
 │         └→ W4 (Table-1 close)  3 commits  — introspect(+s3), macaroon/ledger, jwks
 ├→ W5.2-4 (R5/R6/flip)           2 commits  — R5 lands AFTER W1 (else red on day 1)
 ├→ W6 (docs-from-source)         2 commits  — generator + adoption; R3 flip last
 └→ W7 (field homes)              3 commits  — parallel track; GSI suites per commit
W8  (leftovers)                   4 commits  — anytime after W5.1
W9  (cache study)                 0 commits  — findings land in this doc
```

### Commit-by-commit file map

| # | Commit | Files touched (primary) |
|--:|---|---|
| 1 | W5.1 R4 allowlist | `tools/ci/directive_registry_allowlist.txt` |
| 2 | W1 move | `shared_conf_types.h`, `http_common.c`, `webdav/directives_zones.h`, `webdav/directives_net.h`, `webdav_loc_conf.h`, `webdav/{access,config,config_merge}.c` |
| 3 | W1 decouple | `net/ratelimit/ratelimit_http.c` |
| 4 | W1 s3 | `s3/handler*.c` (gate call), `s3/auth_bearer.c` (cache), `tests/test_rate_limit_s3.py` |
| 5 | W1 cvmfs | cvmfs access path, merge EMERG, `directives.md` |
| 6 | W2 class-(ii) | `http_common.c`, `webdav/module_commands.c`, `webdav/directives_storage.h`, `shared_conf_types.h`, postconfig hook home |
| 7–8 | W2 mirror move+extend | `shared_conf_types.h`, `http_common.c`, `webdav/directives_net.h`, `net/mirror/*`, s3/cvmfs call sites, phase-24 suite |
| 9 | W2 class-(iii) x509 (+W3.5) | `http_common.c`, `module_commands.c`, `webdav_loc_conf.h`, `pki.c`, `auth_cert.c`, migration table |
| 10–13 | W3 clusters | per-cluster tables + configs + suites + migration rows |
| 14 | W4.1 introspect | `http_common.c`, `webdav/directives_zones.h`, `introspect.c`, s3 consult (if (a)), migration |
| 15 | W4.2/W4.4 ledger | Appendix-B rows, 101 Table-1 annotations, R6 map |
| 16 | W4.3 jwks parity | `auth/token/refresh.c`, `http_common.c`, init-worker wiring, new test |
| 17 | W5.2-4 R5/R6/flip | `tools/ci/check_directive_registry.py`, allowlist, fixtures |
| 18–19 | W6 generator | `tools/ci/` generator, `docs/03-configuration/directives.md`, make target, guard |
| 20–22 | W7 (a)(b)(c) | `ftp_gateway.h`+readers, `stream_common.{c,h}`, GSI postconfig, `directives_{auth,tpc}.h`, `auth_gate.c` |
| 23–26 | W8 items | per the W8 table |

Every commit: tree green (`objs/nginx -t` + `check_config_coverage.py` +
pytest `--pr` gate); migration rows + three tests ride the commit they
belong to; ABI-dirty rebuild where flagged; fleet restarts per rename
wave, not per commit. No commits without OP approval in-conversation.

### OP decisions required before the affected commit

| Gate | Decision | Recommendation |
|---|---|---|
| W2-(iii) | per-name: prefix-rename vs R5-ledger (`http_query_token`, `http_secretkey`, `tcp_congestion`, `delegation_endpoint`, `client_certificate_folder`) | rename the first two; `tcp_congestion` decided by its reader trace; ledger the folder; delegation_endpoint → http_common-with-scope-note |
| W3.3 | `authdb_format` selector naming (a/b/c) | c — `brix_authdb_engine`; retire `_format` on stream; HTTP `brix_acc_format` unchanged (it is the value tuner) |
| W4.1 | s3 introspection consult (a) vs scope-note (b) | a — revocation is the check operators assume is global |
| W4.2 | macaroon endpoint pair: de-prefix (a) vs ledger (b) | b — ledger + Table-1 correction row |
| W6 | docs-from-source adoption (carried from 101-W9.4) | adopt for reference tables, per-section, gap sections first |
| W7 | run parallel vs after W1–W6 | parallel; disjoint commit windows with W3 (shared fragments) |
| W9 | go/no-go on a cache-convergence execution phase | decide ON the study's matrix, not before |

### Risk register

| Risk | Mitigation |
|---|---|
| Widening a limit/auth name creates accepted-but-inert config (the W5 trap) | binding order rule stated per W1/W2/W4 step: enforce-then-widen, or scope-and-document; every family's security-neg pins that the inert case either enforces or fails loudly — never silently passes |
| Preamble growth / conf shrink skews offsets across modules | ABI-dirty clean rebuild EVERY W1/W2/W4/W7 commit (memory: phantom auth failures from stale `.o`) |
| A moved family misses a reader and silently reverts to defaults | the per-WS reader inventories above ARE the checklist; re-grep per family immediately before its commit (Appendix C protocol incl. derived fields); flipped behavior suites are the backstop |
| `ratelimit_http.c`-style hidden coupling survives a move (engine in `src/net/`, conf fetch still webdav) | Appendix C.3 records the trap; W1 step 2 closes the known instance; the R5 fixture + a grep for `ngx_http_brix_webdav_module` outside `protocols/webdav/` in the R4 scan catch recurrences |
| Mirror extension perturbs the s3 request lifecycle | mirror taps are observe-only subrequests; the strip_auth + forged-ctx security-negs and the full s3 suite gate the commit |
| W7(b) silently mis-binds cert/trust wiring | per-commit full gridftp+root GSI suites + `test_authdb.py` 9/9; config-parse-only verification is NOT accepted (101-W3 blocker-2 rule) |
| R6 heuristic false-positives erode trust in the checker | stem map + allowlist-with-reason; WARN soak before FAIL; fixtures for every deliberate residual |
| Docs generator degrades prose quality | per-section adoption; prose stubs mandatory (generator errors on missing); hand-written sections keep the option to stay |
| Token-cache on s3 caches a wrong verdict | store only positive verdicts, TTL-capped (existing webdav semantics); the cache-poisoning security-neg pins it on both protocols |
| Site configs break on hard renames | intended and loud (`unknown directive` at `nginx -t`); migration table is the operator path; no silent aliases |

### End-state acceptance for the phase

Strict census: zero webdav-owned bare HTTP names outside the R5 allowlist;
R1=R2=R4=R5=R6=0 in FAIL mode; R3=0 in FAIL mode via generated tables +
stubs; the five W3 clusters single-spelled; Table 1 closed or corrected
and the TPC-tuner family ledgered; `brix_rate_limit` /
`brix_token_cache` / `brix_mirror_*` demonstrably effective on s3 from one
`http{}`-level line (the wave's headline behavior win); jwks refresh live
on both planes; W7 adopt shims deleted with GSI suites green; W8 items
landed; W9 matrix written and decided.

---

## Appendix A — Rename tables (hard renames, no aliases)

### Table 1 — cross-plane drift (W3)

| Current | Unified name | Plane that changes |
|---|---|---|
| `brix_webdav_maxdelay` | `brix_max_delay` | HTTP (defaults stay per-plane: 0=off HTTP, 60 stream — stated in the migration row) |
| `brix_webdav_tpc_token_endpoint` | `brix_tpc_outbound_token_endpoint` | HTTP (name-only; `tpc_cred.*` fields keep) |
| `brix_webdav_tpc_token_client_id` | `brix_tpc_outbound_client_id` | HTTP |
| `brix_webdav_tpc_token_client_secret` | `brix_tpc_outbound_client_secret` | HTTP |
| `brix_webdav_tpc_token_scope` | `brix_tpc_outbound_scope` | HTTP |
| `brix_authdb_audit` | `brix_acc_audit` | stream |
| `brix_authdb_refresh` | `brix_acc_refresh` | stream |
| `brix_authdb_format` | `brix_authdb_engine` (per W3.3-c) | stream |
| `brix_stream_mirror_url` | `brix_mirror_url` | stream |
| `brix_webdav_verify_depth` + `brix_gsi_verify_depth` | `brix_verify_depth` (semantics verified — W3.5) | both |

### Table 2 — W2-(iii) prefix restorations (pending OP)

| Current | New |
|---|---|
| `brix_http_query_token` | `brix_webdav_query_token` |
| `brix_http_secretkey` | `brix_webdav_secretkey` |
| `brix_tcp_congestion` | `brix_webdav_tcp_congestion` (IF the reader trace shows webdav-path-only application; else class-(ii) move, no rename) |

### Table 3 — W4 + W8

| Current | New |
|---|---|
| `brix_webdav_token_introspect_url` | `brix_token_introspect_url` |
| `brix_webdav_token_introspect_loc` | `brix_token_introspect_loc` |
| `brix_webdav_token_introspect_ttl` | `brix_token_introspect_ttl` (+ sec_slot) |
| `brix_webdav_token_introspect_fail_open` | `brix_token_introspect_fail_open` |
| `brix_cache_wt_stage_root` | `brix_wt_stage_root` |
| `brix_cache_wt_stage_backend` | `brix_wt_stage_backend` |
| `brix_cache_wt_stage_block_size` | `brix_wt_stage_block_size` |

### Names that move OWNER without renaming (W1/W2 — no migration rows; changelog rows for new reach)

`brix_kv_zone`, `brix_token_cache`, `brix_rate_limit`,
`brix_rate_limit_zone`, `brix_rate_limit_rule`, `brix_bandwidth_limit`,
`brix_concurrency_limit`,
`brix_mirror_url/_methods/_sample/_strip_auth/_writes/_log_diverge/_timeout/_token`,
`brix_client_ca_store`, `brix_backend_ca_dir`, `brix_credential`,
`brix_delegation_endpoint`, `brix_trusted_ca`, `brix_trusted_ca_dir`,
(new registration, no old spelling: `brix_token_jwks_refresh_interval` on
HTTP).

## Appendix B — additions to the deliberately-NOT-unified ledger (R5/R6 allowlist seeds, one `# reason` each)

| Name(s) | Why it stays |
|---|---|
| `brix_webdav_macaroon_max_validity`, `brix_webdav_macaroon_location` (per W4.2-b) | Macaroon MINTING-endpoint params — the endpoint is a DAV POST; trust material (`brix_macaroon_secret*`) is already bare/shared. Mirrors the `brix_webdav_auth` selector precedent. 101 Table 1 carries the correction row. |
| `brix_webdav_tpc` toggle + `_cadir`, `_cafile`, `_cert`, `_key`, `_credential_forward`, `_curl`, `_low_speed_bytes`, `_low_speed_secs`, `_marker_interval`, `_max_streams`, `_timeout`, `_xfr` (13) | Per-ENGINE tuners: WebDAV TPC = curl COPY, native TPC = SHM registry (INVARIANT 11). `tpc_cafile`/`tpc_cadir` are the curl-leg CA source (`tpc_curl_setup.c:190-195`), distinct from `brix_backend_ca_dir` (proxy back leg) and from the auth-layer `brix_trusted_ca` — a FIFTH and SIXTH CA-mechanism row for the 101-W6 table. R6 map: `webdav_tpc_timeout` ≢ `tpc_max_transfer_secs`/`tpc_transfer_max_age` (curl op timeout vs registry lifetimes — verify once at W4.4 commit). |
| `brix_client_certificate_folder` | Re-affirmed from 101 Appendix B; now also an R5 ledger row (feature-scoped bare name, documented keep). |
| `brix_acc_format` (HTTP) vs `brix_authdb_engine` (stream) after W3.3-c | Value tuner vs engine selector — different mechanisms; R6 stem-map entry with this reason. |
| `brix_mirror_methods` (HTTP) vs `brix_mirror_opcodes`/`_exclude_opcodes` (stream) | Plane-appropriate parameters (HTTP methods vs wire opcodes) of one family — same name would be wrong. R6 allowlist. |
| feature toggles `brix_webdav`, `brix_s3`, `brix_cvmfs`, `brix_scvmfs`, `brix_dashboard`, `brix_guard`, `brix_health`, `brix_srr` | Single-feature enable toggles owned by their module — R5 allowlist class. |
| main-conf SHM zone-size declarations owned by feature TUs (`brix_negcache`, `brix_loc_cache`, `brix_redir_cache`, `brix_srv_registry`, `brix_pending_locate`, `brix_sessions`, `brix_session_handles`, `brix_tpc_keys`, `brix_tpc_transfers`, `brix_stage_waiters`) | Global singletons declared where their engine lives; no per-location conf, no adopt path, no inert-config hazard. R5 allowlist class, one reason line for the class. |
| `brix_webdav_open_file_cache*` | Carried from 101: becomes a bare-family candidate IF s3/cvmfs grow the same cache — noted in directives.md, not pre-renamed. |

## Appendix C — survey reproduction + the traps

### C.1 Strict ownership census

Anchors on the COMMAND ENTRY shape, not on `ngx_string(` occurrences
(run at repo root):

```python
import re, os
entry = re.compile(r'\{\s*ngx_string\("(brix_[a-z0-9_]+)"\)\s*,\s*'
                   r'((?:[^,{}]|\n)*?CONF(?:[^,{}]|\n)*?)\s*,', re.S)
owners = {}
for dp, _, fs in os.walk('src'):
    for f in fs:
        if not f.endswith(('.c', '.h')): continue
        p = os.path.join(dp, f)
        if 'stream' in p or 'gridftp' in p or 'net/cms' in p: continue  # http plane
        for m in entry.finditer(open(p, errors='replace').read()):
            owners.setdefault(m.group(1), set()).add(p)
# flag: bare name whose owner set excludes core/config/http_common.c
# and core/config/tier_directives.h instantiation sites
```

### C.2 The SHM-zone-name trap (hit during this survey)

A bare `ngx_string("brix_X")` scan also matches SHM zone NAMES —
`brix_protocol` and `brix_delegated_cred` (`webdav/module_init.c:263-264`)
and `brix_proxy_pool` (`webdav/proxy_pool.c:81`) are
`ngx_shared_memory_add` zone labels, not directives. Any tooling (R5
included) built on a loose scan reports phantom directives. Companion rule
to 101-Appendix-C's `*_canon` trap: a name's existence as a DIRECTIVE is
proven only by a command-table entry (context flags present), never by an
`ngx_string` literal.

### C.3 The shared-engine/coupled-conf trap (hit during this survey)

An enforcement engine living in a shared bucket (`src/net/…`) does NOT
prove cross-protocol enforcement: `net/ratelimit/ratelimit_http.c`
hard-fetches `ngx_http_get_module_loc_conf(r,
ngx_http_brix_webdav_module)` (:212, :263) — the engine is shared, the
CONFIG SOURCE is webdav-only, so enforcement is webdav-only. Liveness of a
directive on a protocol is proven at that protocol's request path
(directive → field → THIS protocol's reader), never at the engine's
bucket. Grep seed for recurrences:
`grep -rn 'ngx_http_brix_webdav_module' src/ --include='*.c' | grep -v protocols/webdav`.

### C.4 Baseline numbers (2026-08-10)

Checker: 642 registrations / 531 unique / R1=0 / R2=0 / R3=322 /
R4=4-unallowlisted / WARN mode. Strict census: 33 outside-common bare
HTTP names = 8 toggles + 25 webdav-owned. Cross-plane: 92 names spelled
identically on both planes. Custom setters: 138 entries via 106 functions
(101 baseline: 149/114). All numbers reproduce from C.1 plus the checker
run; re-run both before landing W5's FAIL flip and record the deltas here.

---

## Implementation log — 2026-08-10 (W5.1, W1, W3 clusters 1–4, W8)

All work verified on the static build (`/tmp/nginx-1.28.3`), ABI-dirty
rebuilds throughout (full `objs/addon` object wipe before the W1 preamble
growth). Final battery: **145 passed / 0 failed** (`test_rate_limit_s3` 4,
`test_phase20_kv_shm` + `test_phase25_ratelimit{,_b}` 33+1,
`test_phase24_mirror` 25, `test_authdb_engine_split` (updated) ,
`test_acc` / `test_acc_residual` / `test_acc_unification`,
`test_webdav_maxdelay`, `test_w7_sec_slots`, `test_token_unification`,
`test_tls_require`). Checker after: **643 registrations, 524 unique names**
(531 before this wave), R1=0, R2=0, R4=0-unallowlisted; R3 remains
WARN-scoped pending W6. `check_config_coverage` OK; doc guards OK.

### Findings written back (the doc's own verify-at-commit items)

1. **The shaping trio + mirror premise CORRECTION (W1.3/W2).**
   `brix_rl_http_access_handler` / `brix_rl_http_log_handler` / the mirror
   precontent handler are pushed onto nginx's GLOBAL phase arrays from
   webdav's postconfiguration (`postconfig.c:93-115`) — phase handlers run
   for EVERY http request, so the shaping trio and mirror already fired on
   s3/cvmfs locations, reading the webdav conf that first-module-wins had
   filled. The truly-inert directives were exactly `brix_rate_limit` and
   `brix_token_cache`: webdav's access handler DECLINES on
   `!conf->common.enable` (`access.c:416-418`) before `access_rate_limit`,
   and the token cache is consulted only from webdav's auth path. Both are
   now enforced per protocol (below). W2's mirror row should read
   "ownership + conf-source hygiene", not "inert-on-siblings".
2. **W1 enforcement landed.** s3: `s3_rate_limit()` (`s3/handler.c`,
   byte-parallel to webdav's `access_rate_limit`) gates before the auth
   burden, counted via `s3_metrics_return_method`; the bearer path consults
   and populates the shared token cache (`auth_bearer.c` —
   lookup re-checks `exp`, engine caps TTL at 5min, negative verdicts never
   stored). cvmfs: same IP gate at the handler head. HTTP keying is
   IP-only by construction (webdav's gate always keyed by
   `addr_text`; `key=dn` is stream semantics) — the doc's step-3/4
   dn-plumbing is therefore NOT NEEDED on HTTP; `directives.md` should say
   so (rides W6).
3. **Shaping-engine decouple (W1 step 2).** `ratelimit_http.c` reads rules
   from the COMMON module conf (`ccf->common.rl_rules`); the webdav conf
   fetch remains ONLY for the VOLUME-rule path root (`common.root_canon` is
   protocol-derived) and the identity ctx — both documented in-file as the
   residual to retire with the per-protocol identity work. The dead
   webdav-conf guard in the log handler was dropped.
4. **W3.3 enum-table dedup.** Unifying the tuner spellings collided the
   byte-identical `*_audit_modes` tables at link time (`-fno-common`).
   Resolution: ONE definition of `brix_acc_format_modes` /
   `brix_acc_audit_modes` in `auth/authz/acc/config.c`; stream's
   `module_enums.{c,h}` keep extern decls; `brix_authdb_engine` uses
   `brix_acc_format_modes` (same value set). HELPERS-rule win the rename
   forced into the open.
5. **W8 skew clamp gap confirmed and closed.** The `[0,300]` clamp lived in
   webdav's merge only — an s3-only config could set any skew. It now
   lives in `ngx_http_brix_shared_merge` (all HTTP protocols) and in the
   stream merge, rejecting loudly: `brix_token_clock_skew 10m` →
   "capped at 300s (security clamp against unit confusion); got 600".
   Verified by `nginx -t` on an s3-only config.
6. **Pre-existing test-helper breakage fixed in passing.** The stream
   mirror write tests failed at HEAD with `NameError: _kXR_open` /
   `_kXR_write` / `_OPEN_CREATE_WR` — wire constants lost in a helper
   split (the reexport chain never carried them; same staleness class the
   CMS-parity notes flagged). Constants restored per XProtocol.hh; all 25
   mirror tests green, now also exercising the renamed `brix_mirror_url`.
7. **Test-collateral updates.** `test_phase25_ratelimit.py`'s source-layout
   pin now asserts the common-module home AND that webdav does not
   re-register (first-module-wins shadow guard);
   `test_authdb_engine_split.py` pins the post-rename reality (retired
   spellings stock-unknown on both planes; `brix_authdb_engine`
   stream-only; unified `brix_acc_audit`/`_refresh` parse on HTTP); port
   ladder LIFECYCLE_SHARED 554→558 for the two new rate-limit subjects.

### Historical deferred list after implementation session 1

This list was accurate only before session 2. The later implementation log and
the top status supersede it; W2, W3.5, W4.1/W4.2/W4.4, W5.2–4, W8 and the W9
study subsequently landed.

- W1 live s3 bearer-cache test (needs a JWKS+JWT HTTP fixture; the cache
  path is the same engine webdav's live tests pin) — ride the W4.3 jwks
  work which builds that fixture anyway.
- W3.5 verify-depth unification — rides the W2 x509 field-move commit as
  the plan already stated.
- W8 flag-setter audit (`brix_cms_srv_set_enable`, `brix_conf_set_wt_enable`,
  `brix_ftp_set_enable`).
- W2 / W4 / W5.2-4 / W6 / W7 / W9 — not started; OP gates per the summary
  table.

---

## W9 — cache-grammar convergence study (2026-08-10)

Evidence base: `fs/cache/README.md` (architecture section, current),
`cache_storage.c:198-209` (the dual-path resolver), the 101-W8 behavior diff,
and the `stream/directives_cache.h` + `directives_writethrough.h` inventories.
This is the decision-input matrix the phase called for — no directive changed.

### The mechanisms, as they actually compose today

| Mechanism | Config surface | What it actually is |
|---|---|---|
| **Read-cache data tree** | `brix_cache_root` (HTTP, preamble since 101-W8) / stream `brix_cache` + `brix_cache_export` (advertised logical root) | The XCache data tree. Per-worker SD instance (`cache_storage_inst`); POSIX by default; a DRIVER-backed tree needs a separate state root. HTTP roots the stream init loop never visited lazily self-register (`brix_cache_storage_by_root`) |
| **Composable tier store** | `brix_cache_store` (tier X-macro, both planes) | The phase-64 sd_cache DECORATOR — its own store+cstore; `brix_cache_storage()` returns it when set, else `cache_storage_inst` (`cache_storage.c:198-209`). A pure-tier cache never builds the legacy instance |
| **Sidecar/state tree** | `brix_cache_state_root` (always POSIX; REQUIRED for a driver-backed cache) | `.meta`/`.cinfo` records — deliberately split from the data tree |
| **Write-back staging** | `brix_wt_stage_{root,backend,block_size}` (post-W8 one prefix) + `brix_wt_*` + watermarks | The write-through engine's staging area — a third independent role |
| **Admission/eviction knobs** | stream `brix_cache_{allow,deny}_prefix`, `_include_regex`, `_max_file_size`, `_eviction_threshold`, watermarks, `_cold/dirty_max_age`, `_state_root` … (~20 names) | Engine policy for the read cache — stream-registered, consumed by the shared `fs/cache/` engine |

### Findings

1. **The three ROLES (read data, state, write staging) are real architecture,
   not grammar debt** — independently pluggable backends per role, with a
   config-time validation that a driver cache MUST split state from data.
   A single "one cache directive" grammar would erase a load-bearing
   distinction. Convergence should target SPELLING consistency, not role
   merging.
2. **The genuine debt is the legacy-vs-tier dual path** (101-W8's finding,
   unchanged): `brix_cache_root` builds `cache_storage_inst` while
   `brix_cache_store` builds the decorator, and readers pick whichever
   exists. The migration question is precisely: can the tier decorator grow
   the read-through root's semantics (lazy by-root self-registration for
   HTTP, `brix_cache_ready()` three-state readiness, sidecar mapping) so
   `brix_cache_root` becomes sugar for a posix `brix_cache_store` + role
   defaults? Nothing in this study contradicts that direction; what it needs
   is the cache integration suite as the harness (101-W8's bar stands).
3. **The stream admission/eviction family is engine policy consumed by
   shared code** (`fs/cache/`) but registered stream-side only. If/when the
   HTTP plane's tier cache wants admission filters, the family should ride
   the tier X-macro (the mechanism exists; the 101-W3 disposition already
   lists the stream cache fragments as "candidates for later waves").
4. **Operator-facing count** (the "3-line config" benchmark): a POSIX
   read-cache node today = 2 lines (`brix_cache_root` + nothing else, or
   `brix_cache_store file:<dir>`); a driver-backed cache = 4
   (`+ state_root`, `+ store args`); a write-through cache = +3
   (`wt_stage_root`, watermarks optional). That is already close to
   minimal; the confusion cost is the legacy/tier CHOICE, not the line
   count.

### Recommendation to OP

Implemented end-state: **`brix_cache_store` is the single runtime entry** and
HTTP `brix_cache_root` is its POSIX shorthand (option-A revisited). The
shorthand is canonicalized and checked outside the export, lowered before
tier registration, and then removed from the legacy VFS-open path so one
request cannot consult two cache engines. Configuring both forms fails
closed. The state-root and write-staging surfaces stay distinct. The stream
admission family remains outside this convergence wave.

Acceptance evidence (2026-09-03): the configured `-Werror` nginx build
passes; `tests/test_cache_root_unification.py` passes 7/7 (inherited HTTP
success, explicit dual-config error, and inside-export security negative);
and an isolated `http-cache` registry lane passes
`tests/test_http_cache_hit.py` 8/8. That live lane proves first-read fill,
second-read byte-exact hit, miss fallback, corrupt-uncommitted-entry fallback,
checksum parity, automatic cache-directory use, and traversal confinement on
the lowered tier path.

---

## Implementation log — 2026-08-10 session 2 (W2, W3.5, W4.1/4.2/4.4, W5.2–4, W8-audit, W9)

Build: static tree, ABI-dirty rebuilds throughout. Checker after this
session: R1/R2/R4/R5/R6 = 0 with the reasoned allowlist, `--fail` exits 0,
CI lane flipped. NOTE: mid-session a repo linter split `http_common.c`'s
command table into three fragment headers (`http_directives_core/auth/ops.h`)
and `shared_conf.h`'s merge into `shared_conf_merge.h` — the R5 owner list
and two suite layout-pins were updated to match; future edits target the
fragments.

Key deviations/verdicts written back:

1. **`brix_backend_ca_dir` NOT moved (deviates from the W2 table's tentative
   "move").** Reading the setter settled it: it invokes the stock
   `proxy_ssl_trusted_certificate` setter against the nginx proxy module's
   loc conf mid-parse and seeds that location's upstream SSL_CTX — an
   in-location bridge to the proxy engine only webdav runs. Ownership by the
   proxying module is honest; R5-ledgered with this reason.
2. **`brix_tcp_congestion` reader-trace verdict: MOVE (class ii).** The
   single reader is the SHARED file-serve path (`file_serve.c`,
   `serve_apply_tcp_congestion`) covering webdav GET, S3 GetObject and
   cvmfs — it was already cross-protocol via the webdav-conf fetch;
   the fetch now reads the common conf.
3. **Mirror move shape**: settings (`brix_mirror_conf_t`) → preamble;
   merges → `ngx_http_brix_shared_merge` (one audit point, uniform
   defaults); the two custom setters made offset-based (pmark pattern);
   engine plumbing (upstream conf, TLS ctx, webdav-keyed request ctx)
   deliberately stays webdav-side — same documented-residual shape as
   ratelimit_http.c.
4. **W3.5 landed inside W2(iii)**: `brix_verify_depth` bare on both planes
   (webdav field → preamble, default 10 preserved in shared_merge; stream
   name-only rename, its 0=unlimited default untouched).
5. **W4.1 free s3 coverage confirmed**: the introspection access handler is
   globally registered and gates on `introspect_loc` + Bearer — with the
   quad in the preamble the conf source is honest; no s3-specific consult
   code was needed (option (a) satisfied by architecture). `revoke_kv`
   stays webdav-scoped.
6. **R6 earned its keep on day one**: it flagged
   `brix_s3_secret_key` ≈ `brix_webdav_secretkey` unprompted — verified as
   distinct mechanisms (SigV4 bucket credential vs redirect-CGI HMAC) and
   allowlisted with that reason.
7. **Fleet note**: the shared fleet predated this phase's renames; a full
   `manage_test_servers restart` was kicked off to rebase it onto the
   current binary+configs (the three bearer-conformance failures observed
   mid-session were stale-fleet artifacts, to be re-verified after the
   restart).

No implementation work remains in this phase. W4.3, W6, W7 and the W9
cache-grammar follow-on landed on 2026-09-03; their acceptance evidence is
recorded in the owning sections above.

### Addendum — fleet-forensics find (2026-08-11, during final verification)

The final live-suite verification kept intermittently failing with
FileNotFoundError on `/tmp/xrd-test/tokens/signing_key.pem`, cert-load
EMERGs, and 401s on valid tokens. Root cause CAUGHT IN THE ACT and recorded
in the `elusive-fleet-killer` memory as its third (and likely primary)
mechanism: pytest's conftest attach-guard takes lifecycle ownership whenever
its four-way probe (`reachable+owned+ready+master_alive`) fails — which it
does exactly when the fleet is degraded or mid-churn — and then runs the
destructive LOCAL-mode "clean slate" (rmtree DATA/PKI/registry), wiping the
token/PKI fixtures out from under ~all live masters. Self-amplifying, and
NOT fully guarded by `TEST_SKIP_SERVER_SETUP=1`. Recovery recipe (proven,
in the memory): reap ancient masters by worker-ppid, one `start-all`
(re-provisions), `start-dedicated` bind-race losers, restart JWKS-holding
members. After recovery the FULL phase-105 battery is
**190 passed / 1 skipped / 0 failed**, including the live mirror-to-shadow
writes, rate-limit-on-S3, and the WLCG bearer conformance suite on the
current binary. Phase 111 B111-010 completed the attach-probe hardening.
Recovery intersects the configured port's listening socket inode from
`/proc/net/tcp{,6}` with processes proven to reference the exact `TEST_ROOT`;
an argv match by itself is not enough. A proven listener attaches without
lifecycle ownership even when its manifest/ready marker is stale. An unproven
listener becomes a hard, non-destructive collision and is never reaped or
cleaned. Success, absent-socket and foreign-socket cases are pinned by
`tests/test_fleet_listener_ownership.py`, with the conftest decision cases in
`tests/test_conftest_fleet_lifecycle.py`. In passing, three files still carrying phase-101-retired token
spellings were swept (`cmdscripts/tpc_fwd_live.py`,
`cmdscripts/fwd_matrix_live_part3.py`, `tests/nginx.perf.conf`).
