# Phase 90 — plan-phase remainder register: verified outstanding work in phases 70 · 27 · 28 · 54 · 55

**Status:** AUDIT EXECUTED 2026-07-25; **BURNDOWN COMPLETE FOR ALL LOCALLY-DOABLE
WORK 2026-07-27** — §7 doc corrections APPLIED; P90-55.1 RULED (§6.1 Option A);
P90-70.3/.4/.5/.6/.7/.8/.9 CLOSED (per-item blockquotes below §2's tables are
the record — .5 was verify-and-harden, its row premise was stale; .8 was one
implemented slice + three rulings); §3.1 P90-27.1/.2 and the §4.1 phase-28
batch (28.1–28.6) CLOSED (blockquotes in §3/§4). **Remaining open = ONLY
container/infra-blocked:** P90-70.1 (S3 STS lab) · P90-70.2 (krb5 KDC lab) ·
§3.2/§4.2 (ASan/fuzz CI lanes). Register below is the verified open-work
backlog for the five phases that `phase-88-open-work-audit.md` §5 still
labelled "plan-only / not started".
Supersedes the "Plan-only phases: **70** … **27/28** … **54/55**" clause of
`phase-88-open-work-audit.md` §5 (lines 188–191), which is stale.

**Scope:** phase-70 (full credential delegation), phase-27 (memory-safety
hardening), phase-28 (adversarial hardening), phase-54 (thread-safe VFS IO
core), phase-55 (storage-backend abstraction). CVMFS and by-design parity gaps
remain out of scope (per phase-88 §6).

**Method:** three parallel read-only sweeps enumerated every planned item in the
five phase docs, then verified each against the current tree — grep for the
symbol, read the gate test, open the driver — rather than trusting the docs'
`Status:` headers. Every file:line anchor in §2 and §5–§6 (and the load-bearing
ones in §3–§4) was re-verified against the tree on 2026-07-25; anchors carried
from the sweep reports without independent re-verification are marked `(sweep)`.

**How to read this doc.** §1 is the reconciliation summary. §2–§6 are one section
per phase: each opens with a **Landed** evidence table (so the doc is a
self-contained verification record), then a per-item **Open** register. Every
open item carries: *current state* (what exists), *the gap* (what is missing),
*implementation approach* (functions/signatures to add and call sites to wire),
*acceptance criteria / tests*, and *risk*. §7 lists the doc corrections owed to
other files. §8 is the recommended sequencing.

---

## 1. Why this phase exists

`phase-88` (2026-07-20) reconciled the *actionable-bug* backlog but carried the
five plan-phases forward verbatim into its §5 feature backlog as "plan-only /
not started." That characterisation did not survive verification: **all five
phases have substantially landed** — mostly under the `xrootd_*`→`brix_*` rename
(54/55), via the 2026-07-17..20 hyper-hardening sweep (27/28), or in a single
2026-07 delegation commit (`27c89e3e1`, phase-70). This is the exact failure
mode `phase-88` §1 warns about: **`Status:` headers go stale; the
chronologically-last progress section — or the tree — is the truth.**

This phase records the *residual*: the concrete, still-open slice of each phase,
so the next planner starts from what is actually left rather than from a
five-phase greenfield that no longer exists.

**Completion at a glance** (verified 2026-07-25):

| Phase | Landed | Genuinely open | Open work class |
|---|---|---|---|
| 70 full credential delegation | ~65–75% — foundation, bearer PT + RFC-8693 exchange, x509 PT, delegate/mint, 7 of 8 directives | S3-STS / krb5 / SSS origin-leg *drive* + metrics/doc/test polish | feature work, mostly local; 2 legs need containers |
| 27 memory-safety hardening | ~85–90% — `safe_size.h`, `scoped.h`, registry TTL reap, fuzz lane, alloc lint, F1/F2/F4/F5/F9 | 2 small local items + infra-blocked B-2 / C-1-tail / C-2 | mostly infra-blocked |
| 28 adversarial hardening | ~85–90% — SSRF/DNS chokepoint, argv `--`, curl verify, CMS auth, CT SigV4, depth caps, per-identity RL, red-team suite | ~8 small local hardening/verification items + shared infra set | mostly local, low-severity |
| 54 thread-safe VFS IO core | ~100% — verbatim under `brix_vfs_io_core*` | none material (status-header fix only) | — |
| 55 storage-backend abstraction | ~95% — the whole `src/fs/backend/` SD seam, *exceeding* the plan | `brix_vfs_file_fd()` retire-or-rule + directive-grammar decision + degradation metrics | 1 decision + 1 mechanical convert |

Rough remaining effort if every item were pursued: **phase-70 ≈ 3–4 wk**
(dominated by the two container-dependent origin legs), **phase-27/28 local
≈ 1 wk**, **phase-55 ≈ 3–5 d** (or a same-day won't-do ruling), **phase-54 ≈ 0**.
The infra-blocked tail (ASan lane, fuzz entry points) is unchanged from
`phase-88` §4 and is not re-estimated here.

---

## 2. Phase 70 — full credential delegation (residual)

### 2.0 Landed (verification record)

Commit `27c89e3e1` ("per-user/delegated backend credentials (ph 1-3, 70, 71)")
carried the bulk. The delegation *decision engine* is a clean switch in
`src/fs/vfs/vfs_deleg.c` (`brix_vfs_deleg_apply`, the dispatcher at lines
~312–357): a captured full-proxy PEM routes to `brix_vfs_deleg_proxy`, a bearer
to `brix_vfs_deleg_bearer` (or `brix_vfs_deleg_exchange` when an exchange
endpoint is configured), and "neither present" is a missing-cred → deny/fallback.

| Plan item | Status | Verified anchor |
|---|---|---|
| §4.1 mode enum + `mode` field on cred | LANDED | `enum brix_cred_mode { SELECT, PASSTHROUGH, EXCHANGE, DELEGATE, MINT, AUTO }` `src/fs/backend/sd.h:196-202`; field `sd.h:220`. (phase-82 P82.9 refers to the same struct as `brix_credential`.) |
| §4.2 per-request live bag + ctx bind | LANDED | `brix_vfs_deleg_bind` `src/fs/vfs/vfs_deleg_bind.c`; ctx field `deleg_live` in `vfs.h` |
| §4.3 ephemeral proxy materialiser + zero/unlink cleanup | LANDED | `brix_vfs_deleg_proxy` `vfs_deleg.c:240`; reuses `brix_proxy_gsi_write_pem_temp`; unit `tests/gsi_pem_temp_unittest.c` |
| §4.4 `brix_backend_delegation` directive (HTTP + stream) | LANDED | HTTP `src/core/config/http_common.c` (sweep); stream/root:// `src/protocols/root/stream/module.c` (sweep) |
| §5.1 x509 passthrough — capture→materialise→present | LANDED | header channel `X-Brix-Delegate-Proxy` wired in `webdav/access.c` + `s3/util.c` (sweep); root:// bucket capture `src/auth/gsi/parse_x509.c` (sweep) |
| §5.2 DELEGATE mode enum + GridSite endpoint | LANDED (mode) | `BRIX_CRED_DELEGATE`; `src/auth/gsi/delegation.c` |
| §5.3 MINT mode | LANDED | `src/fs/backend/cred_mint.c`, `BRIX_CRED_MINT`; invoked on DECLINED |
| §5.4 bearer PASSTHROUGH + RFC-8693 EXCHANGE | LANDED | `brix_vfs_deleg_bearer` `vfs_deleg.c:156`, `brix_vfs_deleg_exchange` `vfs_deleg.c:185`; `src/auth/token/exchange.{c,h}` |
| §6 no wrong-identity fallback | LANDED | `brix_vfs_deleg_deny` `vfs_deleg.c:127` used on every failure path; EXCHANGE/STS explicitly refuse service-cred fallback |
| §6 namespace parity (`*_cred` snapshot for child ctx) | LANDED | `brix_vfs_deleg_snapshot` (sweep, used in `root/fattr/list.c`, dirlist) |
| §7 config directives | LANDED (8 of 8) | present in `http_common.c` (sweep); `brix_backend_sss_keytab` shipped 2026-07-27 (P90-70.3, both planes, load-validated) |
| §9 new files | LANDED | `src/auth/token/exchange.*`, `src/auth/s3/{sts.*,sts_http.c,sts_sign.c,sts_internal.h}`, `src/auth/krb5/forward.{c,h}`, `src/fs/vfs/vfs_deleg.c` + split sibling `vfs_deleg_bind.c` |

The e2e proof for the landed path is `tests/cmdscripts/fwd_matrix_live.py`
(emits `brix_backend_delegation passthrough`, asserts "userB denied, no leak").
Bearer passthrough + x509 passthrough are the two highest-value asks and are
**done and tested**.

### 2.1 Open — origin-leg drive

The STS and krb5 mechanisms are *code-complete but not wired to the live
credential path*: the hook functions exist, compile, and carry `DEFERRED`
banners in-source stating exactly what remains. This is deliberate — the
mechanisms were built to the point of "call-ready" and parked pending their
integration test infra.

---

**The landed decision engine** (for orientation — this is what the origin legs
plug into). `brix_vfs_deleg_live_cred` (`vfs_deleg.c:314-358`) is the single
dispatcher: it reads the phase-71 credential-kind accept mask
(`brix_sd_cred_accept(brix_vfs_ns_leaf(ctx->sd))`), then branches on which byte
field the front door filled on the bag `brix_deleg_live_t` (`vfs_internal.h:58`):

```
have_proxy_pem + proxy_pem   → CAP gate BRIX_SD_CRED_PROXY_PEM → brix_vfs_deleg_proxy
bearer (+ mode==EXCHANGE
        + tx.endpoint set)   → CAP gate BRIX_SD_CRED_BEARER    → brix_vfs_deleg_exchange
bearer (otherwise)           → CAP gate BRIX_SD_CRED_BEARER    → brix_vfs_deleg_bearer
neither                      → brix_vfs_deleg_deny (EACCES in deny-mode, else fall-through)
```

The STS and krb5 hooks are written to the *same* shape (validate → materialise →
`brix_vfs_deleg_deny` on failure, never a service-cred fallback) but are **not
reachable from this dispatcher** — there is no branch that calls them, and their
inputs are not on the ctx. Driving them means (1) adding the input to the bag/ctx
at capture, and (2) adding a dispatch branch here.

The target cred form is `brix_sd_cred_t` (`sd.h:205-221`), whose relevant slots
are `x509_proxy` (path), `bearer` (text), `s3_ak`/`s3_sk`/`s3_region`,
`ceph_keyring`/`ceph_user`, `mode`, and `fallback_deny:1`. **Note: there is no
`s3_session` slot** — see P90-70.1, which needs one.

---

#### P90-70.1 — S3 SigV4 → STS EXCHANGE origin drive (§5.5)

**Current state.** The STS client is complete and its VFS hook is written:
`brix_vfs_deleg_sts_cred(ctx, const brix_s3_sts_conf_t *cf, cred, use_cred,
err_out)` at `vfs_deleg.c:385-416` already calls `brix_s3_sts_assume()`, denies
fail-closed on error (`vfs_deleg.c:400-406`), and stamps
`cred->s3_ak`/`s3_sk`/`s3_region` + `mode = BRIX_CRED_EXCHANGE`. The client API
(`src/auth/s3/sts.h`) is:

```c
typedef struct { ngx_str_t endpoint, region, role_arn, svc_ak, svc_sk; int ttl_secs; } brix_s3_sts_conf_t;
typedef struct { ngx_str_t *ak, *sk, *session; } brix_s3_sts_out_t;   /* borrowed out-slots */
ngx_int_t brix_s3_sts_assume(ngx_pool_t*, const brix_identity_t *id,
                             const brix_s3_sts_conf_t*, const brix_s3_sts_out_t*, ngx_log_t*);
```

`brix_s3_sts_assume` maps `id->subject`/`id->dn` to the STS `RoleSessionName`
(so origin audit attributes to the real caller), falls back to `GetSessionToken`
when `role_arn` is empty, clamps `ttl_secs` to 900..43200, and never logs
secrets. The verbatim `DEFERRED` banner (`vfs_deleg.c:376-384`) names the exact
blockers:

> *"NOT yet driven from `brix_vfs_deleg_live_cred` because (a) the STS conf
> (`brix_s3_sts_conf_t`: endpoint/region/role_arn + the node's svc_ak/svc_sk) is
> not reachable from `brix_vfs_ctx_t` — `conf->common.backend_sts_endpoint/_role`
> are set, but the SigV4 SERVICE key pair still needs a config source + a
> `brix_vfs_ctx_bind_backend_sts()` at the S3 capture site; and (b) `sd_remote`'s
> `open_cred` must map s3_ak/sk/session through to the origin keys."*

**The gap — four wiring points** (the banner's two, plus two the banner implies):
1. **Service-key config source.** `backend_sts_endpoint`/`_role` parse today, but
   `svc_ak`/`svc_sk` (the credential that *signs* the AssumeRole call) have no
   directive. Add `brix_backend_sts_service_key <ak> <sk>` (or a file form), and
   assemble a `brix_s3_sts_conf_t` at config load, validated there.
2. **Capture binder.** Add `brix_vfs_ctx_bind_backend_sts(vctx, cf)` in
   `vfs_deleg_bind.c` (sibling to `brix_vfs_deleg_set_exchange`,
   `vfs_deleg_bind.c:58`) to hang the assembled conf on the ctx/bag; call it from
   the S3 capture site (`s3/util.c`, beside the existing `X-Brix-Delegate-Proxy`
   capture) whenever the S3 identity is authenticated and the leaf backend
   accepts S3 creds.
3. **Dispatch branch.** In `brix_vfs_deleg_live_cred`, add an EXCHANGE arm: when
   `brix_sd_cred_accept(leaf) & BRIX_SD_CRED_S3` and a bound STS conf is present,
   `return brix_vfs_deleg_sts_cred(ctx, cf, cred, use_cred, err_out);`.
4. **Session-token plumbing — a struct change the sweep missed.** The hook
   collects `session` into a local `ngx_str_t` (`vfs_deleg.c:391-392`) but
   **drops it** — `brix_sd_cred_t` has no `s3_session` field, so the temporary
   credential's `SessionToken` currently goes nowhere. STS temporary creds are
   *unusable without it*. Add `const char *s3_session;` to `brix_sd_cred_t`
   (`sd.h`), store it in the hook, and have `sd_remote`'s `open_cred` emit it as
   the `x-amz-security-token` header on every signed origin request.

**Acceptance / tests.** `test_s3_sts_delegation.py` against MinIO-STS/localstack:
(a) caller A reaches the origin as A's STS session; (b) caller B cannot read A's
object; (c) STS-endpoint failure → clean deny, never a service-cred read;
(d) a returned `SessionToken` actually appears on the origin request. Add an
`sts_sign.c` SigV4-over-"sts"-service unit (no container).

**Risk.** Low-medium. The client + hook are written; the risk sits in the new
`s3_session` field (touches the `brix_sd_cred_t` ABI — rebuild all three build
systems, cf. the `struct_field_abi_clean_rebuild` gotcha) and the `sd_remote`
header threading. Container-dependent → schedule with the phase-88 §4 k8s lab.
**~2–4 d + test infra.**

---

#### P90-70.2 — krb5 GSSAPI forward origin leg (§5.7)

**Current state.** `src/auth/krb5/forward.h` exposes exactly two entry points:

```c
int       brix_krb5_forward_available(void);                    /* 0 → caller falls back to SELECT */
ngx_int_t brix_krb5_deleg_to_origin(ngx_pool_t*, void *deleg_gss_cred,
              const char *origin_service_princ, ngx_str_t *out_token, ngx_log_t*);
```

`brix_krb5_deleg_to_origin` performs **one** `gss_init_sec_context()` step and
returns the first-leg token; the header is explicit that *"the multi-leg GSSAPI
negotiation loop (feeding origin replies back through `gss_init_sec_context`
until `GSS_S_COMPLETE`) belongs to the origin-auth caller."* The VFS hook
`brix_vfs_deleg_krb5_token(ctx, void *deleg_gss_cred, const char
*origin_service_princ, ngx_str_t *out_token)` (`vfs_deleg.c:440-457`) already
guards on `brix_krb5_forward_available()` and calls it. Its verbatim `DEFERRED`
banner (`vfs_deleg.c:432-439`):

> *"NOT yet driven because (a) the captured delegated `gss_cred_id_t` and the
> origin service principal are not carried on `brix_vfs_ctx_t` (root:// krb5 auth
> captures them in the session ctx); and (b) the multi-leg GSS negotiation
> belongs to `origin_auth.c`, which must feed origin replies back through
> `gss_init_sec_context`."*

**The gap.**
1. **Carry the delegated cred.** Add `void *deleg_gss_cred` (opaque
   `gss_cred_id_t`) + the origin SPN to the delegation bag `brix_deleg_live_t`
   (`vfs_internal.h:58`), with a pool cleanup that `gss_release_cred`s it.
   Populate it in the root:// krb5 acceptor **only** when the inbound ticket set
   `GSS_C_DELEG_FLAG` (forwardable); a non-forwardable ticket leaves it NULL.
2. **Origin-auth krb5 leg.** Add a leg in `origin_auth.c` that seeds the
   negotiation with `brix_vfs_deleg_krb5_token` (first token), then owns the
   context handle and drives the reply/re-init loop to `GSS_S_COMPLETE`, per the
   header's contract.
3. **Config + fail-closed.** Validate `backend_krb5_forwardable` + the origin SPN
   at load; a non-forwardable ticket must `brix_vfs_deleg_deny`, not fall back.

**Acceptance / tests.** `test_krb5_forward.py` against a KDC container issuing
*forwardable* tickets: delegated identity reaches the origin; non-forwardable
ticket → clean deny; expired delegated cred handled. Unit the `forward.c`
cred-lifetime/`gss_release_cred` path.

**Risk.** Medium-large. The multi-leg GSS loop in `origin_auth.c` and a
forwardable-KDC test container are the real cost; delegated-cred lifetime (the
`gss_cred_id_t` must outlive the request but be released on teardown) is the
subtle part. **~1–1.5 wk + container.**

---

#### P90-70.3 — SSS identity injection (§5.6)

**Current state.** `brix_cache_origin_auth_sss` (`src/fs/cache/origin_auth.c:229`
(sweep)) re-issues an SSS credential to the origin **from the keytab**, asserting
`key.user` — i.e. the *keytab's* principal, not the inbound caller's identity. So
every request currently reaches the origin as one shared SSS identity.

**The gap.** §5.6 wants the re-issued SSS credential to assert the *inbound*
user's identity (identity injection), so the origin authorises as the real
caller. And the `brix_backend_sss_keytab` directive was dropped from the shipped
§7 set (7 of 8 directives landed — this is the missing one), so there is no
operator surface pointing the injector at a keytab.

**Implementation approach.**
- Add the `brix_backend_sss_keytab <path>` directive (HTTP + stream), validated
  at load (file exists + readable, like the other keytab directives).
- In `brix_cache_origin_auth_sss`, mint the SSS identity block from the ctx's
  authenticated caller (user/group — the same `brix_identity_t` the other legs
  consume) rather than the keytab principal, signing with the configured backend
  keytab. Fail-closed: no caller identity → deny, never the shared identity.
- This is `mode = BRIX_CRED_PASSTHROUGH`-shaped (the caller's identity, re-signed)
  — but note the `cms_mesh_sss_brix_cli_fix` memory: SSS keytab minting must use
  the `-brix` xrdsssadmin tool via the resolver (override→client/bin→PATH), not
  the stock flags.

**Acceptance / tests.** Extend the SSS suite: A's request lands at the origin as
A (not the keytab principal); B lands as B; missing identity denies. Reuse the
keytab fixtures from `test_cms_sss_keytab.py`.

**Risk.** Small-medium; no new container (reuses the SSS fleet). The subtlety is
the keytab-tool invocation (see the memory above). **~2–3 d.**

> **IMPLEMENTED 2026-07-27.** Full chain landed, no shared identity can act any
> more:
> - **Directive** — `brix_backend_sss_keytab <path>` on BOTH planes
>   (`http_common.c` after `brix_backend_passthrough_persist`; stream
>   `module.c` after `brix_backend_delegation`), setter
>   `brix_conf_set_backend_sss_keytab` (`helpers.c`) = str-slot +
>   `brix_sss_load_keytab` load-validation. Smoke-verified: valid keytab passes
>   `nginx -t` on both planes; missing and world-readable (0644) keytabs fail.
>   §7 is now 8-of-8.
> - **Gate leg** — bag field `sss_keytab` + bag-ALLOCATING
>   `brix_vfs_deleg_set_sss()` (`vfs_deleg_bind.c`; injection is precisely the
>   no-captured-bytes case where `brix_vfs_deleg_bind` declines to bind), leg
>   `brix_vfs_deleg_sss()` (`vfs_deleg.c`) dispatched only when NO forwardable
>   bytes exist (proven PEM/bearer always win). Fail-closed: accept-gate on new
>   `BRIX_SD_CRED_SSS` → `FAIL_KIND`; no authenticated identity →
>   `FAIL_MISSING`; principal > 63 bytes (SSS NAME TLV bound) →
>   `FAIL_MATERIALISE` — never truncated (63-byte-prefix principals would
>   collide into one origin identity; `brix_sss_build_credential`'s silent
>   "xrd"-substitute and truncate paths are both hard-denied upstream, with a
>   second bound-check at `brix_cache_origin_auth_sss` as defence in depth).
>   Stamped at all three fronts by `brix_proto_deleg_stamp_conf` (renamed from
>   `_stamp_exchange`; SSS stamp runs first since it may allocate the bag).
> - **Consumer** — `brix_cache_origin_auth_sss` gained `as_user`
>   (NULL = keytab principal, the static service leg); the per-user ladder
>   branch (`origin_protocol_bootstrap.c`) runs BEFORE every service branch and
>   never falls back (missing origin `sss` advert and `kXR_authmore` both
>   hard-stop). `sd_xroot` copies `sss_keytab` through cred-copy/fill-task and
>   its fallback-deny predicates accept the SSS kind.
> - **Tests** — `deleg_gate_test.c` extended (12 cases green via
>   `test_c_auth_units.py -k deleg_gate`): caller-asserted success, no-identity
>   deny, over-bound deny, kind deny, proven-bytes precedence, set_sss
>   allocate/no-op guards. Clean `-Werror` rebuild; guards green on touched
>   files (`check_complexity` reds are pre-existing cvmfs drift).
> - **Out of scope / follow-ups**: async cache-flush legs re-resolve
>   credentials outside this gate (tracked, unchanged behaviour = service
>   cred); e2e fleet A-lands-as-A/B-as-B against a live SSS origin belongs to
>   the origin-legs batch (§2.1 fleet work); injection is reachable under the
>   bag-routed modes (`passthrough`/`exchange`) by design.

### 2.2 Open — hardening & polish

#### P90-70.4 — in-gate RFC-3820 chain re-verify (§5.1)

> **IMPLEMENTED 2026-07-27.** The bag now carries a conf-owned CA store
> (`brix_deleg_live_t.ca_store` + `.ca_verify_depth`, `vfs_internal.h`), stamped
> at both capture sites via the new `brix_vfs_deleg_set_ca_store()`
> (`vfs_deleg_bind.c`; webdav `access.c::webdav_vfs_bind_deleg` passes
> `conf->ca_store`/`conf->verify_depth`, root:// `op_path.c::brix_root_vfs_bind_deleg`
> passes `conf->gsi_store` at depth 0). `brix_vfs_deleg_proxy` re-runs
> `brix_gsi_verify_chain(..., client_purpose=0)` at the gate via
> `brix_vfs_deleg_chain_is_trusted()` (`vfs_deleg.c`), whose parser handles
> grid-format PEM (generic `PEM_read_bio` loop keeping only CERTIFICATE blocks —
> a bare `PEM_read_bio_X509` loop would stop at the embedded PRIVATE KEY and
> lose the EEC). No store stamped ⇒ capture-side gate applies (back-compat).
> Unit: `tests/c/deleg_gate_test.c` (runner `deleg_gate` in
> `tests/cmdscripts/c_auth_units.py`) — trusted-chain materialise + cleanup
> scrub, no-store back-compat, rogue-CA deny (EACCES under `storage_cred_deny`,
> service-fallback with `use_cred=0` otherwise), garbage-PEM deny, setter
> guards. `pytest tests/test_c_auth_units.py -k deleg` GREEN; full rebuild clean.
> The original gap analysis is kept below for the record.

**Current state.** `brix_vfs_deleg_proxy` (`vfs_deleg.c:239-301`) enforces only
PEM well-formedness (`brix_vfs_deleg_pem_is_valid` → `PEM_read_bio_X509`, a single
successful parse) before materialising the 0600 temp. Its verbatim banner
(`vfs_deleg.c:224-238`) defines the *full* four-step gate and states which steps
run where:

> *"(1) chain parses AND is unexpired; (2) leaf DN EQUALS the front-door
> authenticated DN (no privilege swap); (3) chain is RFC-3820-valid AND trusted
> by the export's CA store via `brix_gsi_verify_chain(..., client_purpose=0)`;
> (4) TLS-only transport. Steps (2)-(4) are enforced at CAPTURE (webdav
> `auth_cert.c` / `delegation.c` already run `brix_gsi_verify_chain` against
> `conf->ca_store` and match the DN before stashing the bytes), so only
> already-validated PEM reaches this seam."*

**The gap.** The in-gate re-verify is deferred because *"`brix_gsi_verify_chain`
requires an `X509_STORE*` and `brix_vfs_ctx_t` carries no CA store."* The banner
prescribes the fix exactly: *"add a `const void *ca_store` field to
`brix_vfs_ctx_t` + a `brix_vfs_ctx_bind_ca_store()` call at each deleg capture
site, then re-verify the chain here before materialising."*

**Why it's still worth doing** despite capture-side validation: defence in depth
at the single materialisation seam means a future capture path that forgets to
validate can't silently hand an untrusted proxy to the origin. Small, local, no
container.

**Effort.** ~small (one ctx field + binder + one `brix_gsi_verify_chain` call).

#### P90-70.5–.9

| # | Item (§) | Current state → gap | Approach | Effort |
|---|---|---|---|---|
| P90-70.5 | Client-side full-proxy opt-in (§5.1a) | Server accepts `kXRS_x509_fullproxy` (`src/auth/gsi/parse_x509.c`, sweep); `client/lib/auth/gsi/proxy.c` has **no** fullproxy/DELEGATE send path, so stock/our clients can't exercise the root:// inline bucket | Add an opt-in send flag in the client GSI proxy path that emits the `kXRS_x509_fullproxy` bucket; gate behind an explicit client directive | ~small |
| P90-70.6 | Metrics `mode` dimension (§6) | **DONE 2026-07-27** — `cred_deleg_total[proto][mode][outcome]` (6 fixed modes × user/fallback/deny) + `cred_deleg_fail_total[proto][reason]` (closed 6-reason vocabulary: missing/kind/pem/chain/materialise/exchange) in SHM; every gate terminal routes through `brix_vfs_deleg_deny()` (now cross-TU) or bumps USER at success; exporter `unified_emit_cred_deleg`; enum lock-step compile check in `vfs_deleg_bind.c`; `mode`/`outcome` added to the cardinality guard's ENUM vocabulary; `deleg_gate` unit asserts the exact label pair per case | — | done |
| P90-70.7 | Reference doc (§9) | **DONE 2026-07-27** — `docs/10-reference/backend-delegation.md` written (modes × mechanisms × capture sites × `cred_accept` matrix, cross-links P82.9 + this register + the P90-70.4 gate unit) | — | done |
| P90-70.8 | Proactive DELEGATE drive (§5.2) · session-scoped GridSite variant (§5.1c) · async ephemeral re-acquire record · load-time trust validation for STS/exchange/krb5 endpoints (§6) | Partial / optional — DELEGATE mode exists but is not VFS-driven for non-TPC clients; GridSite header channel covers the (b) use-case so the (c) non-persistent bind variant may be won't-do | Case-by-case; validate endpoint config at load as the cheap first slice | ~small-medium each |
| P90-70.9 | Test hardening (§8) | **Units + wiring DONE 2026-07-27** — audit found the audience directive parsed but enforced NOWHERE (silent fail-open) and `brix_vfs_deleg_set_exchange` had zero callers (EXCHANGE silently degraded to verbatim passthrough). Landed: `auth/token/aud_match.c` (fail-closed `aud` gate, WLCG `/jwt/v1/any` wildcard, string+array forms) + `auth/token/exchange_cache.c` (per-worker direct-mapped RFC-8693 mint cache, SHA-256(subject‖aud) key, TTL = min(`exp`, +5 min), injected `now`) + shared `protocols/shared/deleg_wire.c` wiring BOTH into all three bearer fronts (WebDAV `access.c`, S3 `util.c`, root `op_path.c`; gridftp forwards no bearer; fattr recurse inherits via `deleg_snapshot`); gate exempts EXCHANGE-with-endpoint (it re-audiences). Units: `tests/c/aud_match_test.c` (10 cases incl. substring-aud + no-aud fail-closed) + `tests/c/exchange_cache_test.c` (cross-subject/cross-aud isolation, both TTL bounds, eager expiry-free; needs `brix_crypto_init()`). **Still open (tracks .1–.3):** named `test_deleg_live` e2e + S3-STS/SSS/krb5 e2e as origin legs go live; `fwd_matrix_live.py` GAPs at `:795`/`:1082` | remaining e2e lands with .1–.3 | units done |

> **P90-70.5 VERIFIED-AND-HARDENED 2026-07-27** — the row's premise was STALE:
> the client-side send path has existed since phase-70 T-3, just not in
> `client/lib/auth/gsi/proxy.c` (that file is proxy *file* management). It lives
> in the shared round-2 kernel `src/auth/gsi/gsi_core_cresp_util.c::
> gsi_add_fullproxy_bucket`, called from `gsi_cresp_build_inner`
> (`gsi_core_cresp.c:296`) — compiled into `libxrdproto.a` and therefore into
> the native client, which drives it via `brix_gsi_build_cert_response_ex`
> (`sec_gsi.c`). The opt-in gate is the env var `XRD_DELEGATEFULLPROXY`
> (env vars ARE this client's directive surface — cf. `XRDC_GSI_DELEGATE`),
> and the kernel's server/TPC callers never set it, so they stay inert.
> **Two real gaps found and fixed:** (1) the helper read *only*
> `$X509_USER_PROXY` — with the var unset, opt-in silently no-oped even though
> every GSI client resolves the standard `/tmp/x509up_u<euid>` default; it now
> falls back to that path (cred-store-resolved paths remain out of reach of the
> ngx-free kernel — documented limitation, `X509_USER_PROXY` covers it).
> (2) the key-bearing proxy file was opened with a bare `fopen` — no symlink or
> ownership guard on a predictable `/tmp` path; now `open(O_RDONLY|O_NOFOLLOW|
> O_CLOEXEC)` + `fstat` requiring a regular file owned by the effective uid
> (mirrors the client-lib `brix_open_credfile` contract, which is unavailable
> in the shared kernel). Oversize cap (>16 KiB ⇒ omit, never truncate) and
> `OPENSSL_cleanse` retained. **New suite `tests/test_fullproxy_passthrough.py`
> 8/8 green** incl. live e2e vs the fleet: opt-in over `roots://` → copy OK +
> server logs "full-proxy passthrough accepted" (promotion verified); default-
> off → identical stock behaviour, nothing pushed; opt-in over cleartext
> `root://` → login REJECTED ("supplied over cleartext") — a private key never
> rides a cleartext session; plus source-contract ratchets on the guarded open,
> default-path fallback, env-gate ordering, and the server's TLS+DN promote
> gates (`auth_cert.c::gsi_promote_fullproxy`). All three build systems rebuilt
> clean (-Werror); `nginx -t` OK; 4 CI guards green.

> **P90-70.8 CLOSED 2026-07-27** — case-by-case as the register prescribed;
> one sub-item implemented, three ruled.
> **(d) Load-time trust validation — IMPLEMENTED (the cheap slice).** §6 audit
> of what actually exists: SSS keytab already load-validated (P90-70.3,
> `brix_conf_set_backend_sss_keytab`); mint CA already load-validated
> (`brix_conf_set_mint_ca` parses cert+key at conf time); STS endpoint and
> KDC/realm have **no conf binds yet** — their validation lands with the
> container-blocked P90-70.1/.2 directives. The one live gap was
> `brix_backend_token_exchange_endpoint`: a plain str slot, while the exchange
> client (`exchange.c::brix_tx_http_post`) pins curl HTTPS-only — an `http://`
> value parsed fine and only surfaced as every EXCHANGE delegation fail-closing
> at first use. New setter `brix_conf_set_backend_tx_endpoint`
> (`src/core/config/http_common.c`) rejects at `nginx -t`: non-`https://`,
> host-less, and whitespace/control bytes (value is spliced into `CURLOPT_URL`
> verbatim). No existing config uses the directive → no compat break. Suite
> `tests/test_tx_endpoint_load_validation.py` 4/4 green; build + `nginx -t` +
> 4 guards green. Doc: backend-delegation.md § load-validated.
> **(a) Proactive DELEGATE drive (§5.2) — DEFERRED.** DELEGATE (GridSite
> handshake) exists as an endpoint but driving it from the VFS gate for
> non-TPC clients means initiating a post-login `kXGS_pxyreq` re-key round
> mid-session — a wire/engine change, not a gap-fill. Its use-cases are now
> covered twice over: 70.5 fullproxy passthrough (root://) and the
> `X-Brix-Delegate-Proxy` header channel (WebDAV/S3). Revisit only if a stock
> client that speaks GridSite-DELEGATE-but-not-fullproxy materialises.
> **(b) Session-scoped GridSite variant (§5.1c) — WON'T-DO**, as the register's
> own hedge anticipated: the header channel covers the use-case with
> request-scoped, pool-cleanup-scrubbed binds; a session-persistent variant
> would only widen the credential's lifetime for no consumer.
> **(c) Async ephemeral re-acquire record — SATISFIED BY EXISTING DESIGN.**
> §6 asks that async records store *how to re-acquire*, never the expiring
> bearer/proxy, with unre-acquirable → dead-letter. That is exactly the landed
> stage journal: `brix_stage_cred_t` (`src/fs/xfer/stage_engine.h`) persists
> `{key, principal, dir, deny}` — re-resolvable identity only, no credential
> bytes; flush re-resolves via `brix_sd_ucred_resolve()` at flush time;
> missing/expired ⇒ `deny=1` ⇒ hard EACCES/`BRIX_XFER_DENIED` with dead-letter
> capping in `stage_engine_reconcile.c` — never silent service-cred promotion.
> Ephemeral live creds (captured fullproxy, exchanged bearers) are never
> spilled to the journal at all. Documented, no code needed.

---

## 3. Phase 27 — memory-safety hardening (residual)

### 3.0 Landed (verification record)

The Phase-27 foundation (`safe_size.h`, `scoped.h`) was already in-tree at the
2026-07-02 phase-66 bucket reorg, i.e. *predates* the phase-88 audit that still
called it "not started."

| Plan item | Status | Verified anchor |
|---|---|---|
| W1 checked size arithmetic | LANDED + adopted | `src/core/compat/safe_size.h` — `brix_size_mul` `:39`, `brix_palloc_array` `:87` (+ `pcalloc_array`/`alloc_array`, `__builtin_*_overflow`). Adopted in readv, evict, jwks, net/proxy/pool, aio/uring_submit, gsi/proxy_req, zip_dir, tape_rest_ops |
| W2 cap-before-allocate; F1 readv seg cap | LANDED | `readv_engine.c:198` gates `segment_count > BRIX_READV_MAXSEGS` **and** folds `brix_size_mul(segment_count, sizeof(*ranges), …)` at `:199` |
| W3 scoped-cleanup idiom | LANDED (header) / PARTIAL (adoption) | `src/auth/crypto/scoped.h` — full NULL-safe destroyer set + jansson borrowed/owned cheatsheet. F2 (`tpc_gsi_exchange_cleanup`, sweep) used a bespoke cleanup rather than the shared destroyers |
| W5 registry anti-exhaustion | LANDED (TTL reap) | self-labelled "Phase 27 F4": `last_seen` LRU + `BRIX_SESSION_REAP_MIN_AGE_MS` + reap-on-full + `session_evict_total` metric (`session/registry.h`, sweep) |
| W8 alloc/free invariant lint | LANDED | `tests/cmdscripts/lint_alloc.py` |
| F5 cap-drift (1024 vs doc "256") | RESOLVED | `BRIX_SESSION_REGISTRY_SLOTS 1024`, doc + define agree (sweep) |
| F9 `evict_candidates` realloc growth | LANDED | `src/fs/cache/evict_candidates.c` uses the checked-mul helpers (sweep) |
| W7 wire-parser fuzz harness | LANDED (5 targets) / PARTIAL (coverage) | `tests/fuzz/`: `fuzz_safe_size`, `fuzz_b64url`, `fuzz_zip_dir`, `fuzz_jwt_json`, `fuzz_urlcodec` (+ matching `corpus_*` dirs) + CI lane = hyper-hardening B-3 |

### 3.1 Open — doable locally (low severity)

| # | Item | Current state → gap | Approach | Effort |
|---|---|---|---|---|
| P90-27.1 | W3 broad adoption | `scoped.h` destroyers exist; the 26 EVP call sites are not uniformly routed through them (F2 fixed with a one-off cleanup fn) | Mechanically convert the remaining EVP sites to the shared destroyers; consistency only, no behaviour change | ~small, mechanical |
| P90-27.2 | W5 per-source-identity soft quota | Global LRU reap landed; an explicit *per-peer* cap (so one identity can't evict everyone else's sessions) is absent | Add a per-source counter keyed on the ratelimit subject key; soft-cap before the global LRU kicks in | ~small |

> **P90-27.2 IMPLEMENTED 2026-07-27.** Per-source soft session quota in the
> kXR_bind registry (`src/protocols/root/session/registry.c`). Each slot now
> carries a `src_key` — the ratelimit-vocabulary no-PII bucket id of the
> registrant (`sub:<8-hex>` for token logins, `dn:<8-hex>` otherwise), rendered
> by the now-exported shared formatters `brix_rl_key_{dn,sub}_hash`
> (`src/net/ratelimit/ratelimit_keys.c`) so one principal maps to the same
> bucket in the limiter and the quota. The single scan pass additionally counts
> the registrant's live slots and tracks its own-LRU; at
> `BRIX_SESSION_PER_SOURCE_SOFT_CAP` (64 of 1024) the next registration
> recycles that identity's OWN least-recently-seen session
> (`brix_session_src_cap_evict`, counted in new
> `brix_session_src_cap_evict_total`) BEFORE consuming a free slot and BEFORE
> the F4 global reap — an over-quota identity can neither fill the table nor
> push other identities into the LRU reaper; only its own oldest session pays
> (hence no F4-style min-age gate). DN-less logins are un-keyed (`src_key ""`)
> and stay on the pre-W5 global-LRU-only regime. Callers unchanged (key derived
> inside `brix_session_register` from the dn/token_auth it already receives).
> Tests: `tests/test_phase27_memsafety.py` +3 (success shape · un-keyed
> exemption + defensive bounds · security-neg: self-eviction-only + cap-before-
> F4 ordering), suite 15/15. Verified: `-Werror` rebuild clean + idempotent,
> `objs/nginx -t` pass, metric exported, guards green.
>
> **P90-27.1 IMPLEMENTED 2026-07-27.** Mechanical sweep: all remaining raw
> `EVP_PKEY_free` / `EVP_PKEY_CTX_free` / `EVP_MD_CTX_free` /
> `EVP_CIPHER_CTX_free` call sites in `src/` (117 sites across 39 files —
> auth/gsi, auth/token, auth/crypto, auth/gssapi, auth/pwd, core/compat,
> core/config, fs/backend, fs/cache, protocols/{gridftp,root,webdav}, tpc/gsi)
> now route through the `src/auth/crypto/scoped.h` NULL-safe destroyers
> (`brix_evp_*_free`). Call-form-only replacement (function-pointer references
> untouched); consistency only, no behaviour change. `shared/` and `cvmfs/`
> excluded deliberately — those trees must not include `src/auth` headers
> (layering). Verified: full `-Werror` rebuild clean · `objs/nginx -t` pass ·
> `tests/test_c_auth_units.py` 12/12 (includes converted unittest TUs such as
> `proxy_req_unittest.c`) · file-size/metric-cardinality/vfs-seam/
> config-coverage guards green.

### 3.2 Open — infra-blocked (already tracked in phase-88 §4; no new work)

- **W6 = hyper-hardening B-2** — ASan+UBSan blocking CI lane. Local ASan exists
  (`SANITIZE=1` runtime + build-guide docs); the *blocking lane* does not, so
  findings F6/F7/F10 (EVP leak coverage, jansson ownership, fd-table release)
  have no enforcing gate.
- **W7 tail = hyper-hardening C-1 tail / C-2** — GSI ASN.1, SSS frames, macaroon,
  top-level SigV4 canonicaliser, and the wire-framing dispatcher each need a pure
  `(data,len)` entry point carved from an nginx-coupled TU before a fuzz target
  can attach.

---

## 4. Phase 28 — adversarial hardening (residual)

### 4.0 Landed (verification record)

SSRF work shipped as `src/core/compat/net_target.{c,h}` (not the planned
`egress_policy.{c,h}`); the argv guard shipped as `net_target.c::brix_net_host_chars_valid`
(not `argv_guard.h`).

| Plan item | Status | Verified anchor |
|---|---|---|
| A1–A4 argv/option injection | LANDED | hard `--` terminator in `tpc_cred_exchange.c` + `tpc/outbound/tpc_token_exchange.c`; host-char allowlist `brix_net_host_chars_valid` (sweep) |
| B1 SSRF metadata/loopback/ULA block | LANDED | `src/core/compat/net_target.c` — 127/8, 169.254/16, ::1, fe80::/10, RFC1918, fc00::/7, `::ffff:127.0.0.1` bypass guard; single chokepoint |
| B2 DNS-rebinding TOCTOU | LANDED | `brix_net_target_check_dns_pin` + SSRF-validated `CURLOPT_RESOLVE` (sweep) |
| B3 explicit curl VERIFYPEER/VERIFYHOST | LANDED | `tpc_curl_setup.c` sets both explicitly (sweep) |
| C1 CMS registration auth | LANDED | `cms/server_auth.c` layered controls + registration audit log + `nginx_redteam_cms.conf` (sweep) |
| D1 SigV4 constant-time compare | LANDED | `src/protocols/s3/auth_sigv4_verify_crypto.c:263-290` — reject non-64-char sig first, then `CRYPTO_memcmp(computed_hex, signature)` folded with `key_ok` into one branch |
| E1 admin audit + target allowlist | LANDED (audit + allowlist) / PARTIAL (tamper-evidence) | `admin_audit()` per-mutation line + `admin_url_host_allowed()` (sweep) |
| F1 secret-buffer cleanse | LANDED | `brix_sd_ucred_wipe()` wired into ~20 consumers (hyper-hardening A-4) |
| G1 WebDAV Depth/XML nesting caps | LANDED | `propfind_walk.c` hard entries ceiling + `propfind_depth_total` metric (sweep) |
| G2 per-identity rate/concurrency | LANDED | `BRIX_RL_KEY_SUBJECT` (`src/net/ratelimit/ratelimit_keys.c:95,205`) + `brix_negcache_backoff` |
| H8 red-team suite + threat model | LANDED | `tests/test_security_redteam.py`, `tests/userns/test_e2e_redteam.py`, `docs/07-security/threat-model.md` (sweep) |

### 4.1 Open — doable locally (low severity)

| # | Item | Current state → gap | Approach | Effort |
|---|---|---|---|---|
| P90-28.1 | F3 secret-page hardening | secrets are wiped (F1) but long-lived secret pages are not `MADV_DONTDUMP`/`mlock`'d and core dumps aren't disabled for them | `madvise(MADV_DONTDUMP)` + optional `mlock` on the secret arenas; `prctl(PR_SET_DUMPABLE, 0)` consideration | ~small |
| P90-28.2 | E1 tamper-evidence | per-mutation audit line + allowlist landed; the log is not hash-chained/append-only | Add a rolling hash chain over audit records (each line commits to the prior digest) | ~small-medium |
| P90-28.3 | B4 audience binding | delegated-cred forwarding is identity-aware but explicit cross-target audience binding is unconfirmed | Assert the delegated token/cred audience matches the selected origin before presenting it | ~small |
| P90-28.4 | D3 ADMIN-bit path scope | ADMIN capability path-scoping not confirmed by a test | Add a path-scoped ADMIN test to the red-team suite; fix if the scope leaks | ~small |
| P90-28.5 | D5 replay nonce cache | no short-TTL nonce cache for non-idempotent ops (was explicitly *optional* in the plan) | short-TTL SHM nonce cache keyed on op+identity; reject replays | ~small |
| P90-28.6 | F2 two-tier errors · C3 OCSP/JWKS max-staleness · D2/D4 deny-by-default op×identity matrix + uniform-timing sweep · G3 aggregate-byte TPC quota | partial/verification items — CT compares + OCSP size-cap + JWKS `kid`-authoritative already landed | verify + close each; most are test-and-confirm rather than new code | ~small each |

> **P90-28.2 IMPLEMENTED 2026-07-27.** The admin audit log is now
> hash-chained: `admin_audit()` (`api_admin.c`) builds the canonical line
> text (method · action · target · client · result · `seq=`), computes
> `chain_n = SHA-256(chain_{n-1} || canon)` (genesis = 32 zero bytes), commits
> the state, and emits the line with `seq=` + `chain=<32 hex>` (first 16
> digest bytes via `ngx_hex_dump`; full 32-byte digest kept in state). State
> lives on the dashboard loc conf (`audit_chain[32]` + `audit_seq`,
> pcalloc-zeroed, per-process COW copy) → chains are per worker × location;
> the error log's pid prefix partitions streams for a verifier and `seq=0`
> marks each genesis (worker start/reload). Deleting, reordering, or editing
> any line breaks every subsequent chain value, and a log-scrubbing attacker
> cannot mint a continuation without the point-of-tamper digest. Verifier
> recipe documented in the function comment (`prev=0³²; digest=SHA-256(prev‖
> canon); assert hex(digest[0..15])==chain; prev=digest`). A `brix_sha256`
> failure logs the line with `chain=-` rather than dropping the audit record
> (availability of evidence beats chain continuity). Tests:
> `tests/test_phase28_hardening.py` E1 trio (wired · crypto-failure-never-
> drops · commits-prior-digest+seq with canon<commit<emit ordering), suite
> 12/12. Verified: `-Werror` rebuild clean, `objs/nginx -t` pass, guards
> green.
>
> **P90-28.5 RULED — NOT IMPLEMENTED (deliberate) 2026-07-27.** The D5
> short-TTL replay-nonce cache stays unbuilt. It was explicitly *optional* in
> the phase-28 plan ("optional … where replay matters"), and the window it
> would close is already narrow: SSS frames are timestamp+skew-bounded with
> per-connection challenge/response (`auth_identity_challenge.c`), SigV4 is
> presigned-expiry-bounded, bearer-token requests are TLS-transported (no
> on-path capture without breaking TLS first), and the mutating admin API is
> CIDR/secret-gated + per-IP throttled + now hash-chain audited (P90-28.2).
> A nonce cache would add SHM state + eviction policy (invariant-10 surface)
> against a threat that requires an attacker who can already capture and
> replay inside a seconds-scale skew window on an authenticated channel.
> Revisit only if a non-TLS mutating front with long replay windows appears.
>
> **P90-28.4 VERIFIED-AND-CLOSED 2026-07-27 (test added, no fix needed).**
> The ADMIN bit (`BRIX_AUTH_ADMIN` 0x20, authdb letter `k`) is already
> explicit and path-scoped by construction: the ONLY grant site is the
> literal `case 'k'` in `authdb_parse.c` (`a`=append folds to UPDATE, `r` to
> READ|LOOKUP — nothing implies ADMIN); grants live on per-path-prefix rules
> checked by bit-subset sufficiency (`(rule.privs & needed) == needed`) on a
> boundary-aware longest-prefix match (`find_rule.c` — `/data` ≠ `/data-x`),
> deny when no rule matches; and the bit's single consumer maps it to the
> specific acc CHMOD operation (`auth_gate.c`), never to an allow-all
> shortcut — no native op even *requires* ADMIN today. Tests:
> `tests/test_phase28_hardening.py` D3 trio — never-implicit (single grant
> site on `'k'`) · repo-wide consumer CENSUS ratchet (exactly {config.h,
> authdb_parse.c, auth_gate.c} — any new consumer breaks the test and forces
> review) · rule-scoped + specific-op mapping. Wrong-VO / unlisted-path
> denial behaviour is live-tested by `tests/test_authdb.py`
> (test_unlisted_path_denied et al.).
>
> **P90-28.6 VERIFIED 2026-07-27 — two small gaps found and FIXED, rest
> closed on anchors.** Per leg:
> **F2 two-tier errors — CLOSED, no code.** Every root-wire error string was
> enumerated (`brix_send_error` literals): all generic — no absolute paths,
> internal hostnames, or auth-step detail reach the wire; the detailed reason
> goes to the log (`BRIX_RETURN_ERR` + NOTICE lines), e.g. pwd logs "bad
> credential" while the wire sees only "invalid password".
> **C3 OCSP/JWKS max-staleness — one gap FIXED.** Already landed: periodic
> JWKS refresh with bounded cache age (`src/auth/token/refresh.c` timer at
> `brix_token_jwks_refresh_interval`, mtime-gated in-place key swap; per-issuer
> twin in `issuer_registry.c`) + 5-min L1/SHM validation-cache TTL cap bounds
> result staleness; OCSP fail-closed available (`brix_ocsp_soft_fail off` for
> UNKNOWN, `brix_ocsp_require_nonce` replay guard, REVOKED never overridden;
> response size cap). GAP: `check_ocsp_response()` never checked the
> thisUpdate..nextUpdate window, so a captured nonce-less pre-signed GOOD
> response replayed indefinitely. FIXED: `OCSP_check_validity()` gate in
> `src/auth/crypto/ocsp_request.c` (bounds `BRIX_OCSP_VALIDITY_SKEW_SEC` 300 s
> / `BRIX_OCSP_VALIDITY_MAX_AGE_SEC` 1 day in `ocsp_internal.h`); outside the
> window the status degrades to UNKNOWN (soft_fail policy decides, same as an
> UNKNOWN answer) — REVOKED still denies even when stale.
> **D2 deny-by-default op×identity — CLOSED, no code.** The three-tier gate
> `src/auth/authz/auth_gate.c` (authdb → VO ACL → token scope, first failure →
> `kXR_NotAuthorized`) is called by every namespace/file op — stat, statx,
> locate, dirlist, fattr dispatch, query metadata/checksum, open, mkdir,
> truncate, ext_ops — and the matrix is live-tested: `tests/test_vo_acl.py`
> (wrong-VO denied per op: stat/dirlist/read/write), the SCP token-conformance
> manifest (wrong-scope incl. `..`-traversal SCP-W04), `test_mu_*_authz.py`.
> **D4 uniform auth failure — one gap FIXED.** Wire messages already uniform
> (unknown-user and wrong-password both return the single "invalid password";
> S3 SigV4 folds `key_ok` into the one CT compare — 4.0 D1); secret compares
> CT (`CRYPTO_memcmp` in `pwdfile.c`). GAP: unknown user skipped the PBKDF2
> (10 k iters) — a measurable user-enumeration timing oracle. FIXED:
> lookup-failure branch in `src/auth/pwd/auth.c` burns the same KDF cost
> against a fixed dummy entry (dummy hash sized `BRIX_PWD_HASH_LEN` so the
> `hashlen` gate does not early-return) and falls through to the shared deny.
> **G3 TPC quotas — CLOSED PARTIAL, residual documented.** Covered: the
> amplification hot leg (nginx as TPC *source* serves standard kXR_read →
> per-identity subject-keyed rate/bandwidth buckets charge it, G2), global
> concurrency bounded by the transfer registry (1024 slots + abandoned-transfer
> reap + client-cancel), outbound SSRF policy. RESIDUAL (deferred, not
> test-and-confirm): the curl-driven legs (native pull ingest, WebDAV COPY)
> charge no per-identity byte quota — `brix_tpc_transfer_t` carries no identity
> key, so this needs identity plumbed through the async engine + a quota
> directive; registry `bytes_total` is already accepted-but-ignored for it.
> Tests: `tests/test_phase28_hardening.py` NEW — C3 trio (check wired ·
> stale→UNKNOWN-not-GOOD + ordering · REVOKED-never-overridden) + D4 trio
> (dummy-verify present · single wire message + fall-through · CT compare +
> hashlen-gate sizing), 6/6. Verified: `-Werror` rebuild clean, `objs/nginx -t`
> pass, guards green.
>
> **P90-28.1 IMPLEMENTED 2026-07-27.** `brix_secret_page_guard()` in
> `src/core/compat/crypto.c` (ngx-free, dual-build): page-aligns the range,
> then applies `madvise(MADV_DONTDUMP)` AND `mlock()` independently
> (best-effort — 0/-1 return, callers log a warning and continue; the guard is
> defence-in-depth, never load-bearing). Applied to every long-lived secret
> arena: the parsed SSS keytab key array (`brix_sss_load_keytab` — one
> chokepoint covering `brix_sss_keytab`, the permission policy, and
> `brix_backend_sss_keytab`), the admin bearer secret
> (`brix_admin_set_secret` pool copy), and the macaroon root-secret hex
> strings (server-conf merge; per-request binary keys are stack + F1-cleansed,
> so the conf hex is the only long-lived form). Semantics documented in
> `crypto.h`: the DONTDUMP VMA flag SURVIVES fork — conf-time guards protect
> every worker's core dumps (the primary threat) — while mlock does not cross
> fork (swap pin covers the calling process only); page granularity
> over-covers harmlessly; reload-recycled pages stay guarded (marginal RSS
> pin). **`prctl(PR_SET_DUMPABLE, 0)` RULED OUT as a default**: operators
> depend on worker core dumps for crash diagnosis (coredumpctl-first debug
> policy); targeted DONTDUMP removes the secret pages from those dumps without
> destroying their diagnostic value — global dumpable-off stays an OS-level
> operator choice. Tests: `tests/test_phase27_memsafety.py` +3 (guard + all
> call sites · best-effort-never-fatal · guard-after-materialise + fork-caveat
> doc), suite 18/18. En route fix: `src/auth/crypto/scoped.h` made ngx-free
> (`static inline`, ngx includes dropped) — the P90-27.1 sweep had broken the
> STANDALONE compile of `core/compat/crypto.c` (sd_s3 read unit builds it
> without the nginx include path); unit now green again. Verified: `-Werror`
> rebuild clean, `objs/nginx -t` pass, guards green.
>
> **P90-28.3 VERIFIED-AND-CLOSED 2026-07-27** — satisfied by the P90-70.9
> audience gate; no new code. Binding point: origin selection in this
> architecture happens by conf routing (one location/server conf → one backend
> instance → one origin endpoint; the cache plane likewise carries a single
> origin per conf), so the capture-time gate
> `brix_proto_deleg_gate_bearer` → `brix_token_backend_aud_ok`
> (`src/auth/token/aud_match.c`), enforced at all three fronts (webdav
> `access.c:520`, root `op_path.c:433`, s3 `util.c:87`) against the per-conf
> `brix_backend_token_audience_ok` allow-list, IS the "matches the selected
> origin before presenting" assertion — a token whose `aud` does not name that
> conf's origin (or the WLCG any-endpoint wildcard) is never bound into the
> bag, so it cannot reach any presenter (fail-closed once the gate is
> configured, including malformed/`aud`-less tokens). EXCHANGE mode
> additionally mints origin-audienced tokens (`live->tx_audience`) instead of
> replaying the client's. Granularity note: a conf whose allow-list declares
> several audiences accepts any of them — that is the operator's declaration
> that those origins share a trust domain, consistent with the WLCG profile.
> Unit: `tests/c/aud_match_test.c` (success/error/security-neg incl.
> different-backend `aud` rejection).

### 4.2 Open — infra-blocked

Same shared set as §3.2 (B-2 ASan lane; C-1 tail / C-2 framing fuzz = phase-28 H8
remainder). No phase-28 item was found obsolete-by-surface-retirement.

---

## 5. Phase 54 — thread-safe VFS IO core (residual)

### 5.0 Landed (verification record)

**Done under another name, effectively verbatim.** The plan's `xrootd_vfs_io_*`
POD-job dispatcher is `src/fs/vfs/vfs_io_core.{h,c}` + `vfs_io_core_dirlist.c`.

| Plan item | Status | Verified anchor |
|---|---|---|
| POD job + single execute entry point | LANDED | `brix_vfs_job_t` `vfs_io_core.h:101`; `brix_vfs_io_execute()` (contract in header banner `:8,:21`) zeroes OUT fields then dispatches |
| op enum (READ/WRITE/PGREAD/READV/WRITEV/OPENDIR) | LANDED + EXCEEDED | `vfs_io_core.h:36` `BRIX_VFS_IO_READ=0` … **plus** `BRIX_VFS_IO_SYNC` `:41` and `BRIX_VFS_IO_TRUNCATE` `:42` beyond the 6 planned |
| PREPARE/EXECUTE/COMPLETE triad + init helpers | LANDED | `brix_vfs_job_read_init` `vfs_io_core.h:115` (+ write/sync/truncate/opendir init helpers) prevent stale-field reuse |
| rewire all `*_aio_thread` workers | LANDED | reads/write/readv/dirlist build a job + execute (sweep); no raw `pread/pwrite/open/readdir` left in `src/core/aio` |
| dirlist security upgrade (loop-side beneath-confined dirfd) | LANDED | `int dirfd` on the task struct; worker never re-opens by path (sweep) |
| io_uring untouched | LANDED | fd-keyed submit unchanged (sweep) |
| thread-safety *contract* (reuse nginx pool, no new pool) | LANDED as planned | `brix_aio_post_task → ngx_thread_task_post` (sweep); **no per-handle mutexes, by design** (single-owner-per-connection POD snapshot) |
| VFS-THREAD-SAFE / VFS-LOOP-ONLY annotations + CI grep guard | LANDED + wired | `tools/ci/check_vfs_seam.py` enforced via `tests/test_ci_guards.py` |

### 5.1 Open

**None material.** The doc's "open questions" (e.g. whether `kXR_open` should wrap
an `xrootd_vfs_file_t`) were answered in practice — the stream-slot adapter was
kept. This phase needs only the status-header correction in §7.5.

---

## 6. Phase 55 — storage-backend abstraction (residual)

### 6.0 Landed (verification record)

**Substantially landed and *exceeded*.** The `brix_sd_*` Storage-Driver seam
(`src/fs/backend/`) realises phase-55 and goes past it.

| Plan item | Status | Verified anchor |
|---|---|---|
| SD vtable + capability bitmap + opaque types | LANDED + EXCEEDED | `struct brix_sd_driver_s` `sd.h:350`; caps at `sd.h:83-110` include `CAP_SENDFILE` `:88` and `CAP_MEMFILE` `:110` (+ FSCS/NEARLINE/CATALOG/DIRS_WRITE/XATTR_WRITE beyond the plan) |
| vtable ops (open/close/pread/pwrite/…/staged_*) | LANDED + EXCEEDED | `sd.h:356-536` (sweep) **plus** `read_sendfile_fd` `sd.h:380`, `preadv/copy_range/recall/residency/space/enumerate`, and a `*_cred` credential-forwarding family |
| name→driver registry + per-export instance | LANDED | `sd_registry.c` macro-driven from `src/core/types/fs_list.h` (sweep); `brix_sd_instance_create` |
| namespace/dir/stat/xattr/staged/copy behind `sd_posix` | LANDED | `src/fs/backend/posix/{sd_posix.c,sd_posix_io.c,sd_posix_ns.c}` (sweep) |
| block proof driver + object/S3 driver | LANDED + EXCEEDED | `backend/block/sd_block.c`; richer `backend/pblock/` (sqlite packed-block: snap/quota/dedup/fsck); `backend/s3/*` (range GET, multipart, CopyObject, ListObjectsV2, tags) (sweep) |
| cross-store promote (POSIX staging → object) | LANDED (as decorator) | phase-63/64 `cache` + `stage` decorators (`fs_list.h`, `cache_storage.c`, sweep) — a strict superset of the plan's two-pointer `ctx->sd_staging` model |
| capability-degradation + readonly-backend wire behavior | LANDED (via phase-71) | `test_readonly_backend_wire.py`: `kXR_mkdir/mv → kXR_NotAuthorized`, `truncate → kXR_Unsupported` over an s3 backend |

**Superseded, not open:** the plan's two-store `ctx->sd_staging` pointer pair
(§3.6/§6.3) and the `posix|s3|same` directive grammar were replaced by the more
general phase-63/64 composable decorator stack. That is a *better landed
architecture*, not a gap.

### 6.1 Open

#### P90-55.1 — `brix_vfs_file_fd()` retire-or-rule (§6.1, "the only real API change")

**Current state.** `brix_vfs_file_fd()` is still a live, non-deprecated accessor:
declared `src/fs/vfs/vfs.h:241`, defined `src/fs/vfs/vfs_open_handle.c:64`. It is
called from **~15 sites across 10 protocol files** (verified 2026-07-25):

```
src/protocols/webdav/methods_basic.c:187
src/protocols/shared/file_serve.c:313, 499
src/protocols/root/zip/zip_http.c:125, 148, 223, 261
src/protocols/s3/checksum.c:291, 386, 428
src/protocols/root/query/checksum_qcksum_path.c:525
src/protocols/s3/multipart_complete_upload_part_copy.c:363
src/protocols/s3/object.c:352
src/protocols/s3/object_meta.c:90
src/fs/vfs/vfs_writer.c:383            (internal — the writer's own fd)
```

(The sweep's "9 callers" undercounted; the accurate figure is ~15 call sites /
10 files.)

**The gap / the decision.** §6.1 wanted this accessor retired so no protocol code
handles a raw fd — everything would go through capability-gated read/send
helpers. **But the seam evolved differently:** the `read_sendfile_fd` vtable op
(`sd.h:380`) + `CAP_SENDFILE`/`CAP_MEMFILE` gating already provide the
capability-aware path the retirement was meant to force. So this is a *decision*,
not a mechanical must-do:
- **Option A (won't-do / ruling):** keep `brix_vfs_file_fd()` as the documented
  fast-path for `CAP_FD` backends (posix), where a raw fd is legitimate, and rule
  §6.1 satisfied-in-spirit by the capability gate. Cheapest; needs a written ADR.
- **Option B (retire):** convert the ~15 call sites to capability-aware helpers
  (`brix_sd_read_sendfile_fd`, checksum-over-obj, zip-over-obj), so an S3/memfile
  backend that lacks `CAP_FD` degrades cleanly instead of handing out `-1`.
  Mostly mechanical but touches checksum, zip, and sendfile paths.

**RULING (2026-07-27) — Option A adopted: keep-and-rule. RESOLVED.**

Audit of the call sites (all 10 files, 2026-07-27) confirms the retirement has
no remaining safety payoff:

- The accessor is already null-safe: `brix_vfs_file_fd()` returns
  `fh->obj.fd`, which is `NGX_INVALID_FILE` for fd-less handles
  (`vfs_open_handle.c:64`) — it cannot hand a protocol a *wrong* fd, only a
  sentinel.
- Callers either guard the sentinel explicitly (`object_meta.c`/`object.c`
  check `!= NGX_INVALID_FILE`; `file_serve.c` `dup()`s and error-paths on
  failure) or sit on paths reachable only with fd-backed handles (zip and
  qcksum operate on regular archive/source files; the multipart part-copy
  source is a posix staging object).
- The backend-neutral alternatives the retirement was meant to force already
  exist and are used where fd-less handles occur: `brix_vfs_file_pread`
  (multi-block/object reads) and the `read_sendfile_fd` vtable op +
  `CAP_SENDFILE`/`CAP_MEMFILE` gates pick the serve strategy per handle.

**The rule (binding for new code):** `brix_vfs_file_fd()` is the sanctioned
kernel-fd escape hatch for operations that inherently need a descriptor
(sendfile/`dup`, `fstat`, fd-based checksum/zip parsing). Every new call site
MUST either (a) guard `NGX_INVALID_FILE`, or (b) sit behind a capability gate
that guarantees fd-backed handles on that path. Anything that must work on
fd-less backends uses `brix_vfs_file_pread` / `brix_sd_*` ops instead. This is
not a licence for raw data syscalls on the fd outside `src/fs/backend/` — the
VFS-seam invariant (12) still applies; the fd is for kernel plumbing
(sendfile/dup/fstat), not for reimplementing reads/writes.

§6.1 of phase-55 is thereby satisfied-in-spirit by the capability gate; no
call-site conversion will be done.

#### P90-55.2 — storage-backend/staging directive grammar

**Current state.** Shipped as a `brix_storage_backend` name string (`""`/`posix`/
`pblock`, `shared_conf_types.h:50` sweep) + a boolean `storage_staging`
write-back flag + per-export registry keyed on `root_canon`
(`vfs_backend_registry.c`, sweep).

**The gap.** The plan's richer `posix|s3|same` grammar was never adopted; this is
already tracked as phase-89's "directive-grammar decision." A decision is owed on
whether the current name+flag surface is the final grammar or whether the
composable decorator stack should get first-class directive syntax.

> **RESOLVED 2026-07-27 (phase-89 close-out, ADR-3):** the current surface is
> ruled final — `brix_frm_*` directives stay as engine/adapter knobs (no
> `tape://` URL-param migration), pinned by `tests/test_frm_directive_pin.py`.
> See phase-89-design-backlog-burndown.md §D.1 + phase-64 §13c.

**Effort.** ~1 wk if a new grammar is pursued; ~0 if the current surface is ruled
final. *(Ruled final → 0; item closed.)*

#### P90-55.3 — capability-degradation metrics polish

**Current state.** Degradation behaviour is correct (readonly-backend wire test
green); the metric label coverage (`brix_sd_degraded_total` /
`brix_sd_unsupported_total`) is thin and overlaps the phase-71/89 tail.

**Approach.** Add low-cardinality (invariant 8) counters at the capability-gate
sites so operators can see when a backend degrades an op. **~small.**

---

## 7. Doc corrections needed (not yet applied)

> **APPLIED 2026-07-27.** Items 1–6 landed as inline `> SUPERSEDED` blockquotes
> in the six target docs. Item 7 verified: the `history-security-and-credentials.md`
> / `phase-72` / `phase-75` phase-70 references are factual timeline statements
> ("at the time, delegation was unbuilt") and need no edits.

Prefer inline `> SUPERSEDED:` blockquotes at stale claims over rewriting history,
per `phase-88` §1.

1. **`phase-88-open-work-audit.md` §5 (lines 188–191)** — the "Plan-only phases:
   **70** … **27/28** … **54/55**" clause is stale. Repoint to this doc: 54 fully
   landed, 55 substantially landed/exceeded, 27/28 substantially landed (residual
   = the §4 infra-blocked set it already tracks), 70 substantially landed
   (residual = STS/krb5/SSS origin legs + polish).
2. **`phase-70-full-credential-delegation.md`** — replace `Status: planned`; mark
   §5.5/§5.7 call-ready-but-deferred (cite the `DEFERRED` banners at
   `vfs_deleg.c:376` and `:432`), §5.6's missing identity injection + the
   unshipped `brix_backend_sss_keytab`, the `vfs_deleg.c`→`+vfs_deleg_bind.c`
   split, and cross-reference phase-82 P82.9 as the gridftp capture site.
3. **`phase-27-memory-safety-hardening.md`** — replace `PLAN — not yet begun`;
   mark F1/F2/F4/F5/F9 + W1/W2/W5/W8 DONE with the §3.0 anchors; correct the
   new-files table (`tests/lint_alloc.sh` → `tests/cmdscripts/lint_alloc.py`; add
   `safe_size.h`, `scoped.h`, `tests/fuzz/*`); cross-ref hyper-hardening §11.
4. **`phase-28-adversarial-hardening.md`** — replace `PLAN — not yet begun` with a
   `> SUPERSEDED:` map (A1-A4 → `tpc_*` + `net_target.c`; B1/B2 → `net_target.c`
   + `tpc_curl_setup.c`; C1 → `cms/server_auth.c`; D1 → `auth_sigv4_verify_crypto.c:263`;
   E1 → `admin_audit`; G1 → `propfind_walk.c`; G2 → `BRIX_RL_KEY_SUBJECT`; H8 →
   `test_security_redteam.py`); repoint the new-files table (`egress_policy.{c,h}`
   / `argv_guard.h` → `net_target.{c,h}` + `net_target.c::brix_net_host_chars_valid`);
   tick the satisfied Appendix-B checklist boxes.
5. **`phase-54-vfs-thread-safe-io-core.md`** — replace `PLAN ONLY (not
   implemented)` with LANDED as `brix_vfs_io_core` (note the `xrootd_*`→`brix_*`
   rename so grep-driven readers find `vfs_io_core.{h,c}`).
6. **`phase-55-storage-backend-abstraction.md`** — replace `PLAN — not yet
   implemented` with SUBSTANTIALLY LANDED as the `brix_sd_*` seam; note the §3.6
   two-store / `posix|s3|same` supersession by the phase-63/64 decorator stack,
   and that §6.1 (`brix_vfs_file_fd` retirement) is the one open remainder — now a
   retire-or-rule *decision* (§6.1 of this doc).
7. **Verify (flagged, not confirmed here):** `history-security-and-credentials.md`
   and the `phase-72`/`phase-75` burndown docs for stale "phase-70 delegation
   unbuilt" references now that bearer/x509 passthrough exist.

---

## 8. Recommended sequencing

Highest value, lowest risk first. Items are cross-referenced to their register IDs.

1. **Doc corrections (§7)** — pure editing, no build. Stops the next audit from
   re-flagging five landed phases as greenfield. **~½ d.**
2. **Phase-55 `brix_vfs_file_fd` ruling (P90-55.1)** — make the won't-do vs.
   retire decision *before* any code; capability gating likely already covers it.
   Audit the 10 files, write the ADR. **~½ d.**
3. **Phase-70 local polish (P90-70.4/.6/.7 + the two units from .9)** — in-gate
   chain re-verify, metrics mode dimension, reference doc, audience-matcher +
   exchange-TTL units. Small, local, no new infra. **~3–4 d.**
4. **Phase-70 SSS injection (P90-70.3)** — smallest of the three origin legs, no
   new container (reuses the SSS fleet). **~2–3 d.**
5. **Phase-27/28 local items (§3.1, §4.1)** — secret-page `MADV_DONTDUMP`,
   hash-chained audit, per-source quota, ADMIN path-scope test, W3 EVP
   consistency sweep. Each small; batch them. **~1 wk.**
6. **Origin-leg drives needing containers (P90-70.1 S3-STS, P90-70.2 krb5)** —
   medium; schedule with the phase-88 §4 k8s interop lab so the container work is
   shared. **~1.5–2 wk.**
7. **Infra-blocked (§3.2 / §4.2 = phase-88 §4 B-1/B-2/C-1-tail/C-2/B-3)** —
   unchanged; needs the CI/ASan/fuzz lanes, not local work. Out of this doc's
   actionable scope.
