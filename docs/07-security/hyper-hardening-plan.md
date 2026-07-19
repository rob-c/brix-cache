# Hyper-Hardening Plan — BriX (nginx-xrootd)

> **Status:** Proposed roadmap · **Authored:** 2026-07-17 · **Owner:** security workstream
>
> **Basis:** A five-track source reconnaissance (auth/credential ·
> network/TLS/protocol-parsing · input-validation/VFS · build/CI · credential
> forwarding). Every claim carries a numbered reference `[R#]` resolving to a
> clickable `file:line` in [§9 Reference index](#9-reference-index). Where a fix is
> shown as a code diff, the surrounding source was read directly; where described in
> prose, the change is anchored to a cited line but the exact patch is left to
> implementation to avoid transcription drift.
>
> **This is not a rescue.** BriX is already hardened to a high bar. The plan closes a
> small set of confirmed gaps, makes the *existing* safety net mandatory, and adds
> the next defense-in-depth layer — in that priority order.

> **Implementation status (2026-07-17, inline pass):**
> - **A-1 · Upstream TLS peer verification** — LANDED (fail-closed by default, 2026-07-18).
>   `brix_tls_ctx_enable_verify()` in `runtime_server.c` turns on `SSL_VERIFY_PEER` +
>   host pinning; belt-and-braces `SSL_get_verify_result()` guards in
>   `net/upstream/tls.c` and `net/proxy/connect_upstream.c`. The **fail-open default is
>   now closed**: `brix_server_setup_tls()` refuses (`nginx -t` `emerg`) a TLS leg that
>   is on without a CA — on BOTH legs — unless verification is explicitly disabled.
>   New directives `brix_upstream_tls_verify on|off` (redirector) and
>   `brix_tap_proxy_upstream_tls_verify on|off` (proxy), default **on**; the proxy leg
>   also gained the previously-missing `brix_tap_proxy_upstream_tls_ca` /
>   `brix_tap_proxy_upstream_tls_name` directives (the CTX fields existed but were
>   unsettable). No shipped/test config enables `upstream_tls` today, so nothing
>   regresses. Verified: `test_upstream_tls_verify.py` 11 green (5 source-assert +
>   6 config-gate across both legs), seam + cardinality clean. `[R79]`
> - **A-3 · S3 `GetObjectAcl` existence oracle** — LANDED. `s3_handle_get_acl()` no
>   longer emits its canned owner-`FULL_CONTROL` document for an unstatted key: object
>   `?acl` now threads the resolved `fs_path` and stats it (`brix_vfs_stat` via the
>   HEAD/tag VFS surface) before any body, answering `NoSuchKey` 404 for a missing key
>   or directory target; bucket `?acl` passes `NULL` and is unchanged. Sibling
>   canned responders swept — none were object-existence oracles (bucket versioning/ACL
>   are bucket-scoped, `?cors` already 404s, tagging GET already gates). Existence
>   oracle closed. `tests/test_s3_acl_authz.py` 5 green + `test_s3_tagging.py` 9
>   regression (14/14); seam + build clean.
> - **A-4 · Cleanse secret buffers** — LANDED. `OPENSSL_cleanse` on every post-read
>   return in the three `ucred.c` readers (token/s3/keyring), PLUS the step-2
>   `brix_sd_ucred_wipe()` helper wired into every backend/VFS/root/webdav/stage
>   consumer that finishes with a resolved credential (~20 sites); also fixed a latent
>   block-scoped dangling `ru.path` in `stage_engine.c`. Verified: clean build, seam OK,
>   symbol linked, `test_cmd_user_backend_cred.py` (5p/1s) + `test_delegated_cred.py`
>   (3p) green — no auth regression.
> - **A-6 · OCSP response size cap** — item 1 LANDED. The 64 KiB
>   `OCSP_MAX_RESPONSE_BYTES` cap (moved to `ocsp_internal.h`) is now enforced in
>   `do_ocsp_request()` via an `OCSP_REQ_CTX` +
>   `OCSP_set_max_response_length()`/`OCSP_sendreq_nbio()` loop, replacing the uncapped
>   one-shot read; `test_ocsp.py` 11 green. Item 2 (missing-nonce hard-fail) **LANDED**
>   (2026-07-18): `do_ocsp_request()` now hands the built request back via an
>   `OCSP_REQUEST **req_out` out-param (was freed internally, leaving the nonce branch
>   dead), and `check_ocsp_response()` gained an `int require_nonce` gate that denies a
>   nonce-less response instead of warning. Wired to `brix_ocsp_require_nonce on|off`
>   (default **off** — nonce-less CA responders are common, so opt-in);
>   `test_ocsp_require_nonce.py` 8 green.
> - **A-5 · TPC cred temp files off `/tmp`** — LANDED + HARMONIZED. All credential
>   stagers now route through ONE facility, `brix_cred_stage_write()` in
>   `src/core/compat/cred_stage.{c,h}` (pure libc; links into both the stream and
>   HTTP modules). It stages each secret in a 0600 file under a fail-closed per-uid
>   0700 tmpfs dir `/dev/shm/brix-creds.<euid>` (owner+mode enforced, never `/tmp`).
>   The three previously-duplicated mkstemp sites now delegate: native TPC
>   token-exchange (`tpc/outbound/tpc_token_exchange.c`), WebDAV TPC
>   (`protocols/webdav/tpc_cred_exchange.c`), and GSI proxy delegation
>   (`net/proxy/gsi_upstream.c` — thin named wrapper preserved for its 3 callers +
>   unit test); each cleanses its `body_buf`/PEM after staging (folds A-4).
>   Dedicated tests: `tests/c/test_cred_stage.c` (facility unit — 0600 file,
>   private-dir round-trip, loosened-mode rejected/EPERM, never-`/tmp`, EINVAL args;
>   wired into `c_simple_units` SPECS) + `tests/test_tpc_token_exchange_staging.py`
>   (live end-to-end over `nginx_lc_tpc_token_exchange.conf`: the A-5 directive
>   surface parses under `nginx -t`, a `Credential: token-exchange` COPY reaches
>   staging → 502 at a dead endpoint, and NO credential body leaks into `/tmp`).
>   No new directive.
> - **D-4 · CSPRNG `kXR_bind` sessids** — LANDED. `conn_init_slots_and_sessid`
>   (`root/connection/handler.c`) minted the sessid as `time|pid|ptr|ngx_random()` —
>   predictable in its first 8 bytes and leaking a heap pointer. Now all 16 bytes come
>   from `RAND_bytes`, failing closed (drop the connection) if the CSPRNG is unavailable.
>   `test_conf_sessions.py::test_d4_*` (valid-bind / forged-reject / unpredictable) green;
>   44 session-suite tests green.
> - **D-5 · JWKS `kid` authoritative** — LANDED. Removed the single-key leniency in
>   `token_select_key_by_kid` (`auth/token/validate_sig.c`): an asserted `kid` naming no
>   loaded JWKS key is now a hard reject (was: fall back to the sole key). Signature
>   always gated regardless, so this closes an authoritativeness gap, not a forgery. No
>   compat flag — the kid-absent rotation-grace trial covers every spec-faithful
>   single-key deployment. `test_wlcg_token_conformance_edge.py` E08/E09/E10 green; 27
>   malicious-credentials + multikey regression green.
> - **D-6 · Recursive tree-op depth cap** — LANDED. Audit found all three confined
>   tree recursions (`brix_fs_remove_tree_confined`, `brix_vfs_copytree`,
>   `brix_vfs_driver_rmtree`) recurse on the C stack UNBOUNDED (none via the capped
>   `vfs_walk_dir`). Added shared `BRIX_FS_TREE_MAX_DEPTH` (512, `fs_walk.h`); each split
>   into a depth-carrying core behind a depth-0 wrapper, recursion re-enters the core at
>   `depth + 1`, aborts `ELOOP` past the cap. `test_tree_depth_cap.py` 6 green + 21 live
>   regression (no wedge/crash).
> - **D-7 · Clone offset/length bounds** — LANDED. Negative/overflow guard in
>   `root/read/clone.c` → `kXR_ArgInvalid`; `test_new_opcodes_b.py::TestClone` 4/4 green.
> - **E-3 · Metric-label cardinality CI guard** — LANDED. `check_metric_cardinality.sh`
>   rejects any interpolated Prometheus label value outside a 26-name low-cardinality
>   vocabulary (INVARIANT #8), wired into `guards.yml`; a path/user/DN/IP-valued label
>   fails CI. `test_source_guards.py` real-tree pass + 3 injected fixtures green.
> - **D-2 · Opaque (CGI) schema validation** — LANDED (byte-hygiene + schema).
>   Tier 1 (always on): `brix_opaque_illegal_byte` (`opaque_validate.c`) rejects control /
>   high-bit / shell-metacharacter bytes in the CGI opaque at the central native kXR_open
>   edge (`brix_open_precheck`) before any handler parses, logs, or forwards it — closing
>   the log/CRLF-injection + TPC request-smuggling + command-injection class with zero false
>   positives (conforming clients percent-encode). Tier 2 (opt-in `brix_opaque_strict on`):
>   `brix_opaque_schema_check` type-enforces `oss.asize` as an unsigned int and rejects any
>   key outside the recognized XRootD namespace vocabulary, off by default so stock parity is
>   untouched. `test_conf_openflags.py` §L2 13 + C unit `test_opaque_schema` (10 asserts) +
>   `test_opaque_strict.py` 4 (incl. a strict-off parity case) all green → `kXR_ArgInvalid`.
> - **D-3 · seccomp-BPF worker syscall filter** — LANDED (audit + enforce). Tri-state
>   `brix_seccomp off|audit|enforce` (default off) installs a `libseccomp` allowlist per
>   worker at the tail of `init_process` (strictest mode across enabled server blocks
>   wins). Enforce `SCMP_ACT_KILL_PROCESS`es `execve`/`execveat`/`ptrace`/`process_vm_*`
>   and `EPERM`s any other non-allowlisted syscall (fail-safe); audit is log-only for
>   allowlist convergence. ngx-free core (`src/core/seccomp/seccomp_core.c`) so the shipped
>   tables are the ones tested; runtime string-resolved syscalls (arch/kernel-portable,
>   seam-clean); fails closed if built without libseccomp. C unit `test_seccomp.c` 7/7
>   (execve+ptrace SIGSYS-killed, chroot EPERM'd, audit no-kill, allowlisted survives) +
>   integration `test_seccomp_enforce.py` 3/3 (live kXR stat/GET/PUT under enforce **and**
>   audit prove allowlist completeness; bogus mode refused by `nginx -t`).
> - **E-4 · DoS resilience: negative-path backoff + per-identity rate-limiting** — LANDED.
>   *Part 1:* a sixth rate-limit key dimension `BRIX_RL_KEY_SUBJECT` (`key=subject`) throttles
>   a token-authenticated flood per WLCG/JWT `sub` (hashed `sub:<8 hex>`, INVARIANT #8; IP
>   fallback for anonymous), not just per-IP. *Part 2:* new opt-in directive
>   `brix_negcache_backoff off | <threshold> <window_s> <wait_s>` — a per-principal SHM
>   sliding-window counter of missing-path lookups (`kXR_stat`/`kXR_locate` → `NotFound`) that
>   arms past `threshold` and paces the principal to one served miss per `wait` interval (each
>   excess miss → `kXR_wait`), throttling a stat/locate-harvest loop to ~one path/`wait` while
>   never wedging a request (the client's wait-and-retry lands a served miss one interval
>   later) and never touching a legitimate rarely-missing client. ngx-free core
>   (`negcache_core.c`, `test_negcache.c` 4/4) + slab-allocated SHM wrapper (INVARIANT #10);
>   enforced at the `ENOENT`/not-found edges of `read/stat.c` + `read/locate.c`; fail-open.
>   `test_negcache_backoff.py` 3/3 over the raw wire (harvest trips backoff · other identity
>   unaffected · bogus config refused) + SUBJECT-key parse test; ratelimit suite 24/24,
>   seam + cardinality gates clean.
> - **D-1 · Protocol-downgrade protection** — LANDED. New per-server directive
>   `brix_min_sec_level none|compat|intense` (default `none`), a distinct axis from
>   `brix_security_level` (request *signing*): it enforces the negotiated *session's*
>   posture so a client cannot walk the connection below the operator's floor. `brix_tls`
>   only *advertises* an in-protocol TLS upgrade — a client may finish login/auth in
>   cleartext — so **compat** refuses a cleartext session every data op with
>   `kXR_TLSRequired`, and **intense** additionally refuses an anonymous (`auth=none`)
>   identity even over TLS with `kXR_NotAuthorized`. Enforced fail-closed in
>   `brix_min_sec_enforce()` (handshake/policy.c), wired into `brix_dispatch()` after the
>   session opcodes so the handshake is never blocked; pairs with **A-1** so neither leg
>   walks down. `test_min_sec_level.py` 4/4 (cleartext dropped · genuine in-protocol TLS
>   upgrade proceeds · anonymous-under-intense refused · bogus config rejected); sibling
>   suites 27/27, seam + cardinality gates clean.
> - **E-5 · Hardening-flag alignment + strcpy audit** — LANDED. Three guarded
>   `strcpy`→bounded-`memcpy` sites (`cvmfs/config/repo.c` ×2, `cvmfs/failover/failover.c`);
>   CMake fallback flags aligned with `./config` (FORTIFY/stack-clash/CET/noexecstack).
>   `test_cvmfs_conf_unit.py` green under `-Werror`.
> - **Build hardening flags (E-5 adjunct)** — `./config` now additionally probes and
>   appends two exploit-mitigation flags when `$CC` accepts them (portable across the
>   gcc/clang fleet): `-fzero-call-used-regs=used-gpr` (wipe call-used GPRs on return —
>   defeats ROP/JOP register harvesting; gcc 11+) and `-ftrivial-auto-var-init=zero`
>   (zero uninitialised automatics — kills a class of stack info-leaks; gcc 12+/clang).
>   On the RHEL-9 build host (gcc 11.5) the first is accepted, the second gracefully
>   skipped. Verified via the configure log + a clean module rebuild.
>
> - **B-3 · CI-drive the libFuzzer harnesses** — LANDED. `.github/workflows/fuzz.yml`:
>   blocking PR/push smoke (`FUZZ_TIME=60`) + nightly cron soak (600s) over the three
>   `tests/fuzz/` harnesses via the existing `cmdscripts.fuzz_all` runner. Standing up the
>   gate exposed and fixed a rotted harness: `fuzz_zip_dir` had stopped building after a
>   `sd_posix.c`→`sd_posix_io.c` file-split left its unity-build vtable unresolved — fixed
>   by pulling the split TU into the `#include` set. All three build + fuzz clean. Corpus
>   auto-grow-back deferred (needs a git-write bot).
>
> - **C-1 · Fuzz the unauthenticated auth parsers** — IN PROGRESS (2 harnesses landed).
>   (a) JWT/JWKS JSON: `tests/fuzz/fuzz_jwt_json.c` drives all five
>   `src/auth/token/json.c` helpers with hostile bytes as the pre-auth JWT/JWKS document
>   (out-cap, per-item [256] array truncation, fractional-NumericDate, exact aud match,
>   member probe), ~1.5 M runs clean. (b) Shared HTTP percent-codec:
>   `tests/fuzz/fuzz_urlcodec.c` drives `brix_http_urldecode`/`urlencode`
>   (`src/core/compat/uri.c`) — the byte core under S3 SigV4 canonicalisation, WebDAV
>   query parsing, and XrdHttp paths — with undersized-dst/malformed-`%HH`/round-trip
>   cases, ~950 K runs clean. Both wired into the B-3 `fuzz.yml` lane. Remaining targets
>   (GSI ASN.1, SSS frames, macaroon, top-level SigV4 canonicaliser) are nginx-coupled
>   and need a pure `(data,len)` entry carved from their TUs first (a production refactor
>   kept out of the additive fuzz work).
>
> Deferred (need an ASan lane, new CI, or new directives/process): A-2 (blocked on B-2 —
> static-inspection pass 2026-07-18 cleared all three named suspects), B-1 (analyzer
> workflows exist; blocking-flip needs a pinned CI toolchain baseline), B-2 (ASan lane),
> remaining C-1 targets + C-2 (framing fuzz — need pure-entry refactors; attach to the
> new B-3 lane).

---

## Table of contents

- [§0 How to read this](#0-how-to-read-this)
- [§1 Threat model](#1-threat-model-who-we-defend-against)
- [Phase A — Close confirmed vulnerabilities](#phase-a--close-confirmed-vulnerabilities) · A-1 … A-6
- [Phase B — Make the safety net mandatory](#phase-b--make-the-existing-safety-net-mandatory) · B-1 … B-3
- [Phase C — Expand attacker-facing coverage](#phase-c--expand-attacker-facing-coverage) · C-1 … C-3
- [Phase D — New defense-in-depth controls](#phase-d--new-defense-in-depth-controls) · D-1 … D-7
- [Phase E — Deployment safety & DoS resilience](#phase-e--deployment-safety-dos-resilience--hygiene) · E-1 … E-5
- [§6 Sequencing](#6-suggested-sequencing)
- [§7 New directives & config surface](#7-new-configuration-surface-introduced-by-this-plan)
- [§8 New observability](#8-new-observability-introduced-by-this-plan)
- [§9 Reference index](#9-reference-index)
- [§10 Deliberately untouched](#10-what-this-plan-deliberately-does-not-touch)
- [§11 Risk register (CWE/CVSS)](#11-risk-register--cwe--cvss--detectability)
- [§12 Config recipes](#12-configuration-recipes-secure-vs-insecure)
- [§13 Verification & repro commands](#13-per-item-verification--repro-commands)

---

## 0. How to read this

### Scoring key

| Field | Values |
|---|---|
| **Severity** | `CRIT` remote unauth compromise · `HIGH` remote MITM / memory-safety / auth-bypass · `MED` info-leak / local race / hardening-with-preconditions · `LOW` defense-in-depth / consistency |
| **Effort** | `S` hours · `M` 1–3 days · `L` >3 days or cross-cutting |
| **Type** | `BUG` · `GATE` (CI/process) · `COVERAGE` (test/fuzz) · `DEPTH` (new control) · `HYGIENE` (deploy/doc) |
| **Confidence** | `CONFIRMED` code read directly · `STRONG` recon + history corroborate · `NEEDS-REPRO` believed real, needs a live trigger |

### Per-item anatomy

Location · Current behaviour · Failure scenario (attack narrative) · Root cause ·
Fix (numbered steps, with diffs where read) · New directives/metrics · Edge cases ·
Test matrix (success / error / security-negative) · Acceptance · Effort breakdown ·
Deps / Rollback.

### Governance (from CLAUDE.md & coding-standards)

- Three tests per change: success + error + security-negative.
- No `goto`; early-return; functional/modular.
- Reuse HELPERS (path/auth/metrics/framing) — never reimplement.
- **No git write operations without explicit per-conversation approval.**
- New storage-plane raw syscalls need `/* vfs-seam-allow: <reason> */` and must pass
  `check_vfs_seam.sh` `[R68]`.
- New `.c` files go in repo-root `./config`; re-`./configure` only on source-list /
  `--with-*` changes; validate with `objs/nginx -t`.

---

## 1. Threat model (who we defend against)

| # | Actor | Position | Goal | Items |
|---|---|---|---|---|
| T1 | Remote unauth client | Opens a socket to any listener | Crash a worker; bypass auth; hit a pre-auth parser bug | A-2, C-1, C-2, C-3, E-1 |
| T2 | On-path network attacker | Between BriX and its upstream/origin | MITM the upstream hop; capture re-sent credentials | **A-1**, D-1 |
| T3 | Authenticated-but-limited client | Holds a valid token/cert for *some* scope | Escalate scope; traverse out of export; harvest metadata | A-3, C-3, D-2, E-4 |
| T4 | Local co-tenant | Shell on the same host / mount NS | Race a temp file; read a secret; symlink-swap | A-4, A-5, D-6 |
| T5 | Malicious/compromised upstream | The origin or a redirect target | Corrupt the proxy; feed a hostile response | A-2, A-1 |
| T6 | Future maintainer (regression) | Commits new code | Reintroduce a solved bug class | B-*, C-3, E-3 |

T6 is why Phase B ranks so highly: the cheapest CVE to prevent is the one a mandatory
gate refuses to merge.

---

# PHASE A — Close confirmed vulnerabilities

## A-1 · Verify upstream TLS peer certificates on the proxy & redirector legs — ✅ LANDED (fail-closed, 2026-07-18)

| Severity | Effort | Type | Confidence |
|---|---|---|---|
| **HIGH** | M | BUG | CONFIRMED (code read) |

> **LANDED (2026-07-18, fail-closed).** Steps 1–3 (context `SSL_VERIFY_PEER` + host
> pinning, pre-handshake `SSL_set1_host`, belt-and-braces `SSL_get_verify_result`) were
> already in the tree. This pass closed the remaining **fail-open default**:
> `brix_server_setup_tls` now refuses a TLS leg that is on without a CA (both the
> redirector and the tap-proxy leg) with an `nginx -t` `emerg`, unless verification is
> explicitly turned off. New flags `brix_upstream_tls_verify` /
> `brix_tap_proxy_upstream_tls_verify` (default **on**); the proxy leg also gained the
> missing `brix_tap_proxy_upstream_tls_ca` / `_name` directives (the CTX fields existed
> but had no parser). Tests: `test_upstream_tls_verify.py` 11 green. `[R79]` The full
> live-MITM handshake negatives (untrusted-chain / wrong-host abort with no `kXR_login`
> leak) rest on the already-landed R1–R12 crypto and a fake-TLS-origin fixture that is
> deferred; the config-gate suite covers the net-new fail-closed behaviour end to end.

**Evidence:** `[R1][R2][R3][R4][R5][R6][R7]` (the two broken legs + inert ctx build)
vs the four verifying callers `[R8][R9][R10][R11][R12]`.

**Location.** Redirector: `brix_upstream_start_tls()` `[R2]` and the done-callback
`[R1]`. Proxy: done-callback `[R3]`. Context build: `brix_server_setup_tls()` `[R4]`,
`ngx_ssl_create(...)` at `[R5][R6]`, optional CA at `[R7]`. Correct reference:
`brix_cache_origin_tls_upgrade()` `[R8][R9]`.

**Current behaviour.** Both upgrade paths call `ngx_ssl_create_connection()` with a
*shared* server-block context, set SNI, run the handshake, then proceed the instant
`uconn->ssl->handshaked` is true `[R1][R3]`. The context is built without
`SSL_CTX_set_verify(SSL_VERIFY_PEER)` `[R5][R6]`, and neither callback calls
`SSL_get_verify_result()` or `ngx_ssl_check_host()`. Loading a trust store `[R7]`
without `SSL_VERIFY_PEER` is **inert**: OpenSSL clients default to `SSL_VERIFY_NONE`,
so an untrusted / wrong-host chain completes the handshake. `handshaked` means "a TLS
session exists," not "the peer is trusted."

**Failure scenario (T2/T5).**
1. A site runs BriX as a redirecting cache with `upstream_tls on` and even sets
   `upstream_tls_ca`, believing the hop is authenticated.
2. An on-path attacker intercepts the TCP connection and presents *any* certificate
   (self-signed, or a valid cert for an unrelated host).
3. `brix_upstream_start_tls()` `[R2]` completes the handshake; the done-callback `[R1]`
   proceeds and **re-sends `kXR_login` over the attacker's channel** (the callback's
   own purpose is to re-login post-upgrade).
4. The attacker holds the client's credentials and relays/alters all traffic. The
   client sees a working "encrypted" session.

Provable outlier: `[R8][R9][R10][R11][R12]` all verify; only these two legs do not.

**Root cause.** Written to the `ngx_ssl_create_connection` idiom (shared ctx, async
handshake) rather than the per-connection idiom used by the verifying callers; the
verification step was never ported across.

**Fix.**

*Step 1 — enable verification when building the contexts* (in `brix_server_setup_tls`
after `[R5]` and `[R6]`):

```c
SSL_CTX_set_verify(xcf->proxy.tls_ctx->ctx, SSL_VERIFY_PEER, NULL);
if (xcf->proxy.upstream_tls_ca.len == 0 && xcf->proxy.upstream_ssl_verify) {
    ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
        "brix: proxy upstream_tls requires upstream_tls_ca (or "
        "proxy_ssl_verify off) — refusing an unauthenticated TLS upstream");
    return NGX_ERROR;                     /* fail closed by default */
}
```

Mirror for the redirector ctx after `[R6]`.

*Step 2 — bind the expected hostname before the handshake* (in `brix_upstream_start_tls`
`[R2]`, after `ngx_ssl_create_connection` and before `ngx_ssl_handshake`, mirroring
`[R9]`):

```c
SSL_set_hostflags(uconn->ssl->connection, X509_CHECK_FLAG_NO_PARTIAL_WILDCARDS);
if (SSL_set1_host(uconn->ssl->connection, sni) != 1) {
    return NGX_ERROR;
}
```

With `SSL_VERIFY_PEER` + `SSL_set1_host`, a chain **or** hostname mismatch fails the
handshake itself, so the existing `!handshaked` branch `[R1]` already aborts a MITM.
Do the same in the proxy `start_tls` sibling.

*Step 3 — explicit belt-and-braces check in the done-callbacks* (defense in depth, so
the trust decision is legible and survives refactors), after the `handshaked` check
in `[R1]` and `[R3]`:

```c
if (SSL_get_verify_result(uconn->ssl->connection) != X509_V_OK) {
    brix_upstream_abort(up, "upstream: TLS peer verification failed");
    return;
}
```

**New directives.** `proxy_ssl_verify on|off` (default **on**),
`upstream_ssl_verify on|off` (default **on**), plus an optional
`upstream_tls_name <host>` override already present for SNI. See [§7](#7-new-configuration-surface-introduced-by-this-plan).

**New metrics.** `brix_upstream_tls_verify_failures_total{leg="proxy|redirector"}` —
increment on the Step-3 abort. See [§8](#8-new-observability-introduced-by-this-plan).

**Edge cases.** (a) Legacy interop with a self-signed origin must set
`proxy_ssl_verify off` explicitly — document this loudly. (b) IP-literal upstreams:
`SSL_set1_host` with an IP requires the cert to carry an iPAddress SAN; support an
`upstream_tls_name` override for name-based verification of IP-addressed upstreams.
(c) Ensure `ngx_ssl_trusted_certificate` `[R7]` is still called so the store is
populated — Step 1 only flips the verify mode.

**Test matrix** (`tests/test_upstream_tls_verify.py`, new):
- *success* — CA-valid cert, matching SNI → session proceeds, bytes intact.
- *error* — self-signed / untrusted chain → handshake aborts; assert (via a capturing
  fake origin) that **no `kXR_login` byte reaches the upstream**; client gets a clean
  error, not a hang.
- *security-negative* — valid cert for the **wrong host** → aborts (this is the case
  `SSL_VERIFY_PEER` alone misses and `SSL_set1_host` catches). Also:
  `proxy_ssl_verify on` + no CA → `objs/nginx -t` fails `emerg`.

**Acceptance.** `nginx -t` rejects `upstream_tls on` without a CA unless verify is
explicitly off; wrong-host and untrusted-chain negatives both fail closed; existing
proxy/redirect suites unchanged.

**Effort breakdown.** Ctx + directive plumbing ~0.5d · callback checks ~0.5d · tests
(fake-origin cert fixtures) ~1d.

**Deps.** None. Enforcement half of **D-1** — land adjacent. **Rollback.**
`proxy_ssl_verify off` restores prior behaviour per server block.

---

## A-2 · WebDAV-proxy → stock-XrdHttp heap corruption

| Severity | Effort | Type | Confidence |
|---|---|---|---|
| ~~HIGH~~ **RESOLVED — surface retired** | — | BUG | CLOSED (transport deleted 2026-07-20) |

> **Resolution (2026-07-20) — surface retired, not patched.** The crash lived in
> the WebDAV **reverse-proxy transport** (`brix_webdav_proxy` /
> `brix_webdav_proxy_upstream` — nginx-upstream request/response relay). That
> transport had already been **retired** in the legacy-proxy cleanup: the
> directives were removed and the enabling flag `upstream_proxy` could no longer
> be set by any config, so `proxy_response.c`'s `webdav_proxy_process_header`
> (the crash site) was **unreachable dead code**. The live sibling on the
> reachable path — `mirror_process_header` (`http_mirror_request.c`) — uses the
> hardened *discard-headers* parse (`continue` on `NGX_OK`) and never performs
> the delimiter NUL-write, so there is no equivalent live OOB.
>
> Rather than leave a latent, never-root-caused heap defect as a footgun that a
> future revival could resurrect, the dead transport was **deleted** (2026-07-20):
> `proxy.c`, `proxy_response.c`, `proxy_request.c`, `proxy_config.c`,
> `proxy_internal.h`, `webdav_proxy.h` removed; the `upstream_*` loc-conf fields,
> the two orphaned setters (`webdav_conf_proxy_auth` / `_upstream`), the
> `webdav_merge_upstream_conf` merge, and the `upstream_proxy` gates in
> `dispatch.c` / `access.c` / `ratelimit_http.c` excised. `proxy_pool.c` (the SHM
> pool behind the REST admin API) was kept. Verified: clean `-Werror`+ASan build;
> `nginx -t` accepts a valid WebDAV config; **`brix_webdav_proxy` now fails with
> "unknown directive"** — the surface cannot be re-enabled via config.
>
> The original repro/inspection record is preserved below for archaeology; **B-2
> (ASan lane) is no longer a dependency for this item.**

**Evidence:** `[R13]`.

**Location.** `src/protocols/webdav/proxy_response.c` (response/header parse) `[R13]`.

**Current behaviour.** `xrootd_webdav_proxy` against a *stock* XrdHttp backend
intermittently corrupts the heap / SIGSEGVs; ~8/100 requests surface as 502 under
load. Reproduces only against the real XrdHttp response shape.

**Failure scenario (T5/T1).** A hostile or merely unusual backend response (header
ordering, chunk boundaries, an under-sized field) drives an out-of-bounds write in the
proxy's response accumulator. Worst case is not just the observed availability hit but
a potentially shapeable write primitive reachable from attacker-influenced input.

**Root cause.** Unknown until reproduced. Top suspects: (a) a length/offset computed
from a backend header used to size or index the accumulator; (b) a lifetime bug where
the body buffer is realloc'd/freed while a pointer into it stays live.

**Static-inspection pass (2026-07-18).** All three response-path accumulators named
as suspects were read and audited clean — no inspectable OOB write or use-after-free:
- `webdav_proxy_process_header` (`proxy_response.c:94`) is a faithful copy of stock
  nginx `ngx_http_proxy_process_header`; the two `data[len] = '\0'` NUL writes land on
  the delimiter byte the parser already consumed inside `u->buffer` (same invariant
  stock relies on), and the status-line copy (`:71`) is an exact-length
  `ngx_pnalloc`+`ngx_memcpy`.
- `xrdhttp_digest_body_filter` (`xrdhttp_tpc.c:197`) only *reads* the body (adler32 over
  each in-memory buf); the trailer alloc `sizeof("adler32=")-1 + 8 + 1 = 17` exactly
  fits `ngx_sprintf(v, "adler32=%08xD", …)`.
- `xrdhttp_add_checksum_header` (`xrdhttp_tpc.c:141`) writes only via bounded
  `brix_integrity_format_http_digest(&info, hdr_value, sizeof(hdr_value))` /
  `brix_sanitize_log_string(..., sizeof(safe_alg))`.

Confirms the plan's premise: this is a **load-dependent** corruption (~8/100, real
XrdHttp shape only) that inspection alone will not localise — it must be caught in the
act under ASan. **Remains blocked on B-2**; no guess-fix will be applied (a larger
buffer or speculative bound would violate "must be *found*" and mask the real defect).

**Fix (method, not guess — this one must be *found*).**
1. Bring up the hybrid mesh under ASan (build `SANITIZE=1`, `manage_test_servers.sh
   restart` `[R32]`); drive the WebDAV-proxy→XrdHttp path in a loop until ASan fires.
   **B-2 makes this routine.**
2. From the ASan report, fix the bound or the lifetime — do **not** paper over it with
   a larger buffer.
3. Add a regression test that replays the exact triggering response shape.

**Edge cases.** Confirm the fix also covers chunked *and* Content-Length framings, and
a response with no body. Check for the same pattern in the sibling S3/CVMFS proxy
response parsers.

**Test matrix** (`tests/test_webdav_proxy_xrdhttp.py`, extend):
- *success* — 1000 sequential GET/PUT/PROPFIND via the proxy, ASan-clean, zero 502s.
- *error* — truncated/oversized header block → clean 502, no crash.
- *security-negative* — crafted header set targeting the corrupting field → ASan-clean.

**Acceptance.** ASan-clean over ≥1000 mixed requests; `MEMORY.md`
`hybrid_mesh_webdav_proxy_xrdhttp_crash` moves to *Fixed*.

**Effort breakdown.** Repro under ASan ~1d (once B-2 exists) · fix + regression ~1–2d.

**Deps.** **B-2** (ASan lane) — sequence A-2 to *start* in parallel but land after
B-2 is available. **Rollback.** n/a (pure fix).

---

## A-3 · Confirm S3 `GetObjectAcl` (and canned-200 siblings) run behind the authz gate — ✅ LANDED (2026-07-17)

| Severity | Effort | Type | Confidence |
|---|---|---|---|
| **MED** | S | BUG | STRONG |

> **Status — LANDED (2026-07-17, inline pass).** The audit confirmed the real
> defect: `s3_handle_get_acl()` produced its canned owner-`FULL_CONTROL`
> `AccessControlPolicy` with HTTP 200 for **any** object key without ever
> statting it — an existence oracle (200-vs-404) over data the caller cannot
> read, fully unauthenticated on an anon bucket. **Fix:** the handler now takes an
> `fs_path` (object `?acl` passes the resolved key; bucket `?acl` passes `NULL`),
> and for an object it stats the key through the same VFS surface the HEAD/tag
> paths use (`s3_tag_vfs_ctx` + `brix_vfs_stat`) **before** any document is
> produced — a missing key or a directory target answers `NoSuchKey` 404, exactly
> like `s3_handle_get_object_tagging`. Object dispatch
> (`handler_object_route.c` `s3_dispatch_object_get`) now threads `fs_path`;
> bucket dispatch (`handler_dispatch.c` `s3_dispatch_bucket_get`) passes `NULL`
> and its canned bucket ACL is unchanged (it has no per-object target).
> **Sibling sweep:** the neighbouring canned responders were reviewed and are
> *not* object-existence oracles — `GetBucketVersioning`/`GetBucketAcl` are
> bucket-scoped (no per-object key), `GET ?cors` already returns the honest
> `NoSuchCORSConfiguration` 404, and the tagging GET already gates on
> `s3_tag_load(...) < 0 → NoSuchKey`. Only `GetObjectAcl` bypassed the gate.
> **Tests:** `tests/test_s3_acl_authz.py` (5) — existing-object → 200 FULL_CONTROL
> (success), absent key → 404 NoSuchKey with no FULL_CONTROL leak (error), no
> existence-oracle + directory-target → 404 + bucket ?acl still canned 200
> (security-negative). 14/14 green with the full `test_s3_tagging.py` regression;
> VFS seam clean; build clean. Item 3 (make 404-missing vs 403-unauthorized
> indistinguishable) is **not applicable to this gateway**: per-object S3 ACL
> *authorization* is deferred to XrdAcc/tokens at the data path, so the only leak
> present was existence (now closed); there is no separate per-object 403 verdict
> for `?acl` to converge with.

**Evidence:** `[R14][R15][R16]`; anon-mode context `[R55]`.

**Location.** `s3_handle_get_acl()` `[R14]` returns a canned owner/`FULL_CONTROL` ACL;
the handler's own comment states "the gateway authorizes via XrdAcc/tokens, not
per-object S3 ACLs" `[R15]`; dispatched from `s3_dispatch_bucket_get` at `[R16]`.

**Current behaviour.** `?acl` GET returns a fixed document with HTTP 200. SigV4 verify
(`s3_verify_sigv4`) authenticates the *requester*, but per-key **authorization** is a
separate gate. If the canned 200 is emitted for any existing key without the object
authz check, the 200-vs-404 distinction leaks object existence to a requester who
cannot read the object. Note anon buckets (`access_key.len==0`) pass SigV4 with **zero
verification** `[R55]`, so on such a bucket the oracle is fully unauthenticated.

**Failure scenario (T3, or T1 on an anon bucket).** `GET /bucket/secret-key?acl` — if
it short-circuits to the canned 200 for any present key, the attacker enumerates the
namespace by presence (200 = exists, 404/403 = not), an existence oracle over data
they cannot read.

**Root cause.** A canned-response op reachable before, or bypassing, the shared object
authz gate — the S3 sibling of the C-3 "return before verdict" class.

**Fix.**
1. Trace `[R16]` → `s3_handle_get_acl` `[R14]`; assert the request has passed SigV4/
   bearer verify **and** the object authz gate on the resolved key before the canned
   document is produced. If not, route it through the same gate the object `GET` uses.
2. Sweep the neighbouring canned-200 responders (bucket versioning `[R14]`-adjacent,
   location, CORS, tagging GETs) for the same shape and fix uniformly.
3. Ensure a **404 (missing)** and a **403 (unauthorized-but-present)** are
   indistinguishable in body/timing where the threat model requires it.

**Test matrix** (`tests/test_s3_acl_authz.py`, new):
- *success* — authorized SigV4 `?acl` on a readable key → 200 canned doc.
- *error* — `?acl` on a **missing** key → 404.
- *security-negative* — unauth/unauthorized `?acl` on an **existing** key → 403, never
  a 200 that reveals existence; repeat on an anon bucket `[R55]`.

**Acceptance.** No S3 canned-200 responder returns before the authz gate; existence
oracle closed.

**Effort breakdown.** Trace + gate wiring ~0.5d · sibling sweep ~0.5d · tests ~0.5d.

**Deps.** None. **Related.** C-3 (same anti-pattern, other protocols). **Rollback.** n/a.

---

## A-4 · Zeroize per-user backend secrets after use — ✅ LANDED (2026-07-17)

| Severity | Effort | Type | Confidence |
|---|---|---|---|
| **MED** | S | BUG | ✅ LANDED (2026-07-17) |

**Status — LANDED (2026-07-17).** Step 1 (reader cleanses in `ucred_read_token/_s3/
_keyring`) and step 2 (`brix_sd_ucred_wipe()` helper — `OPENSSL_cleanse`s `bearer`,
`s3_sk`, `ceph_keyring`; NULL-safe) both shipped. `brix_sd_ucred_wipe` is now called
from **every** consumer that finishes with a resolved credential: VFS gate sites
(`vfs_open`, `vfs_staged`, `vfs_stat` ×2, `vfs_dir`, `vfs_rename`, `vfs_unlink`,
`vfs_copy` ×2, `vfs_mkdir` ×3, `vfs_xattr` ×4), root read path
(`open_resolved_file_open`, `open_request` ×2), `http_serve_offload` (after the
detached-copy into task ctx), the WebDAV `$brix_delegated_cred` variable and TPC
user-proxy resolver (both decline- and success-tail wipes), and `stage_engine`.
**Bonus fix:** `stage_engine.c` held a latent dangling-pointer bug — `ru`
(`brix_sd_ucred_t`) was block-scoped but its `.path` was borrowed by `sdcred` and
consumed by `stage_engine_move()` outside the block; hoisted `ru` to function scope
(zero-inited) and wipe after the move. Verified: clean build, VFS-seam guard OK,
symbol linked, `test_cmd_user_backend_cred.py` (5 pass/1 skip) +
`test_delegated_cred.py` (3 pass) green — no auth regression. Step 4 (TPC body-buffer
cleanse) folds into A-5.

**Evidence:** `[R17][R18][R19][R20][R21]`; contrast the 49 cleanse sites elsewhere.

**Location.** `ucred_read_token()` `[R17]`, `ucred_read_s3()` `[R18]` (holds the S3
**secret key**), `ucred_read_keyring()` `[R19]`; caller-lifetime of `brix_sd_ucred_t`.

**Current behaviour.** Each reader slurps the raw credential file into a stack buffer,
copies the wanted field into the output struct, and returns **without cleansing the
buffer** `[R17][R18][R19]`. The file content — including the secret key and the full
first chunk of a keyring — is left on the worker stack; the extracted secret in
`out->bearer`/`out->s3_sk`/`out->ceph_keyring` is never wiped by the consumer. Lone gap
against an otherwise strong zeroization discipline.

**Failure scenario (T4).** A later stack frame, a core dump, or a heap/stack info-leak
in an *unrelated* bug reads back a live bearer token or S3 secret that should have been
erased on consumption. Defense-in-depth: minimize secret residency.

**Root cause.** Readers treat the scratch buffer as ordinary I/O scratch, not
secret-bearing memory.

**Fix.**
1. `OPENSSL_cleanse(buf, sizeof(buf))` before **every** return in the three readers
   `[R17][R18][R19]`. Early-return + no-`goto` house rule → cleanse before each
   `return`, or wrap so the buffer is cleansed once at the tail:

   ```c
   /* before each return in ucred_read_token [R17] */
   OPENSSL_cleanse(buf, sizeof(buf));
   ```
2. Add `brix_sd_ucred_wipe(brix_sd_ucred_t *)` that `OPENSSL_cleanse`s `bearer`,
   `s3_sk`, `ceph_keyring` (and any other secret field); call it from every backend
   site that finishes with a resolved credential.
3. Audit callers for the documented footgun: `brix_sd_ucred_resolve` leaves output
   fields untouched on DECLINED `[R21]`; `brix_sd_ucred_select` already
   `memset(out, 0, …)` `[R20]`, but every *direct* `brix_sd_ucred_resolve` caller must
   zero-init `out` first or risk reading uninitialized `expired`/secret fields.
4. **Also cleanse the TPC body buffer** `[R22]` — `body_buf[4096]` holds the JWT
   `subject_token` and is not wiped after the file write (folds into A-5's work).

**Test matrix** (`tests/test_ucred_zeroize.py` + a C unit if a harness exists):
- *success* — a resolved bearer/S3 credential is used by the backend exactly as today.
- *error* — malformed `.s3` (missing secret line) → DECLINED, scratch cleansed.
- *security-negative* — instrumented/valgrind assertion that the reader's scratch is
  zero after return.

**Acceptance.** `grep OPENSSL_cleanse src/fs/backend/ucred.c` covers all three readers;
`brix_sd_ucred_wipe` exists and is called by every consumer.

**Effort breakdown.** Reader cleanses ~0.25d · wipe helper + caller wiring ~0.5d ·
tests ~0.25d.

**Deps.** None. **Rollback.** n/a.

---

## A-5 · Move TPC credential temp files off shared `/tmp` — ✅ LANDED (2026-07-17)

| Severity | Effort | Type | Confidence |
|---|---|---|---|
| **MED** | S | BUG | CONFIRMED (code read) |

**Evidence:** `[R22][R23][R24][R25][R26]`.

**Location.** `tpc_rfc8693_stage_body()` — `body_buf` holds the JWT `[R22]`, `/tmp`
template `[R23]`, `mkstemp` `[R24]`; WebDAV sibling `[R25]`. Private-dir helper `[R26]`.

**Current behaviour.** TPC credential exchange writes a **live bearer/subject token or
X.509 proxy** to a `mkstemp` file so a subprocess can read it — a deliberate, good
choice to keep it off the process cmdline (`[R22]` docblock). Mitigations present:
0600, unpredictable name, `unlink` on every exit path. The residual issue is the
**directory**: the template is `/tmp/tpc_token_body_XXXXXX` `[R23]`, world-traversable,
so a co-tenant in the same mount NS can `open()` the inode during the subprocess window.

**Failure scenario (T4).** A co-tenant loops opening predictable-shape `/tmp` temp
files; during the millisecond the credential exists with the child holding it open,
the co-tenant opens the same inode by name and reads the live token. Name-
unpredictability shrinks but does not close the window.

**Root cause.** Stage directory defaults to world-traversable `/tmp` rather than the
already-existing 0700 per-worker dir.

**Fix.**
1. Stage into the **0700 per-worker credential dir** (`/dev/shm/brix-creds`, ensured by
   `brix_shared_credential_dir_ensure` `[R26]`) instead of `/tmp` `[R23]`. A 0700
   parent removes the co-tenant `open()` entirely.
2. Where the child accepts an fd rather than a path, prefer
   `memfd_create(..., MFD_CLOEXEC)` and pass the fd — no filesystem name at all.
3. Keep 0600 + prompt-`unlink` belt-and-braces; cleanse `body_buf` `[R22]` (shared with
   A-4).

**New directive.** `tpc_credential_staging_dir <path>` (default the 0700 shm dir); a
legacy `= /tmp` escape hatch for sites that need it.

**Edge cases.** `/dev/shm` may be `noexec`/small — the body is tiny, fine; if `/dev/shm`
is unavailable, fall back to `$TMPDIR` under a freshly-`mkdir(…,0700)` per-worker
subdir, never bare `/tmp`.

**Test matrix** (`tests/test_tpc_cred_staging.py`, new; multiuser fleet):
- *success* — TPC pull/push with credential forwarding works unchanged.
- *error* — stage dir missing/unwritable → clean failure, **no `/tmp` fallback**.
- *security-negative* — assert the stage path's parent dir mode is 0700 and no cred
  material ever lands under a world-traversable directory.

**Acceptance.** No TPC credential file under `/tmp`; parent 0700 worker-owned or the
secret is a `memfd`.

**Effort breakdown.** Path swap + dir ensure ~0.5d · memfd variant ~0.5d · tests ~0.5d.

**Deps.** Shares `body_buf` cleanse with A-4. **Rollback.** `tpc_credential_staging_dir
/tmp`.

---

## A-6 · Enforce the OCSP response size cap (and missing-nonce policy) — ✅ LANDED (both items, 2026-07-18)

| Severity | Effort | Type | Confidence |
|---|---|---|---|
| **MED** | S | BUG | ✅ LANDED — item 1 (2026-07-17), item 2 (2026-07-18) |

**Status — item 1 LANDED (2026-07-17); item 2 LANDED (2026-07-18).** The response
size cap is now enforced: `OCSP_MAX_RESPONSE_BYTES` (64 KiB) moved from an unused
`#define` in `ocsp.c` into the shared `ocsp_internal.h`, and `do_ocsp_request()`
(ocsp_request.c) replaced the one-shot `OCSP_sendreq_bio()` (which read under only
OpenSSL's internal default cap) with a driven `OCSP_REQ_CTX`: `OCSP_sendreq_new()` →
`OCSP_set_max_response_length(rctx, OCSP_MAX_RESPONSE_BYTES)` →
`OCSP_sendreq_nbio()` retry loop → `OCSP_REQ_CTX_free()`. On failure/over-cap the
partial `OCSP_RESPONSE` is freed and NULL returned. Tests: `tests/test_ocsp.py`
`TestOCSPResponseSizeCap` (cap-applied / over-cap-freed / no-uncapped-oneshot) — 11
green.

**Item 2 (missing-nonce hard-fail) LANDED (2026-07-18).** The nonce branch was
formerly dead: `do_ocsp_request()` freed the request before returning, so
`check_ocsp_response()` ran with `req_for_nonce == NULL`. The fix threads the built
request out of `do_ocsp_request()` via an `OCSP_REQUEST **req_out` out-param (owned
and freed by the caller at both live sites in `ocsp.c`), so the nonce survives to
the verify step. `check_ocsp_response()` gained an `int require_nonce` gate: when
set, a response that omits the request nonce (`OCSP_check_nonce < 0`) frees the
BASICRESP and returns -1 (deny) instead of warning through. A nonce *mismatch*
(`== 0`) already denied unconditionally and still does. The gate is wired to a new
`brix_ocsp_require_nonce on|off` stream directive plumbed through
`brix_ocsp_conf_t.require_nonce` (init `NGX_CONF_UNSET`, merge default **0/off**)
and threaded `auth.c → brix_ocsp_check_cert → ocsp_check_urls`; the staple-fetch
loop passes `require_nonce = 0`. **Default OFF, not on**: most CA responders serve
pre-signed, nonce-less responses, so a hard-fail-by-default would break interop —
the operator opts in per the D-2/opaque-strict precedent. Tests:
`tests/test_ocsp_require_nonce.py` — 8 green (request threaded out · mismatch always
denies · missing-nonce denies only when required · conf default-off · directive
registered · `nginx -t` on/off parse + non-flag rejected).

**Evidence:** `[R27]` (cap defined, unwired).

**Location.** `OCSP_MAX_RESPONSE_BYTES` (64 KiB) defined at `[R27]` but not applied on
the OCSP HTTP response read; missing-nonce is warn-only.

**Current behaviour.** The cap constant exists `[R27]` but the fetch read applies no
explicit byte cap; a *missing* response nonce only warns. Bounded today only because
the AIA URL comes from an already-verified certificate — and OCSP fetches are typically
plaintext HTTP, so the transport itself is MITM-able.

**Failure scenario (T2).** A responder or a MITM of the plaintext OCSP fetch returns an
unbounded body → memory growth / DoS on the worker doing the revocation check.
Separately, a stripped nonce allows replay of a captured OCSP response.

**Root cause.** Cap and strict-nonce policy specified but never wired into the transport
read / verification decision.

**Fix.**
1. Enforce `OCSP_MAX_RESPONSE_BYTES` `[R27]` in the response read loop — abort once the
   cap is exceeded.
2. In hard-fail OCSP mode, treat a *missing* response nonce as a failure, not a warning.

**New directive.** `ocsp_response_max_bytes <size>` (default 64 KiB) to make the cap
tunable — deferred (compile-time cap ships now). `brix_ocsp_require_nonce on|off`
(default **off** — opt-in; nonce-less CA responders are common) — LANDED.

**Test matrix** (extend the OCSP suite):
- *success* — well-formed, correctly-sized, nonce-matching response verifies.
- *error* — oversized response → fetch aborts within the cap, revocation fails cleanly.
- *security-negative* — nonce-stripped (replay) response in hard-fail mode → deny.

**Acceptance.** No unbounded OCSP read; missing-nonce denies under hard-fail.

**Effort breakdown.** Read-loop cap ~0.25d · nonce policy ~0.25d · tests ~0.5d.

**Deps.** None. **Rollback.** Soft-fail default remains available.

---

# PHASE B — Make the existing safety net mandatory

Process, not product. The tooling exists; today it is advisory. Making it a wall is the
cheapest large risk-reduction available (defends T6).

## B-1 · Static analyzers: blocking, per-PR, pinned

| Severity | Effort | Type | Confidence |
|---|---|---|---|
| **HIGH** | S | GATE | CONFIRMED |

**Evidence:** `[R28][R29][R30][R31]`.

**Current behaviour.** `fanalyzer.yml` (gcc `-fanalyzer`) and `codechecker.yml`
(Clang SA + clang-tidy) both run `continue-on-error` on a **weekly cron only**
`[R28][R29]`; `fanalyzer.yml`'s header notes it already caught a real NULL-deref — i.e.
a memory-safety bug *did* merge. The blocking per-PR gate `guards.yml` `[R30]` runs
only the invariant guards, not the analyzers. The ratchet baselines `[R31]` already work
(fail only on *new* findings vs a frozen baseline).

**Fix.**
1. Add `pull_request` + `push` triggers to both analyzer workflows (mirror `[R30]`).
2. Remove `continue-on-error` `[R28][R29]` so a new finding is red.
3. **Pin the toolchain** — clang 21.x to match dev, a fixed gcc — so results are
   reproducible and the baseline is stable across runners (the codechecker header
   explicitly blocks on this).
4. Keep the ratchet `[R31]`: frozen entries stay; only *new* findings fail; never
   hand-edit a baseline to silence a failure.

**Cost control.** Scope the analyzer compile to changed translation units on PRs; full
sweep on cron. A configured nginx build (`NGX_BUILD`) is a prerequisite — cache it.

**Test.** A throwaway PR with a deliberate leak/UAF/NULL-deref turns the gate red;
revert → green; a clean PR needs no baseline regen.

**Acceptance.** Both analyzers block merges on new findings; toolchain pinned in the
workflow.

**Effort breakdown.** Trigger/flag edits ~0.25d · toolchain pin + build cache ~0.5d ·
scoped-compile logic ~0.5d.

**Deps.** None. **Rollback.** Revert trigger/continue-on-error change.

---

## B-2 · CI ASan + UBSan test lane

| Severity | Effort | Type | Confidence |
|---|---|---|---|
| **HIGH** | M | GATE | CONFIRMED |

**Evidence:** `[R32][R33]`.

**Current behaviour.** Runtime wiring exists — `manage_test_servers.sh` sets
`ASAN_OPTIONS`/`UBSAN_OPTIONS` and expects a `SANITIZE=1` build `[R32]`, plus a race
harness `[R33]` — but **no CI job runs any of it**. The remotely-reachable heap
corruption A-2 sits open precisely because nothing exercises the code under ASan.

**Fix.**
1. Add a CI lane building `-fsanitize=address,undefined`, running the **fast tier** on
   every PR against the sanitized fleet.
2. On cron, run the **slow/chaos/resilience tier** (~1,770 tests) under ASan+UBSan —
   where fault-injection surfaces A-2-class bugs.
3. Wire `ASAN_OPTIONS=abort_on_error=1:detect_leaks=1` and
   `UBSAN_OPTIONS=halt_on_error=1:print_stacktrace=1` so any finding fails the job.

**Edge cases.** Sanitizer builds are 2–3× slower and memory-hungry — scope the PR lane
to the fast tier; watch for LSan false positives from nginx's own pools (suppress with
a curated `lsan.supp`, reviewed).

**Test.** Lane green on `main`; goes red on the A-2 repro before A-2's fix (a natural
joint acceptance test).

**Acceptance.** PRs run a blocking ASan+UBSan fast-tier gate; cron runs the sanitized
slow tier.

**Effort breakdown.** Build target ~0.5d · fleet integration ~1d · suppressions + tuning
~0.5d.

**Deps.** Provides the repro capability A-2 needs. **Rollback.** Demote to cron-only if
PR latency is unacceptable, but keep it blocking on cron.

---

## B-3 · CI-drive (and grow) the libFuzzer harnesses — ✅ LANDED (smoke + nightly lane, 2026-07-18)

| Severity | Effort | Type | Confidence |
|---|---|---|---|
| **MED** | S | GATE | CONFIRMED |

**Evidence:** `[R34][R35]`.

**What landed.** `.github/workflows/fuzz.yml` — a **blocking** PR/push smoke that
builds all three harnesses `clang -fsanitize=fuzzer,address,undefined` and replays
their committed corpora (`FUZZ_TIME=60` each), plus a nightly cron soak
(`FUZZ_TIME=600`). Driven by the existing `python3 -m cmdscripts.fuzz_all` runner so
CI and local `PHASE81_RUN_FUZZ_PORT=1 pytest test_cmd_fuzz_all.py` share one build
path. Unlike `fanalyzer.yml` this lane is blocking, not advisory: the harnesses are
self-contained deterministic clang builds with no version-sensitive baseline, so a
finding is a real reproducible fault.

**Harness rot found & fixed in the same change.** Standing up the lane immediately
surfaced why "run them in CI" mattered: `fuzz_zip_dir` no longer **built**. A
concurrent file-split had carved the raw fd byte ops out of `sd_posix.c` into
`sd_posix_io.c`, so the harness's unity build (`#include "…/sd_posix.c"`) left the
`brix_sd_posix_driver` vtable's `sd_posix_pread/…/fstat` slots unresolved at link.
Fix: add `#include "…/sd_posix_io.c"` to the unity build (the ns ops stay compiled
out under `XRDPROTO_NO_NGX`). All three harnesses now build + fuzz clean. This is the
canonical argument for the gate — an un-run harness silently rotted.

**Current behaviour (pre-landing).** Three harnesses exist with corpora — `fuzz_zip_dir`,
`fuzz_b64url`, `fuzz_safe_size` `[R34]` — built `clang -fsanitize=fuzzer,address,
undefined`; the README states the real attack surface is the wire parsers `[R35]`.
Nothing ran them in CI.

**Fix.**
1. ✅ CI **fuzz smoke**: each harness ~60s against its committed corpus on every PR; any
   new crash/leak fails. — *done (`fuzz.yml`, blocking).*
2. ⏳ **Nightly** longer run — *done (600s cron)*; corpus minimization **committed back**
   so coverage compounds is **deferred**: it needs a write-back bot (a CI job that
   `git commit`s minimized corpora), which is a git-write automation to add under its own
   review, not folded into the scaffold.
3. This same lane hosts the *new* C-1/C-2 harnesses as they land.

**Test.** A seeded crashing input in a scratch harness fails the smoke; removing it
passes. *(Verified live: the pre-existing `fuzz_zip_dir` link break is exactly the
"harness stopped working" failure mode the smoke now catches — it was red before the
`sd_posix_io.c` unity-build fix, green after.)*

**Acceptance.** Three harnesses run in CI; corpora are version-controlled *(corpus
auto-grow-back deferred, see Fix 2)*.

**Effort breakdown.** Smoke job ~0.5d · nightly + corpus-commit ~0.5d.

**Deps.** Shares the sanitizer toolchain with B-2. **Rollback.** Remove the job.

---

# PHASE C — Expand attacker-facing coverage

Wire parsing is already well-bounded — per-opcode `dlen` caps *before* allocation
`[R41][R42]`, `SIZE_MAX-1` overflow guards `[R43]`, overflow-checked `readv` multiply
`[R44]` with a 256 MiB total cap `[R45]`, signed-`rlen` trap `[R46]`. The gap is fuzz
*reach* into the auth parsers, and one recurring logic-bug class.

## C-1 · Fuzz the unauthenticated auth parsers — 🔶 IN PROGRESS (JWT-JSON + shared percent-codec landed 2026-07-18)

| Severity | Effort | Type | Confidence |
|---|---|---|---|
| **HIGH** | L | COVERAGE | CONFIRMED (2 harnesses landed: JWT-JSON, percent-codec) |

**Why first.** They parse attacker-controlled bytes **before** authentication — the
highest-value remote surface (T1), several hand-rolled.

**Targets, priority order.**
1. **GSI / X.509 ASN.1 from wire** — `parse_x509_signed.c` sizes a decrypt blob from
   `EVP_PKEY_size()` on an **attacker-supplied** pubkey `[R36]`; plus
   `parse_x509_unsigned.c`, `parse_crypto_helpers.c`.
2. ✅ **JWT JSON claim/key extraction** — `json.c` `[R37]`, `b64url.c` *(b64url already
   fuzzed by `fuzz_b64url`)*. **LANDED:** `tests/fuzz/fuzz_jwt_json.c` drives all five
   `json.c` helpers (`json_get_string` out-cap, `json_get_string_array` per-item [256]
   truncation, `json_get_int64` fractional-NumericDate, `json_string_or_array_contains`,
   `json_has_member`) with hostile bytes as the JWT/JWKS document, seeded from realistic
   claim/JWKS/`aud`-array/`crit` corpora; ASan+UBSan-clean over ~1.5 M runs. *Correction
   to the plan text: `json.c` is jansson-backed (thin bounds-checking wrappers), not a
   hand-rolled parser — the harness exercises those wrapper bounds and jansson itself.*
3. **SSS credential frames** — `auth_request.c` `[R38]` (the phase-79 bug lived here),
   `auth_crypto_helpers.c`.
4. **Macaroon parse** — `macaroon_parse.c` `[R39]`, `macaroon_caveats.c`.
5. **S3 SigV4 canonicalization** — `auth_sigv4_canonical.c` `[R40]`, `auth_sigv4_parse.c`.
   **PARTIAL:** the shared percent-codec beneath the canonicaliser — `brix_http_urldecode`
   / `brix_http_urlencode` (`src/core/compat/uri.c`), the byte-handling core the SigV4
   canonical query string, WebDAV query parsing, and XrdHttp paths all run on
   pre-auth — is now fuzzed by `tests/fuzz/fuzz_urlcodec.c` (undersized-dst overflow
   guard + malformed-`%HH` + `+`-to-space + round-trip encode), ASan+UBSan-clean over
   ~950 K runs, wired into the B-3 lane. The higher-level `build_canonical_qs()` in
   `auth_sigv4_canonical.c` still hard-includes `s3.h` (→ `ngx_http.h`), so harnessing
   the full canonicaliser needs its handful of `ngx_flag_t`/`ngx_memcpy`/`ngx_strcmp`
   uses decoupled from the full nginx header first.

**Fix.** One libFuzzer harness per target under `tests/fuzz/`, seeded from real corpora
(capture valid frames from the existing suites), run under ASan+UBSan in the B-2/B-3
lane. Land incrementally, GSI ASN.1 and JWT JSON first. *Remaining targets (1, 3, 4, and
the top-level SigV4 canonicaliser in 5): GSI ASN.1 and SSS frames are heavily
nginx-coupled (15–28 `ngx_` refs, take `ngx_connection_t*`/`brix_ctx_t*`) and need a
pure `(data,len)` entry carved out of their TUs before they can be harnessed standalone
— a production-source refactor deliberately kept out of the additive fuzz-lane work.*

**Test / acceptance.** Each harness builds, runs clean on its seed corpus in CI, and is
wired into the nightly job. Any crash becomes a regression test.

**Effort breakdown.** ~0.5–1d per harness × 5+ (land one per PR).

**Deps.** B-2/B-3. **Rollback.** n/a (additive).

## C-2 · Fuzz the XRootD wire-framing dispatcher

| Severity | Effort | Type | Confidence |
|---|---|---|---|
| **MED** | M | COVERAGE | STRONG |

**Evidence:** `[R41][R42][R43][R44][R45][R46]`.

**Fix.** A structure-aware harness feeding arbitrary framed PDUs (opcode + `dlen` +
body) into the dispatcher `[R41][R42]`; assert no crash/UB and that the per-opcode cap
holds — i.e. **no path allocates before the cap check**. This makes executable the
bound the recon proved statically.

**Acceptance.** Harness in CI, clean on seed corpus; the `dlen`-cap invariant becomes
executable, not review-only. **Deps.** B-2/B-3.

## C-3 · Audit the `NGX_OK`-on-deny sentinel class — ✅ LANDED (audit + guard, 2026-07-18)

| Severity | Effort | Type | Confidence |
|---|---|---|---|
| **MED** | M | COVERAGE / BUG | STRONG |

**Status — LANDED (2026-07-18).** Audit complete, no live instance, regression
guard shipped. **Finding:** the session verdict is a single flag,
`ctx->login.auth_done`, and the authorization choke point gates on it — request
processing is unreachable until `handshake/policy.c` confirms `logged_in &&
auth_done` (the verdict), and the proxy branch (`handshake/dispatch.c`) gates on
`auth_done`; neither reads a bare `NGX_OK`/`send_ok` return as "authenticated."
Every one of the nine sites that raises the verdict sits on a verified-success
path: the seven credential handlers (`auth/{gsi,gsi-token,host,krb5,pwd,sss,unix}`)
each set it only after the deny path has `BRIX_RETURN_ERR`'d out, and the two
session-plane sites are legitimate — anonymous login (`session/login.c`) and
secondary-stream bind (`session/bind.c`, which inherits the primary's verified
state only after the sessid is confirmed in the registry, deny returning early).
The two historical instances (SSS deny→NULL-deref, funnelled to `NGX_DONE`; the
proxy branch that gated on `logged_in`, an intermediate step) remain fixed.
**Guard:** `tools/ci/check_auth_verdict_sentinel.sh` (wired into
`.github/workflows/guards.yml`) confines `login.auth_done = 1` to those nine
sanctioned files — a new proxy/TPC/dispatch/op site that marks a session
authenticated fails CI, forcing the assignment to live in an auth handler where
the verified-success precondition is reviewable. Tests:
`tests/test_source_guards.py` (real tree clean · sanctioned setter passes ·
rogue proxy setter refused). A-3 (S3 instance) folded in as already-fixed.

**Evidence:** `[R47][R48]`; A-3 is one instance in S3.

**The class.** `brix_send_error`, `brix_send_ok`, `BRIX_RETURN_ERR` **all return
`NGX_OK`** `[R47]` (they queue a wire response and signal "handled," not
"authenticated"). Any auth handler treating a bare `NGX_OK` as "verified, continue"
mishandles a queued-error as success → auth bypass. Two confirmed instances, both fixed:
the SSS deny→NULL-deref+bypass (funnelled to `NGX_DONE` `[R48]`) and the proxy-branch
fail-open (gated on `logged_in`, an intermediate step, not `auth_done`, the verdict).
History flags this a **repeating class** and warns prior "verified false-positive"
labels are not trustworthy.

**Fix.**
1. Enumerate every auth/authz handler and every proxy/TPC/mirror/redirect branch
   (`src/auth/**`, `src/protocols/**/auth_*`, dispatch sites). Prove each success path
   distinguishes "authenticated" from "error queued" — gates on the **verdict**, not a
   step.
2. Where the contract is ambiguous, introduce a distinct sentinel (or a typed
   auth-result enum) so "handled-with-error" cannot read as "authenticated." Prefer a
   compile-time lint / `#define` discipline over a comment.
3. Fold A-3 into this sweep's checklist.

**Test / acceptance.** Per-handler negatives (a denied/malformed attempt must not reach
an authenticated path); every proxy/redirect branch reachable only after `auth_done`; a
written inventory of handlers with their return contract.

**Effort breakdown.** Inventory ~1d · per-handler proofs/tests ~1–2d.

**Deps.** None. **Rollback.** n/a.

---

# PHASE D — New defense-in-depth controls

## D-1 · Protocol-downgrade protection (`brix_min_sec_level`) — ✅ LANDED (2026-07-18)

| Severity | Effort | Class | Status |
|---|---|---|---|
| **MED** | M | DEPTH | ✅ LANDED (2026-07-18) |

`MED · M · DEPTH.` TLS *version* floor is already good (1.2/1.3 only, ctx build
`[R5][R6]`); this governs the *negotiated session* posture. `brix_tls only
ADVERTISES` an in-protocol upgrade (`kXR_ableTLS`) — a client is free to finish
login/auth in cleartext, which is precisely the walked-down session D-1 refuses.

**Finding + fix (LANDED).** New per-server directive `brix_min_sec_level
none|compat|intense` (default `none`), a **distinct axis** from `brix_security_level`
(which governs `kXR_sigver` request *signing*):

- **none** (0) — no floor (default; stock behaviour unchanged).
- **compat** (1) — the session transport must be TLS-encrypted (`c->ssl->connection`
  set, whether by in-protocol upgrade or otherwise); a cleartext session is refused
  every data/metadata opcode with `kXR_error`/**`kXR_TLSRequired`** (3028).
- **intense** (2) — compat **plus** a non-anonymous identity; an `auth=none` listener
  authenticates nobody, so even over TLS it is refused with **`kXR_NotAuthorized`**
  (3010).

Enforced in `brix_min_sec_enforce()` (`src/protocols/root/handshake/policy.c`),
wired into `brix_dispatch()` **after** `brix_dispatch_session_opcode` — so the
login/auth/protocol/bind/TLS-upgrade handshake is never blocked; every opcode
reaching the gate is a data/metadata request. Mirrors the fail-closed shape of
`brix_signing_enforce_level`. Pairs with **A-1** (upstream TLS peer verification)
so neither the client nor the upstream leg can be independently walked down.

Plumbing: enum table `brix_min_sec_levels` (module_enums.c), conf field
`min_sec_level` (srv_conf_fields_cache.inc) + `NGX_CONF_UNSET_UINT`/merge-to-0,
directive (directives_security.inc), `BRIX_MIN_SEC_*` macros + decl (handshake.h).

**Test (LANDED).** `tests/test_min_sec_level.py` 4/4 — raw-wire XRootD client
(reuses test_phase25_ratelimit's stat/open/status parsing): (1) cleartext session
vs `compat` → `kXR_TLSRequired` on a *real, readable* file (below-floor dropped);
(2) the same handshake completing the **genuine in-protocol TLS upgrade** vs
`compat` → stat/open proceed (at/above proceeds); (3) anonymous-over-TLS vs
`intense` → `kXR_NotAuthorized` (second branch); (4) bogus value → `nginx -t`
rejects. Sibling suites (negcache backoff, phase-25 ratelimit) 27/27 green; VFS
seam + metric-cardinality gates clean. **Register:** R77.

> **Observed latent issue (out of D-1 scope, follow-up):** `listen ... ssl`
> (nginx-terminated TLS) on a brix stream block SIGSEGVs the worker on the first
> connection — brix owns TLS via the in-protocol upgrade and does not expect
> `c->ssl` set at accept. Not a supported mode (no test/doc uses it); D-1's
> enforcement reads `c->ssl` which the in-protocol path sets correctly.

## D-2 · Opaque-parameter (CGI) schema validation — ✅ LANDED (byte-hygiene + schema, 2026-07-18)
`MED · M · DEPTH.` `oss.*` / `tpc.*` / `auth.*` opaque params are string-matched. Add a
central schema at the opaque-parse edge: type-enforce (`oss.asize` = positive int),
reject control/shell-meta/non-ASCII bytes before any handler, reject unknown keys in a
`brix_opaque_strict on` mode. **Test:** malformed/typed-wrong/illegal-byte params
rejected pre-handler; valid pass unchanged.

**Finding + fix (LANDED — byte-hygiene half).** The opaque query string (everything
after `?` in a wire path) is consumed by several handlers — TPC source/dest URLs,
delegated-token modes, compression negotiation, ZIP member selection — and is **logged**
and, for native/WebDAV TPC, **spliced into an OUTBOUND request**. A raw control byte is
therefore a log/CRLF-injection and request-smuggling primitive, a shell/quoting
metacharacter is a command-injection primitive if any value ever reaches a shell, and a
high-bit byte is non-conforming (mojibake / filter-evasion). None appear in a legitimate
opaque — conforming clients percent-encode anything outside the unreserved/structural set
— so a single always-on byte-hygiene gate at the parse edge kills the whole class with
zero false positives. New `brix_opaque_illegal_byte()`
(`src/protocols/root/path/opaque_validate.c`, pure C / no libc-string deps) consults a
256-entry permit table built once from an explicit allow set: URL-unreserved
(`A-Za-z0-9 . - _ ~`), path/authority (`/ : @`), percent-encoding (`% +`), and CGI
structure (`= & , ?`). Everything else (0x00–0x1F, 0x7F, 0x80–0xFF, and printable
metacharacters `space ! " # $ ' ( ) * ; < > [ \ ] ^ \` { | }`) is rejected. Wired into
`brix_open_precheck` (`src/protocols/root/read/open_request.c`) at the central native
kXR_open edge (INVARIANT #4 territory): the opaque is extracted via the existing
`open_extract_opaque()` and, on an illegal byte, the open is refused with
`kXR_ArgInvalid` **before** any handler parses, logs, or forwards it. **Tests:** end-to-end raw-wire against a fresh nginx-xrootd instance
(`tests/test_conf_openflags.py` §L2 — `test_open_opaque_structural_bytes_allowed`
[success: `%`/`+`/`,`/nested-`?` opaque opens], `test_open_opaque_injection_byte_rejected`
[security-negative, parametrized over LF/CR/ESC/DEL/high-bit/backtick/`$`/`;`/`<`/space/`'`
→ each `kXR_error`+`kXR_ArgInvalid`], `test_open_opaque_injection_byte_no_opaque_clean`
[error boundary: clean opaque still resolves]); all 13 verified green (structural-allowed
+ clean-open + 11 injection rejects), VFS seam OK. OURS intentionally diverges from stock
here (stock accepts the raw bytes) — the §L2 rejection tests assert OURS-only rejection,
not parity.

**Finding + fix (LANDED — schema half, 2026-07-18).** The two pieces the byte-hygiene
landing deferred — `oss.asize` positive-int type-enforcement and unknown-key rejection —
share the plan's caveat that stock consumes neither on the native path (both are stripped),
so enforcing them *always-on* risks diverging from stock fuzz behaviour. Resolved by making
the whole schema tier **opt-in behind a new `brix_opaque_strict on|off` directive (default
off)**: with it off, only the always-on byte-hygiene gate runs and parity is untouched;
with it on, an operator deliberately elects the stricter posture. The tier lives in the
same pure-C core as tier 1 (`src/protocols/root/path/opaque_validate.c`,
`brix_opaque_schema_check()`, ABI in the new `opaque_validate.h`, no ngx/libc-string deps):
it walks the `&`-separated `key=value` pairs and returns the first violation — `oss.asize`
whose value is not an unsigned decimal integer (`BAD_TYPE`), or a key in no recognized
namespace (`UNKNOWN_KEY`). The vocabulary is the XRootD-namespaced set the wire actually
carries — prefixes `oss. tpc. xrd. xrdcl. cms. scitag.` plus the bare `authz` — read as
*"reject a key in an unrecognized namespace"* (a `space`-free bare `xrd` cannot masquerade
as the `xrd.` namespace; the offending key is named in the log and the error). Wired into
`brix_open_precheck` **after** the byte-hygiene gate (so the schema only ever sees clean
bytes) and only when `conf->opaque_strict` is set; a violation refuses the open with
`kXR_ArgInvalid` before any handler parses. Plumbing mirrors D-1: `ngx_flag_t opaque_strict`
srv-conf field + `NGX_CONF_UNSET` init + `ngx_conf_merge_value(...,0)` + `brix_opaque_strict`
flag directive. **Documented scope (opt-in, not a bug):** the walk splits on top-level `&`,
so a value embedding a nested URL query with a raw `&` would see the nested pair as a
sibling — conforming clients percent-encode a nested query and TPC passes source/dest CGI in
the dedicated `tpc.scgi`/`tpc.dcgi` keys, which is why the tier is opt-in rather than
always-on. **Tests:** C unit `tests/c/test_opaque_schema.c` (10 asserts: valid namespaces +
typed int pass; NULL/empty/leading-`?`/stray-`&` OK; `abc`/`-5`/`1.5`/empty `oss.asize`
→ `BAD_TYPE`+key named; `bogus.key`/`evil`/bare-`xrd`/`authz2` → `UNKNOWN_KEY`; key
truncation NUL-safe) — registered in `cmdscripts/c_simple_units.py`, green via
`test_c_simple_units.py::…[opaque_schema]`; end-to-end raw-wire `tests/test_opaque_strict.py`
4 green (success: well-formed opaque opens under strict; error: `oss.asize=abc`
→ `kXR_error`+`kXR_ArgInvalid`; security-negative: unknown key `evilparam` rejected the same;
**parity: with strict off the same unknown key opens unchanged** — proving the tier never
regresses default behaviour). Byte-hygiene §L2 (17) still green after the `brix_open_precheck`
restructure; VFS seam + metric-cardinality gates clean.

## D-3 · seccomp-BPF worker syscall filter — ✅ LANDED (audit + enforce, 2026-07-18)
`MED · L · DEPTH.` Privilege model already strong — unprivileged operation,
`PR_SET_NO_NEW_PRIVS` `[R59]` + full cap-drop `[R57]` (kill-list incl. `CAP_SETUID`
`[R58]`) in the impersonation worker. Missing: a syscall allowlist. The impersonation
**broker retains `CAP_SETUID`** by necessity (root-equivalent if the broker is
exploited) — seccomp is the most direct mitigation for that residual. Install a
`libseccomp` allowlist at `ngx_worker_process_init` (pread/pwrite/sendfile/openat/stat/
socket-for-upstream/…); deny `execve`, `process_vm_*`, `ptrace`. **Ship audit/log-only
mode first** (`brix_seccomp audit|enforce|off`) to converge the set, then flip to
enforce. **Test:** a denied syscall (`execve`) killed under enforce; full suite green
under enforce.

**Finding + fix (LANDED).** New tri-state directive `brix_seccomp off|audit|enforce`
(default `off`, `NGX_STREAM_SRV_CONF|TAKE1`, enum-slot, mirrors the `brix_io_uring`
pattern — enum in `tunables.h` `BRIX_SECCOMP_*`, table in `module_enums.c`, field in
`srv_conf_fields_cache.inc`, `NGX_CONF_UNSET_UINT` create + `merge_uint` default-off).
The process-global mode is the **strictest value across all enabled server blocks**
(`off < audit < enforce` by enum order), resolved in `process.c` and installed **once
at the TAIL of `ngx_stream_brix_init_process`** — after every one-shot setup syscall has
run, so only the steady-state serving set needs allowlisting. The filter itself lives in
an **ngx-free core** (`src/core/seccomp/seccomp_core.c`, same convention as `wverify` /
`opaque_validate`) so the *shipped* tables are the ones a standalone C unit test drives;
`src/core/seccomp/seccomp.c` is the thin ngx wrapper that routes libseccomp failures to
`ngx_log_error` and emits the operator NOTICE. **AUDIT** = default `SCMP_ACT_LOG`
(allow + kernel-audit-log), allowlist added as `SCMP_ACT_ALLOW` so only *unexpected*
syscalls surface — the convergence mode, nothing denied. **ENFORCE** = default
`SCMP_ACT_ERRNO(EPERM)` (fail-safe: a forgotten syscall degrades one call, never crashes
the worker) with the named-dangerous set (`execve`/`execveat`/`ptrace`/`process_vm_readv`/
`process_vm_writev`) at `SCMP_ACT_KILL_PROCESS`. Syscalls are named as **strings resolved
at runtime** via `seccomp_syscall_resolve_name()` (skip on `__NR_SCMP_ERROR`) so one
table serves every arch and does not fail to *compile* against a libseccomp whose headers
predate a syscall (this build's headers lack `__SNR_openat2`/`__SNR_epoll_pwait2`, which
would make the compile-time `SCMP_SYS()` macro a hard error) — VFS seam #12 stays clean
because every syscall name sits inside a string literal, never as a call. Built behind
`-DBRIX_HAVE_SECCOMP` (config probes `pkg-config libseccomp`, else a header/`-lseccomp`
link probe); **without libseccomp the wrapper fails closed** for audit/enforce (worker
refuses to run rather than silently serve unfiltered) and is a no-op for `off`.
**Tests (3-per-change, all green):** (1) *security-negative + success + error* — C unit
`tests/c/test_seccomp.c` (`seccomp` `CUnitSpec` in `c_simple_units.py`) forks children
against the shipped core: enforce **SIGSYS-kills** `execve` and `ptrace`, **EPERMs**
(does not kill) a non-allowlisted `chroot` (fail-safe proof), permits allowlisted
`getpid`, audit never kills, `off` is a no-op, and the installed counts are non-empty
allow + exactly 5 deny — 7/7. (2) *success — allowlist completeness* — integration
`tests/test_seccomp_enforce.py` boots a real worker under `enforce` **and** `audit`
(template `nginx_seccomp.conf`) and round-trips a live kXR `stat` + `xrdcp` GET + `xrdcp`
PUT over the wire, asserting the `worker syscall filter active (mode=…)` NOTICE is logged
— so a missing allowlist entry would surface as a dead worker or failed transfer, not a
silent pass. (3) *error/security-negative* — same file asserts `brix_seccomp bogus` is
refused by `nginx -t` (`invalid value`). Clean full rebuild links `-lseccomp`; VFS seam
guard OK.

## D-4 · CSPRNG-mint `kXR_bind` session IDs — ✅ LANDED (2026-07-17)
`LOW · S · DEPTH.` `kXR_bind` sessid acts as a bearer token but is not CSPRNG-derived
(FINDING-BIND-1); forgery tests pass (all 64 forged rejected) so this is a contract
weakness, not a live hole. Mint via `RAND_bytes` (a draft existed and was reverted).
**Test:** forged sessid rejected; minted sessid unpredictable.

**Finding + fix (LANDED).** `conn_init_slots_and_sessid`
(`src/protocols/root/connection/handler.c`) packed the 16-byte sessid as
`time | pid | (uintptr_t)c | ngx_random()` — explicitly "not a CSPRNG value" (and
`ngx_random()` is the non-cryptographic `random(3)`). The first 8 bytes (time word + pid
word) were constant/near-constant across every connection a worker served, so the bearer
was predictable, and byte 8..12 additionally leaked a live heap pointer past ASLR. All 16
bytes are now drawn from `RAND_bytes` (OpenSSL CSPRNG, already linked; header via
`core/ngx_brix_module.h`). The mint **fails closed**: a `RAND_bytes` failure means the
process entropy source is dead (TLS would be broken too), so `conn_init_slots_and_sessid`
returns `NGX_ERROR` and `conn_init_ctx` finalizes the connection rather than emit a weak
session ID — matching the existing alloc-failure path. Forgery was already rejected
(registry lookup), so this closes the predictability/leak gap, not a live bypass.
**Tests:** `tests/test_conf_sessions.py::test_d4_valid_minted_sessid_binds` (a genuine
issued sessid still binds — success), `::test_d4_forged_sessid_rejected` (64 random
guesses + the all-zero sessid never bind — security-negative), `::test_d4_sessid_unpredictable_csprng`
(32 sessids all-distinct, 8-byte prefix carries entropy, no byte position constant — the
regression that FAILS under the old time/pid packing). 44 session-suite tests green, build
clean, VFS seam OK.

## D-5 · Harden JWKS `kid` handling — ✅ LANDED (2026-07-17)
`LOW · S · DEPTH.` In `token_select_key_by_kid`, an asserted `kid` that matches no JWKS
key but with exactly one key loaded uses that key anyway ("legacy single-key leniency")
→ `kid` not authoritative. Make an unmatched `kid` a **hard reject** even with one key,
behind a compat flag if any deployment relies on the leniency. The kid-*absent*
multi-key trial is spec-faithful (rotation grace) and stays.

**Finding + fix (LANDED).** The signature *always* gated (`token_sig_ok` runs regardless
of how the key was selected), so this was never a forgery bypass — but the resolved key
could disagree with the client's own `kid` assertion, so `kid` was not authoritative
(spec-authoritativeness gap, LOW). Removed the `a->key_count == 1` fallback in
`token_select_key_by_kid` (`src/auth/token/validate_sig.c`): an asserted `kid` that names
no loaded JWKS key is now a hard reject. **No compat flag was added** — a spec-faithful
single-key deployment either asserts the correct `kid` (exact match) or omits `kid`
entirely (the caller's rotation-grace multi-key trial, unchanged), so nothing legitimate
depends on the fallback; the args struct is populated by direct field assignment at all
five callsites (no `memset`), so a defaulted-off field would have been an
uninitialized-read footgun rather than a clean escape hatch. Only a self-inconsistent
client (asserts key id X, signs under the sole key Y) loses, and the signature already
gated that. **Tests:** `tests/test_wlcg_token_conformance_edge.py` E08 (matching `kid`,
single key → accept) / E09 (unmatched `kid`, single key → **reject**, the changed
behaviour) / E10 (traversal-shaped `kid` → reject, security-negative), all green; the
kid-*absent* path (E04) and the multikey signature family unchanged and green;
`test_malicious_credentials.py::test_kid_path_traversal_not_used_as_path` still green
(its comment updated: the traversal `kid` now rejects rather than falling back). 27
malicious-credentials + multikey tests green, build clean, VFS seam OK.

## D-6 · Confirm the recursive tree ops share the depth cap — ✅ LANDED (2026-07-17)
`LOW · S · DEPTH.` The generic walk **already** caps depth — `vfs_walk_dir` prunes at
`depth > max_depth` `[R52]`. The residual concern is whether `brix_vfs_copytree` `[R53]`
and `brix_fs_remove_tree_confined` `[R54]` route through that capped walker or use
independent C-stack recursion.

**Finding + fix (LANDED).** Audited: **neither** routes through `vfs_walk_dir` — both
recurse independently on the C stack with **no depth cap**, and a **third** op,
`brix_vfs_driver_rmtree` (vfs_unlink.c, recursive DELETE through a non-POSIX/S3
driver), does the same. All three were unbounded → an attacker-nested tree (deep
MKCOL/PUT) could overflow the single-threaded worker's C stack (crash-class DoS, T2).
Added one shared ceiling `BRIX_FS_TREE_MAX_DEPTH` (512, in `core/compat/fs_walk.h`)
and wired it into all three: each was split into a **depth-carrying recursive core**
(`brix_fs_remove_tree_at` / `vfs_copytree_run` / the `depth`-parametrised
`brix_vfs_driver_rmtree`) behind a thin **depth-0 public wrapper**; the recursion edge
now re-enters the core with `depth + 1` (never the public entry, which would reset
depth and defeat the cap), and each core aborts with `errno = ELOOP` past the ceiling.
512 levels stays well inside an 8 MiB stack (each frame carries only a few KiB of path
buffers) while dwarfing any legitimate collection depth (ingress already caps a single
request at 32 components). **Tests:** `tests/test_tree_depth_cap.py` (6 — cap defined /
all-three-enforce / ELOOP-not-crash / each op recurses through the depth-carrying core,
incl. the depth-reset footgun) green; regression `test_webdav_delete_lock_security.py`
+ `test_deep_tree_special_files.py` (live single-worker recursive-subtree traversal, no
wedge/crash) 21 green. Build clean, VFS seam OK.

## D-7 · Validate `clone.c` offsets/lengths — ✅ LANDED
`LOW · S · DEPTH.` `kXR_clone` cast wire `uint64` `src_offset`/`dst_offset` straight to
signed `off_t` `[R49]` and `src_len` to `size_t` `[R50]` with no negative/overflow check,
relying on kernel `EINVAL` — inconsistent with the explicit guard in the read path
`[R51]`. **Fix (landed):** `clone.c` now rejects, before `brix_copy_range`, any item
where `src_off < 0 || dst_off < 0 || src_len > SSIZE_MAX ||
src_off > SSIZE_MAX - src_len || dst_off > SSIZE_MAX - src_len` → `kXR_ArgInvalid`
("clone offset/length out of range"), mirroring the read-path negative-offset guard.
**Test:** `tests/test_new_opcodes_b.py::TestClone::test_clone_negative_offset_rejected` —
a high-bit-set `src_offset` and an `off_t`-overflowing `dst_offset` are each refused with
`kXR_ArgInvalid(3000)` (not a kernel `EINVAL`/`kXR_IOError` round-trip), and the worker
survives to serve a subsequent valid clone.

---

# PHASE E — Deployment safety, DoS resilience & hygiene

## E-1 · Loud startup warnings for insecure-but-valid configs — ✅ LANDED (2026-07-17)
`MED · S · HYGIENE.` Each valid-but-dangerous config should `warn` at load and be
refused under a new `--strict-security` / `brix_strict_security on`:
- **S3 unset `access_key`** → every request passes with **zero verification** `[R55]`.
- **WebDAV `auth optional`** → a rejected token silently falls through to anonymous
  (anonymous PUT → 201); token rejection becomes unobservable.
- **Dashboard `brix_dashboard_anonymous on`** → no-password admin surface.
- **OCSP soft-fail** default; **unverified upstream TLS** (until A-1 lands) `[R1][R3]`.
**Test:** each insecure config emits its warning; strict mode fails `nginx -t` on each.

**Landed.** New `brix_strict_security on|off` flag on the shared HTTP preamble
(`ngx_http_brix_shared_conf_t.strict_security`, directive in `http_common.c`,
default `off`), plus a single shared gate `brix_shared_security_gate(cf, strict,
what, remedy)` in `shared_conf.h` that emits `[warn] brix: insecure
configuration — …` by default and, under strict, an `[emerg] … (refused:
brix_strict_security on)` that the caller turns into an `nginx -t` failure. Three
HTTP surfaces route through it, each in its own merge so the diagnostic points at
the offending location:
- **S3** (`s3/module.c`): an enabled export with `brix_s3_token off` **and** no
  `brix_s3_access_key` accepts unauthenticated requests.
- **WebDAV** (`webdav/config_merge.c::webdav_validate_auth_paths`): `brix_allow_write
  on` with `brix_webdav_auth` not `required`. This is now the *single* audit point
  for that case — the pre-existing plain-warn NOTE in `webdav/config.c` was removed
  in favour of the gate (which also enforces strict).
- **Dashboard** (`observability/dashboard/module.c`): `brix_dashboard_anonymous on`
  (the dashboard has no shared preamble, so it reads `strict_security` from the
  common module's location conf).

OCSP soft-fail warnings were already covered; unverified upstream TLS is now
fail-closed by default in A-1's `brix_server_setup_tls` (it only `[warn]`s when the
operator explicitly opts out via `..._tls_verify off`), so neither is routed through
the new flag. **Test:** `tests/test_strict_security_e1.py` — 12
green (self-contained `nginx -t`): each surface's secured variant is clean, the
insecure variant `[warn]`s and still loads, and the same insecure variant under
`brix_strict_security on` fails `nginx -t` with the `[emerg]` refusal.

## E-2 · Guard the PROXY-protocol / host-ACL trust coupling — ✅ LANDED (2026-07-17)
`MED · S · HYGIENE.` Host-based auth trusts `c->sockaddr` `[R56]`. If a deployment
enables nginx-native `listen … proxy_protocol`, that address becomes the advertised
(spoofable) one → host-ACL bypass. No in-tree guard or doc today. Require a
`set_real_ip_from` trusted-proxy allowlist when host-ACL and `proxy_protocol` coexist;
fail config validation otherwise; document the coupling. **Test:** host-ACL +
`proxy_protocol` without a trusted-proxy allowlist → config rejected.

**Landed.** New stream-postconfiguration guard `postconf_proxy_protocol_host_acl`
(`src/core/config/postconfiguration.c`), run fail-closed at the top of
`ngx_stream_brix_postconfiguration` before any runtime object is built. It walks
`cmcf->ports → port.addrs` (populated during `listen` parse, before
`ngx_stream_optimize_servers`) and, for every address with `opt.proxy_protocol` set,
resolves each bound server (`addr.servers`, an array of core srv confs) to its brix srv
conf; if any carries a `host_allow` allowlist it logs `[emerg]` naming the listen and
returns `NGX_ERROR`, so `nginx -t` fails. This build is compiled **without the realip
module** (confirmed via `nginx -V`: no `http_realip`/`stream_realip`), so
`set_real_ip_from` is not an expressible directive and no trusted-proxy allowlist can
constrain who may forge a PROXY header — the combination is therefore *unconditionally*
unsafe here (a hard failure, not a `brix_strict_security` warn like E-1). Should realip
ever be added, this guard is the natural place to relax the check to "reject only when no
`set_real_ip_from` covers the peer." Note the guard reads the *merged* `host_allow`
(merge runs during parse, before postconfiguration). Test: `tests/test_proxy_protocol_host_acl_e2.py`
(3 green) — host-ACL on a plain listener loads; `proxy_protocol` alone loads;
`proxy_protocol` + `brix_host_allow` is refused with an `[emerg]` naming the coupling.

## E-3 · Metric-label cardinality CI guard (invariant 8) — ✅ LANDED (2026-07-17)
`LOW · M · GATE.` Invariant 8 (low-cardinality labels) is enforced only by review; a new
metric family interpolating a path/user/DN/IP into a label would pass CI → memory
blow-up / DoS. Add `check_metric_cardinality.sh` (analogous to `check_vfs_seam.sh`
`[R68]`) rejecting non-enum label values, wired into `guards.yml` `[R30]`. **Test:** a PR
adding a path-valued label fails the guard.

**Finding + fix (LANDED).** INVARIANT #8 was doc-and-review only. New guard
`tools/ci/check_metric_cardinality.sh` greps every string-interpolated label token
(`<name>=\"%…\"`) in `src/observability/metrics/*.c` and rejects any whose label NAME
is not on a curated low-cardinality vocabulary (26 names, two justified classes: ENUM —
fixed compile-time set; CONFIG-N — configured/observed resource names bounded by
deployment config: export/backend/upstream/zone/repo/vo/server/port). A genuinely
per-request value (`path`/`user`/`dn`/`ip`/`uri`/`key`) matches no vocabulary entry and
fails; literal-valued labels (`source=\"hit\"`) are cardinality-1 and never flagged; a
one-off bounded gauge carries a per-line `/* metric-cardinality-allow: <reason> */`
marker (same escape-hatch shape as the VFS-seam guard). The vocabulary is curated, not a
shrinking backlog — extending it is a deliberate reviewed act mirroring an enum edit in
`unified.h`. The current tree passes clean (all 19 live interpolated labels are already
bounded); reconcile with `check_metric_cardinality.sh --list`. Wired into `guards.yml`
after the http-helper guard. Tests: `test_source_guards.py` — the guard runs green in the
parametrized real-tree pass, plus three injected-fixture cases (approved label passes /
path-valued label fails with "INVARIANT #8" / marker overrides).

## E-4 · DoS resilience: negative-stat backoff + per-identity rate limiting — ✅ LANDED (2026-07-18)

| Severity | Effort | Class | Status |
|---|---|---|---|
| **LOW** | L | DEPTH | ✅ LANDED (2026-07-18) |

**Finding.** Metadata-harvesting (repeated `kXR_stat`/`kXR_locate` on non-existent paths)
and floods were rate-limited only by IP, not authenticated identity.

**Fix (LANDED) — two independent parts.**

*Part 1 — per-identity rate-limiting by token subject.* The Phase-25 leaky-bucket limiter
(`src/net/ratelimit/`) already keys `kXR_open`/`kXR_read`/`…`/`kXR_locate` on identity
dimensions incl. the GSI subject DN. Added a sixth dimension `BRIX_RL_KEY_SUBJECT`
(`ratelimit.h`) that keys on the WLCG/JWT token subject — the enum value, the stream +
HTTP key builders (`rl_key_sub_hash` → `sub:<8 hex>`, FNV-1a32 so no raw identity reaches a
metric label, INVARIANT #8; anonymous → IP fallback per invariant 5), and the `key=subject`
directive parser. So a token-authenticated flood is now throttled per-`sub`, not just per-IP.

*Part 2 — negative-path backoff (the genuinely-new defense).* New opt-in directive
`brix_negcache_backoff off | <threshold> <window_seconds> <wait_seconds>`
(`NGX_STREAM_SRV_CONF`, default off). A per-principal (token subject → DN → client IP)
SHM sliding-window counter of *missing-path* lookups (`kXR_stat`/`kXR_locate` resolving to
`kXR_NotFound`): once a principal crosses `threshold` misses inside `window`, the slot
**arms** and the core paces it to at most one served miss per `wait` interval — every excess
miss returns `kXR_wait`. Because the stock XRootD client answers `kXR_wait` by sleeping and
re-sending the *same* request, each lookup still completes (on its retry, one interval later)
while a harvest loop is throttled to ~one path per `wait` — no request is ever wedged, and a
legitimate client (which rarely misses, so never arms) is untouched. ngx-free core
(`src/core/negcache/negcache_core.c`, unit-tested standalone) + thin ngx/SHM wrapper
(`negcache.c`, slab-allocated via `brix_shm_table_alloc` per INVARIANT #10); enforced at the
`ENOENT` branch of `read/stat.c` and the not-found branch of `read/locate.c`. Fail-open on an
unattached zone or a misconfigured rule.

**Tests (3+1).** `tests/c/test_negcache.c` 4/4 (arm→pace→release, window decay, per-principal
isolation + 4 fail-open guards, zero-key bucketing). `tests/test_negcache_backoff.py` 3/3 over
the raw XRootD wire: **success** — a stat-harvest loop trips `kXR_wait` while a real file on
the same over-budget connection still stats+opens; **security-neg** — a second identity
(distinct loopback source IP → distinct principal) is served, not throttled, while the first
is flooded; **error** — a malformed `brix_negcache_backoff` is refused by `nginx -t`.
`tests/test_phase25_ratelimit.py::test_subject_key_wired_and_parses` covers the Part-1 SUBJECT
key (markers + both-plane `key=subject` parse); full ratelimit suite 24/24. VFS-seam +
metric-cardinality CI gates clean.

**Deferred:** none for E-4.

## E-5 · Audit-hygiene follow-ups — ✅ LANDED (2026-07-18)
`LOW · S · HYGIENE.` All discrete items done: CMake fallback aligned to `config`'s
hardening set (`_FORTIFY_SOURCE=3` deliberately declined for GCC-8/11 toolchain
portability), the CVMFS fixed-buffer `strcpy`s proven bounds-safe, and the two stale
`history-*` findings reconciled. The `check_vfs_seam.sh` allowlist audit below is a
standing practice (re-run whenever the allowlist grows), not a one-shot deliverable.
- ~~**Align the CMake fallback build** with the production `config` flag set: the fallback
  optflags `[R63]` omit `_FORTIFY_SOURCE`, `-fstack-clash-protection`,
  `-fcf-protection`, and the fallback ldflags `[R64]` omit `-Wl,-z,noexecstack`.~~
  ✅ **Done.** `CMakeLists.txt` `_default_optflags` now carries
  `-D_FORTIFY_SOURCE=2 -fstack-protector-strong -fstack-clash-protection
  -fcf-protection=full` and `_default_ldflags` carries `-Wl,-z,relro -Wl,-z,now
  -Wl,-z,noexecstack` — byte-for-byte the hardening set in `config` (`CFLAGS` line +
  the `NGX_LD_OPT` relro/now/noexecstack branch), used only when `rpm --eval
  %{optflags}` is unavailable (non-RHEL dev/packaging hosts). **`_FORTIFY_SOURCE=3`
  deliberately declined:** it requires GCC 12+, but the RPM matrix builds on
  AlmaLinux 8/9 (GCC 8/11), where `=3` silently degrades to `=2` at best and warns at
  worst — pinning `=2` keeps one flag set valid across every supported toolchain.
  Revisit only if the alma8/9 lanes are retired.
- ~~**Verify caller-side length bounds** for the fixed-buffer `strcpy` in
  `shared/cvmfs/config/repo.c:26,32` and `shared/cvmfs/failover/failover.c:21`.~~
  ✅ **Done (2026-07-17).** These sites are now bounds-proven `memcpy`s, not `strcpy`:
  `cvmfs_repo_config_add_server`/`_add_proxy` gate `len >= sizeof(dst)` before the copy
  (`repo.c:26,33`, comment "bound proven above"), and `failover.c`'s `add_endpoint`
  helper does the same (`failover.c:19,22`). `grep strcpy shared/cvmfs/` is now empty —
  no fixed-buffer string copy remains in the CVMFS shared code.
- **Audit `RAW_ALLOW`/`TIER3_ALLOW`** in `check_vfs_seam.sh` `[R68]` whenever it grows —
  the allowlist is the grep-based guard's blind spot (a raw syscall via function
  pointer/macro, or `lseek()+read()` instead of `pread()`, evades tier-1). Consider a
  complementary clang-tidy check.
- ~~**Reconcile stale docs:** `history-security-and-credentials.md` lists FINDING-EXP-1
  (absent-`exp` accepted) and the `storage.modify` dead-permission bug as open.~~
  ✅ **Done (2026-07-17).** Both are already fixed in code; there were no xfail markers
  left to flip — the tracking cases assert the fixed behaviour directly (positive tests,
  not `xfail`). `exp` is now mandatory (`validate.c:214` rejects absent/non-positive `exp`)
  — verified green this session: `test_ext_clm2_05_missing_exp_reject`,
  `test_ext_ndt_03_exp_null_reject` (both `[webdav,s3]`). `storage.modify` is consulted as
  write-like (`scopes.c:279` grants write on `modify`) — read-denial verified green
  (`test_b07_modify_scope_no_read_reject`, `test_fil_wg_07_modify_atlas_get_reject`), and
  write-grant verified green on both protocols (`test_wr_04_modify_scope_accept[webdav,s3]`,
  `test_fil_wg_08_modify_atlas_put_accept`). All 11 cited conformance cases run green after
  a clean fleet restart. Both `history-security-and-credentials.md` entries updated with
  code + test citations.

---

## 6. Suggested sequencing

| Sprint | Items | Theme | Exit criterion |
|---|---|---|---|
| **1** | A-1, A-3, A-4, A-5, A-6, **B-1**, **B-2** | Close holes + raise the net | MITM/oracle/secret gaps closed; analyzers + ASan block merges |
| **1 (parallel)** | A-2 | Heap-corruption hunt | ASan-clean under B-2; open bug → Fixed |
| **2** | B-3, C-1 (GSI+JWT first), C-3, E-1, E-2 | Coverage + deploy safety | Fuzzers in CI; auth-return audit written; insecure configs warn |
| **3** | C-2, D-1, D-2, **D-3**, D-4, D-5, D-6, D-7, **E-4**, E-3, E-5 | Depth + consistency | Framing fuzzed; downgrade + schema live; seccomp audit+enforce live; negative-path backoff + subject-keyed rate limiting live; cardinality gate + low-risk cleanups done |
| **Backlog** | remaining C-1 | Bigger bets | fuzzers / ASan lane |

Every code change carries the three-test rule and lands behind the Phase-B gates once
they exist.

---

## 7. New configuration surface introduced by this plan

| Directive | Item | Default | Effect |
|---|---|---|---|
| `brix_tap_proxy_upstream_tls_verify on\|off` | A-1 | `on` | Verify the proxy-leg upstream cert; `nginx -t` fails if the leg is `on` without a CA (LANDED — the plan's working name was `proxy_ssl_verify`) |
| `brix_upstream_tls_verify on\|off` | A-1 | `on` | Same for the redirector leg (LANDED — working name `upstream_ssl_verify`) |
| `brix_tap_proxy_upstream_tls_ca <path>` | A-1 | (none) | Trust anchor for the proxy leg (LANDED — the CTX field existed but had no parser until A-1) |
| `brix_tap_proxy_upstream_tls_name <host>` | A-1 | (proxy host) | SNI + verify name for the proxy leg (LANDED) |
| `brix_upstream_tls_name <host>` | A-1 | (SNI host) | Name to verify against (IP-addressed upstreams) |
| `tpc_credential_staging_dir <path>` | A-5 | 0700 shm dir | Where TPC creds stage; `/tmp` only as an explicit escape hatch |
| `ocsp_response_max_bytes <size>` | A-6 | `64k` | Cap the OCSP response read |
| `brix_ocsp_require_nonce on\|off` | A-6 | `off` | Deny a nonce-less OCSP response (replay guard); opt-in — nonce-less CA responders are common (LANDED — working name `ocsp_require_nonce`) |
| `brix_min_sec_level none\|compat\|intense` | D-1 | `none` | Session security floor; drop below-floor clients |
| `brix_opaque_strict on\|off` | D-2 | `off` | Reject unknown/ill-typed opaque params |
| `brix_seccomp off\|audit\|enforce` | D-3 | `off` → `audit` → `enforce` | Worker syscall filter |
| `brix_strict_security on\|off` | E-1 | `off` | Refuse to start on any insecure-but-valid config |

All new directives default to **backward-compatible** behaviour except the two
`*_ssl_verify` (default `on`) — the one intentional break, gated by an explicit opt-out,
because shipping unauthenticated TLS as the default is the bug.

---

## 8. New observability introduced by this plan

| Metric (low-cardinality labels only, invariant 8) | Item |
|---|---|
| `brix_upstream_tls_verify_failures_total{leg}` | A-1 |
| `brix_s3_authz_denied_total{op}` (ACL/tagging gate denials) | A-3 |
| `brix_ocsp_response_truncated_total` | A-6 |
| `brix_seccomp_violations_total{mode}` (audit-mode counter before enforce) | D-3 |
| `brix_ratelimit_identity_throttled_total` | E-4 |

---

## 9. Reference index

Clickable `file:line`. Line numbers verified against the tree at authoring time; a
future edit may shift them — search the symbol if a jump lands off by a few lines.

| # | Location | What |
|---|---|---|
| R1 | src/net/upstream/tls.c:80 | Redirector leg proceeds on `handshaked` only (no verify) |
| R2 | src/net/upstream/tls.c:26 | `brix_upstream_start_tls` — where to set `SSL_set1_host` |
| R3 | src/net/proxy/connect_upstream.c:130 | Proxy leg proceeds on `handshaked` only |
| R4 | src/core/config/runtime_server.c:404 | `brix_server_setup_tls` |
| R5 | src/core/config/runtime_server.c:414 | Proxy ctx `ngx_ssl_create` (no `SSL_VERIFY_PEER`) |
| R6 | src/core/config/runtime_server.c:438 | Redirector ctx `ngx_ssl_create` |
| R7 | src/core/config/runtime_server.c:421 | `ngx_ssl_trusted_certificate` (inert without verify) |
| R8 | src/fs/cache/origin_connection.c:103 | Correct: `SSL_CTX_set_verify(SSL_VERIFY_PEER)` |
| R9 | src/fs/cache/origin_connection.c:133 | Correct: `SSL_set1_host` + hostflags |
| R10 | src/tpc/outbound/tls.c:60 | Verifying TPC-outbound leg |
| R11 | src/auth/crypto/ocsp_transport.c:215 | Verifying OCSP transport |
| R12 | src/protocols/webdav/module_init.c:155 | WebDAV cert verify (`X509_V_OK`) |
| R13 | src/protocols/webdav/proxy_response.c:1 | WebDAV-proxy heap corruption site |
| R14 | src/protocols/s3/tagging.c:501 | `s3_handle_get_acl` canned ACL |
| R15 | src/protocols/s3/tagging.c:503 | Comment: "gateway authorizes via XrdAcc/tokens" |
| R16 | src/protocols/s3/handler_dispatch.c:246 | `?acl` dispatch |
| R17 | src/fs/backend/ucred.c:117 | `ucred_read_token` — no cleanse |
| R18 | src/fs/backend/ucred.c:214 | `ucred_read_s3` — secret key, no cleanse |
| R19 | src/fs/backend/ucred.c:367 | `ucred_read_keyring` — no cleanse |
| R20 | src/fs/backend/ucred.c:616 | `memset(out,0,…)` in `_select` |
| R21 | src/fs/backend/ucred.c:501 | `_resolve` leaves fields on DECLINED |
| R22 | src/tpc/outbound/tpc_token_exchange.c:84 | `body_buf` holds the JWT (no cleanse) |
| R23 | src/tpc/outbound/tpc_token_exchange.c:101 | `/tmp/tpc_token_body_XXXXXX` template |
| R24 | src/tpc/outbound/tpc_token_exchange.c:103 | `mkstemp` |
| R25 | src/protocols/webdav/tpc_cred_exchange.c:76 | WebDAV TPC cred stage |
| R26 | src/core/config/shared_conf.h:1 | `brix_shared_credential_dir_ensure` (0700 shm) |
| R27 | src/auth/crypto/ocsp.c:41 | `OCSP_MAX_RESPONSE_BYTES` defined, unwired |
| R28 | .github/workflows/fanalyzer.yml:16 | cron-only + `continue-on-error` |
| R29 | .github/workflows/codechecker.yml:14 | cron-only + `continue-on-error` |
| R30 | .github/workflows/guards.yml:13 | Blocking per-PR gate (invariant guards) |
| R31 | tools/ci/fanalyzer_baseline.txt:1 | Analyzer ratchet baseline |
| R32 | tests/manage_test_servers.sh:53 | `ASAN_OPTIONS`/`UBSAN_OPTIONS`, `SANITIZE=1` |
| R33 | tests/race_shim.c:1 | TSan/ASan race harness |
| R34 | tests/fuzz/fuzz_safe_size.c:1 | One of 3 existing libFuzzer targets |
| R35 | tests/fuzz/README.md:1 | "real attack surface = wire parsers" |
| R36 | src/auth/gsi/parse_x509_signed.c:52 | Decrypt blob sized from attacker pubkey |
| R37 | src/auth/token/json.c:1 | Hand-rolled JWT JSON parser |
| R38 | src/auth/sss/auth_request.c:1 | SSS frame parse (phase-79 bug home) |
| R39 | src/auth/token/macaroon_parse.c:1 | Macaroon parser |
| R40 | src/protocols/s3/auth_sigv4_canonical.c:1 | SigV4 canonicalization |
| R41 | src/protocols/root/connection/recv_process.c:24 | `brix_max_payload_for_request` |
| R42 | src/protocols/root/connection/recv_process.c:261 | Per-opcode cap check before alloc |
| R43 | src/protocols/root/connection/recv_process.c:59 | `SIZE_MAX-1` overflow guard |
| R44 | src/protocols/root/read/readv.c:200 | Overflow-checked `brix_size_mul` |
| R45 | src/protocols/root/read/readv.c:14 | `BRIX_MAX_READV_TOTAL` (256 MiB) |
| R46 | src/protocols/root/read/pgread.c:292 | Signed-`rlen` trap |
| R47 | src/protocols/root/protocol/frame_hdr.h:1 | `brix_send_*`/`BRIX_RETURN_ERR` return `NGX_OK` |
| R48 | src/auth/sss/auth_request.c:1 | `sss_deny()` → `NGX_DONE` funnel (fix) |
| R49 | src/protocols/root/read/clone.c:106 | `off_t` cast, no negative check |
| R50 | src/protocols/root/read/clone.c:108 | `copy_len` cast, no overflow check |
| R51 | src/protocols/root/read/read.c:75 | Reference: negative-offset reject |
| R52 | src/fs/vfs/vfs_walk.c:229 | `vfs_walk_dir` depth cap (prune) |
| R53 | src/fs/vfs/vfs_walk.c:541 | `brix_vfs_copytree` |
| R54 | src/core/compat/fs_walk_remove.c:1 | `brix_fs_remove_tree_confined` |
| R55 | src/protocols/s3/auth_sigv4_verify.c:398 | Anon mode = zero verification |
| R56 | src/auth/host/auth.c:99 | Host auth trusts `c->sockaddr` |
| R57 | src/auth/impersonate/lifecycle_worker.c:45 | `imp_worker_drop_caps` |
| R58 | src/auth/impersonate/lifecycle_worker.c:50 | kill-list incl. `CAP_SETUID` |
| R59 | src/auth/impersonate/lifecycle_worker.c:57 | `PR_SET_NO_NEW_PRIVS` |
| R60 | config:23 | Hardened CFLAGS (FORTIFY=2, stack-clash, CET, format-security) |
| R61 | config:28 | RELRO + BIND_NOW + noexecstack (link) |
| R62 | config:54 | Performance profile (v2 default) |
| R63 | CMakeLists.txt:117 | Softer fallback optflags (missing 3 hardening flags) |
| R64 | CMakeLists.txt:118 | Fallback ldflags (missing noexecstack) |
| R65 | src/fs/path/beneath.c:94 | `do_openat2_resolve` confinement chokepoint |
| R66 | src/fs/path/beneath.c:102 | `O_NONBLOCK` forced on data opens (FIFO-DoS defense) |
| R67 | src/fs/path/beneath.c:64 | Requires kernel ≥ 5.6 (openat2) |
| R68 | tools/ci/check_vfs_seam.sh:1 | VFS seam tier guards (zero backlog) |
| R69 | src/auth/token/validate.c:161 | Issuer pinning (exp/nbf window nearby) |
| R70 | src/auth/token/scopes.c:97 | `storage.modify` parsed |
| R71 | src/auth/token/scopes.c:272 | `storage.modify` consulted as write-like |
| R72 | tools/ci/check_metric_cardinality.sh:1 | Metric-label cardinality gate (INVARIANT #8, E-3) |
| R73 | src/protocols/root/path/opaque_validate.c:68 | `brix_opaque_illegal_byte` CGI byte-hygiene gate (D-2), wired at `open_request.c` `brix_open_precheck` |
| R74 | src/core/seccomp/seccomp_core.c:1 | `brix_seccomp_core_apply` per-worker seccomp allowlist (D-3); ngx wrapper `seccomp.c`, installed at tail of `process.c` `init_process` |
| R75 | src/core/negcache/negcache_core.c:1 | `brix_negcache_core_note` per-principal missing-path throttle (E-4 Part 2); ngx/SHM wrapper `negcache.c` (`brix_negcache_backoff`), enforced at `read/stat.c` ENOENT + `read/locate.c` not-found |
| R76 | src/net/ratelimit/ratelimit_keys.c:1 | `BRIX_RL_KEY_SUBJECT` token-subject rate-limit key (E-4 Part 1); `rl_key_sub_hash` → `sub:<8 hex>`, `key=subject` parser |
| R77 | src/protocols/root/handshake/policy.c | `brix_min_sec_enforce` session-posture floor (D-1); `brix_min_sec_level none\|compat\|intense`, wired in `dispatch.c` after session opcodes → `kXR_TLSRequired` (cleartext) / `kXR_NotAuthorized` (anonymous under intense) |
| R78 | src/protocols/root/path/opaque_validate.c | `brix_opaque_schema_check` opt-in opaque schema tier (D-2 schema half); ABI `opaque_validate.h`, `brix_opaque_strict on\|off`, wired at `open_request.c` `brix_open_precheck` after byte-hygiene → `kXR_ArgInvalid` on `oss.asize` non-int or unknown-namespace key |
| R79 | src/core/config/runtime_server.c:465 | A-1 fail-closed gate: `brix_server_setup_tls` refuses (`nginx -t` `emerg`) `upstream_tls` on with no CA on both legs unless `..._tls_verify off`; new flags `upstream_ssl_verify`/`proxy.upstream_ssl_verify` (default on) + new proxy `brix_tap_proxy_upstream_tls_ca`/`_name` directives; enforcement complements the already-landed R1–R12 crypto path |
| R80 | src/auth/crypto/ocsp_request.c:213 | A-6 item 2: `check_ocsp_response` `require_nonce` gate denies a nonce-less response (`OCSP_check_nonce < 0` → free bresp + return -1) instead of warning; `do_ocsp_request` hands the request back via `OCSP_REQUEST **req_out` (was freed internally, nonce branch dead) so the nonce survives to verify; wired to `brix_ocsp_conf_t.require_nonce` + `brix_ocsp_require_nonce on\|off` (default **off** — opt-in, nonce-less CA responders common), threaded `auth.c → brix_ocsp_check_cert → ocsp_check_urls`; staple loop passes 0. `test_ocsp_require_nonce.py` 8 green |
| R81 | tools/ci/check_auth_verdict_sentinel.sh | C-3: audit found no live `NGX_OK`-on-deny instance — authorization gates on the verdict `login.auth_done` (`handshake/policy.c` `logged_in && auth_done`; proxy branch `handshake/dispatch.c` on `auth_done`), and all 9 verdict setters sit on verified-success paths. Shipped a regression guard confining `login.auth_done = 1` to the 7 credential handlers + `session/login.c` + `session/bind.c`; wired into `guards.yml`. `test_source_guards.py` (real clean + sanctioned pass + rogue-proxy refuse) |

---

## 10. What this plan deliberately does *not* touch

Examined and found sound — re-hardening is motion without progress:

- **Kernel path confinement** — `do_openat2_resolve` `[R65]` with `RESOLVE_BENEATH` /
  `RESOLVE_NO_MAGICLINKS` / `RESOLVE_IN_ROOT`, `*at()`-family parent pre-resolution,
  `O_NONBLOCK` on data opens `[R66]`, kernel ≥ 5.6 hard requirement `[R67]`, NUL-byte
  rejection at ingress.
- **VFS storage seam** — tier-2/tier-3 backlogs at **zero**; raw positional syscalls
  confined to `src/fs/backend/`, mechanically guarded `[R68]`.
- **Wire-framing bounds** — per-opcode `dlen` caps *before* allocation `[R41][R42]`,
  `SIZE_MAX-1` overflow guards `[R43]`, overflow-checked `readv` multiply `[R44]` with a
  256 MiB total cap `[R45]`, signed-`rlen` traps `[R46]`.
- **JWT/macaroon core** — `alg:none`+`crit` rejection, mandatory expiry, issuer/audience
  pinning `[R69]`, `storage.modify` now consulted `[R70][R71]`, constant-time
  HMAC/SigV4/pwd compares, 900 s SigV4 skew window, RFC 3820 limited-proxy monotonicity,
  IGTF key-strength floor.
- **Temp-file model** — audit rounds 1–3; no `O_CREAT` without `O_EXCL` or `O_NOFOLLOW`;
  staged-atomic-write for COPY/TPC/PUT.
- **Invariant-2 TLS-vs-sendfile gating** — file-backed sendfile only on cleartext or
  kTLS; splice refuses TLS on either leg.
- **Secret zeroization discipline** — 49 cleanse sites (the `ucred.c`/TPC gaps in
  A-4/A-5 are the lone exceptions this plan closes).
- **Production `config` build hardening** — `_FORTIFY_SOURCE=2`,
  `-fstack-protector-strong`, `-fstack-clash-protection`, `-fcf-protection=full`, full
  RELRO + BIND_NOW + noexecstack, `-Werror=format-security`, VLA ban `[R60][R61]`.
- **Privilege model** — unprivileged operation, cap-drop + `NO_NEW_PRIVS`
  `[R57][R58][R59]` (D-3 only *adds* seccomp on top).

---

## 11. Risk register — CWE / CVSS / detectability

CVSS v3.1 base vectors are indicative (site posture varies); they exist to *rank*, not
to certify. "Detect today" = can current CI/tests catch a regression of this class
before the fix lands.

| Item | CWE | Indicative CVSS v3.1 | Base | Detect today? |
|---|---|---|---|---|
| **A-1** upstream TLS no-verify | CWE-295 Improper Cert Validation | `AV:N/AC:H/PR:N/UI:N/S:C/C:H/I:H/A:N` | **7.4 High** | ✅ (`test_upstream_tls_verify.py`) |
| **A-2** WebDAV-proxy heap corruption | CWE-787 Out-of-bounds Write | `AV:N/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:H` | **7.5 High** | ❌ (no ASan lane → B-2) |
| **A-3** S3 ACL existence oracle | CWE-204 / CWE-639 | `AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N` | **4.3 Med** | ✅ done |
| **A-4** secret not zeroized | CWE-226 Sensitive Info in Reused Resource | `AV:L/AC:H/PR:L/UI:N/S:U/C:H/I:N/A:N` | **4.7 Med** | ✅ (`test_ucred_zeroization.py`) |
| **A-5** cred temp file in `/tmp` | CWE-377 Insecure Temp File | `AV:L/AC:H/PR:L/UI:N/S:U/C:H/I:N/A:N` | **4.7 Med** | ✅ (`test_cred_stage.c` + `test_tpc_token_exchange_staging.py`) |
| **A-6** OCSP unbounded read | CWE-770 Alloc w/o Limits | `AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:H` | **5.9 Med** | ✅ (`test_ocsp.py::TestOCSPResponseSizeCap`) |
| **C-3** `NGX_OK`-on-deny bypass class | CWE-697 / CWE-288 | `AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N` | **9.1 Crit** *(no live instance — audited 2026-07-18)* | ✅ `check_auth_verdict_sentinel.sh` |
| **D-2** opaque CGI bytes unvalidated | CWE-88 Argument Injection / CWE-93 CRLF Injection / CWE-117 Log Injection | `AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:N` | **5.4 Med** | ✅ byte-hygiene (`test_conf_openflags.py::test_open_opaque_injection_byte_rejected`) + schema (`test_opaque_strict.py`, `brix_opaque_strict`) |
| **D-4** `kXR_bind` sessid predictable | CWE-330 Use of Insufficiently Random Values / CWE-200 | `AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:N` | **4.8 Med** | ✅ (`test_conf_sessions.py::test_d4_sessid_unpredictable_csprng`) |
| **D-5** JWKS `kid` not authoritative | CWE-347 Improper Cryptographic Signature Verification | `AV:N/AC:H/PR:L/UI:N/S:U/C:L/I:L/A:N` | **3.7 Low** | ✅ (`test_wlcg_token_conformance_edge.py::test_e09_unmatched_kid_single_key_reject`) |
| **D-7** clone offset unchecked | CWE-190 / CWE-681 | `AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:L` | **4.3 Med** | ✅ (`test_new_opcodes_b.py::TestClone::test_clone_negative_offset_rejected`) |
| **E-3** unbounded metric-label cardinality | CWE-770 Alloc w/o Limits (metric explosion) | `AV:N/AC:H/PR:L/UI:N/S:C/C:N/I:N/A:L` | **3.7 Low** | ✅ (`test_source_guards.py::test_metric_cardinality_path_label_fails`) |
| **E-1** insecure default configs | CWE-1188 Insecure Default | (deployment-dependent) | — | ✅ (`test_strict_security_e1.py`) |
| **E-2** proxy_protocol host spoof | CWE-290 Auth Bypass by Spoofing | `AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N` | **9.8 Crit** *(if misconfigured)* | ✅ (`test_proxy_protocol_host_acl_e2.py`) |

Two items reach *critical* only under a precondition (C-3 needs a live unfixed instance;
E-2 needs `proxy_protocol` enabled without a trusted-proxy allowlist). That precondition
gating is exactly why they sit in the "make the net mandatory + warn loudly" phases
rather than as confirmed A-track holes — but their *ceiling* is why they are not backlog.

---

## 12. Configuration recipes (secure vs. insecure)

Concrete blocks a deployer can copy. Directives marked *(new)* are introduced by this
plan (§7); the rest exist today.

### 12.1 A redirecting cache with an authenticated upstream (post A-1)

```nginx
# SECURE — upstream peer is verified; a MITM cert fails the handshake.
server {
    listen 1094 ssl;
    brix_role            cache;
    upstream_tls         on;
    upstream_tls_ca      /etc/grid-security/certificates/ca-bundle.pem;   # required
    upstream_ssl_verify  on;                    # (new) default on
    upstream_tls_name    origin.example.org;    # (new) verify this SAN
    proxy_ssl_verify     on;                     # (new) default on
}
```

```nginx
# INSECURE — refused by `nginx -t` once A-1 lands (verify on, no CA).
server {
    upstream_tls on;            # no CA, no explicit opt-out  →  emerg at load
}
# To *intentionally* talk to a self-signed origin, you must say so out loud:
server {
    upstream_tls on;
    upstream_ssl_verify off;    # explicit, logged, greppable in audit
}
```

### 12.2 Fail-closed WebDAV auth (avoid the E-1 silent-anonymous fallthrough)

```nginx
# SECURE — a rejected token is an error, not a silent downgrade to anonymous.
location / {
    brix_webdav          on;
    brix_webdav_auth     required;   # NOT `optional`
    brix_strict_security on;         # (new) refuse to start on any insecure default
}
```

Under `brix_strict_security on` (E-1) the loader `emerg`s on: S3 with an unset
`access_key` (anonymous-everything `[R55]`), `brix_webdav_auth optional`, an anonymous
dashboard, OCSP soft-fail, and — until A-1 — an unverified upstream TLS leg.

### 12.3 Host-ACL with a real proxy in front (close E-2)

```nginx
# SECURE — host-ACL trusts c->sockaddr [R56]; only honor a forwarded address
# from a trusted hop, else the ACL is spoofable.
server {
    listen 1094 proxy_protocol;
    set_real_ip_from 10.0.0.0/24;    # the ONLY hops allowed to assert a client IP
    brix_host_acl /etc/brix/host.acl;
    # Without set_real_ip_from, config validation (E-2) refuses this combination.
}
```

> **This build has no realip module** (`nginx -V` shows no `http_realip`/`stream_realip`),
> so `set_real_ip_from` is not a valid directive here and the "secure" form above cannot
> be expressed — E-2's guard therefore rejects *any* `proxy_protocol` + host-ACL pairing.
> The remedy on this build is to terminate PROXY-protocol on a front tier and have brix
> `listen` plainly, or to authenticate by token/GSI instead of host. Adding the realip
> module is the prerequisite for the trusted-proxy form.

### 12.4 TPC credential staging off `/tmp` (A-5) and seccomp rollout (D-3)

```nginx
tpc_credential_staging_dir /dev/shm/brix-creds;   # (new) 0700, default; never /tmp
brix_seccomp audit;   # (new) start in audit → converge the syscall set → flip to enforce
```

### 12.5 OCSP hard-fail with a bounded response (A-6)

```nginx
ocsp_response_max_bytes 64k;   # (new) enforce the already-defined cap [R27]
ocsp_require_nonce      on;    # (new) a stripped nonce denies under hard-fail
```

---

## 13. Per-item verification & repro commands

Copy-paste starting points. Fleet/log conventions per CLAUDE.md
(`tests/manage_test_servers.sh`, logs in `/tmp/xrd-test/logs/`).

| Item | Command / method |
|---|---|
| **A-1** | `openssl s_server -cert wronghost.pem` as a fake origin; point `upstream_tls_ca` at a real CA → today the handshake completes (bug); after the fix it aborts. New: `PYTHONPATH=tests pytest tests/test_upstream_tls_verify.py -v` |
| **A-2** | `SANITIZE=1 tests/manage_test_servers.sh restart` then loop the WebDAV-proxy→XrdHttp path; inspect `${SANITIZE_LOG_DIR}/asan.<pid>`. Note the harness runs `abort_on_error=0` (`manage_test_servers.sh:64`) — the **CI** lane (B-2) must set `abort_on_error=1` so a finding *fails* rather than logs |
| **A-3** | `curl -s -o /dev/null -w '%{http_code}' "$S3/bucket/known-key?acl"` vs a missing key — a 200/404 split on an unreadable key is the oracle. New: `pytest tests/test_s3_acl_authz.py -v` |
| **A-4** | `grep -c OPENSSL_cleanse src/fs/backend/ucred.c` must cover all three readers `[R17][R18][R19]`; valgrind/`--tool=memcheck` assertion that reader scratch is zero on return |
| **A-5** | While a TPC transfer runs: `ls -la /tmp/tpc_token_body_* 2>/dev/null` must return nothing; `stat -c '%a' "$(dirname <stage-path>)"` must be `700`. New: `pytest tests/test_tpc_cred_staging.py -v` |
| **A-6** | Fake OCSP responder returning a 1 GiB body → worker memory must stay bounded; nonce-stripped replay → deny under hard-fail |
| **B-1** | Open a throwaway PR with a deliberate NULL-deref → both analyzer gates go red; revert → green. Never hand-edit `[R31]` to silence |
| **B-2** | New lane builds `-fsanitize=address,undefined`; `ASAN_OPTIONS=abort_on_error=1:detect_leaks=1`; goes red on the A-2 repro (joint acceptance) |
| **B-3** | ✅ wired: `.github/workflows/fuzz.yml` runs all three via `python3 -m cmdscripts.fuzz_all` (PR smoke 60s, nightly 600s). Local: `PHASE81_RUN_FUZZ_PORT=1 pytest tests/test_cmd_fuzz_all.py` |
| **C-1** | ✅ 2 harnesses in the `fuzz.yml` lane: `fuzz_jwt_json.c` (+`json.c -ljansson`, `corpus_jwt_json/`) and `fuzz_urlcodec.c` (+`uri.c`+`hex.c`, `corpus_urlcodec/`). Per remaining harness: `clang -O1 -g -fsanitize=fuzzer,address,undefined <harness>.c -o <t>` against a seed corpus captured from the live auth suites |
| **C-3** | `grep -rn "return NGX_OK" src/auth src/protocols/**/auth_* ` and prove each success path gates on the verdict, not an intermediate step `[R47]` |
| **D-3** | `brix_seccomp audit` → drive the full suite → collect the audit-logged syscall set → author the allowlist → `brix_seccomp enforce` → suite must stay green; `execve` from a worker must be killed |
| **D-6** | Build a directory tree deeper than `max_depth`; `brix_vfs_copytree`/remove must prune cleanly (no stack overflow) — confirm both route through `vfs_walk_dir` `[R52]` |
| **D-7** | Send `kXR_clone` with `src_offset=0xFFFFFFFFFFFFFFFF` → must return `kXR_ArgInvalid`, not round-trip to the kernel `[R49][R51]` |
| **E-2** | `listen … proxy_protocol` + `brix_host_acl` without `set_real_ip_from` → `objs/nginx -t` must fail |
| **E-3** | A PR adding a metric with a path/user/IP-valued label must fail the new `check_metric_cardinality.sh` (model on `check_vfs_seam.sh` `[R68]`) |
| **E-5** | `diff <(hardening flags in config `[R60][R61]`) <(CMakeLists fallback `[R63][R64]`)` — the fallback must gain FORTIFY / stack-clash / cf-protection / noexecstack; audit the two unguarded `strcpy` sites (`shared/cvmfs/config/repo.c:26,32`, `shared/cvmfs/failover/failover.c:21`) `[R72][R73]` |

### New reference anchors used above

| # | Location | What |
|---|---|---|
| R72 | shared/cvmfs/config/repo.c:26 | Unguarded `strcpy` into fixed `server_urls` buffer |
| R73 | shared/cvmfs/failover/failover.c:21 | Unguarded `strcpy` into fixed `url` buffer |
