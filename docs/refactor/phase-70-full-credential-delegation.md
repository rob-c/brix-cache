# Phase-70 — Full Credential Delegation & Pass-Through to Backend Storage

**Status:** planned
**Scope:** every user-facing auth mechanism on every protocol (root://, davs:///WebDAV, S3, cvmfs-rw) delegated or passed through to the (potentially remote) backend.
**Builds on:** per-user backend credential phases 1–3 (`docs/10-reference/per-user-backend-credentials.md`) — the *selection* + GridSite-upload + mint layer already in-tree.

---

## 1. Goal

Authenticate the backend leg as the **inbound user**, by one of three strategies per credential type, with zero admin pre-provisioning wherever physically possible:

- **PASSTHROUGH** — forward the exact credential the user presented (bearer token bytes; a user-supplied full x509 proxy incl. private key).
- **EXCHANGE** — trade the inbound credential for a backend-valid one (RFC 8693 token-exchange; S3 STS; GSSAPI krb5 forwarding).
- **DELEGATE / MINT** — obtain a fresh short-lived proxy (GridSite handshake, or CA mint) when nothing forwardable exists.

`SELECT` (today's directory lookup) remains the fallback mode.

---

## 2. Reality matrix — what each mechanism physically permits

| Inbound mechanism | Capture point (file:line) | Raw cred available? | Backend-usable strategy | New work |
|---|---|---|---|---|
| **x509 EEC/proxy — root GSI** | `src/auth/gsi/parse_x509.c:65` `gsi_chain_from_plaintext()`; `src/auth/gsi/auth.c:395` | Chain PEM only (**no private key** — GSI proves possession, never sends key) | PASSTHROUGH only if user *supplies full proxy+key* (§5.1); else DELEGATE/MINT | §5.1–5.3 |
| **x509 EEC/proxy — WebDAV TLS** | `src/protocols/webdav/auth_cert.c:180` (`SSL_get_peer_cert_chain`) | Chain X509* only (**no key**) | same as above | §5.1–5.3 |
| **WLCG/SciToken bearer — root** | `src/auth/gsi/token.c:196` → `ctx->bearer_token[4096]` | **Yes — raw JWT** | PASSTHROUGH + EXCHANGE | §5.4 |
| **WLCG/SciToken bearer — WebDAV** | `src/protocols/webdav/auth_token.c:68` → `rctx->bearer_token` | **Yes — raw JWT** | PASSTHROUGH + EXCHANGE | §5.4 |
| **WLCG/SciToken bearer — S3** | `src/protocols/s3/auth_bearer.c:87` | **Yes — raw JWT** | PASSTHROUGH + EXCHANGE | §5.4 |
| **AWS SigV4 — S3** | `src/protocols/s3/auth_sigv4_verify.c:143` | Access-key id only (**secret never transmitted**) | EXCHANGE (STS) or SELECT `.s3` | §5.5 |
| **SSS — root** | `src/auth/sss/auth_request.c:13` | Decrypted user/group; shared keytab is node-held | PASSTHROUGH (re-issue SSS to origin from same keytab) | §5.6 |
| **krb5 — root** | `src/auth/krb5/auth.c:80` | AP_REQ only; TGT not present unless forwardable | EXCHANGE (GSSAPI `GSS_C_DELEG_FLAG`) — needs forwardable ticket | §5.7 |
| **XrdSecpwd — root** | `src/auth/pwd/auth.c` | Password never stored (PBKDF2 only) | Not forwardable → SELECT only | §5.8 doc |
| **unix / host — root** | `src/auth/unix/auth.c:150` / `src/auth/host/auth.c:80` | Unverified assertion / reverse-DNS | Not a real credential → SELECT/deny only | §5.8 doc |
| **VOMS AC** | `src/auth/voms/extract.c:31` | Embedded in proxy | Rides the x509 path | — |

Identity for every mechanism lands in `brix_identity_t` (`src/core/types/identity.h:27-63`): `dn`, `subject`, `issuer`, `scopes`, `vo_list`, `auth_method`.

---

## 3. Architecture — one delegation pipeline, three seams

```
front door (capture raw cred + identity)
   └─ bind to request ctx  ──►  brix_vfs_ctx_bind_backend_cred / *_bind_backend_deleg
        └─ VFS gate (vfs_cred.c: resolve MODE → produce brix_sd_cred_t)
             └─ sd driver open_cred/*_cred  (sd_xroot / sd_remote / sd_ceph)
                  └─ origin auth  (origin_protocol.c → origin_auth.c GSI/ZTN/SSS)
```

Three seams already exist and are reused verbatim:

- **Carrier:** `brix_cache_fill_t{ cred_x509_proxy[1024] (PATH), cred_bearer[4096] (bytes), cred_principal[512] }` (`src/fs/cache/cache_internal.h:124-126`).
- **SD cred:** `brix_sd_cred_t{ x509_proxy, bearer, s3_ak/sk/region, ceph_*, principal, cred_dir, fallback_deny }` + `open_cred`/`*_cred` vtable slots + `brix_sd_*_maybe_cred` forwarders (`src/fs/backend/sd.h:160-751`).
- **Backend GSI presenter:** `brix_cache_origin_auth_gsi(t, oc, gsi_parms, proxy_path)` loads cert PEM (`cache_origin_load_proxy_pem`, `origin_auth.c:117`) + private key (`cache_origin_load_proxy_key`, `origin_auth.c:162`) and does the signed-DH cert response (`brix_gsi_build_cert_response`, `gsi_core.h:146`). **It authenticates from a proxy file PATH — so any strategy that can materialise a proxy PEM (chain+key) at a 0600 path reuses this unchanged.**

---

## 4. Foundation (do first)

1. **Mode field.** Add `enum brix_cred_mode { BRIX_CRED_SELECT, PASSTHROUGH, EXCHANGE, DELEGATE, MINT, AUTO }` to `src/fs/backend/sd.h`; add `mode` to `brix_sd_cred_t`. Default `SELECT` (no behaviour change).
2. **Per-request live-cred bag.** New `brix_deleg_live_t` (in `src/fs/vfs/vfs_internal.h`): `{ int have_proxy_pem; ngx_str_t proxy_pem; ngx_str_t bearer; brix_identity_t *id; }`, bound onto `brix_vfs_ctx_t` by a new `brix_vfs_ctx_bind_backend_deleg(vctx, live)`. This carries **bytes**, distinct from the existing dir-based bind.
3. **Ephemeral proxy materialiser (reuse).** `brix_proxy_gsi_write_pem_temp(pem, len, out, cap)` (`src/net/proxy/gsi_upstream.c:20`) already writes a 0600 mkstemp PEM and returns its path — the universal "bytes → path" adaptor for the GSI presenter. Add a `pool_cleanup` that `unlink()`s + zeroes it.
4. **Directive.** `brix_backend_delegation <select|passthrough|exchange|delegate|mint|auto>` per protocol; owned in `src/core/config/http_common.c` (HTTP plane, beside the existing `brix_storage_credential*` at lines 105-138) and in the stream table for root://. `auto` = §2 dispatch by `id->auth_method`.

---

## 5. Per-mechanism work

### 5.1 x509 PASS-THROUGH of a user-supplied non-delegated proxy  ← primary new ask

**Problem.** Neither GSI nor TLS hands the node the user's private key, so the node cannot *replay* an x509 login. Pass-through is only possible if the user **voluntarily supplies a full proxy (cert chain + private key)**. That full proxy is then presented **directly, unmodified** to the upstream XRootD — the node impersonates the user with the user's own (short-lived, non-delegated) proxy. This is exactly the credential form `origin_auth.c` already consumes.

**Transport (how the user provides the proxy) — three channels, all opt-in:**

- **(a) root:// inline bucket.** Extend the GSI login to accept an *optional* client-pushed full-proxy bucket (a new kXRS sub-type, e.g. `kXRS_x509_fullproxy`) sent only when the client opts in (`XRD_DELEGATEFULLPROXY`-style). Captured beside `gsi_chain_from_plaintext()` at `src/auth/gsi/parse_x509.c:65`; bytes → `brix_deleg_live_t.proxy_pem`. **Client-side counterpart** required in `client/` (xrdcp/xrdfs flag) since stock clients never send a key.
- **(b) WebDAV/S3 header.** `X-Brix-Delegate-Proxy: <base64 PEM>` (or a `PUT /.well-known/brix-delegation/passthrough` body) over TLS only, cert- or token-authenticated. Parse in `auth_cert.c`/`auth_token.c`, DN/sub must match the presented identity, bytes → `brix_deleg_live_t.proxy_pem`.
- **(c) Reuse GridSite upload store, session-scoped.** The existing PUT `/.well-known/brix-delegation` (`delegation.c:1422`) already accepts and DN-validates a proxy; add a *non-persistent* variant that binds the proxy to the request ctx instead of writing `<dir>/<key>.pem`.

**Backend presentation (no new code on the origin leg):**
`brix_deleg_live_t.proxy_pem` → `brix_proxy_gsi_write_pem_temp()` → 0600 path → set `brix_sd_cred_t.x509_proxy = path`, `.mode = PASSTHROUGH` → `sd_xroot_open_cred` copies to `t->cred_x509_proxy` (`sd_xroot.c:102`) → `brix_cache_origin_bootstrap` sees non-empty proxy → `brix_cache_origin_auth_gsi(..., proxy_path)` presents it upstream.

**Validation gate (new, in vfs_cred.c decide body ~`:119`):** before materialising — (1) chain parses and is unexpired; (2) leaf/EEC DN **equals** the front-door authenticated DN (no privilege swap); (3) chain is RFC-3820-valid and trusted by `conf->ca_store` (reuse `brix_gsi_verify_chain`, the same check phase-3 added to the delegation endpoints); (4) TLS-only transport. Fail → EACCES→403, never fall to service cred.

**Security invariants (document in the reference doc):** private key lives only in a 0600 tmpfs file for the op's duration, `unlink`+zero on pool cleanup; never logged; never persisted for sync ops. For **async write-back** a captured full proxy MAY be spilled to the stage-journal owner dir **only** under an explicit `brix_backend_passthrough_persist on` (default off) with mode 0600 + TTL guard, else the write is done synchronously or dead-lettered (§6).

**Tasks:** T-x509pt-1 wire bag+materialiser+gate; T-2 WebDAV/S3 header channel; T-3 root:// bucket + `client/` flag; T-4 session-scoped delegation-store variant; T-5 tests (§7).

### 5.2 x509 DELEGATE (GridSite handshake)
Already implemented (`delegation.c`: GET `/request` → CSR, PUT `/<id>` → assembled proxy, per-worker 256-slot 600s store). **Work:** promote from opt-in endpoint to a `DELEGATE` mode the VFS gate can *drive proactively* for TPC and for clients that advertise delegation; document client requirement (gfal / xrdcp-with-delegation). No origin-leg change.

### 5.3 x509 MINT
Already implemented (`cred_mint.c` `brix_cred_mint(cred_dir, ca_cert, ca_key, principal, key, ttl, log)`, EC P-256, atomic). **Work:** expose as `MINT` mode; **precondition:** upstream must trust the mint CA (operational). Already invoked once on DECLINED in `vfs_cred.c` when a mint CA is configured.

### 5.4 Bearer PASSTHROUGH + EXCHANGE
- **PASSTHROUGH:** thread the captured raw JWT (`ctx->bearer_token` / `rctx->bearer_token`) into `brix_deleg_live_t.bearer` → `brix_sd_cred_t.bearer` → `t->cred_bearer` → `brix_cache_origin_auth_ztn` (already wired at `origin_protocol.c:191`). Gate: only when origin advertises `ztn` **and** token `aud` accepts the backend (new `brix_backend_token_audience_ok` list). This is the one true zero-provisioning path.
- **EXCHANGE (RFC 8693):** new `src/auth/token/exchange.c` — `brix_token_exchange(subject_token, resource/aud, scope, out_token, log)` POSTs `grant_type=token-exchange` to the issuer token endpoint; cache by `(sub,aud,scope)` keyed on `exp`. Config: `brix_backend_token_exchange_endpoint`, `_client_id`, `_client_secret`. Use when `aud` is node-bound. A related capture path already exists for TPC (`tpc_cred.c` `BRIX_TPC_CRED_TOKEN_EXCHANGE`) — factor its HTTP client into the shared helper.
- **Async:** JWTs expire; write-back needs an offline/refresh token (store in journal owner record) or falls to robot-cred/dead-letter (§6).

### 5.5 S3 SigV4 → EXCHANGE (STS) / SELECT
New `src/auth/s3/sts.c` — `brix_s3_sts_assume(inbound_id, out_ak, out_sk, out_session, ttl)` calling backend `AssumeRole`/`GetSessionToken`; result fills `brix_sd_cred_t.s3_ak/sk/region` consumed by `sd_remote` open_cred (phase-3). Fallback: existing `.s3` SELECT. SigV4 secret is never forwardable, so pure passthrough is impossible by design — document.

### 5.6 SSS PASSTHROUGH
The node holds the shared keytab, so it can **re-issue** an SSS credential to the origin asserting the same decrypted user/group. **Work:** `brix_cache_origin_auth_sss` already takes a `keytab_path` (`origin_auth.c:442`); add identity injection so the re-issued blob carries the inbound user, gated on origin advertising `sss`. Config: `brix_backend_sss_keytab`.

### 5.7 krb5 EXCHANGE (GSSAPI forwarding)
Only works with a **forwardable** ticket (`GSS_C_DELEG_FLAG`) — captured delegated GSS cred → new `src/auth/krb5/forward.c` `brix_krb5_deleg_to_origin()` initiating a fresh GSSAPI context to the origin. Needs origin `krb5` advertise + cross-realm/forwardable policy. Document as best-effort; fall to SELECT.

### 5.8 Non-delegable (document, don't build)
XrdSecpwd (no stored secret), unix (unverified assertion), host (reverse-DNS) — SELECT-only or deny. Reference doc states why.

---

## 6. Cross-cutting invariants

- **No wrong-identity fallback.** In `fallback_deny`/deny mode any passthrough/exchange/delegate failure → EACCES→403, never the service cred (existing `vfs_cred.c` decide-body contract; all 12 `brix_sd_*_maybe_cred` forwarders already refuse when the slot is missing).
- **Namespace parity.** stat/opendir/unlink/rename/xattr must ride the same live cred via the `*_cred` slots + `brix_vfs_ns_leaf` unwrap (phase-2 T1) — no service-cred metadata probe leaking existence.
- **Lifetime guard.** Deny when cred TTL < estimated op window; hard-required before spilling any cred into the async stage journal.
- **Async write-back.** Owner identity persists in the stage journal (`brix_stage_cred_t` in `brix_sreq_t`); flush re-resolves. For ephemeral live creds the record stores *how to re-acquire* (exchange refresh token / re-mint key), not the expiring bearer/proxy. Unre-acquirable → dead-letter (`<journal>/deadletter/`, existing), never wrong-identity.
- **Secret hygiene.** proxy keys / s3_sk / bearer never logged; 0600 tmpfs; zero+unlink on cleanup; base64-inline proxies rejected over cleartext transport.
- **Trust config validated at load** (issuer, backend `aud`, mint CA, STS endpoint, KDC realm, SSS keytab) — not first use.
- **Metrics.** Add `mode` dimension to `brix_metric_cred_result` (`BRIX_CRED_OUTCOME_{USER,FALLBACK,DENY}` today); add `PASSTHROUGH/EXCHANGE/DELEGATE/MINT` outcome + failure-reason counters.

---

## 7. Config directives (new)

HTTP plane in `http_common.c` (beside `brix_storage_credential*`); mirror needed ones in the stream table.

```
brix_backend_delegation            select|passthrough|exchange|delegate|mint|auto   (default select)
brix_backend_token_audience_ok     <aud> [<aud> ...]
brix_backend_token_exchange_endpoint <url>
brix_backend_token_exchange_client_id <id>
brix_backend_token_exchange_client_secret <secret|@file>
brix_backend_passthrough_persist   on|off        (default off; async full-proxy spill)
brix_backend_sss_keytab            <path>
brix_backend_s3_sts_endpoint       <url>
brix_backend_krb5_forwardable      on|off         (default off)
```

---

## 8. Test plan (3 per mode per protocol: success / expiry-or-aud-reject / wrong-identity-deny)

- **x509 passthrough:** client supplies full proxy → remote xrootd read+write byte-exact **as the user**; DN-mismatch proxy → 403; expired proxy → 403; cleartext transport → 403. Live via a second xrootd origin + provisioned per-user grid-mapfile.
- **bearer passthrough/exchange:** mock IdP; aud-bound token → exchanged then accepted; aud-ok token → forwarded verbatim; expired → deny.
- **S3 STS:** against MinIO STS.
- **SSS re-issue / krb5 forward:** container with shared keytab / forwardable KDC.
- **delegate/mint:** gfal delegation; mint-CA-trusting origin.
- Unit: `test_deleg_live` (bytes→path→cleanup+zero), audience matcher, exchange cache TTL, passthrough validation gate.

---

## 9. File manifest

**New:** `src/auth/token/exchange.{c,h}`, `src/auth/s3/sts.{c,h}`, `src/auth/krb5/forward.{c,h}`, `src/fs/vfs/vfs_deleg.c` (live-bag bind + gate), `docs/10-reference/backend-delegation.md` (capability matrix).
**Touched:** `sd.h` (mode enum/field), `vfs_cred.c` + `vfs_internal.h` (live bag, decide-body mode dispatch), `http_common.c` + stream module table (directives), `gsi/parse_x509.c` + `auth/gsi/auth.c` (root full-proxy bucket), `webdav/auth_cert.c`/`auth_token.c` + `s3/auth_bearer.c` (header capture), `delegation.c` (session-scoped variant), `origin_auth.c` (SSS identity inject), `client/` (opt-in full-proxy send flag), `./config` (new srcs).

---

## 10. Sequencing

**P70.1** Foundation §4 → **P70.2** bearer passthrough+exchange §5.4 (highest value, only true zero-provisioning) → **P70.3** x509 passthrough §5.1 (primary ask) → **P70.4** delegate/mint promotion §5.2–5.3 → **P70.5** S3 STS §5.5 → **P70.6** cross-cutting/async/metrics §6 → **P70.7** SSS/krb5 §5.6–5.7 → **P70.8** docs/tests. Each sub-phase: implement → 3 tests/mode → review → commit to main (per repo git policy).
