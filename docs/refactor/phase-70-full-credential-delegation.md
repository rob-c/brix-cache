# Phase-70 — Full Credential Delegation & Pass-Through to Backend Storage

**Status:** SUPERSEDED / SUBSTANTIALLY LANDED. The chronological update block
below is authoritative; the remaining live-backend details are owned by the
newer audit and backend plans, not by every unchecked item in this original
design.

> SUPERSEDED (2026-07-25): substantially LANDED. Bearer + x509-proxy PASSTHROUGH
> and token EXCHANGE are live end-to-end — capture (`deleg_capture.h`,
> `gsi_promote_fullproxy`, gridftp P82.9 per `phase-82-gridftp-gateway.md`),
> binding (`brix_vfs_deleg_bind` in `src/fs/vfs/vfs_deleg_bind.c` — the planned
> `vfs_deleg.c` split into materialiser + bind/setters), and the fail-closed
> materialiser gate (`src/fs/vfs/vfs_deleg.c::brix_vfs_deleg_live_cred`).
> §5.5 (S3 STS) and §5.7 (krb5) are call-ready-but-DEFERRED — hooks
> `brix_vfs_deleg_sts_cred` / `brix_vfs_deleg_krb5_token` exist with `DEFERRED`
> banners in `vfs_deleg.c` (≈:376 / :432) awaiting container labs. §5.6 origin
> identity injection + `brix_backend_sss_keytab` LANDED 2026-07-27 (P90-70.3 —
> both planes, load-validated directive; caller-asserted SSS mint, fail-closed
> on missing/over-bound identity; see the register row +
> `docs/10-reference/backend-delegation.md`). Residual
> register: `phase-90-plan-phase-remainder-register.md` §2.
>
> UPDATE (2026-07-27, phase-90 burndown complete): §5.1a client send path
> VERIFIED-AND-HARDENED (P90-70.5 — it had existed since T-3 in the shared
> kernel `gsi_core_cresp_util.c::gsi_add_fullproxy_bucket`, opt-in
> `XRD_DELEGATEFULLPROXY`; hardened with the `/tmp/x509up_u<euid>` default-path
> fallback + guarded `O_NOFOLLOW` euid-owned open; first live e2e proof
> `tests/test_fullproxy_passthrough.py` 8/8). §6 "validated at load" holds for
> everything that has a conf bind: SSS keytab, mint CA, and now the exchange
> endpoint (`brix_conf_set_backend_tx_endpoint` rejects non-https/host-less/
> control-byte URLs at `nginx -t`, P90-70.8(d)); **the S3 STS endpoint now
> validates at load too** — `brix_conf_set_backend_sts_endpoint`
> (`src/core/config/helpers.c`, wired in the `http_common.c` command table)
> rejects a scheme-less / host-less /
> control-byte `brix_backend_s3_sts_endpoint` at `nginx -t`, accepting BOTH
> `http://` and `https://` (the STS client is SigV4-signed and never transmits
> the secret, so a lab MinIO STS over http is legitimate — unlike the HTTPS-only
> exchange endpoint), gated by `tests/test_sts_endpoint_load_validation.py` (5:
> https+http parse, scheme-less/host-less/whitespace reject). The STS exchange
> *seam itself* (the XML→credential parser + the SigV4 request builder that the
> deferred §5.5 origin leg calls into) is now unit-covered without a container:
> `tests/c/sts_units_test.c` (runner `sts_units`) links the real `sts_http.o` +
> `sts_sign.o` and asserts well-formed AssumeRole/GetSessionToken parse+build, a
> stable 64-hex signature, and the fail-closed paths (unparseable / missing /
> empty secret, buffer overflows, and a bounded oversized-secret field). Only the
> KDC-realm validation still lands with its deferred directive.
>
> UPDATE (2026-07-28): the S3 STS **exchange** path is now LIVE against a real
> MinIO. The AWS-dialect leg (unit/gate-green) could not actually exchange with
> MinIO — a genuine wire divergence the canned unit masked: MinIO implements
> **only** `POST` + form-body + header-auth-SigV4 `AssumeRole` (no AWS
> GET/presigned, no `GetSessionToken`). Added an additive
> `brix_backend_s3_sts_flavor aws|minio` dialect (default `aws`, AWS path
> byte-unchanged) — both planes + `deleg_wire` stamp; new `sts_build_post` /
> `sts_http_post` MinIO transport (`sts_prep_common` extracted so both dialects
> share prep). Live proof `tests/test_sts_minio_live.py` (docker-direct, opt-out
> `STS_MINIO_LIVE=0`, 3 green) drives the production
> `brix_s3_sts_assume(flavor=MINIO)` via `tests/c/sts_live_assume.c` and shows
> the returned temp creds fetch a seeded object byte-for-byte, no-token GET →
> 403, wrong-secret AssumeRole fails closed; offline `sts_units` gained
> `test_build_post_{minio,no_role,deterministic}`. Full detail: §5.5.1. Still
> deferred = the nginx-runtime STS *invocation* and the whole krb5 leg. §5.2 proactive DELEGATE
> drive DEFERRED (post-login
> re-key = engine change; covered by §5.1a + the WebDAV/S3 header channel);
> §5.1c session-scoped GridSite variant WON'T-DO (header channel covers it);
> §6's async re-acquire record SATISFIED by the stage journal
> (`brix_stage_cred_t` re-resolvable identity + deny/dead-letter — no cred
> bytes persisted). §8 hardening: aud gate + exchange mint cache wired at all
> three bearer fronts (P90-70.9). Open = origin legs §5.5/§5.7 only.
> **UPDATE 2026-07-28 (c):** §5.7 krb5 crypto core now LIVE-verified vs a real
> KDC — capture (`capture.c`) + forward (`forward.c`) + origin-principal
> derivation + the `brix_backend_krb5_forwardable` stream-plane directive all
> landed & tested (`test_krb5_forward_live.py` 4 tests, `test_krb5_origin_princ.py`
> 3). Only the runtime *wire* invocation (inbound two-round auth state machine +
> outbound multi-leg drive) remains, blocked on live krb5 peers — see §5.7.1.
> (container-blocked P90-70.1/.2).
> **UPDATE 2026-07-31:** both origin-leg crypto cores re-verified green together
> on the provisioned box — `test_sts_minio_live.py` **3/3** vs a real MinIO +
> `test_krb5_forward_live.py` **4/4** vs a real MIT KDC (**7/7**, both
> self-provisioning + opt-out-gated, so this is a durable regression floor). The
> remaining residual is unchanged and is a genuine subsystem build, not polish:
> `brix_vfs_deleg_live_cred` (`src/fs/vfs/vfs_deleg.c`) has a wired STS branch but
> **no krb5 branch**, the delegated `gss_cred_id_t` + origin principal are not yet
> carried on `brix_vfs_ctx_t`, and the multi-leg negotiation belongs in
> `origin_auth.c`. Gap (a) alone would mint a first-leg token with no consumer, so
> (a)+(b) land together or not at all — deferred as the correct call. The read-AIO
> disconnect UAF coverage this leg's concurrent recv-flip was blocked behind is now
> closed (`test_aio.py::TestAioDestroyedGuard` RST-mid-flight + churn drivers, ride
> the nightly ASan lane). See phase-88 audit § 4.
> **UPDATE 2026-07-31 (b):** the multi-leg negotiation itself is now **built +
> live-verified** — `brix_krb5_deleg_negotiate()` (`forward.c`) drives the full
> `gss_init_sec_context` ↔ origin loop to `GSS_S_COMPLETE` with mutual auth, proven
> by `test_krb5_forward_live.py`'s new `negotiate` mode (now **7/7** vs the real
> KDC). The residual narrows to just (i) the kXR `"krb5"` **wire adapter** in
> `origin_auth.c` implementing the engine's transceiver seam (blocked: no live
> GSSAPI XRootD origin here — would be untestable dead code) and (ii) the
> **request-synchronous carry** of the live `gss_cred_id_t` onto the request path
> (the async `brix_cache_fill_t` cannot safely hold a request-scoped GSS handle),
> which the `vfs_deleg.c` krb5 branch waits on. See §5.7.1 item 2.
> **UPDATE 2026-07-31 (c) — S3 STS runtime wire LANDED + live-verified:** the
> end-to-end nginx-runtime STS invocation (front-door capture → VFS deleg gate →
> `sd_remote` origin open) is now **built and driven live**, closing the §5.5
> origin leg (the STS half of the residual). A booted `root://` gateway
> (`tests/configs/nginx_root_s3_sts.conf`) fronts an S3 export whose **static
> `brix_storage_credential` carries a deliberately WRONG secret**; a byte-exact
> read is therefore provable ONLY if the STS-minted temporary credential
> authenticated the origin leg. `tests/test_sts_runtime_e2e.py` **3/3** vs a real
> docker MinIO: positive (exchange mints temp cred, `session=<token sub>`,
> byte-exact read), plus two fail-closed negatives (`delegation off` → wrong
> static secret refused; corrupted STS **service** secret → deny, no fallback).
> Two product fixes were required, both defensible correctness (not test scaffolding):
> (1) **gate ordering** in `brix_vfs_deleg_live_cred` (`src/fs/vfs/vfs_deleg.c`) —
> when the operator armed STS and the leaf accepts `BRIX_SD_CRED_S3`, the STS
> branch now decides **before** the bearer branch: a WLCG bearer is the caller's
> *identity* (→ RoleSessionName), never an S3-consumable secret, so forwarding it
> verbatim to an S3 origin would fall back to the static service key and defeat
> per-caller scoping. STS-unarmed (`live->sts == NULL`) is unchanged — a genuine
> bearer for an xroot/https origin is still forwarded. New unit cases
> `deleg_gate_test.c` #13 (precedence) + #14 (regression guard). (2) the **read
> staging pre-flight probe** (`open_resolved_file_staging.c`) now threads
> `ctx->identity` into its probe ctx so its STS exchange is scoped to the caller,
> not `anonymous` — a policy-scoped AssumeRole could otherwise answer the probe
> and the real open differently and turn a legitimate read into a spurious
> `kXR_NotFound`. **Only the krb5 origin leg (§5.7.1 items i/ii) now remains open**
> — infra-blocked (no live GSSAPI XRootD origin) + the request-sync GSS-carry.
> **UPDATE 2026-07-31 (d) — inbound krb5 delegation-CAPTURE state machine LANDED:**
> the last synchronous krb5 seam is built — the two-round `kXR_authmore`/`"fwdtgt"`
> capture path in a new `src/auth/krb5/deleg_capture.{c,h}` module (round-1 parks the
> session `krb5_auth_context` + verified client on the connection-scoped
> `brix_ctx_krb5_t` and replies `"fwdtgt"`; round-2 decodes the forwarded `KRB_CRED`
> via the live-proven capture core, serialises the TGT to a 0600 FILE ccache, and
> finalizes through the extracted `brix_krb5_session_grant` so the single-round path
> is byte-for-byte unchanged), armed by the new `brix_krb5_delegate on|off` directive
> (default off), and bound at request time by `brix_root_vfs_bind_deleg` (`op_path.c`)
> which derives the origin SPN and calls `brix_vfs_deleg_set_krb5` — closing the loop
> into the already-landed vfs_deleg → `&P=krb5` dispatch chain. Unit-covered by
> `tests/c/krb5_deleg_capture_test.c` (RUNNER `krb5_deleg_capture`, no KDC) +
> `test_krb5_delegate_load.py` (`nginx -t` directive parse, 3/3). Only driving it end
> to end with a real XrdSeckrb5-*forwarding* client stays environment-blocked; the
> krb5 core underneath is already live-proven (`test_krb5_forward_live.py` `capture`).
> **UPDATE 2026-08-01 (e) — inbound leg now LIVE end-to-end (the forwarding client is
> built):** the environment block on item 1 is lifted. The clean-room client's krb5
> module (`client/lib/auth/sec/sec_krb5.c`) gained a round-2 `more()` handler: on the
> server's `"fwdtgt"` continuation it forwards the caller's TGT via
> `krb5_fwd_tgt_creds()` under the round-1 auth context (the subkey the server picked
> up through `krb5_rd_req`) and replies `"krb5"` + `KRB_CRED`. Round state
> ({context, auth-context, ccache, client principal}) is parked file-static across
> rounds — sound because the native auth driver is synchronous and single-connection —
> and freed by `more()` after forwarding or by a new `cleanup()` on a single-round
> `kXR_ok` (delegation off), so the AP-REQ-only path is unchanged (native-krb5 suite
> still 7/7). Forwarding requires a forwardable TGT (`kinit -f`); a non-forwardable
> ticket fails closed with a clear message rather than silently downgrading. New live
> e2e `test_krb5_delegation_e2e.py` (3/3 vs a real MIT KDC): forwardable TGT → the
> two-round exchange completes and the login succeeds; the acceptor logs
> `"krb5 delegation captured forwarded TGT"` at info (added to `brix_krb5_deleg_capture`
> as the airtight server-side proof); non-forwardable TGT → refused. The last
> synchronous *and* the inbound-live krb5 seams are now closed; only a live `&P=krb5`
> **XRootD origin** for the outbound handshake (§5.7.1 item 2 / REMAINING ii) remains
> infra-blocked.
>
> **UPDATE 2026-08-01 (f) — native client krb5 wire made reference-correct + interop
> gate landed; outbound leg reclassified as a dialect mismatch.** A packet capture of
> the stock reference client (`/usr/bin/xrdfs` → real `xrootd`+`libXrdSeckrb5`) settled
> the exact XRootD krb5 wire: the credential payload is `"krb5\0"` (NUL-terminated
> protocol name, per `XrdSecInterface.hh`) + a **raw AP-REQ** (`krb5_rd_req`, ASN.1 tag
> `0x6e`). Two consequences: **(1)** the native client's bare 4-byte `"krb5"` prefix was
> *not* reference-correct (only brix's own tolerant acceptor accepted it) — `sec_krb5.c`
> now emits `"krb5\0"`, proven against a real reference origin by the new
> `tests/test_krb5_xrootd_interop.py` (4/4: stat/ls/byte-exact download/no-ccache
> negative), with brix tiers unchanged (native-krb5 7/7, delegation-e2e 3/3). **(2)** the
> *outbound* leg emits a **GSSAPI** token (`gss_init_sec_context`, tag `0x60`), which no
> stock `&P=krb5` XRootD origin accepts — so its live handshake is not "no peer" but a
> dialect gap; the de-risked closure is a raw-krb5 outbound path reusing the delegated
> TGT (see §5.7.1 REMAINING).
>
> **UPDATE 2026-08-01 (g) — raw-krb5 outbound leg BUILT, LANDED, and live-verified;
> production dispatch switched to it.** The de-risked closure from (f) is now the
> production path. New `src/auth/krb5/apreq.{c,h}` `brix_krb5_apreq_from_ccache()`
> renders the `"krb5\0"`+AP-REQ payload straight from the delegated per-user TGT
> (`krb5_cc_resolve` the carried ccache PATH → `krb5_get_credentials` a service ticket
> for the origin SPN → `krb5_mk_req_extended`), byte-identical to the (reference-verified)
> native client. `origin_auth.c` gains `brix_cache_origin_auth_krb5_raw()` — one
> `kXR_auth` leg over the existing `brix_krb5_kxr_wire` codec — and the origin dispatch
> (`origin_protocol_bootstrap.c` `origin_bs_auth_krb5`) now calls the RAW path, sourcing
> the ticket target from the advertised `&P=krb5,<spn>` (falling back to the request-time
> carried principal), no GSS re-import. The GSSAPI engine (`forward.c`,
> `brix_cache_origin_auth_krb5`) is retained (unused in production) with its unit intact.
> **Live proof:** the new `apreq` mode of `tests/c/krb5_forward_live.c` builds the AP-REQ
> from alice's delegated TGT against the unprivileged MIT KDC lab and validates it with
> `krb5_rd_req` against the origin keytab — exactly what a real `&P=krb5` origin does —
> asserting the recovered identity is `alice` (`tests/test_krb5_forward_live.py`:
> raw-leg-carries-user-identity / bound-to-origin-principal / wrong-password-no-credential).
> The dispatch unit `tests/c/origin_krb5_dispatch_test.c` was updated to the raw contract
> (advertised-SPN-wins + bare-advert fallback + fail-closed). This closes REMAINING (ii):
> the outbound krb5 leg is no longer a dialect gap but a shipped, interoperable path.
>
> **UPDATE 2026-08-01 (h) — the end-to-end brix-cache → LIVE stock-`xrootd` krb5
> origin handshake is CLOSED; §5.7 has NO residual.** The "environment-blocked
> only" gate in (g) is lifted — a stock `xrootd` krb5-ONLY origin
> (`sec.protbind * krb5`, `libXrdSeckrb5`) runs in this shell, so the full
> delegated chain is now proven with three real processes and no mocks:
> native client ─krb5(+deleg)→ brix-cache ─`"krb5\0"`+AP-REQ→ stock `xrootd`.
> `tests/test_krb5_cache_origin_e2e.py` (**5/5** vs the session MIT KDC):
> forwardable-TGT capture → 0600-ccache carry → raw AP-REQ → `krb5_rd_req`
> acceptor → **byte-exact** download; capture-marker proof; missing-object clean
> error; non-forwardable-TGT fail-closed; and a delegated `ls /` that enumerates
> the origin AS the user (path-op leg). Because the origin admits *no* protocol
> but krb5, a correct transfer is airtight proof the delegated outbound AP-REQ was
> accepted end-to-end. **Three correctness fixes fell out of being the first live
> exerciser of the cache-MISS outbound leg:** (1) `sd_xroot` `.cred_accept` was
> missing `BRIX_SD_CRED_GSS_KRB5` (the VFS deny-gate refused the delegated cred
> before origin contact); (2) `brix_cache_origin_auth_krb5_raw` dereferenced
> `t->c->log`, but the composed SOURCE-backend fill task has `t->c == NULL` (worker
> SIGSEGV) — now `(t->c != NULL) ? t->c->log : ngx_cycle->log`; (3) **the real
> gap** — the composed-tier cache MISS-fill (`brix_cache_open_fill_offload` →
> `brix_cache_fill_composed_thread` → `brix_sd_cache_fill_key`) opened the source
> **anonymously** (`sd_cache_fill(…, NULL)`) even though the cred-carry infra
> existed one layer down (`cache_fill_acquire` already threads a `brix_sd_cred_t`).
> Closed by resolving the delegated cred on the MAIN thread in
> `brix_open_try_cache_offload` (the `open_request_resolve.c` recipe; fail-closed on
> a deny-mode gate), carrying it onto the fill task's `cred_*` fields
> (`cache_fill_carry_cred`), and projecting it back for the source open
> (`cache_fill_cred_view`) through the now-cred-aware
> `brix_sd_cache_fill_key(inst, key, cred)`. **This is generic** — it forwards
> bearer / x509-proxy / SSS / krb5 identity on every composed-cache MISS, not just
> krb5; HTTP-cache + CVMFS-prewarm callers pass `NULL` (service credential,
> unchanged). A latent adjacent bug was also fixed: the path-op session copier
> `sd_xroot_cred_copy` + its deny gate `sd_xroot_cred_must_deny` (`sd_xroot_ns.c`)
> omitted `krb5_ccache`, so write/namespace ops under a krb5 EXCHANGE cred would
> silently drop the TGT and fall back to the service credential even under
> `fallback_deny` — both now handle krb5 (covered by the delegated-`ls` test).
> **§5.7 (the krb5 origin leg) is now complete with zero infra-blocked residual.**

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

#### 5.5.1 STS wire dialect: `aws` vs `minio` (LANDED 2026-07-28, UNCOMMITTED)
The AWS-dialect origin leg was unit- and gate-green but could **not** exchange
against a real MinIO STS — the two implementations diverge on the wire, and the
offline unit (canned XML, fixed inputs) masked it. Empirically, against
`quay.io/minio/minio:latest`:

- **AWS** — `GET` with the SigV4 in the query (presigned form); implements
  `GetSessionToken` (no role ARN) and `AssumeRole`. MinIO **rejects** this: a
  `GET` with `X-Amz-*` query params routes to MinIO's *S3* presigned handler
  (which then demands `X-Amz-Expires`), never to STS.
- **MinIO** — `POST` to the endpoint **root** with an
  `application/x-www-form-urlencoded` body and **header-auth** SigV4 (service
  scope `sts`, literal `/` in the credential scope, signed headers
  `content-type;host;x-amz-content-sha256;x-amz-date`). Implements **only**
  `AssumeRole` — `GetSessionToken` returns *"Unsupported action"*. A bare
  `AssumeRole` with **no** `RoleArn` succeeds and returns creds inheriting the
  service user's policy; the returned `SessionToken` is a JWT.

The dialect is an explicit, load-validated config choice, added as an **additive**
transport — the AWS GET/query path is byte-for-byte unchanged:

```
brix_backend_s3_sts_flavor  aws | minio;      # default aws
```

Plumbed on **both** planes (HTTP `http_common.c` + stream `module.c`, enum-slot
`aws|minio`), merged in `shared_conf.h` (`NGX_CONF_UNSET_UINT` → `aws`), stamped
into `brix_s3_sts_conf_t.flavor` by `deleg_wire_stamp_sts`. Implementation:
`sts.h` (`enum brix_s3_sts_flavor`, `.flavor` field) · `sts_internal.h`
(`sts_post_t`, `sts_build_post`, `sts_http_post`) · `sts_sign.c`
(`sts_form_encode` + `sts_build_post` — form body, body-hash, header-auth SigV4
over `sts`) · `sts_http.c` (`sts_http_post` — POST + form body + the four signed
headers, explicit `Host:` with port so it matches the signed authority) · `sts.c`
(`sts_prepare_minio` / `sts_perform_post`, and the `flavor` branch in
`brix_s3_sts_assume` that POSTs to the bare endpoint). `sts_prep_common` was
extracted from `sts_prepare` so both dialects share TTL/clock/host/RoleSessionName
derivation identically.

**Tests.**
- Offline (`tests/c/sts_units_test.c`, runs under `test_c_auth_units.py`):
  `test_build_post_minio` (body/hash/scope/signed-headers/64-hex signature,
  RoleArn `:`/`/` percent-encoded in the body), `test_build_post_no_role`
  (no-ARN AssumeRole), `test_build_post_deterministic` (pure function → identical
  bytes). Real `sts_sign.o`/`crypto.o`/`sigv4.o` link.
- Live (`tests/test_sts_minio_live.py`, docker-direct, opt-out `STS_MINIO_LIVE=0`):
  boots MinIO, seeds a bucket+object, drives the **production**
  `brix_s3_sts_assume(flavor=MINIO)` through the `tests/c/sts_live_assume.c`
  harness, then proves the *returned* temp creds authenticate a token-folded S3
  GET byte-for-byte (200 + match), and the security-negatives: the same GET
  **without** the session token → 403, and an AssumeRole signed with a wrong
  service secret fails closed (no credential material leaks). 3/3 green.

#### 5.5.2 STS runtime wire — end-to-end through a live worker (LANDED 2026-07-31, UNCOMMITTED)
The §5.5.1 live proof exercised `brix_s3_sts_assume` directly; the *runtime* leg —
a booted worker capturing a front-door bearer, gating it through the VFS deleg
chain, and opening the S3 origin with the STS-minted cred — is now closed too.

**Config** (`tests/configs/nginx_root_s3_sts.conf`): a `root://` gateway with
`brix_auth token` (ztn front door → `tokenauth_map_identity` captures the raw JWT
into `ctx->bearer_token` and sets `ctx->identity`), an `s3://` storage backend,
`brix_backend_delegation exchange`, and the full `brix_backend_s3_sts_*` service
triple pointing at MinIO. **The discriminator:** the static
`brix_storage_credential` deliberately carries a **WRONG** secret, so a byte-exact
read can ONLY come from the STS-minted temporary credential — never the static
fallback.

**Runtime chain proven:** `tokenauth_map_identity` (capture) → read-open
`brix_root_vfs_bind_deleg` binds the bearer + `brix_proto_deleg_stamp_conf` →
`deleg_wire_stamp_sts` arms `live->sts` (EXCHANGE) → `brix_vfs_backend_cred` →
`brix_vfs_deleg_live_cred` **STS branch** → `brix_vfs_deleg_sts_cred` →
`brix_s3_sts_assume(RoleSessionName = token sub)` → `sd_remote` signs the outbound
S3 GET/HEAD with the temp `(ak, sk, session)` (session folded into
`x-amz-security-token` + the SigV4). Verified by `mc admin trace`: MinIO receives
an `AssumeRole` POST then the object GET signed with a **temporary** access key
(not the static `brixroot`), returning the bytes.

**Two product fixes** (both correctness, driven by this being the first runtime exerciser):
1. **Gate ordering** (`brix_vfs_deleg_live_cred`, `src/fs/vfs/vfs_deleg.c`): when
   `live->sts` is armed and the leaf accepts `BRIX_SD_CRED_S3`, STS is decided
   **before** the bearer branch. `sd_remote.cred_accept` lists BOTH `BEARER` and
   `S3`, so previously a captured WLCG bearer shadowed STS and was forwarded
   verbatim — an S3 origin cannot consume it, so the driver fell back to the static
   (wrong) key → 403. A bearer is the caller's *identity* here (RoleSessionName),
   not a forwardable S3 secret. Narrowed to armed-STS only: `live->sts == NULL`
   still forwards a genuine bearer to an xroot/https origin (unchanged).
2. **Staging pre-flight probe identity** (`open_resolved_file_staging.c`): the
   probe's VFS ctx now carries `ctx->identity` so its STS exchange is scoped to the
   caller (`RoleSessionName = sub`), not `anonymous`. A policy-scoped AssumeRole
   could otherwise answer the probe (anonymous) and the real open (the caller)
   differently → spurious `kXR_NotFound`, the exact failure the probe's deleg
   exists to prevent.

**Tests.**
- Runtime (`tests/test_sts_runtime_e2e.py`, docker-direct MinIO, port band
  LIFECYCLE_SHARED 30456, group `lc-sts-e2e`): **3/3** — `test_sts_exchange_mints_
  origin_cred_and_reads` (positive, byte-exact through the live worker),
  `test_delegation_off_falls_to_wrong_static_cred_and_is_refused` (SELECT → wrong
  static secret → refused), `test_broken_sts_service_secret_fails_closed` (armed
  STS with a corrupted **service** secret → deny, no service-cred fallback).
- Unit (`tests/c/deleg_gate_test.c` #13/#14): the gate-ordering precedence
  (STS-wins-over-bearer on an S3 leaf) and its regression guard (STS-unarmed bearer
  still forwarded), via an observable `brix_vfs_deleg_sts_cred` stub.

### 5.6 SSS PASSTHROUGH
The node holds the shared keytab, so it can **re-issue** an SSS credential to the origin asserting the same decrypted user/group. **Work:** `brix_cache_origin_auth_sss` already takes a `keytab_path` (`origin_auth.c:442`); add identity injection so the re-issued blob carries the inbound user, gated on origin advertising `sss`. Config: `brix_backend_sss_keytab`.

### 5.7 krb5 EXCHANGE (GSSAPI forwarding)
Only works with a **forwardable** ticket (`GSS_C_DELEG_FLAG`) — captured delegated GSS cred → new `src/auth/krb5/forward.c` `brix_krb5_deleg_to_origin()` initiating a fresh GSSAPI context to the origin. Needs origin `krb5` advertise + cross-realm/forwardable policy. Document as best-effort; fall to SELECT.

#### 5.7.1 Status — 2026-08-01 (crypto core + multi-leg negotiation engine + kXR wire adapter LIVE-verified against a real KDC over real frame bytes; async-safe cred carry + vfs_deleg gate + `&P=krb5` origin dispatch + the inbound two-round `"fwdtgt"` delegation-CAPTURE state machine ALL landed and unit/live-verified; **the outbound origin leg is now BUILT as a raw-krb5 AP-REQ path** (`apreq.c` + `brix_cache_origin_auth_krb5_raw`, the dialect stock `&P=krb5` XRootD origins actually speak) and live-verified via `krb5_rd_req` against the origin keytab in the KDC lab — see UPDATE (g); **the end-to-end brix-cache → live stock-`xrootd` krb5-origin handshake is now CLOSED — `test_krb5_cache_origin_e2e.py` 5/5, three correctness fixes landed, ZERO residual — see UPDATE (h)**)

The cryptographic halves of the krb5 EXCHANGE path — **capture** (round-2
forwarded-TGT → delegated GSS cred), **forward** (origin-leg
`gss_init_sec_context`), the **full multi-leg negotiation engine**
`brix_krb5_deleg_negotiate()` (loop to `GSS_S_COMPLETE` with mutual auth), and now
the **kXR wire adapter** `brix_krb5_kxr_wire()` (`src/auth/krb5/kxr_wire.c`) that
frames each negotiation leg as a `kXR_auth`/`kXR_authmore`/`kXR_ok` exchange — are
implemented and proven end-to-end against a live MIT KDC. The **same production
frame bytes** the origin leg emits are exercised in the live test against a
real-GSS kXR-framed acceptor (the codec is transport-agnostic over `send`/`recv`
seams, so production and test drive identical wire code). The async-safe cred
carry, the `vfs_deleg.c` gate branch, and the **`&P=krb5` production dispatch
site** (`origin_protocol_bootstrap.c`, selecting the krb5 leg on a live advert and
re-importing the carried TGT) have ALL landed and are unit/live-verified. What
remains is only the live GSSAPI handshake against a real `&P=krb5` XRootD origin
plus the inbound XrdSeckrb5-*forwarding* capture state machine (`auth.c`) — both
needing live krb5-speaking peers this environment does not have, exactly analogous
to the still-blocked S3-STS runtime invocation (§5.5). See item 2 below for the
exact split of what landed vs. what stays blocked.

**LANDED + VERIFIED (uncommitted):**
- `src/auth/krb5/capture.c` / `capture.h` — `brix_krb5_capture_fwd_cred()`: the
  round-2 crux. Decrypts the `KRB_CRED` blob the XrdSeckrb5 client sends after the
  server's `"fwdtgt"` challenge (`krb5_rd_cred` under the round-1 auth context),
  parks the forwarded TGT in a MEMORY ccache, and imports it as a
  `gss_cred_id_t` via `gss_krb5_import_cred`. Ownership of the ccache passes to
  the caller (the GSS cred references it). Opaque `void*` handles keep krb5/GSSAPI
  out of the header, mirroring `forward.h`.
- `brix_krb5_origin_princ_from_host()` (in `forward.c`, always compiled) — builds
  the origin principal `host/<backend-fqdn>@<REALM>` for the forwarded context,
  the realm taken from the gateway's own configured principal. This is the
  **derive-from-backend-host** decision: no dedicated directive for the origin
  principal. Rejects a backend host carrying `/` or `@` (no realm/component
  smuggling) and a realmless gateway principal.
- `brix_backend_krb5_forwardable on|off` (default **off**) — now on **both**
  planes: HTTP (`http_common.c`) and the root:// stream (`stream/module.c`, added
  here — krb5 auth runs on the stream plane). Load-validated at `nginx -t`
  (accepts `on`/`off`, rejects any other token). The shared `common` conf field +
  init + merge already existed; this wired the missing stream directive entry.
- `src/auth/krb5/kxr_wire.c` / `kxr_wire.h` — the **kXR wire adapter**
  `brix_krb5_kxr_wire()`: a `brix_krb5_wire_fn` transceiver that frames one
  negotiation leg as the XRootD `ClientAuthRequest` (24-byte header, credtype
  `"krb5"`, big-endian `dlen`) carrying the outbound GSS token, reads the
  8-byte `ServerResponseHeader`, and classifies the reply
  (`brix_krb5_kxr_classify`: `kXR_authmore`→continue, `kXR_ok`→settle, anything
  else→fail closed) with an anti-OOM `max_body` cap on the reply length. It is
  transport-agnostic over `send`/`recv` function pointers so the identical frame
  code runs in production and in the live test. The production origin-leg wrapper
  `brix_cache_origin_auth_krb5()` (`src/fs/cache/origin_auth.c`, guarded
  `BRIX_HAVE_KRB5`) binds this codec to a real `brix_cache_origin_conn_t` and
  drives `brix_krb5_deleg_negotiate()` to completion. **Call-ready but not yet
  dispatched in production** — see REMAINING (i).

**Verification (docker-free, opt-out `KRB5_LIVE=0`):**
- `tests/test_krb5_forward_live.py` — an **unprivileged** MIT KDC stood up inside
  a user namespace (`unshare -Ur`, uid→root in-ns; KDC on high port 18800 in the
  shared netns). **11 tests** (was 4): origin leg carries alice's identity · token
  bound to the origin principal (wrong-keytab acceptor refuses) · wrong password
  yields no cred · **capture path** — alice's TGT forwarded via `krb5_fwd_tgt_creds`
  into a real `KRB_CRED`, run through the production `brix_krb5_capture_fwd_cred`,
  and the resulting delegated cred drives the origin leg to an acceptor that still
  sees `alice@BRIX.TEST` · **negotiate path** (3, added 2026-07-31) — the
  production multi-leg engine `brix_krb5_deleg_negotiate()` drives the WHOLE GSSAPI
  loop to `GSS_S_COMPLETE` against an in-process acceptor loop, both sides reaching
  completion carrying `alice@BRIX.TEST` with mutual auth verified; wrong-keytab
  origin fails closed; wrong password never enters the engine · **kXR wire path**
  (4 new, added 2026-07-31) — `classify` self-test pins the reply-status branches
  (`kXR_authmore`→continue / `kXR_ok`→settle / `kXR_error`+unexpected→fail closed);
  the multi-leg drive now runs **over real kXR frames** — `brix_krb5_kxr_wire`
  serialises each `brix_krb5_deleg_negotiate` leg as a `ClientAuthRequest` across a
  socketpair to a real-GSS kXR acceptor thread, and alice's identity arrives at the
  far side · wrong-keytab origin and wrong password each fail closed with no
  identity leak. Harness `tests/c/krb5_forward_live.c` (modes `origin` / `capture`
  / `negotiate` / `kxrwire` / `classify`), compiled ad-hoc by the pytest (not in
  `./config`); the `kxrwire`/`classify` link path pulls in the production
  `kxr_wire.o`.
- `tests/test_krb5_origin_princ.py` — offline (no KDC): success / overflow /
  injection for `brix_krb5_origin_princ_from_host()`. Harness
  `tests/c/krb5_origin_princ_test.c`.
- `tests/test_krb5_forwardable_load.py` — `nginx -t` only (no server boot): the
  `brix_backend_krb5_forwardable` directive parses `on`/`off` on **both** the HTTP
  and the stream plane, and a non-boolean value is a hard load error on both. Pins
  the stream command-table entry added here so a future edit cannot silently drop
  the directive (which would turn an armed forwardable config into a fail-open
  no-op). 6 tests.

**LANDED:**
1. **Inbound two-round delegation-CAPTURE state machine** — **DONE (2026-07-31).**
   Both rounds arrive as `kXR_auth` with the `"krb5"` credtype prefix (routed to
   the krb5 handler via `gsi_auth_cred_routes`); the connection-scoped
   `brix_ctx_krb5_t` sub-struct (`ctx_structs.h`) disambiguates by `round`. The
   round logic lives in a dedicated `src/auth/krb5/deleg_capture.{c,h}` module (new
   in `./config`; the file/CCN caps forbid inlining it into `auth.c`), gated by the
   new `brix_krb5_delegate on|off` directive (default off — `brix_krb5_deleg_wanted`).
   - **Round 1** (`brix_krb5_begin_delegation`, `auth.c`): after `krb5_rd_req`
     succeeds, instead of finalizing, `brix_krb5_deleg_park()` copies the verified
     client principal and parks it + the round-1 `krb5_auth_context` (the session
     subkey) on the ctx via an `ngx_pool_cleanup_add` handler (frees the handles +
     `unlink`s the 0600 ccache at connection close), sets `round = 1`, and
     `brix_krb5_send_fwdtgt()` replies `kXR_authmore` carrying `"krb5"`+`"fwdtgt"`.
   - **Round 2** (`brix_krb5_finish_delegation` → `brix_krb5_deleg_capture`): the
     payload post-`"krb5"` prefix (optional-NUL-stripped by
     `brix_krb5_deleg_credbytes`) is fed to `brix_krb5_capture_fwd_cred(context,
     parked_auth_ctx, parked_client, …)`; the returned initiator cred is serialised
     to a fresh 0600 FILE ccache (`brix_krb5_cred_to_ccache`) whose PATH is stashed
     on `ctx->krb5.ccache`, all round-1 + capture handles are released on every
     path, and the shared success bookkeeping (`brix_krb5_session_grant`, extracted
     from `brix_krb5_finalize` so the single-round path is byte-for-byte unchanged)
     finalizes the login. At request time `brix_root_vfs_bind_deleg` (`op_path.c`)
     derives the origin SPN from `cache_origin_host` + the gateway principal
     (`brix_krb5_deleg_origin_spn`, gated on `backend_krb5_forwardable`) and binds
     the carried ccache PATH + SPN via `brix_vfs_deleg_set_krb5` — closing the loop
     into the already-landed `vfs_deleg.c` krb5 branch → `&P=krb5` origin dispatch.
   - **Coverage:** the always-compiled synchronous seams (`_wanted` gate,
     `_credbytes` native/NUL/short/empty framing, `_send_fwdtgt` wire bytes,
     `_origin_spn` gate + derivation, security-negatives) are unit-covered by
     `tests/c/krb5_deleg_capture_test.c` (RUNNER `krb5_deleg_capture`; `#include`s
     the TU compiled WITHOUT `BRIX_HAVE_KRB5`, stubs the wire/pool surface — no
     krb5/OpenSSL/project objects linked). The krb5/GSSAPI capture core underneath
     it is proven live vs a real MIT KDC by `test_krb5_forward_live.py` mode
     `capture`. Only a live XrdSeckrb5-*forwarding* client to exercise the full
     two-round wire round-trip end-to-end stays environment-blocked (see below).
2. **Outbound multi-leg drive** — the *negotiation engine* is now **LANDED +
   live-verified**; only the kXR transport bridge and the synchronous cred carry
   remain (both environment-blocked).
   - **DONE (2026-07-31):** `brix_krb5_deleg_negotiate()` (`src/auth/krb5/forward.c`,
     decl `forward.h`) owns the full loop `gss_init_sec_context` ↔ origin replies to
     `GSS_S_COMPLETE`. It takes a caller-supplied `brix_krb5_wire_fn` transceiver
     (one call per outbound token; hands back the origin's reply + a `done` flag
     modelling `kXR_authmore`/`kXR_ok`), requests mutual auth and **refuses to
     complete without `GSS_C_MUTUAL_FLAG`**, fails closed on a premature/empty
     origin reply or a token still owed after `kXR_ok`, guards against runaway legs,
     and never leaks the GSS context/target. Where `brix_krb5_deleg_to_origin()`
     does one step, this owns the whole exchange. Live-proven by the `negotiate`
     mode above (7/7 vs a real KDC), so this is the hard crypto/protocol piece
     named as the §5.7 gap — no longer open.
   - **DONE (2026-07-31) — kXR wire adapter.** The `brix_krb5_wire_fn` over a real
     `brix_cache_origin_conn_t` is **built and live-verified**: the codec
     `brix_krb5_kxr_wire()` (`src/auth/krb5/kxr_wire.c`) frames each leg as
     `kXR_auth` credtype `"krb5"` → `kXR_authmore`/`kXR_ok`, and the production
     wrapper `brix_cache_origin_auth_krb5()` (`origin_auth.c`, guarded
     `brix_krb5_forward_available()`) binds it to the origin connection and drives
     `brix_krb5_deleg_negotiate()`. The **exact production frame bytes** are proven
     against a real-GSS acceptor by the `kxrwire` test above — no longer dead wire
     code. The **dispatch site** that invokes this wrapper on a live `&P=krb5`
     origin advert has since landed too (see the `&P=krb5` production dispatch
     item below); only the live GSSAPI origin needed to exercise the completed
     handshake end-to-end stays environment-blocked.
   - **DONE (2026-07-31) — (ii) async-safe cred carry.** The lifetime blocker (a
     live `gss_cred_id_t` is request-scoped and unsafe to embed in the async
     `brix_cache_fill_t`, which outlives the request on a worker thread) is solved
     the same way the gsi leg carries an x509 proxy: **serialise to a 0600 FILE
     ccache and carry the PATH**, which is async-safe. `src/auth/krb5/carry.c`
     (NEW in `./config`) provides `brix_krb5_cred_to_ccache()` (export the captured
     initiator cred via RFC 5588 `gss_store_cred_into` with an explicit `ccache`
     store element, `overwrite=1` — **not** the deprecated `gss_krb5_copy_ccache`,
     which cannot initialise the target and rejects an empty temp as "bad format"),
     `brix_krb5_cred_from_ccache()` (re-import on a fresh handle for the fill task),
     and `brix_krb5_cred_carry_release()` (release cred + backing ccache/context
     together). Live-proven by `test_krb5_forward_live.py` mode `carry`: export
     alice's forwarded TGT → re-import on a fresh handle → drive the SAME production
     kXR multi-leg engine → the acceptor still observes `alice@REALM` (functionally
     identical), plus mode `carry-badpath` (re-import from a non-existent path fails
     closed, never fabricating a usable cred).
   - **DONE (2026-07-31) — (ii) `vfs_deleg.c` gate branch + capture-site bind.**
     `brix_deleg_live_s` now carries `krb5_ccache` (the async-safe FILE-ccache path)
     + `krb5_origin_princ`; `brix_vfs_deleg_set_krb5()` (`vfs_deleg_bind.c`) is the
     capture-site setter (allocates the bag when none is bound, mirroring
     `set_sts`/`set_sss`); `brix_vfs_deleg_krb5()` + a new branch in
     `brix_vfs_deleg_live_cred()` (`vfs_deleg.c`) select krb5 GSSAPI EXCHANGE right
     after the x509-proxy branch (a forwarded TGT is a real forwardable user
     credential, so it outranks STS/bearer/SSS), accept-gated on the new
     `BRIX_SD_CRED_GSS_KRB5` kind (EACCES before any origin contact when the leaf
     does not consume it) and carrying `krb5_ccache`/`krb5_princ` onto the POD
     `brix_sd_cred_t` as an EXCHANGE. Unit-covered by `deleg_gate_test.c` #15
     (selection SUCCESS), #16 (FAIL_KIND deny, no service fallback), #17 (setter
     allocate-bag + SELECT/empty no-op guards).
   - **DONE (2026-07-31) — (ii) the `&P=krb5` production dispatch.** The last
     buildable increment landed: the fill task now carries `cred_krb5_ccache`
     (the async-safe FILE-ccache PATH) + `cred_krb5_princ` (`cache_internal.h`),
     copied out of the POD `brix_sd_cred_t` by `sd_xroot_copy_cred_into_task`
     (`sd_xroot.c`) exactly like the x509/bearer/sss legs. The origin advert
     parser (`origin_bs_parse_advert`) now detects `&P=krb5` → `has_krb5`, and the
     credential ladder `origin_bs_auth_dispatch` (`origin_protocol_bootstrap.c`)
     gained a krb5 branch placed right after x509-proxy (a forwarded TGT is a
     forwardable USER credential, so it outranks bearer/sss). A new static helper
     `origin_bs_auth_krb5()` re-imports the delegated TGT from the carried ccache
     PATH via `brix_krb5_cred_from_ccache()`, drives `brix_cache_origin_auth_krb5`
     against the advertised `cred_krb5_princ`, and releases the fresh cred
     (`brix_krb5_cred_carry_release`) whatever the outcome. Per-user semantics are
     preserved end-to-end: a bad carried ccache fails CLOSED (`kXR_AuthFailed`)
     rather than falling back to a service credential, an origin that does not
     advertise krb5 for a carried TGT is refused, and an advert-less
     `kXR_authmore` never presents a service credential for a per-user TGT
     (`origin_bs_authmore_fallback` hard-stop). Unit-covered by
     `tests/c/origin_krb5_dispatch_test.c` (RUNNER `origin_krb5_dispatch`): advert
     parse (krb5 detected / mixed advert / absent), dispatch selection with the
     carried service principal, the not-advertised refusal, the fail-closed
     re-import, and the advert-less authmore hard-stop — the harness `#include`s
     the TU to reach its static helpers and stubs the whole external surface
     (origin wire I/O, the four auth legs, the krb5 carry), so no krb5/OpenSSL/
     project objects are linked.
   - **DONE (2026-08-01, UPDATE (g)) — the outbound leg is now a shipped raw-krb5
     path; the dialect gap is closed.** The GSS outbound path (`brix_krb5_deleg_negotiate`,
     `src/auth/krb5/forward.c`) drove `gss_init_sec_context()` and framed a **GSSAPI**
     token (tag `0x60`, mech-OID wrapper) which — as the reference capture proved
     (`/usr/bin/xrdfs` → stock `xrootd`+`libXrdSeckrb5`, `tests/test_krb5_xrootd_interop.py`)
     — no stock `&P=krb5` XRootD origin accepts: stock XRootD krb5 is **raw** (`"krb5\0"`
     + a bare **AP-REQ**, ASN.1 `[APPLICATION 14]`, tag `0x6e`, fed to `krb5_rd_req()`).
     The closure is now BUILT: new `src/auth/krb5/apreq.{c,h}` `brix_krb5_apreq_from_ccache()`
     takes the delegated per-user TGT (`t->cred_krb5_ccache`), `krb5_cc_resolve`s it,
     `krb5_get_credentials` a service ticket for the origin SPN, `krb5_mk_req_extended`
     an AP-REQ, and emits `"krb5\0"` + AP-REQ **byte-identical to the reference-verified
     native client**. `origin_auth.c` `brix_cache_origin_auth_krb5_raw()` presents it in
     one `kXR_auth` leg over the existing `brix_krb5_kxr_wire` codec, and the origin
     dispatch (`origin_protocol_bootstrap.c` `origin_bs_auth_krb5`) now routes to the RAW
     path — ticket target from the advertised `&P=krb5,<spn>`, falling back to the
     request-time carried principal — with **no GSS re-import**. The GSS engine remains
     in-tree (unused in production) with its unit intact. **Live-verified:** the new
     `apreq` mode of `tests/c/krb5_forward_live.c` builds the AP-REQ from alice's
     delegated TGT against the unprivileged MIT KDC lab and validates it with
     `krb5_rd_req` against the origin keytab (recovered identity == `alice`), plus a
     bound-to-origin-principal negative and a wrong-password-no-credential negative
     (`tests/test_krb5_forward_live.py`). The **sole** residual is an end-to-end
     brix-cache → live `xrootd`-origin handshake (environment-blocked only); the crypto
     and the exact wire are now reference-proven on both the build and validate sides.
   - **DONE (2026-08-01, UPDATE (f)) — the native client krb5 wire is now
     reference-correct + interop-verified.** Separately from the outbound leg, the
     clean-room client emitted a **bare** 4-byte `"krb5"` credential prefix, which the
     brix acceptor tolerated (it auto-skips the optional NUL) but which **no** reference
     XrdSec acceptor accepts — `XrdSecInterface.hh` requires the payload to *begin with
     the protocol name as a string*. `sec_krb5.c` now emits `"krb5\0"` (both the round-1
     AP-REQ and the round-2 forwarded-TGT payloads), matching the captured reference
     byte-for-byte. `tests/test_krb5_xrootd_interop.py` drives the native `xrdfs`/`xrdcp`
     against a real `xrootd`+`libXrdSeckrb5` origin (stat/ls/byte-exact download +
     no-ccache negative, 4/4); the brix-server tiers are unchanged (native-krb5 7/7,
     delegation-e2e 3/3 still green). **Item 1's inbound leg remains fully live**
     (UPDATE (e)): the round-2 `more()` forwarding handler drives the two-round
     `kXR_authmore`/`"fwdtgt"` capture SM end to end vs a real MIT KDC.

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

**New:** `src/auth/token/exchange.{c,h}`, `src/auth/s3/sts.{c,h}`, `src/auth/krb5/forward.{c,h}`, `src/auth/krb5/kxr_wire.{c,h}` (§5.7 origin kXR wire), `src/auth/krb5/carry.{c,h}` (§5.7 (ii) async-safe FILE-ccache cred carry), `src/fs/vfs/vfs_deleg.c` (live-bag bind + gate, incl. the krb5 GSSAPI-EXCHANGE branch), `docs/10-reference/backend-delegation.md` (capability matrix).
**Touched:** `sd.h` (mode enum/field), `vfs_cred.c` + `vfs_internal.h` (live bag, decide-body mode dispatch), `http_common.c` + stream module table (directives), `gsi/parse_x509.c` + `auth/gsi/auth.c` (root full-proxy bucket), `webdav/auth_cert.c`/`auth_token.c` + `s3/auth_bearer.c` (header capture), `delegation.c` (session-scoped variant), `origin_auth.c` (SSS identity inject), `client/` (opt-in full-proxy send flag), `./config` (new srcs).

---

## 10. Sequencing

**P70.1** Foundation §4 → **P70.2** bearer passthrough+exchange §5.4 (highest value, only true zero-provisioning) → **P70.3** x509 passthrough §5.1 (primary ask) → **P70.4** delegate/mint promotion §5.2–5.3 → **P70.5** S3 STS §5.5 → **P70.6** cross-cutting/async/metrics §6 → **P70.7** SSS/krb5 §5.6–5.7 → **P70.8** docs/tests. Each sub-phase: implement → 3 tests/mode → review → commit to main (per repo git policy).
