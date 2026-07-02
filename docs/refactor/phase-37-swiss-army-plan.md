# Phase 37 — Swiss-army-knife client: capability engine + just-works auth

**Status:** planning / critic artifact. Use `client/` and
[`docs/04-protocols/native-client-tools.md`](../04-protocols/native-client-tools.md)
as the current source-verified client feature surface.

Grounded design (codebase discovery + adversarial critic, 2026-06-15). The native
clients keep official flag/semantics for compatibility; everything here is additive.
Guiding principle: **the user states intent; two engines absorb the protocol/auth
mechanics and hide them.**

---

## Engine 1 — Capability discovery (hide complexity)

One probe at connect → a cached `xrdc_caps` struct on `xrdc_conn`; every op consults
it and silently does the right thing. Re-runs automatically on redirect because
`xrdc_reconnect()` re-enters `xrdc_bringup_ex()`.

**Populate (`xrdc_caps_populate()` at end of `xrdc_bringup_ex`, lib/conn.c):**
- FREE (already decoded): `server_flags` (conn.c:131 — suppgrw→pgrw, haveTLS,
  gotoTLS→tls_required, supposc→posc, role bits), `sec_level` (conn.c:137), TLS
  posture (roots:// + live io.ssl), the `&P=` list (conn.c:202).
- ONE batched `kXR_Qconfig "chksum readv tpc tpcdlg xrdfs.ext"` (key set verified in
  src/query/config.c:117-156). Server emits all 7 checksums; `tpc` is a bare digit
  (XrdCl compat); `xrdfs.ext` folds in the standalone probe in ops_ext.c:170 (delete it).
- **Fail-open contract (mandatory):** the probe NEVER fails the connection; a missing
  answer or `key=0` leaves the cap false → client degrades to plain/compat paths.

**Adaptations (consumers read `c->caps`, never re-decode):**
- pgread/pgwrite ↔ plain read/write on `caps.pgrw` (`--pgrw`=require, `--no-pgrw`=off, default auto).
- TPC ↔ client-streamed on `caps.tpc`/`caps.tpcdlg` (TPC_ONLY fails fast).
- checksum auto-negotiate: intersect compiled algos ∩ `caps.cksum_algos` (pref crc32c>adler32>crc64nvme>crc64>md5).
- readv/writev auto-chunk under MAXSEGS/MAXBYTES; plain-loop emulation when `!caps.readv`.
- TLS posture applied uniformly to primary + kXR_bind secondaries + redirect reconnects.
- `xrdc_caps_explain()` + pure accessors = single source of truth for xrddiag / xrdfs explain.

---

## Engine 2 — Just-works auth (matches the nginx module's accepted set)

Server accepts (verified): root:// `gsi, ztn(JWT), krb5, sss, unix` (src/session/login.c
`&P=`); web `Bearer JWT` (src/webdav/auth_token) + `S3 SigV4` (src/s3/auth_sigv4*);
plus X.509 proxy/VOMS (src/auth/gsi), macaroons (WebDAV).

**Layer 1 — unified discovery (`lib/sec/cred_discover.c`, new):** centralize the orders
that today live scattered across the sec modules — token `BEARER_TOKEN`→`BEARER_TOKEN_FILE`
→`$XDG_RUNTIME_DIR/bt_u<uid>`→`/tmp/bt_u<uid>`; X.509 `X509_USER_PROXY`→`/tmp/x509up_u<uid>`
(+ cert/key `X509_USER_CERT/KEY`→`~/.globus/usercert.pem` for auto-mint); S3 env + AWS
credentials-file/`AWS_PROFILE`; sss/krb5 existing. root:// (auth.c) and web
(copy.c `web_auth_headers`) both delegate here → identical semantics, no wire change.

**Layer 1.5 — `~/.xrdrc` profiles (`lib/config/xrdrc.c`, new, optional):** `[profile <name>]`
with host/scheme glob + overrides (token file, proxy, cert/key, sss keytab, s3 creds,
preferred order, audience, scope). Precedence CLI > profile > [default] > env > default
path. Byte-identical to today when absent.

**Layer 2 — server-driven negotiation (extend auth.c:142-184):** rank candidates by the
server's `&P=` ORDER ∩ client preference ∩ **live TLS state** (never send ztn/gsi in the
clear when the server meant TLS-only); accumulate a per-candidate attempt ladder so the
final error reads "tried gsi (proxy expired), ztn (no token), unix (refused non-loopback)".

**Layer 3 — refresh/renew before a doomed send:** X.509 auto-renew via the existing
`xrdc_proxy_create()` (proxy.c — today only the CLI calls it) when proxy missing/near-expiry
and cert+key are discoverable (TTY-on/batch-off, <20min threshold); token refresh via
`credinfo.c` `xrdc_token_meta_get` (re-read source / optional `token_refresh_cmd`),
audience/scope selection among multiple tokens.

---

## Roadmap (phased; Phase 0 is the keystone)

- **Phase 0 — Capability engine foundation.** `xrdc_caps` + `xrdc_caps_populate` + batched
  Qconfig + fail-open + re-probe-on-redirect + `xrdc_caps_explain`. ~9 features collapse to
  "read c->caps". Tests: populated / fail-open / replaced-after-redirect.
- **Phase 1 — Capability-aware fallbacks.** pgrw, cksum-negotiate, TPC auto, readv chunking.
- **Phase 2 — Just-works auth (discovery + negotiation).** cred_discover, ranked negotiation,
  attempt-ladder errors, ~/.xrdrc.
- **Phase 3 — Auth lifecycle.** X.509 auto-renew, token refresh, audience/scope selection.
- **Phase 4 — Transparency.** route handle-based read/write/sync through the
  wait/waitresp/redirect absorber; mid-stream redirect replay; TLS posture uniformity;
  HTTP upload framing auto-select.
- **Phase 5 — POSIX emulation.** `xrdc_walk` (generalize copy_recursive + xrdfs walk_dir) →
  `rm -r`/`chmod -R`/`stat -R`/`du`; `xrdc_glob` wired into all path-taking ops.

---

## Critic gaps (beyond the above — important, several are WLCG table-stakes)

1. **Redirect-carried opaque/CGI dropped (REAL BUG).** `parse_redirect` (frame.c) reads only
   port+host and discards the `?...` tail — but WLCG redirectors append a data-node token /
   fresh `&P=` / `tried=` there. Capture it and prefer a redirect-supplied token over local
   re-discovery on reconnect. Breaks the dominant manager-mints-data-node-token pattern.
2. **VOMS FQAN / token aud-scope are diagnostic-only.** Never used to SELECT a credential or
   warn pre-flight. Promote to first-class selection; surface "proxy lacks /cms/Role=production".
   `xrdc_proxy_create` mints a PLAIN RFC proxy with no VOMS AC — document or add.
3. **No token ACQUISITION (only discovery).** Add pluggable acquirers: oidc-agent socket,
   htgettoken/vault, built-in OAuth2 device-code flow keyed off the endpoint issuer. The
   "no token at all" laptop/student case is the biggest just-works miss.
4. **TPC token delegation still has remaining gaps, but is no longer absent.**
   WebDAV `Credential: oidc-agent` and RFC 8693 `token-exchange` are implemented
   in `src/webdav/tpc_cred.c`; native root TPC can complete ztn or GSI outbound
   auth after `kXR_authmore` when configured. Remaining work is automatic
   downscoped token/macaroon minting and broader multihop/native delegation
   polish.
5. **krb5 lifecycle.** FAST/armored AS, forwardable/delegated tickets, ccache COLLECTIONS
   (DIR:/KEYRING:/KCM: — the RHEL9 default), auto-kinit from keytab (CI), TGT renew. Today:
   plain AP-REQ vs default ccache only.
6. **Clock-skew leeway missing from the live decision.** `exp <= now()` is hard; add symmetric
   ~300s leeway to exp/nbf/iat + proxy notBefore/notAfter, and surface measured skew (HTTP Date).
7. **No transfer-level retry / replica failover / resume.** Only clean open-handle redirect is
   covered — not TCP reset, flaky-node kXR_error, or "try the next replica". Add bounded
   backoff+jitter retries + replica failover (reuse the aio_mgr.c reconnect philosophy).
8. **kXR_wait: blocking sleep, no jitter/deadline/cancellation.** Thundering-herd on CI; add
   jitter, a wall-clock deadline, progress/ETA for tape recalls, SIGINT responsiveness.
9. **CI/batch persona.** Stable exit-code taxonomy (auth vs not-found vs transport vs quota,
   from xrdc_status), `--json` explain/caps, guaranteed zero-prompt in non-TTY.
10. **S3 breadth.** `AWS_SESSION_TOKEN`/X-Amz-Security-Token (STS), path-vs-vhost addressing,
    pass presigned URLs through unsigned, region-redirect on 301.
