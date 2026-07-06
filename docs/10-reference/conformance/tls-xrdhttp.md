# TLS / HTTP client-certificate path — conformance

This component covers how an x.509 client certificate presented over `davs://`
(HTTPS/WebDAV, TLS mutual auth) is validated before the request is authorized.

The load-bearing architectural fact is that **our `davs://` path runs the same
GSI chain-verification core as our `root://` path**, whereas the official XRootD
`XrdHttp` server performs **TLS-layer verification only** for HTTP client certs
and never invokes its GSI chain validator (`XrdCryptoX509Chain::Verify`) on that
path. As a result every GSI-profile control our module enforces for `root://`
— signing_policy / namespace confinement, RFC 3820 proxy validation, limited-proxy
monotonicity, per-cert weak-algorithm and DN-sanity policy, CRL strictness —
also applies to HTTPS clients on our server but does not apply to HTTPS clients
on stock XRootD.

Entry points:
- Ours (HTTP): `src/protocols/webdav/auth_cert.c:415` (`webdav_verify_proxy_cert`)
  → shared core `src/auth/crypto/gsi_verify.c:162` (`brix_gsi_verify_chain`).
- XRootD (HTTP): `/tmp/xrootd-src/src/XrdHttp/XrdHttpSecurity.cc:94`
  (`XrdHttpProtocol::HandleAuthentication`).

## Normative basis

- **RFC 5246 / RFC 8446 (TLS)** — TLS server MUST validate the client
  certificate chain to a trust anchor when mutual authentication is required.
- **RFC 5280 §6.1** — certification-path validation (trust anchor, validity,
  basicConstraints, name-chaining, revocation).
- **RFC 5280 §4.2.1.12 (extendedKeyUsage) / §4.2.1.3 (keyUsage)** — a certificate
  used for TLS client authentication must be usable for that purpose; `anyExtendedKeyUsage`
  nominally "permits every purpose."
- **RFC 3820** — X.509 Proxy Certificate profile (proxyCertInfo criticality,
  pCPathLenConstraint, delegation semantics, limited-proxy restriction §3.8).
- **IGTF Classic/MICS/SLCS profiles + Globus signing_policy / EACL** — a trusted
  CA is authorized to sign only within its delegated subject-DN namespace.
- **RFC 5280 §6.3 / IGTF** — CRL-based revocation checking of the presented chain.

## Requirements

### TLS-layer chain validation of the client certificate (RFC 5246; RFC 5280 §6.1)

- **Requirement:** the server must verify the presented client certificate chains
  to a configured trust anchor and is otherwise valid (dates, basicConstraints,
  name chaining) before accepting the connection identity.
- **Ours:** nginx's `ssl_verify_client on` engages the OpenSSL peer-verify path
  during the handshake; the request handler then reads the outcome with
  `SSL_get_verify_result(ssl)` at `src/protocols/webdav/auth_cert.c:458` and refuses
  to proceed unless the leaf is present (`SSL_get_peer_certificate`,
  `auth_cert.c:451`) and `X509_V_OK`. A `X509_V_OK` result plus a config where our
  CA file/CRL are identical to nginx's own `ssl_client_certificate`/`ssl_crl`
  (`webdav_nginx_verify_compatible`, `auth_cert.c:328`) is accepted directly;
  otherwise the code re-verifies against our own cached `X509_STORE`
  (`auth_cert.c:471-491`).
- **XRootD v6.1.0:** `XrdTlsContext` sets `SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, …)`
  (`/tmp/xrootd-src/src/XrdTls/XrdTlsContext.cc:701`) and, when CRL checking is
  configured, `X509_V_FLAG_CRL_CHECK[_ALL]` on the context store
  (`XrdTlsContext.cc:708-711`). `HandleAuthentication` reads
  `SSL_get_verify_result(ssl)` and rejects a non-zero result
  (`/tmp/xrootd-src/src/XrdHttp/XrdHttpSecurity.cc:97-101`).
- **Verdict:** Conformant — both perform standard OpenSSL path validation at the
  TLS layer. Pinned by the `davs` chain matrix (CHN-001..010).

### GSI-profile chain validation on the HTTP path (RFC 3820; IGTF/EACL)

- **Requirement:** for a WLCG/grid deployment, HTTP client certificates must be held
  to the same grid trust model as the native protocol — proxy-profile checks,
  namespace/signing-policy confinement, and per-cert conformance policy.
- **Ours:** `webdav_verify_proxy_cert` funnels the leaf + peer chain into the
  **same** `brix_gsi_verify_chain` used by `root://` (`auth_cert.c:478`). That core
  runs, after `X509_verify_cert`: signing_policy enforcement
  (`gsi_verify.c:64` → `brix_sp_table_check`, `store_policy.c:269`), limited-proxy
  monotonicity (`gsi_verify.c:40` → `brix_proxy_chain_ok`, `store_policy.c:355`),
  and per-cert policy (`gsi_verify.c:116` → `brix_cert_policy_violation` /
  `brix_proxy_pci_ok`, `store_policy.c:404`/`:493`).
- **XRootD v6.1.0:** `HandleAuthentication` parses the peer stack into an
  `XrdCryptoX509Chain` (`XrdHttpSecurity.cc:104-109`) but only ever calls
  `chain.EECname()` / `chain.EEChash()` to extract a DN for the gridmap
  (`XrdHttpSecurity.cc:116-131`). It **never** calls `XrdCryptoX509Chain::Verify`
  — a grep for `->Verify(`/`chain.Verify` across `src/XrdHttp/*.cc` returns nothing.
  Signing_policy is not parsed anywhere in `XrdSecgsi` at all; the GSI proxy-chain
  validator is engaged only on the `root://` `kXR_auth` path.
- **Verdict:** Stricter-than-XRootD — our `davs://` clients get full GSI-profile
  validation that stock `XrdHttp` clients do not. Pinned by the `davs`-run
  signing_policy and proxy families (see the divergence table).

### extendedKeyUsage / keyUsage for client authentication (RFC 5280 §4.2.1.12/§4.2.1.3)

- **Requirement:** a certificate presented for TLS client authentication must be
  usable for that purpose. RFC 5280 states `anyExtendedKeyUsage` "permits every
  purpose"; a leaf whose EKU omits `clientAuth` (and is not `anyEKU`) is not a
  valid client cert, and a serverAuth-only intermediate should not issue a client leaf.
- **Ours:** two independent layers. (1) nginx's TLS layer verifies the client
  under the OpenSSL `SSL_CLIENT` purpose (server-side peer verification), which
  performs EKU chaining and does **not** honor an `anyExtendedKeyUsage`-only leaf
  for client auth and rejects a `serverAuth`-restricted intermediate in the client
  path — this is production truth of `ssl_verify_client` and is recorded as a
  deliberate stricter-than-RFC reading in
  `tests/clauses/_decisions.py` (CHN-031, CHN-040, CHN-118). (2) At the application
  layer, `brix_gsi_verify_chain` is called with `client_purpose=1`
  (`auth_cert.c:481`), which runs `brix_leaf_purpose_violation`
  (`store_policy.c:460`): if EKU is present it must include `clientAuth` or `anyEKU`
  (`store_policy.c:469`) and, if keyUsage is present, it must assert
  `digitalSignature` or `keyAgreement` (`store_policy.c:484`).
- **XRootD v6.1.0:** no EKU/keyUsage purpose check beyond whatever the TLS layer's
  `SSL_VERIFY_PEER` applies; `HandleAuthentication` does no application-level purpose
  validation (`XrdHttpSecurity.cc:94-149`).
- **Verdict:** Stricter-than-XRootD (and stricter-than-a-naive-RFC-reading at the
  TLS layer). Pinned CHN-031, CHN-040, CHN-118.

### Proxy certificates over HTTPS (RFC 3820)

- **Requirement:** proxy certificates carry impersonation authority; a server must
  either validate them to the full RFC 3820 profile or not accept them for the
  connection identity.
- **Ours:** the `davs://` path deliberately **does not accept proxies**. The
  `client_purpose=1` argument suppresses `X509_V_FLAG_ALLOW_PROXY_CERTS`
  (`gsi_verify.c:191-193`), so a proxy leaf presented over TLS fails standard path
  validation rather than being treated as a delegated client identity. HTTPS clients
  are expected to present an end-entity certificate; delegated authority on the HTTP
  side is carried by bearer tokens, not TLS proxies. Where a proxy *is* in play
  (native `root://`, `client_purpose=0`), the full RFC 3820 controls apply:
  proxyCertInfo criticality/policy-language (`brix_proxy_pci_ok`,
  `store_policy.c:493-518`) and limited→full monotonicity (`brix_proxy_chain_ok`,
  `store_policy.c:355`).
- **XRootD v6.1.0:** `XrdHttp` extracts only the EEC DN
  (`EECname()`, `XrdHttpSecurity.cc:116`) and performs no proxy-profile validation
  on the HTTP path. Legacy Globus GT2/GT3 proxies (CN=proxy with no proxyCertInfo)
  are recognized by the native code (`XrdCryptosslX509.cc`) but not held to RFC 3820
  monotonicity.
- **Verdict:** Divergent (by design) on acceptance — we refuse TLS proxies over
  `davs://` (`client_purpose=1`); Stricter-than-XRootD on the `root://` proxy
  controls. Legacy-proxy rejection is recorded in `tests/clauses/_decisions.py`
  (PXY-004/005/025..030/072/073/113/114 → reject) and PXY-136 (bare CN=proxy EEC → accept).

### Weak-algorithm, key-strength, serial and DN-sanity policy (RFC 5280 §4.1.2; IGTF)

- **Requirement:** conforming certificates use adequate key sizes and non-broken
  signature algorithms, positive ≤20-octet serials, and DNs free of embedded
  control bytes.
- **Ours:** enforced on every cert in the verified chain (both protocols) via
  `brix_cert_policy_violation` (`store_policy.c:404`): rejects RSA/DSA `< 2048` bits
  and EC `< 256` bits (`store_policy.c:414-420`); rejects MD2/MD4/MD5/**SHA-1**
  signatures (`store_policy.c:428-431`); rejects zero/negative serials and (for
  non-proxies) serials `> 20` octets (`store_policy.c:441-442`); and rejects any
  subject or issuer DN containing a byte `< 0x20` or `== 0x7f`
  (`brix_dn_has_control_bytes`, `store_policy.c:384-401`, `:451-454`).
- **XRootD v6.1.0:** uses raw `X509_verify()` and does not reject MD5/SHA-1 or
  short keys; DN comparison is raw byte `strcmp` with no control-byte or
  encoding normalization (per behavior notes: `XrdCrypto/X509.cc:782-812`,
  `XrdCryptoX509Chain.cc:622`).
- **Verdict:** Stricter-than-XRootD. Pinned by the chain/DN families on the `davs`
  run (CHN-*, DN-encoding). DN *encoding* normalization (UTF8 vs Printable,
  case-folding) remains unnormalized on both sides — a shared **Documented-limitation**.

### CRL revocation and CRL-expiry semantics (RFC 5280 §6.3; IGTF)

- **Requirement:** the presented chain should be checked against current CRLs;
  a stale (expired) CRL is not evidence of non-revocation.
- **Ours:** CRL strictness is a mode, `try` (default) or `require`
  (`store_policy.c:597`). Under `require` — or under `try` when a CRL exists —
  `X509_V_FLAG_CRL_CHECK` is set (`store_policy.c:613-618`). The `try`-mode verify
  callback `brix_crl_try_verify_cb` (`store_policy.c:582`) downgrades **only**
  `X509_V_ERR_UNABLE_TO_GET_CRL` (a CA that has no CRL at all) to success; every
  other CRL verdict, including `X509_V_ERR_CRL_HAS_EXPIRED` and `CERT_REVOKED`,
  stays fatal (`store_policy.c:588-591`). An expired CRL is therefore fatal even in
  the lenient mode.
- **XRootD v6.1.0:** at the TLS layer it can set `X509_V_FLAG_CRL_CHECK[_ALL]`
  (`XrdTlsContext.cc:708-711`) and honors `http.allowmissingcrl`
  (`XrdHttpProtocol.cc:1142-1144`). In its native GSI CRL parser an expired
  `nextUpdate` is logged at DEBUG but **not** treated as fatal
  (per behavior notes: `XrdCryptosslX509Crl.cc:573-576`); GSI CRL strictness is a
  0–3 config scale (crlIgnore/crlTry/crlUse/crlRequire).
- **Verdict:** Stricter-than-XRootD (expired-CRL-fatal under `try`). Pinned by the
  CRL family (CRL-*); note the CONSERVATIVE `removeFromCRL` decisions
  (`tests/clauses/_decisions.py` CRL-065/066) where we follow OpenSSL. Delta-CRL
  handling is not implemented on either side — a shared **Documented-limitation**.

## Divergence summary

| Aspect | Ours (`davs://`) | XRootD `XrdHttp` | Verdict | Tests |
|---|---|---|---|---|
| GSI chain verify on HTTP path | Full `brix_gsi_verify_chain` (`auth_cert.c:478`) | None — parses chain for DN only, no `Verify()` (`XrdHttpSecurity.cc:104-131`) | Stricter-than-XRootD | signing_policy + proxy families (davs run) |
| signing_policy / namespace | Enforced (`gsi_verify.c:64`, `store_policy.c:269`) | Not parsed at all in `XrdSecgsi` | Stricter-than-XRootD | signing_policy family |
| Client-auth EKU/keyUsage | TLS `SSL_CLIENT` purpose + `brix_leaf_purpose_violation` (`store_policy.c:460`) | TLS `SSL_VERIFY_PEER` only | Stricter-than-XRootD | CHN-031, CHN-040, CHN-118 |
| Proxy certs over TLS | Rejected (`client_purpose=1`, `gsi_verify.c:191`) | DN extracted, no proxy validation | Divergent (by design) | PXY-004/005/025..030/072/073/113/114, PXY-136 |
| Limited→full proxy monotonicity | Enforced (`store_policy.c:355`) | Detected, not enforced | Stricter-than-XRootD (root://) | proxy family |
| Weak sig (MD5/SHA-1) + short keys | Rejected (`store_policy.c:414-431`) | Raw `X509_verify()`, accepted | Stricter-than-XRootD | chain family |
| DN control-byte rejection | Rejected (`store_policy.c:384-401`) | Raw `strcmp`, no check | Stricter-than-XRootD | dn_encoding family |
| DN encoding normalization | Not normalized | Not normalized | Documented-limitation (shared) | dn_encoding family |
| Expired CRL | Fatal even under `try` (`store_policy.c:588`) | Warns only (DEBUG), not fatal | Stricter-than-XRootD | crl family |
| Delta CRLs | Not implemented | Not implemented | Documented-limitation (shared) | crl family |
