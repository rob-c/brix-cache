# Authentication & Authorization: official XRootD vs nginx-xrootd

> Part of the [XRootD vs nginx-xrootd comparison set](./README.md).

This document compares how **official XRootD** (the upstream C++ server, source
under `/tmp/xrootd-src/src`) and the **nginx-xrootd module** (this repository,
source under `src/`) authenticate clients and authorize requests. Every claim is
grounded in source with file paths and, where load-bearing, symbol/line
references. Where a fact could not be confirmed from source it is explicitly
marked **(not verified)**.

The two implementations share a wire protocol (`root://` `kXR_login` →
`kXR_auth`; HTTP `Authorization` / TLS client cert) and the WLCG identity model
(X.509/VOMS, WLCG/SciTokens bearer tokens, XrdAcc-style ACLs), but the codebases
are independent. They agree closely on the *visible* mechanisms and diverge in
plugin breadth, validation locality, and operational hardening.

For the module-internal view of these same topics see
[`docs/06-authentication/`](../../../06-authentication/auth-overview.md) and the
[source-verified comparison](../../source-verified-xrootd-comparison.md); this
page is the side-by-side. Nothing here is intended to contradict those documents
— where this module has grown since they were written (notably the `pwd` and
`host` protocols, added 2026-06), that is called out in
[Parity, divergences, and interop](#parity-divergences-and-interop).

---

## Scope

In scope:

- **Authentication** — proving *who* the client is: GSI/X.509/VOMS, WLCG /
  SciTokens / macaroon bearer tokens, SSS (shared secret), Kerberos 5, UNIX,
  password (`pwd`), host-based.
- **Authorization** — deciding *what* an authenticated (or anonymous) identity
  may do: XrdAcc-style authdb ACLs, VO ACLs, token-scope path gates, the global
  write gate, and path confinement as it relates to policy.
- The **protocol-security matrix** (which mechanisms apply to `root://` vs
  HTTP/WebDAV/S3), the **fail-closed invariants**, and the **admin configuration
  surface** on both sides.

Out of scope: transport TLS internals, the data plane, monitoring, and identity
→ local-UNIX-user mapping mechanics (covered in
[`identity-mapping.md`](../../../06-authentication/identity-mapping.md)).

---

## In official XRootD

Official XRootD authenticates `root://` clients through the **XrdSec** plugin
framework and authorizes through the **XrdAcc** (or plugged-in) authorization
library. HTTP/WebDAV is served by **XrdHttp**, which has its *own* TLS-cert and
token plumbing distinct from XrdSec and bridges the resulting identity into the
xrootd core.

- **Framework:** `/tmp/xrootd-src/src/XrdSec/` — `XrdSecPManager`
  (`XrdSecPManager.cc`) loads `libXrdSec<pid>.so` per protocol id and resolves
  `XrdSecProtocol<pid>Object`/`...Init`. The server advertises available
  protocols in the `kXR_login` reply as a `&P=<pid>[,<args>]` token
  (`XrdSecServer.cc` `add2token()` ~`:1120`); the client picks one and runs the
  per-protocol `kXR_auth` exchange. The common identity carrier is
  `XrdSecEntity` (`XrdSecEntity.hh:64`): `prot`, `name`, `host`, `vorg`, `role`,
  `grps`, `endorsements`, `creds`, `uid`/`gid`.
- **Protocols shipped:** `gsi` (`XrdSecgsi/`), `krb5` (`XrdSeckrb5/`), `sss`
  (`XrdSecsss/`), `unix` (`XrdSecunix/`), `pwd` (`XrdSecpwd/`), `ztn` token
  transport (`XrdSecztn/`), and the built-in `host`
  (`XrdSec/XrdSecProtocolhost.cc`, special-cased in the loader, no separate
  `.so`).
- **Token validation** is *not* in `ztn`. `ztn` is pure transport: it mandates
  TLS, frames/size-checks the token, applies an expiry policy, and delegates all
  signature/claim validation to an external authorization plugin —
  **XrdSciTokens** (`XrdSciTokens/`, links `scitokens-cpp`) and/or
  **XrdMacaroons** (`XrdMacaroons/`, links `libmacaroons`). These plugins also
  serve the HTTP token surface.
- **Authorization:** `/tmp/xrootd-src/src/XrdAcc/` — an authdb file (default
  `/etc/xrootd/authdb`) parsed by `XrdAccAuthFile.cc`, evaluated by
  `XrdAccAccess::Access()` (`XrdAccAccess.cc:105`), enabled with
  `ofs.authorize` + `acc.authdb`. SciTokens/Macaroons chain *in front of*
  XrdAcc by implementing the same `XrdAccAuthorize` interface.
- **VOMS:** `/tmp/xrootd-src/src/XrdVoms/` — one shared object exposed under two
  names (`libXrdSecgsiVOMS` for GSI, `libXrdHttpVOMS` for HTTP), wrapping
  `libvomsapi` to fill `Entity.vorg/grps/role`.

## In nginx-xrootd

The module reimplements the same surface as nginx stream/HTTP handlers backed by
OpenSSL, with a strong bias toward **doing validation in-process and
fail-closed**, and toward operational hardening (per-worker caches, circuit
breakers, in-flight caps).

- **`root://` handshake:** `src/session/login.c` drives `kXR_protocol →
  kXR_login → kXR_auth` from a single `xrootd_auth` enum
  (`tunables.h:221` `XROOTD_AUTH_{NONE,GSI,TOKEN,BOTH,SSS,UNIX,KRB5,HOST,PWD}`).
  `xrootd_handle_login()` (`login.c:61`) builds the `&P=` advertisement; the
  per-method dispatch lives in `src/handshake/`.
- **Per-method backends:** `src/auth/gsi/` (shared client/server core), `src/auth/token/`,
  `src/auth/sss/`, `src/auth/krb5/`, `src/auth/unix/`, `src/auth/pwd/`, `src/auth/host/`, `src/auth/voms/`.
- **In-process token validation:** unlike upstream's `ztn`-delegates-to-plugin
  split, `src/auth/token/validate.c` validates JWT/WLCG tokens *itself* (RS256/ES256
  against a JWKS), and `src/auth/token/macaroon.c` validates macaroons itself.
- **Authorization:** a **dual engine** — `src/auth/authz/authdb.c` (native `u/g/p/a`
  format, `root://` only) and `src/auth/authz/acc/` (a faithful XrdAcc port, all three
  protocols), selected by `xrootd_authdb_format`. Plus VO ACLs (`src/auth/authz/acl.c`,
  `find_rule.c`), token-scope path gates (`src/auth/token/scopes.c`), and a global
  write gate.
- **The decision pipeline** for `root://` runs through
  `src/auth/authz/auth_gate.c` `xrootd_auth_gate_op()` (authdb → VO ACL → token scope,
  fail-closed on first failure), behind the `auth_done` completion gate in
  `src/handshake/policy.c`.
- **HTTP/WebDAV/S3** auth lives in `src/webdav/auth_cert.c`,
  `src/webdav/auth_token.c`, and `src/s3/` (SigV4), all reusing the same
  `src/auth/token/` and `src/auth/authz/acc/` cores.

---

## Authentication methods

### GSI / X.509 / VOMS

**Handshake.** Both implement the XrdSecgsi four-message Diffie-Hellman exchange:
client `certreq` → server `cert` → (optional `pxyreq` for delegation) →
client `sigpxy`.

- *Official:* `XrdSecgsi/XrdSecProtocolgsi.cc` — client steps
  `kXGC_certreq/kXGC_cert/kXGC_sigpxy`, server steps
  `kXGS_init/kXGS_cert/kXGS_pxyreq` (`XrdSecProtocolgsi.hh:89-104`); the
  exchange is a `switch(step)` on each side (client `getCredentials()`
  ~`:1411`, server `Authenticate()` ~`:1748`).
- *Module:* `src/auth/gsi/auth.c` routes on the 4-byte `credtype` and the GSI step
  byte; round-1 → `xrootd_gsi_send_cert()` (`cert_response.c:128`), round-2 →
  `xrootd_gsi_parse_x509()` (`parse_x509.c:251`) or the signed variant
  (`parse_x509.c:123`). DH primitives are in the **shared** `src/auth/gsi/gsi_core.c`
  (`xrootd_gsi_dh_keygen`, `_dh_derive`) used by both this server and the native
  client. The 3072-bit DH parameters are copied verbatim from
  `XrdCryptosslCipher.cc` (`gsi_core.c` comment) for byte-level interop.

**Symmetric-cipher negotiation.** Both negotiate a session cipher in the
`kXRS_cipher_alg` bucket.

- *Official:* default list `aes-128-cbc:bf-cbc:des-ede3-cbc`
  (`XrdSecProtocolgsi.cc:160` `DefCipher`); server advertises the full list,
  client picks the first it supports and echoes the choice, server validates
  against `DefCipher`.
- *Module:* table-driven over
  `gsi_cipher_allow[] = {aes-128-cbc, aes-256-cbc, bf-cbc, des-ede3-cbc}`
  (`gsi_core.c:494`), default emit order
  `aes-128-cbc:aes-256-cbc:bf-cbc:des-ede3-cbc` (`gsi_core.c:501`) — **aes-128
  first by design** for the proven default and stock interop
  (`gsi_core.h:76`). Operators can filter/reorder with `xrootd_gsi_ciphers`
  (`cert_response.c:174`). `bf`/`3des` are reached through the OpenSSL-3 legacy
  provider (`gsi_load_legacy_once()`). The module thus *adds* `aes-256-cbc` to
  the upstream set. This matches the project memory on GSI cipher negotiation
  (aes-128 byte-identical to stock; aes-256/bf/3des table-driven).

**Message-digest negotiation.** Official advertises `DefMD = "sha256"`
(`:161`, bucket `kXRS_md_alg`). The module advertises `"sha256:sha1"`
(`cert_response.c:151`) but derives its signing key with a hard-wired SHA-256
HMAC (`parse_x509.c`, `xrootd_gsi_sigver_hmac()` in `gsi_core.c:930`); a digest
**pick** function was not found module-side **(not verified)** — digest
advertisement is effectively informational.

**Signed-DH / RSA-signed DH.** Both sign the DH public key with the endpoint's
RSA private key and verify with the peer's public key, **version-gated** at
protocol ≥ 10400.

- *Official:* automatic, not a config flag — gated on `RemVers >= 10400`
  (`XrdSecgsiVersDHsigned 10400`, `XrdSecProtocolgsi.hh:75`); if the peer omits
  signed DH, proxy delegation is disabled.
- *Module:* a tri-state operator control `xrootd_gsi_signed_dh` →
  `XROOTD_GSI_SDH_{OFF,AUTO,REQUIRE}` (`tunables.h:231`), with
  `gsi_use_signed_dh()` (`cert_response.c:112`) deciding per handshake against
  the client version. Signed → RSA-signed public blob emitted as `kXRS_cipher`;
  unsigned → bare blob as `kXRS_puk`. The advertised GSI version is `10600`
  when signed-DH is on, else `10000` (`session/login.c`). This is the
  "signed-DH server path" recorded in project memory (advertise aes-128 first;
  off/auto/require; stock-interop).

**VOMS.** Both delegate AC parsing to `libvomsapi`.

- *Official:* external plugin (`libXrdVoms.so`); `XrdVomsFun::VOMSFun()`
  (`XrdVoms/XrdVomsFun.cc:185`) calls `vomsdata::Retrieve(... RECURSE_CHAIN)`
  and reads `voname`/`std`(group/role/cap)/`fqan`, filling
  `Entity.vorg/grps/role/endorsements`.
- *Module:* `src/auth/voms/loader.c` `dlopen`s `libvomsapi.so.1` (graceful
  `NGX_DECLINED` if absent); `extract.c` calls `VOMS_Retrieve(... RECURSE_CHAIN)`.
  Notably the module reads **only `voname` and `fqan`** — the `std` group/role/
  cap triples are declared but never dereferenced (`collect.c`), so VO is derived
  by name (or first FQAN path component, `xrootd_fqan_to_vo()`), not from the
  parsed role/capability structure. GSI and HTTP share one implementation behind
  two declaring headers (`voms_http.h:50`).

**Proxy chains, CA, CRL, OCSP.**

- *Official:* proxy certs handled as `XrdCryptogsiX509Chain`; CA defaults
  `/etc/grid-security/certificates/`, CRL ext `.r0`; verify/CRL policy levels in
  `XrdSecgsiOpts.hh` (`caVerifyss` default; `crlTry` default; refresh 86400s).
  Chain + CRL verification in `XrdCrypto/XrdCryptoX509Chain.cc::Verify()`
  (`:678`, per-link `crl->IsRevoked()` `:813`). **No OCSP anywhere** in
  `XrdSecgsi` or `XrdCrypto` — revocation is CRL-only (including CRL-DP URI
  download).
- *Module:* `src/auth/gsi/config.c` `xrootd_rebuild_gsi_store()` sets
  `X509_V_FLAG_ALLOW_PROXY_CERTS`; `trusted_ca` is stat'd and treated as an
  OpenSSL CApath when a directory (hashed grid certs dir) or a CAfile otherwise.
  CRLs load in `src/auth/crypto/pki_build.c` (matches `*.pem` and grid `*.r0..r9`)
  and set `CRL_CHECK | CRL_CHECK_ALL | USE_DELTAS`; CRL mtime-skip reload lives
  in `src/core/config/process.c` `xrootd_crl_reload_handler()` (a CApath directory is
  always rebuilt). **OCSP exists** here as a module feature
  (`src/auth/crypto/ocsp.c`): AIA-derived responder, `xrootd_ocsp_check_cert()`
  (REVOKED is always fatal), stapling cache, and a hardened
  `XROOTD_OCSP_TIMEOUT_SECS = 5` connect deadline, wired from `gsi/auth.c`
  behind `xrootd_ocsp_enable`. **This is a module-only addition relative to
  upstream GSI.**

**Interop.** Module GSI is explicitly cross-checked against **EOS**
(`gsi_core.c:307`, `gsi_core.h:48-52`, aes-128 byte-identical) — see
[`gsi-interop-eos-dcache.md`](../../../06-authentication/gsi-interop-eos-dcache.md).
dCache is named in that doc but is **not referenced in module source** **(not
verified in code)**.

### Bearer tokens (WLCG / SciTokens / macaroon)

The architectures differ fundamentally: **upstream separates transport from
validation; the module validates in-process.**

**Official.**

- `root://`: `XrdSecztn/XrdSecProtocolztn.cc` requires TLS (`needTLS()`=true),
  discovers the token (`BEARER_TOKEN`, `BEARER_TOKEN_FILE`, `$XDG_RUNTIME_DIR`,
  `/tmp/bt_u<uid>`, or `xrd.ztn=`), frames it (`TokenHdr`/`TokenResp`,
  `MaxTokSize` default 4096), and on the server **delegates validation to an
  external `XrdSciTokensHelper::Validate()`** before stashing the raw token into
  `Entity.creds`. With `-tokenlib none`, ztn validates nothing and accepts any
  token as `anon`.
- Validation itself is in **XrdSciTokens** (`XrdSciTokensAccess.cc`, a
  `XrdAccAuthorize` implementation linking `scitokens-cpp`):
  `scitoken_deserialize()` + `enforcer_generate_acls()`; `[Issuer …]` config
  blocks map `issuer`/`base_path`/`username_claim`/`groups_claim`
  (default `wlcg.groups`); scope strings map to `Access_Operation` then to
  `XrdAccPrivs`.
- HTTP: XrdHttp forwards `Authorization` as opaque CGI via
  `http.header2cgi Authorization authz`; **Macaroons** (`XrdMacaroons/`) verify
  via `libmacaroons` (`macaroon_verify()` HMAC) and serve the token endpoint
  (`POST /.oauth2/token` or `Content-Type: application/macaroon-request`) from an
  `XrdHttpExtHandler`. The macaroon secret must base64-decode to ≥32 bytes;
  `maxduration` default 24h.

**Module.** `src/auth/token/validate.c` `xrootd_token_validate()` is a single
in-process pipeline: length gate (≤8192) → split → header decode → **alg check
(only `RS256`/`ES256`; `alg:"none"` and all others rejected before any
verification)** → kid/key select → **signature verify (before payload is
trusted)** → claims → `iss` → `aud` → `exp` (required, positive) → `nbf` →
scopes.

- **JWKS:** `src/auth/token/jwks.c` reads a **local file only** (no remote HTTP
  fetch), max 8 keys, reloaded by a per-worker mtime-polling timer
  (`refresh.c`). This is a deliberate divergence from issuer-discovery JWKS
  fetching.
- **Scopes:** `src/auth/token/scopes.c` parses space-separated `permission:path`;
  empty path defaults to `/` (WLCG convention); `storage.read/write/create/
  modify/stage` map to read/write/create/modify; path matching is
  boundary-aware (`/data` ≠ `/database`).
- **Caches:** an **always-on, per-worker, lockless L1** validation cache
  (`worker_cache.c`, 1024 slots, TTL `min(exp, now+300s)`) fronts an **opt-in
  cross-worker SHM L2** (`token_cache.c`, `xrootd_token_cache zone=...`, key =
  SHA-256(token)). This exists to keep per-request RSA+JSON off the event loop
  (project memory: "Token-auth L1 cache (HTTP ReadTimeout fix)").
- **Macaroons:** `src/auth/token/macaroon.c` validates the HMAC chain in-process
  with two hardened invariants — **mandatory expiry** (`macaroon.c:528`: a
  root-context macaroon with no `before:` caveat is rejected) and
  **issuer-pinning** (`validate.c:201`: `location`/`iss` must match the
  configured issuer; a no-location macaroon is rejected when an issuer is
  configured). Discharge bundles are supported (`xrootd_macaroon_validate_bundle()`,
  ≤8 discharges, AES-256-CBC vid decryption). The HTTP token endpoint exists at
  `src/webdav/macaroon_endpoint.c` (`/.well-known/oauth-authorization-server`
  discovery + `POST /.oauth2/token`, `grant_type=client_credentials`,
  anonymous rejected 401). These map to the project memory on macaroon
  mandatory-expiry/issuer-pinning.

> Both sides require TLS for `root://` token auth in practice; the module gates
> bearer use on TLS at the WebDAV verifier and on the `ztn` advertisement for
> the stream.

### SSS (shared secret)

- *Official:* `XrdSecsss/` — encrypted keytab (`XrdSecsssKT`, mode `0600`/`0640`
  for `.grp`, **mode-bits checked but not ownership**), **Blowfish only**, no
  interactive nonce (freshness is a ~13s timestamp window; the `Rand[32]` is
  anti-known-plaintext only), optional source-IP binding unless `noIPCK`. Weak
  `srand48` RNG fallback when `/dev/urandom` is absent.
- *Module:* `src/auth/sss/` — Blowfish-CFB64 (zero IV, no padding) with a **CRC-32/
  IEEE** integrity/wrong-key check; cleartext prefix = 32-byte random nonce +
  gen_time; replay window enforced (`gen_time + sss_lifetime <= now` rejected).
  Keytab parsing (`config.c`) enforces owner-only `0600` (`0640` for `.grp`)
  with `O_NOFOLLOW` + fstat anti-TOCTOU. ID mapping is TLV-based
  (`auth_identity_challenge.c`, `auth_request.c`) honoring keytab opts
  ANYUSR/ALLUSR/ANYGRP/USRGRP. A **proxy-upstream SSS arm**
  (`auth_proxy_credential.c`, used by `src/proxy/`) presents an SSS credential
  to a backend (`credtype "sss\0"`), with `xrootd_sss_upstream_needed()` loading
  keys even when the front-end auth is not SSS (project memory: "Chaos mixed
  x509/SSS auth + SSS proxy bugs"). Directive: `xrootd_sss_keytab`.

### Kerberos 5

- *Official:* `XrdSeckrb5/XrdSecProtocolkrb5.cc` — **native MIT krb5 AP-REQ/
  AP-REP, not GSSAPI** (`krb5_mk_req_extended()` / `krb5_rd_req()`); keytab via
  `krb5_kt_resolve` or `krb5_kt_default`; optional `-ipchk` (off by default);
  forwardable-cred delegation via `-exptkn` + `krb5_fwd_tgt_creds`.
- *Module:* `src/auth/krb5/auth.c` — also **native `krb5_rd_req()` AP-REQ, not
  GSSAPI**; gated on build flag `XROOTD_HAVE_KRB5` (absent ⇒ unconditional
  deny); validates the AP-REQ against a pre-loaded principal + keytab; maps the
  client principal to a local name via `krb5_aname_to_localname`. Directives:
  `xrootd_krb5_principal`, `xrootd_krb5_keytab`, `xrootd_krb5_ip_check`. The two
  designs match (no credential forwarding/delegation on the module side **(not
  verified to exist)**).

### UNIX

- *Official:* `XrdSecunix/XrdSecProtocolunix.cc` — **trusts client-asserted
  uid/gid**; no `SO_PEERCRED`/`getpeereid`/`SCM_CREDENTIALS`. The server copies
  the wire `"<user> <group>"` verbatim into `Entity.name`/`Entity.grps` and
  returns success unconditionally.
- *Module:* `src/auth/unix/auth.c` — also takes the username from the wire
  credential (self-asserted), but is **loopback-only by default**
  (`xrootd_unix_peer_is_loopback()` accepts 127/8, ::1, AF_UNIX) and rejects
  remote peers unless `xrootd_unix_trust_remote on`. It also allow-lists the
  name bytes (`[A-Za-z0-9_.@+-]`). The module is therefore *stricter* than
  upstream by default.

### Password (`pwd`)

- *Official:* `XrdSecpwd/` — salted KDF (`DoubleHash`) or libc `crypt()` against
  a `$HOME/.xrd/` info dir; netrc/autologin support; `xrdpwdadmin` admin tool.
- *Module:* `src/auth/pwd/` — **a real implementation** (added 2026-06, Phase-52
  WS-B; *not* a stub), confirmed in source: a 2-round DH-bootstrapped exchange
  (`pwd_round1` establishes a DH session key without looking up the user, for
  anti-enumeration; `pwd_round2` decrypts the AES-128-CBC credential and
  verifies). Hashing is **PBKDF2-HMAC-SHA1, 10000 iterations** (`auth.c`,
  byte-compatible target with stock XrdSecpwd), constant-time compare, file
  format `user:salthex:hashhex` (`pwdfile.c`). Caveat noted in source: full
  byte-interop with stock XrdSecpwd is follow-on (our-client ↔ our-server is
  verified); run under TLS. Directive: `xrootd_pwd_file`. (The other reference
  gap docs — [source-verified comparison](../../source-verified-xrootd-comparison.md),
  [feature matrix](../../xrootd-feature-matrix.md),
  [gaps-vs-xrootd](../../gaps-vs-xrootd.md) — have been reconciled to show `pwd`
  as implemented.)

### Host-based

- *Official:* built-in `host` protocol (`XrdSec/XrdSecProtocolhost.cc`), no
  crypto — identity is the peer host, `Authenticate()` always returns success
  setting `Entity.prot="host"`.
- *Module:* `src/auth/host/auth.c` — **a real implementation** (added 2026-06,
  Phase-52 WS-C; *not* a stub). Identity is the socket **reverse-DNS** hostname
  (never client-supplied), matched against an allowlist
  (`xrootd_host_pattern_match()`: leading `.` = domain suffix, else exact,
  case-insensitive). **Hostname/suffix only — no CIDR/IP matching**; empty
  allowlist = deny-all. Directive: `xrootd_host_allow`. (The reference gap docs
  have been reconciled to show `host` as implemented, same as `pwd`.)

### Support matrix

| Method | Official XRootD | nginx-xrootd | Notes |
|---|---|---|---|
| Anonymous | core flow | `xrootd_auth none` | both |
| GSI / X.509 proxy | `XrdSecgsi` | `src/auth/gsi/` (shared core) | 4-msg DH; signed-DH ≥10400 both |
| GSI cipher set | aes-128/bf/3des | + aes-256 (table-driven) | module adds aes-256-cbc |
| OCSP revocation | **none** (CRL only) | `src/auth/crypto/ocsp.c` | **module-only** |
| VOMS | `XrdVoms`→`libvomsapi` | `src/auth/voms/`→`libvomsapi` | module reads voname/fqan only |
| WLCG/SciToken `root://` | `ztn` transport + `XrdSciTokens` plugin | `src/auth/token/validate.c` in-process | module validates RS256/ES256 itself |
| JWKS source | issuer/scitokens-cpp | **local file + mtime poll** | divergence |
| Macaroon | `XrdMacaroons`/`libmacaroons` | `src/auth/token/macaroon.c` in-process | module: mandatory-expiry + issuer-pin |
| Token endpoint (HTTP) | XrdMacaroons ext handler | `src/webdav/macaroon_endpoint.c` | both `POST /.oauth2/token` |
| SSS | `XrdSecsss` (Blowfish, ts window) | `src/auth/sss/` (Blowfish-CFB + CRC32 + replay window) | + proxy-upstream arm |
| Kerberos 5 | `XrdSeckrb5` (native AP-REQ) | `src/auth/krb5/` (native AP-REQ) | both not-GSSAPI; build-gated |
| UNIX | `XrdSecunix` (self-asserted) | `src/auth/unix/` (self-asserted, loopback-default) | module stricter by default |
| Password (`pwd`) | `XrdSecpwd` | `src/auth/pwd/` (PBKDF2, DH-bootstrapped) | added 2026-06; interop follow-on |
| Host | built-in `host` | `src/auth/host/` (reverse-DNS allowlist) | added 2026-06; no CIDR |
| Token transport (`ztn`) | yes (transport only) | n/a (validation in-process) | architectural difference |

---

## Authorization

### XrdAcc-style authdb

**Official (`XrdAcc/`).** Enabled by `ofs.authorize` + `acc.authdb` (default
`/etc/xrootd/authdb`).

- *Grammar* (`XrdAccAuthFile.cc` `getRec()` switch): record letters
  `u`(user) `g`(group) `h`(host) `o`(org) `r`(role) `t`(template) `s`(set)
  `n`(netgroup) `x`(fungible/exclusive) `=`(id def). Path tokens start with `/`;
  others are template names. **No `v`/`l` record types** — VO/role/group come
  from `XrdSecEntity` attributes matched through `o`/`r`/`g`.
- *Privileges* (`XrdAccPrivs.hh`): bit set `All=0x1ff` with letters
  `a`ll `d`elete `i`nsert `k`(lock) `l`ookup `n`(**rename**) `r`ead `w`rite,
  `-` switching to a negative set. **No `x` privilege letter; `n` is rename,
  not none.**
- *Evaluation* (`XrdAccAccess::Access()` `:105`): privileges are **accumulated
  across all identity dimensions** (user/group/org/role/host/netgroup/default),
  then `effective = positive & ~negative` (`:266`). Within one list,
  `XrdAccCapability::Privs()` takes the **first prefix match** (`strncmp`), not
  the longest. Capability path templates substitute the requesting username at
  `@=` (`XrdAccCapability.cc`).
- *create-vs-update:* decided by the **caller** (XrdOfs passes `AOP_Create` vs
  `AOP_Update`); the `need[]` table maps `AOP_Create→0x062` (adds the Insert
  bit) and `AOP_Update→0x060` (`XrdAccAccess.cc:422`).
- *reverse-DNS:* host matching uses `Entity->addrInfo->Name()` in
  `XrdAccAccess::Resolve()` (`:339`), with a suffix compare for domains
  (`XrdAccGroups.cc` handles unix/netgroups via `getgrent`/`innetgr`).
- *audit:* `XrdAccAudit.cc` emits per-decision lines.

**Module — dual engine.** `xrootd_authdb_format` selects:

- **`native`** (`src/auth/authz/authdb.c`, default, `root://` only): records
  `[u|g|p|a] <id> <path> <privs>` (`u`ser/`g`roup/`p`=host-CIDR/`a`ll — **no
  principal kind**); 6 privilege bits (`r`ead, `l`ookup, `w`/`a`→update,
  `d`elete, `m`kdir, `k`→admin); **longest-prefix selection** with
  privilege-sufficiency folded in (a shorter sufficient rule beats a longer
  insufficient one). Host `p` rules are **IP/CIDR string match — no reverse-DNS**
  in the native engine. Directive `xrootd_authdb`.
- **`xrdacc`** (`src/auth/authz/acc/`): a **faithful XrdAcc port** with a generational
  table swap on mtime hot-reload (`config.c`, single-threaded-worker
  pointer-swap, per-worker COW). Grammar matches stock: record types
  `= x s g h n o r t u`; selectors `g h o r u` (**no `v`, no `l`; role is `r`**);
  privilege letters `a d i k l n r w` (**no `x` letter**); `r` does **not** imply
  `l` (deliberate divergence from some stock builds). create-vs-update via a
  numeric `need[]` table (`AOP_CREATE=3→INSERT|READ|WRITE`,
  `AOP_UPDATE=12→READ|WRITE`, `EXCL_CREATE=13`), matching XRootD's enum values
  (`privs.h:73`). `@=` capability substitution (`capability.c`,
  `xrootd_acc_cap_subcomp()`). Reverse-DNS via `xrootd_acc_resolve_peer()`
  (`resolve.c`/`groups.c`, `getnameinfo NI_NAMEREQD`) with a **circuit breaker**
  (2000ms / 5-trip / 10s cooldown) and an NSS breaker for `getpwnam`/
  `getgrouplist`/`innetgr` — hardening absent upstream. The access decision
  `xrootd_acc_access()` (`access.c:86`) ports `XrdAccAccess::Access` (exclusive →
  default → host → netgroup → unix group → fungible → user → per-tuple). **Applies
  to all three protocols** (`root://` via `auth_gate.c`, WebDAV via
  `webdav/access.c`, S3 via `s3/handler.c`). Project memory: "XrdAcc port" +
  "XrdAcc residual gaps."

### VO ACLs

- *Official:* VO authorization is expressed through XrdAcc `o`/`r`/`g` matching
  on `Entity.vorg/role/grps`, or via the GSI VO-authz plugin
  (`XrdSecgsiAuthzFunVO.cc`, `vo2grp`/`vo2usr`/`cn2usr`).
- *Module:* a dedicated VO-ACL tier (`src/auth/authz/acl.c`,
  `xrootd_check_vo_acl_identity()`; rule lookup in `find_rule.c`, longest-prefix
  over `vo_rules`), plus the `xrootd_require_vo` directive. Empty required-VO ⇒
  allow; empty VO list ⇒ deny. This runs as the middle tier of the auth gate.

### Token-scope path gates

- *Official:* SciTokens maps token scopes to `Access_Operation`/`XrdAccPrivs`
  inside `XrdSciTokensAccess.cc`, evaluated like any other authz rule.
- *Module:* `src/auth/token/scopes.c` checks the requested path against the token's
  `permission:path` scopes directly (boundary-aware), via
  `xrootd_token_check_read`/`_check_write` (write accepts write|create|modify),
  enforced as the **third** tier of `auth_gate.c` and at the WebDAV verifier
  (`webdav/auth_token.c`, `webdav_check_token_write_scope()`).

> The CLAUDE.md HELPERS list names `xrootd_token_check_scope` — that exact symbol
> does not exist; the real helpers are `xrootd_token_check_read`/`_check_write`
> and `webdav_check_token_write_scope`/`xrootd_identity_check_token_scope`.

### The decision pipeline

Module `root://` authorization is a single fail-closed pipeline,
`src/auth/authz/auth_gate.c` `xrootd_auth_gate_op()` (`:212`): **authdb → VO ACL →
token scope**, denying with `kXR_NotAuthorized` on the first failure. The XrdAcc
engine keys on the logical request path; the native authdb keys on the resolved
filesystem path. An optional cross-worker **L2 auth-cache**
(`xrootd_auth_cache zone=...`, `auth_cache.c`, default TTL 30s) is fronted by a
per-worker lockless **L1** (`auth_gate_l1.c`, created only when L2 is enabled),
keyed on a SHA-256 of the full decision inputs. Upstream's XrdAcc refreshes its
table on a timer but has no equivalent per-request decision cache.

---

## Fail-closed design & security invariants

Both sides are fail-closed in intent; the module encodes several invariants
explicitly:

1. **Gate on the *completed* auth verdict only.** Access is gated on
   `ctx->auth_done` (the final success verdict), **never** on the intermediate
   `ctx->logged_in`. The gate is `xrootd_dispatch_require_auth()` in
   `src/handshake/policy.c:56`
   (`if (!ctx->logged_in || !ctx->auth_done) → kXR_NotAuthorized`); `auth_done`
   is set only on per-backend success and cleared on `endsess`. This directly
   encodes the project-memory invariant "auth gate on completed-auth only (BAD
   PATTERN to gate on `logged_in`/has-token)" and the fix for a HIGH proxy
   fail-open. *Correction to the research framing:* the `auth_done` gate is in
   `handshake/policy.c`, not `path/auth_gate.c`; `auth_gate.c` is the
   path-authorization tier that runs **after** the verdict gate.
2. **Global write gate before token scope** (INVARIANT #3). `conf->common.
   allow_write` is checked by callers *before* any token-scope grant —
   `read/open_request.c:350` (before the auth gate at `:594`), `webdav/access.c:249`,
   and a VFS leaf re-check (`fs/vfs_open.c:275`). A site that has not enabled
   writes cannot be talked into them by a permissive token. Upstream has no such
   global pre-gate; write permission is purely whatever the authz stack grants.
3. **Token validation order is verify-before-trust.** Signature is checked
   before any payload claim is trusted; `alg:"none"` and any non-RS256/ES256
   algorithm is rejected before verification (`validate.c:249`).
4. **Macaroon mandatory-expiry + issuer-pinning** (above) — non-expiring or
   issuer-mismatched macaroons are rejected.
5. **Path confinement** — all wire paths resolve through
   `resolve_path()`/`xrootd_open_confined_canon()` before any syscall
   (INVARIANT #4); authorization keys on those resolved/logical paths.
6. **OCSP REVOKED is always fatal** regardless of soft-fail
   (`ocsp.c`), and the SSS replay window / nonce, krb5 build-gating, unix
   loopback-default, and the GSI in-flight handshake cap
   (`xrootd_gsi_max_inflight_handshakes`) are all conservative defaults.

Upstream-side cautions worth noting for migration: `ztn` with `-tokenlib none`
accepts any token as `anon`; `XrdSecunix` trusts self-asserted uid/gid with no
kernel check; `XrdSecsss` checks keytab mode bits but not ownership and has a
weak-RNG fallback. The module's equivalents are stricter on each point.

---

## Admin configuration (both sides)

### Official XRootD (`xrootd.cfg`)

```text
# transport TLS (shared by root:// and HTTP)
xrd.tls   /etc/grid-security/hostcert.pem /etc/grid-security/hostkey.pem
xrd.tlsca certdir /etc/grid-security/certificates

# advertise sec protocols for root://
sec.protocol /usr/lib64 gsi -certdir:/etc/grid-security/certificates \
             -cert:/etc/grid-security/hostcert.pem \
             -key:/etc/grid-security/hostkey.pem -crl:1 -vomsat:extract
sec.protocol sss -s /etc/xrootd/sss.keytab
sec.protocol krb5 host/_HOST@REALM
sec.protbind <host> <protocols>          # per-host bindings

# token transport + validation plugins
sec.protocol ztn
ofs.authlib  libXrdAccSciTokens.so       # SciTokens validation
# (XrdMacaroons loaded as an XrdHttp ext handler for HTTP)

# authorization
ofs.authorize
acc.authdb   /etc/xrootd/authdb
acc.audit    deny

# HTTP / WebDAV
http.cadir     /etc/grid-security/certificates
http.secxtractor libXrdHttpVOMS.so
http.header2cgi Authorization authz
```

Parse sites: `sec.protocol`/`protbind` → `XrdSec/XrdSecServer.cc::ConfigXeq`;
`ofs.authorize`/`authlib` → `XrdOfs/XrdOfsConfig.cc::ConfigXeq` (`:878`);
`acc.*` → `XrdAcc/XrdAccConfig.cc::ConfigXeq` (`:333`); `xrd.tls*` →
`Xrd/XrdConfig.cc`; `http.*` → `XrdHttp/XrdHttpProtocol.cc::Config` (`:983`).
File conventions: CA dir `/etc/grid-security/certificates`, CRLs `*.r0`, authdb
`/etc/xrootd/authdb`, SSS keytab via `xrdsssadmin`.

### nginx-xrootd (`nginx.conf`)

```nginx
# root:// listener (stream module)
stream {
  server {
    listen 1094;
    xrootd on;
    xrootd_root /export;

    xrootd_auth both;                       # none|gsi|token|both|sss|unix|krb5|host|pwd
    xrootd_security_level standard;

    # GSI
    xrootd_certificate     /etc/grid-security/hostcert.pem;
    xrootd_certificate_key /etc/grid-security/hostkey.pem;
    xrootd_trusted_ca      /etc/grid-security/certificates;   # dir -> CApath
    xrootd_gsi_signed_dh   auto;            # off|auto|require
    xrootd_gsi_ciphers     aes-128-cbc:aes-256-cbc;
    xrootd_crl             /etc/grid-security/certificates;
    xrootd_crl_reload      300;
    xrootd_ocsp_enable     on;              # module-only OCSP
    xrootd_vomsdir         /etc/grid-security/vomsdir;

    # tokens
    xrootd_token_jwks      /etc/xrootd/jwks.json;   # local file
    xrootd_token_issuer    https://issuer.example/;
    xrootd_token_audience  https://se.example/;
    xrootd_macaroon_secret /etc/xrootd/macaroon.key;
    xrootd_token_cache     zone=tok:8m;     # opt-in SHM L2

    # other methods
    xrootd_sss_keytab        /etc/xrootd/sss.keytab;
    xrootd_krb5_principal    host/se.example@REALM;
    xrootd_krb5_keytab       /etc/krb5.keytab;
    xrootd_unix_trust_remote off;           # loopback-only by default
    xrootd_pwd_file          /etc/xrootd/passwd;
    xrootd_host_allow        .example.org;

    # authorization
    xrootd_allow_write       on;            # global write pre-gate
    xrootd_authdb            /etc/xrootd/authdb;
    xrootd_authdb_format     xrdacc;        # native|xrdacc
    xrootd_authdb_audit      deny;
    xrootd_authdb_refresh    60;
    xrootd_require_vo        / cms;
  }
}

# davs:// / S3 listener (http module)
http {
  server {
    listen 8444 ssl;
    ssl_certificate     /etc/grid-security/hostcert.pem;
    ssl_certificate_key /etc/grid-security/hostkey.pem;
    location / {
      xrootd_webdav on;
      xrootd_webdav_auth         required;  # none|optional|required
      xrootd_webdav_proxy_certs  on;
      xrootd_webdav_cadir        /etc/grid-security/certificates;
      xrootd_webdav_token_jwks   /etc/xrootd/jwks.json;
      xrootd_webdav_token_issuer https://issuer.example/;
      xrootd_authdb              /etc/xrootd/authdb;   # shared engine
      xrootd_authdb_format       xrdacc;
    }
  }
}
```

Directive sources: stream table `src/stream/module.c`; WebDAV table
`src/webdav/module.c`; per-module `config.c` files. Field conventions:
`trusted_ca` directory → OpenSSL CApath (grid certs dir); CRLs `*.pem` or hash
`*.r0..r9`; **JWKS is a local file with mtime reload** (no issuer fetch); SSS
keytab from `xrdsssadmin` format. See
[`docs/06-authentication/`](../../../06-authentication/auth-overview.md) and
[`pki-config.md`](../../../06-authentication/pki-config.md) for full file layout.

---

## Parity, divergences, and interop

**Strong parity (drop-in-ish):**

- GSI four-message DH handshake, cipher negotiation, signed-DH ≥10400, proxy
  chains, VOMS via `libvomsapi` — module GSI is byte-checked against EOS.
- Native-krb5 AP-REQ (both, not GSSAPI), SSS Blowfish keytabs, self-asserted
  UNIX semantics, XrdAcc authfile grammar and `@=`/AOP-create-vs-update
  semantics (the `src/auth/authz/acc/` port deliberately mirrors upstream enum values).

**Module-side additions (nginx+):**

- **OCSP** revocation (`src/auth/crypto/ocsp.c`) — upstream GSI/XrdCrypto have none.
- **In-process token + macaroon validation** with **mandatory-expiry** and
  **issuer-pinning**, the **always-on per-worker L1 / opt-in SHM L2** caches, and
  the **global write pre-gate** — none of these exist upstream, where validation
  is delegated to `scitokens-cpp`/`libmacaroons` and write permission is purely
  authz-driven.
- **Hardening**: GSI in-flight handshake cap, DNS/NSS circuit breakers in
  `src/auth/authz/acc/`, SSS replay window + CRC32 wrong-key detection, OCSP connect
  timeout, UNIX loopback-default.
- **`aes-256-cbc`** added to the GSI cipher set.
- XrdAcc engine applies to **all three** protocols (root/WebDAV/S3); upstream
  XrdAcc is the `root://`/OFS authz path while XrdHttp bridges identity into it.

**Divergences to weigh before migration:**

- **JWKS is a local file (mtime-poll), not issuer-fetched** — sites relying on
  OIDC discovery / remote JWKS rotation must stage the JWKS file.
- **`ztn` token *transport* protocol is not implemented** as such; the module
  validates tokens in-process rather than transporting them to a plugin. For
  WLCG bearer auth over `root://` this is functionally equivalent given TLS, but
  it is not literally the `ztn` mechanism.
- **Native authdb has no `principal` rule kind**, the **XrdAcc port has no `v`/
  `l` keywords and no `x` privilege letter**, and `r` does not imply `l` —
  complex stock authdb files should be reviewed/translated (use the `xrdacc`
  engine for closest fidelity).
- **VOMS role/capability triples are not consumed** module-side (VO derived by
  name / first FQAN component); sites doing fine-grained role/capability authz
  via VOMS `std` data should verify behavior.
- **`pwd` byte-interop with stock XrdSecpwd is follow-on** (our-client ↔
  our-server verified); **`host` supports hostname/suffix only, no CIDR**.

**Note on existing docs:** the reference gap docs (the
[source-verified comparison](../../source-verified-xrootd-comparison.md),
[feature matrix](../../xrootd-feature-matrix.md), and
[gaps-vs-xrootd](../../gaps-vs-xrootd.md)) originally recorded `pwd` and `host`
as *Missing*; they have now been reconciled to reflect the 2026-06 Phase-52
additions of `src/auth/pwd/` and `src/auth/host/`. The XrdAcc port remains *Partial* — the
residual grammar gaps (no `v`/`l`/`x`, narrower identity classes) still hold and
are repeated above.

---

## Source references

**Official XRootD** (`/tmp/xrootd-src/src/`):

- Framework: `XrdSec/XrdSecPManager.cc`, `XrdSecServer.cc`,
  `XrdSecInterface.hh`, `XrdSecEntity.hh`, `XrdSec/XrdSecProtocolhost.cc`
- GSI: `XrdSecgsi/XrdSecProtocolgsi.cc` + `.hh`, `XrdSecgsiOpts.hh`,
  `XrdSecgsiGMAPFunDN.cc`, `XrdSecgsiAuthzFunVO.cc`, `XrdSecgsiAuthzFunDN.cc`
- Crypto: `XrdCrypto/XrdCryptoFactory.*`, `XrdCryptoX509Chain.cc`,
  `XrdCryptoX509Crl.*`, `XrdCryptossl*.cc` (no OCSP present)
- Tokens: `XrdSecztn/XrdSecProtocolztn.cc` + `XrdSecztn.cc`,
  `XrdSciTokens/XrdSciTokensAccess.cc` + `XrdSciTokensHelper.hh`,
  `XrdMacaroons/XrdMacaroons*.cc`
- Other methods: `XrdSecsss/XrdSecProtocolsss.cc` + `XrdSecsssKT.*` +
  `XrdSecsssID.*`, `XrdSeckrb5/XrdSecProtocolkrb5.cc`,
  `XrdSecunix/XrdSecProtocolunix.cc`, `XrdSecpwd/XrdSecProtocolpwd.cc` +
  `XrdSecpwdSrvAdmin.cc`
- Authz: `XrdAcc/XrdAccAuthFile.cc`, `XrdAccAccess.cc`, `XrdAccCapability.cc`,
  `XrdAccGroups.cc`, `XrdAccPrivs.hh`, `XrdAccEntity.cc`, `XrdAccAudit.cc`,
  `XrdAccConfig.cc`; `XrdOfs/XrdOfsConfig.cc`
- VOMS: `XrdVoms/XrdVomsFun.cc`, `XrdVomsHttp.cc`, `XrdVomsgsi.cc`,
  `XrdVomsMapfile.cc`
- HTTP: `XrdHttp/XrdHttpProtocol.cc`, `XrdHttpSecurity.cc`, `XrdHttpExtHandler.hh`
- Config: `Xrd/XrdConfig.cc` (`xrd.tls*`), `XrdXrootd/XrdXrootdConfig.cc`

**nginx-xrootd** (`src/`):

- GSI: `gsi/gsi_core.c` + `.h`, `gsi/auth.c`, `gsi/cert_response.c`,
  `gsi/parse_x509.c`, `gsi/parse_crypto_helpers.c`, `gsi/config.c`
- Crypto/PKI: `crypto/ocsp.c`, `crypto/pki_build.c`, `crypto/pki_check.c`,
  `config/process.c` (CRL reload)
- Tokens: `token/validate.c`, `token/jwks.c`, `token/keys.c`, `token/scopes.c`,
  `token/signature.c`, `token/macaroon.c`, `token/macaroon_issue.c`,
  `token/worker_cache.c`, `token/token_cache.c`, `token/refresh.c`,
  `webdav/macaroon_endpoint.c`
- Other methods: `sss/auth_request.c`, `sss/auth_identity_challenge.c`,
  `sss/auth_proxy_credential.c`, `sss/config.c`; `krb5/auth.c` + `config.c`;
  `unix/auth.c`; `pwd/auth.c` + `pwdfile.c`; `host/auth.c`
- VOMS: `voms/loader.c`, `voms/extract.c`, `voms/collect.c`
- Authz: `path/auth_gate.c` + `auth_gate_l1.c` + `auth_cache.c`,
  `path/authdb.c`, `path/acl.c`, `path/find_rule.c`; `acc/access.c`,
  `acc/authfile.c`, `acc/capability.c`, `acc/groups.c`, `acc/resolve.c`,
  `acc/privs.c` + `privs.h`, `acc/config.c`, `acc/audit.c`
- Session/gate: `session/login.c`, `session/protocol.c`, `handshake/policy.c`
- HTTP: `webdav/auth_cert.c`, `webdav/auth_token.c`, `webdav/access.c`;
  `s3/handler.c`
- Config tables: `stream/module.c`, `webdav/module.c`, `types/tunables.h`,
  `types/config.h`

**Companion docs:**
[`docs/06-authentication/auth-overview.md`](../../../06-authentication/auth-overview.md),
[`gsi-auth.md`](../../../06-authentication/gsi-auth.md),
[`gsi-interop-eos-dcache.md`](../../../06-authentication/gsi-interop-eos-dcache.md),
[`authorization.md`](../../../06-authentication/authorization.md),
[`authorization-xrdacc.md`](../../../06-authentication/authorization-xrdacc.md),
[`identity-mapping.md`](../../../06-authentication/identity-mapping.md),
[source-verified comparison](../../source-verified-xrootd-comparison.md).
