# CRL / revocation — conformance

Scope: X.509 Certificate Revocation List processing for GSI/proxy credentials —
loading, freshness, signature, scope, reason codes, and multi-CRL / delta
semantics. Applies uniformly to `root://`/`roots://` (stream GSI) and
`davs://` (WebDAV client-cert) because both build the **same** OpenSSL
`X509_STORE` via `brix_build_ca_store()` (`src/auth/crypto/pki_build.c:149`).
This is itself a divergence from XRootD, which splits CRL handling between two
independent stacks (see the last subsection).

Pinning family: `tests/clauses/crl.py` (IDs `CRL-001..094`). Deliberate-verdict
corrections: `tests/clauses/_decisions.py` (`CRL-065/066/075/080/081`).

## Normative basis

- **RFC 5280 §6.3.3** — basic CRL processing during path validation: a
  certificate whose serial appears on a valid, in-scope, correctly-signed,
  time-current CRL for its issuer is revoked.
- **RFC 5280 §5.1.1.3** — the CRL signature MUST verify under the CRL issuer's
  key (the issuing CA).
- **RFC 5280 §5.1.2.3** — CRL `issuer` MUST match the certificate issuer whose
  revocation status is being determined (scope).
- **RFC 5280 §5.1.2.4 / §5.1.2.5** — `thisUpdate` (must not be in the future)
  and `nextUpdate` (freshness; a CRL past `nextUpdate` is stale).
- **RFC 5280 §5.2.3** — `CRLNumber`: a monotonically increasing sequence number
  giving relative ordering / authority among a CA's full CRLs.
- **RFC 5280 §5.2.4 / §5.3.1** — delta CRLs and the `reasonCode` extension,
  including `removeFromCRL` (value 8), which is meaningful **only** in a delta.
- **IGTF classic-profile / WLCG** — a "require CRL" deployment MUST fail closed
  when no fresh, valid CRL is available for an issuing CA.

The three enforcement modes are `brix_crl_mode off|try|require`
(`BRIX_CRL_MODE_OFF/TRY/REQUIRE = 0/1/2`,
`src/auth/crypto/store_policy.h:26`), default **try**
(`src/core/config/server_conf.c:306`, `src/protocols/webdav/config.c:331`).
XRootD's analogue is `-crl:<level>` with `crlIgnore/crlTry/crlUse/crlRequire =
0/1/2/3` (`XrdSecgsi/XrdSecgsiOpts.hh:105-108`), default `crlTry`
(`XrdSecgsi/XrdSecgsiOpts.hh:120`).

---

### CRL loading from the hashed CA directory (RFC 5280 §5, IGTF)

- **Requirement:** revocation data for a CA is distributed as a DER/PEM CRL
  filed in the trust anchor's hashed directory under the CA subject hash with a
  `.rN` extension (`<hash>.r0`, `<hash>.r1`), the de-facto grid layout.
- **Ours:** `pki_load_crls()` scans the configured `brix_crl` path; for a
  directory it accepts `*.pem` and `*.r0`..`*.r9`
  (`src/auth/crypto/pki_build.c:105-113`), adding each with
  `X509_STORE_add_crl()` (`pki_build.c:47`). The count feeds the mode gate.
- **XRootD v6.1.0:** `GetCRL()` builds `<CAdir>/<caroot><crlext>` with
  `crlext` defaulting to `.r0` (`XrdSecgsi/XrdSecProtocolgsi.cc:143`,
  loaded at `:4334-4346`); a comma-list of CA dirs is walked
  (`:4338`).
- **Verdict:** Conformant. Both read the same `<hash>.rN` grid layout. Pinned
  transitively by every `CRL-*` row (the oracle scans `.r0`/`.r1` exactly as a
  real `/etc/grid-security/certificates` deployment).

### Enforcement modes: off / try / require vs XRootD crl 0-3 (IGTF, WLCG)

- **Requirement:** a deployment MUST be able to (a) ignore revocation, (b)
  check it best-effort, and (c) fail closed when no fresh CRL exists (IGTF
  "require").
- **Ours:** the gate is in `brix_store_configure()`
  (`src/auth/crypto/store_policy.c:613-621`): CRL verify flags
  (`X509_V_FLAG_CRL_CHECK | CRL_CHECK_ALL | USE_DELTAS`) are set under
  `REQUIRE` unconditionally, and under `TRY` only when at least one CRL was
  loaded (`crl_count > 0`). Under `OFF` no flags are set and a revoked cert is
  accepted (with a startup WARN when GSI is on but no CRL is configured,
  `src/core/config/postconfiguration.c:80-83`).
  - `off`: revocation ignored → accept revoked (`CRL-006`, `CRL-012`).
  - `try`: revoked serial rejected where a CRL exists, **missing** CRL
    tolerated (`CRL-004` reject vs `CRL-013` accept).
  - `require`: missing CRL is fatal (`CRL-014` reject).
- **XRootD v6.1.0:** the level is applied in `GetCACheck()`
  (`XrdSecgsi/XrdSecProtocolgsi.cc:4649`):
  `if ((crl_check == 2 && !crl) || (crl_check == 3 && crl->IsExpired())) goodcrl = 0;`
  — i.e. a missing CRL fails closed only at `crlUse`(2)/`crlRequire`(3); at the
  default `crlTry`(1) a missing CRL is tolerated. `VerifyCRL()` similarly gates
  a missing signing cert on `CRLCheck >= 2`
  (`:4444-4451`).
- **Verdict:** Conformant. Our `try`/`require` map onto XRootD `crlTry`/
  `crlRequire`; our `try` folds XRootD's `crlUse` "reject-if-listed, tolerate-
  if-missing" into the same mode. Pinned by the full mode matrix, e.g.
  `CRL-004..006`, `CRL-013..015`.

### Revoked end-entity certificate (RFC 5280 §6.3.3)

- **Requirement:** an EEC whose serial is on a valid CRL for its issuer MUST be
  rejected.
- **Ours:** OpenSSL applies `X509_V_FLAG_CRL_CHECK` inside
  `X509_verify_cert()` (`src/auth/crypto/gsi_verify.c:199`); a listed serial
  yields `X509_V_ERR_CERT_REVOKED`, which the `try` callback does **not**
  downgrade (only `UNABLE_TO_GET_CRL` is downgraded,
  `src/auth/crypto/store_policy.c:588-590`).
- **XRootD v6.1.0:** `XrdCryptosslX509Crl::IsRevoked()` looks the serial up in
  the parsed CRL cache (`XrdCrypto/XrdCryptosslX509Crl.cc:563-601`).
- **Verdict:** Conformant. Pinned `CRL-004/005` (single), `CRL-010/011`
  (one-of-ten), and the reason-code catalogue `CRL-038..067`.

### Revoked intermediate CA (RFC 5280 §6.3.3)

- **Requirement:** if a root CRL revokes an intermediate CA, every leaf beneath
  that intermediate MUST be rejected.
- **Ours:** `X509_V_FLAG_CRL_CHECK_ALL` forces revocation checking at **every**
  chain position, not just the leaf (`store_policy.c:616-617`); the revoked
  intermediate trips `CERT_REVOKED` mid-chain.
- **XRootD v6.1.0:** revocation is applied per node as the chain is walked in
  `XrdCryptoX509Chain::Verify()` (`XrdCrypto/XrdCryptoX509Chain.cc:816`).
- **Verdict:** Conformant. Pinned `CRL-034` (revoked intermediate, reject) vs
  `CRL-036` (clean intermediate, accept). `require` is intentionally omitted for
  this scenario — it would additionally demand a CRL for the intermediate,
  confounding the revocation signal (see `crl.py:363-365`).

### CRL freshness / expiry — **STRICTER than XRootD** (RFC 5280 §5.1.2.4/§5.1.2.5)

- **Requirement:** a CRL past `nextUpdate` is stale; one with a future
  `thisUpdate` is not yet valid. RFC 5280 does not mandate a single failure
  action, but IGTF/WLCG treat staleness as loss of revocation assurance.
- **Ours:** a stale or not-yet-valid CRL is **fatal under `try`**, not only
  under `require`. OpenSSL raises `X509_V_ERR_CRL_HAS_EXPIRED` /
  `X509_V_ERR_CRL_NOT_YET_VALID`; the `try` verify callback deliberately lets
  every verdict except `UNABLE_TO_GET_CRL` stand
  (`src/auth/crypto/store_policy.c:576-592` — the doc comment states
  "a stale (expired) CRL stays fatal (staleness is evidence)").
- **XRootD v6.1.0:** at the default `crlTry`(1) level expiry is **not** fatal.
  `IsRevoked()` only emits a DEBUG warning when `now > NextUpdate()`
  (`XrdCrypto/XrdCryptosslX509Crl.cc:573-576`) and continues checking. Expiry
  becomes fatal only at `crlRequire`(3): `GetCACheck()`
  (`XrdSecgsi/XrdSecProtocolgsi.cc:4649`) and `VerifyCRL()`
  (`XrdSecgsi/XrdSecProtocolgsi.cc:4453-4455`,
  `if (CRLCheck >= 3 && crl && crl->IsExpired()) rc = -5`).
- **Verdict:** **Stricter-than-XRootD.** We reject a stale CRL at the default
  strictness where XRootD would accept and merely warn. Pinned `CRL-019/020`
  (stale, reject under both try and require), `CRL-022/023` (stale + also
  listed), `CRL-025/026` (not-yet-valid `thisUpdate`).

### CRL signature verification (RFC 5280 §5.1.1.3, §6.3.3)

- **Requirement:** a CRL MUST be signed by the CA whose certificates it
  revokes; a CRL bearing the CA's issuer name but signed by a foreign key MUST
  NOT be honored.
- **Ours:** OpenSSL verifies the CRL signature against the store CA before
  applying it; a rogue-signed CRL fails to attach and cannot revoke — but
  under `try` it also does not spuriously reject the good leaf, and under
  `require` the absence of a *valid* CRL fails closed
  (`store_policy.c:613-621` gate + OpenSSL signature check).
- **XRootD v6.1.0:** `VerifyCRL()` explicitly calls `crl->Verify(xcasig)` and
  returns `-4` on failure (`XrdSecgsi/XrdSecProtocolgsi.cc:4452-4457`).
- **Verdict:** Conformant. Pinned `CRL-028` (rogue-signed CRL, `try` → accept
  the good leaf because the bad CRL is discarded) and `CRL-029` (`require` →
  reject: no valid CRL present).

### CRL scope / issuer match (RFC 5280 §5.1.2.3)

- **Requirement:** a CRL filed for CA-A but whose `issuer` is CA-B does not
  cover CA-A's certificates; it is out of scope and provides no revocation
  assurance for CA-A.
- **Ours:** OpenSSL matches CRL issuer to certificate issuer when selecting the
  applicable CRL; a mismatched CRL is not applied, so under `try` the leaf is
  accepted (no in-scope revocation) and under `require` it is rejected (no
  valid in-scope CRL) — same gate as above.
- **XRootD v6.1.0:** `VerifyCRL()` compares `xca->SubjectHash()` with
  `crl->IssuerHash()` and returns `-2` on mismatch
  (`XrdSecgsi/XrdSecProtocolgsi.cc:4436-4467`).
- **Verdict:** Conformant. Pinned `CRL-031` (mismatch under `try` → accept) and
  `CRL-032` (under `require` → reject).

### Reason codes, including removeFromCRL in a full CRL (RFC 5280 §5.3.1)

- **Requirement:** every `reasonCode` on a normal CRL entry (unspecified,
  keyCompromise, cACompromise, affiliationChanged, superseded,
  cessationOfOperation, certificateHold, privilegeWithdrawn, aACompromise) is
  an effective revocation. `removeFromCRL` (8) is defined **only** for delta
  CRLs; in a full CRL it is malformed.
- **Ours:** all nine reason codes reject (the reason field does not alter the
  revoked-serial verdict). For `removeFromCRL` in a **full** CRL we follow
  OpenSSL, which treats the malformed entry as **non-revoking** — the cert
  verifies. This is recorded as a deliberate CONSERVATIVE decision
  (`_decisions.py` `CRL-065`/`CRL-066`: "removeFromCRL in a full CRL is
  malformed; OpenSSL treats the entry as non-revoking … We follow OpenSSL").
- **XRootD v6.1.0:** `IsRevoked()` keys only on serial-number presence and
  revocation time (`XrdCryptosslX509Crl.cc:563-601`); it does not inspect
  `reasonCode`, so a listed serial with `removeFromCRL` would still be treated
  as revoked — a different, non-OpenSSL behavior.
- **Verdict:** Conformant (reason catalogue) / Divergent-but-documented
  (`removeFromCRL`-in-full-CRL: we defer to OpenSSL's non-revoking reading).
  Pinned `CRL-038..064` (all reasons reject), `CRL-065/066` (accept, per
  `_decisions.py`).

### Delta CRLs (RFC 5280 §5.2.4) — CONSERVATIVE / shared limitation

- **Requirement:** a delta CRL (`deltaCRLIndicator` present) supplements a base
  CRL. Additions on a delta revoke; a `removeFromCRL` entry on a delta
  un-revokes a serial listed on the base.
- **Ours:** a delta that **adds** a serial is honored as a revocation (any CRL
  listing the serial revokes — fail-safe): `CRL-068/069` reject. A delta that
  **un-revokes** via `removeFromCRL` is **not** honored — the base revocation
  stands: `_decisions.py` `CRL-075` ("delta-CRL un-revocation … is not honored;
  the base-CRL revocation stands"). `X509_V_FLAG_USE_DELTAS` is set
  (`store_policy.c:617`) but OpenSSL only applies a delta when it is fully
  IDP/`freshestCRL`-consistent, so the un-revocation path is conservatively a
  no-op here.
- **XRootD v6.1.0:** **no delta-CRL support at all** — zero references to
  delta / `deltaCRLIndicator` / `freshestCRL` anywhere in `XrdCrypto`,
  `XrdSecgsi`, or `XrdTls` (verified by grep). Only base CRLs are parsed.
- **Verdict:** Documented-limitation (fail-safe). We never *drop* a revocation
  we hold; we simply do not let a delta lift one. XRootD is strictly less
  capable here. Pinned `CRL-068..076`.

### Multiple full CRLs / CRLNumber precedence (RFC 5280 §5.2.3) — CONSERVATIVE

- **Requirement:** among a CA's full CRLs, the one with the highest `CRLNumber`
  is authoritative; a newer CRL that drops a serial supersedes an older one
  that listed it.
- **Ours:** `CRLNumber`-based precedence across multiple full CRLs is **not**
  implemented — any loaded CRL that lists the serial revokes it (fail-safe):
  `_decisions.py` `CRL-080`/`CRL-081` ("multi-CRL precedence by CRLNumber is
  not implemented; any CRL that lists the serial revokes it"). Consequently a
  newer clean CRL does **not** override an older revoking one
  (`CRL-080/081` reject), while a newer revoking CRL over an older clean one
  correctly rejects (`CRL-077/078`), and two clean CRLs accept
  (`CRL-083/084`).
- **XRootD v6.1.0:** no `CRLNumber` handling (grep: zero matches); it loads a
  single `<hash>.r0` per CA and does not reconcile multiple full CRLs.
- **Verdict:** Documented-limitation (fail-safe, security-preserving). The only
  observable difference from RFC 5280 is that a serial *un-listed* by a newer
  CRL but *listed* by an older one stays rejected — we never under-revoke.
  Pinned `CRL-077..085`.

### Signature-algorithm variety on the CRL (RFC 5280 §6.3.3)

- **Requirement:** CRLs may be signed with RSA or ECDSA over any acceptable
  digest; a revocation carried on an EC/SHA-384 or RSA/SHA-512 CRL is as binding
  as one on an RSA/SHA-256 CRL.
- **Ours:** OpenSSL verifies the CRL signature regardless of key/digest; a
  revoked serial on an ECDSA-P384/SHA-384 or RSA/SHA-512 CRL rejects.
- **XRootD v6.1.0:** `crl->Verify(xcasig)` delegates to OpenSSL likewise
  (`XrdSecgsi/XrdSecProtocolgsi.cc:4452`).
- **Verdict:** Conformant. Pinned `CRL-086/087` (EC-P384 CA, ECDSA-SHA384 CRL)
  and `CRL-089/090` (RSA CA, SHA-512 CRL).

### Cross-protocol unification (architectural)

- **Requirement (derived):** revocation policy should not silently weaken
  depending on which door a credential enters by.
- **Ours:** both the stream GSI store (`src/auth/gsi/config.c:31-41`) and the
  WebDAV client-cert store (`src/protocols/webdav/auth_store.c:52-55`) are built
  by the single `brix_build_ca_store()` with the same `crl_mode`, and both run
  the full chain verify (`src/auth/crypto/gsi_verify.c:163-226`). `davs://` and
  `root://` therefore enforce identical CRL semantics.
- **XRootD v6.1.0:** the two paths are **different code**. `root://` GSI runs
  the `XrdCrypto` CRL machinery above (expiry non-fatal below `crlRequire`).
  `XrdHttp` (`davs://`) does **only** TLS-layer verification
  (`XrdHttp/XrdHttpProtocol.cc:1842-1853`): the OpenSSL store gets
  `X509_V_FLAG_CRL_CHECK` (`XrdTls/XrdTlsContext.cc:707-711`), gated by
  `http.allowmissingcrl` (`XrdHttpProtocol.cc:1142-1143`) — so on the HTTP path
  expiry is OpenSSL-fatal, but no GSI proxy/signing-policy revocation logic runs
  at all.
- **Verdict:** Stricter-than-XRootD (consistency). Our WebDAV path applies the
  identical CRL mode and the full GSI chain policy that XRootD's HTTP path
  omits. Pinned by running the `CRL-*` matrix under the shared verifier.

---

## Divergence summary

| Aspect | Ours | XRootD v6.1.0 | Verdict | Tests |
|---|---|---|---|---|
| CRL loading `<hash>.rN` from hashed CA dir | `*.pem` + `*.r0..r9` scan (`pki_build.c:105-113`) | `<caroot>.r0` (`XrdSecProtocolgsi.cc:143,4334-4346`) | Conformant | CRL-* (all) |
| Strictness modes | off/try/require (`store_policy.c:613-621`) | crl 0-3, default crlTry (`XrdSecgsiOpts.hh:105-120`) | Conformant | CRL-004..006, 013..015 |
| Revoked EEC | `CERT_REVOKED` via OpenSSL (`gsi_verify.c:199`) | `IsRevoked()` (`XrdCryptosslX509Crl.cc:563`) | Conformant | CRL-004/005, 010/011 |
| Revoked intermediate CA | `CRL_CHECK_ALL` every node (`store_policy.c:616`) | per-node (`XrdCryptoX509Chain.cc:816`) | Conformant | CRL-034 vs 036 |
| **Stale CRL (past nextUpdate)** | **FATAL under try** (`store_policy.c:576-592`) | warn only below crlRequire (`XrdCryptosslX509Crl.cc:573-576`; fatal only `:4453-4455`) | **Stricter-than-XRootD** | CRL-019/020, 022/023, 025/026 |
| CRL signature (rogue signer) | OpenSSL verify + mode gate | `crl->Verify()` `-4` (`XrdSecProtocolgsi.cc:4452`) | Conformant | CRL-028/029 |
| CRL issuer/scope mismatch | OpenSSL issuer match + gate | hash compare `-2` (`XrdSecProtocolgsi.cc:4436`) | Conformant | CRL-031/032 |
| Reason codes (9x) | all revoke | serial-only, ignores reason (`XrdCryptosslX509Crl.cc:563`) | Conformant | CRL-038..064 |
| removeFromCRL in a **full** CRL | non-revoking (follow OpenSSL) | would still revoke (serial-only) | Divergent (documented, `_decisions.py` CRL-065/066) | CRL-065/066 |
| Delta CRL adds serial | revokes (fail-safe) | no delta support at all | Documented-limitation | CRL-068/069 |
| Delta CRL un-revokes (removeFromCRL) | not honored; base stands (`_decisions.py` CRL-075) | no delta support | Documented-limitation | CRL-074/075 |
| Multi-CRL CRLNumber precedence | not implemented; any listing revokes (`_decisions.py` CRL-080/081) | no CRLNumber handling | Documented-limitation | CRL-077..085 |
| EC/SHA-512 CRL signatures | OpenSSL verifies | OpenSSL verifies (`XrdSecProtocolgsi.cc:4452`) | Conformant | CRL-086/087, 089/090 |
| root:// vs davs:// parity | one store, same crl_mode (`auth_store.c:52-55`, `gsi/config.c:31-41`) | split: XrdCrypto vs TLS-only (`XrdHttpProtocol.cc:1842-1853`) | Stricter-than-XRootD (consistency) | CRL-* under shared verifier |
