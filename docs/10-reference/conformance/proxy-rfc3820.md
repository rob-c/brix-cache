# Proxy certificates (RFC 3820) — conformance

Scope: recognition and validation of X.509 proxy certificates (RFC 3820,
"Internet X.509 Public Key Infrastructure (PKI) Proxy Certificate Profile") on
the GSI authentication path, and the Globus GT2/GT3 legacy variants. Our
implementation is the shared chain verifier `brix_gsi_verify_chain`
(`src/auth/crypto/gsi_verify.c`) plus the pure-C proxy helpers in
`src/auth/crypto/store_policy.c`; the delegated-proxy request/sign path is
`src/auth/crypto/../gsi/proxy_req.c`. The reference is XRootD v6.1.0's
`XrdCryptogsiX509Chain::Verify` (`/tmp/xrootd-src/src/XrdCrypto/XrdCryptogsiX509Chain.cc`)
driven from `XrdSecProtocolgsi::ServerDoIt` (`/tmp/xrootd-src/src/XrdSecgsi/XrdSecProtocolgsi.cc`),
with proxy classification in `XrdCryptosslX509.cc` and the PCI codec in
`XrdCryptosslgsiAux.cc`.

Both root:// GSI and davs:// (WebDAV cert auth) route through the *same*
`brix_gsi_verify_chain` (`src/protocols/webdav/auth_cert.c:478`), so proxy
semantics are identical on both surfaces. XRootD's HTTP surface (XrdHttp) does
**not** run `XrdCryptogsiX509Chain::Verify` at all — it trusts the TLS layer's
`SSL_get_verify_result` — so this component's XRootD reference is the root://
GSI path only.

A critical architectural fact governs the whole comparison: the XRootD server
verify call is
`x509ChainVerifyOpt_t vopt = {0, ...}` — **`opt == 0`, so `kOptsRfc3820` is
NOT set** (`XrdSecProtocolgsi.cc:3216`). The `kOptsRfc3820` bit that makes
`XrdCryptogsiX509Chain::Verify` demand a proxyCertInfo extension
(`XrdCryptogsiX509Chain.cc:177`) is set only by the standalone unit test
(`XrdSecgsitest.cc:381,399`). In production, XRootD therefore accepts a proxy
detected purely by subject-name shape (`kProxy` set in `XrdCryptosslX509.cc`)
and does not require RFC 3820 conformance at all. Our module has no such
"lenient" mode: RFC 3820 structure is always enforced.

## Normative basis

- **RFC 3820 §3.1** — a proxy certificate MUST carry exactly one ProxyCertInfo
  extension, and it MUST be critical.
- **RFC 3820 §3.2** — ProxyPolicy carries a `policyLanguage` OID: `id-ppl-inheritAll`
  (impersonation, 1.3.6.1.5.5.7.21.1), `id-ppl-independent` (1.3.6.1.5.5.7.21.2),
  or a specific policy language (Globus limited, 1.3.6.1.4.1.3536.1.1.1.9). An
  unrecognised policy language whose semantics the verifier cannot process MUST
  cause rejection.
- **RFC 3820 §3.4** — a proxy's subject MUST be the issuer's subject with exactly
  one CommonName RDN appended; the issuer MUST be an EEC or another proxy (never a
  CA / trust anchor).
- **RFC 3820 §3.7** — a proxy MUST NOT be a CA (no basicConstraints CA:TRUE / no
  keyCertSign) and MUST NOT carry a subjectAltName.
- **RFC 3820 §4.2 (pCPathLenConstraint)** — the ProxyCertInfo path-length
  constraint bounds the number of proxy certificates that may follow; at most
  `pCPathLenConstraint` further proxies are permitted.
- **RFC 3820 §3.8 (limited-proxy monotonicity)** — a restricted (limited) proxy
  must not be able to issue a less-restricted (full/independent) proxy;
  restriction is monotone down the delegation chain.
- **RFC 5280 §6.1.3** — path validation checks each certificate's validity window
  at the present time.
- **OID assignment** — RFC-standard proxyCertInfo OID `1.3.6.1.5.5.7.1.14`;
  pre-standard Globus draft OID `1.3.6.1.4.1.3536.1.222`.

---

### proxyCertInfo recognition + OIDs (RFC 3820 §3.1; OID assignment)

- **Requirement:** a proxy is identified by a ProxyCertInfo extension carrying the
  standard OID `1.3.6.1.5.5.7.1.14` (or the pre-standard draft OID
  `1.3.6.1.4.1.3536.1.222`).
- **Ours:** classification is by OpenSSL's `EXFLAG_PROXY` flag, which OpenSSL sets
  only for the standard `NID_proxyCertInfo` (1.3.6.1.5.5.7.1.14) — see
  `brix_px_classify` (`src/auth/crypto/store_policy.c:315`) and the per-cert PCI
  scan `brix_proxy_pci_ok` (`src/auth/crypto/store_policy.c:501-503`, which locates
  the extension by `X509_get_ext_by_NID(cert, NID_proxyCertInfo, -1)`). We also
  emit the standard OID when building/signing delegated proxies
  (`GSI_PROXYCERTINFO_OID`, `proxy_req.c:62`, `proxy_req.c:235`). A cert bearing
  **only** the draft OID `1.3.6.1.4.1.3536.1.222` is not flagged `EXFLAG_PROXY`,
  so we treat it as an ordinary EEC — which then fails path validation at the
  proxy position.
- **XRootD v6.1.0:** recognises **both** OIDs: `GetExtension(gsiProxyCertInfo_OID)`
  falls back to `GetExtension(gsiProxyCertInfo_OLD_OID)` (`XrdCryptogsiX509Chain.cc:178-179`),
  and the PCI codec decodes either OID (`XrdCryptosslgsiAux.cc:170-173`). The
  draft OID `1.3.6.1.4.1.3536.1.222` is defined at `XrdCryptoFactory.hh:93`.
- **Verdict:** Conformant (standard OID) / Stricter-than-XRootD for the draft OID —
  we honour only the RFC-standard OID, XRootD additionally accepts the pre-standard
  draft. Pinned by PXY-006 (critical PCI recognised), PXY-018 (`_draft_only_pci`
  rejected).

### Critical-PCI requirement (RFC 3820 §3.1)

- **Requirement:** the ProxyCertInfo extension MUST be marked critical.
- **Ours:** `brix_proxy_pci_ok` locates the extension and rejects it outright when
  `X509_EXTENSION_get_critical(ext)` is false
  (`src/auth/crypto/store_policy.c:513-514`), and rejects a malformed PCI that fails
  `X509_get_ext_d2i` (`store_policy.c:516-519`). When emitting proxies we always set
  the critical bit (`X509_EXTENSION_set_critical(ext, 1)`, `proxy_req.c:239`).
- **XRootD v6.1.0:** `XrdCryptosslX509.cc:393` only classifies the cert as `kProxy`
  (pxytype 2, "RFC 382{0,1} compliant") when `X509_EXTENSION_get_critical(ext)` is
  true; a non-critical PCI leaves `type == kUnknown` (`XrdCryptosslX509.cc:415-416`),
  and a non-proxy at the proxy position then fails with `kInvalidProxy`
  (`XrdCryptogsiX509Chain.cc:165-168`).
- **Verdict:** Conformant (both reject a non-critical PCI). Pinned by PXY-007..010
  (non-critical PCI at leaf and in chain, all policy kinds).

### Policy language: impersonation / independent / limited (RFC 3820 §3.2)

- **Requirement:** the ProxyPolicy `policyLanguage` selects the delegation
  semantics; a verifier that cannot process an unrecognised policy language MUST
  reject.
- **Ours:** `brix_proxy_pci_ok` decodes `pci->proxyPolicy->policyLanguage` and
  accepts **only** the three recognised OIDs — impersonation
  `1.3.6.1.5.5.7.21.1`, independent `1.3.6.1.5.5.7.21.2`, Globus limited
  `1.3.6.1.4.1.3536.1.1.1.9` — rejecting any other or absent policy language
  (`src/auth/crypto/store_policy.c:380-382`, `store_policy.c:520-528`). The empty
  ProxyPolicy (no `policyLanguage`) is rejected because `pci->proxyPolicy->policyLanguage`
  yields no OID text to match.
- **XRootD v6.1.0:** does **not** inspect which policy language is present. Under
  `kOptsRfc3820` it calls the PCI handler with `haspolicy`, which sets
  `*haspolicy = (pci->proxyPolicy) ? 1 : 0` (`XrdCryptosslgsiAux.cc:185-187`) — a
  bare presence check, "the content ignored for the time being"
  (`XrdCryptosslgsiAux.cc:154`). In production (`opt == 0`) it does not look at the
  PCI policy at all. Any policyLanguage OID, including a bogus one, is accepted.
- **Verdict:** Stricter-than-XRootD — we allowlist the three RFC/Globus policy OIDs
  and reject unknown ones; XRootD accepts any (or, in production, does not check).
  Pinned by PXY-001..003 (three known kinds accepted), PXY-011..012 (bogus OID
  rejected), PXY-014 (empty ProxyPolicy rejected), PXY-013 (duplicate PCI
  rejected), and the chain-leaf variant PXY row for a bogus OID at depth.

### pcPathLenConstraint — extract + enforce (RFC 3820 §4.2)

- **Requirement:** the ProxyCertInfo path-length constraint bounds the number of
  proxies that may follow; at most `pCPathLenConstraint` further proxy certificates
  are permitted.
- **Ours:** enforcement is delegated to OpenSSL's proxy-aware path validation.
  `brix_gsi_verify_chain` sets `X509_V_FLAG_ALLOW_PROXY_CERTS`
  (`src/auth/crypto/gsi_verify.c:192`; also on the store at build,
  `src/auth/gsi/config.c:38`), and OpenSSL's `X509_verify_cert` decrements and
  enforces `pcPathLenConstraint` natively for `EXFLAG_PROXY` certs — a chain that
  exceeds the constraint fails verification. We also extract and correctly
  decrement the constraint when *building* delegated proxies
  (`pxr_parent_pathlen` / `pxr_make_pci_ext`, `proxy_req.c:99-133`, `192-215`) and
  when *signing* a request we take `min(req, signer-1)`
  (`proxy_req.c:538-540`).
- **XRootD v6.1.0:** extracts `pxplen` from the PCI (`XrdCryptogsiX509Chain.cc:176-186`,
  via `XrdCryptosslProxyCertInfo`, `XrdCryptosslgsiAux.cc:180-182`) and enforces it
  by hand: the running `plen` is decremented per proxy and tightened to the
  stricter `pxplen` when smaller (`XrdCryptogsiX509Chain.cc:188-194`); the loop
  terminates and the global depth check at `:76-80` reports `kTooMany`.
- **Verdict:** Conformant (both extract and enforce; ours via OpenSSL, XRootD by
  hand). Pinned by the pcPathLenConstraint grid PXY rows (top constraint 0..3 ×
  0..4 following proxies) and the limited-proxy constraint grid (§15), plus the
  monotone-decrement chains (PXY §5b).

### Limited → full monotonicity (RFC 3820 §3.8) — STRICTER

- **Requirement:** a limited (restricted) proxy must not issue a full or otherwise
  less-restricted proxy; restriction is monotone down the chain.
- **Ours:** enforced. `brix_gsi_verify_chain` calls
  `brix_gsi_enforce_proxy_monotonicity` (`src/auth/crypto/gsi_verify.c:39-49`),
  which delegates to `brix_proxy_chain_ok` (`src/auth/crypto/store_policy.c:354-375`):
  it walks the chain root→leaf, and once a limited proxy is seen, any subsequent
  full proxy is an escalation and returns 0 → reject. "Limited" is recognised both
  by the Globus limited policy OID (`brix_px_classify`, `store_policy.c:322`) and by
  the legacy `CN=limited proxy` RDN (`store_policy.c:339-343`).
- **XRootD v6.1.0:** **detects but does not enforce** monotonicity. The production
  verify path (`opt == 0`) never distinguishes a limited proxy by policy language,
  and even under `kOptsRfc3820` the verifier only checks PCI presence, not the
  policy OID (`XrdCryptosslgsiAux.cc:185-187`). The only place XRootD recognises
  `CN=limited proxy` is the `xrdgsiproxy` display CLI
  (`XrdSecgsiProxy.cc:242`), not the server verify path. No code rejects a full
  proxy beneath a limited one.
- **Verdict:** Stricter-than-XRootD (documented deliberate divergence). Pinned by
  PXY (§10) monotonicity rows — limited→full rejected, limited→limited and
  full→limited accepted, deep re-escalation `full→limited→full` rejected, and
  `_escalate_via_proxy_from` (a full proxy minted beneath a limited one) rejected.

### Legacy Globus GT2/GT3 proxies — deliberately REJECTED (STRICTER)

- **Requirement (context):** RFC 3820 is the standard proxy profile; the legacy
  Globus GT2 form (subject ending `/CN=proxy` or `/CN=limited proxy`, no
  proxyCertInfo) and GT3 predate it. RFC 3820 does not require accepting them.
- **Ours:** only RFC 3820 proxies are honoured. A legacy GT2 proxy has no
  proxyCertInfo, so OpenSSL does not set `EXFLAG_PROXY`; it is treated as an
  ordinary certificate whose issuer (the EEC) is not a CA, so `X509_verify_cert`
  rejects the chain (the non-CA EEC cannot issue a non-proxy cert). Note
  `brix_px_classify` still *recognises* the legacy `CN=proxy` / `CN=limited proxy`
  RDN (`src/auth/crypto/store_policy.c:330-349`) — but purely to feed the
  monotonicity check, never to *admit* a legacy proxy. The one non-proxy case is a
  bare `CN=proxy` EEC signed directly by a CA, which is an ordinary end-entity
  cert (the CN is cosmetic) and is accepted as such (register: PXY-136).
- **XRootD v6.1.0:** accepts legacy proxies. `XrdCryptosslX509.cc:421-425` sets
  `pxytype = 4; type = kProxy` when the last CN is `proxy` or `limited proxy`, and
  GT3 proxies get `pxytype = 3` via `XrdCryptosslX509CheckProxy3`
  (`XrdCryptosslX509.cc:378-381`). Because production runs with `opt == 0`, these
  legacy/GT3 proxies verify without any proxyCertInfo.
- **Verdict:** Stricter-than-XRootD (documented deliberate divergence,
  `tests/clauses/_decisions.py` PXY-004/005/025..030/072/073/113/114). Pinned by
  the legacy-acceptance rows (§1 PXY-004/005 → reject), the GT2 interaction rows
  (§9: legacy-under-RFC, RFC-under-legacy, legacy-only chains all reject), and
  PXY-136 (bare `CN=proxy` EEC off a CA accepted as an ordinary cert).

### Proxy subject / issuer naming (RFC 3820 §3.4)

- **Requirement:** a proxy's subject is the issuer subject plus exactly one CN RDN;
  the issuer is an EEC or proxy with signing capability, never a trust anchor.
- **Ours:** OpenSSL's proxy path validation (`X509_V_FLAG_ALLOW_PROXY_CERTS`)
  enforces the "issuer subject + one CN" naming rule for `EXFLAG_PROXY` certs; a
  subject that is not `issuer + one CN`, or one that adds no CN, fails
  verification. A proxy signed directly by the CA fails because the CA is a trust
  anchor issuing a proxy the naming/consistency rules forbid. The issuer's
  signing capability is additionally held to `digitalSignature` on the leaf/EEC via
  `brix_leaf_purpose_violation` (`src/auth/crypto/store_policy.c:459-490`, keyUsage
  must assert `digitalSignature` or `keyAgreement`).
- **XRootD v6.1.0:** implements the naming rule by hand in `SubjectOK`
  (`XrdCryptogsiX509Chain.cc:211-285`): the subject must start with the issuer name
  (accounting for a proxy issuer's trailing `/CN=`), and exactly one `CN=` must be
  appended (`:266-281`).
- **Verdict:** Conformant. Pinned by PXY §7 (`_subject_unrelated`,
  `_subject_missing_cn`, `_wrong_signer`) and §8 (proxy off CA rejected, EEC
  lacking digitalSignature rejected).

### Forbidden extensions on a proxy (RFC 3820 §3.7)

- **Requirement:** a proxy MUST NOT assert basicConstraints CA:TRUE / keyCertSign
  and MUST NOT carry a subjectAltName.
- **Ours:** a proxy with basicConstraints CA:TRUE is rejected by OpenSSL path
  validation (a proxy is not permitted to be a CA under
  `X509_V_FLAG_ALLOW_PROXY_CERTS`). Our proxy *builder* strips subjectAltName from
  copied parent extensions (`GSI_SUBJ_ALT_NAME_OID` skipped, `proxy_req.c:148-150`)
  and the *signer* path refuses to sign a request whose signer carries a SAN
  (`sgn_copy_signer_exts` returns -1 on SAN, `proxy_req.c:434-436`).
- **XRootD v6.1.0:** the CA flag is set from basicConstraints
  (`XrdCryptosslX509.cc:354-356`), so a CA:TRUE cert is typed `kCA` and cannot
  occupy the proxy position. XRootD's proxy creation similarly excludes SAN.
- **Verdict:** Conformant. Pinned by PXY §6 (CA:TRUE and SAN rejection across
  policy kinds, at leaf and in chain) and §17 (forbidden extensions deeper in the
  chain).

### Validity windows (RFC 5280 §6.1.3)

- **Requirement:** each certificate's notBefore/notAfter is checked at the present
  time.
- **Ours:** `X509_verify_cert` checks every cert's window at wall-clock time; an
  expired or not-yet-valid proxy/EEC anywhere in the chain fails
  (`src/auth/crypto/gsi_verify.c:199`).
- **XRootD v6.1.0:** `XrdCryptoX509Chain::Verify(...when...)` checks validity at
  `when = time(0)` for each node (`XrdCryptogsiX509Chain.cc:70`, and the per-node
  `Verify` calls throughout).
- **Verdict:** Conformant. Pinned by PXY §11 and §19 validity rows (expired proxy,
  expired/expired-intermediate EEC, not-yet-valid proxy/EEC, deep all-valid
  control).

---

## Divergence summary

| Aspect | Ours | XRootD v6.1.0 | Verdict | Tests |
|---|---|---|---|---|
| Standard PCI OID `…7.1.14` | Recognised (EXFLAG_PROXY) | Recognised | Conformant | PXY-006 |
| Draft PCI OID `…3536.1.222` | Not treated as proxy → EEC path | Accepted as proxy | Stricter | PXY-018 |
| PCI criticality | Rejected if non-critical (`store_policy.c:513`) | Not `kProxy` if non-critical (`X509.cc:393`) | Conformant | PXY-007..010 |
| Policy language | Allowlist of 3 OIDs, else reject (`store_policy.c:520-528`) | Presence-only / ignored (`gsiAux.cc:185`) | Stricter | PXY-011,012,014 |
| pcPathLenConstraint | Extract + enforce (OpenSSL + builder) | Extract + enforce by hand (`X509Chain.cc:188-194`) | Conformant | PXY §5, §15 |
| Limited→full monotonicity | Enforced (`brix_proxy_chain_ok`) | Detected (CLI only), not enforced | Stricter | PXY §10 |
| Legacy GT2/GT3 proxies | Rejected (RFC 3820 only) | Accepted (pxytype 3/4) | Stricter | PXY-004,005; §9 |
| `CN=proxy` EEC off a CA | Accepted as ordinary cert | Accepted | Conformant (NOT-MANDATED) | PXY-136 |
| Proxy subject/issuer naming | OpenSSL proxy rules | Hand-rolled `SubjectOK` | Conformant | PXY §7, §8 |
| Forbidden ext (CA:TRUE / SAN) | Rejected | Rejected | Conformant | PXY §6, §17 |
| Validity windows | Per-cert at now | Per-cert at `when` | Conformant | PXY §11, §19 |
| Verify strictness mode | Always RFC-3820-strict | Production `opt==0` (lenient) | Stricter | (architectural) |

Every divergence in this component runs in the direction of *more* restrictive
behaviour than XRootD v6.1.0: we reject legacy proxies, unknown policy languages,
the draft-only OID, and limited→full escalation that XRootD (in its production
`opt == 0` verify path) admits. No case exists where XRootD is stricter than our
module on the proxy path. Deliberate divergences are registered in
`tests/clauses/_decisions.py` (PXY-004/005/025..030/072/073/113/114 legacy;
PXY-136 cosmetic CN).
