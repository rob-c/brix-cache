# Chain building (RFC 5280 PKIX) — conformance

Scope: X.509 certification-path construction and validation as performed by our
module's shared verification core (`src/auth/crypto/gsi_verify.c`,
`store_policy.c`, `pki_build.c`) versus the official XRootD v6.1.0 chain engine
(`XrdCrypto/XrdCryptoX509Chain.cc`, `XrdCryptosslX509.cc`), both measured against
RFC 5280 §4.1/§4.2/§6, RFC 3820 (proxy delegation depth), and the IGTF profile
(weak-algorithm and key-size floors).

The central architectural fact is this: **our module delegates path validation
to OpenSSL `X509_verify_cert()`** (`src/auth/crypto/gsi_verify.c:199`), then
layers additional IGTF/RFC-5280 policy checks on top of the verified chain
(`brix_gsi_enforce_cert_policy`, `gsi_verify.c:116-144`). **XRootD implements its
own hand-rolled chain walk** that calls raw `X509_verify()` (signature only) per
link (`XrdCryptosslX509.cc:798`, `XrdCryptoX509Chain.cc:833`) and enforces
neither basicConstraints pathLen, keyUsage, extendedKeyUsage, unknown-critical
extensions, serial-number rules, signature-algorithm policy, nor key-size floors
at the PKIX layer. Consequently our module is **stricter than XRootD on every
axis below except the two shared limitations** (subject-hash CApath collisions
and DN encoding normalization), where both defer to OpenSSL's raw behaviour.

The clause test family is [`tests/clauses/chain.py`](../../../tests/clauses/chain.py)
(prefix `CHN-`), all rows run in group `sp_off_crl_off` so the verdict reflects
chain behaviour only. Deliberate-divergence rationales live in
[`tests/clauses/_decisions.py`](../../../tests/clauses/_decisions.py).

## Normative basis

- **RFC 5280 §4.1.2.2** — serialNumber MUST be a positive integer; conforming CAs
  MUST NOT use serials longer than 20 octets.
- **RFC 5280 §4.1.2.5** — validity: a certificate is usable only within
  [notBefore, notAfter].
- **RFC 5280 §4.1.1.2 / §4.1.2.3** — signatureAlgorithm identifies the algorithm;
  the IGTF profile forbids MD5/SHA-1-based signatures.
- **RFC 5280 §4.2.1.1 / §4.2.1.2** — authorityKeyIdentifier / subjectKeyIdentifier
  are advisory aids to path construction, not trust inputs.
- **RFC 5280 §4.2.1.3** — keyUsage: a CA that asserts keyUsage MUST set
  keyCertSign to sign certificates; an end-entity used for TLS client auth needs
  digitalSignature (or keyAgreement for fixed-ECDH).
- **RFC 5280 §4.2.1.9** — basicConstraints: only cA=TRUE certs may be CAs;
  pathLenConstraint bounds the number of subordinate CAs.
- **RFC 5280 §4.2.1.12** — extendedKeyUsage constrains the certified purpose.
- **RFC 5280 §4.2** — a certificate-using system MUST reject a certificate that
  carries an unrecognized **critical** extension.
- **RFC 5280 §6.1** — path-validation algorithm: build to a trust anchor, verify
  each signature, honour depth, basic constraints, and validity.
- **IGTF profile** — RSA ≥ 2048, EC ≥ 256; SHA-2 signatures.

---

### Issuer selection / AKID tolerance (RFC 5280 §4.2.1.1)

- **Requirement:** authorityKeyIdentifier "provides a means of identifying the
  public key corresponding to the private key used to sign a certificate"; it is
  an aid to path construction. RFC 5280 §4.2.1.1 does not make an AKID/SKID match
  a precondition of trust — the binding is proven by the issuer's signature.
- **Ours:** we install a `check_issued` override on the store,
  `brix_sp_proxy_check_issued` (`src/auth/crypto/store_policy.c:548-573`,
  registered at `store_policy.c:611`). It defers to `X509_check_issued`; on
  `X509_V_ERR_AKID_SKID_MISMATCH` or `X509_V_ERR_AKID_ISSUER_SERIAL_MISMATCH` it
  accepts the name-matching issuer anyway, because the RSA signature is still
  verified afterwards by `X509_verify_cert`. This relaxes issuer *selection*, not
  trust, and is required for delegated grid proxies (xrdgsiproxy/voms-proxy-init
  copy the EEC's own AKID into the proxy). Verified by CHN-043..046, CHN-119
  (AKI keyid match, mismatch, issuer+serial, wrong serial, AKI-match-no-SKI — all
  accept).
- **XRootD v6.1.0:** selects the issuer purely by subject-name/hash equality in
  `XrdCryptoX509Chain::Reorder` (`XrdCryptoX509Chain.cc:576-640`, via
  `FindSubject(...,kExact,...)`) and then verifies the signature with raw
  `X509_verify()` (`XrdCryptosslX509.cc:798`). The AKID extension is never
  consulted for selection. Our tolerance produces the same effective selection.
- **Verdict:** Conformant (behaviourally aligned with XRootD, and both correct
  per §4.2.1.1). CHN-043..046, CHN-119.

### basicConstraints cA flag (RFC 5280 §4.2.1.9, §6.1.4(k)(m))

- **Requirement:** a certificate may act as a CA only if basicConstraints is
  present with cA=TRUE; a cert without it (or with cA=FALSE) MUST NOT be accepted
  as an issuer.
- **Ours:** `X509_verify_cert()` enforces this by default
  (`gsi_verify.c:199`). CHN-002 (CA:FALSE used as issuer → reject), CHN-003
  (issuer with no basicConstraints → reject), CHN-001 (CA:TRUE intermediate →
  accept), CHN-004 (non-critical BC on CA → still validates), CHN-017 (a CA cert
  presented as an end entity → accept).
- **XRootD v6.1.0:** determines the cert *type* from basicConstraints in
  `XrdCryptosslX509::CertType` — `bc->ca` sets `type = kCA`
  (`XrdCryptosslX509.cc:353-358`). `CheckCA` requires the top of the chain to be
  a `kCA` (`XrdCryptoX509Chain.cc:200`), and the walk enchains by exact
  issuer/subject name. A cA=FALSE cert is typed `kEEC` and cannot occupy the CA
  slot. Aligned on the cA flag.
- **Verdict:** Conformant. CHN-001..004, CHN-017.

### basicConstraints pathLenConstraint (RFC 5280 §4.2.1.9, §6.1.4(m))

- **Requirement:** pathLenConstraint gives the maximum number of non-self-issued
  intermediate CAs that may follow this CA in a valid path; exceeding it MUST
  fail validation.
- **Ours:** `X509_verify_cert()` enforces X.509 pathLenConstraint at every CA in
  the path. The family exercises this exhaustively: CHN-005..016, CHN-107,
  CHN-108, CHN-110 cover pathLen 0/1/2/3 at both intermediate and root, direct
  vs. subordinate issuance, and non-critical-BC pathLen. E.g. CHN-006
  (pathLen=0 CA issues a sub-CA → reject), CHN-008 (pathLen=1 with two sub-CAs →
  reject), CHN-108 (non-critical BC pathLen=0 issues sub-CA → reject).
- **XRootD v6.1.0:** does **not** enforce the X.509 basicConstraints
  pathLenConstraint at all. Its only "path length" is (a) a *global* configured
  chain-size ceiling `vopt->pathlen` compared against `size`
  (`XrdCryptoX509Chain.cc:706-711`), and (b) the RFC 3820 proxy delegation depth
  `pcPathLengthConstraint`, which is a proxy-only extension decrement in
  `XrdCryptogsiX509Chain.cc:176-194` — unrelated to CA basicConstraints. A real
  CA whose pathLen budget is exceeded by an over-long CA chain passes XRootD's
  walk.
- **Verdict:** Stricter-than-XRootD. CHN-005..016, CHN-107, CHN-108, CHN-110.

### keyUsage keyCertSign on issuing CAs (RFC 5280 §4.2.1.3)

- **Requirement:** if a CA certificate includes a keyUsage extension, the
  keyCertSign bit MUST be set for it to sign certificates.
- **Ours:** enforced by `X509_verify_cert()`. CHN-024 (issuing CA lacks
  keyCertSign → reject), CHN-109 (intermediate keyCertSign cleared → reject),
  CHN-028 (root lacks keyCertSign → reject), CHN-025 (CA lacks cRLSign only →
  accept, cRLSign is irrelevant with CRL checking off), CHN-026 (CA with no
  keyUsage extension → accept, absent = unrestricted), CHN-027 (CA keyUsage
  non-critical, keyCertSign present → accept).
- **XRootD v6.1.0:** never inspects keyUsage. Its per-link check is raw
  `X509_verify()` (`XrdCryptosslX509.cc:798`), which is a bare signature check;
  keyUsage keyCertSign is not consulted anywhere in the chain engine. A CA whose
  keyUsage omits keyCertSign still signs valid subordinates under XRootD.
- **Verdict:** Stricter-than-XRootD. CHN-024, CHN-028, CHN-109.

### End-entity keyUsage / extendedKeyUsage for client auth (RFC 5280 §4.2.1.3/§4.2.1.12)

- **Requirement:** a leaf used for TLS client authentication needs a keyUsage
  compatible with the negotiated key exchange (digitalSignature, or keyAgreement
  for fixed-ECDH) and, if extendedKeyUsage is present, a purpose that permits
  client auth.
- **Ours:** two enforcement points. (1) The TLS layer: nginx `ssl_verify_client`
  applies the OpenSSL `SSL_CLIENT` purpose before our handler runs — this
  rejects a leaf whose EKU excludes clientAuth. (2) Our own
  `brix_leaf_purpose_violation` (`store_policy.c:459-490`, invoked via
  `gsi_verify.c:137` when `client_purpose`): if EKU is present it must include
  clientAuth or anyEKU; if keyUsage is present it must assert digitalSignature or
  keyAgreement. CHN-018..023 (keyUsage variants), CHN-029..042 (EKU variants).
  Three rows are stricter than a naive §4.2.1.12 reading because the TLS-layer
  purpose is production truth — recorded in `_decisions.py`:
  - **CHN-031** (anyEKU-only leaf) → reject: OpenSSL `SSL_CLIENT` purpose does
    not honour an anyExtendedKeyUsage-only leaf for client auth.
  - **CHN-040** (intermediate serverAuth, EEC clientAuth) → reject: SSL_CLIENT
    does EKU chaining and rejects a serverAuth-restricted issuer.
  - **CHN-118** (intermediate anyEKU, EEC clientAuth) → reject: SSL_CLIENT
    rejects an anyEKU intermediate in the client-auth path.
- **XRootD v6.1.0:** consults neither keyUsage nor extendedKeyUsage in the GSI
  chain engine; a leaf with serverAuth-only EKU or a keyUsage lacking
  digitalSignature is accepted by its raw signature walk. (XRootD's `XrdHttp`
  path relies solely on the TLS-layer `SSL_get_verify_result`,
  `XrdHttpSecurity.cc:96`, and does not run the GSI chain verify at all.)
- **Verdict:** Stricter-than-XRootD. CHN-018..042 (accept/reject split),
  CHN-113..118; the three TLS-layer overrides CHN-031/040/118.

### Validity windows (RFC 5280 §4.1.2.5)

- **Requirement:** a certificate is valid only within [notBefore, notAfter]; an
  expired, not-yet-valid, or inverted-window cert anywhere in the path MUST fail.
- **Ours:** enforced by `X509_verify_cert()` for every cert in the chain.
  CHN-051..062, CHN-122..124, CHN-134 cover leaf/intermediate/root × expired,
  not-yet-valid, inverted (notBefore > notAfter, hand-forged DER in
  `chain.py:_raw_eec`/`_inverted_validity`). E.g. CHN-054 (expired EEC → reject),
  CHN-058 (notBefore > notAfter → reject), CHN-059/061 (expired intermediate/root
  → reject), CHN-056 (not-yet-valid → reject).
- **XRootD v6.1.0:** checks validity per cert via `IsValid(when)`
  (`XrdCryptoX509.cc:105-111`: `now >= NotBefore()-kAllowedSkew && now <=
  NotAfter()`), called from both `XrdCryptoX509Chain::Verify`
  (`XrdCryptoX509Chain.cc:826`) and `CheckValidity`. Note XRootD applies a
  `kAllowedSkew` tolerance on notBefore; OpenSSL applies none by default. Both
  reject expired and not-yet-valid certs.
- **Verdict:** Conformant (both enforce the window; the notBefore skew is a
  minor XRootD leniency, not a strictness gap for us). CHN-051..062,
  CHN-122..124, CHN-134.

### Signature-algorithm policy — MD5/SHA-1 rejection (RFC 5280 §4.1.1.2, IGTF)

- **Requirement:** signatures MUST use a strong algorithm; the IGTF profile
  deprecates and forbids MD5- and SHA-1-based certificate signatures.
- **Ours:** `brix_cert_policy_violation` (`store_policy.c:423-433`) reads
  `X509_get_signature_nid`, resolves the digest via `OBJ_find_sigid_algs`, and
  rejects `NID_md5`, `NID_sha1`, `NID_md2`, `NID_md4`. Applied to **every** cert
  in the verified chain (`gsi_verify.c:122-129`), so a weak signature on the
  leaf, an intermediate, or the trust-anchor self-signature is fatal. CHN-072/073
  (SHA-1/MD5 leaf → reject), CHN-075/076 (SHA-1/MD5 intermediate → reject),
  CHN-078 (SHA-1 root self-signature → reject), CHN-132 (SHA-1 ECDSA → reject);
  CHN-069..071, CHN-074, CHN-077, CHN-079, CHN-125..128, CHN-133 confirm SHA-256
  /384/512 accept.
- **XRootD v6.1.0:** uses raw `X509_verify()` (`XrdCryptosslX509.cc:798`) and
  `X509_verify_cert()` (`XrdCryptosslAux.cc:178`) with no algorithm allow-list;
  it accepts an MD5- or SHA-1-signed cert as long as the signature arithmetically
  verifies (subject to OpenSSL's own security level, which does not by itself
  reject SHA-1 at the default level). No explicit weak-algorithm policy exists in
  the chain engine.
- **Verdict:** Stricter-than-XRootD. CHN-072/073/075/076/078/132.

### Key-size floor — RSA ≥ 2048 / EC ≥ 256 (IGTF)

- **Requirement:** the IGTF profile mandates RSA (and DSA) keys ≥ 2048 bits and
  EC keys ≥ 256 bits.
- **Ours:** `brix_cert_policy_violation` (`store_policy.c:409-421`) inspects
  `EVP_PKEY_base_id`/`EVP_PKEY_bits`: RSA/RSA2/DSA below 2048 or EC below 256 is
  rejected, on every cert in the chain. CHN-083/084 (RSA-1024/512 leaf → reject),
  CHN-088 (RSA-1024 intermediate → reject), CHN-094 (RSA-1024 root → reject);
  CHN-080..082, CHN-085..093, CHN-129..131 confirm the accept side (RSA
  2048/3072/4096, EC P-256/384/521 at leaf/intermediate/root).
- **XRootD v6.1.0:** performs no key-size check in the chain engine; a
  1024-bit-RSA or short-EC credential that verifies is accepted (again subject
  only to whatever OpenSSL security level the TLS context happens to impose).
- **Verdict:** Stricter-than-XRootD. CHN-083/084/088/094.

### Serial-number validation (RFC 5280 §4.1.2.2)

- **Requirement:** serialNumber MUST be a positive integer; conforming CAs MUST
  NOT issue serials exceeding 20 octets; DER INTEGER encoding must be minimal
  (X.690 §8.3.2).
- **Ours:** `brix_cert_policy_violation` (`store_policy.c:435-448`) converts the
  serial to a BIGNUM and rejects zero, negative, or (for non-proxy certs)
  `BN_num_bytes > 20`. RFC 3820 proxies are deliberately exempt from the 20-octet
  ceiling because grid proxies derive large serials — see the `is_proxy` guard at
  `store_policy.c:407` and comment at `:435-436`. CHN-065 (serial = 0 → reject),
  CHN-066 (negative serial → reject), CHN-067 (21-octet serial → reject);
  CHN-063/064 (serial 1 / 20-octet → accept). CHN-068 (non-minimal leading
  zeros) is checked on the `c-oracle` surface (X.690 §8.3.2) rather than through
  the TLS wire.
- **XRootD v6.1.0:** extracts the serial only for display and CRL matching
  (`XrdCryptosslX509.cc:622-647` `SerialNumber`/`SerialNumberString`;
  `XrdCryptoX509Chain.cc:814-815`). It performs no positivity, length, or
  minimal-encoding validation.
- **Verdict:** Stricter-than-XRootD. CHN-063..068.

### DN control-byte rejection (RFC 5280 §4.1.2.6)

- **Requirement:** the subject/issuer Name must be a well-formed
  DirectoryString; embedded control or NUL bytes are malformed and a security
  hazard (log injection, DN-spoofing).
- **Ours:** `brix_dn_has_control_bytes` (`store_policy.c:384-401`) scans every
  RDN value of both subject and issuer for bytes `< 0x20` or `0x7f` and rejects
  the cert (`store_policy.c:451-454`). This is beyond what OpenSSL enforces and
  has no XRootD analogue.
- **XRootD v6.1.0:** renders the DN via `X509_NAME_oneline`/`X509_NAME_print_ex`
  (`XrdCryptosslAux.cc:736-746`) without control-byte screening; a DN with
  embedded control bytes is carried through into the mapped identity string.
- **Verdict:** Stricter-than-XRootD.

### Unknown critical extensions (RFC 5280 §4.2)

- **Requirement:** a system MUST reject a certificate containing an unrecognized
  extension marked critical; unrecognized non-critical extensions are ignored.
- **Ours:** `X509_verify_cert()` rejects unhandled critical extensions by
  default. CHN-095 (EEC unknown critical → reject), CHN-097 (intermediate unknown
  critical → reject), CHN-120 (second unknown critical OID → reject); CHN-096,
  CHN-098, CHN-121 confirm non-critical extensions are ignored (accept).
- **XRootD v6.1.0:** the chain engine only *looks for* specific known extensions
  (basicConstraints, proxyCertInfo); a foreign critical extension is neither
  recognized nor rejected by the raw `X509_verify()` walk. XRootD accepts a cert
  with an unknown critical extension.
- **Verdict:** Stricter-than-XRootD. CHN-095, CHN-097, CHN-120.

### Chain depth (RFC 5280 §6.1)

- **Requirement:** implementations may bound the length of an acceptable
  certification path.
- **Ours:** depth is bounded by `X509_STORE_CTX_set_depth` when a caller
  configures a limit (`gsi_verify.c:195-197`), mapping to nginx
  `ssl_verify_depth`. CHN-099/100/111/112 (2/4/5/8 intermediates → accept),
  CHN-101 (14 intermediates → reject when over the configured depth).
- **XRootD v6.1.0:** bounds the *total* chain size via the optional
  `vopt->pathlen` ceiling (`XrdCryptoX509Chain.cc:706-711`); when unset (`-1`)
  there is no depth limit. Comparable mechanism, config-dependent on both sides.
- **Verdict:** Conformant (config-dependent). CHN-099..101, CHN-111, CHN-112.

### Structural failures & signature integrity (RFC 5280 §6.1.3, X.690)

- **Requirement:** a tampered signature, a truncated/unparseable certificate, a
  self-signed leaf presented as an EEC, a wrong (untrusted) issuer, or an issuer
  DN collision with a mismatched signing key MUST all fail path validation.
- **Ours:** `X509_verify_cert()` (plus DER parse before the wire) rejects all of
  these. CHN-102 (tampered signatureValue → reject), CHN-103 (truncated DER,
  c-oracle surface → reject), CHN-049 (wrong issuer not in store → reject),
  CHN-050 (self-signed leaf → reject), CHN-106 (issuer DN collision, rogue
  signing key → reject), CHN-104/105 (cross-signed intermediate resolvable via
  either root A or B → accept).
- **XRootD v6.1.0:** rejects a bad signature (`kVerifyFail` from `X509_verify()`,
  `XrdCryptoX509Chain.cc:833-836`), an inconsistent/unenchainable set
  (`kInconsistent`/`Reorder` returns −1, `:690-693`), and a missing CA
  (`kNoCA`/`CheckCA`, `:716-719`). Aligned on structural integrity.
- **Verdict:** Conformant. CHN-102..106, CHN-049, CHN-050.

### Shared limitation — subject-hash CApath collisions

- **Requirement:** §6.1 path construction should consider every candidate
  issuer, including CAs that share a subject-name hash.
- **Ours:** we build the `X509_STORE` from a hashed CApath
  (`pki_build.c:172-178`, `X509_STORE_load_path`). OpenSSL's builder selects the
  first `<hash>.0` slot and does not retry sibling `<hash>.1/.2` slots when the
  signature mismatches. Recorded in `_decisions.py` CAD-019/020 as a
  dependency-inherent LIMITATION; real IGTF trust stores have no subject-hash
  collisions.
- **XRootD v6.1.0:** its `FindSubject` name-based reorder
  (`XrdCryptoX509Chain.cc`) likewise resolves a single same-name issuer and does
  not exhaustively try colliding anchors. Shared limitation.
- **Verdict:** Documented-limitation (shared). CAD-019, CAD-020.

### Shared limitation — DN encoding normalization

- **Requirement:** RFC 5280 §7.1 defines encoding-independent name comparison
  (e.g. BMPString ≡ UTF8String); RFC 4518 defines LDAP space-folding.
- **Ours:** DN comparison for signing_policy uses the `X509_NAME_oneline`
  rendering (`brix_x509_oneline`, `store_policy.c:48-71`) with a raw
  case-insensitive string match; encoding-independent equality and RFC 4518
  space-folding are not implemented. Recorded in `_decisions.py` DNE-003/005/006
  /028 as a LIMITATION shared with XRootD.
- **XRootD v6.1.0:** compares DN strings byte-wise (`XrdCryptoX509Chain.cc:622`
  `FindSubject`; render via `XrdCryptosslAux.cc:736-746`), likewise with no
  encoding normalization.
- **Verdict:** Documented-limitation (shared). DNE-003, DNE-005, DNE-006,
  DNE-028.

---

## Divergence summary

| Aspect | Ours | XRootD v6.1.0 | Verdict | Tests |
|---|---|---|---|---|
| Path validation engine | OpenSSL `X509_verify_cert` + IGTF policy layer (`gsi_verify.c:199`) | Hand-rolled walk, raw `X509_verify` per link (`XrdCryptoX509Chain.cc:833`) | — | — |
| AKID/SKID issuer selection | Advisory: name-match issuer accepted on AKID mismatch (`store_policy.c:548-573`) | Subject-name/hash selection, AKID ignored (`XrdCryptoX509Chain.cc:576`) | Conformant | CHN-043..046, CHN-119 |
| basicConstraints cA flag | Enforced (OpenSSL) | Enforced via cert type (`XrdCryptosslX509.cc:353`) | Conformant | CHN-001..004, CHN-017 |
| basicConstraints pathLen | Enforced (OpenSSL) | Not enforced (only proxy pcPathLen + global size) | Stricter-than-XRootD | CHN-005..016, CHN-107/108/110 |
| keyUsage keyCertSign (CA) | Enforced (OpenSSL) | Not checked | Stricter-than-XRootD | CHN-024, CHN-028, CHN-109 |
| Leaf keyUsage/EKU (client auth) | TLS-layer SSL_CLIENT + `brix_leaf_purpose_violation` (`store_policy.c:459`) | Not checked in GSI engine | Stricter-than-XRootD | CHN-018..042, CHN-113..118 |
| Validity windows | Enforced (OpenSSL) | Enforced `IsValid` w/ notBefore skew (`XrdCryptoX509.cc:105`) | Conformant | CHN-051..062, CHN-122..124/134 |
| MD5/SHA-1 signature policy | Rejected on every cert (`store_policy.c:423-433`) | Accepted (raw verify, no alg policy) | Stricter-than-XRootD | CHN-072/073/075/076/078/132 |
| Key-size floor RSA≥2048/EC≥256 | Rejected below floor (`store_policy.c:409-421`) | Not checked | Stricter-than-XRootD | CHN-083/084/088/094 |
| Serial positive + ≤20 octets | Enforced, proxy-exempt (`store_policy.c:435-448`) | Not checked (display/CRL only) | Stricter-than-XRootD | CHN-063..068 |
| DN control/NUL bytes | Rejected (`store_policy.c:384-401`) | Not screened | Stricter-than-XRootD | — |
| Unknown critical extension | Rejected (OpenSSL) | Not rejected | Stricter-than-XRootD | CHN-095/097/120 |
| Chain depth | `X509_STORE_CTX_set_depth` (`gsi_verify.c:195`) | Global `vopt->pathlen` ceiling | Conformant (config) | CHN-099..101, CHN-111/112 |
| Structural integrity (tamper/truncate/wrong-issuer) | Rejected (OpenSSL + parse) | Rejected (`kVerifyFail`/`kInconsistent`/`kNoCA`) | Conformant | CHN-102..106, CHN-049/050 |
| Subject-hash CApath collision | First-slot only (OpenSSL) | First-name only | Documented-limitation (shared) | CAD-019/020 |
| DN encoding normalization | oneline raw match (`store_policy.c:48-71`) | Byte-wise match | Documented-limitation (shared) | DNE-003/005/006/028 |
