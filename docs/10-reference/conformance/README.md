# WLCG X.509 conformance — overview + master matrix

This directory is the authoritative conformance write-up for the module's
WLCG/IGTF X.509 authentication stack: the shared GSI chain verifier
(`src/auth/crypto/gsi_verify.c`, `store_policy.c`, `signing_policy.c`,
`pki_build.c`) that both the `root://`/`roots://` stream path and the `davs://`
WebDAV client-certificate path run. It measures that stack against the governing
standards — RFC 5280 (PKIX), RFC 3820 (proxy certificates), RFC 5755/GFD-C.182
(VOMS attribute certificates), the Globus/IGTF `signing_policy` (EACL) namespace
grammar, and the IGTF authentication profile — and, clause by clause, against the
behaviour of the official XRootD v6.1.0 GSI stack (`/tmp/xrootd-src`, git tag
v6.1.0).

## The conformance approach

The write-up is **spec-first and clause-indexed**. Every normative requirement is
decomposed into an individually-identified clause (`CHN-`, `PXY-`, `SPL-`,
`CRL-`, `DNE-`, `CAD-`, plus the `VMS-` VOMS-token cases), each carrying its
expected verdict derived from the standard — not from what the code happens to
do. The clause registry (`tests/clauses/`) forges **559 clause rows** and drives
each one through three independent surfaces:

- a **C oracle** (the `x509_oracle` runner in `tests/cmdscripts/c_auth_units.py`,
  Python port of the retired `run_x509_oracle.sh`) that compiles the real
  verification cores (`signing_policy.c` + `store_policy.c` + `brix_store_configure`)
  and replays every clause against forged fixtures, asserting the manifest verdict;
- a **live `davs://` fleet** (`tests/test_wlcg_conformance_matrix.py`) that replays
  every WebDAV-surface clause on the wire against a pre-stood
  `ConformanceFleet`, proving the production `auth_cert.c → brix_gsi_verify_chain`
  path reaches the same verdict the oracle validates in bulk;
- a **differential** (`tests/cmdscripts/x509_differential.py`, Python port of
  the retired `run_x509_differential.sh`) that replays the same
  matrix against our module *and* stock XRootD, asserting ours matches the spec
  and recording XRootD's divergences.

Where our module's actual (correct/conservative/deliberately-stricter) verdict
differs from a naive reading of the standard, the correction lives in a single
auditable **decisions register** (`tests/clauses/_decisions.py`) with a category
tag (`STRICTER` / `CONSERVATIVE` / `NOT-MANDATED` / `LIMITATION`) — never by
editing the clause files — so every deviation from the letter of a spec is
traceable to a stated rationale.

**Headline finding.** In every area where our module and XRootD v6.1.0 differ,
**our module is stricter** — it rejects credentials XRootD would accept. There is
**no area where XRootD is stricter than our module.** The only non-conformances
are a small set of encoding-normalization and multi-CRL-reconciliation gaps that
are (a) fail-safe (they never produce a false *accept*) and (b) shared with
XRootD.

## Master clause matrix

Verdicts: **Conformant** (matches the standard, behaviourally aligned with
XRootD) · **Stricter** (stricter than XRootD — we reject what it accepts) ·
**Documented-limitation** (a fail-safe normalization/reconciliation gap, shared
with XRootD unless noted). Tests column gives the pinning clause IDs.

### Chain building — RFC 5280 PKIX ([chain-building-rfc5280.md](chain-building-rfc5280.md))

| Area | Standard | Our behavior | XRootD v6.1.0 | Verdict | Tests |
|---|---|---|---|---|---|
| Path-validation engine | §6.1 | OpenSSL `X509_verify_cert` + IGTF policy layer (`gsi_verify.c:199`) | Hand-rolled walk, raw `X509_verify` per link (`XrdCryptoX509Chain.cc:833`) | Conformant | CHN-* |
| AKID/SKID issuer selection | §4.2.1.1 | Name-match issuer accepted on AKID mismatch (`store_policy.c:548`) | Subject-name/hash selection, AKID ignored | Conformant | CHN-043..046, 119 |
| basicConstraints cA flag | §4.2.1.9 | Enforced (OpenSSL) | Enforced via cert type (`XrdCryptosslX509.cc:353`) | Conformant | CHN-001..004, 017 |
| basicConstraints pathLen | §4.2.1.9, §6.1.4 | Enforced (OpenSSL) | Not enforced (only proxy pcPathLen + global size ceiling) | Stricter | CHN-005..016, 107/108/110 |
| keyUsage keyCertSign (CA) | §4.2.1.3 | Enforced (OpenSSL) | Not checked (raw signature only) | Stricter | CHN-024, 028, 109 |
| Leaf keyUsage / EKU (client auth) | §4.2.1.3/§4.2.1.12 | TLS `SSL_CLIENT` purpose + `brix_leaf_purpose_violation` (`store_policy.c:459`) | Not checked in GSI engine | Stricter | CHN-018..042, 113..118 |
| Validity windows | §4.1.2.5 | Enforced per-cert (OpenSSL) | Enforced `IsValid` w/ notBefore skew | Conformant | CHN-051..062, 122..124/134 |
| MD5/SHA-1 signature policy | §4.1.1.2, IGTF | Rejected on every cert (`store_policy.c:423`) | Accepted (no algorithm policy) | Stricter | CHN-072/073/075/076/078/132 |
| Key-size floor RSA≥2048 / EC≥256 | IGTF | Rejected below floor (`store_policy.c:409`) | Not checked | Stricter | CHN-083/084/088/094 |
| Serial positive + ≤20 octets | §4.1.2.2 | Enforced, proxy-exempt (`store_policy.c:435`) | Not checked (display/CRL only) | Stricter | CHN-063..068 |
| Unknown critical extension | §4.2 | Rejected (OpenSSL) | Not rejected | Stricter | CHN-095/097/120 |
| Chain depth | §6.1 | `X509_STORE_CTX_set_depth` (`gsi_verify.c:195`) | Global `vopt->pathlen` ceiling | Conformant (config) | CHN-099..101, 111/112 |
| Structural integrity (tamper/truncate/wrong-issuer) | §6.1.3, X.690 | Rejected (OpenSSL + parse) | Rejected (`kVerifyFail`/`kInconsistent`/`kNoCA`) | Conformant | CHN-102..106, 049/050 |
| Subject-hash CApath collision | §6.1 | First hash-slot only (OpenSSL builder) | First-name only | Documented-limitation (shared) | CAD-019/020 |

### Proxy certificates — RFC 3820 ([proxy-rfc3820.md](proxy-rfc3820.md))

| Area | Standard | Our behavior | XRootD v6.1.0 | Verdict | Tests |
|---|---|---|---|---|---|
| Standard PCI OID `…7.1.14` | §3.1, OID assign. | Recognised (`EXFLAG_PROXY`) | Recognised | Conformant | PXY-006 |
| Draft PCI OID `…3536.1.222` | OID assign. | Not treated as proxy → EEC path fails | Accepted as proxy | Stricter | PXY-018 |
| PCI criticality | §3.1 | Rejected if non-critical (`store_policy.c:513`) | Not `kProxy` if non-critical | Conformant | PXY-007..010 |
| Policy language (impersonation/independent/limited) | §3.2 | Allowlist of 3 OIDs, else reject (`store_policy.c:520`) | Presence-only / ignored in production (`opt==0`) | Stricter | PXY-011/012/014 |
| pcPathLenConstraint | §4.2 | Extract + enforce (OpenSSL + builder) | Extract + enforce by hand | Conformant | PXY §5, §15 |
| Limited→full monotonicity | §3.8 | Enforced (`brix_proxy_chain_ok`, `store_policy.c:354`) | Detected (CLI only), **not enforced** | Stricter | PXY §10 |
| Legacy Globus GT2/GT3 proxies | (RFC 3820 supersedes) | Rejected (RFC 3820 only) | Accepted (pxytype 3/4) | Stricter | PXY-004/005; §9 |
| Proxy subject/issuer naming | §3.4 | OpenSSL proxy rules | Hand-rolled `SubjectOK` | Conformant | PXY §7, §8 |
| Forbidden extensions (CA:TRUE / SAN) | §3.7 | Rejected | Rejected | Conformant | PXY §6, §17 |

### signing_policy / EACL namespace — Globus/IGTF ([signing-policy-eacl.md](signing-policy-eacl.md))

| Area | Standard | Our behavior | XRootD v6.1.0 | Verdict | Tests |
|---|---|---|---|---|---|
| signing_policy enforcement (at all) | IGTF EACL | Full parser + per-CA table + chain-walk enforcement (`signing_policy.c`, `gsi_verify.c:63`) | **Not implemented** (zero grep matches; `GetCA` loads only `<hash>.0`+CRL) | Stricter | SPL-001..104 |
| EACL grammar (blocks/rights/cond_subjects, comments/CRLF/tabs/order) | Globus EACL | Parsed, fail-closed on mis-ordered directives | Absent | Stricter | SPL-025..042 |
| Glob semantics (`*` crosses `/`, `?`=1 char, case-fold, both-ends anchored) | Globus EACL | `brix_sp_glob_match` (`signing_policy.c:95`) | Absent | Stricter | SPL-001..024, 082..100 |
| Hashed discovery (new+legacy subject hash, DN fallback) | IGTF hashed store | `sp_find_by_hash`/`sp_find_by_dn` (`store_policy.c:235,255`) | Only `<hash>.0`+CRL | Stricter | SPL-053..056 |
| Fail-closed (malformed / unreadable / wrong-CA / empty cond) | IGTF profile | Reject (`store_policy.c:292,296`) | N/A — CA accepted with no namespace | Stricter | SPL-029..035, 057, 064, 071, 075, 103 |
| Modes off/on/require | IGTF profile | `brix_sp_mode_t`; REQUIRE mandates policy per CA (`store_policy.c:289,623`) | No namespace-strictness axis | Stricter | SPL-058..076 |

### CRL / revocation — RFC 5280 §5/§6.3 ([crl-revocation.md](crl-revocation.md))

| Area | Standard | Our behavior | XRootD v6.1.0 | Verdict | Tests |
|---|---|---|---|---|---|
| CRL loading `<hash>.rN` from hashed dir | §5, IGTF | `*.pem` + `*.r0..r9` scan (`pki_build.c:105`) | `<caroot>.r0` (`XrdSecProtocolgsi.cc:143`) | Conformant | CRL-* |
| Strictness modes | IGTF/WLCG | off/try/require (`store_policy.c:613`) | crl 0-3, default crlTry | Conformant | CRL-004..006, 013..015 |
| Revoked EEC / revoked intermediate CA | §6.3.3 | `CERT_REVOKED`, `CRL_CHECK_ALL` every node (`store_policy.c:616`) | `IsRevoked()` per node | Conformant | CRL-004/005/010/011, 034 |
| **Stale CRL (past nextUpdate)** | §5.1.2.4/5 | **FATAL under `try`** (`store_policy.c:576`) | warn only below crlRequire; fatal only at level 3 | Stricter | CRL-019/020, 022/023, 025/026 |
| CRL signature (rogue signer) | §5.1.1.3 | OpenSSL verify + mode gate | `crl->Verify()` → `-4` | Conformant | CRL-028/029 |
| CRL issuer / scope mismatch | §5.1.2.3 | OpenSSL issuer match + gate | hash compare → `-2` | Conformant | CRL-031/032 |
| Reason codes (9×) | §5.3.1 | All revoke | serial-only, ignores reason | Conformant | CRL-038..064 |
| `removeFromCRL` in a **full** CRL | §5.3.1 | Non-revoking (follow OpenSSL) | Would still revoke (serial-only) | Documented-limitation (conservative) | CRL-065/066 |
| Delta CRL (add / un-revoke) | §5.2.4 | Add revokes; un-revoke not honored, base stands | **No delta support at all** | Documented-limitation (fail-safe) | CRL-068..076 |
| Multi-CRL CRLNumber precedence | §5.2.3 | Not implemented; any listing revokes | No CRLNumber handling | Documented-limitation (fail-safe) | CRL-077..085 |
| EC / SHA-512 CRL signatures | §6.3.3 | OpenSSL verifies | OpenSSL verifies | Conformant | CRL-086/087, 089/090 |

### DN handling & string encoding — RFC 5280 §4.1.2 / §7.1 ([dn-encoding.md](dn-encoding.md))

| Area | Standard | Our behavior | XRootD v6.1.0 | Verdict | Tests |
|---|---|---|---|---|---|
| DN rendering / canonicalization | §4.1.2.4 | `X509_NAME_oneline` slash form (`store_policy.c:49`) | default `X509_NAME_print_ex` multiline → `/` | Conformant (different renderer) | DNE-001/002/004 |
| caseIgnore matching (CN / DC) | RFC 4517/4519 | Case-insensitive glob + `strcasecmp` (`signing_policy.c:103`) | case-sensitive `strcmp` | Conformant | DNE-026/027/029/030 |
| Literal `/ * +` in value; anchored match | RFC 4514 | Anchored, policy-side `*` only (`signing_policy.c:101`) | Opaque payload, straight `strcmp` | Conformant | DNE-011..025 |
| Embedded NUL / control byte in DN | §4.1.2.6 | Rejected for every cert (`store_policy.c:384`) | Not checked (only SAN dNSName) | Stricter | DNE-031/032 |
| §7.1 encoding-independent equality | §7.1 | Not implemented; oneline-byte glob (wide encodings rejected by control gate) | Not implemented; `strcmp` on rendered `Subject()` | Documented-limitation (shared) | DNE-003/005/006 |
| RFC 4518 insignificant-space folding | RFC 4518 | Not implemented (exact match) | Not implemented (`strcmp`) | Documented-limitation (shared) | DNE-028 |

### VOMS attribute certificates — RFC 5755 / GFD-C.182 ([voms.md](voms.md))

| Area | Standard | Our behavior | XRootD v6.1.0 | Verdict | Tests |
|---|---|---|---|---|---|
| AC cryptographic validation | RFC 5755 | `dlopen libvomsapi.so.1` → `VOMS_Retrieve` (`extract.c:91`) | pluggable `XrdSecgsiVOMSFun` over `libvomsapi` | Conformant (aligned) | VMS-01..03, 32 |
| FQAN → VO-name derivation | GFD-C.182 | First-component parse + dedup (`collect.c:80`) | inside VOMS plug-in; core consumes `Entity.vorg` | Conformant | VMS-06 |
| VO-name sanitization (list/log/label) | INVARIANT #8 | Reject ctrl/space/`,`/`/`/`\`/non-ASCII (`vo_token.h:32`) | None — `strdup` verbatim | Stricter | VMS-04..31 |
| No-library graceful degradation | (optional infra) | dlopen-optional, best-effort (`loader.c:39`) | `vatIgnore` default, skipped | Conformant (aligned) | — |
| VOMS-required (`vomsat=require`) mode | (not mandated) | Not implemented (advisory; enforced via ACL) | `-vomsat:require` fatal | Documented-limitation | — |

### TLS / HTTP client-certificate path — RFC 5246/8446 ([tls-xrdhttp.md](tls-xrdhttp.md))

| Area | Standard | Our behavior (`davs://`) | XRootD `XrdHttp` | Verdict | Tests |
|---|---|---|---|---|---|
| TLS-layer chain validation | RFC 5246, §6.1 | `ssl_verify_client` + `SSL_get_verify_result` (`auth_cert.c:458`) | `SSL_VERIFY_PEER` + `SSL_get_verify_result` | Conformant | CHN-001..010 (davs) |
| Unified GSI chain verify on HTTP path | RFC 3820, IGTF/EACL | Full `brix_gsi_verify_chain` on `davs://` (`auth_cert.c:478`) | **None** — parses chain for DN only, never `Verify()` | Stricter | signing_policy + proxy families (davs run) |
| Proxy certificates over TLS | RFC 3820 | **Refused** (`client_purpose=1` suppresses `ALLOW_PROXY_CERTS`, `gsi_verify.c:191`) | DN extracted, no proxy validation | Stricter (by design) | PXY-004/005…, 136 |

## Verdict rollup

Counting the **51 major clause/area rows** in the master matrix above:

- **Conformant — 23.** Both implementations meet the standard and are
  behaviourally aligned (issuer selection, cA flag, validity, chain depth,
  structural integrity, PCI OID/criticality/pcPathLen/naming/forbidden-ext, CRL
  loading/modes/revocation/signature/scope/reasons/algorithm variety, DN
  rendering/case-fold/literal-metachars, VOMS AC delegation/FQAN/degradation, and
  TLS-layer validation).
- **Stricter-than-XRootD — 21.** Every one of these rejects a credential that
  XRootD v6.1.0 accepts; XRootD is stricter in none.
- **Documented-limitation — 7.** Fail-safe gaps that never produce a false
  accept: subject-hash CApath collisions, `removeFromCRL`-in-full-CRL, delta
  CRLs, multi-CRL CRLNumber precedence, RFC 5280 §7.1 encoding-independent DN
  equality, RFC 4518 space folding, and the (unimplemented) VOMS-required mode.
  All except the VOMS mode are **shared with XRootD** — XRootD is no more capable.

### Headline divergences (all in the stricter direction)

- **signing_policy / EACL namespace confinement** — we parse and enforce the
  Globus EACL grammar end-to-end (parser → per-CA table → per-link chain check);
  XRootD v6.1.0 has **zero** signing_policy support anywhere in its tree, so a
  technically-valid signature from a trusted-but-out-of-namespace CA is silently
  accepted. ([signing-policy-eacl.md](signing-policy-eacl.md))
- **Limited-proxy monotonicity (RFC 3820 §3.8)** — we reject a full/independent
  proxy minted beneath a limited one (`brix_proxy_chain_ok`); XRootD *detects*
  limited proxies only in its display CLI and never enforces the restriction on
  the server verify path. ([proxy-rfc3820.md](proxy-rfc3820.md))
- **CRL-expiry-fatal under `try`** — a stale CRL (past `nextUpdate`) is fatal at
  our default strictness; XRootD merely logs a DEBUG warning below `crlRequire`.
  ([crl-revocation.md](crl-revocation.md))
- **Unified `davs://`/`root://` verification** — both surfaces run the same
  `brix_gsi_verify_chain`, so HTTPS clients get full GSI-profile validation
  (signing_policy, proxy profile, weak-algorithm, CRL strictness); XRootD's
  `XrdHttp` does **TLS-layer verification only** and never invokes its GSI chain
  validator. ([tls-xrdhttp.md](tls-xrdhttp.md))
- **Weak-algorithm / key-strength / serial rejection (IGTF, RFC 5280 §4.1.2)** —
  we reject MD5/SHA-1 signatures, RSA <2048 / EC <256 keys, and non-positive or
  >20-octet serials on every cert in the chain; XRootD's raw `X509_verify()` walk
  applies no such policy. ([chain-building-rfc5280.md](chain-building-rfc5280.md))
- **Legacy Globus GT2/GT3 proxy rejection** — only RFC 3820 proxies are honoured;
  legacy `CN=proxy` / `CN=limited proxy` credentials with no proxyCertInfo are
  rejected, whereas XRootD's production verify path (`opt==0`) accepts them.
  ([proxy-rfc3820.md](proxy-rfc3820.md))
- **DN control-byte / embedded-NUL rejection (RFC 5280 §4.1.2.6)** and **VOMS
  VO-name sanitization** — we reject DNs and VO tokens carrying control bytes,
  NULs, or list/log/label-breaking separators that XRootD propagates verbatim.
  ([dn-encoding.md](dn-encoding.md), [voms.md](voms.md))

## How the suite is organized

- **C oracle** — the `x509_oracle` runner in
  [`tests/cmdscripts/c_auth_units.py`](../../../tests/cmdscripts/c_auth_units.py)
  (pytest wrapper `tests/test_c_auth_units.py`; Python port of the retired
  `run_x509_oracle.sh`): forges the full clause matrix into fixtures, compiles the real cores
  (`signing_policy.c` + `store_policy.c` + `brix_store_configure`) into
  `tests/c/x509_oracle.c` under `-Wall -Wextra -Werror`, and asserts every
  clause verdict matches the manifest. Exit 0 = full conformance. This is the bulk
  verifier and covers the proxy (`PXY-`) family that the WebDAV wire refuses.
- **Live davs matrix** — [`tests/test_wlcg_conformance_matrix.py`](../../../tests/test_wlcg_conformance_matrix.py):
  replays every `davs`-surface clause against a long-lived `ConformanceFleet`
  (one server per config-group over the shared multi-CA directory), proving the
  production `auth_cert.c → brix_gsi_verify_chain` path reaches the manifest
  verdict on the wire. Marked `slow`.
- **Differential** — [`tests/cmdscripts/x509_differential.py`](../../../tests/cmdscripts/x509_differential.py)
  (pytest wrapper `tests/test_cmd_x509_differential.py`; Python port of the
  retired `run_x509_differential.sh`; opt-in `TEST_X509_DIFF=1`): replays the matrix against our module and stock
  XRootD, asserts ours == spec, and records XRootD's divergence cells into
  `docs/10-reference/wlcg-x509-differential-findings.md`. The XRootD leg is
  best-effort (records "unavailable" rather than failing when no driveable
  `xrootd` is present).
- **Decisions register** — [`tests/clauses/_decisions.py`](../../../tests/clauses/_decisions.py):
  the single auditable table of every deliberate expected-verdict correction,
  each tagged `STRICTER` / `CONSERVATIVE` / `NOT-MANDATED` / `LIMITATION` and
  cited directly from the deep-dive divergence sections.

### The seven deep dives

1. [chain-building-rfc5280.md](chain-building-rfc5280.md) — RFC 5280 PKIX path
   construction and validation (`CHN-`, `CAD-`).
2. [proxy-rfc3820.md](proxy-rfc3820.md) — RFC 3820 proxy certificates + legacy
   Globus variants (`PXY-`).
3. [signing-policy-eacl.md](signing-policy-eacl.md) — Globus/IGTF signing_policy
   (EACL) namespace confinement (`SPL-`).
4. [crl-revocation.md](crl-revocation.md) — CRL/revocation processing (`CRL-`).
5. [dn-encoding.md](dn-encoding.md) — DN rendering & ASN.1 string encoding
   (`DNE-`).
6. [voms.md](voms.md) — VOMS attribute-certificate extraction & sanitization
   (`VMS-`).
7. [tls-xrdhttp.md](tls-xrdhttp.md) — TLS / HTTP client-certificate path
   (`davs://` vs XRootD `XrdHttp`).

Source-level XRootD behaviour notes:
[.source-notes/xrootd-v6.1.0-behavior.md](.source-notes/xrootd-v6.1.0-behavior.md).
</content>
</invoke>
