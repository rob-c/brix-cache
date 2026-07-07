# WLCG X.509 / CA-Directory Conformance — Standards, Methodology, and Results

**Scope:** This document is the authoritative reference for the WLCG X.509 /
grid-PKI conformance test suite in `nginx-xrootd`. It records **every
specification, profile, trust-federation policy, and convention the X.509
credential path has been tested to conform to**, the methodology, the test
families and their standard-to-test mappings, and the conformance results —
including the differential evidence where the implementation is demonstrably
*more* conformant than stock XRootD.

Companion to the bearer-token document
[`wlcg-token-conformance-standards.md`](wlcg-token-conformance-standards.md);
together they cover the two authentication planes of the module.

**Suite at a glance**

| Metric | Value |
|---|---|
| Total conformance cases | **559** (master clause matrix) + a standalone C-unit foundation (~42–51 checks) |
| Test layers | 3 (C-unit oracle, live-`davs://` wire, opt-in differential-vs-stock-XRootD) |
| Surfaces exercised | `davs://` (mutual-TLS client cert, shares the verifier with `root://` GSI), plus the C oracle and config-startup surfaces |
| Config-group server profiles | 7 (`signing_policy` × `crl_mode` combinations + bundle) |
| Fixture forge | `tests/x509forge.py` (~1000 lines) — hostile PKI scenario trees + a Clause-indexed v2 registry |
| Differential result | **3 real stock-XrdHttp divergences found** (stock accepts out-of-namespace, wrong-CA-policy, and revoked certs where this module rejects) |
| Standards conformed to | RFC 5280, RFC 3820, RFC 5755, RFC 6960, Globus EACL, IGTF profiles, OpenSSL CA-dir convention, TLS |

---

## 1. Methodology: spec-first conformance

The suite is **specification-first**: correctness is defined by RFC 5280,
RFC 3820, the IGTF Authentication Profiles, and the Globus EACL `signing_policy`
grammar — **not** by the behaviour of any reference implementation. Stock XRootD
(its `XrdHttp` / GSI client-cert path) is used only as an optional *comparison
target*; where stock XRootD diverges from a specification the divergence is
recorded as a finding, never copied. The suite carries **no `xfail`s on the
module's side** — every case asserts the specification-mandated verdict and the
module meets it.

For each testable normative requirement the forge materializes a **conforming**
and a **violating** PKI artefact (certificate, CRL, proxy chain, or CA-directory
layout) and asserts the mandated `accept`/`reject`. A single `manifest.json`
(the forge's master clause matrix, 559 entries) is the source of truth consumed
by all three layers, so a verdict can never drift between the C oracle and the
wire.

---

## 2. Normative sources tested against

### 2.1 IETF Standards (RFCs)

| Standard | Title | What it governs here | Where tested |
|---|---|---|---|
| **RFC 5280** | Internet X.509 PKI Certificate and CRL Profile | Chain building and PKIX path validation; certificate validity windows; `keyUsage` (`digitalSignature`, `keyCertSign`); `extendedKeyUsage` (`clientAuth`/`anyExtendedKeyUsage`); `basicConstraints` (CA:TRUE/FALSE, pathlen); serial-number limits (≤20 octets, no NUL bytes in DN); CRL structure, `nextUpdate`, revocation, and delta-CRL indicators | CHN, CRL, per-cert policy (`brix_cert_policy_violation`, `brix_leaf_purpose_violation`) |
| **RFC 3820** | Internet X.509 PKI Proxy Certificate Profile | Proxy certificates: the `proxyCertInfo` (PCI) extension **must be critical**; recognized policy-language OIDs (`1.3.6.1.5.5.7.21.1` impersonation / `.21.2` independent / Globus limited `1.3.6.1.4.1.3536.1.1.1.9`); path-length delegation limits; and the **§3.8 monotonicity rule** — a full proxy must not appear beneath a limited proxy | PXY (proxy classification + monotonicity) |
| **RFC 5755** | An Internet Attribute Certificate Profile for Authorization | VOMS attribute certificates (VO/group/role FQANs) carried as X.509 ACs | VMS / VOMS boundary (via `libvomsapi`, on the `root://` surface) |
| **RFC 6960** | X.509 Internet PKI Online Certificate Status Protocol (OCSP) | Real-time revocation status | *Out of scope* beyond not regressing the existing optional OCSP path (design non-goal) |
| **RFC 5246 / RFC 8446** | TLS 1.2 / TLS 1.3 | The mutual-TLS transport that carries the client certificate on the `davs://` surface — the X.509 credential is the client-authentication side of the TLS handshake | the `davs://` wire surface (all e2e families) |

### 2.2 Trust-federation profiles and grid conventions

| Source | What it governs here | Where tested |
|---|---|---|
| **Globus EACL `signing_policy` grammar** — the Extended Access Control List format (`access_id_CA X509 '<DN>'`, `pos_rights globus CA:sign`, `cond_subjects globus '"<glob>" ...'`, `neg_rights`) | The operative WLCG mechanism binding each trust-anchor CA to the namespace of subject DNs it may sign. Glob semantics: `*` matches any run **including `/`**, `?` matches one char, case-insensitive; DN canonicalized to OpenSSL oneline slash form by one shared helper (`brix_x509_oneline`) so the policy side and cert side cannot diverge | SPL family; `signing_policy_unittest.c` grammar checks |
| **IGTF Authentication Profiles** (International Grid Trust Federation — Classic / MICS / SLCS) | CA and end-entity cryptographic requirements: RSA key ≥ 2048 bits (EC ≥ 256), and no MD5/SHA-1 signatures on modern certificates | per-cert policy checks (`brix_cert_policy_violation`); DNE/CHN families |
| **EUGridPMA `.namespaces` (EACL) format** | The EUGridPMA-flavoured namespace file | *Explicitly not implemented* (design non-goal) — `signing_policy` is the operative mechanism, matching Globus/XRootD behaviour; documented, tested by its absence |
| **OpenSSL hashed CA-directory convention** | `<subject_hash>.0`/`.1` CA links, `<hash>.r0` CRLs, `<hash>.signing_policy` policy files, and the dual **new-SHA-1** + **legacy-MD5** (`subject_hash_old`) hash-link scheme | CAD family (SHA-1-only / MD5-only / both / collision `.0`+`.1` / junk-file / dangling-symlink / bundle-file layouts) |
| **VOMS** (Virtual Organization Membership Service) | VO attribute assertion via signed ACs; VO-name sanitisation | VMS boundary; `vo_token` safety predicate |

### 2.3 Security research and lineage (test-case foundations)

| Foundation | Threat | Cases derived |
|---|---|---|
| MD5 collision → **rogue CA certificate** (Sotirov, Stevens, Appelbaum, Lenstra, Molnar, Osvik, de Weger, *"MD5 considered harmful today,"* 2008) | A forged CA cert via chosen-prefix MD5 collision | Rejection of MD5-signed certificates; the forge mints MD5/SHA-1/SHA-256+ signature variants |
| Weak / undersized RSA keys (512–768-bit factorability; the Debian OpenSSL entropy defect) | Signature forgery against small keys | RSA/EC key-size floors (`≥2048`/`≥256`); the forge mints 512/768/1024-bit keys |
| Grid Security Infrastructure proxy-delegation model (Foster, Kesselman, Tsudik, Tuecke) and its RFC 3820 codification | Privilege escalation via proxy delegation (a limited proxy issuing a full proxy) | PXY monotonicity (`brix_proxy_chain_ok`, RFC 3820 §3.8) |
| Namespace-confinement bypass (a trusted CA signing outside its authorised namespace) | Cross-CA impersonation | SPL out-of-namespace / wrong-CA-block rejection — the exact class the differential found stock XRootD accepting |

---

## 3. Suite architecture (three layers)

**Layer 1 — C unit / oracle** (`tests/c/signing_policy_unittest.c`,
`tests/c/x509_conformance_test.c`; ~42 checks, plus the `vo_token` predicate
checks). Links the `ngx`-free crypto core (`signing_policy.c`, `store_policy.c`,
and the shared `brix_store_configure` extracted for exactly this purpose) as a
standalone binary. It asserts the EACL grammar/matcher with malformed-input
precision (glob-crossing-`/`, case folding, CRLF+comments, single-vs-double-quoted
globs, multi-block isolation, fail-closed on truncated/unknown/`neg_rights`),
and drives the **real verifier** over forge-built fixture trees: signing-policy
decisions, chain building (expired anchor, valid-under-CA), CRL revocation with
`CRL_CHECK` flags, proxy classification + RFC 3820 §3.8 monotonicity, and the
per-cert policy gates.

**Layer 2 — live-`davs://` wire** (`tests/test_wlcg_conformance_*.py`; 6 files,
driving the 559-clause matrix). Real mutual-TLS PROPFIND handshakes against a
running fleet with custom CA directories, `signing_policy` files, and CRLs. The
`davs://` surface shares the verifier (`brix_gsi_verify_chain`) with `root://`
GSI, so a verdict here proves both. A `2xx` is `accept`, an auth failure is
`reject`. Helpers: `WlcgInstance` (a standalone instance with a bespoke CA dir)
and `ConformanceFleet` (7 long-lived servers, one per config-group, dispatched by
the manifest's `group` field) for the bulk matrix run. Hot-reload cases use the
timer-driven trust-store rebuild rather than a restart.

**Layer 3 — differential vs stock XRootD** (`tests/run_x509_differential.sh`,
`tests/x509_differential.py`, opt-in `TEST_X509_DIFF=1`). For each `davs://`
scenario it captures `{ours, xrootd, spec}`, asserts `ours == spec` (hard
failure on any mismatch), and records `xrootd != spec` divergences — without
failing — into `docs/10-reference/wlcg-x509-differential-findings.md`. Skips
cleanly when no stock `xrootd` binary is present.

### 3.1 The fixture forge (`tests/x509forge.py`)

A ~1000-line hostile-PKI generator on the `cryptography` package with a
raw-DER escape hatch for extensions the library refuses to emit (e.g. a
non-critical `proxyCertInfo`). It materializes complete hashed CA directories and
credential chains, and its **v2 Clause registry** indexes every case to a spec
clause with an `expected` verdict and a `surface`, emitting `manifest.json` /
`manifest.tsv`. Hostile artefacts include: wrong/absent `keyUsage`, `CA:FALSE`
intermediates and `CA:TRUE` proxies, bogus policy OIDs, pathlen violations,
MD5-signed and weak-key certs, UTF8String-vs-PrintableString DN encodings and
`/`/`*` embedded in RDN values, CRLs with past `nextUpdate` / wrong issuer / bad
signature / delta indicators, expired CAs, MD5-only vs SHA-1-only hash links,
hash-collision `.0`+`.1` layouts, bundle-file mode, dangling symlinks, and junk
files.

---

## 4. Test families

Case-ID families and their standard mappings (the 559-clause master matrix plus
the C-unit foundation).

| Family | ~N | Standards | Coverage |
|---|---|---|---|
| **SPL** signing_policy | 104 | Globus EACL; IGTF namespace confinement | In/out-of-namespace enforcement, EACL grammar variants, wrong-CA block fail-closed, proxy-CN exemption, `on`/`require`/`off` modes, policy hot-reload |
| **PXY** proxy | 136 | RFC 3820 | Full/limited/legacy classification, critical-PCI requirement, recognized-policy-OID requirement, pathlen delegation, **limited→full escalation rejection (§3.8)**, non-critical-PCI reject |
| **CRL** revocation | 94 | RFC 5280 | Revoked EEC/intermediate reject, expired CRL, wrong-issuer/bad-signature CRL, delta-CRL, un-revocation via reload, `off`/`try`/`require` modes |
| **CAD** CA-directory | 52 | OpenSSL CA-dir convention | SHA-1-only / MD5-only / both / duplicate-hash `.0`+`.1` / dangling-symlink / junk-file / expired-CA / bundle-file / `require`+bundle-error / add-remove-via-reload |
| **CHN** chain building | 135 | RFC 5280 | PKIX path building, `keyCertSign`, `CA:FALSE` intermediate, pathlen, depth, expired intermediate, valid-under-valid-CA controls |
| **DNE** DN encoding | 32 | RFC 5280 §4.1.2; IGTF | UTF8String vs PrintableString equivalence, escaped RDN values, embedded `/` and `*` in DN components |
| **SMK / VMS** VOMS | 6 | RFC 5755; VOMS | VO-name sanitisation and AC boundary bytes |
| **RT** runtime | (in matrix) | operational | Trust-store rebuild under live load preserves valid creds, applies revocation, and fails closed on a malformed policy appearing mid-reload |

Per-cert conformance gates applied by `brix_gsi_verify_chain` across all
families: RSA ≥ 2048 / EC ≥ 256 (IGTF), no MD5/SHA-1 signatures (IGTF / MD5-collision
lineage), serial ≤ 20 octets and no NUL in DN (RFC 5280), and leaf `clientAuth`
EKU + `digitalSignature` keyUsage (RFC 5280).

---

## 5. Conformance results

### 5.1 Directives and enforcement

| Directive | Modes | Default | Semantics |
|---|---|---|---|
| `brix_signing_policy` (+ `brix_webdav_signing_policy`) | `off` \| `on` \| `require` | **on** | `off`: never read; `on`: enforce EACL when a `<hash>.signing_policy` is present (backward-compatible — a CA with no policy validates by chain only); `require`: a policy file is mandatory per CA |
| `brix_crl_mode` (+ `brix_webdav_crl_mode`) | `off` \| `try` \| `require` | **try** | `off`: no CRL flags; `try`: `CRL_CHECK_ALL` with a callback that tolerates a missing CRL but rejects a stale/expired one; `require`: missing/expired/unverifiable CRL is fatal |

Enforcement lives in the **single shared verifier** `brix_gsi_verify_chain`
(`gsi_verify.c`), so it covers `root://` GSI **and** `davs://` client certs
identically; the same store-build path is used by the origin client
(`sd_xroot.c`), pinned to safe modes. The `crl_mode` default of `try` is a
deliberate, documented behaviour change from the old implicit
"require-when-any-CRL-loaded" rule; `require` restores the stricter behaviour.

### 5.2 Confirmed conformant behaviours

- **Namespace confinement** (Globus EACL): a trust-anchor CA signing a subject
  outside its `cond_subjects` globs is rejected on both surfaces; wrong-CA-block
  and malformed policy fail closed.
- **RFC 3820 proxy monotonicity**: a full proxy issued beneath a limited proxy is
  rejected; non-critical or unrecognized `proxyCertInfo` is rejected.
- **CRL strictness** is pinned in all three `crl_mode`s, including expired /
  missing / delta-CRL corners and un-revocation via hot reload.
- **CA-directory mechanics**: dual SHA-1/MD5 hash links, collisions, bundle-mode
  parity, and junk-file tolerance behave per the OpenSSL convention.
- **Per-cert IGTF/RFC-5280 gates**: undersized keys, MD5/SHA-1 signatures,
  over-long serials, and missing leaf EKU/keyUsage are all rejected.

### 5.3 Differential evidence — the module is *more* conformant than stock

The opt-in differential tier asserted `ours == spec` for every scenario and
recorded **three cases where stock XRootD/XrdHttp diverges from the
specification** in its baseline CA-directory configuration:

| Scenario | Spec | This module | Stock XRootD |
|---|---|---|---|
| CA signs **out of its namespace** (Globus EACL) | reject | **reject** | **accept** ⚠ |
| EEC under a **wrong-CA `signing_policy` block** | reject | **reject** | **accept** ⚠ |
| **Revoked** EEC (CRL present) | reject | **reject** | **accept** ⚠ |

These are recorded (not failed) in
[`wlcg-x509-differential-findings.md`](wlcg-x509-differential-findings.md) as
upstream-behaviour evidence.

### 5.4 Documented deviations / non-goals

- **EUGridPMA `.namespaces`** enforcement is intentionally not implemented
  (`signing_policy` is the operative WLCG mechanism, matching Globus/XRootD).
- **OCSP** is out of scope beyond not regressing the existing optional path.
- **VOMS AC** validation is unchanged (via `libvomsapi`, `root://` surface).
- An **MD5-only** CA hash link is not found by OpenSSL's new-SHA-1 `X509_STORE`
  lookup and therefore rejected — a documented interaction, not a bug (WLCG ships
  both hash links).

---

## 6. Running / reproducing

```bash
# Layer 1 — C unit / oracle (fast, no fleet)
tests/run_x509_conformance.sh        # (or the per-binary runners)

# Layer 2 — live davs:// wire matrix (needs the fleet)
PYTHONPATH=tests pytest tests/test_wlcg_conformance_*.py -v

# Layer 3 — differential vs stock XRootD (opt-in)
TEST_X509_DIFF=1 tests/run_x509_differential.sh
```

**Build note:** a new source file requires `export REPO=<repo>` **before**
`./configure --add-module=$REPO` — an unexported `REPO=... ./configure` expands
empty in the parent shell and silently builds a module-less nginx.

---

## 7. Companion documents

- [`wlcg-token-conformance-standards.md`](wlcg-token-conformance-standards.md) — the bearer-token (JWT/SciTokens) plane.
- [`wlcg-x509-differential-findings.md`](wlcg-x509-differential-findings.md) — the generated Layer-3 findings golden file.
- [`../superpowers/specs/2026-07-06-wlcg-x509-conformance-design.md`](../superpowers/specs/2026-07-06-wlcg-x509-conformance-design.md) — the design spec.
- `src/auth/crypto/signing_policy.{c,h}`, `store_policy.{c,h}`, `gsi_verify.c`, `pki_build.c` — the implementation.

---

## Appendix A — Glossary

- **EEC** End-Entity Certificate (a user/host cert, as opposed to a CA or proxy).
- **Proxy certificate** a short-lived cert an EEC issues to delegate its identity (RFC 3820); a **limited** proxy restricts what it may do.
- **`proxyCertInfo` (PCI)** the RFC 3820 extension marking a cert as a proxy and carrying its policy language.
- **EACL / `signing_policy`** the Globus Extended Access Control List binding a CA to the DN namespace it may sign.
- **Hashed CA directory** OpenSSL's `X509_STORE` layout: CA certs and CRLs symlinked by subject hash (`<hash>.0`, `<hash>.r0`), with legacy MD5 (`subject_hash_old`) links alongside new SHA-1 links.
- **IGTF** International Grid Trust Federation — the body whose Authentication Profiles set CA cryptographic requirements.
- **VOMS** Virtual Organization Membership Service — issues X.509 attribute certificates (RFC 5755) asserting VO/group/role membership.
- **`davs://`** WebDAV-over-HTTPS; here it carries the mutual-TLS client certificate and shares the GSI verifier with `root://`.
