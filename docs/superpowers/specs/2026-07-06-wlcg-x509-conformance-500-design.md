# WLCG X.509 Security-Stack Conformance at Scale — Design Spec

**Date:** 2026-07-06
**Status:** Approved design, pending implementation plan(s)
**Owner:** Rob Currie
**Builds on:** [2026-07-06-wlcg-x509-conformance-design.md](2026-07-06-wlcg-x509-conformance-design.md) (the ~100-check first pass, LANDED)

## 1. Goal

Two deliverables:

1. **500+ conformance tests** across the full WLCG X.509 security stack, every
   test indexed to a specific normative clause (RFC 5280, RFC 3820, RFC 5755,
   the IGTF classic-profile store layout, the Globus EACL `signing_policy`
   grammar). Valid and violating cases are symmetric per clause.
2. **A source-level conformance write-up** — a doc set that, per component,
   states the normative requirement, cites **our** implementation
   (`src/…:line`), cites the **official XRootD v6.1.0** implementation
   (`/tmp/xrootd-src/src/XrdCrypto*`, `XrdSecgsi*`, `XrdHttp*`, `XrdTls*`:line),
   and tabulates the divergences with the test IDs that pin each one.

Correctness is **spec-first**. XRootD is the comparison target, not the
reference; where both diverge from a standard, that is itself a finding.

### Gap stance (decided)

**Fix every gap the tests expose.** The target is 500+ green with **zero
xfails on our side**. Where a deviation is inherent to a dependency (e.g.
OpenSSL `X509_STORE_load_path` looking CAs up only by the new SHA-1 hash), we
implement a targeted fix in our layer (pre-index the CA dir / load by cert
rather than relying on hash-name lookup) rather than declaring it unfixable.
Any deviation that genuinely cannot be closed without replacing a dependency's
core behavior is called out explicitly in the write-up with the reason — but
the presumption is that we close it.

### Reference material (confirmed present)

- Full XRootD **v6.1.0** source at `/tmp/xrootd-src` (git, tag `v6.1.0`).
  Key files: `XrdSecgsi/XrdSecProtocolgsi.cc` (GSI protocol, CA/CRL load,
  proxy handling, VOMS callback), `XrdSecgsi/XrdSecgsiProxy.cc` (proxyCertInfo
  / pathlen), `XrdCrypto/XrdCryptoX509Chain.cc` + `XrdCryptogsiX509Chain.cc`
  (chain `Verify()`), `XrdCrypto/XrdCryptosslX509.cc`,
  `XrdCrypto/XrdCryptosslX509Crl.cc` (CRL), `XrdCrypto/XrdCryptosslgsiAux.cc`
  (GSI crypto aux), `XrdSecgsi/XrdSecgsiGMAPFunDN.cc` (DN mapping),
  `XrdHttp/XrdHttpProtocol.cc` + `XrdHttpSecXtractor.hh` (XrdHttp cert auth),
  `XrdTls/XrdTlsContext.cc`. Running binary: v5.9.5 (differential).

### Non-goals

- No new wire protocol work; the module's verification code is the subject.
- We do not modify OpenSSL; we constrain/augment its behavior in our layer.
- Not a fuzzing campaign — cases are curated per clause, not randomly generated
  (a fuzz harness may be a later effort).

## 2. Test taxonomy (≥500, clause-indexed)

Each test carries `{id, clause, title, expected, surface, group}` where
`clause` is a normative citation (e.g. `RFC5280 §4.2.1.9`), `expected` ∈
{accept, reject}, `surface` ∈ {davs, root, c-oracle, config}, `group` names the
server config it runs against (§4).

| Family | ID prefix | ~N | Normative basis |
|---|---|---|---|
| Chain / PKIX | `CHN` | 120 | RFC 5280 §4.1–4.2, §6 |
| Proxy | `PXY` | 120 | RFC 3820 |
| signing_policy / EACL | `SPL` | 90 | Globus EACL, IGTF |
| CRL / revocation | `CRL` | 80 | RFC 5280 §5 |
| CA-directory | `CAD` | 40 | IGTF store layout |
| VOMS / AC | `VMS` | 30 | RFC 5755, VOMS AC |
| DN / encoding | `DNE` | 20 | RFC 4514, RFC 5280 §4.1.2.4/6 |

Per-family clause coverage (representative, not exhaustive — the plan enumerates
each ID):

- **CHN** — basicConstraints (CA:TRUE/FALSE, pathLenConstraint 0/1/N/exceeded,
  criticality), keyUsage (keyCertSign / cRLSign / digitalSignature presence &
  criticality), extendedKeyUsage (clientAuth / serverAuth / anyEKU / absent),
  authority/subject key identifier match & mismatch, validity (expired,
  not-yet-valid, notBefore>notAfter), serial (zero, negative, huge), signature
  algorithm (SHA-256/384/512 accept; SHA-1 policy-gated; MD5 reject), key
  type/size (RSA 1024 reject / 2048 / 4096, EC P-256 / P-384; DSA), unknown
  **critical** extension → reject, unknown non-critical → accept, chain depth
  limits, self-signed leaf, intermediate CA chains, cross-signed dual path,
  wrong-issuer, tampered signature.
- **PXY** — RFC 3820 impersonation (`1.3.6.1.5.5.7.21.1`), independent
  (`.21.2`), limited (Globus `1.3.6.1.4.1.3536.1.1.1.9`); proxyCertInfo
  criticality (critical accept / non-critical reject); pcPathLenConstraint
  (absent, 0 forbids further delegation, N with decrement, exceeded → reject);
  legacy GT2 (`CN=proxy`) / GT3 / limited (`CN=limited proxy`); EEC keyUsage
  digitalSignature required to sign a proxy; proxy carrying CA:TRUE / SAN /
  keyCertSign → reject; proxy notAfter beyond EEC; delegation depth 1..N;
  monotonicity (limited→full reject); mixed legacy-below-RFC3820 → reject.
- **SPL** — grammar (comment/blank/CRLF, single vs double quoting, multi-block,
  `pos_rights` variants, `neg_rights` grants-nothing, `cond_subjects` forms,
  unknown directive → fail-closed, truncated → fail-closed); glob (`*` crossing
  `/`, `?` single, case-insensitive, anchoring, empty glob, multiple globs,
  literal `*`/`/` in DN value); DN matching (RDN order, UTF8String vs
  PrintableString equivalence, escaping); discovery (new/old hash names,
  symlink, missing → mode-dependent, wrong-CA block → fail-closed, multiple
  policy files); modes (on/off/require × present/absent).
- **CRL** — revoked EEC / revoked intermediate; CRL validity (thisUpdate future,
  nextUpdate past = expired, not-yet-valid); signature (correct / wrong signer /
  bad sig); issuer scope mismatch; delta CRL (base+delta, USE_DELTAS); r0 + r1
  two CRLs; CRL number monotonicity; reason codes (keyCompromise,
  removeFromCRL); un-revocation via reload; hash naming (`.r0`/`.r1`); modes
  (off/try/require × absent/present/expired/revoked).
- **CAD** — hash links (new-only, old-only, both, none, collision two CAs same
  hash), symlinks (valid, dangling), junk files ignored, bundle-file vs dir
  parity, expired CA in dir, reload add/remove CA, huge dir (many CAs).
- **VMS** — FQAN parse (VO/Group/Role/Capability), AC validity (valid, expired,
  not-yet-valid), tampered AC signature, AC on wrong chain level, VO-name
  sanitization (comma, slash, backslash, control, newline, non-ASCII, DEL,
  empty), lsc/vomsdir presence.
- **DNE** — oneline canonicalization traps, embedded `/` and `*` in RDN values,
  empty DN, multi-valued RDN, BMPString/T61String/UTF8String equivalence,
  very long DN, duplicate RDNs.

## 3. Fixture forge v2 — declarative, clause-indexed

Refactor `tests/x509forge.py` into a **table-driven** generator without
breaking the existing scenario functions (they become thin adapters or are
migrated). A `CLAUSES` registry holds one row per test:

```python
Clause(id="CHN-042", clause="RFC5280 §4.2.1.9",
       title="pathLenConstraint=0 forbids a subordinate CA",
       build=lambda f: ...,           # returns (ca_dir_key, credential, ...)
       expected="reject", surface="davs", group="sp_off_crl_off")
```

New builder capabilities on top of v1: EC keypairs (P-256/384), selectable
signature digest, **raw-DER DN** encoding (choose UTF8String / PrintableString /
BMPString / T61String per RDN, embedded specials), nameConstraints, EKU sets,
arbitrary unknown extensions with a criticality flag, delta CRLs, CRL reason
codes and CRL numbers, cross-signed pairs.

**Output layout** (materialized once):

- `shared/ca/` — the **big multi-CA directory**: every "normal" test CA cert +
  both hash links + `<hash>.signing_policy` + `<hash>.r0/.r1`. Mirrors a real
  `/etc/grid-security/certificates` with hundreds of entries.
- `special/<name>/ca/` — dirs that need a pathological store state
  (md5_only, sha1_only, expired_ca, absent_ca, hash_collision, bundle).
- `creds/<id>.pem` — one credential (leaf-first chain + key) per test.
- `manifest.json` — 500+ rows: `{id, clause, title, cred, expected, surface,
  group, reason}`. Single source of truth for every consumer.

Determinism: fixed epoch (no `Date.now()`); validity windows are relative to it.

## 4. The vehicle — a fixed conformance fleet stood up once

Per the chosen approach, we **do not** stand up a server per case. A
session-scoped fixture (`tests/wlcg_conformance_fleet.py`) stands up a small,
fixed set of long-lived servers and dispatches all 500 credentials to them:

- **Config-group servers on `shared/ca/`** — one nginx per distinct
  `(signing_policy_mode, crl_mode, ca-form)` a test needs, e.g.
  `sp_on_crl_off`, `sp_off_crl_off`, `sp_require_crl_off`, `sp_on_crl_try`,
  `sp_on_crl_require`, `sp_off_crl_try`. (~6)
- **Special-dir servers** — one per `special/<name>` dir. (~6)
- Total ≈ 12–15 nginx servers, each on its own port, started once. Running 500
  `curl --cert` PROBES against pre-stood servers is ~1–2 min.

The manifest's `group` field selects the target server; `surface` selects the
mechanism:

- `surface=davs` → curl client-cert PROPFIND against the group server (2xx =
  accept). **Primary — exercises the real production path.**
- `surface=c-oracle` → the C oracle (below), for credentials that OpenSSL
  rejects *before* the wire (malformed DER, disallowed key) or pure
  parser/glob unit cases. The oracle links our **real** ngx-free cores.
- `surface=config` → `nginx -t` assertion (e.g. require+bundle).
- `surface=root` → reserved; see §7 scope note (root:// GSI proxy wire).

**C oracle** (`tests/c/x509_oracle.c`): links `signing_policy.c`,
`store_policy.c`, `brix_proxy_chain_ok`, and a small shared **store-config
helper** extracted from `pki_build.c` so the oracle builds the store with the
*exact* flags/callbacks production uses (this extraction is itself a small
de-duplication win). Reads the manifest, runs every `c-oracle` (and, for
cross-check, every `davs`) case, asserts against `expected`. Fast enough to run
the whole 500 in CI in seconds.

**Differential fleet**: the same server matrix stood up with stock XRootD
(XrdHttp) — `xrd.port` off 1094, one instance per group/special dir. The
differential replays all `davs`-surface cases and records ours/xrootd/spec.
Best-effort and skip-clean (v1 mechanics, scaled).

## 5. Source-level write-up — `docs/10-reference/conformance/`

A doc set (not one file):

- `README.md` — overview + the **master clause matrix**: one row per clause
  (or clause-group), columns *normative summary · our behavior · XRootD
  behavior · test IDs · verdict (conformant / divergent / stricter / gap)*.
  Plus a verdict rollup and a "how the suite is organized" section.
- Seven deep dives, one per component:
  `proxy-rfc3820.md`, `crl-revocation.md`, `signing-policy-eacl.md`,
  `chain-building-rfc5280.md`, `dn-encoding.md`, `voms.md`, `tls-xrdhttp.md`.
  Each dive is structured: **(a)** the normative requirement (quoted/cited);
  **(b)** our implementation with `src/…:line`; **(c)** XRootD's with
  `/tmp/xrootd-src/…:line`; **(d)** a divergence table; **(e)** the pinning
  test IDs.
- `differential-findings.md` — the generated ours/xrootd/spec matrix (the v1
  file, relocated here and expanded to the full set).

The write-up is authored from **reading the XRootD source** (v6.1.0), not from
behavior alone; the differential corroborates the behavioral half.

## 6. Execution model (workflows + parallel agents — approved)

The effort decomposes into phases; several fan out cleanly:

- **P0 Infrastructure** (sequential): forge v2 core + `CLAUSES` registry +
  store-config helper extraction + conformance fleet + C oracle skeleton.
- **P1 Test families** (parallel): seven families generated concurrently — each
  agent owns one family's `CLAUSES` rows + any builder extensions it needs.
  A merge/dedup step reconciles the shared forge.
- **P2 Gap closure** (mostly sequential, some parallel): run the suite, triage
  every reject/accept mismatch, implement fixes until zero xfails. Adversarial
  verification of each fix (a fix must not loosen another case).
- **P3 XRootD source analysis** (parallel): seven agents each read one XRootD
  component and draft its deep-dive `(c)`/`(d)` sections; a synthesis agent
  writes `README.md` + the master matrix.
- **P4 Differential + finalize** (sequential): full differential run, findings
  regen, suite tiering, CI wiring, final verification.

Writing-plans will emit **one plan per phase** (P1 possibly one plan per family
given the volume), since each phase yields independently testable software.

## 7. Constraints & standards (Global)

- NO `goto`; functional/modular; WHAT/WHY/HOW blocks; new `.c` files in
  `./config`; `export REPO=…` before `./configure` (bare-nginx footgun).
- Every new source file added to the build; incremental `make` otherwise.
- Forge determinism (fixed epoch); manifest is the single truth.
- Fleet interaction: pre-stood conformance fleet is **owned by this suite**
  (its own ports/prefixes), independent of the shared dev fleet; attach-don't-
  wipe still honored for the dev fleet.
- New pytest marker `x509conf` already registered; scale under it, tier the
  heavy fleet run as `slow`/`nightly`.

### Scope note — root:// GSI proxy on the wire

Proxy (`PXY`) conformance is enforced by the same shared verifier both surfaces
use, but WebDAV refuses proxy chains, so proxy cases run via the **C oracle**
(`brix_proxy_chain_ok` + full chain build) against the exact forged chains the
wire would see, and a curated subset also runs **root:// GSI** if a GSI proxy
client harness is stood up in P0; otherwise root:// proxy wire coverage is
documented as oracle-backed. This is the one area where wire coverage may be
oracle-substituted; it is called out in the write-up.

## 8. Acceptance criteria

1. ≥500 distinct, clause-indexed conformance cases; **zero xfails on our
   side**; every case cites a normative clause in the manifest.
2. Every family (CHN/PXY/SPL/CRL/CAD/VMS/DNE) present at ≥ its §2 target.
3. Conformance fleet stands up ≤ ~15 servers once and runs the full set in a
   few minutes; C oracle runs the full set in seconds.
4. All gaps surfaced are **fixed** (or, if dependency-inherent and truly
   unfixable, explicitly justified in the write-up — expected to be none or
   near-none).
5. Write-up doc set complete: overview + master matrix + seven source-level
   deep dives (each citing our code AND XRootD v6.1.0 code AND the standard) +
   generated differential findings.
6. Differential run executed against stock XRootD; divergence rows recorded.
7. No regression: first-pass suite + existing suite stay green; build + `nginx
   -t` clean.

## 9. Risks & mitigations

- **"Fix every gap" scope creep** → triage each gap by security impact first;
  fix in priority order; a gap that is purely cosmetic still gets fixed but is
  scheduled last. The zero-xfail bar is the definition of done.
- **OpenSSL-inherent behaviors** (hash-name lookup, algorithm policy) → fix in
  our layer (pre-index CA dir; explicit sig-alg/key policy gate) rather than
  bending OpenSSL.
- **Forge merge conflicts across parallel family agents** → each family writes
  its own `CLAUSES` module (`tests/clauses/<family>.py`); the forge imports and
  concatenates; no shared-file contention.
- **XRootD source drift (v6.1.0 vs running v5.9.5)** → the write-up cites
  v6.1.0 source; the differential notes the running version; discrepancies
  between the two are themselves noted.
- **Fleet port pressure** (~15 nginx + ~15 xrootd) → dedicated ephemeral port
  block; the differential fleet is opt-in and torn down after.
