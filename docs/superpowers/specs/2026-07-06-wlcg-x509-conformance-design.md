# WLCG X.509 / CA-Directory Conformance — Design Spec

**Date:** 2026-07-06
**Status:** Approved design, pending implementation plan
**Owner:** Rob Currie

## 1. Goal

Make the module's X.509 handling conform to the WLCG/IGTF CA-directory trust
model, and build a ~120-case conformance suite that actively hunts for
corner-case mistakes in cert/CRL/proxy/signing-policy handling. Correctness is
defined **spec-first** (RFC 5280, RFC 3820, the IGTF profile, the Globus EACL
signing_policy grammar); stock XRootD is a *comparison target*, not the
reference. Divergences found in XRootD are recorded as findings, not copied.

### Non-goals

- `.namespaces` (EUGridPMA format) enforcement — `signing_policy` is the
  operative WLCG mechanism; `.namespaces` stays unread (as in Globus/XRootD).
- OCSP changes — the existing optional OCSP path (`src/auth/crypto/ocsp.c`)
  is out of scope beyond not regressing it.
- Replacing libvomsapi AC validation with our own AC parser.

## 2. Background — current state (audited 2026-07-06)

What already conforms:

| Aspect | Where |
|---|---|
| Hashed CA dir OR bundle, auto-detected via stat() | `src/auth/gsi/config.c:28` → `brix_build_ca_store()` (`src/auth/crypto/pki_build.c:185`) |
| Grid CRL naming `*.r[0-9]` + `*.pem`, CRL_CHECK\|CRL_CHECK_ALL\|USE_DELTAS when any CRL loads | `pki_build.c:156,247` |
| Hot trust-store rebuild on timer (`brix_crl_reload`) | `src/core/config/process.c:40` |
| RFC 3820 proxy chains: critical proxyCertInfo, pathlen extract+decrement, ALLOW_PROXY_CERTS | `src/auth/gsi/proxy_req.c`, `src/auth/crypto/gsi_verify.c:46` |
| One shared verifier + X509_STORE across root:// and davs:// | `gsi_verify.c`, `webdav/auth_cert.c` |
| VOMS AC extraction via dlopen'd libvomsapi, VO-name sanitization | `src/auth/voms/` |
| Non-fatal startup CA↔CRL consistency audit | `src/auth/crypto/pki_check.c:135` |

Gaps this effort closes:

1. **`<hash>.signing_policy` files are never read.** The test PKI even writes
   them (`tests/pki_helpers.py:86`), but no code enforces the EACL — a
   trusted CA signing outside its namespace is accepted today.
2. **No limited-proxy semantics.** Legacy `CN=limited proxy` and the Globus
   limited-policy OID are treated as ordinary proxies; nothing prevents a
   limited proxy from issuing a full proxy (RFC 3820 §3.8 violation).
3. **CRL strictness is ambiguous.** Behavior flips from "no checking" to
   "CRL required for every CA" based solely on whether *any* CRL file loaded.
   No operator knob pins the intent.
4. **Untested corners:** delta CRLs (flag set, zero coverage), MD5-only hash
   links, expired-CRL behavior, hash collisions, revocation via hot reload —
   the test PKI has never generated a CRL containing a revoked cert.

## 3. Implementation

### 3.1 signing_policy engine — `src/auth/crypto/signing_policy.{c,h}`

Pure C, ngx-free (standalone-testable like the guard/tap cores; allocation via
caller-supplied malloc/free hooks, logging via a callback — same pattern as
`src/net/guard/`).

**Grammar accepted** (Globus EACL subset actually used by IGTF
distributions):

```
# comment lines and blank lines ignored
access_id_CA      X509    '<CA subject DN, slash form>'
pos_rights        globus  CA:sign
cond_subjects     globus  '"<glob>" "<glob>" ...'
```

- A file may contain multiple blocks; each `access_id_CA` line opens a new
  block. Only blocks whose `access_id_CA` DN matches the actual CA subject
  apply.
- `cond_subjects` value: single-quoted string containing whitespace-separated
  double-quoted globs; a single unquoted glob (no inner double quotes) is also
  accepted (both forms appear in real IGTF files).
- `neg_rights` lines are parsed and cause the block to grant nothing.
- Glob semantics: `*` matches any run of characters **including `/`**
  (Globus behavior); `?` matches one character. Matching is
  **case-insensitive**.
- DN canonical form for matching: OpenSSL oneline slash form
  (`/C=UK/O=eScience/...`), produced by one shared helper so the policy side
  and the cert side can never diverge in escaping.

**Compiled representation:** at store-build time
(`brix_build_ca_store()` and every timer rebuild), each CA in the directory
gets a `brix_signing_policy_t` — matched CA DN + array of globs — held in a
table keyed by CA subject hash, owned by the same lifetime as the
`X509_STORE`.

**Enforcement point:** after `X509_verify_cert()` succeeds, in
`brix_gsi_verify_chain()` (and thus shared by root:// GSI and davs:// client
certs): walk the verified chain; for every certificate whose issuer is a
trust-anchor CA from the directory, the certificate's subject DN must match
that CA's `cond_subjects` globs. Proxy certificates are exempt (their issuer
is the EEC/parent proxy, not a trust-anchor) — i.e. the policy binds the
**EEC and intermediate CAs**, never proxy `CN=` suffixes. Sub-CA certs are
checked against the *issuing* CA's policy (each link independently).

**Failure semantics (fail closed):**

- Malformed policy file → that CA's certs are rejected at verify time; one
  WARN per load naming the file and the parse error line.
- Policy file present but contains no block matching the CA's DN → reject
  (a policy that names the wrong CA is a misconfiguration, not an absence).
- Unreadable file (EACCES, dangling symlink) → treated as malformed.

**Directive:** `brix_signing_policy on|off|require`, default **on**, on the
shared trust-store configuration (one knob; root:// and davs:// share the
store). Semantics:

| Mode | `<hash>.signing_policy` present | absent |
|---|---|---|
| `on` (default) | enforced | chain validation only (today's behavior) |
| `require` | enforced | CA rejected |
| `off` | ignored | ignored |

Policy files are looked up in the CA directory by both new (SHA-1 canonical)
and old (MD5) hash names, mirroring OpenSSL's dual-hash link convention. When
`brix_trusted_ca` points at a bundle *file*, `on` degrades to `off` (no
directory to search) and `require` is a config-time error.

### 3.2 Proxy tightening — `src/auth/crypto/gsi_verify.c` + chain walk

- **Classification:** each proxy in the chain is classified as
  RFC 3820 (critical proxyCertInfo, policy OID `1.3.6.1.5.5.7.21.1`
  impersonation / `.21.2` independent / Globus limited OID
  `1.3.6.1.4.1.3536.1.1.1.9`), legacy Globus (`CN=proxy` /
  `CN=limited proxy`, no proxyCertInfo), or invalid.
- **Monotonicity:** once a limited proxy appears, every subsequent proxy must
  also be limited; a full proxy issued by a limited one → reject.
- **Authn policy:** limited proxies still authenticate (matches XRootD);
  classification is exposed on the auth context so future authz can consume
  it. No new directive — this is spec enforcement, not policy.
- Mixed legacy/RFC-3820 chains: legacy segment may not appear *below* an
  RFC 3820 proxy (Globus rule); reject.

### 3.3 CRL strictness — `brix_crl_mode off|try|require`

Default **`try`** (XRootD-parity: "use CRLs where available").

| Mode | Behavior |
|---|---|
| `off` | no CRL flags set even if CRL files load (they still load for `/healthz` audit) |
| `try` | CRL_CHECK_ALL set; a verify callback downgrades `X509_V_ERR_UNABLE_TO_GET_CRL` (missing CRL for a CA) to accept-with-INFO. Expired CRL (`nextUpdate` past) for a CA that *has* one → reject (a stale CRL is evidence, not absence) |
| `require` | CRL_CHECK_ALL, nothing downgraded: missing, expired, or unverifiable CRL → reject |

This is a **behavior change** from today's implicit rule ("any CRL loaded ⇒
require for all CAs"). Migration note in docs; sites wanting the old
effective-strictness set `require`. `USE_DELTAS` stays set in all non-off
modes and gains test coverage.

### 3.4 Config surface

New shared-trust-store fields on the common conf
(`src/core/config/config.h` + `directives.c` merge, per the standard recipe):
`signing_policy_mode`, `crl_mode`. Both stream (`directives_auth.inc`) and
WebDAV (`webdav/module.c`) directive tables reference the same setters.
No `./configure` rerun needed except for the new source files added to
`./config` (`signing_policy.c`, plus test binaries).

## 4. Fixture forge — `tests/x509forge.py`

Python library on the `cryptography` package, with a raw-DER escape hatch
(hand-built TLVs appended as extensions / substituted signatures) for
artifacts `cryptography` refuses to emit. New test-only dependency;
documented in `tests/README` alongside the existing pytest deps.

- **Scenario trees:** `forge.scenario("name")` materializes a complete hashed
  CA directory under the session tmpdir — CA certs with **both** SHA-1 and
  MD5 hash links, `.signing_policy`, `.r0`/`.r1` CRLs — plus client
  credentials (EEC, proxy chains) and a `manifest.json`.
- **Manifest:** every scenario records
  `{scenario, credential, expected: accept|reject, expected_reason, spec_ref}`.
  The manifest is the single source of truth consumed by all three layers, so
  a verdict can never drift between the C tier and the wire tier.
- **Hostile artifact catalog (forge capabilities):** wrong/absent
  keyUsage, CA:FALSE intermediates, non-critical proxyCertInfo, bogus policy
  OIDs, pathlen violations, MD5-signed certs, 512-bit keys, UTF8String vs
  PrintableString DN encodings, duplicate RDNs, `/` and `*` inside RDN
  values, CRLs with past `nextUpdate` / wrong issuer / bad signature / delta
  indicators, expired CAs, hash-collision link layouts, junk files in the CA
  dir.
- Existing `tests/pki_helpers.py` is untouched; existing suites unaffected.

## 5. Test suite (~120 cases, three layers)

Naming: `SP-*` signing_policy, `PX-*` proxy, `CRL-*` revocation, `CAD-*`
CA-dir mechanics, `CHN-*` chain building, `VMS-*` VOMS, `RT-*` runtime.
Every case ID appears in the manifest and in the test name.

### Layer 1 — C unit (fast, malformed-input precision)

- `tests/c/signing_policy_unittest.c` — links `signing_policy.c` standalone
  (ngx-free). ~30 grammar/matching cases (SP-01…SP-30): comments/whitespace/
  quoting variants, multi-block files, wrong-CA blocks, `neg_rights`,
  single-vs-double-quoted globs, glob-crossing-`/`, case folding, RDN-order
  sensitivity, UTF8String≡PrintableString equivalence, `/` embedded in RDN
  value, empty `cond_subjects`, truncated file, CRLF files, >4k lines,
  fail-closed on every malformed shape.
- `tests/c/x509_conformance_test.c` — links the verifier the way
  `tests/c/gsi_interop_test.c` does; loads forge-written fixture trees by
  path (forge invoked once by the test runner script). ~35 cases covering
  CHN-01…CHN-15 (AKID/SKID mismatch, cross-signed dual path, CA:FALSE
  intermediate, missing keyCertSign, depth limit, MD5-signed cert, weak key,
  self-signed leaf, expired intermediate…) and the C-reachable halves of
  PX-* and CRL-*.

### Layer 2 — pytest e2e (`tests/test_wlcg_conformance_*.py`)

Real handshakes against a live fleet on **both** surfaces — every scenario
runs as root:// GSI *and* davs:// client-cert unless inherently
single-surface. Scenario groups share a CA-dir layout to bound fleet
restarts; hot-reload cases use `brix_crl_reload` instead of restarting.

- `test_wlcg_conformance_signing_policy.py` — SP enforcement on the wire
  (~15): out-of-namespace EEC rejected on both surfaces, in-namespace
  accepted, `require` vs `on` vs `off`, sub-CA outside parent's namespace,
  proxy-CN exemption, policy hot-reload after edit.
- `test_wlcg_conformance_proxy.py` — PX-01…PX-25: RFC 3820 accept matrix,
  limited-proxy authn, limited→full escalation reject, legacy Globus proxy,
  legacy-below-RFC3820 reject, pathlen-0 delegation reject, proxy with
  CA:TRUE / SAN / bogus OID, expired proxy on valid EEC, proxy outliving EEC,
  non-critical PCI.
- `test_wlcg_conformance_crl.py` — CRL-01…CRL-20: revoked EEC / revoked
  intermediate rejected, un-revocation via reload, expired CRL per mode,
  missing CRL per mode, wrong-issuer CRL, bad-signature CRL, delta CRL
  honored, `.r1` second CRL, malformed CRL file non-fatal at startup but
  correct at verify time.
- `test_wlcg_conformance_cadir.py` — CAD-01…CAD-15: MD5-only links,
  SHA1-only links, `.0`+`.1` duplicate-hash CAs, dangling symlink, junk
  files ignored, expired CA rejected, CA added/removed via hot reload,
  bundle-file mode parity, `require`+bundle config error.
- `test_wlcg_conformance_voms.py` — VMS-01…VMS-08: valid AC FQANs, expired
  AC, tampered AC signature, AC on wrong chain level, hostile VO names
  rejected by sanitizer, libvomsapi-absent graceful degradation.
- `test_wlcg_conformance_runtime.py` — RT-01…RT-07: store rebuild under
  live load (no dropped in-flight requests), corrupt CRL appearing
  mid-reload keeps old store serving, reload-interval revocation latency
  bound.

### Layer 3 — differential vs stock XRootD (opt-in, `TEST_X509_DIFF=1`)

`tests/run_x509_differential.sh`: for each manifest scenario, point a stock
`xrootd` (gsi auth, same CA dir, `-crl`/policy options mapped per mode) at
the scenario tree, attempt the same credential, record
`{ours, xrootd, spec}` verdicts.

- **Asserts:** `ours == spec` (any mismatch is a suite failure — same truth
  as layers 1–2).
- **Reports:** `xrootd != spec` divergences are *recorded, not failed* into
  generated `docs/10-reference/wlcg-x509-differential-findings.md` (verdict
  table + repro command per finding) — the upstream-bug evidence file.
- Skips cleanly when no `xrootd` binary is present (`BRIX_BIN`-style
  override honored, per the load-test bridge convention).

### Suite integration

Wire-level tests are pytest-marked `x509conf`; the family joins the standard
tiers (fast subset in `--pr`, full in `--nightly` per the existing
slow-marker convention). C tests get `tests/run_x509_conformance.sh`
mirroring `run_cvmfs_core_unit.sh`. Fleet interaction follows the
attach-don't-wipe conftest rule; scenarios needing their own CA dir use
`TEST_OWN_FLEET=1` serial mode.

## 6. Documentation

- `docs/09-developer-guide/wlcg-ca-conformance.md` — the trust model as
  implemented: directive semantics tables (§3.1, §3.3), supported EACL
  grammar, limited-proxy rules, migration note for the CRL default change,
  how to run each suite layer, how to regenerate the differential findings.
- Directive reference entries in `docs/03-configuration/quick-reference.md`.
- Generated findings file under `docs/10-reference/` (checked in after each
  differential run, reviewed like a golden file).

## 7. Acceptance criteria

1. ≥120 distinct conformance cases across the three layers, all green, zero
   xfails on our side.
2. `signing_policy` enforced per §3.1 on both root:// and davs://; the
   out-of-namespace-CA attack is demonstrably rejected in an e2e test.
3. Limited-proxy monotonicity enforced; escalation rejected e2e.
4. `brix_crl_mode` semantics pinned by tests in all three modes, including
   expired/missing/delta CRL corners.
5. Differential findings report generated with at least the full scenario
   matrix executed against stock XRootD (content depends on what diverges).
6. No regression: full existing suite (`run_suite.sh --pr`) stays green;
   the 3-tests-per-change floor (success + error + security-negative) is met
   for every new code path.

## 8. Risks & mitigations

- **DN canonicalization mismatches** (oneline escaping vs policy-file text)
  are the classic source of both false accepts and false rejects — mitigated
  by the single shared DN-formatting helper plus dedicated SP cases for
  every escaping corner we can forge.
- **Fleet-restart cost** for 100+ wire tests — mitigated by grouping
  scenarios into shared CA-dir layouts and preferring hot reload over
  restart.
- **CRL default change** (`try` vs today's implicit require-when-present) —
  flagged in docs and release notes; `require` restores strictness.
- **Stock-XRootD environment drift** in the differential tier — tier is
  opt-in, skip-clean, and asserts nothing about XRootD itself.
