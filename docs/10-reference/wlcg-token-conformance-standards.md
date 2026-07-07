# WLCG Bearer-Token Conformance — Standards, Methodology, and Results

**Scope:** This document is the authoritative reference for the WLCG bearer-token
(JWT/SciTokens) conformance test suite in `nginx-xrootd`. It records **every
specification, profile, and body of published work the token implementation has
been tested to conform to**, the methodology used to test it, the exact test
families and their standard-to-test mappings, and the conformance results
(bugs fixed, behaviours confirmed robust, and documented deviations).

**Suite at a glance**

| Metric | Value |
|---|---|
| Total conformance cases | **510** (82 C-unit checks + 428 wire cases) |
| Normative rules in the oracle | **158** (see [`wlcg-token-rfc-rules.md`](wlcg-token-rfc-rules.md)) |
| Test layers | 3 (C-unit, live-fleet wire, opt-in differential-vs-stock-XRootD) |
| Protocols exercised | `root://` (XRootD), WebDAV/HTTP, S3 |
| Enforcing test ports | 11097, 11119 (strict-skew), 11250 (multi-key), 11251 (registry), 8446 (WebDAV), 9002 (S3) |
| Fixture-forge mint methods | 85 (hostile-token generator, `tests/tokenforge.py`) |
| Bugs found & fixed | 7 + one new feature (S3 bearer auth) |
| Regression baseline | existing token (118) + S3 (203) + C-unit suites, all green |

---

## 1. Methodology: spec-first conformance

The suite is **specification-first**. Correctness is defined by the normative
text of the standards below — **not** by the behaviour of any reference
implementation. Stock XRootD (and its `XrdSecztn` / SciTokens C++ paths) is used
only as an optional *comparison target*; where stock XRootD diverges from a
specification the divergence is recorded as a finding, never copied.

For every testable normative requirement (a `MUST`/`MUST NOT`/`SHALL`/`SHOULD`)
the suite constructs at least one **conforming** artefact and at least one
**violating** artefact and asserts the specification-mandated verdict. Where the
implementation diverges from a requirement, the test asserts the *specification*
and the divergence is triaged as either a **fix** (for actionable `MUST`-level
gaps) or a **documented deviation** (for `MAY`/`SHOULD`-level items or
intentional profile choices), with the governing rule cited in both cases.

The full requirement set is catalogued as **158 numbered, cited rules** in
[`docs/10-reference/wlcg-token-rfc-rules.md`](wlcg-token-rfc-rules.md); security-critical
rules are tagged `[SEC]`. Each test names the rule(s) it exercises.

---

## 2. Normative sources tested against

### 2.1 IETF Standards (RFCs)

| Standard | Title | What it governs here | Families / where tested |
|---|---|---|---|
| **RFC 7515** | JSON Web Signature (JWS) | Compact serialization (3 base64url segments), the JOSE header parameters `alg`/`typ`/`cty`/`kid`/`jku`/`jwk`/`x5u`/`x5c`/`x5t`/`crit`, signature computation, and the rule that a verifier selects keys from its **own** trust configuration, never from header-embedded material | HDR, SIG, ALG; C-unit base64 |
| **RFC 7517** | JSON Web Key (JWK) | JWKS representation of trust anchors — RSA (`n`,`e`), EC (`crv`,`x`,`y`) — and multi-key sets with `kid` selection | key handling, ALG, multi-key SIG |
| **RFC 7518** | JSON Web Algorithms (JWA) | The `alg` identifiers `RS256/384/512`, `PS256/384/512`, `ES256/384/512`, `HS256/384/512`, `none`; curve↔alg binding (ES256↔P-256, ES384↔P-384, ES512↔P-521); RSA key-size floor (≥2048 bits); ECDSA fixed-size R‖S signatures | ALG |
| **RFC 7519** | JSON Web Token (JWT) | Registered claims (`iss`,`sub`,`aud`,`exp`,`nbf`,`iat`,`jti`); `NumericDate` and `StringOrURI` types; `aud` as string **or** array with case-sensitive membership; unknown-claim tolerance; unsecured-JWT (`alg:none`) rejection | CLM, CLM2, NDT, AUD, VER |
| **RFC 8725** | JSON Web Token Best Current Practices (**BCP 225**) | The security spine: perform algorithm verification (don't trust header `alg`), reject `none`, prevent key-confusion (RS↔HS), validate `crit`, don't dereference `jku`/`x5u`, validate every relied-upon claim, use `typ` to prevent cross-JWT confusion | ALG, HDR, BCP cross-cutting, PAR |
| **RFC 9068** | JWT Profile for OAuth 2.0 Access Tokens (`at+jwt`) | Explicit-typing (`typ: at+jwt`), required access-token claims | HDR (`typ`) |
| **RFC 6749 §3.3** | OAuth 2.0 — scope syntax | `scope` = space-delimited, case-sensitive tokens; the scope-token character set (`%x21 / %x23-5B / %x5D-7E`, excluding space/`"`/`\`); order-independence | SCP2; C-unit charset |
| **RFC 6750** | OAuth 2.0 Bearer Token Usage | The three transport methods (header / form-body / query), case-insensitive `Bearer` scheme, exactly-one-transport-per-request, and the error-response model: `WWW-Authenticate: Bearer`, and `invalid_request`→400 / `invalid_token`→401 / `insufficient_scope`→403 | BEAR, PROTO |
| **RFC 7235** | HTTP/1.1 Authentication | Case-insensitive auth-scheme matching (`bearer`/`BEARER`/`Bearer`) | BEAR |
| **RFC 4648** | Base16/32/64 Data Encodings | base64url alphabet (`-`/`_`, no padding); rejection of standard-base64 `+`/`/` and `=` padding in JWS segments | C-unit base64, HDR |
| **RFC 3986 §6** | URI Generic Syntax — normalization | Scope-path normalization (`///foo/../baz` ≡ `/baz`) before authorization comparison | SCP2, scope traversal |
| **RFC 8414** | OAuth 2.0 Authorization Server Metadata | Issuer discovery via `<iss>/.well-known/...` → `jwks_uri` (the trust-establishment model our single-issuer and multi-issuer-registry configs implement) | ISS, issuer trust |
| **RFC 7797** | JWS Unencoded Payload Option | The `b64` critical header parameter — a concrete `crit` value used to exercise unknown-`crit` rejection | HDR (`crit`) |
| **RFC 8693** | OAuth 2.0 Token Exchange | The scope-syntax reference the WLCG profile builds on | SCP2 (via WLCG) |

**Out of scope (documented):** RFC 7516 (JWE) — encrypted tokens are not part of
the WLCG/SciTokens bearer-token profile and are not accepted.

### 2.2 Community profiles and specifications

| Source | What it governs here | Families |
|---|---|---|
| **WLCG Common JWT Profile v1.0** — WLCG Authorization Working Group, 2019 (Zenodo record [3460258](https://zenodo.org/records/3460258); source [`WLCG-AuthZ-WG/common-jwt-profile`](https://github.com/WLCG-AuthZ-WG/common-jwt-profile/blob/master/profile.md)) | The governing profile for this deployment: `wlcg.ver`, required claim set, the `aud` wildcard `https://wlcg.cern.ch/jwt/v1/any`, `storage.{read,create,modify,stage}:<path>` and `compute.{read,modify,create,cancel}` scopes, `wlcg.groups`, the capability-vs-group-vs-identity token model, and the `<6h` (target ~20 min) token-lifetime recommendation | WLCG, SCP2 |
| **SciTokens** — [scitokens.org technical docs](https://scitokens.org/technical_docs/Claims); the SciTokens paper: A. Withers, B. Bockelman, D. Weitzel, D. Brown, J. Gaynor, J. Basney, T. Tannenbaum, Z. Miller, *"SciTokens: Capability-Based Secure Access to Remote Scientific Data,"* PEARC '18, [doi:10.1145/3219104.3219135](https://doi.org/10.1145/3219104.3219135) | The capability model this profile descends from: `ver: "scitokens:2.0"`, the `aud` special value `ANY`, and the `read:`/`write:`/`queue:`/`execute:` `$AUTHZ:$PATH` scope form with RFC 3986 path normalization | SCITOK |
| **OpenID Connect Discovery 1.0** | Issuer `/.well-known/openid-configuration` → `jwks_uri` key discovery (the mechanism underlying issuer trust) | ISS (referenced) |

### 2.3 Security research and advisories (test-case lineage)

The security-critical cases are grounded in the published attack literature so
that each is a *known* failure mode, not a hypothetical:

| Source | Attack class | Cases derived |
|---|---|---|
| Tim McLean, *"Critical vulnerabilities in JSON Web Token libraries"* (2015) — the seminal disclosure of the `alg:none` bypass and the RS256↔HS256 key-confusion attack | Algorithm substitution / `none` bypass | ALG (`alg_none`, `none_with_sig`, `alg_hs256_confusion`, `alg_variant`), BCP |
| RFC 8725 §2 (which codifies the above and the header-URL SSRF / cross-JWT-confusion classes) | Key injection, SSRF, audience redirection, cross-JWT confusion | HDR (`jku`/`jwk`/`x5c` injection), AUD/BCP (audience redirection), `typ` confusion |
| **scitokens-cpp** security advisories — the sibling-path prefix and path-traversal authorization-bypass class in capability-scope path matching | Path-prefix / traversal authorization bypass | SCP2 (segment-boundary `/foo`≠`/foobar`; `..`/`//` normalization; missing-path fail-closed), scope traversal on all protocols |

---

## 3. Suite architecture (three layers)

**Layer 1 — C unit** (`tests/run_token_conformance.sh`; 82 checks). Links the
`ngx`-free token core (`src/auth/token/scopes.c`, `b64url.c`, `json.c`) as a
standalone binary and asserts parser- and matcher-level rules with malformed-input
precision: base64url alphabet/padding, `NumericDate` type handling, JSON
duplicate-key behaviour, `aud` string/array membership, scope-path boundary and
`..` semantics, the clock-skew formula, and WLCG scope-permission bit mapping.
Files: `tests/c/token_scope_unittest.c`, `tests/c/token_conformance_test.c`.

**Layer 2 — live-fleet wire** (`tests/test_wlcg_token_conformance_*.py`, pytest
marker `tokenconf`; 428 cases). Real protocol handshakes against a running fleet.
Every case mints a token with the forge and presents it over the wire:
`root://` via the raw `kXR_auth ztn` sequence, WebDAV via `Authorization: Bearer`
(and `?authz=`/`?access_token=` query transports), and S3 via `Authorization:
Bearer`. Verdicts are `accept`/`reject` (and, for HTTP, response-header/status
inspection). The suite **self-provisions** its data files so a fleet restart
cannot break it.

**Layer 3 — differential vs stock XRootD** (`tests/run_token_differential.sh`,
opt-in `TEST_TOKEN_DIFF=1`). Asserts *our* verdict equals the specification for a
representative scenario set, and — when a SciTokens-configured stock `xrootd` is
available — records any `xrootd ≠ spec` divergences into a checked-in findings
file. Skips cleanly (with an honest findings note) when a token-validating stock
server is not configured.

### 3.1 The fixture forge (`tests/tokenforge.py`)

An 85-method hostile-token generator (extends `utils/make_token.TokenIssuer`)
that mints every artefact the rules require: RS256/384/512, PS256/384/512,
ES256/384/512 and HS-family signatures; a deliberately **undersized 1024-bit
RSA** key and **wrong-curve P-384/P-521** keys; `alg:none` (empty and non-empty
signature); HS↔RS confusion; `crit`/`typ`/`cty`/`jku`/`jwk`/`x5c` JOSE headers
(including attacker-key injection); fractional/negative/huge/`null`/string
`NumericDate`; duplicate claim names; padded and standard-base64 segments; the
WLCG `aud` wildcard and SciTokens `ANY`; `compute.*` and SciTokens `read:`/`write:`
scopes; and multi-issuer `scitokens.cfg` trust configurations. A JSON manifest
(`token_manifest.json`) is the single source of truth consumed by the layers.

---

## 4. Test families

Case-ID prefixes and their standard mappings. Wire families run against the
enforcing ports; each family asserts specification-correct verdicts and marks any
real divergence as a documented `xfail`.

| Family | Standards | Coverage |
|---|---|---|
| **SIG** / **SIG-multikey** | RFC 7515/7518, 8725; McLean 2015 | `alg:none`, HS↔RS confusion, `alg` case-sensitivity, unsupported-alg rejection, truncated/tampered signatures, `kid` hit/miss, `kid`-less multi-key rotation grace, ES256 verification |
| **ALG** | RFC 7518 §3, 8725 §2.2/§3 | Full JWA matrix: RS384/512, PS256/384/512, ES384/512 rejected as Optional-not-implemented; `none`/`none`-with-sig, wrong-curve (ES256 header on a P-384 key), undersized-RSA, weak-HS all reject; positive RS256/ES256 controls |
| **HDR** | RFC 7515 §4.1, 8725 §2.8/§3.11, 9068, 7797 | `crit` (unknown/empty/non-array/lists-`alg`/missing-name), `typ`/`at+jwt`, `cty`; `jku` not fetched (SSRF-safe), embedded `jwk`/`x5c` keys not trusted |
| **CLM** / **CLM2** | RFC 7519 §4/§7 | `exp`/`nbf`/`iat`/`iss`/`sub` presence and type; string-`exp` rejection; non-string `iss`/`sub`; duplicate claim names; `iat>exp`/`nbf>exp` ordering; unknown-claim tolerance; malformed JSON |
| **NDT** | RFC 7519 §2 | `NumericDate` edges: fractional, negative, huge (over-int64), `null`, `exp==now`, skew boundaries |
| **AUD** | RFC 7519 §4.1.3, 8725 §3.9, WLCG §Audience | Scalar and array audience (position-independent, case-sensitive), empty/missing, multi-element arrays, and the WLCG `.../v1/any` wildcard |
| **SCP** / **SCP2** | RFC 6749 §3.3, 3986 §6, WLCG/SciTokens scopes | `storage.{read,write,create,modify,stage}` semantics; segment-boundary matching (`/data`≠`/database`, `/atl`≠`/atlas`); `..`/`//` normalization; path-less-storage-scope reject; scope charset; `compute.*`; order-independence; unknown-scope fail-closed |
| **VER** / **WLCG** / **SCITOK** | WLCG Profile v1.0, SciTokens v2.0 | `wlcg.ver`, required-claim set, `aud` wildcard, `wlcg.groups`, capability-vs-group model, lifetime; SciTokens `ver`/`ANY`/`read:` model boundary |
| **BEAR** / **PROTO** | RFC 6750, 7235 | Header vs `?authz=`/`?access_token=` transports; case-insensitive `Bearer`; multiple-transport handling; `WWW-Authenticate`; `invalid_request`/`invalid_token`/`insufficient_scope` status mapping; query `Cache-Control: no-store` |
| **ISS** | RFC 8414, WLCG §Base Tokens | Multi-issuer registry: per-issuer `base_path`/`restricted_path` enforcement, unknown-issuer rejection, issuer-URL exactness |
| **PAR** / **parity-ext** / **write** | all `[SEC]` | Cross-protocol uniformity — the core RFC set and write-scope enforcement run identically on `root://`, WebDAV, and S3 |
| **RT** / **CACHE** / **skew** | operational | Concurrent-validation cache consistency and isolation; configurable-clock-skew boundaries; token-cache correctness |
| **edge** / **fill** | boundary | NumericDate/scope/aud boundary matrices, token payload-size boundary, permission×operation matrix, per-port negative controls |

---

## 5. Conformance results

### 5.1 Confirmed robust (security-critical negatives)

The suite confirms the implementation is hardened against the published JWT
attack classes:

- **Algorithm allowlist is exactly `RS256`/`ES256`.** Every Optional algorithm
  (`RS384/512`, `PS*`, `ES384/512`, `HS*`) is rejected — RFC-compliant (RS256
  Required, ES256 Recommended+, the rest Optional). `alg:none` (empty and
  non-empty signature), the RS256↔HS256 key-confusion attack, `alg` case-variants,
  wrong-curve keys, undersized RSA, and truncated/tampered signatures **all
  reject**.
- **All three header key-injection vectors are blocked** (RFC 8725 §2.8): `jku`
  is never dereferenced (SSRF-safe), and an embedded `jwk` or `x5c` key is never
  trusted — the verifier selects keys solely from its configured JWKS.
- **Path-traversal / sibling-prefix authorization bypass is blocked** on all
  protocols (segment-boundary matching; `..` rejected before scope evaluation).
- **Cross-protocol uniformity**: signature, claim, audience, and scope rules hold
  identically on `root://`, WebDAV, and S3; read-scope-only tokens cannot write.

### 5.2 Bugs found and fixed (7 total; all independently reviewed)

| # | Finding | Governing rule | Fix |
|---|---|---|---|
| 1 | `scitokens.cfg` strategy key `authz_strategy` silently dropped | WLCG registry parse | Real key is `authorization_strategy` |
| 2 | Clock skew hard-coded at 30s, no operator knob | RFC 7519 §4.1.4 | `brix_token_clock_skew` / `_webdav_` / `_s3_` (default 30, ≤300, `exp`-only) |
| 3 | `kid`-less tokens rejected during JWKS rotation | RFC 7515 §4.1.4 | Verify against every JWKS key when `kid` absent |
| 4 | **WebDAV did not enforce READ scope** (GET/HEAD/PROPFIND) | WLCG §Authorization | Enforce read scope in the access phase, uniform with root:///S3 |
| 5 | Unknown `crit` header ignored | RFC 7515 §4.1.11 `[SEC]` | Reject any token asserting unimplemented critical headers |
| 6 | Fractional/large `NumericDate` rejected | RFC 7519 §2 | Accept `json_real`; `JSON_DECODE_INT_AS_REAL`; saturating `exp+skew` |
| 7 | WLCG `aud` wildcard `.../v1/any` rejected | WLCG §Audience | Accept the wildcard alongside exact-match |

**New feature (previously absent):** S3 WLCG bearer-token authentication + scope
authorization (`src/protocols/s3/auth_bearer.c`), mutually exclusive with SigV4.

### 5.3 Documented deviations (found, not fixed — follow-up candidates)

Each is recorded as an `xfail` with its governing rule; the rationale is captured
so the deviation is a conscious decision, not an oversight.

- **RFC 6750 error responses** (`[SEC]` MUST/SHOULD): invalid/absent token returns
  `403` rather than `401`; no `WWW-Authenticate: Bearer` header; dual credential
  transports return `200` instead of `400`; query-token responses omit
  `Cache-Control: no-store`. *Rationale:* the `403`-for-auth-failure convention is
  common in storage servers; changing the status split risks the existing
  WebDAV-status suite. Recommended as a scoped, independently-reviewed follow-up
  fix wave.
- `wlcg.ver` is advisory (WLCG requires `"1.0"`); token lifetime `>6h` is not
  rejected (WLCG SHOULD); `iat>exp` ordering is unchecked; a non-string `sub` is
  accepted; SciTokens `ANY` audience and the `read:`/`write:` scope model are not
  honoured (this is a WLCG server — `storage.*` only).
- **Effective payload limit ~4096 bytes** (the `pay_json[4096]` buffer in
  `validate.c`), stricter than the 8192-byte raw-token guard — a very rich
  `wlcg.groups` token could be rejected.

---

## 6. Running / reproducing

```bash
# Layer 1 — C unit (fast, no fleet)
tests/run_token_conformance.sh

# Layer 2 — live-fleet wire (needs the fleet)
tests/manage_test_servers.sh start-all
PYTHONPATH=tests pytest tests/test_wlcg_token_conformance_*.py -v

# Layer 3 — differential vs stock XRootD (opt-in)
TEST_TOKEN_DIFF=1 tests/run_token_differential.sh
```

**Operational note:** any rebuild that runs `start-all` desyncs the dedicated
token ports; after a source change, run a clean `stop-all` then `start-all` and
re-run the full suite.

---

## 7. Companion documents

- [`wlcg-token-rfc-rules.md`](wlcg-token-rfc-rules.md) — the 158-rule normative catalog (the oracle).
- [`../09-developer-guide/wlcg-token-conformance.md`](../09-developer-guide/wlcg-token-conformance.md) — the trust model, validation pipeline, directives, and family list.
- [`../superpowers/specs/2026-07-06-wlcg-token-conformance-design.md`](../superpowers/specs/2026-07-06-wlcg-token-conformance-design.md) — the base-suite design.
- [`../superpowers/specs/2026-07-06-wlcg-token-rfc-conformance-expansion.md`](../superpowers/specs/2026-07-06-wlcg-token-rfc-conformance-expansion.md) — the RFC-expansion design.
- `wlcg-token-differential-findings.md` — the generated Layer-3 findings golden file.

---

## Appendix A — Glossary

- **JWT** JSON Web Token · **JWS** JSON Web Signature · **JWK/JWKS** JSON Web Key (Set) · **JWA** JSON Web Algorithms · **JOSE** the JSON Object Signing and Encryption header.
- **NumericDate** a JSON number of seconds since the Unix epoch (RFC 7519 §2).
- **StringOrURI** a JSON string that, if it contains a `:`, must be a URI (RFC 7519 §2).
- **Capability token** authorization by `scope` claim; **group token** by `wlcg.groups`; **identity token** an OIDC ID token — distinct WLCG validation models.
- **`ztn`** the XRootD "Zero Trust Network" security protocol carrying a bearer token in `kXR_auth`.
