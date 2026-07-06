# WLCG Token RFC-Conformance Expansion (→ 500 cases) — Design

**Date:** 2026-07-06
**Status:** Approved design (extends `2026-07-06-wlcg-token-conformance-design.md`)
**Owner:** Rob Currie

## 1. Goal & philosophy shift

Expand the WLCG token conformance suite from ~145 cases to **~500**, grounded
in the **normative text of the RFCs and published profiles**. The operative
change from the first effort: **the specs are the oracle**. Where the module's
behaviour diverges from a `MUST`/`MUST NOT`, the test asserts the spec and the
divergence is a **finding** — fixed when the requirement is `MUST`-level and
actionable, or documented as an intentional deviation with a rationale when it
is `MAY`/`SHOULD`-level and the current behaviour is defensible.

Authoritative sources (the rule catalog is
[`docs/10-reference/wlcg-token-rfc-rules.md`](../../10-reference/wlcg-token-rfc-rules.md),
158 numbered rules):

- **RFC 7519** JWT · **RFC 7515** JWS · **RFC 7517** JWK · **RFC 7518** JWA
- **RFC 8725** JWT BCP (BCP 225) · **RFC 9068** `at+jwt` access-token profile
- **RFC 6749 §3.3** scope syntax · **RFC 6750** Bearer token usage
- **WLCG Common JWT Profile v1.0** · **SciTokens v2.0**

## 2. New case families (case-ID prefix → rule refs → ~count)

| Prefix | Area | Rule refs | ~N |
|---|---|---|---|
| **ALG** | JWA matrix: RS384/512, PS256/384/512, ES384/512, HS*, `none` variants, alg-case, curve binding, RSA key-size, EC sig format | 43–56, 147–149, 152–153 | 55 |
| **HDR** | JWS headers: `crit` (unknown/empty/non-array/lists-alg), `typ`/`at+jwt`, `cty`, `jku`/`jwk`/`x5u`/`x5c` key-injection, missing `alg`, padded-base64, segment count, duplicate headers | 24–42, 70, 74–75, 150–151 | 50 |
| **NDT** | NumericDate: fractional, negative, string, huge, `exp==now`, past-1s, `nbf` future-1s, missing, zero | 1–3, 10–13, 155 | 25 |
| **CLM2** | Claim types/interactions: non-string `iss`/`sub`, duplicate claim names, unknown-claims-ignored, `iat>exp`, `nbf>exp`, required-claim absence | 4–9, 14–21, 69, 102, 123–124 | 35 |
| **BEAR** | RFC 6750: Bearer case-insensitivity, malformed syntax, **multiple methods→400**, query `Cache-Control: no-store`, **WWW-Authenticate** on 401, error codes **invalid_token=401 / insufficient_scope=403 / invalid_request=400**, form-body | 79–95, 158 | 45 |
| **SCP2** | Scope syntax/authz: RFC 6749 charset (forbid space/`"`/`\`), order-independence, `storage.*` **path-required**, sibling-prefix `/foo`≠`/foobar`, `..`/`//` normalization, `create`≠`modify`, unknown-scope fail-closed | 96–100, 110–118, 125, 134–143, 156 | 55 |
| **WLCG** | Profile: `wlcg.ver` required=`"1.0"`, **aud wildcard `.../v1/any`**, required-claim set, lifetime `<6h`, `wlcg.groups` array syntax, capability-vs-group model | 101–125 | 45 |
| **SCITOK** | SciTokens v2.0: `ver="scitokens:2.0"` required, aud `ANY`, `read:`/`write:`/`queue:`/`execute:` model, RFC 3986 path normalization | 126–146 | 30 |
| **PAR** | Cross-protocol parity: a core subset of every family run on root:// **and** WebDAV **and** S3 to prove uniform RFC compliance | all `[SEC]` | 100 |

New ≈ 440; with the existing ~145 the suite lands **~500–585** cases; the C-unit
tier absorbs the parser-level rules (base64 padding, JSON duplicate keys,
NumericDate types, scope charset, path normalization) and the wire tier the
protocol-observable ones.

## 3. Expected divergences (spec-first → findings)

Predicted from a read of `validate.c` against the catalog; each becomes a
red case that is then **fixed** or **documented**:

1. **`crit` ignored** (RFC 7515 §4.1.11, `[SEC]`) — an unknown critical param
   must reject; the validator currently ignores `crit`. **Fix** (security).
2. **Multiple credential transports** (RFC 6750 §2) — header+query must be
   `400 invalid_request`; earlier PROTO-07 showed header-wins-200. **Fix.**
3. **WLCG `aud` wildcard** (WLCG §Audience, rule 104–105) —
   `https://wlcg.cern.ch/jwt/v1/any` must be accepted; exact-match rejects it.
   **Fix** (profile conformance).
4. **`WWW-Authenticate` on 401** (RFC 6750 §3, rule 87/90) — likely absent on
   WebDAV/S3. **Fix** where cheap, else document.
5. **`invalid_token` vs `insufficient_scope`** status split (401 vs 403, rules
   90–91) — verify the module distinguishes them.
6. **Padded / non-base64url segments** (RFC 7515 §2, rule 25) — verify the
   decoder rejects `=`/`+`/`/`.
7. **RSA key < 2048** (RFC 7518 §3.3, rule 50) — verify rejection.
8. **Query token `Cache-Control: no-store`** (RFC 6750 §2.3, rule 85).
9. **`wlcg.ver` enforcement** (rule 101) — advisory today; WLCG says required.
   Decide: enforce under a strict-profile port, or document as advisory.
10. **Token lifetime > 6h** (rule 108) — `MAY` reject; document (no fix unless
    a strict-profile knob is wanted).

`MUST`-level security divergences (1–3, 6) are fixed; `SHOULD`/`MAY` items are
fixed when cheap or documented with rationale. Fixes follow the reviewed-fix
pattern (red case → fix → full review) already used for the four prior fixes.

## 4. Execution

Same 3-layer + reviewed-subagent structure as the base effort:

1. **Forge extension** (`tests/tokenforge.py`): mint the new shapes —
   `crit`/`typ`/`cty`/`jku`/`jwk`/`x5c` headers; PS256/384/512, ES384/512,
   HS256/384/512 signing; an **undersized (1024-bit) RSA** key and a **P-384**
   EC key (curve-mismatch); NumericDate edge types; duplicate claim names;
   padded-base64 segments; scope-charset payloads; `aud` wildcard; compute
   scopes; SciTokens `ver`. A **strict-profile** JWKS/port may be added for
   `wlcg.ver`/lifetime enforcement tests.
2. **C-unit expansion**: parser-level rules against `b64url.c`/`json.c`/
   `scopes.c` (padding, duplicate keys, NumericDate, charset, normalization,
   sibling-prefix).
3. **Wire families** (per prefix above) against the enforcing ports, plus a
   **cross-protocol parity** driver; each triages divergences (xfail-strict +
   documented, or manifest-corrected).
4. **Fixes** for the `MUST`-level findings, each reviewed.
5. **Docs + final verification**; the differential findings doc gains the new
   scenarios; the dev doc's coverage table is updated.

## 5. Acceptance

- ≥500 conformance cases across the three layers, green (or xfail-strict with a
  documented finding).
- Every `[SEC]` rule in the catalog has at least one case.
- Each fixed divergence lands with a red→green case + full review; each
  documented deviation names the rule and the rationale.
- No regression in the existing token/S3 suites.
