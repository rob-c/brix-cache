# WLCG Token (JWT/Bearer) Conformance — Design Spec

**Date:** 2026-07-06
**Status:** Approved design, pending implementation plan
**Owner:** Rob Currie

## 1. Goal

Make the module's WLCG bearer-token handling conform to the **WLCG Common JWT
Profile v1.0** (built on RFC 7519 JWT, RFC 8725 JWT BCP, the SciTokens scope
model, and the WLCG storage-authorization scopes), and build a ~150-case
conformance suite that actively hunts for corner-case mistakes in
token parsing, signature verification, claim validation, scope authorization,
multi-issuer trust, and per-protocol token plumbing. Correctness is defined
**spec-first**; stock XRootD (its `XrdSecztn` / `XrdHttp` token paths and the
SciTokens C++ library) is a *comparison target*, not the reference. Divergences
found in XRootD are recorded as findings, not copied.

This effort also **closes the real bugs the suite exposes** — it is not
test-only. Sibling to `2026-07-06-wlcg-x509-conformance-design.md`; reuses that
spec's three-layer structure, manifest-as-single-source-of-truth, and fixture-
forge conventions.

### Non-goals

- OAuth2 token *acquisition* flows (device-code, refresh, `oidc-agent`) beyond
  the existing TPC delegation path — we validate presented tokens, we are not
  an OAuth client except where TPC already is.
- Full macaroon third-party-caveat *discharge issuance* — existing macaroon
  validation and the `/macaroon` endpoint are covered for regression, not
  extended.
- Replacing the hand-rolled JSON/JWT parser (`src/auth/token/json.c`,
  `b64url.c`) with a library — it is deliberately dependency-free; we harden it,
  we don't swap it.
- New claim *transforms* (e.g. arbitrary claim→env mapping). Group/scope/subject
  handling stays as specified by the WLCG profile.

## 2. Background — current state (audited 2026-07-06)

What already conforms:

| Aspect | Where |
|---|---|
| RS256/ES256 verify via EVP; `alg=none` blocked before verify | `src/auth/token/validate.c:258`, `signature.c` |
| RFC 7519 `aud` as string **or** array | `validate.c:325`, `json_string_or_array_contains()` |
| `exp` with 30s skew, `nbf`, `iat` temporal checks | `validate.c:389` (`BRIX_TOKEN_CLOCK_SKEW_SECS`) |
| WLCG scopes `storage.read/write/create/modify/stage`, prefix-boundary match | `src/auth/token/scopes.c:71,126` |
| `wlcg.groups` extraction → group ACL strategy | `validate.c:354`, `identity.c:482` |
| Multi-issuer registry from `scitokens.cfg` (base_path/restricted_path) | `issuer_registry.c:185,286` |
| JWKS hot-reload via mtime poll; up to 8 keys/issuer | `refresh.c:110`, `keys.c` |
| L1 per-worker + L2 SHM token cache keyed on token hash, expiring at `exp` | `worker_cache.c`, `token_cache.c` |
| WebDAV bearer via `Authorization` header **and** `?authz=`/`?access_token=` | `webdav/auth_token.c:101,136` |
| root:// `ztn` token auth in `kXR_auth` | `src/auth/gsi/token.c:43` |
| Macaroon validation + secret-rotation grace | `macaroon.c` |

Gaps this effort closes:

1. **root:// multi-issuer authz escape.** The registry (`scitokens.cfg`
   `base_path`/`restricted_path`) is consulted at initial `kXR_auth`, but
   subsequent file operations on root:// authorize only against the identity's
   *scopes* (capability/group/mapping) — the issuer's `base_path`/
   `restricted_path` is **not** re-enforced per file op. A token from issuer A
   can pass login then reach paths outside A's base. WebDAV enforces this via
   `brix_identity_check_token_scope()`; root:// does not. **Security bug.**
2. **Clock skew is hardcoded** at 30s (`BRIX_TOKEN_CLOCK_SKEW_SECS`) with no
   operator knob. Sites with >30s NTP drift fail all tokens; sites wanting
   *zero* leeway (strict conformance) cannot get it. Needs a directive.
3. **JWT signature has no key-rotation fallback.** During JWKS rotation, if a
   token was signed by a key no longer selected (e.g. `kid`-less token after a
   new key is prepended), verification fails hard — whereas macaroons get an
   old-secret grace retry. Multi-key JWKS with correct `kid` works; the gap is
   the `kid`-absent and mid-rotation windows.
4. **S3 has no bearer-token path at all** (SigV4-only). The WLCG profile is
   increasingly used against S3-style endpoints; `brix_token_validate` is
   protocol-agnostic and should be reachable from the S3 handler.
5. **Scope-path traversal not conformance-pinned.** Scope matching is prefix-
   based on the request path; whether the request path is canonicalized
   (`/a/../b`) *before* scope matching — on every protocol — has no test. Must
   be proven closed.
6. **Untested corners:** multi-key JWKS `kid` selection, `alg` case-sensitivity,
   HS256-signed-with-RSA-public-key confusion on every surface, `wlcg.ver`
   profile-version handling, oversized/pathological tokens, `jti`/replay, and
   broad per-protocol asymmetry (many checks tested on only one of
   root://, WebDAV, S3, query-param).

## 3. Implementation

### 3.1 root:// per-file issuer path gating — `src/auth/token/validate.c` + `src/auth/gsi/token.c`

At `kXR_auth` (`brix_handle_token_auth`), when the token was validated through
the multi-issuer registry, persist the *matched issuer* on the identity
(`brix_identity_t.token_issuer` already exists — ensure it is populated on the
root:// path as it is on WebDAV). Then, in the per-op authz gate that root://
file operations already pass through (`brix_token_authz_strategy()` /
`brix_identity_check_token_scope()`), call `brix_token_issuer_path_ok()` for the
resolved request path **before** the capability/group/mapping ladder — exactly
as WebDAV does. Fail closed: path not under any `base_path`, or under a
`restricted_path`, → `kXR_NotAuthorized` (403). Single-issuer mode
(`brix_token_issuer`/`brix_token_jwks`, no registry) has no base_path concept
and is unaffected. This makes root:// and WebDAV enforce the identical
issuer-scoping invariant.

### 3.2 Configurable clock skew — `brix_token_clock_skew <seconds>`

New directive on the shared common conf (`src/core/config/config.h` field +
`directives.c` merge, per the standard recipe), default **30** (preserves
today's behavior). `0` = strict (no leeway, for conformance). Applied uniformly
in `validate.c` to both the `exp` upper bound and the `nbf` lower bound
(currently `nbf` is checked with **no** skew — this aligns them; a token whose
`nbf` is a few seconds ahead of a slightly-slow verifier should not be rejected
when `exp` gets the same grace). Referenced by both stream
(`directives_auth.inc`) and WebDAV (`webdav/module.c`) directive tables via one
setter. Bounded (e.g. ≤300s) with a config-time error above the cap so a typo
can't disable expiry.

### 3.3 JWT key-rotation robustness — `src/auth/token/validate.c` + `keys.c`

When a token carries a `kid`, selection stays exact (unchanged). When a token
has **no** `kid` and the issuer has multiple JWKS keys, verify against **each**
key of the matching `kty`/`alg` until one succeeds (bounded loop, ≤8 keys),
rather than only the single-key shortcut. This closes the mid-rotation window
(new key prepended, old `kid`-less tokens still in flight) symmetrically with
the macaroon old-secret grace. No new directive — this is correctness. A token
with a `kid` that matches *no* key still fails (no silent fallthrough to
try-all when a `kid` was asserted — asserting a wrong `kid` is a hard reject,
per RFC 8725).

### 3.4 S3 bearer-token authorization — `src/protocols/s3/auth.c` (+ handler)

Add a WLCG bearer path alongside SigV4 in the S3 auth dispatch: if the request
carries `Authorization: Bearer <jwt>` (and SigV4 is absent), route to
`brix_token_validate` using the S3 server block's token config
(`brix_s3_token_jwks`/`_issuer`/`_audience` or shared `brix_token_config`),
then map S3 operations to WLCG scope checks via the **same** scope helpers
(`brix_token_check_read`/`_write`) the other protocols use — GET/HEAD/List →
read, PUT/POST/multipart/DELETE → write/create/modify, keyed on the resolved
object path (bucket+key → export path). SigV4 and bearer are mutually exclusive
per request (never blend auth logic — INVARIANT §6). New config directives are
S3-scoped names that reference the shared common token fields (owned once in
`http_common.c`, per the unified-storage-directive rule). This is the one
genuinely new *feature* in the effort; it reuses the entire existing validation
core and adds only the S3-edge plumbing + scope→verb mapping.

### 3.5 Scope-path canonicalization guarantee

Audit every protocol's path used for scope matching and ensure it is the
**post-`resolve_path()` canonical** path (traversal-collapsed, confined), not a
raw wire path. INVARIANT §4 already requires `resolve_path()` before `open()`;
this extends the guarantee to the *authz* step so `storage.read:/a` can never be
satisfied by a wire path `/a/../secret`. Where a protocol currently scope-checks
a pre-canonical path, fix it to use the resolved one. Pinned by SCP traversal
cases on all three surfaces.

### 3.6 Config surface

New shared fields on the common conf: `token_clock_skew` (§3.2). New S3 token
directives (§3.4) referencing shared common token fields. Both stream and
WebDAV directive tables reference the skew setter. `./configure` rerun only for
the new source files added to `./config` (S3 bearer unit + test binaries); the
directive additions are field+command+merge only.

## 4. Fixture forge — `tests/tokenforge.py`

Python library extending the existing `utils/make_token.py` (RS256-only today)
into a full hostile-token mint, on `cryptography` + PyJWT-style raw assembly
(hand-built `header.payload.signature` for artifacts a library refuses, e.g.
`alg=none`, HS256-signed-with-an-RSA-public-key, tampered segments). New
test-only capability documented alongside existing pytest deps.

- **Scenario materialization:** `forge.scenario("name")` produces the token
  string(s) plus any needed server-side trust artifacts — single- or multi-key
  JWKS files (distinct `kid`s, RSA and EC), `scitokens.cfg` registries with
  `base_path`/`restricted_path`, macaroon secrets — under the session tmpdir.
- **Manifest:** every case records
  `{case_id, mint_recipe, protocol, expected: accept|reject, expected_reason,
  spec_ref}` in `token_manifest.json` — the single source of truth consumed by
  all three layers, so a verdict can never drift between the C tier and the wire
  tier.
- **Hostile artifact catalog (forge capabilities):** `alg=none`,
  `alg` case variants (`rs256`), HS256-with-public-key confusion, RS384/PS256/
  unsupported alg, wrong/missing/duplicate `kid`, multi-key JWKS, corrupted &
  truncated signatures, ES256 DER-vs-P1363 encodings, `exp`/`nbf`/`iat` skew &
  boundary & wrong-type (string) & missing, 8KB+ oversized payloads, malformed
  JSON, non-JWT 3-segment blobs, scalar/array/empty/missing `aud`, scope
  traversal payloads (`storage.read:/a` + request `/a/../b`), boundary scopes
  (`/data` vs `/database`), empty-path scope, unknown permissions,
  `wlcg.ver` missing/wrong/`2.0`, `wlcg.groups` variants, `jti` for replay,
  wrong/unknown issuer, out-of-`base_path` registry tokens.
- Existing `utils/make_token.py` positive/negative factories stay; existing
  token suites (`test_token_*.py`) are untouched and must stay green.

## 5. Test suite (~152 cases, three layers)

Naming: `SIG-*` signature/alg, `CLM-*` claims/temporal, `ISS-*` issuer/multi-
issuer, `AUD-*` audience, `SCP-*` scope authz, `GRP-*` groups, `PROTO-*`
protocol parity/location, `VER-*` wlcg.ver, `CACHE-*` token cache, `ROT-*`
key/secret rotation, `MAC-*` macaroon, `TPC-*` TPC delegation, `RT-*` runtime.
Every case ID appears in the manifest and in the test name.

### Layer 1 — C unit (fast, malformed-input precision)

Links the ngx-free token core (`validate.c` helpers, `scopes.c`, `b64url.c`,
`json.c`, `signature.c`) standalone, the way existing `tests/c/*_unittest.c` do.

- `tests/c/token_scope_unittest.c` — ~30 cases (SCP-*, VER-*): prefix-boundary
  (`/data`≠`/database`), traversal-collapse expectation, empty-path→`/`, root
  scope, read-vs-write mapping, `storage.stage`→read, `storage.modify`→write,
  unknown permission grants nothing, >8 scopes truncation, malformed scope
  strings, `wlcg.ver` presence/variants, group extraction.
- `tests/c/token_conformance_test.c` — ~35 cases (C-reachable halves of SIG-*,
  CLM-*, AUD-*): base64url decode edge cases, 3-segment split, `alg` extraction
  & case & unsupported, `alg=none` block, `kid` selection over multi-key JWKS,
  `exp`/`nbf`/`iat` boundary arithmetic incl. configurable skew, wrong-type
  claims, oversized/truncated tokens fail-closed, `aud` string/array/empty
  membership, RS256/ES256 verify with forge-minted keys, HS-confusion rejected.
- Runner `tests/run_token_conformance.sh` (mirrors `run_cvmfs_core_unit.sh`):
  invokes `tokenforge.py --emit-c-fixtures` once, builds & runs both unit bins.

### Layer 2 — pytest e2e (`tests/test_wlcg_token_conformance_*.py`)

Real handshakes against the live fleet — every applicable scenario runs on
root:// (11097), WebDAV (8443), **and S3 (9001)** unless inherently single-
surface, to catch per-protocol asymmetry directly. Marked `tokenconf`; folded
into standard tiers (fast subset `--pr`, full `--nightly`). Attach-don't-wipe
conftest rule; isolated-config scenarios use `TEST_OWN_FLEET=1`.

- `test_wlcg_token_conformance_signature.py` — SIG (~20): `alg=none` reject on
  every surface, HS256-with-RSA-pubkey confusion reject, `alg` case, RS384/PS256
  unsupported, multi-key JWKS `kid` hit/miss, `kid`-less multi-key fallback
  (§3.3), ES256 on **root://** (gap today) + WebDAV + S3, corrupted/truncated
  sig.
- `test_wlcg_token_conformance_claims.py` — CLM (~18): `exp==now` boundary,
  expired, `nbf` future vs skew (§3.2), missing `exp`, string `exp`, oversized
  token, malformed JSON, `iat` sanity — each on all surfaces.
- `test_wlcg_token_conformance_issuer.py` — ISS (~15): issuer match/mismatch,
  unknown issuer, registry lookup, **root:// per-file `base_path` enforcement
  (§3.1)** + `restricted_path`, `iss`-peek spoof (wrong-signature token whose
  `iss` names a trusted issuer → reject), single-vs-multi-issuer parity.
- `test_wlcg_token_conformance_audience.py` — AUD (~10): scalar, array-member at
  any position, missing, wrong, empty, multi-audience config — root://+WebDAV+S3
  (array only tested on WebDAV today).
- `test_wlcg_token_conformance_scope.py` — SCP (~22): read/write/create/modify/
  stage enforcement, `/data`vs`/database` boundary, **`/a/../b` traversal
  (§3.5) on all surfaces**, empty-path scope, missing scope, unknown perm,
  read-on-write-only & write-on-read-only, sub-path grant.
- `test_wlcg_token_conformance_proto.py` — PROTO (~15) + GRP (~8): query
  `?authz=`/`?access_token=` (WebDAV; documented reject on root://), Bearer-
  prefix vs raw, header-vs-query precedence, **S3 bearer accept/reject (§3.4)**,
  group→ACL mapping, empty groups.
- `test_wlcg_token_conformance_rotation.py` — ROT (~10) + CACHE (~8): JWKS
  hot-reload, old-key rejection after rotation, **`kid`-less mid-rotation
  fallback (§3.3)**, corrupt-JWKS keeps old keys, macaroon secret grace, L1/L2
  cache hit-consistency, distinct-token isolation, expiry eviction.
- `test_wlcg_token_conformance_runtime.py` — MAC (~8) + TPC (~6) + RT (~6):
  macaroon path/activity caveat + expiry, TPC read-src/write-dst scope,
  concurrent validation under load, reload mid-flight, `jti` replay (documented
  behavior — reject-if-enforced or accept-with-note).

### Layer 3 — differential vs stock XRootD (opt-in, `TEST_TOKEN_DIFF=1`)

`tests/run_token_differential.sh`: for each manifest scenario reachable over a
protocol stock XRootD serves (root:// `ztn`, `XrdHttp` bearer), point a stock
`xrootd` (SciTokens-configured, same JWKS/issuer/audience) at the scenario and
record `{ours, xrootd, spec}` verdicts.

- **Asserts:** `ours == spec` (any mismatch is a suite failure).
- **Reports:** `xrootd != spec` divergences are recorded, not failed, into
  generated `docs/10-reference/wlcg-token-differential-findings.md` (verdict
  table + repro per finding).
- Skips cleanly when no `xrootd`/SciTokens present (`BRIX_BIN`-style override,
  per the load-test bridge convention).

## 6. Documentation

- `docs/09-developer-guide/wlcg-token-conformance.md` — the token trust model as
  implemented: validation pipeline order, scope semantics, multi-issuer path
  gating (now symmetric across protocols), the `brix_token_clock_skew`
  directive, S3 bearer support, key-rotation behavior, how to run each suite
  layer, how to regenerate the differential findings.
- Directive reference entries in `docs/03-configuration/quick-reference.md`
  (`brix_token_clock_skew`, S3 token directives).
- Generated findings file under `docs/10-reference/` (checked in after each
  differential run, reviewed like a golden file).

## 7. Acceptance criteria

1. ≥120 (target ~152) distinct conformance cases across the three layers, all
   green, zero unexplained xfails on our side.
2. Each of the five §3 fixes lands with a red→green case: the root:// base_path
   escape (§3.1) is demonstrably rejected e2e; `brix_token_clock_skew` (§3.2)
   pinned in strict/default/wide modes; `kid`-less rotation fallback (§3.3)
   proven; S3 bearer (§3.4) accept+reject e2e; scope traversal (§3.5) rejected
   on all three surfaces.
3. Per-protocol parity: signature/claim/aud/scope invariants hold identically on
   root://, WebDAV, and S3 (asymmetries in the audit are closed or explicitly
   documented as intended).
4. Differential findings report generated with the full reachable scenario
   matrix executed against stock XRootD (content depends on what diverges).
5. No regression: existing `test_token_*.py` and `run_suite.sh --pr` stay green;
   the 3-tests-per-change floor (success + error + security-negative) is met for
   every new code path.

## 8. Risks & mitigations

- **Auth-logic bleed** between S3 SigV4 and bearer — mitigated by a hard
  mutually-exclusive dispatch (INVARIANT §6, never share auth logic) and
  security-negative cases that present both/blended credentials.
- **The clock-skew alignment** (applying skew to `nbf` too) is a behavior
  change — flagged in docs; default 30s preserves current `exp` behavior and the
  `nbf` grace only ever *widens* acceptance within the same bound, never past
  `exp`.
- **Root:// base_path enforcement** could break single-issuer deployments if
  mis-gated — mitigated by gating strictly on "validated via registry" and
  leaving single-issuer mode untouched, with an explicit parity test.
- **Fleet cost** for 150 wire cases across three protocols — mitigated by
  manifest-driven parametrization sharing one fleet, hot-reload over restart,
  and the fast/nightly tier split.
- **Stock-XRootD/SciTokens environment drift** in the differential tier — tier
  is opt-in, skip-clean, and asserts nothing about XRootD itself.
