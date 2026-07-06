# WLCG Token Conformance — Trust Model, Suite, and Findings

**Status:** Implemented 2026-07-06. Companion to the design spec
[`docs/superpowers/specs/2026-07-06-wlcg-token-conformance-design.md`](../superpowers/specs/2026-07-06-wlcg-token-conformance-design.md).

This document describes how the module validates WLCG bearer tokens (the
SciTokens/WLCG Common JWT Profile), the conformance suite that exercises it,
the bugs the suite exposed, the fixes that landed, and how to run each layer.

## 1. Validation pipeline (as implemented)

Every bearer token — on `root://`, WebDAV, and S3 — funnels through one
entry point, `brix_token_validate()` (`src/auth/token/validate.c`), or its
multi-issuer wrapper `brix_token_validate_registry_authn()`. The pipeline,
in order:

1. **Macaroon vs JWT** routing (macaroons validate via HMAC + caveats).
2. **Length** — `0 < len ≤ 8192`.
3. **Structure** — exactly three base64url segments.
4. **Algorithm** — `RS256` or `ES256` only; `alg:"none"` is rejected
   **before** the signature step. The `alg` string is compared
   case-sensitively (`rs256` ≠ `RS256`). HS256 is rejected, which defeats the
   classic "HS256-signed-with-the-RSA-public-key" confusion attack.
5. **Key selection + signature.** With a `kid`, an exact JWKS match is
   required (a single-key store keeps a legacy leniency). **Without a `kid`,
   the token is verified against every JWKS key** until one succeeds — this is
   the rotation-grace behaviour (see §3, fix 3). ES256 signatures are the
   P-256 R‖S (P1363) form.
6. **Claims** — `iss`, `sub`, `aud`, `scope`, `wlcg.groups`, `exp`, `nbf`,
   `iat`.
7. **Issuer** — must equal the configured/registry issuer.
8. **Audience** — RFC 7519 §4.1.3: `aud` may be a string **or an array**;
   membership is position-independent.
9. **Expiry** — `now > exp + clock_skew` rejects. The skew is configurable
   (see §3, fix 2); it applies to `exp` only.
10. **Not-before** — `nbf > now` rejects, with **no** skew (deliberately
    strict: a token must not be used before its `nbf`).
11. **Scope parse** — space-separated `permission:path` entries.

`wlcg.ver` is parsed but **advisory** — it is not enforced (an absent or
unknown version does not reject). This matches the WLCG profile, which does
not mandate rejection on minor-version mismatch.

## 2. Scope authorization

WLCG scopes are `permission:path`: `storage.read`, `storage.write`,
`storage.create`, `storage.modify`, and `storage.stage` (staged files are
read-only → read). Path matching is exact-prefix with a boundary check, so
`storage.read:/data` covers `/data/x` but **not** `/database`. An empty path
(`storage.read:`) defaults to `/`. Scope checks always use the **canonical,
traversal-collapsed logical path**, never a raw wire path.

Every protocol enforces scope on the resolved path:

- **root://** — `brix_check_token_scope()` (`handshake/policy.c`) on every
  file op; `..` is rejected earlier by `brix_reject_dotdot_path()`.
- **WebDAV** — `webdav_check_token_scope()` in the access phase for read
  **and** write verbs (GET/HEAD/PROPFIND get read scope; PUT/DELETE/MKCOL/…
  get write). OPTIONS and LOCK/UNLOCK are exempt. `..` is collapsed by nginx's
  URI parser before the check.
- **S3** — `brix_identity_check_token_scope()` in `s3_dispatch_after_auth`
  on the `"/"+key` logical path; GET/HEAD → read, PUT/POST/DELETE → write.

For multi-issuer deployments (`scitokens.cfg`), each issuer's `base_path` /
`restricted_path` is enforced per-op before the scope ladder
(`brix_token_issuer_path_ok`), so a token from issuer A cannot reach paths
outside A's base.

## 3. Bugs found and fixed by the suite

The suite was built spec-first to hunt for corner-case mistakes. It found and
fixed:

1. **`scitokens.cfg` strategy key silently dropped.** The registry parser
   accepts `authorization_strategy`, not `authz_strategy`; a wrong key was
   ignored, leaving the authz strategy unset. (Fixture/parser mismatch, fixed
   in the forge + documented.)
2. **Clock skew was hard-coded** at 30s with no operator knob. Added
   `brix_token_clock_skew` (stream) / `brix_webdav_token_clock_skew` (HTTP) /
   `brix_s3_token_clock_skew` — default 30, max 300, applied to the `exp`
   grace only (`nbf` stays strict). `0` gives exact-expiry conformance.
3. **`kid`-less tokens were rejected during JWKS rotation.** When a token had
   no `kid` and the JWKS had multiple keys, only the first key was tried. Now
   every key is tried (`src/auth/token/validate.c`), so a `kid`-less token
   signed by any trusted key verifies — closing the new-key-prepended rotation
   window symmetrically with the macaroon old-secret grace.
4. **WebDAV did not enforce READ scope.** `GET`/`HEAD`/`PROPFIND` skipped the
   scope check entirely, so a token scoped to `/atlas` — or with **no** scope —
   could read any path. WebDAV now enforces read scope like root:// and S3.
   **This was a genuine authorization gap.**

New feature (was absent): **S3 bearer-token authentication + scope
authorization** (`src/protocols/s3/auth_bearer.c`), mutually exclusive with
SigV4, with full read/write scope enforcement.

## 4. Directives

| Directive | Plane | Meaning |
|---|---|---|
| `brix_token_clock_skew <secs>` | root:// | `exp` grace (default 30, ≤300) |
| `brix_webdav_token_clock_skew <secs>` | WebDAV | same, HTTP plane |
| `brix_s3_token on\|off` | S3 | enable WLCG bearer auth (enforcing) |
| `brix_s3_token_jwks <path>` | S3 | JWKS file (required when token on) |
| `brix_s3_token_issuer <url>` | S3 | expected `iss` |
| `brix_s3_token_audience <aud>` | S3 | expected `aud` |
| `brix_s3_token_clock_skew <secs>` | S3 | `exp` grace |

`brix_s3_token on` without `brix_s3_token_jwks` is a config-time error.

## 5. Test suite (three layers)

**Layer 1 — C unit** (`tests/run_token_conformance.sh`): 63 checks in
`tests/c/token_scope_unittest.c` (scope precision, boundary, traversal-raw,
stage/modify/empty-path) and `tests/c/token_conformance_test.c` (alg case,
claim extraction, string-`exp` rejection, aud string/array, b64url, and the
skew formula). Links the ngx-free token core standalone.

**Layer 2 — pytest e2e** (`tests/test_wlcg_token_conformance_*.py`, marker
`tokenconf`): real handshakes against the live fleet, ~82 cases across
families:

| Family | File | What |
|---|---|---|
| SIG | `_signature.py`, `_signature_multikey.py` | alg=none, HS-confusion, alg-case, unsupported, truncated/tampered, `kid` hit/miss, `kid`-less multi-key rotation, ES256 |
| CLM | `_claims.py` | exp/nbf/missing/string/oversized/malformed, skew boundaries (`_skew.py`) |
| AUD | `_audience.py` | scalar, array (position-independent), empty, missing |
| SCP | `_scope.py` | boundary, stage, write-only, empty-path, missing, `..` traversal |
| VER | `_version.py` | `wlcg.ver` advisory |
| ISS | `_issuer.py` | multi-issuer `base_path` enforcement |
| PROTO | `_proto.py` | header vs `?authz=`/`?access_token=`, precedence |
| WebDAV parity | `_webdav_parity.py` | read/write scope enforcement on port 8446 |
| S3 | `_s3.py` | bearer accept/reject/scope, SigV4-anon unaffected |
| RT | `_runtime.py` | concurrent cache consistency, isolation |

The suite **self-provisions** its data files (`ensure_conformance_data()`),
so a fleet restart cannot break it. Enforcing test ports: root:// 11097,
strict-skew 11119, multi-key 11250, registry 11251, WebDAV-token 8446,
S3-token 9002.

**Layer 3 — differential vs stock XRootD** (`tests/run_token_differential.sh`,
opt-in `TEST_TOKEN_DIFF=1`): compares our root:// verdicts against a
SciTokens-configured stock `xrootd`; asserts ours == spec and records any
stock divergences into
[`docs/10-reference/wlcg-token-differential-findings.md`](../10-reference/wlcg-token-differential-findings.md).
Skips cleanly when a token-validating stock xrootd is not configured.

## 6. Adjacent existing coverage

Some profile areas are covered by pre-existing suites rather than the
conformance families: **L1/L2 token cache** (`tests/test_token_cache_l1.py`),
**JWKS hot-reload / key rotation** (`tests/test_token_jwks_refresh.py`),
**macaroons + caveats** (`tests/test_token_macaroon.py`), and **query-token
redaction** (`tests/test_query_token.py`). `jti`/replay is **not** enforced
(there is no replay cache) — a token may be presented repeatedly until `exp`;
this is by design and noted here for completeness. Group-based authorization
(`wlcg.groups`) requires a group-strategy issuer plus a VO ACL and is exercised
through the VO/ACL subsystem, not these families.

## 7. Running it

```bash
# Layer 1 (fast, no fleet)
tests/run_token_conformance.sh

# Layer 2 (needs the fleet: tests/manage_test_servers.sh start-all)
PYTHONPATH=tests pytest tests/test_wlcg_token_conformance_*.py -v

# Layer 3 (opt-in)
TEST_TOKEN_DIFF=1 tests/run_token_differential.sh
```

The conformance families carry the `conformance` filename hint, so they are in
the `--nightly` slow tier; the fast per-file runs above are the iteration path.
