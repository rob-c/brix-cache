# WLCG Token Conformance Suite — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build a ~152-case WLCG bearer-token conformance suite (3 layers: C unit, pytest e2e across root://+WebDAV+S3, differential-vs-stock), and fix every real bug it exposes.

**Architecture:** A single Python fixture forge (`tests/tokenforge.py`, extending `utils/make_token.py`) mints every token/JWKS/registry artifact and writes a `token_manifest.json` that is the single source of truth `{case_id, mint_recipe, protocol, expected, expected_reason, spec_ref}`. Layer-1 C tests link the ngx-free token core (`scopes.c`, `b64url.c`, `json.c`) standalone. Layer-2 pytest tests are manifest-parametrized against the live fleet. Fixes are **TDD-driven** — write the failing case, run it, fix only where red.

**Tech Stack:** C (nginx module, OpenSSL EVP), Python 3 (`cryptography`, `requests`, pytest), bash runners. Spec: `docs/superpowers/specs/2026-07-06-wlcg-token-conformance-design.md`.

## Global Constraints

- **NO `goto`** anywhere in `src/`, `shared/`, `client/`. Early-return + helper decomposition only.
- **Use HELPERS, never reimplement** path/auth/metrics/framing. Token validation is `brix_token_validate()`; scope checks are `brix_token_check_read/_write`; never hand-roll JWT parsing outside `src/auth/token/`.
- **3 tests per code change**: success + error + security-negative.
- **INVARIANT §6**: S3 SigV4 ≠ WLCG token — never share auth logic; the two paths are mutually exclusive per request.
- **INVARIANT §4**: all wire paths → `resolve_path()` before `open()`; scope checks use the *logical* (post-resolve, traversal-collapsed) path.
- **Config directive recipe**: field in `config.h` (`NGX_CONF_UNSET`) → `ngx_command_t` in the directive table → merge in `merge_*_conf()`. No `./configure` unless a new top-level block or new source file.
- **New source file ⇒** add to repo-root `./config`, then `rm -rf objs && ./configure --with-stream --with-stream_ssl_module --with-http_ssl_module --with-http_dav_module --with-threads --add-module=$REPO && make -j$(nproc)` (configure over stale objs = mixed-ABI SIGSEGV).
- **Build (incremental):** `make -j$(nproc)`. **Validate:** `/tmp/nginx-1.28.3/objs/nginx -t -c /tmp/xrd-test/conf/nginx.conf`.
- **Test fleet:** `tests/manage_test_servers.sh restart`; attach-don't-wipe conftest rule; `TEST_OWN_FLEET=1` for a clean restart. Serial-only suites must not run under xdist concurrently with PKI-wiping suites.
- **Ports:** root:// token = 11097, WebDAV HTTPS = 8443, S3 = 9001. Token dir = `{TOKENS_DIR}` = `/tmp/xrd-test/tokens`, JWKS = `{TOKEN_DIR}/jwks.json`.
- **Commit to `main` directly** (no feature branches — user preference). Commit messages end with the two trailers from the harness guide.
- **Case IDs**: `SIG-* CLM-* ISS-* AUD-* SCP-* GRP-* PROTO-* VER-* CACHE-* ROT-* MAC-* TPC-* RT-*`; every case ID appears in the manifest AND the test name.

---

## File Structure

**New files:**
- `tests/tokenforge.py` — fixture forge: hostile-token mint + JWKS/registry writers + `token_manifest.json` emitter. Imports and extends `utils/make_token.TokenIssuer`.
- `tests/c/token_scope_unittest.c` — Layer-1 scope/version precision (~30 cases).
- `tests/c/token_conformance_test.c` — Layer-1 signature/claims/aud precision (~35 cases).
- `tests/run_token_conformance.sh` — Layer-1 runner (mirrors `run_cvmfs_core_unit.sh`).
- `tests/test_wlcg_token_conformance_signature.py` — SIG (~20).
- `tests/test_wlcg_token_conformance_claims.py` — CLM (~18).
- `tests/test_wlcg_token_conformance_issuer.py` — ISS (~15).
- `tests/test_wlcg_token_conformance_audience.py` — AUD (~10).
- `tests/test_wlcg_token_conformance_scope.py` — SCP (~22).
- `tests/test_wlcg_token_conformance_proto.py` — PROTO (~15) + GRP (~8).
- `tests/test_wlcg_token_conformance_rotation.py` — ROT (~10) + CACHE (~8).
- `tests/test_wlcg_token_conformance_runtime.py` — MAC (~8) + TPC (~6) + RT (~6).
- `tests/lib/tokenconf.py` — shared pytest helpers (manifest loader, root:// ztn client, WebDAV/S3 bearer request helpers, verdict asserter).
- `tests/run_token_differential.sh` — Layer-3 opt-in (`TEST_TOKEN_DIFF=1`).
- `src/protocols/s3/auth_bearer.c` — S3 WLCG bearer auth (new).
- `docs/09-developer-guide/wlcg-token-conformance.md` — trust-model doc.
- `docs/10-reference/wlcg-token-differential-findings.md` — generated golden.

**Modified files:**
- `src/core/types/tunables.h` — keep `BRIX_TOKEN_CLOCK_SKEW_SECS` as the default only.
- `src/core/config/config.h`, `src/core/config/directives.c`, `src/core/config/server_conf.c` — `token_clock_skew` field/command/merge (root://).
- `src/protocols/webdav/module.c` — `brix_token_clock_skew` on the WebDAV table.
- `src/auth/token/token.h`, `validate.c` — thread `clock_skew` param; `kid`-less multi-key fallback.
- `src/auth/token/token_internal.h` — plumb skew to the temporal check.
- `src/protocols/s3/module.c`, `src/protocols/s3/s3.h` (loc conf), `src/protocols/s3/handler.c`, `src/protocols/s3/auth_sigv4_verify.c` — S3 bearer dispatch + directives.
- `tests/configs/nginx_shared.conf` — multi-issuer root:// + WebDAV blocks, S3 token block, ES256/second-key JWKS, `scitokens.cfg`.
- `tests/manage_test_servers.*` / `tests/lib/dedicated.sh` — forge invocation + extra JWKS/registry artifacts at fleet start.
- `pytest.ini` — register the `tokenconf` marker.
- `config` — add `src/protocols/s3/auth_bearer.c` to S3 srcs.

---

## Phase 1 — Fixture forge + manifest

### Task 1: `tokenforge.py` core mint + manifest skeleton

**Files:**
- Create: `tests/tokenforge.py`
- Test: `tests/c/` not involved yet; validated by a throwaway `python3 -c` smoke (Step 2).

**Interfaces:**
- Consumes: `utils.make_token.TokenIssuer` (`init_keys()`, `generate(sub, scope, groups, lifetime, audience, issuer)`, `_sign_jwt(header, payload)`, `DEFAULT_ISSUER`, `DEFAULT_AUDIENCE`, `DEFAULT_KID`).
- Produces:
  - `class TokenForge(TokenIssuer)` with methods returning JWT strings:
    `alg_none()`, `alg_hs256_confusion()`, `alg_lowercase()`, `alg_unsupported(alg="RS384")`,
    `wrong_kid(kid="nope")`, `no_kid()`, `truncated_sig()`, `oversized(nbytes=9000)`,
    `malformed_json()`, `not_a_jwt()`,
    `temporal(exp_delta, nbf_delta=0, iat_delta=0)`, `exp_string()`, `missing_exp()`,
    `aud_value(aud)` (accepts str or list), `scope(scope_str)`, `no_scope()`,
    `wlcg_ver(ver)` (None omits), `groups(groups_list)`, `with_jti(jti)`,
    `for_issuer(issuer, kid=None)` (mint under an arbitrary iss).
  - `write_jwks(path, keys=[...])` — write a multi-key JWKS (RSA and/or EC entries, distinct `kid`s).
  - `write_scitokens_cfg(path, issuers=[{name, issuer, audience, base_paths, restricted_paths, jwks_path, strategy}])`.
  - `Manifest` class: `.add(case_id, mint_recipe, protocol, expected, expected_reason, spec_ref)` and `.write(path)`.

- [ ] **Step 1: Write the smoke test (inline, run in Step 2)** — none as a file yet; the deliverable is exercised by Step 2's command.

- [ ] **Step 2: Implement `tokenforge.py`**

```python
"""WLCG token conformance fixture forge.

Extends utils.make_token.TokenIssuer into a full hostile-token mint. Every
minted artifact is described by a manifest row so the C and pytest layers
share one verdict source. See docs/superpowers/specs/2026-07-06-wlcg-token-
conformance-design.md.
"""
import base64
import json
import os
import time

from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.hazmat.primitives import hashes, serialization

import sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from utils.make_token import TokenIssuer


def _b64url(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def _seg(obj) -> str:
    return _b64url(json.dumps(obj, separators=(",", ":")).encode("utf-8"))


class TokenForge(TokenIssuer):
    """A TokenIssuer that can also emit deliberately-malformed tokens."""

    def _base_claims(self, **over):
        now = int(time.time())
        c = {
            "iss": self.issuer, "sub": "conformance", "aud": self.audience,
            "exp": now + 3600, "iat": now, "nbf": now,
            "scope": "storage.read:/", "wlcg.ver": "1.0",
        }
        c.update(over)
        return c

    # --- signature / algorithm ---------------------------------------
    def alg_none(self):
        h = {"alg": "none", "typ": "JWT"}
        return _seg(h) + "." + _seg(self._base_claims()) + "."

    def alg_hs256_confusion(self):
        # Sign with HMAC keyed on the RSA *public* key PEM — the classic
        # confusion attack. A correct verifier rejects because alg!=RS256/ES256.
        import hmac, hashlib
        h = {"alg": "HS256", "typ": "JWT", "kid": self.DEFAULT_KID}
        signing_input = (_seg(h) + "." + _seg(self._base_claims())).encode()
        pub_pem = self._key.public_key().public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo)
        sig = hmac.new(pub_pem, signing_input, hashlib.sha256).digest()
        return signing_input.decode() + "." + _b64url(sig)

    def alg_lowercase(self):
        h = {"alg": "rs256", "typ": "JWT", "kid": self.DEFAULT_KID}
        return self._sign_with_header(h, self._base_claims())

    def alg_unsupported(self, alg="RS384"):
        h = {"alg": alg, "typ": "JWT", "kid": self.DEFAULT_KID}
        # Still RSA-sign so only the alg string is "wrong".
        return self._sign_with_header(h, self._base_claims())

    def wrong_kid(self, kid="nope"):
        h = {"alg": "RS256", "typ": "JWT", "kid": kid}
        return self._sign_with_header(h, self._base_claims())

    def no_kid(self):
        h = {"alg": "RS256", "typ": "JWT"}
        return self._sign_with_header(h, self._base_claims())

    def truncated_sig(self):
        tok = self.generate()
        h, p, s = tok.split(".")
        return h + "." + p + "." + s[: len(s) // 2]

    # --- structure / claims ------------------------------------------
    def oversized(self, nbytes=9000):
        return self._sign_with_header(
            {"alg": "RS256", "typ": "JWT", "kid": self.DEFAULT_KID},
            self._base_claims(pad="x" * nbytes))

    def malformed_json(self):
        h = _seg({"alg": "RS256", "typ": "JWT", "kid": self.DEFAULT_KID})
        bad = _b64url(b'{"iss":"x", not json]')
        return h + "." + bad + "." + _b64url(b"\x00" * 32)

    def not_a_jwt(self):
        return "this.is.not-base64url-\x01"

    def temporal(self, exp_delta, nbf_delta=0, iat_delta=0):
        now = int(time.time())
        return self._sign_with_header(
            {"alg": "RS256", "typ": "JWT", "kid": self.DEFAULT_KID},
            self._base_claims(exp=now + exp_delta, nbf=now + nbf_delta,
                              iat=now + iat_delta))

    def exp_string(self):
        return self._sign_with_header(
            {"alg": "RS256", "typ": "JWT", "kid": self.DEFAULT_KID},
            self._base_claims(exp=str(int(time.time()) + 3600)))

    def missing_exp(self):
        c = self._base_claims()
        c.pop("exp")
        return self._sign_with_header(
            {"alg": "RS256", "typ": "JWT", "kid": self.DEFAULT_KID}, c)

    # --- audience / scope / version ----------------------------------
    def aud_value(self, aud):
        return self._sign_with_header(
            {"alg": "RS256", "typ": "JWT", "kid": self.DEFAULT_KID},
            self._base_claims(aud=aud))

    def scope(self, scope_str):
        return self._sign_with_header(
            {"alg": "RS256", "typ": "JWT", "kid": self.DEFAULT_KID},
            self._base_claims(scope=scope_str))

    def no_scope(self):
        c = self._base_claims()
        c.pop("scope")
        return self._sign_with_header(
            {"alg": "RS256", "typ": "JWT", "kid": self.DEFAULT_KID}, c)

    def wlcg_ver(self, ver):
        c = self._base_claims()
        if ver is None:
            c.pop("wlcg.ver", None)
        else:
            c["wlcg.ver"] = ver
        return self._sign_with_header(
            {"alg": "RS256", "typ": "JWT", "kid": self.DEFAULT_KID}, c)

    def groups(self, groups_list):
        return self._sign_with_header(
            {"alg": "RS256", "typ": "JWT", "kid": self.DEFAULT_KID},
            self._base_claims(**{"wlcg.groups": groups_list}))

    def with_jti(self, jti):
        return self._sign_with_header(
            {"alg": "RS256", "typ": "JWT", "kid": self.DEFAULT_KID},
            self._base_claims(jti=jti))

    def for_issuer(self, issuer, kid=None):
        h = {"alg": "RS256", "typ": "JWT"}
        if kid:
            h["kid"] = kid
        return self._sign_with_header(h, self._base_claims(iss=issuer))

    # --- signing helper: RSA-sign an arbitrary (header, payload) ------
    def _sign_with_header(self, header, payload):
        signing_input = (_seg(header) + "." + _seg(payload)).encode("ascii")
        sig = self._key.sign(signing_input, padding.PKCS1v15(),
                             hashes.SHA256())
        return signing_input.decode("ascii") + "." + _b64url(sig)


class Manifest:
    def __init__(self):
        self.rows = []

    def add(self, case_id, mint_recipe, protocol, expected,
            expected_reason, spec_ref):
        assert expected in ("accept", "reject")
        self.rows.append({
            "case_id": case_id, "mint_recipe": mint_recipe,
            "protocol": protocol, "expected": expected,
            "expected_reason": expected_reason, "spec_ref": spec_ref,
        })

    def write(self, path):
        with open(path, "w") as fh:
            json.dump({"cases": self.rows}, fh, indent=2, sort_keys=True)
```

- [ ] **Step 3: Smoke-run the forge**

Run:
```bash
cd /home/rcurrie/HEP-x/nginx-xrootd
python3 utils/make_token.py init /tmp/tf-smoke
python3 - <<'PY'
import sys; sys.path.insert(0, "tests")
from tokenforge import TokenForge
f = TokenForge("/tmp/tf-smoke"); f.init_keys()
for name in ("alg_none","alg_hs256_confusion","alg_lowercase","no_kid",
             "truncated_sig","oversized","malformed_json","exp_string"):
    t = getattr(f, name)()
    assert t.count(".") in (1, 2), (name, t[:40])
    print("ok", name, len(t))
print("ok generate", len(f.generate()))
PY
```
Expected: `ok alg_none ...` through `ok generate ...`, exit 0.

- [ ] **Step 4: Commit**

```bash
git add tests/tokenforge.py && git commit -m "test(token): tokenforge fixture mint for WLCG conformance

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_01HoHKtMqVkR3mhMCWyNLMfQ"
```

### Task 2: Manifest generation entrypoint + INI-key verification

> NOTE (plan amendment, post-Task-1 review): `write_jwks`, `write_scitokens_cfg`, `_rsa_jwk`, and `_ec_jwk` were ALREADY added to `tests/tokenforge.py` in Task 1 (commit 6883728) to resolve the interface seam. Task 2 is now ONLY the manifest builder + verifying the scitokens INI keys against the real C parser (and fixing the emitter if they differ).

**Files:**
- Modify: `tests/tokenforge.py`

**Interfaces:**
- Consumes: `TokenForge`, `Manifest`, `write_jwks`, `write_scitokens_cfg` (all already in `tokenforge.py` from Task 1).
- Produces: module-level `def build_manifest(out_dir) -> str` that mints the full case set and writes `token_manifest.json`; returns its path. A `__main__` `manifest <out_dir>` subcommand.

- [ ] **Step 1: Verify the scitokens INI keys against the real parser and fix the emitter if wrong.**

Run: `grep -nE '"(issuer|audience|base_path|restricted_path|jwks|authz|strategy)' src/auth/token/issuer_registry.c src/auth/token/ini.c`

The `write_scitokens_cfg` emitter (already in `tokenforge.py`) uses keys `issuer`, `audience`, `base_path`, `restricted_path`, `jwks_file`, `authz_strategy` and section header `[Issuer <name>]`. Compare against what the C parser actually accepts and **edit the emitter in `tokenforge.py` to the real keys** if any differ. This is the one place a wrong string silently disables the registry — treat a mismatch as a required fix, and record the confirmed keys in a comment above `write_scitokens_cfg`.

- [ ] **Step 2: Add `build_manifest()`** — enumerate every case ID with its recipe. (Full list below; abbreviated here — the implementer copies each family's case rows from the family test tasks, which own the canonical list.)

```python
def build_manifest(out_dir):
    os.makedirs(out_dir, exist_ok=True)
    f = TokenForge(out_dir)
    if not os.path.exists(f.key_path):
        f.init_keys()
    m = Manifest()
    # SIG family (see Task 8) — representative rows:
    m.add("SIG-01", {"m": "alg_none"}, "all", "reject",
          "alg=none blocked before verify", "spec §2, RFC8725")
    m.add("SIG-02", {"m": "alg_hs256_confusion"}, "all", "reject",
          "HS256-with-RSA-pubkey confusion", "spec §2, RFC8725")
    m.add("SIG-03", {"m": "alg_lowercase"}, "all", "reject",
          "alg is case-sensitive", "RFC7515 §4.1.1")
    # ... all families appended by their respective test tasks ...
    m.write(os.path.join(out_dir, "token_manifest.json"))
    return os.path.join(out_dir, "token_manifest.json")


if __name__ == "__main__":
    import argparse
    ap = argparse.ArgumentParser()
    ap.add_argument("cmd", choices=["manifest"])
    ap.add_argument("out_dir")
    args = ap.parse_args()
    print(build_manifest(args.out_dir))
```

- [ ] **Step 3: Verify the registry INI keys against the parser, then run**

Run:
```bash
cd /home/rcurrie/HEP-x/nginx-xrootd
grep -nE '"(issuer|audience|base_path|restricted_path|jwks|authz|strategy)' src/auth/token/issuer_registry.c src/auth/token/ini.c
python3 tests/tokenforge.py manifest /tmp/tf-manifest && python3 -c "import json;print(len(json.load(open('/tmp/tf-manifest/token_manifest.json'))['cases']),'cases')"
```
Expected: prints the INI keys, then `token_manifest.json` path, then a case count.

- [ ] **Step 4: Commit**

```bash
git add tests/tokenforge.py && git commit -m "test(token): JWKS/scitokens writers + manifest builder

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_01HoHKtMqVkR3mhMCWyNLMfQ"
```

---

## Phase 2 — Layer-1 C unit tests

### Task 3: `run_token_conformance.sh` + empty unit harness compiling green

**Files:**
- Create: `tests/run_token_conformance.sh`, `tests/c/token_scope_unittest.c`, `tests/c/token_conformance_test.c`

**Interfaces:**
- Consumes: ngx-free `src/auth/token/scopes.c` (`brix_token_parse_scopes`, `brix_token_check_read/_write`, `brix_token_scope_path_matches`), `b64url.c`, `json.c`. Signatures per spec §Background; structs `brix_token_scope_t` (`{char path[256]; unsigned read:1,write:1,create:1,modify:1;}`).

- [ ] **Step 1: Write a one-assertion `token_scope_unittest.c`**

```c
/* WLCG token scope conformance — Layer-1 unit (ngx-free). */
#include <stdio.h>
#include <string.h>
#include "auth/token/scopes.h"

static int g_checks, g_failed;
#define CHECK(cond, name) do {                                            \
    g_checks++;                                                           \
    if (cond) { printf("  ok   %s\n", name); }                           \
    else { printf("  FAIL %s (line %d)\n", name, __LINE__); g_failed++; } \
} while (0)

static void test_path_boundary(void)
{
    /* SCP-01: "/data" scope must NOT authorize "/database". */
    CHECK(brix_token_scope_path_matches("/data", "/database") == 0,
          "SCP-01 boundary /data != /database");
    CHECK(brix_token_scope_path_matches("/data", "/data/f") == 1,
          "SCP-02 /data covers /data/f");
    CHECK(brix_token_scope_path_matches("/", "/anything") == 1,
          "SCP-03 root scope covers all");
}

int main(void)
{
    test_path_boundary();
    printf("\n%d checks, %d failed\n", g_checks, g_failed);
    return g_failed ? 1 : 0;
}
```

- [ ] **Step 2: Write a one-assertion `token_conformance_test.c`** (b64url round-trip)

```c
/* WLCG token signature/claims conformance — Layer-1 unit (ngx-free). */
#include <stdio.h>
#include <string.h>
#include "auth/token/b64url.h"

static int g_checks, g_failed;
#define CHECK(cond, name) do {                                            \
    g_checks++;                                                           \
    if (cond) { printf("  ok   %s\n", name); }                           \
    else { printf("  FAIL %s (line %d)\n", name, __LINE__); g_failed++; } \
} while (0)

int main(void)
{
    u_char out[64];
    ssize_t n = b64url_decode("aGVsbG8", 7, out, sizeof(out)); /* "hello" */
    CHECK(n == 5 && memcmp(out, "hello", 5) == 0, "b64url decode hello");
    printf("\n%d checks, %d failed\n", g_checks, g_failed);
    return g_failed ? 1 : 0;
}
```
> NOTE: confirm `b64url.h` exposes `b64url_decode` and the `u_char`/`ssize_t` types it uses; if `u_char` isn't typedef'd in the ngx-free header, add `#include <sys/types.h>` and `typedef unsigned char u_char;` guard at the top, matching how `b64url.c` compiles standalone.

- [ ] **Step 3: Write `run_token_conformance.sh`**

```bash
#!/usr/bin/env bash
# Layer-1 WLCG token conformance: compile the ngx-free token core standalone
# and run the two unit binaries. Mirrors tests/run_cvmfs_core_unit.sh.
set -euo pipefail
cd "$(dirname "$0")/.."
CC=${CC:-gcc}
FLAGS="-Wall -Wextra -Werror -I src"
DEPS_SCOPE="src/auth/token/scopes.c"
DEPS_SIG="src/auth/token/b64url.c src/auth/token/json.c"

echo "== token_scope_unittest =="
$CC $FLAGS -o /tmp/token_scope_ut tests/c/token_scope_unittest.c $DEPS_SCOPE -lcrypto
/tmp/token_scope_ut

echo "== token_conformance_test =="
$CC $FLAGS -o /tmp/token_conformance_ut tests/c/token_conformance_test.c $DEPS_SIG -lcrypto
/tmp/token_conformance_ut

echo "ALL TOKEN CONFORMANCE UNIT TESTS PASSED"
```

- [ ] **Step 4: Run it — expect green**

Run: `chmod +x tests/run_token_conformance.sh && tests/run_token_conformance.sh`
Expected: both binaries print `0 failed`, final `ALL TOKEN CONFORMANCE UNIT TESTS PASSED`. If `json.c` needs `-ljansson`, append it to `DEPS_SIG` link line.

- [ ] **Step 5: Commit**

```bash
git add tests/run_token_conformance.sh tests/c/token_scope_unittest.c tests/c/token_conformance_test.c
git commit -m "test(token): Layer-1 conformance unit harness (green skeleton)

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_01HoHKtMqVkR3mhMCWyNLMfQ"
```

### Task 4: Fill the ~30 SCP/VER scope unit cases

**Files:** Modify `tests/c/token_scope_unittest.c`

- [ ] **Step 1: Add the full case set** — for each, `CHECK` with the `SCP-NN`/`VER-NN` name. Cover, using `brix_token_parse_scopes` + `brix_token_check_read/_write` + `brix_token_scope_path_matches`:
  - SCP-04..08 read/write/create/modify/stage mapping: parse `"storage.read:/a"`, assert `check_read(...,"/a")==1`, `check_write(...,"/a")==0`; `"storage.write:/a"` → write 1; `"storage.create:/a"` → write 1; `"storage.modify:/a"` → write 1; `"storage.stage:/a"` → read 1, write 0.
  - SCP-09 unknown permission grants nothing: `"storage.bogus:/a"` → read 0 && write 0.
  - SCP-10 empty scope path defaults to `/`: `"storage.read:"` → `check_read(...,"/anything")==1`.
  - SCP-11 missing scope: `parse_scopes("", ...)==0`.
  - SCP-12..14 boundary trio at parse level (`/data` vs `/database`, `/data/` trailing slash normalized, `/data/x` sub-path).
  - SCP-15 read-on-write-only denied; SCP-16 write-on-read-only denied.
  - SCP-17..20 traversal *string* expectations: `check_read(parse("storage.read:/a"), "/a/../b")` — document the expected value: since the C helper does pure prefix matching, `/a/../b` **prefix-matches** `/a` (next char `/`) and would be *granted* at this layer. This proves canonicalization MUST happen upstream (INVARIANT §4). Assert the raw behavior AND add a comment referencing SCP wire cases (Task 12) that prove the resolved path is canonical before this is called.
  - SCP-21,22 `>8` scopes truncation and multiple-scope OR semantics.
  - VER-01..06: `wlcg.ver` is not parsed by `scopes.c`; VER cases live at claims level. Move VER to `token_conformance_test.c` (Task 5) — leave a comment here.

- [ ] **Step 2: Run** `tests/run_token_conformance.sh` — Expected: all SCP cases `ok`, `0 failed`.
- [ ] **Step 3: Commit** (`test(token): SCP scope-precision unit cases`).

### Task 5: Fill the ~35 SIG/CLM/AUD claim+signature unit cases

**Files:** Modify `tests/c/token_conformance_test.c`

- [ ] **Step 1:** These require JSON claim extraction (`json.c`) and (for real verify) the ngx-coupled `validate.c`/`signature.c`. Keep Layer-1 to the *C-reachable halves*:
  - Use `json.c`'s `json_get_string`/number extractor (grep `json.h` for the exact API) to assert: SIG-03 alg case string compare; CLM aud string vs array membership via the same helper `validate.c` uses (`json_string_or_array_contains` — if ngx-free, link it; if not, replicate the pure check by extracting `aud`); CLM exp/nbf arithmetic with a local reimplementation of the skew comparison to lock the intended formula: `now > exp + skew → reject`, `nbf>0 && now < nbf - skew → reject` (the post-fix formula from Task 6).
  - `alg=none`, HS-confusion, kid selection, RS/ES verify are **wire-only** (need EVP + keys) → assert them in Layer-2 (Tasks 8/9). Add a comment listing which SIG-NN are wire-only so the manifest coverage check (Task 16) knows.

- [ ] **Step 2: Run** — Expected `0 failed`.
- [ ] **Step 3: Commit** (`test(token): claim/aud/skew-formula unit cases`).

---

## Phase 3 — The §3 code fixes (TDD; fix only where red)

> Each fix task writes its failing wire test FIRST (in the relevant Layer-2 file, created here and expanded in Phase 5), runs to observe red-or-green, and only edits `src/` if red. Root:// base_path (§3.1) and scope-traversal (§3.5) are *expected green already* (phase-59 W1 + INVARIANT §4) — their tasks lock the behavior as regression tests and note "no src change if green."

### Task 6: `brix_token_clock_skew` directive (§3.2)

**Files:**
- Modify: `src/core/config/config.h`, `src/core/config/directives.c`, `src/core/config/server_conf.c`, `src/protocols/webdav/module.c`, `src/auth/token/token.h`, `src/auth/token/validate.c`, callers of `brix_token_validate` (`src/auth/gsi/token.c`, `src/protocols/webdav/auth_token.c`, `src/auth/token/issuer_registry.c` via `validate_registry_authn`).
- Test: `tests/test_wlcg_token_conformance_claims.py` (create), `tests/c/token_conformance_test.c` (formula).

**Interfaces:**
- Produces: `brix_token_validate(..., int clock_skew, ...)` — new trailing `int clock_skew` parameter (seconds); a config field `token_clock_skew` (default `BRIX_TOKEN_CLOCK_SKEW_SECS`=30, bounded ≤300).

- [ ] **Step 1: Write failing wire tests (CLM skew trio)** in `tests/test_wlcg_token_conformance_claims.py` — using the Task 7 helpers: mint `temporal(exp_delta=-20)` (20s expired). With default skew 30 → **accept**; configure a strict (skew=0) port → **reject**. Also `temporal(nbf_delta=+20)` future-nbf: default skew 30 → accept (post-fix), strict → reject.
- [ ] **Step 2: Run** — Expected FAIL: strict behavior unconfigurable (no directive) and future-nbf currently rejected even within skew (nbf has no skew today).
- [ ] **Step 3: Implement.** Add the field (verify the exact common/token conf struct name first): in `config.h`, `ngx_int_t token_clock_skew;` initialized `NGX_CONF_UNSET`; `ngx_command_t` `brix_token_clock_skew` (`ngx_conf_set_num_slot`) in the root:// auth table and WebDAV table; merge `ngx_conf_merge_value(conf->token_clock_skew, prev->token_clock_skew, BRIX_TOKEN_CLOCK_SKEW_SECS)` and clamp `>300 → config error`. Thread the value as a new `int clock_skew` param through `brix_token_validate` and `brix_token_validate_registry_authn`; replace the two `BRIX_TOKEN_CLOCK_SKEW_SECS` uses in `validate.c:389-404` with the parameter, and apply it to `nbf` too:

```c
if (now > (time_t) claims->exp + clock_skew) { /* ...expired... */ return -1; }
if (claims->nbf > 0 && now < (time_t) claims->nbf - clock_skew) {
    /* ...not yet valid... */ return -1;
}
```
Update every call site to pass the configured skew (S3 bearer added in Task 10 passes it too).

- [ ] **Step 4: Rebuild + run** — `make -j$(nproc)`; restart fleet; `PYTHONPATH=tests pytest tests/test_wlcg_token_conformance_claims.py -k skew -v`. Expected PASS.
- [ ] **Step 5: Update the Layer-1 skew-formula assertions** (Task 5) to the `nbf - skew` form; run `tests/run_token_conformance.sh`.
- [ ] **Step 6: Commit** (`fix(token): configurable brix_token_clock_skew, apply to nbf`).

### Task 7: pytest shared helpers `tests/lib/tokenconf.py`

**Files:** Create `tests/lib/tokenconf.py`

**Interfaces:**
- Produces:
  - `load_manifest(family=None) -> list[dict]` — reads `{TOKENS_DIR}/token_manifest.json` (built at fleet start), optionally filtered by case-ID prefix.
  - `mint(case_row) -> str` — dispatches `case_row["mint_recipe"]` to a `TokenForge` method, returns the token string.
  - `root_ztn(token, path="/test.txt", write=False) -> (verdict, detail)` — raw root:// handshake→login→auth ztn→(stat or open) on 11097; returns `"accept"`/`"reject"`. (Lift `_raw_handshake`/`_send_login`/`_send_auth_ztn` from `tests/test_token_auth.py` into this shared helper.)
  - `webdav_bearer(token, path="/test.txt", write=False) -> (verdict, detail)` — `requests.get/put` on `https://…:8443` with `Authorization: Bearer`.
  - `s3_bearer(token, key="test.txt", write=False) -> (verdict, detail)` — `requests.get/put` on `http://…:9001` with `Authorization: Bearer`.
  - `assert_verdict(case_row, protocol)` — mints, calls the right client, asserts observed == `case_row["expected"]`, includes `case_id`+`expected_reason` in the assertion message.

- [ ] **Step 1: Implement helpers** (lift the raw root:// framing from `test_token_auth.py`; reuse `requests` pattern from `test_token_aud_array.py`). Map HTTP 200/206 → accept, 401/403 → reject; root:// `kXR_ok` → accept, `kXR_NotAuthorized` → reject.
- [ ] **Step 2: Smoke** — `PYTHONPATH=tests python3 -c "from lib.tokenconf import load_manifest; print(len(load_manifest()))"` after a fleet start (Task 15 wires manifest build). Until then, point at `/tmp/tf-manifest`.
- [ ] **Step 3: Commit** (`test(token): shared conformance client helpers`).

### Task 8: `kid`-less multi-key rotation fallback (§3.3)

**Files:** Modify `src/auth/token/validate.c`; test `tests/test_wlcg_token_conformance_signature.py` + `tests/test_wlcg_token_conformance_rotation.py`.

- [ ] **Step 1: Write failing test (ROT `kid`-less mid-rotation).** Configure an issuer whose JWKS has TWO keys (key-A first/new, key-B second/old, distinct `kid`s). Mint `no_kid()` signed by **key-B** (the second). Present it. Expected accept (post-fix); today `validate.c` picks `keys[0]` (key-A) when `kid` is empty and multi-key, verify fails → reject.
- [ ] **Step 2: Run** — Expected FAIL (rejected).
- [ ] **Step 3: Implement** the try-all-keys loop for the `kid`-absent multi-key case at `validate.c:271-286`. Replace the single-pick with: exact `kid` match stays exact-only; when `kid[0]=='\0'`, attempt verification against each key of matching type until one succeeds; a `kid` that matches no key with `key_count>1` stays a hard reject (no silent fallthrough). Concretely, restructure so signature verification is attempted per candidate key:

```c
/* kid asserted: exactly one candidate (or hard reject). */
if (kid[0] != '\0') {
    pkey = NULL;
    for (i = 0; i < key_count; i++) {
        if (strcmp(keys[i].kid, kid) == 0) { pkey = keys[i].pkey; break; }
    }
    if (pkey == NULL) { /* WARN no key matching kid */ return -1; }
    if (verify(pkey) != OK) return -1;
} else {
    /* kid absent: try every key; accept on first success (rotation grace). */
    int ok = 0;
    for (i = 0; i < key_count; i++) {
        if (verify(keys[i].pkey) == OK) { ok = 1; break; }
    }
    if (!ok) { /* WARN no key verified kid-less token */ return -1; }
}
```
Factor the actual `EVP` verify (already in `signature.c` as `brix_token_verify_rs256`/`_es256`) behind a small local `verify(pkey)` that selects by `alg`. Keep the single-key path a natural case of the loop.

- [ ] **Step 4: Rebuild + run** SIG multi-key cases (`SIG-10..14`: `kid` hit, `kid` miss→reject, `no_kid` single-key accept, `no_kid` multi-key fallback accept, wrong-`kid` multi-key reject). Expected PASS.
- [ ] **Step 5: Commit** (`fix(token): verify kid-less tokens against all JWKS keys (rotation grace)`).

### Task 9: root:// base_path regression lock (§3.1) + scope-traversal lock (§3.5)

**Files:** Test-only: `tests/test_wlcg_token_conformance_issuer.py`, `tests/test_wlcg_token_conformance_scope.py`. Possibly modify `src/protocols/webdav/*` or `src/protocols/s3/auth_bearer.c` if traversal is red there.

- [ ] **Step 1: Write ISS base_path tests.** Two issuers in `scitokens.cfg`: issuer-A `base_path=/atlas`, issuer-B `base_path=/cms`. Mint a valid token from issuer-A with `scope=storage.read:/` . Request `/cms/secret` on root:// (11097-registry port) → Expected **reject** (outside A's base). Request `/atlas/f` → accept.
- [ ] **Step 2: Run** — Likely PASS (phase-59 W1 wires this). If PASS: annotate the test `# regression lock — phase-59 W1`; no src change. If FAIL: the gap is real — check that the registry port has `brix_token_config` set and `ctx->identity` is non-NULL on that path; fix by ensuring `brix_check_token_scope` is reached for the op (it already is for stat/open/dirlist per `query/prepare.c`). Add the missing call at the op that lacks it.
- [ ] **Step 3: Write SCP traversal wire tests** on all three protocols: token `scope=storage.read:/a`, request logical path `/a/../secret`. Expected **reject** on every surface (path canonicalized to `/secret`, not under `/a`). root:// additionally blocks dot-dot at `has_forbidden_component`.
- [ ] **Step 4: Run** — root:// expected PASS (forbidden-component). WebDAV/S3: if red, the handler scope-checks a pre-canonical path — fix to scope-check the post-`resolve_path` logical path. Re-run.
- [ ] **Step 5: Commit** (`test(token): lock root:// base_path + scope-traversal conformance` [+ fix if any]).

---

## Phase 4 — S3 bearer feature (§3.4)

### Task 10: S3 WLCG bearer auth path + directives

**Files:**
- Create: `src/protocols/s3/auth_bearer.c`
- Modify: `src/protocols/s3/s3.h` (loc conf fields), `src/protocols/s3/module.c` (directives + merge), `src/protocols/s3/auth_sigv4_verify.c` or `handler.c` (dispatch), `config` (add src), `tests/configs/nginx_shared.conf` (S3 token block).
- Test: `tests/test_wlcg_token_conformance_proto.py` (S3 rows).

**Interfaces:**
- Consumes: `brix_token_validate(log, token, len, keys, key_count, iss, aud, NULL, 0, clock_skew, &claims)`; `brix_token_check_read/_write`; `s3ctx->identity` (`brix_identity_t`); the S3 method→op mapping (GET/HEAD/List=read; PUT/POST/multipart/DELETE=write); bucket+key→export path resolver already in the handler.
- Produces: `ngx_int_t s3_verify_bearer(ngx_http_request_t *r, ngx_http_s3_loc_conf_t *cf, brix_identity_t *identity)` returning `NGX_OK` (authenticated; scope enforced later per-op) / an error response; and `int s3_bearer_present(ngx_http_request_t *r)`.

- [ ] **Step 1: Write failing e2e tests** (S3 bearer accept + reject + SigV4-still-works + blended-credential-rejected) in `tests/test_wlcg_token_conformance_proto.py` against port 9001 once the S3 block has token config. Use `tokenconf.s3_bearer`.
- [ ] **Step 2: Run** — Expected FAIL (S3 ignores bearer; anonymous or 403).
- [ ] **Step 3: Add loc-conf fields + directives.** In `s3.h` loc conf: `ngx_str_t token_jwks; ngx_str_t token_issuer; ngx_str_t token_audience; ngx_str_t token_config; ngx_flag_t token_enable;` and `brix_jwks_key_t jwks_keys[BRIX_MAX_JWKS_KEYS]; int jwks_key_count; void *token_registry;`. In `module.c` add `brix_s3_token_jwks/_issuer/_audience/_config` (`ngx_conf_set_str_slot`) + `brix_s3_token` flag; load JWKS/registry in the S3 postconfig the same way root:// does (reuse `brix_token_jwks_load`/registry loader — grep for the loader used by `keys.c`/`issuer_registry.c` and call it from S3 init). Add `src/protocols/s3/auth_bearer.c` to the S3 `ngx_module_srcs` in `./config`.
- [ ] **Step 4: Implement `auth_bearer.c`.** `s3_bearer_present` = Authorization header starts `Bearer `. `s3_verify_bearer`: extract token, call `brix_token_validate` (single-issuer) or `brix_token_validate_registry_authn` (if `token_config`), populate `identity` via `brix_identity_set_token_claims` + set `token_issuer` when via registry (mirror `src/auth/gsi/token.c:178-190`), set `auth_method` (a new `BRIX_AUTHN_TOKEN` on the S3 identity). Return `NGX_OK`; the per-op scope check calls `brix_identity_check_token_scope(identity, object_path, need_write)` at the point S3 resolves the object path — add that call in the S3 op dispatch for GET/PUT/DELETE/List. On reject → `s3_send_xml_error(r, 403, "AccessDenied", ...)`.
- [ ] **Step 5: Wire dispatch (mutually exclusive).** In `s3_verify_sigv4` (auth_sigv4_verify.c:358) or at handler.c:403: if `s3_bearer_present(r)` and no SigV4 `Credential=`, route to `s3_verify_bearer` and return; if BOTH a `Bearer` and a SigV4 `Authorization` somehow appear, reject (`400 InvalidRequest`) — never blend (INVARIANT §6).
- [ ] **Step 6: Add S3 token block to `nginx_shared.conf`** (port 9001 location): `brix_s3_token on; brix_s3_token_jwks {TOKEN_DIR}/jwks.json; brix_s3_token_issuer "https://test.example.com"; brix_s3_token_audience "nginx-xrootd";` plus a second S3 server on a new port with `brix_s3_token_config {TOKEN_DIR}/scitokens.cfg` for multi-issuer S3 (add the port to `settings.py`).
- [ ] **Step 7: Rebuild (new src ⇒ full reconfigure).** `rm -rf /tmp/nginx-1.28.3/objs && (cd /tmp/nginx-1.28.3 && ./configure --with-stream --with-stream_ssl_module --with-http_ssl_module --with-http_dav_module --with-threads --add-module=/home/rcurrie/HEP-x/nginx-xrootd) && make -j$(nproc) -C /tmp/nginx-1.28.3`. `nginx -t`. Restart fleet.
- [ ] **Step 8: Run** the S3 bearer tests. Expected PASS (accept, reject-out-of-scope, SigV4 unaffected, blended rejected).
- [ ] **Step 9: Commit** (`feat(s3): WLCG bearer-token authorization alongside SigV4`).

---

## Phase 5 — Layer-2 pytest e2e (manifest-parametrized, all families)

> Each family task: (a) append its case rows to `tokenforge.build_manifest`, (b) write the parametrized test that loads `load_manifest("PREFIX")` and calls `assert_verdict(row, proto)` for each applicable protocol, (c) run, (d) triage failures — a failure is either a bug (fix in a follow-up task) or a wrong `expected` in the manifest (fix the manifest with justification). Register the `tokenconf` marker once (Task 11).

### Task 11: Register marker + fleet manifest wiring

**Files:** Modify `pytest.ini`, `tests/lib/dedicated.sh` (or `manage_test_servers`), `tests/conftest.py`.

- [ ] **Step 1:** Add to `pytest.ini` markers: `tokenconf: WLCG token conformance suite (manifest-parametrized)`. Note the conftest slow auto-marker already matches `conformance` in the filename → these land in `--nightly`; add a fast subset via a `-k "not slow"`-safe design (mark only the heavy multi-issuer/rotation cases; keep a core subset unmarked for `--pr`). Simplest: let the whole family be slow (auto), and add an explicit `@pytest.mark.tokenconf` core smoke in each file that is NOT slow — but since filename contains `conformance`, ALL are auto-slow. To get a PR-tier subset, put the ~12-case smoke in a differently-named file `tests/test_token_conformance_smoke.py` OR accept nightly-only. Decision: **nightly-only for the full 152; a 12-case smoke in `test_token_conformance_smoke.py` for `--pr`.** Document in the file header.
- [ ] **Step 2:** In `dedicated.sh` fleet start, after token init, build the manifest and extra artifacts: `python3 tests/tokenforge.py manifest "${main_tokens_dir}"` and write `jwks_multi.json`, `jwks_ec.json`, `scitokens.cfg` into `${main_tokens_dir}` (call a new `tokenforge.py fleet-artifacts <dir>` subcommand that writes them). Add the multi-issuer root:// server + registry port to `nginx_shared.conf` and `settings.py`.
- [ ] **Step 3:** Run `tests/manage_test_servers.sh restart` and confirm the new ports listen (`ss -tlnp | grep -E '11097|8443|9001'` + the registry port) and `token_manifest.json` exists.
- [ ] **Step 4: Commit** (`test(token): register tokenconf marker + fleet manifest artifacts`).

### Task 12: SIG family wire tests (~20)

**Files:** `tests/test_wlcg_token_conformance_signature.py`; append SIG rows in `tokenforge.build_manifest`.

- [ ] **Step 1:** Manifest rows SIG-01..20 (alg=none, HS-confusion, alg-lowercase, alg-unsupported RS384/PS256, kid hit/miss, no_kid single & multi (§3.3), wrong-kid multi reject, truncated sig, bad sig, ES256 accept on **root://**+WebDAV+S3, ES256 corrupted). Set `protocol: "all"` where the recipe is protocol-agnostic; the test expands `all` → each of root/webdav/s3.
- [ ] **Step 2:** Write the parametrized test:

```python
import pytest
from lib.tokenconf import load_manifest, assert_verdict, PROTOCOLS

@pytest.mark.tokenconf
@pytest.mark.parametrize("row,proto", [
    (r, p) for r in load_manifest("SIG")
           for p in (PROTOCOLS if r["protocol"] == "all" else [r["protocol"]])
], ids=lambda x: x if isinstance(x, str) else x["case_id"])
def test_sig(row, proto):
    assert_verdict(row, proto)
```

- [ ] **Step 3: Run** `PYTHONPATH=tests pytest tests/test_wlcg_token_conformance_signature.py -v`. Triage each failure (bug vs manifest). ES256-on-root:// is the likely find — if root:// rejects ES256 that WebDAV accepts, that's a real asymmetry to fix in the root:// verify path; open a fix sub-task mirroring Task 8's structure.
- [ ] **Step 4: Commit** (`test(token): SIG family wire conformance (~20)`).

### Task 13: CLM (~18) + AUD (~10) wire tests

**Files:** `tests/test_wlcg_token_conformance_claims.py` (extend from Task 6), `tests/test_wlcg_token_conformance_audience.py`.

- [ ] **Step 1:** Manifest CLM-01..18 (exp==now boundary, expired beyond skew, expired within skew accept, nbf future beyond/within skew, missing exp, string exp, oversized, malformed JSON, not-a-jwt, iat-in-future sanity) and AUD-01..10 (scalar match/mismatch, array-member first/middle/last, empty array, missing aud, multi-audience config accept, wrong aud). Each `protocol: "all"`.
- [ ] **Step 2:** Parametrized tests mirroring Task 12.
- [ ] **Step 3: Run + triage.** AUD array on root://+S3 is a likely find (array tested only on WebDAV today) — if root:// or S3 mishandles array aud, fix in `validate.c` aud handling (it already supports arrays per `json_string_or_array_contains`; more likely a protocol wiring gap).
- [ ] **Step 4: Commit** (`test(token): CLM+AUD family wire conformance`).

### Task 14: SCP (~22) + GRP (~8) + VER (~6) wire tests

**Files:** `tests/test_wlcg_token_conformance_scope.py` (extend Task 9), `tests/test_wlcg_token_conformance_proto.py` (GRP).

- [ ] **Step 1:** Manifest SCP wire rows (read/write/create/modify/stage enforcement per surface, boundary, traversal (§3.5), empty-path, missing-scope-denies-all, unknown-perm, read-on-write-only, write-on-read-only, sub-path), GRP rows (group→ACL accept when VO ACL grants, empty-groups reject under group strategy), VER rows (wlcg.ver present accept, missing → document behavior, `2.0` → document).
- [ ] **Step 2:** Parametrized tests; write cases need `brix_allow_write on` ports.
- [ ] **Step 3: Run + triage.** VER handling is likely *not enforced* today (wlcg.ver isn't validated) — decide expected: accept-regardless (document as intended, WLCG profile does not mandate rejection of unknown minor versions) OR enforce. Default: **accept-regardless, documented**; manifest `expected: accept` with reason "wlcg.ver advisory".
- [ ] **Step 4: Commit** (`test(token): SCP+GRP+VER family wire conformance`).

### Task 15: PROTO (~15) wire tests

**Files:** `tests/test_wlcg_token_conformance_proto.py` (extend Tasks 10/14).

- [ ] **Step 1:** Manifest PROTO rows: query `?authz=` accept (WebDAV), `?access_token=` accept (WebDAV), Bearer-prefix vs raw token, header-vs-query precedence, root:// query-param **documented reject** (no query support), S3 bearer accept/reject (§3.4), S3 SigV4-still-works, blended-credential reject, token-in-body **documented reject**.
- [ ] **Step 2:** Tests with per-protocol `expected`.
- [ ] **Step 3: Run + triage.**
- [ ] **Step 4: Commit** (`test(token): PROTO family (query/header/S3 parity)`).

### Task 16: ROT (~10) + CACHE (~8) + MAC (~8) + TPC (~6) + RT (~6)

**Files:** `tests/test_wlcg_token_conformance_rotation.py` (extend Task 8), `tests/test_wlcg_token_conformance_runtime.py`.

- [ ] **Step 1:** Manifest rows: ROT (JWKS hot-reload accept-new/reject-old, kid-less mid-rotation (§3.3), corrupt-JWKS keeps old keys, macaroon secret grace), CACHE (L1 hit consistency, distinct-token isolation, expiry eviction, registry-bypasses-cache), MAC (path/activity caveat enforce, expiry, wrong-secret reject), TPC (read-src+write-dst scope, token-exchange mode parse), RT (concurrent validation N-threads same token, reload mid-flight, jti replay documented).
- [ ] **Step 2:** Tests; rotation/reload cases use `TEST_OWN_FLEET=1` serial + file edits + `nginx -s reload` (or the mtime-poll refresh interval). Mark `serial`.
- [ ] **Step 3: Run + triage.** jti replay is almost certainly not enforced — document as accept-with-note unless a replay cache exists.
- [ ] **Step 4:** Add the **manifest coverage check** — a tiny test `test_token_conformance_coverage.py` asserting every manifest `case_id` appears in exactly one collected test and total ≥120. Run it.
- [ ] **Step 5: Commit** (`test(token): ROT+CACHE+MAC+TPC+RT families + coverage guard`).

---

## Phase 6 — Layer-3 differential

### Task 17: `run_token_differential.sh` (opt-in)

**Files:** Create `tests/run_token_differential.sh`, `docs/10-reference/wlcg-token-differential-findings.md` (generated).

- [ ] **Step 1:** Write the runner: gated on `TEST_TOKEN_DIFF=1`; locates a stock `xrootd`+SciTokens (skip-clean if absent, `BRIX_BIN` override); for each manifest case reachable over root:// `ztn` and `XrdHttp` bearer, run against a stock server configured with the same JWKS/issuer/audience, capture `{ours, xrootd, spec}`.
- [ ] **Step 2:** Assert `ours == spec` for every case (reuse the pytest verdict via a `--collect` JSON dump or re-run the client helpers from a small Python driver invoked by the script). Record `xrootd != spec` into the findings markdown (verdict table + repro).
- [ ] **Step 3: Run** `TEST_TOKEN_DIFF=1 tests/run_token_differential.sh` — Expected: skip-clean message if no stock xrootd; else findings file written and `ours==spec` holds.
- [ ] **Step 4: Commit** (`test(token): differential-vs-stock harness + findings golden`).

---

## Phase 7 — Docs + suite integration + final verification

### Task 18: Developer doc + quick-reference

**Files:** Create `docs/09-developer-guide/wlcg-token-conformance.md`; modify `docs/03-configuration/quick-reference.md`; update `CLAUDE.md` OP→FILE token row if needed.

- [ ] **Step 1:** Write the trust-model doc: validation pipeline order, scope semantics, per-protocol parity table (now symmetric), `brix_token_clock_skew`, S3 bearer, key-rotation behavior, how to run each layer, how to regenerate findings.
- [ ] **Step 2:** Add directive entries (`brix_token_clock_skew`, `brix_s3_token_*`) to quick-reference.
- [ ] **Step 3: Commit** (`docs(token): WLCG token conformance + new directives`).

### Task 19: Final verification pass

- [ ] **Step 1:** `tests/run_token_conformance.sh` → all green.
- [ ] **Step 2:** `tests/manage_test_servers.sh restart` then `PYTHONPATH=tests pytest tests/test_wlcg_token_conformance_*.py tests/test_token_conformance_*.py -p no:cacheprovider -v` (serial for rotation) → all pass or documented xfail=0; confirm coverage guard ≥120.
- [ ] **Step 3:** Regression: `PYTHONPATH=tests pytest tests/test_token_*.py -v` (existing suite) → green.
- [ ] **Step 4:** `tests/run_suite.sh --pr` → green under the <5min gate.
- [ ] **Step 5:** Summarize findings (which §3 items were real bugs vs already-correct; any new asymmetries fixed) in the differential findings doc's intro and in the commit body. Final commit if any doc/manifest tweaks remain.

---

## Self-Review

**Spec coverage:** §3.1 root:// base_path → Task 9 (regression lock, fix-if-red). §3.2 clock skew → Task 6. §3.3 kid-less rotation → Task 8. §3.4 S3 bearer → Task 10. §3.5 traversal → Task 9. Forge/manifest §4 → Tasks 1–2. Layer-1 §5 → Tasks 3–5. Layer-2 §5 → Tasks 11–16. Layer-3 §5 → Task 17. Docs §6 → Task 18. Acceptance §7 → Task 19. All families (SIG/CLM/ISS/AUD/SCP/GRP/PROTO/VER/CACHE/ROT/MAC/TPC/RT) have a task. ✓

**Placeholder scan:** Fixture recipe methods, the skew formula, the kid-loop restructure, and the S3 dispatch are all shown as real code. Two deliberate verify-first NOTEs (registry INI keys; `b64url.h` types) instruct grepping the real symbol before finalizing — these are correctness guards, not placeholders. ✓

**Type consistency:** `TokenForge` methods, `Manifest.add/write`, `load_manifest/mint/assert_verdict/PROTOCOLS`, `brix_token_validate(..., int clock_skew, ...)`, `s3_verify_bearer`/`s3_bearer_present` names are used consistently across tasks. The new `clock_skew` param is introduced in Task 6 and consumed by Tasks 8/10. ✓
