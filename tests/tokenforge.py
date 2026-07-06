"""WLCG token conformance fixture forge.

Extends utils.make_token.TokenIssuer into a full hostile-token mint. Every
minted artifact is described by a manifest row so the C and pytest layers
share one verdict source. See docs/superpowers/specs/2026-07-06-wlcg-token-
conformance-design.md.
"""
import base64
import hashlib
import hmac
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


def _rsa_jwk(pub, kid):
    nums = pub.public_numbers()
    def b(i):
        return _b64url(i.to_bytes((i.bit_length() + 7) // 8, "big"))
    return {"kty": "RSA", "kid": kid, "use": "sig", "alg": "RS256",
            "n": b(nums.n), "e": b(nums.e)}


def _ec_jwk(pub, kid):
    nums = pub.public_numbers()
    size = 32  # P-256
    def b(i):
        return _b64url(i.to_bytes(size, "big"))
    return {"kty": "EC", "kid": kid, "use": "sig", "alg": "ES256",
            "crv": "P-256", "x": b(nums.x), "y": b(nums.y)}


def write_jwks(path, entries):
    """entries: list of (public_key, kid)."""
    keys = []
    for pub, kid in entries:
        if isinstance(pub, ec.EllipticCurvePublicKey):
            keys.append(_ec_jwk(pub, kid))
        else:
            keys.append(_rsa_jwk(pub, kid))
    with open(path, "w") as fh:
        json.dump({"keys": keys}, fh, indent=2)


# Confirmed INI keys (issuer_registry.c reg_kv(), verified 2026-07-06):
#   Section:  [Issuer <name>]  (strncasecmp prefix "Issuer ", len 7)
#   Keys:     issuer, base_path, restricted_path, audience / audience_json,
#             jwks_file, authorization_strategy, map_subject, username_claim,
#             groups_claim, default_user, name_mapfile, onmissing, enabled
#   base_path/restricted_path values: reg_add_list() splits on " ," so a
#     comma-separated list on ONE line is correct — no need to repeat the key.
#   Strategy key: "authorization_strategy" (line 162) NOT "authz_strategy".
#   [Global] only accepts: audience / audience_json.
def write_scitokens_cfg(path, issuers):
    """issuers: list of dicts {name, issuer, audience, base_paths,
    restricted_paths, jwks_path, strategy}. Emits the INI the C registry
    parser (src/auth/token/issuer_registry.c) reads."""
    lines = ["[Global]", "audience = nginx-xrootd", ""]
    for it in issuers:
        lines.append(f"[Issuer {it['name']}]")
        lines.append(f"issuer = {it['issuer']}")
        lines.append(f"audience = {it.get('audience', 'nginx-xrootd')}")
        # reg_add_list() splits on " ," so comma-separated on one line is fine.
        lines.append("base_path = " + ", ".join(it.get("base_paths", ["/"])))
        if it.get("restricted_paths"):
            lines.append("restricted_path = " +
                         ", ".join(it["restricted_paths"]))
        lines.append(f"jwks_file = {it['jwks_path']}")
        # Real key is "authorization_strategy" (issuer_registry.c:162).
        lines.append(
            f"authorization_strategy = {it.get('strategy', 'capability')}")
        lines.append("")
    with open(path, "w") as fh:
        fh.write("\n".join(lines))


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
        h = {"alg": "HS256", "typ": "JWT", "kid": self.DEFAULT_KID}
        signing_input = (_seg(h) + "." + _seg(self._base_claims())).encode()
        pub_pem = self.private_key.public_key().public_bytes(
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
        if kid is not None:
            h["kid"] = kid
        return self._sign_with_header(h, self._base_claims(iss=issuer))

    # --- signing helper: RSA-sign an arbitrary (header, payload) ------
    def _sign_with_header(self, header, payload):
        signing_input = (_seg(header) + "." + _seg(payload)).encode("ascii")
        sig = self.private_key.sign(signing_input, padding.PKCS1v15(),
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


def build_manifest(out_dir):
    """Mint the core representative manifest cases and write token_manifest.json.

    WHAT: Creates out_dir, initialises a TokenForge (generating keys on first
          run), and appends the SIG-family seed rows so the manifest file is
          always valid.  Later family tasks append their own rows by calling
          build_manifest() and extending the result, or by inserting m.add()
          calls between the seed rows and the write() call.
    WHY:  Provides a self-contained entrypoint so CI and the pytest harness can
          confirm the manifest round-trips without needing the full test suite.
    HOW:  Constructs TokenForge → Manifest → writes JSON; returns the manifest
          path so callers can open it directly.
    """
    os.makedirs(out_dir, exist_ok=True)
    f = TokenForge(out_dir)
    if not os.path.exists(f.key_path):
        f.init_keys()
    m = Manifest()

    # SIG family — root:// only.
    # WebDAV port 8443 is optional-auth (cannot enforce reject), and S3 port
    # 9001 has no token path, so these cases run on root:// exclusively.
    #
    # DEFERRED (need a JWKS-varied port — added with the multi-key-JWKS port task):
    #   SIG-10..14: kid selection (hit/miss), no_kid multi-key fallback,
    #   wrong-kid multi-key reject, ES256 accept.
    m.add("SIG-01", {"m": "alg_none"}, "root", "reject",
          "alg=none blocked before verify (RFC8725)", "spec §2, RFC8725")
    m.add("SIG-02", {"m": "alg_hs256_confusion"}, "root", "reject",
          "HS256-signed-with-RSA-pubkey confusion", "spec §2, RFC8725")
    m.add("SIG-03", {"m": "alg_lowercase"}, "root", "reject",
          "alg is case-sensitive; rs256 != RS256", "RFC7515 §4.1.1")
    m.add("SIG-04", {"m": "alg_unsupported", "args": ["RS384"]}, "root", "reject",
          "RS384 not in {RS256,ES256}", "spec §2")
    m.add("SIG-05", {"m": "alg_unsupported", "args": ["PS256"]}, "root", "reject",
          "PS256 not accepted", "spec §2")
    m.add("SIG-06", {"m": "generate"}, "root", "accept",
          "valid RS256 token", "spec §2")
    m.add("SIG-07",
          {"m": "for_issuer", "args": ["https://evil.example.com"]},
          "root", "reject",
          "wrong issuer, validly signed", "spec §3.1")
    m.add("SIG-08", {"m": "truncated_sig"}, "root", "reject",
          "truncated signature fails verify", "RFC7515 §5.2")
    m.add("SIG-09", {"m": "generate_bad_signature"}, "root", "reject",
          "tampered signature fails verify", "RFC7515 §5.2")

    # CLM family — temporal, structural, and size checks; root:// only.
    # Ground truth: src/auth/token/validate.c
    #   - token_len > 8192       → reject (line 220)
    #   - now > exp + BRIX_TOKEN_CLOCK_SKEW_SECS (30)  → reject (line 389)
    #   - now < nbf (no skew on nbf)                   → reject (line 398)
    #   - missing/string exp: json_get_int64 leaves exp=0 → treated as expired
    m.add("CLM-01", {"m": "temporal", "args": [-3600]}, "root", "reject",
          "expired 1h beyond 30s skew", "RFC7519 §4.1.4, tunables.h skew=30")
    m.add("CLM-02", {"m": "temporal", "args": [-20]}, "root", "accept",
          "expired 20s but within current 30s skew (locks pre-Task-6 behavior)",
          "RFC7519 §4.1.4, tunables.h skew=30")
    m.add("CLM-03", {"m": "missing_exp"}, "root", "reject",
          "missing exp → json_get_int64 leaves exp=0 → treated as expired",
          "RFC7519 §4.1.4")
    m.add("CLM-04", {"m": "exp_string"}, "root", "reject",
          "string-typed exp is not an integer → parse fail → exp=0 → expired",
          "RFC7519 §4.1.4")
    m.add("CLM-05", {"m": "oversized", "args": [9000]}, "root", "reject",
          "token_len>8192 rejected at size check before any parsing",
          "validate.c line 220")
    m.add("CLM-06", {"m": "malformed_json"}, "root", "reject",
          "malformed JSON payload fails jansson parse", "RFC7515 §7.2")
    m.add("CLM-07", {"m": "not_a_jwt"}, "root", "reject",
          "not a compact JWS (no dots) → structural reject", "RFC7515 §3.1")
    m.add("CLM-08", {"m": "temporal", "args": [3600, 120]}, "root", "reject",
          "nbf 120s in future; nbf has no skew tolerance (validate.c line 398)",
          "RFC7519 §4.1.5")
    m.add("CLM-09", {"m": "generate"}, "root", "accept",
          "valid token baseline — all temporal checks pass",
          "RFC7519 §4.1.4-5")

    # AUD family — audience claim: scalar vs array membership; root:// only.
    # Ground truth: json_string_or_array_contains (src/auth/token/json.c line 165)
    #   iterates ALL array elements → position-independent membership test.
    m.add("AUD-01", {"m": "aud_value", "args": ["nginx-xrootd"]},
          "root", "accept",
          "scalar aud match against expected nginx-xrootd",
          "RFC7519 §4.1.3")
    m.add("AUD-02", {"m": "aud_value", "args": ["wrong-aud"]},
          "root", "reject",
          "scalar aud mismatch — nginx-xrootd not present",
          "RFC7519 §4.1.3")
    m.add("AUD-03", {"m": "aud_value", "args": [["nginx-xrootd", "other"]]},
          "root", "accept",
          "array aud — expected nginx-xrootd is first element",
          "RFC7519 §4.1.3, json_string_or_array_contains")
    m.add("AUD-04", {"m": "aud_value", "args": [["other", "nginx-xrootd"]]},
          "root", "accept",
          "array aud — expected nginx-xrootd is last element (position-independent)",
          "RFC7519 §4.1.3, json_string_or_array_contains")
    m.add("AUD-05", {"m": "aud_value", "args": [["a", "b"]]},
          "root", "reject",
          "array aud without expected nginx-xrootd — membership fails",
          "RFC7519 §4.1.3")
    m.add("AUD-06", {"m": "aud_value", "args": [[]]},
          "root", "reject",
          "empty array aud — membership check finds nothing",
          "RFC7519 §4.1.3")

    # VER family — wlcg.ver claim: advisory, not enforced; root:// only.
    # Ground truth: wlcg.ver is NOT read anywhere in src/auth/token/validate.c;
    #   the claim is emitted by pelican_register.c but never validated — advisory.
    m.add("VER-01", {"m": "generate"}, "root", "accept",
          "wlcg.ver=1.0 present — standard valid token baseline",
          "WLCG Token Profile §2.1")
    m.add("VER-02", {"m": "wlcg_ver", "args": [None]}, "root", "accept",
          "wlcg.ver absent is advisory, not fatal (not read by validate.c)",
          "WLCG Token Profile §2.1 advisory")
    m.add("VER-03", {"m": "wlcg_ver", "args": ["2.0"]}, "root", "accept",
          "unknown wlcg.ver advisory, not fatal — validate.c ignores the claim",
          "WLCG Token Profile §2.1 advisory")

    # ... further families appended by their respective test tasks ...

    manifest_path = os.path.join(out_dir, "token_manifest.json")
    m.write(manifest_path)
    return manifest_path


if __name__ == "__main__":
    import argparse

    ap = argparse.ArgumentParser(
        description="WLCG token conformance fixture forge CLI")
    sub = ap.add_subparsers(dest="cmd")
    manifest_p = sub.add_parser("manifest",
                                 help="Build token_manifest.json in out_dir")
    manifest_p.add_argument("out_dir",
                             help="Directory to write fixtures into")
    args = ap.parse_args()

    if args.cmd == "manifest":
        print(build_manifest(args.out_dir))
    else:
        ap.print_help()
