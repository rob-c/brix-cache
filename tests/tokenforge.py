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


def write_scitokens_cfg(path, issuers):
    """issuers: list of dicts {name, issuer, audience, base_paths,
    restricted_paths, jwks_path, strategy}. Emits the INI the C registry
    parser (issuer_registry.c) reads."""
    lines = ["[Global]", "audience = nginx-xrootd", ""]
    for it in issuers:
        lines.append(f"[Issuer {it['name']}]")
        lines.append(f"issuer = {it['issuer']}")
        lines.append(f"audience = {it.get('audience', 'nginx-xrootd')}")
        lines.append("base_path = " + ", ".join(it.get("base_paths", ["/"])))
        if it.get("restricted_paths"):
            lines.append("restricted_path = " +
                         ", ".join(it["restricted_paths"]))
        lines.append(f"jwks_file = {it['jwks_path']}")
        lines.append(f"authz_strategy = {it.get('strategy', 'capability')}")
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
