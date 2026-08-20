# ARCHIVE — the pre-TS-5 flat body of ``tests/_tokenforge_part2_mixina.py``, kept byte-identical so
# the "verbatim move" claim in the TS-5 decision note is checkable on disk
# rather than only in git history.  Nothing imports this; the live forge is
# ``brix_suite.security.tokens``.  ``test_ci_ts5_tokens_move.py`` diffs every
# moved method against this text.
"""WLCG token conformance fixture forge.

Extends utils.make_token.TokenIssuer into a full hostile-token mint. Every
minted artifact is described by a manifest row so the C and pytest layers
share one verdict source. See docs/superpowers/specs/2026-07-06-wlcg-token-
conformance-design.md.
"""
import base64
import datetime
import hashlib
import hmac
import json
import os
import time

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.x509.oid import NameOID

import sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from utils.make_token import TokenIssuer



def _b64url(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def _seg(obj) -> str:
    return _b64url(json.dumps(obj, separators=(",", ":")).encode("utf-8"))


class _TokenForgeMixinA:
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

    # --- key management: lazy load-or-create persisted secondary keys -----

    @property
    def second_rsa_key(self):
        """Lazily load or create {token_dir}/signing_key_2.pem (RSA-2048, kid test-key-2)."""
        if hasattr(self, "_second_rsa_key"):
            return self._second_rsa_key
        path = os.path.join(self.token_dir, "signing_key_2.pem")
        if os.path.exists(path):
            with open(path, "rb") as fh:
                self._second_rsa_key = serialization.load_pem_private_key(
                    fh.read(), password=None)
        else:
            os.makedirs(self.token_dir, exist_ok=True)
            key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
            pem = key.private_bytes(serialization.Encoding.PEM,
                                    serialization.PrivateFormat.TraditionalOpenSSL,
                                    serialization.NoEncryption())
            tmp = path + f".tmp.{os.getpid()}"
            try:
                with open(tmp, "wb") as fh:
                    fh.write(pem)
                os.chmod(tmp, 0o400)
                os.replace(tmp, path)
            finally:
                if os.path.exists(tmp):
                    os.unlink(tmp)
            self._second_rsa_key = key
        return self._second_rsa_key

    @property
    def ec_key(self):
        """Lazily load or create {token_dir}/signing_key_ec.pem (EC SECP256R1, kid ec-key-1)."""
        if hasattr(self, "_ec_key"):
            return self._ec_key
        path = os.path.join(self.token_dir, "signing_key_ec.pem")
        if os.path.exists(path):
            with open(path, "rb") as fh:
                self._ec_key = serialization.load_pem_private_key(
                    fh.read(), password=None)
        else:
            os.makedirs(self.token_dir, exist_ok=True)
            key = ec.generate_private_key(ec.SECP256R1())
            pem = key.private_bytes(serialization.Encoding.PEM,
                                    serialization.PrivateFormat.TraditionalOpenSSL,
                                    serialization.NoEncryption())
            tmp = path + f".tmp.{os.getpid()}"
            try:
                with open(tmp, "wb") as fh:
                    fh.write(pem)
                os.chmod(tmp, 0o400)
                os.replace(tmp, path)
            finally:
                if os.path.exists(tmp):
                    os.unlink(tmp)
            self._ec_key = key
        return self._ec_key

    @property
    def weak_rsa_key(self):
        """Lazily load or create {token_dir}/signing_key_weak_rsa.pem (RSA-1024, kid weak-rsa).

        WHY: Rule 50 — undersized RSA key (< 2048-bit) must be rejected by a
             conformant verifier either by key-size policy or by not including
             the weak-rsa kid in the served JWKS.
        """
        if hasattr(self, "_weak_rsa_key"):
            return self._weak_rsa_key
        path = os.path.join(self.token_dir, "signing_key_weak_rsa.pem")
        if os.path.exists(path):
            with open(path, "rb") as fh:
                self._weak_rsa_key = serialization.load_pem_private_key(
                    fh.read(), password=None)
        else:
            os.makedirs(self.token_dir, exist_ok=True)
            key = rsa.generate_private_key(public_exponent=65537, key_size=1024)
            pem = key.private_bytes(serialization.Encoding.PEM,
                                    serialization.PrivateFormat.TraditionalOpenSSL,
                                    serialization.NoEncryption())
            tmp = path + f".tmp.{os.getpid()}"
            try:
                with open(tmp, "wb") as fh:
                    fh.write(pem)
                os.chmod(tmp, 0o400)
                os.replace(tmp, path)
            finally:
                if os.path.exists(tmp):
                    os.unlink(tmp)
            self._weak_rsa_key = key
        return self._weak_rsa_key

    @property
    def ec_p384_key(self):
        """Lazily load or create {token_dir}/signing_key_ec_p384.pem (EC SECP384R1, kid ec-p384).

        WHY: Rule 48 / es256_wrong_curve — provides a P-384 key used both as a
             valid ES384 signer and as the mismatch key for the curve-confusion
             mint method.
        """
        if hasattr(self, "_ec_p384_key"):
            return self._ec_p384_key
        path = os.path.join(self.token_dir, "signing_key_ec_p384.pem")
        if os.path.exists(path):
            with open(path, "rb") as fh:
                self._ec_p384_key = serialization.load_pem_private_key(
                    fh.read(), password=None)
        else:
            os.makedirs(self.token_dir, exist_ok=True)
            key = ec.generate_private_key(ec.SECP384R1())
            pem = key.private_bytes(serialization.Encoding.PEM,
                                    serialization.PrivateFormat.TraditionalOpenSSL,
                                    serialization.NoEncryption())
            tmp = path + f".tmp.{os.getpid()}"
            try:
                with open(tmp, "wb") as fh:
                    fh.write(pem)
                os.chmod(tmp, 0o400)
                os.replace(tmp, path)
            finally:
                if os.path.exists(tmp):
                    os.unlink(tmp)
            self._ec_p384_key = key
        return self._ec_p384_key

    @property
    def ec_p521_key(self):
        """Lazily load or create {token_dir}/signing_key_ec_p521.pem (EC SECP521R1, kid ec-p521).

        WHY: ES512 algorithm requires a P-521 key; this property provides it for
             the es512() mint method and the ALG-family JWKS.
        """
        if hasattr(self, "_ec_p521_key"):
            return self._ec_p521_key
        path = os.path.join(self.token_dir, "signing_key_ec_p521.pem")
        if os.path.exists(path):
            with open(path, "rb") as fh:
                self._ec_p521_key = serialization.load_pem_private_key(
                    fh.read(), password=None)
        else:
            os.makedirs(self.token_dir, exist_ok=True)
            key = ec.generate_private_key(ec.SECP521R1())
            pem = key.private_bytes(serialization.Encoding.PEM,
                                    serialization.PrivateFormat.TraditionalOpenSSL,
                                    serialization.NoEncryption())
            tmp = path + f".tmp.{os.getpid()}"
            try:
                with open(tmp, "wb") as fh:
                    fh.write(pem)
                os.chmod(tmp, 0o400)
                os.replace(tmp, path)
            finally:
                if os.path.exists(tmp):
                    os.unlink(tmp)
            self._ec_p521_key = key
        return self._ec_p521_key

    # --- signing helper: RSA-sign an arbitrary (header, payload) ------
    def _sign_with_header(self, header, payload, key=None):
        """RS256-sign header+payload.  key defaults to self.private_key."""
        k = key if key is not None else self.private_key
        signing_input = (_seg(header) + "." + _seg(payload)).encode("ascii")
        sig = k.sign(signing_input, padding.PKCS1v15(), hashes.SHA256())
        return signing_input.decode("ascii") + "." + _b64url(sig)

    # --- generic signing helper for the ALG family --------------------
    def _sign_generic(self, alg, key, payload=None, header_extra=None, kid=None):
        """Build and sign a compact JWS using any JWA algorithm family.

        WHAT: Constructs header={alg,typ="JWT"[,kid][,...header_extra]} +
              payload (defaults to _base_claims()), signs the
              base64url(header).base64url(payload) input, and returns the
              compact serialisation.
        WHY:  Mint methods for PS/ES384-512/HS variants share all mechanics
              except the hash/padding selection; this helper centralises that
              dispatch so each public method is a one-liner.
        HOW:  Dispatch by alg.upper():
              RS256/384/512  → PKCS1v15 + SHA-{256,384,512}
              PS256/384/512  → PSS(MGF1(SHA-N), MAX_LENGTH) + SHA-N
              ES256/384/512  → ECDSA(SHA-N) → DER decoded → P1363 R‖S
                               with fixed coord widths 32/48/66 bytes.
              HS256/384/512  → HMAC-SHA-N (key must be bytes).
              Unknown alg    → falls back to PKCS1v15+SHA256 (label mismatch
                               tests like alg_variant/alg_unsupported).
        """
        hdr = {"alg": alg, "typ": "JWT"}
        if kid is not None:
            hdr["kid"] = kid
        if header_extra:
            hdr.update(header_extra)
        if payload is None:
            payload = self._base_claims()
        signing_input = (_seg(hdr) + "." + _seg(payload)).encode("ascii")

        alg_key = alg.upper()

        if alg_key in ("RS256", "RS384", "RS512"):
            _hash = {"RS256": hashes.SHA256, "RS384": hashes.SHA384,
                     "RS512": hashes.SHA512}[alg_key]
            sig = key.sign(signing_input, padding.PKCS1v15(), _hash())
        elif alg_key in ("PS256", "PS384", "PS512"):
            _hash = {"PS256": hashes.SHA256, "PS384": hashes.SHA384,
                     "PS512": hashes.SHA512}[alg_key]
            sig = key.sign(signing_input,
                           padding.PSS(mgf=padding.MGF1(_hash()),
                                       salt_length=padding.PSS.MAX_LENGTH),
                           _hash())
        elif alg_key in ("ES256", "ES384", "ES512"):
            _hash = {"ES256": hashes.SHA256, "ES384": hashes.SHA384,
                     "ES512": hashes.SHA512}[alg_key]
            _sz   = {"ES256": 32, "ES384": 48, "ES512": 66}[alg_key]
            der = key.sign(signing_input, ec.ECDSA(_hash()))
            r, s = decode_dss_signature(der)
            sig = r.to_bytes(_sz, "big") + s.to_bytes(_sz, "big")
        elif alg_key in ("HS256", "HS384", "HS512"):
            _hash_fn = {"HS256": hashlib.sha256, "HS384": hashlib.sha384,
                        "HS512": hashlib.sha512}[alg_key]
            sig = hmac.new(key, signing_input, _hash_fn).digest()
        else:
            # Unknown alg label: RSA PKCS1v15+SHA256 so the structure is valid
            # but the header alg string is a deliberate mismatch.
            sig = key.sign(signing_input, padding.PKCS1v15(), hashes.SHA256())

        return signing_input.decode("ascii") + "." + _b64url(sig)

    # --- ES256 signing helper (P1363 encoding, not DER) ----------------
    def _sign_es256(self, header, payload):
        """ES256-sign header+payload using the persisted EC key.

        WHAT: Produces a compact JWS with an ES256 signature in IEEE P1363
              format (R||S concatenation, 64 bytes for P-256).
        WHY:  cryptography's ec.ECDSA returns DER; JWT/JWS requires P1363.
        HOW:  Sign → decode DER (r, s) via decode_dss_signature →
              r.to_bytes(32) + s.to_bytes(32) → base64url.
        """
        signing_input = (_seg(header) + "." + _seg(payload)).encode("ascii")
        der = self.ec_key.sign(signing_input, ec.ECDSA(hashes.SHA256()))
        r, s = decode_dss_signature(der)
        sig = r.to_bytes(32, "big") + s.to_bytes(32, "big")
        return signing_input.decode("ascii") + "." + _b64url(sig)

    # --- multi-key / EC signing methods --------------------------------

    def es256(self):
        """Valid ES256 token signed by the persisted EC key (kid=ec-key-1)."""
        h = {"alg": "ES256", "typ": "JWT", "kid": "ec-key-1"}
        return self._sign_es256(h, self._base_claims())
