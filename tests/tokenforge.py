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
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
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
    """Build an EC JWK entry for pub, supporting P-256, P-384, and P-521.

    WHAT: Serialises an EC public key into a JSON Web Key dict.
    WHY:  write_jwks handles RSA and EC uniformly; EC entry parameters vary
          (coordinate byte size, crv name, alg label) per curve.
    HOW:  Map curve.name to (coord_size_bytes, crv_name, alg_name); encode x/y
          as fixed-width big-endian base64url per RFC 7518 §6.2.1.2.
    """
    _CURVE_PARAMS = {
        "secp256r1": (32, "P-256",  "ES256"),
        "secp384r1": (48, "P-384",  "ES384"),
        "secp521r1": (66, "P-521",  "ES512"),
    }
    size, crv_name, alg_name = _CURVE_PARAMS.get(
        pub.curve.name, (32, "P-256", "ES256"))
    nums = pub.public_numbers()
    def b(i):
        return _b64url(i.to_bytes(size, "big"))
    return {"kty": "EC", "kid": kid, "use": "sig", "alg": alg_name,
            "crv": crv_name, "x": b(nums.x), "y": b(nums.y)}


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

    def es256_bad_sig(self):
        """ES256 token with one bit flipped in the signature (verify must fail)."""
        tok = self.es256()
        h, p, s = tok.split(".")
        # Pad to 4-byte boundary for standard b64decode, then corrupt byte 0.
        raw = bytearray(base64.urlsafe_b64decode(s + "=="))
        raw[0] ^= 0x01
        return h + "." + p + "." + _b64url(bytes(raw))

    def signed_by_key2(self, kid="test-key-2"):
        """RS256 token signed by second_rsa_key; header carries kid test-key-2."""
        h = {"alg": "RS256", "typ": "JWT", "kid": kid}
        return self._sign_with_header(h, self._base_claims(),
                                      key=self.second_rsa_key)

    def no_kid_key2(self):
        """RS256 signed by second_rsa_key with NO kid in header.

        Used to test rotation-fallback: a kid-less token signed by a non-first
        key — the verifier must either try all keys or reject cleanly.
        """
        h = {"alg": "RS256", "typ": "JWT"}
        return self._sign_with_header(h, self._base_claims(),
                                      key=self.second_rsa_key)

    def wrong_kid_multikey(self, kid="does-not-exist"):
        """RS256 signed by the MAIN key but header kid names an absent key.

        Used to assert that a kid that resolves to nothing in the JWKS causes
        a reject even though the signature would verify against the main key.
        """
        h = {"alg": "RS256", "typ": "JWT", "kid": kid}
        return self._sign_with_header(h, self._base_claims())

    # --- ALG-family mint methods (RFC 7518 §3, RFC 8725 §2.2, rules 43–56) ---

    def rs384(self):
        """Valid RS384 token signed by the main RSA key (kid test-key-1)."""
        return self._sign_generic("RS384", self.private_key, kid="test-key-1")

    def rs512(self):
        """Valid RS512 token signed by the main RSA key (kid test-key-1)."""
        return self._sign_generic("RS512", self.private_key, kid="test-key-1")

    def ps256(self):
        """Valid PS256 (RSA-PSS SHA-256) token signed by the main RSA key."""
        return self._sign_generic("PS256", self.private_key, kid="test-key-1")

    def ps384(self):
        """Valid PS384 (RSA-PSS SHA-384) token signed by the main RSA key."""
        return self._sign_generic("PS384", self.private_key, kid="test-key-1")

    def ps512(self):
        """Valid PS512 (RSA-PSS SHA-512) token signed by the main RSA key."""
        return self._sign_generic("PS512", self.private_key, kid="test-key-1")

    def es384(self):
        """Valid ES384 token signed by the P-384 key (kid ec-p384).

        ACCEPT when the verifying JWKS includes ec-p384; REJECT when the server
        does not list PS/ES384 as an accepted algorithm (config-dependent).
        """
        return self._sign_generic("ES384", self.ec_p384_key, kid="ec-p384")

    def es512(self):
        """Valid ES512 token signed by the P-521 key (kid ec-p521).

        ACCEPT when the verifying JWKS includes ec-p521; REJECT when the server
        restricts accepted algorithms to RS256/ES256 only.
        """
        return self._sign_generic("ES512", self.ec_p521_key, kid="ec-p521")

    def es256_wrong_curve(self):
        """ES256 header but signed with the P-384 key — curve/alg mismatch (rule 48).

        WHAT: Header declares alg=ES256 (implying P-256 with SHA-256) but the
              signing key is P-384.  Signature uses actual ES384 mechanics
              (SHA-384, 96-byte P1363 R‖S) so the token is structurally valid.
        WHY:  A conformant verifier resolves kid=ec-p384 to a P-384 key and must
              reject because the header alg (ES256) contradicts the key's curve.
        HOW:  Build the header with alg=ES256, sign with P-384/SHA-384 so r,s
              are 48-byte quantities; the resulting signature is 96 bytes rather
              than the 64 bytes ES256 mandates — a correct verifier will detect
              the mismatch.
        """
        hdr = {"alg": "ES256", "typ": "JWT", "kid": "ec-p384"}
        payload = self._base_claims()
        signing_input = (_seg(hdr) + "." + _seg(payload)).encode("ascii")
        der = self.ec_p384_key.sign(signing_input, ec.ECDSA(hashes.SHA384()))
        r, s = decode_dss_signature(der)
        sig = r.to_bytes(48, "big") + s.to_bytes(48, "big")
        return signing_input.decode("ascii") + "." + _b64url(sig)

    def hs256_weak_secret(self):
        """HS256 signed with the low-entropy secret b'secret' (rules 51/65).

        Two independent grounds for rejection: (1) the server is asymmetric-only
        so no HS key is configured; (2) the secret is 6 bytes, far below the
        minimum entropy threshold mandated by RFC 8725 §2.2 rule 51/65.
        """
        hdr = {"alg": "HS256", "typ": "JWT", "kid": "hs-weak"}
        payload = self._base_claims()
        signing_input = (_seg(hdr) + "." + _seg(payload)).encode("ascii")
        sig = hmac.new(b"secret", signing_input, hashlib.sha256).digest()
        return signing_input.decode("ascii") + "." + _b64url(sig)

    def alg_variant(self, variant):
        """RS256-signed token whose header alg field is the given variant string.

        WHAT: Returns a validly RS256-signed compact JWS with alg=variant in the
              header instead of the canonical "RS256".
        WHY:  Rule 54 — alg comparison is case-sensitive and whitespace-exact;
              "Rs256", "rs256", "RS256 " etc. must all be rejected.
        HOW:  Uses _sign_with_header (PKCS1v15+SHA256) so the cryptographic
              signature is valid; only the header label is wrong.
        """
        hdr = {"alg": variant, "typ": "JWT", "kid": self.DEFAULT_KID}
        return self._sign_with_header(hdr, self._base_claims())

    def none_with_sig(self):
        """alg=none header with a NON-empty signature segment (rule 55 must reject).

        WHAT: Constructs a three-segment compact JWS where the header declares
              alg=none but the third segment contains a non-empty bogus value.
        WHY:  RFC 7518 §3.6 and rule 55 — alg=none tokens must have an empty
              signature segment; a non-empty segment is a protocol violation and
              must cause rejection regardless of what the bytes contain.
        """
        hdr = {"alg": "none", "typ": "JWT"}
        payload = self._base_claims()
        bogus_sig = _b64url(b"\xde\xad\xbe\xef" * 8)  # 32 non-empty bytes
        return _seg(hdr) + "." + _seg(payload) + "." + bogus_sig

    def weak_rsa_signed(self):
        """RS256-signed with the 1024-bit weak RSA key (kid weak-rsa, rule 50).

        WHAT: A syntactically valid RS256 token whose signing key is only 1024
              bits rather than the RFC 8725 §2.2 minimum of 2048 bits.
        WHY:  A conformant server should reject this either because (a) it
              enforces a minimum key size policy, or (b) it only trusts keys
              listed in the JWKS and weak-rsa is deliberately absent from
              jwks_alg.json.
        """
        hdr = {"alg": "RS256", "typ": "JWT", "kid": "weak-rsa"}
        return self._sign_with_header(hdr, self._base_claims(),
                                      key=self.weak_rsa_key)


def fleet_artifacts(token_dir):
    """Ensure multi-key JWKS and scitokens.cfg for the managed test fleet.

    WHAT: Materialises the secondary RSA and EC keys, then writes:
          - jwks_multi.json  — three-key JWKS (main RSA + key-2 RSA + EC).
          - scitokens.cfg    — two-issuer registry (atlas + cms), each using
                              the MAIN jwks.json so forge-minted tokens verify.
    WHY:  Called once per start-all so the multikey and registry dedicated nginx
          instances have fresh artifacts that survive key rotation (main key
          re-created by TokenIssuer.init_keys on a clean tree).
    HOW:  TokenForge lazy-creates the secondary keys on first access; write_jwks
          and write_scitokens_cfg handle serialisation.
    """
    os.makedirs(token_dir, exist_ok=True)
    f = TokenForge(token_dir)
    if not os.path.exists(f.key_path):
        f.init_keys()
    # Materialise the secondary keys (side-effect: persists them to disk).
    second_pub = f.second_rsa_key.public_key()
    ec_pub = f.ec_key.public_key()
    main_pub = f.private_key.public_key()

    write_jwks(os.path.join(token_dir, "jwks_multi.json"), [
        (main_pub,   "test-key-1"),
        (second_pub, "test-key-2"),
        (ec_pub,     "ec-key-1"),
    ])

    main_jwks = os.path.join(token_dir, "jwks.json")
    write_scitokens_cfg(os.path.join(token_dir, "scitokens.cfg"), [
        {
            "name":       "atlas",
            "issuer":     "https://atlas.example.com",
            "base_paths": ["/atlas"],
            "jwks_path":  main_jwks,
            "strategy":   "capability",
        },
        {
            "name":       "cms",
            "issuer":     "https://cms.example.com",
            "base_paths": ["/cms"],
            "jwks_path":  main_jwks,
            "strategy":   "capability",
        },
    ])


def alg_jwks(token_dir):
    """Write {token_dir}/jwks_alg.json for the ALG-family's ACCEPT cases.

    WHAT: Materialises ec_p384_key and ec_p521_key (side-effect: persists them to
          disk), then writes a JWKS containing the three keys that the ALG-family
          ACCEPT tests verify against: main RSA (test-key-1), P-384 (ec-p384),
          P-521 (ec-p521).
    WHY:  The ALG-family nginx port serves this JWKS so rs384/rs512/ps*/es384/es512
          ACCEPT cases validate correctly, while weak_rsa_signed and es256_wrong_curve
          REJECT because their kids (weak-rsa, ec-p384 signed as ES256) are either
          absent or curve-mismatched.
    HOW:  Creates a TokenForge, initialises the main key if needed, accesses the
          three ACCEPT-case keys, delegates to write_jwks.
    """
    os.makedirs(token_dir, exist_ok=True)
    f = TokenForge(token_dir)
    if not os.path.exists(f.key_path):
        f.init_keys()
    write_jwks(os.path.join(token_dir, "jwks_alg.json"), [
        (f.private_key.public_key(),   "test-key-1"),
        (f.ec_p384_key.public_key(),   "ec-p384"),
        (f.ec_p521_key.public_key(),   "ec-p521"),
    ])


class Manifest:
    def __init__(self):
        self.rows = []

    def add(self, case_id, mint_recipe, protocol, expected,
            expected_reason, spec_ref, path=None, write=False):
        """Append a manifest row.

        Args:
            case_id:         Unique case identifier string (e.g. "SCP-W01").
            mint_recipe:     Dict describing how to mint the token (keys: "m",
                             optionally "args" / "kwargs").
            protocol:        One of "root", "webdav", "s3".
            expected:        "accept" or "reject".
            expected_reason: Human-readable rationale for the verdict.
            spec_ref:        Spec section or RFC reference.
            path:            XRootD/WebDAV path to probe; defaults to
                             "/test.txt" at assertion time when None.
            write:           If True, probe via a write operation rather than
                             read.  Stored in the row for assert_verdict().
        """
        assert expected in ("accept", "reject")
        row = {
            "case_id": case_id, "mint_recipe": mint_recipe,
            "protocol": protocol, "expected": expected,
            "expected_reason": expected_reason, "spec_ref": spec_ref,
        }
        if path is not None:
            row["path"] = path
        if write:
            row["write"] = write
        self.rows.append(row)

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

    # SCP family — scope-enforcement and path-traversal defense; root:// only.
    # Ground truth: src/auth/token/scopes.c (brix_token_check_scope),
    #   src/protocols/root/path/op_path.c (brix_op_path_forbidden_component),
    #   src/protocols/root/read/stat.c (brix_reject_dotdot_path called BEFORE scope).
    # Rules:
    #   - storage.stage maps to read permission.
    #   - scope path prefix /data does NOT cover /database (no boundary crossing).
    #   - scope path "" (empty after the colon) defaults to root "/".
    #   - paths with ".." components → kXR_ArgInvalid BEFORE scope check (§3.5).
    #   - a token that auth-passes but has no scope covering the path → kXR_NotAuthorized.
    m.add("SCP-W01",
          {"m": "scope", "args": ["storage.read:/atlas"]},
          "root", "accept",
          "in-scope read: storage.read:/atlas covers /atlas/ok.txt",
          "WLCG Token Profile §4, scopes.c",
          path="/atlas/ok.txt")
    m.add("SCP-W02",
          {"m": "scope", "args": ["storage.read:/atlas"]},
          "root", "reject",
          "out-of-scope read: storage.read:/atlas does not cover /cms/ok.txt",
          "WLCG Token Profile §4, scopes.c",
          path="/cms/ok.txt")
    m.add("SCP-W03",
          {"m": "scope", "args": ["storage.read:/data"]},
          "root", "reject",
          "/data prefix must not cover /database (boundary: /data != /database)",
          "WLCG Token Profile §4 path-prefix rules",
          path="/database/ok.txt")
    m.add("SCP-W04",
          {"m": "scope", "args": ["storage.read:/atlas"]},
          "root", "reject",
          "TRAVERSAL: dot-dot escape must not reach /cms (§3.5 — "
          "brix_reject_dotdot_path fires before scope check)",
          "spec §3.5, op_path.c brix_reject_dotdot_path",
          path="/atlas/../cms/ok.txt")
    m.add("SCP-W05",
          {"m": "scope", "args": ["storage.read:/"]},
          "root", "accept",
          "root scope storage.read:/ covers all paths including /test.txt",
          "WLCG Token Profile §4",
          path="/test.txt")
    m.add("SCP-W06",
          {"m": "no_scope"},
          "root", "reject",
          "authenticated but scope claim absent — no grant covers any path",
          "WLCG Token Profile §4, scopes.c",
          path="/test.txt")
    m.add("SCP-W07",
          {"m": "scope", "args": ["storage.stage:/atlas"]},
          "root", "accept",
          "storage.stage grants read permission per WLCG token profile",
          "WLCG Token Profile §4, scopes.c storage.stage→read alias",
          path="/atlas/ok.txt")
    m.add("SCP-W08",
          {"m": "scope", "args": ["storage.write:/atlas"]},
          "root", "reject",
          "write-only scope storage.write:/atlas does not grant read",
          "WLCG Token Profile §4, scopes.c",
          path="/atlas/ok.txt")
    m.add("SCP-W09",
          {"m": "scope", "args": ["storage.read:"]},
          "root", "accept",
          "empty path after colon defaults to root scope / — covers /test.txt",
          "WLCG Token Profile §4, scopes.c empty-path-defaults-to-root",
          path="/test.txt")

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
    fleet_p = sub.add_parser(
        "fleet-artifacts",
        help="Write jwks_multi.json and scitokens.cfg into token_dir")
    fleet_p.add_argument("token_dir",
                         help="Directory to write fleet artifacts into")
    args = ap.parse_args()

    if args.cmd == "manifest":
        print(build_manifest(args.out_dir))
    elif args.cmd == "fleet-artifacts":
        fleet_artifacts(args.token_dir)
    else:
        ap.print_help()
