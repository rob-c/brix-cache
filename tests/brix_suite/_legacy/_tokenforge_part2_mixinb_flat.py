# ARCHIVE — the pre-TS-5 flat body of ``tests/_tokenforge_part2_mixinb.py``, kept byte-identical so
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


class _TokenForgeMixinB:
    """A TokenIssuer that can also emit deliberately-malformed tokens."""

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


    # --- raw assembly signing path -----------------------------------

    def _sign_raw(self, header_json: str, payload_json: str, key=None):
        """Sign arbitrary raw header/payload JSON strings (RS256, main key).

        WHAT: Accepts pre-formed JSON strings for header and payload, encodes
              them as base64url without Python serialisation, and produces a
              valid RS256 compact JWS.
        WHY:  Required for cases json.dumps cannot produce: duplicate claim
              names, non-string claim types (numeric iss), raw floats, and
              huge integers in numeric date positions.
        HOW:  b64url(header_json) + "." + b64url(payload_json) forms the
              signing_input; RS256 (PKCS1v15+SHA256) over it; appends sig.
        """
        key = key or self.private_key
        signing_input = (_b64url(header_json.encode()) + "." +
                         _b64url(payload_json.encode())).encode("ascii")
        sig = key.sign(signing_input, padding.PKCS1v15(), hashes.SHA256())
        return signing_input.decode("ascii") + "." + _b64url(sig)

    def _raw_hdr(self):
        """Standard RS256 header JSON string for _sign_raw calls."""
        return json.dumps(
            {"alg": "RS256", "typ": "JWT", "kid": self.DEFAULT_KID},
            separators=(",", ":"))

    # --- HDR family (RFC 7515 header parameters) ---------------------

    def crit_unknown(self):
        """crit lists an unknown extension parameter — MUST reject (rule 36).

        WHAT: Header contains crit=["http://example.com/UNKNOWN"] and the
              named extension as a boolean header member.
        WHY:  RFC 7515 §4.1.11 / rule 36 — an unrecognised critical extension
              MUST cause the JWS to be rejected by a conformant processor.
        """
        return self._sign_generic(
            "RS256", self.private_key, kid="test-key-1",
            header_extra={"crit": ["http://example.com/UNKNOWN"],
                          "http://example.com/UNKNOWN": True})

    def crit_empty(self):
        """crit is an empty array — MUST reject (rule 37).

        WHY: RFC 7515 §4.1.11 — the crit array MUST NOT be empty;
             an empty array is a structural error → reject.
        """
        return self._sign_generic("RS256", self.private_key, kid="test-key-1",
                                  header_extra={"crit": []})

    def crit_non_array(self):
        """crit is a string rather than an array — MUST reject (rule 37).

        WHY: RFC 7515 §4.1.11 — crit MUST be a JSON array; a scalar string
             violates the type constraint → reject.
        """
        return self._sign_generic("RS256", self.private_key, kid="test-key-1",
                                  header_extra={"crit": "exp"})

    def crit_lists_alg(self):
        """crit lists the RFC-defined 'alg' parameter — MUST reject (rule 38).

        WHY: RFC 7515 §4.1.11 — the crit array MUST NOT list parameters whose
             semantics are already specified in the JWS/JWA registrations (such
             as 'alg', 'kid', 'typ').  Including them is a structural violation.
        """
        return self._sign_generic("RS256", self.private_key, kid="test-key-1",
                                  header_extra={"crit": ["alg"]})

    def crit_missing_name(self):
        """crit lists 'kid' but kid is absent from the header — reject (rule 37).

        WHAT: The crit array names "kid" as a critical extension, but the header
              carries no "kid" member — so the named parameter is absent.
        WHY:  RFC 7515 §4.1.11 / rule 37 — every name in crit MUST also appear
              as a header member; absence is a structural error → reject.
        HOW:  Build header without kid; _sign_with_header used directly so no
              kid is injected automatically.
        """
        hdr = {"alg": "RS256", "typ": "JWT", "crit": ["kid"]}
        return self._sign_with_header(hdr, self._base_claims())

    def typ_at_jwt(self):
        """typ=at+jwt — valid access-token type designator (rule 75; accept).

        WHY:  RFC 9068 designates "at+jwt" as the IANA media type for OAuth 2.0
              access tokens.  A conformant validator must accept this value;
              characterises whether 'at+jwt' is treated equivalently to 'JWT'.
        """
        return self._sign_generic("RS256", self.private_key, kid="test-key-1",
                                  header_extra={"typ": "at+jwt"})

    def typ_wrong(self):
        """typ=id_token+jwt — cross-JWT confusion type (rules 71/75; characterize).

        WHY:  Tokens bearing a typ that names a different token profile (here an
              ID Token) SHOULD be rejected by access-token validators to prevent
              cross-JWT confusion attacks (RFC 8725 §2.8 rules 71/75).
        """
        return self._sign_generic("RS256", self.private_key, kid="test-key-1",
                                  header_extra={"typ": "id_token+jwt"})

    def typ_missing(self):
        """typ is absent from the header entirely (rule 70; characterize).

        WHAT: Build a header with alg and kid but no typ field.
        WHY:  RFC 8725 §2.9 / rule 70 — servers SHOULD require typ to prevent
              confusion; characterises whether the implementation enforces it.
        HOW:  _sign_generic always sets typ; _sign_with_header used directly
              to construct a header without any typ member.
        """
        hdr = {"alg": "RS256", "kid": self.DEFAULT_KID}
        return self._sign_with_header(hdr, self._base_claims())

    def cty_set(self):
        """cty=JWT on a non-nested token (rule 35; characterize).

        WHY:  RFC 7515 §4.1.10 — the cty (content type) header parameter SHOULD
              be absent for non-nested JWS objects; its presence characterises
              whether validators flag or accept it.
        """
        return self._sign_generic("RS256", self.private_key, kid="test-key-1",
                                  header_extra={"cty": "JWT"})

    def header_jku(self):
        """jku header with an attacker JWKS URL (rule 28; MUST be ignored → accept).

        WHAT: Header carries jku="https://attacker.example.com/jwks.json"; the
              token is still RS256-signed by the main key.
        WHY:  RFC 7515 §4.1.2 / rule 28 — a conformant server MUST NOT fetch or
              trust the jku value; it verifies against its statically configured
              JWKS.  If jku is ignored (correct), the main-key signature verifies
              → accept; fetching the attacker URL would be a critical vulnerability.
        """
        return self._sign_generic(
            "RS256", self.private_key, kid="test-key-1",
            header_extra={"jku": "https://attacker.example.com/jwks.json"})

    def header_jwk_injection(self):
        """Embedded attacker public key in jwk header param, signed by attacker key.

        WHAT: Generate a throwaway RSA key-pair; embed its public key as a JWK
              in the header's 'jwk' member; sign the token with the throwaway
              private key (NOT the main key configured in the JWKS).
        WHY:  RFC 7515 §4.1.3 / rules 29/150 — the server MUST NOT trust the
              key embedded in 'jwk'; it must verify against its configured JWKS.
              The attacker key is absent from the JWKS → MUST reject.
        HOW:  rsa.generate_private_key(65537, 2048) → attacker key pair;
              _rsa_jwk(pub, "attacker-1") → JWK dict → header["jwk"];
              sign with attacker private key.
        """
        attacker_key = rsa.generate_private_key(
            public_exponent=65537, key_size=2048)
        attacker_jwk = _rsa_jwk(attacker_key.public_key(), "attacker-1")
        hdr = {"alg": "RS256", "typ": "JWT", "kid": "attacker-1",
               "jwk": attacker_jwk}
        return self._sign_with_header(hdr, self._base_claims(),
                                      key=attacker_key)

    def header_x5c_injection(self):
        """Embedded attacker cert chain in x5c header, signed by attacker key.

        WHAT: Generate a throwaway RSA key; self-sign a certificate for it;
              base64-encode the DER cert for the x5c array (RFC 4648 §4 — not
              base64url); sign the token with the throwaway private key.
        WHY:  RFC 7515 §4.1.6 / rules 32/150 — the server MUST NOT trust key
              material from x5c; it verifies against its configured JWKS.
              The attacker key is absent from the JWKS → MUST reject.
        HOW:  cryptography.x509 builds a minimal self-signed cert; DER-encode;
              base64.b64encode (standard, not url-safe — x5c requires RFC 4648).
        """
        attacker_key = rsa.generate_private_key(
            public_exponent=65537, key_size=2048)
        now = datetime.datetime.utcnow()
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "attacker")])
        cert = (
            x509.CertificateBuilder()
            .subject_name(name)
            .issuer_name(name)
            .public_key(attacker_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now)
            .not_valid_after(now + datetime.timedelta(days=1))
            .sign(attacker_key, hashes.SHA256())
        )
        der = cert.public_bytes(serialization.Encoding.DER)
        x5c_entry = base64.b64encode(der).decode("ascii")
        hdr = {"alg": "RS256", "typ": "JWT", "x5c": [x5c_entry]}
        return self._sign_with_header(hdr, self._base_claims(),
                                      key=attacker_key)

    # --- CLM2 family (claim types / interactions) --------------------

    def dup_claim_names(self):
        """Payload JSON with duplicate 'aud' keys (rule 21; characterize → reject).

        WHAT: Constructs the payload string by hand so it contains two 'aud'
              entries — e.g. aud='nginx-xrootd' followed by aud='evil'.
        WHY:  RFC 7159 §4 / rule 21 — duplicate member names SHOULD be rejected;
              a compliant parser must not silently accept the last/first value
              without flagging the ambiguity.
        HOW:  json.dumps() cannot emit duplicate keys; raw string construction
              is used via _sign_raw.
        """
        now = int(time.time())
        payload = (
            '{"iss":' + json.dumps(self.issuer) +
            ',"sub":"conformance"' +
            ',"aud":"nginx-xrootd"' +
            ',"aud":"evil"' +
            ',"exp":' + str(now + 3600) +
            ',"nbf":' + str(now) +
            ',"iat":' + str(now) +
            ',"scope":"storage.read:/"' +
            ',"wlcg.ver":"1.0"}'
        )
        return self._sign_raw(self._raw_hdr(), payload)
