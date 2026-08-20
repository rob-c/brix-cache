"""JOSE encoding and JWKS emission for the token forge.

ONE copy.  Before this module `_b64url` and `_seg` were defined five times
over — once in `tokenforge.py` and again in each of the four
`_tokenforge_part2_mixin*` slices, because the mixins were cut by line count
and every slice re-imported the same prelude.  All five bodies hashed
identically, so the duplication bought nothing and hid the fact that
`_rsa_jwk` was defined in only one of them (see `signing.header_jwk_injection`).
"""
import base64
import json

from cryptography.hazmat.primitives.asymmetric import ec


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
