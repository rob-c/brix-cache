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

from split_continuation import load as _load_continuations
_load_continuations(globals(), __file__, "tokenforge_part2.py", "tokenforge_part3.py")
