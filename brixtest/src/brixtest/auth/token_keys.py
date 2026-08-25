"""Lazy asymmetric JWT key generation, signing, verification, and JWK export."""

from __future__ import annotations

import base64
import json
from pathlib import Path
from typing import Mapping, Tuple, Union

from brixtest.errors import SpecError


def _crypto():
    try:
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa, utils
    except ImportError as exc:
        raise SpecError(
            "token algorithm", "asymmetric",
            "requires the BriXTest crypto extra: pip install 'brixtest[crypto]'",
        ) from exc
    return hashes, serialization, ec, padding, rsa, utils


def _b64(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode()


def _integer(value: int) -> str:
    size = max(1, (value.bit_length() + 7) // 8)
    return _b64(value.to_bytes(size, "big"))


def generate_keypair(algorithm: str, key_bits: int) -> Tuple[bytes, bytes]:
    """Generate a PEM private/public pair for ES256 or RS256."""
    _hashes, serialization, ec, _padding, rsa, _utils = _crypto()
    key = ec.generate_private_key(ec.SECP256R1()) if algorithm == "ES256" else (
        rsa.generate_private_key(public_exponent=65537, key_size=key_bits)
    )
    private = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    public = key.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return private, public


def sign(value: bytes, algorithm: str, private_key: Union[str, bytes]) -> bytes:
    """Sign compact-JWT input using a declared asymmetric algorithm."""
    hashes, serialization, ec, padding, _rsa, utils = _crypto()
    key = serialization.load_pem_private_key(_bytes(private_key), password=None)
    if algorithm == "RS256":
        return key.sign(value, padding.PKCS1v15(), hashes.SHA256())
    encoded = key.sign(value, ec.ECDSA(hashes.SHA256()))
    left, right = utils.decode_dss_signature(encoded)
    return left.to_bytes(32, "big") + right.to_bytes(32, "big")


def verify(
    value: bytes, signature: bytes, algorithm: str,
    public_key: Union[str, bytes],
) -> None:
    """Verify compact-JWT input or raise a structured signature error."""
    hashes, serialization, ec, padding, _rsa, utils = _crypto()
    key = serialization.load_pem_public_key(_bytes(public_key))
    selected = signature
    if algorithm == "ES256":
        if len(signature) != 64:
            raise SpecError("token.signature", "invalid", "ES256 signature must be 64 bytes")
        selected = utils.encode_dss_signature(
            int.from_bytes(signature[:32], "big"), int.from_bytes(signature[32:], "big"),
        )
    try:
        if algorithm == "RS256":
            key.verify(selected, value, padding.PKCS1v15(), hashes.SHA256())
        else:
            key.verify(selected, value, ec.ECDSA(hashes.SHA256()))
    except Exception as exc:
        raise SpecError(
            "token.signature", "invalid", "does not match the configured public key",
        ) from exc


def jwk(public_key: Union[str, bytes], algorithm: str, key_id: str) -> Mapping[str, str]:
    """Return the public key as a standards-shaped JSON Web Key."""
    _hashes, serialization, _ec, _padding, _rsa, _utils = _crypto()
    key = serialization.load_pem_public_key(_bytes(public_key))
    common = {"use": "sig", "alg": algorithm, "kid": key_id}
    if algorithm == "RS256":
        numbers = key.public_numbers()
        return {"kty": "RSA", "n": _integer(numbers.n), "e": _integer(numbers.e), **common}
    numbers = key.public_numbers()
    return {
        "kty": "EC", "crv": "P-256", "x": _integer(numbers.x),
        "y": _integer(numbers.y), **common,
    }


def write_keyset(root: Path, algorithm: str, key_bits: int, key_id: str) -> dict[str, Path]:
    """Write mode-0600 signing material and public JWKS into one auth root."""
    private, public = generate_keypair(algorithm, key_bits)
    private_path, public_path = root / "signing.key", root / "signing.pem"
    private_path.write_bytes(private)
    private_path.chmod(0o600)
    public_path.write_bytes(public)
    jwks = root / "jwks.json"
    jwks.write_text(json.dumps({"keys": [jwk(public, algorithm, key_id)]}, indent=2) + "\n")
    return {"private_key": private_path, "public_key": public_path, "jwks": jwks}


def _bytes(value: Union[str, bytes]) -> bytes:
    return value if isinstance(value, bytes) else value.encode()


__all__ = ["generate_keypair", "jwk", "sign", "verify", "write_keyset"]
