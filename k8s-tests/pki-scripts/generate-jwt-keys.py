#!/usr/bin/env python3
"""Generate RSA-2048 JWT signing keys in JWKS format for dynamic token auth testing.

This script generates a keypair on-demand (no persistent OAuth provider needed) and:
1. Writes the public key as a JWKS file (for nginx-xrootd `xrootd_token_jwks` directive)
2. Optionally writes both keys to stdout in PEM format for K8s Secret creation

Usage:
    # Generate JWKS file only (for nginx-xrootd server pods):
    python3 generate_jwt_keys.py --mode=jwks --output=/etc/nginx/jwks.json --kid=test-key-1

    # Generate K8s-compatible Secret YAML (for test startup Job):
    python3 generate_jwt_keys.py --mode=secret --output-dir=/tmp/k8s-secrets

    # Output both formats:
    python3 generate_jwt_keys.py --mode=both --output-jwks=/etc/nginx/jwks.json \
                                 --output-secret=/tmp/k8s-secrets/

Environment Variables:
    KEY_ID       Override the key ID (default: test-key-1)
    KEY_ALG      RSA algorithm (RS256, RS384, RS512 — default: RS256)
    EXPIRY_DAYS  JWT token expiry in days (default: 1 — short-lived for testing)

Requirements: cryptography>=42.0.0 (already a test dependency)
"""

import argparse
import base64
import json
import os
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

try:
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.backends import default_backend
except ImportError:
    print("ERROR: 'cryptography' library is required. Install with: pip install cryptography", file=sys.stderr)
    sys.exit(1)


def generate_rsa_keypair(key_size=2048):
    """Generate an RSA-2048 keypair."""
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=key_size,
        backend=default_backend(),
    )
    return private_key


def b64url_encode(data: bytes) -> str:
    """Base64url encode without padding (JWKS standard)."""
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def key_to_jwks(private_key, kid: str) -> dict:
    """Convert RSA private key to JWKS public key representation."""
    # Export public key in SubjectPublicKeyInfo format (DER)
    pub_bytes = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )

    # Extract modulus and exponent using cryptography primitives
    rsa_public_key = private_key.public_key()
    public_numbers = rsa_public_key.public_numbers()

    n_bytes = public_numbers.n.to_bytes((public_numbers.n.bit_length() + 7) // 8, byteorder="big")
    e_bytes = public_numbers.e.to_bytes(3, byteorder="big")  # exponent is always small

    return {
        "kty": "RSA",
        "kid": kid,
        "alg": "RS256",
        "n": b64url_encode(n_bytes),
        "e": b64url_encode(e_bytes),
        "use": "sig",
    }


def generate_jwt_token(private_key, subject: str = "test-user", groups: list[str] | None = None) -> str:
    """Generate a minimal RS256 JWT token for testing (no external auth provider needed)."""
    # Header
    header = {"alg": "RS256", "typ": "JWT", "kid": os.environ.get("KEY_ID", "test-key-1")}

    # Payload — WLCG-compatible claims
    now = datetime.now(timezone.utc)
    payload = {
        "sub": subject,
        "iss": "nginx-xrootd-test",
        "aud": "nginx-xrootd-test-clients",
        "iat": int(now.timestamp()),
        "exp": int((now + timedelta(days=int(os.environ.get("EXPIRY_DAYS", 1)))).timestamp()),
        "nbf": int(now.timestamp()) - 60,  # slightly in the past for flexibility
    }
    if groups:
        payload["wlcg.groups"] = groups

    def encode_payload(payload_part):
        return b64url_encode(json.dumps(payload_part, separators=(",", ":")).encode("utf-8"))

    header_b64 = encode_payload(header)
    payload_b64 = encode_payload(payload)

    # Sign (simplified — uses cryptography library's direct signing)
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import padding, utils

    sign_input = f"{header_b64}.{payload_b64}".encode("ascii")
    signature = private_key.sign(
        sign_input,
        padding.PKCS1v15(),
        hashes.SHA256(),
    )
    sig_b64 = b64url_encode(signature)

    return f"{header_b64}.{payload_b64}.{sig_b64}"


def write_jwks_file(jwks_dict: dict, output_path: str | None = None):
    """Write JWKS to file or stdout."""
    json_str = json.dumps(jwks_dict, indent=2)

    if output_path:
        Path(output_path).parent.mkdir(parents=True, exist_ok=True)
        with open(output_path, "w") as f:
            f.write(json_str)
        print(f"JWKS written to {output_path}", file=sys.stderr)
    else:
        print(json_str)


def write_secret_yaml(private_key, jwks_dict: dict, output_dir: str | None = None):
    """Write K8s Secret YAML containing both keys and JWKS."""
    # Export private key in PEM format
    priv_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode("utf-8")

    # Get public key PEM for reference
    pub_pem = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("utf-8")

    jwks_str = json.dumps(jwks_dict, separators=(",", ":"))

    # Build namespace from environment or default
    namespace = os.environ.get("NAMESPACE", "k8s-tests-dev")
    key_id = os.environ.get("KEY_ID", "test-key-1")

    yaml_content = f"""apiVersion: v1
kind: Secret
metadata:
  name: jwt-signing-keys-{key_id}
  namespace: {namespace}
type: Opaque
stringData:
  private.pem: |
{priv_pem.replace('\\\\n', '\\n')}
  public.pem: |
{pub_pem.replace('\\\\n', '\\n')}
  jwks.json: |
{jwks_str.replace('\\n', '\\n    ')}
"""

    if output_dir:
        Path(output_dir).mkdir(parents=True, exist_ok=True)
        output_path = os.path.join(output_dir, f"jwt-keys-{key_id}.yaml")
        with open(output_path, "w") as f:
            f.write(yaml_content)
        print(f"Secret YAML written to {output_path}", file=sys.stderr)
    else:
        print(yaml_content)


def main():
    parser = argparse.ArgumentParser(description="Generate dynamic JWT keys for nginx-xrootd testing")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--mode-jwks", action="store_true", help="Output JWKS file only (for server pods)")
    group.add_argument("--mode-secret", action="store_true", help="Output K8s Secret YAML")
    group.add_argument("--mode-both", action="store_true", help="Output both formats")

    parser.add_argument("--output-jwks", "-j", default=None, help="JWKS output file path (for --mode-jwks/--mode-both)")
    parser.add_argument("--output-secret", "-s", default=None, help="Secret YAML output directory (for --mode-secret/--mode-both)")

    args = parser.parse_args()

    # Read configuration from environment
    kid = os.environ.get("KEY_ID", "test-key-1")
    key_alg = os.environ.get("KEY_ALG", "RS256")

    print(f"Generating RSA-2048 keypair (kid={kid}, alg={key_alg})...", file=sys.stderr)

    # Generate keys
    private_key = generate_rsa_keypair(2048)
    jwks_entry = key_to_jwks(private_key, kid)
    jwks_dict = {"keys": [jwks_entry]}

    if args.mode_jwks:
        write_jwks_file(jwks_dict, args.output_jwks)
    elif args.mode_secret:
        write_secret_yaml(private_key, jwks_dict, args.output_secret)
    elif args.mode_both:
        write_jwks_file(jwks_dict, args.output_jwks)
        write_secret_yaml(private_key, jwks_dict, args.output_secret or "/tmp")


if __name__ == "__main__":
    main()
