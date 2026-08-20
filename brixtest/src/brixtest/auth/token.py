"""Small standards-shaped HS256 token issuer and verifier for test stacks."""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import time
from typing import Mapping, Optional, Sequence, Tuple

from brixtest.errors import SpecError

__all__ = ["decode_token", "issue_token", "verify_token"]


def _encode(value: object) -> str:
    try:
        raw = json.dumps(value, separators=(",", ":"), sort_keys=True).encode()
    except (TypeError, ValueError) as exc:
        raise SpecError("token claims", value, "must be JSON serializable") from exc
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def _decode(value: str) -> object:
    padding = "=" * (-len(value) % 4)
    try:
        return json.loads(base64.urlsafe_b64decode(value + padding))
    except (ValueError, TypeError, json.JSONDecodeError) as exc:
        raise SpecError("token", "malformed", "contains invalid base64url JSON") from exc


def issue_token(
    *, secret: str, issuer: str, audience: str, subject: str,
    scopes: Sequence[str] = (), claims: Optional[Mapping[str, object]] = None,
    lifetime: int = 3600, now: Optional[int] = None,
) -> str:
    """Issue a deterministic-time-capable HS256 JWT for test infrastructure."""
    if not isinstance(secret, str) or not secret:
        raise SpecError("token.secret", secret, "must not be empty")
    for field, value in (
        ("token.issuer", issuer), ("token.audience", audience), ("token.subject", subject),
    ):
        if not isinstance(value, str) or not value:
            raise SpecError(field, value, "must be non-empty text")
    if isinstance(lifetime, bool) or not isinstance(lifetime, int) or lifetime <= 0:
        raise SpecError("token.lifetime", lifetime, "must be a positive integer")
    if now is not None and (isinstance(now, bool) or not isinstance(now, int)):
        raise SpecError("token.now", now, "must be an integer timestamp")
    if isinstance(scopes, (str, bytes)) or not all(
        isinstance(scope, str) and scope for scope in scopes
    ):
        raise SpecError("token.scopes", scopes, "must contain non-empty strings")
    if claims is not None and not isinstance(claims, Mapping):
        raise SpecError("token.claims", claims, "must be a mapping")
    extra = dict(claims or {})
    if not all(isinstance(key, str) for key in extra):
        raise SpecError("token.claims", claims, "claim names must be strings")
    protected = {"iss", "aud", "sub", "iat", "exp", "scope"}
    conflicts = sorted(protected.intersection(extra))
    if conflicts:
        raise SpecError("token.claims", conflicts, "cannot override standard claims")
    issued = int(time.time()) if now is None else int(now)
    payload = {
        "iss": issuer, "aud": audience, "sub": subject, "iat": issued,
        "exp": issued + lifetime, "scope": " ".join(scopes), **extra,
    }
    header = {"alg": "HS256", "typ": "JWT"}
    signing_input = "%s.%s" % (_encode(header), _encode(payload))
    signature = hmac.new(secret.encode(), signing_input.encode(), hashlib.sha256).digest()
    return "%s.%s" % (
        signing_input, base64.urlsafe_b64encode(signature).rstrip(b"=").decode()
    )


def decode_token(token: str) -> Tuple[Mapping[str, object], Mapping[str, object]]:
    """Decode and structurally validate a compact token without verifying it."""
    if not isinstance(token, str):
        raise SpecError("token", type(token).__name__, "must be compact text")
    parts = token.split(".")
    if len(parts) != 3:
        raise SpecError("token", "malformed", "must have three compact JWT segments")
    header, payload = _decode(parts[0]), _decode(parts[1])
    if not isinstance(header, dict) or not isinstance(payload, dict):
        raise SpecError("token", "malformed", "header and payload must be JSON objects")
    return header, payload


def verify_token(
    token: str, *, secret: str, issuer: Optional[str] = None,
    audience: Optional[str] = None, now: Optional[int] = None,
) -> Mapping[str, object]:
    """Verify signature, time bounds, and optional issuer/audience constraints."""
    if not isinstance(secret, str) or not secret:
        raise SpecError("token.secret", secret, "must not be empty")
    if now is not None and (isinstance(now, bool) or not isinstance(now, int)):
        raise SpecError("token.now", now, "must be an integer timestamp")
    header, payload = decode_token(token)
    if header.get("alg") != "HS256" or header.get("typ") != "JWT":
        raise SpecError("token.header", header, "must declare HS256 JWT")
    signing_input, encoded_signature = token.rsplit(".", 1)
    expected = base64.urlsafe_b64encode(
        hmac.new(secret.encode(), signing_input.encode(), hashlib.sha256).digest()
    ).rstrip(b"=").decode()
    if not hmac.compare_digest(encoded_signature, expected):
        raise SpecError("token.signature", "invalid", "does not match the configured secret")
    instant = int(time.time()) if now is None else int(now)
    expires = payload.get("exp")
    issued = payload.get("iat")
    if isinstance(expires, bool) or not isinstance(expires, int) or expires <= instant:
        raise SpecError("token.exp", expires, "token is expired or invalid")
    if isinstance(issued, bool) or not isinstance(issued, int) or issued > instant:
        raise SpecError("token.iat", issued, "token was issued in the future")
    if issuer is not None and payload.get("iss") != issuer:
        raise SpecError("token.iss", payload.get("iss"), "does not match the expected issuer")
    if audience is not None and payload.get("aud") != audience:
        raise SpecError("token.aud", payload.get("aud"), "does not match the expected audience")
    return payload
