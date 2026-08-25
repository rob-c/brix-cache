"""Small standards-shaped HS256 token issuer and verifier for test stacks."""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import time
from typing import Mapping, Optional, Sequence, Tuple, Union

from brixtest.auth.token_keys import sign as _asymmetric_sign
from brixtest.auth.token_keys import verify as _asymmetric_verify
from brixtest.errors import SpecError

__all__ = ["decode_token", "issue_token", "verify_token"]


def _required_text(field: str, value: object) -> str:
    if not isinstance(value, str) or not value:
        raise SpecError(field, value, "must be non-empty text")
    return value


def _token_time(lifetime: object, now: object) -> int:
    if not _positive_integer(lifetime):
        raise SpecError("token.lifetime", lifetime, "must be a positive integer")
    if not _optional_integer(now):
        raise SpecError("token.now", now, "must be an integer timestamp")
    return int(time.time()) if now is None else int(now)


def _positive_integer(value: object) -> bool:
    return not isinstance(value, bool) and isinstance(value, int) and value > 0


def _optional_integer(value: object) -> bool:
    return value is None or (not isinstance(value, bool) and isinstance(value, int))


def _extra_claims(value: object) -> dict[str, object]:
    if value is not None and not isinstance(value, Mapping):
        raise SpecError("token.claims", value, "must be a mapping")
    extra = dict(value or {})
    if not _string_keys(extra):
        raise SpecError("token.claims", value, "claim names must be strings")
    protected = {"iss", "aud", "sub", "iat", "exp", "scope"}
    conflicts = sorted(protected.intersection(extra))
    if conflicts:
        raise SpecError("token.claims", conflicts, "cannot override standard claims")
    return extra


def _string_keys(value: Mapping[object, object]) -> bool:
    return all(isinstance(key, str) for key in value)


def _scopes(value: object) -> Sequence[str]:
    if isinstance(value, (str, bytes)) or not all(
        isinstance(scope, str) and scope for scope in value
    ):
        raise SpecError("token.scopes", value, "must contain non-empty strings")
    return value


def _signature(secret: str, signing_input: str) -> str:
    digest = hmac.new(secret.encode(), signing_input.encode(), hashlib.sha256).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode()


def _algorithm(value: object) -> str:
    if value not in ("HS256", "ES256", "RS256"):
        raise SpecError("token.algorithm", value, "must be HS256, ES256, or RS256")
    return str(value)


def _key(value: object, field: str) -> Union[str, bytes]:
    if not isinstance(value, (str, bytes)) or not value:
        raise SpecError(field, type(value).__name__, "must contain signing key data")
    return value


def _sign(
    signing_input: str, algorithm: str, secret: str,
    private_key: Union[str, bytes],
) -> str:
    if algorithm == "HS256":
        return _signature(_required_text("token.secret", secret), signing_input)
    signature = _asymmetric_sign(
        signing_input.encode(), algorithm, _key(private_key, "token.private_key"),
    )
    return base64.urlsafe_b64encode(signature).rstrip(b"=").decode()


def _signature_bytes(value: str) -> bytes:
    try:
        return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
    except (ValueError, TypeError) as exc:
        raise SpecError("token.signature", "invalid", "must be base64url data") from exc


def _verify_times(payload: Mapping[str, object], instant: int) -> None:
    expires, issued = payload.get("exp"), payload.get("iat")
    if isinstance(expires, bool) or not isinstance(expires, int) or expires <= instant:
        raise SpecError("token.exp", expires, "token is expired or invalid")
    if isinstance(issued, bool) or not isinstance(issued, int) or issued > instant:
        raise SpecError("token.iat", issued, "token was issued in the future")


def _verify_identity(
    payload: Mapping[str, object], issuer: Optional[str], audience: Optional[str],
) -> None:
    if issuer is not None and payload.get("iss") != issuer:
        raise SpecError("token.iss", payload.get("iss"), "does not match the expected issuer")
    if audience is not None and payload.get("aud") != audience:
        raise SpecError("token.aud", payload.get("aud"), "does not match the expected audience")


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
    *, secret: str = "", issuer: str, audience: str, subject: str,
    scopes: Sequence[str] = (), claims: Optional[Mapping[str, object]] = None,
    lifetime: int = 3600, now: Optional[int] = None, algorithm: str = "HS256",
    private_key: Union[str, bytes] = b"", key_id: str = "",
) -> str:
    """Issue a deterministic-time-capable HS256, ES256, or RS256 JWT."""
    selected_algorithm = _algorithm(algorithm)
    for field, value in (
        ("token.issuer", issuer), ("token.audience", audience), ("token.subject", subject),
    ):
        _required_text(field, value)
    issued = _token_time(lifetime, now)
    extra = _extra_claims(claims)
    payload = {
        "iss": issuer, "aud": audience, "sub": subject, "iat": issued,
        "exp": issued + lifetime, "scope": " ".join(_scopes(scopes)), **extra,
    }
    header = {"alg": selected_algorithm, "typ": "JWT"}
    if key_id:
        header["kid"] = _required_text("token.key_id", key_id)
    signing_input = "%s.%s" % (_encode(header), _encode(payload))
    return "%s.%s" % (
        signing_input, _sign(signing_input, selected_algorithm, secret, private_key),
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
    token: str, *, secret: str = "", issuer: Optional[str] = None,
    audience: Optional[str] = None, now: Optional[int] = None,
    public_key: Union[str, bytes] = b"", algorithms: Sequence[str] = ("HS256",),
) -> Mapping[str, object]:
    """Verify signature, time bounds, and optional issuer/audience constraints."""
    instant = _token_time(1, now)
    header, payload = decode_token(token)
    allowed = tuple(_algorithm(value) for value in algorithms)
    algorithm = header.get("alg")
    if algorithm not in allowed or header.get("typ") != "JWT":
        raise SpecError("token.header", header, "declares an unaccepted JWT algorithm")
    signing_input, encoded_signature = token.rsplit(".", 1)
    _verify_signature(
        signing_input, encoded_signature, str(algorithm), secret, public_key,
    )
    _verify_times(payload, instant)
    _verify_identity(payload, issuer, audience)
    return payload


def _verify_signature(
    signing_input: str, encoded: str, algorithm: str, secret: str,
    public_key: Union[str, bytes],
) -> None:
    if algorithm == "HS256":
        expected = _signature(_required_text("token.secret", secret), signing_input)
        if not hmac.compare_digest(encoded, expected):
            raise SpecError(
                "token.signature", "invalid", "does not match the configured secret",
            )
        return
    _asymmetric_verify(
        signing_input.encode(), _signature_bytes(encoded), algorithm,
        _key(public_key, "token.public_key"),
    )
