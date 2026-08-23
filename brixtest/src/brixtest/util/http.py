"""Validation shared by HTTP-based collectors and exporters."""

from __future__ import annotations

import re
from urllib.parse import urlsplit

from brixtest.errors import SpecError

_SERVER_URL = re.compile(r"^\{server_[A-Za-z0-9_]+_url\}(?:/.*)?$")


def http_url(value: object, field: str, *, allow_server_reference: bool = False) -> str:
    """Return an HTTP(S) URL or raise a field-specific specification error."""
    if not isinstance(value, str) or not value:
        raise SpecError(field, value, "must be a non-empty HTTP(S) URL")
    if allow_server_reference and _SERVER_URL.fullmatch(value):
        return value
    parsed = _parse_url(value, field)
    if parsed.scheme not in ("http", "https") or not parsed.hostname:
        raise SpecError(field, value, "must use http:// or https:// with a hostname")
    return value


def _parse_url(value: str, field: str):
    try:
        parsed = urlsplit(value)
        parsed.hostname
    except ValueError as exc:
        raise SpecError(field, value, "must be a valid HTTP(S) URL") from exc
    return parsed
