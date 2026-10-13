"""Helpers for assertions over BriX's structured native diagnostics."""

from __future__ import annotations

import re


_MESSAGE = re.compile(r'(message=")([^"]*)(" truncated=[01])')
_ESCAPE_RUN = re.compile(r'(?:\\x[0-9a-fA-F]{2})+')


def _utf8_or_none(raw: bytes) -> str | None:
    try:
        decoded = raw.decode("utf-8")
    except UnicodeDecodeError:
        return None
    return decoded if decoded.isprintable() else None


def _decode_printable(match: re.Match[str]) -> str:
    encoded = match.group(0)
    raw = bytes(int(encoded[index + 2:index + 4], 16)
                for index in range(0, len(encoded), 4))
    if any(byte < 0x20 or byte == 0x7f for byte in raw):
        return encoded
    decoded = _utf8_or_none(raw)
    return decoded if decoded is not None else encoded


def semantic_log_text(text: str) -> str:
    """Decode printable message-field escapes for semantic assertions.

    Control-byte escapes remain encoded so this view cannot manufacture a
    forged line. Tests of the wire/log encoding itself must inspect raw text.
    """
    def decode_message(match: re.Match[str]) -> str:
        body = _ESCAPE_RUN.sub(_decode_printable, match.group(2))
        return f"{match.group(1)}{body}{match.group(3)}"

    return _MESSAGE.sub(decode_message, text)
