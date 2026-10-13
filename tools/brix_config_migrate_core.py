"""Data model and input parsing for :mod:`brix_config_migrate`.

This module is intentionally dependency-free so the migration command remains
a standalone release artifact.  It parses text only and never evaluates an
include, expands an environment variable, or loads an XRootD plugin.
"""
from __future__ import annotations

import re
import shlex
import unicodedata
from dataclasses import dataclass, field


@dataclass(frozen=True)
class Directive:
    """One tokenized XRootD directive and its source location."""

    name: str
    args: tuple[str, ...]
    line: int


@dataclass(frozen=True)
class Finding:
    """One conversion decision without copying possibly-secret arguments."""

    severity: str
    line: int
    directive: str
    message: str


@dataclass
class ConvertOptions:
    """Operator-supplied values that cannot be safely inferred."""

    ca_bundle: str | None = None
    vomsdir: str | None = None
    voms_cert_dir: str | None = None
    ceph_pool: str | None = None
    ceph_conf: str | None = None
    ceph_key_prefix: str | None = None
    n2n_scheme: str | None = None
    n2n_pool: str | None = None
    n2n_prefix: str | None = None
    http_port: str | None = None
    http_connect_timeout: str | None = None
    http_idle_timeout: str | None = None
    authdb_path: str | None = None
    require_vo: list[str] = field(default_factory=list)


@dataclass
class Conversion:
    """Generated directive state and its audit trail."""

    values: dict[str, list[tuple[str, ...]]] = field(default_factory=dict)
    http_values: dict[str, tuple[str, ...]] = field(default_factory=dict)
    findings: list[Finding] = field(default_factory=list)
    http_port: str | None = None

    def set(self, name: str, *args: str) -> None:
        self.values[name] = [tuple(args)]

    def add(self, name: str, *args: str) -> None:
        self.values.setdefault(name, []).append(tuple(args))

    def note(self, severity: str, directive: Directive, message: str) -> None:
        self.findings.append(Finding(severity, directive.line,
                                     directive.name, message))


@dataclass
class PfcState:
    """Values needed to derive the prefetch byte window."""

    blocksize: int | None = None
    prefetch: int | None = None


def _logical_lines(text: str) -> list[tuple[int, str]]:
    """Join backslash continuations while retaining the first source line."""
    if "\x00" in text:
        raise ValueError("NUL byte in input")
    logical: list[tuple[int, str]] = []
    start = 1
    pending = ""
    for number, physical in enumerate(text.splitlines(), 1):
        _validate_physical(physical, number)
        stripped = _normalize_spacing(physical).rstrip()
        start = start if pending else number
        continued = stripped.endswith("\\")
        piece = stripped[:-1] if continued else stripped
        pending = f"{pending} {piece}".strip()
        logical, pending = _finish_logical(
            logical, pending, start, continued)
    if pending:
        raise ValueError(f"unterminated continuation starting on line {start}")
    return logical


def _validate_physical(physical: str, number: int) -> None:
    invalid = any(ord(char) < 32 and char != "\t" for char in physical)
    if invalid:
        raise ValueError(f"control byte on line {number}")


def _normalize_spacing(physical: str) -> str:
    return "".join(" " if unicodedata.category(char) == "Zs" else char
                   for char in physical)


def _finish_logical(logical: list[tuple[int, str]], pending: str,
                    start: int, continued: bool) -> tuple[list[tuple[int, str]], str]:
    if continued:
        return logical, pending
    logical.append((start, pending))
    return logical, ""


def parse_config(text: str) -> list[Directive]:
    """Tokenize XRootD configuration text without evaluating its contents."""
    parsed: list[Directive] = []
    for line, raw in _logical_lines(text):
        lexer = shlex.shlex(raw, posix=True)
        lexer.whitespace_split = True
        lexer.commenters = "#"
        try:
            tokens = list(lexer)
        except ValueError as exc:
            raise ValueError(f"line {line}: {exc}") from exc
        if not tokens:
            continue
        tokens[-1] = tokens[-1].removesuffix(";")
        parsed.append(Directive(tokens[0].lower(), tuple(tokens[1:]), line))
    return parsed


_AUTHDB_VALUE = r"(?:'(?:\\.|[^'\\])*'|\"(?:\\.|[^\"\\])*\"|[^#\s]+)"
_AUTHDB_IDDEF = re.compile(
    rf"^(?P<head>\s*=\s+{_AUTHDB_VALUE})"
    rf"(?P<body>(?:\s+[ghnoru]:\s+{_AUTHDB_VALUE})+)"
    r"(?P<tail>\s*(?:#.*)?)$")
_AUTHDB_PAIR = re.compile(
    rf"(?P<lead>\s+)(?P<selector>[ghnoru]):"
    rf"(?P<separator>\s+)(?P<value>{_AUTHDB_VALUE})")


def _convert_authdb_line(line: str, number: int) -> str:
    raw = line.rstrip("\r\n")
    ending = line[len(raw):]
    _validate_physical(raw, number)
    matched = _AUTHDB_IDDEF.fullmatch(raw)
    if matched is None:
        return line
    body = _AUTHDB_PAIR.sub(
        r"\g<lead>\g<selector>\g<separator>\g<value>",
        matched.group("body"))
    return matched.group("head") + body + matched.group("tail") + ending


def convert_authdb(text: str) -> str:
    """Normalize standard ``o:`` XrdAcc selectors for BriX's XrdAcc reader."""
    if "\x00" in text:
        raise ValueError("NUL byte in authdb input")
    return "".join(_convert_authdb_line(line, number)
                   for number, line in enumerate(text.splitlines(keepends=True), 1))


def _first(directives: list[Directive], name: str) -> Directive | None:
    return next((item for item in directives if item.name == name), None)


def _named(directives: list[Directive], name: str) -> list[Directive]:
    return [item for item in directives if item.name == name]


def _prefer(primary: str | None, fallback: str | None) -> str | None:
    return primary if primary is not None else fallback


def _gsi_option(args: tuple[str, ...], option: str) -> str | None:
    """Read either ``-name:value`` or ``-name value`` GSI option spelling."""
    prefix = f"-{option}:"
    for index, value in enumerate(args):
        if value.startswith(prefix):
            return value[len(prefix):]
        if value == f"-{option}" and index + 1 < len(args):
            return args[index + 1]
    return None


def _auth_protocol(directive: Directive) -> str | None:
    supported = ("gsi", "ztn", "sss", "krb5", "unix", "host", "pwd")
    return next((value for value in directive.args if value.lower() in supported),
                None)


def _size_bytes(value: str) -> int | None:
    match = re.fullmatch(r"([0-9]+)([kmgt]?)b?", value.lower())
    if match is None:
        return None
    shift = {"": 0, "k": 10, "m": 20, "g": 30, "t": 40}[match[2]]
    return int(match[1]) << shift
