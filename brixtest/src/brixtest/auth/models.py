"""Immutable declarations for managed authentication stacks."""

from __future__ import annotations

import dataclasses
import re
from typing import Mapping, Optional, Sequence, Tuple

from brixtest.design import _name
from brixtest.errors import SpecError
from brixtest.network import _hostname
from brixtest.util.immutable import freeze_mapping

__all__ = [
    "AuthRecipe", "KerberosAuth", "TLSAuth", "TokenAuth", "VOMSAuth",
    "kerberos_auth", "tls_auth", "token_auth", "voms_auth",
]

_REALM = re.compile(r"^[A-Z][A-Z0-9.-]*[A-Z0-9]$")
_VO = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]*$")


def _kind(value: str, expected: str) -> None:
    if value != expected:
        raise SpecError("auth.kind", value, f"{expected.title()}Auth kind must be {expected}")


def _positive_int(value: object, field: str) -> None:
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        raise SpecError(field, value, "must be a positive integer")


def _key_policy(days: object, key_bits: object, field: str) -> None:
    _positive_int(days, f"{field}.days")
    if isinstance(key_bits, bool) or key_bits not in (2048, 3072, 4096):
        raise SpecError(f"{field}.key_bits", key_bits, "must be 2048, 3072, or 4096")


def _tcp_port(value: object) -> bool:
    return not isinstance(value, bool) and isinstance(value, int) and 0 < value < 65536


def _voms_fqans(vo: str, values: object) -> Tuple[str, ...]:
    if isinstance(values, (str, bytes)) or not isinstance(values, Sequence):
        raise SpecError("voms.fqans", values, "must be an FQAN sequence")
    fqans = tuple(values) or ("/%s/Role=NULL/Capability=NULL" % vo,)
    prefix = "/%s/" % vo
    if not all(_valid_fqan(value, prefix) for value in fqans):
        raise SpecError("voms.fqans", fqans, "must be absolute FQANs beneath the declared VO")
    return fqans


def _valid_fqan(value: object, prefix: str) -> bool:
    return isinstance(value, str) and value.startswith(prefix) and "\n" not in value


def _common_name(value: object, field: str) -> None:
    if not isinstance(value, str) or not value or any(char in value for char in "/\n\r"):
        raise SpecError(field, value, "must be a safe common name")


def _token_identity(value: object, field: str) -> None:
    if not isinstance(value, str) or not value:
        raise SpecError(field, value, "must be non-empty text")


def _token_scopes(value: object) -> Tuple[str, ...]:
    if isinstance(value, (str, bytes)) or not all(
        isinstance(scope, str) and scope for scope in value
    ):
        raise SpecError("token.scopes", value, "must contain non-empty strings")
    return tuple(value)


def _token_claims(value: object) -> Mapping[str, object]:
    if not isinstance(value, Mapping) or not all(isinstance(key, str) for key in value):
        raise SpecError("token.claims", value, "claim names must be strings")
    protected = {"iss", "aud", "sub", "iat", "exp", "scope"}
    overlap = protected.intersection(value)
    if overlap:
        raise SpecError("token.claims", sorted(overlap), "cannot override standard claims")
    return freeze_mapping(value)


def _token_key_policy(
    algorithm: object, key_bits: object, key_id: object, secret: object,
) -> None:
    if algorithm not in ("HS256", "ES256", "RS256"):
        raise SpecError("token.algorithm", algorithm, "must be HS256, ES256, or RS256")
    _token_key_bits(algorithm, key_bits)
    if algorithm != "HS256" and secret:
        raise SpecError(
            "token.secret", "[redacted]",
            "is only valid for HS256; asymmetric private keys are managed by BriXTest",
        )
    _token_identity(key_id, "token.key_id")


def _token_key_bits(algorithm: object, key_bits: object) -> None:
    if algorithm == "RS256" and key_bits not in (2048, 3072, 4096):
        raise SpecError("token.key_bits", key_bits, "must be 2048, 3072, or 4096")
    if algorithm != "RS256" and key_bits != 2048:
        raise SpecError("token.key_bits", key_bits, "is configurable for RS256 only")


def _kerberos_principal(user: object, service: object) -> None:
    if not _simple_principal_component(user):
        raise SpecError("kerberos.user", user, "must be a simple principal component")
    if not _service_principal(service):
        raise SpecError("kerberos.service", service, "must be service/hostname without a realm")


def _simple_principal_component(value: object) -> bool:
    return isinstance(value, str) and bool(value) and not any(
        char in value for char in "@/\n\r"
    )


def _service_principal(value: object) -> bool:
    return isinstance(value, str) and "/" in value and not any(
        char in value for char in "@\n\r"
    )


def _kerberos_secrets(password: object, master_password: object) -> None:
    if not isinstance(password, str) or not isinstance(master_password, str) \
            or not password or not master_password:
        raise SpecError("kerberos.password", "", "passwords must not be empty")


def _kerberos_runtime(port: object, start_kdc: object) -> None:
    if isinstance(port, bool) or not isinstance(port, int) or not 0 <= port < 65536:
        raise SpecError("kerberos.port", port, "must be zero or a TCP port")
    if not isinstance(start_kdc, bool):
        raise SpecError("kerberos.start_kdc", start_kdc, "must be boolean")


def _token_authority_policy(managed: object, rotate_on_restart: object) -> None:
    if not isinstance(managed, bool) or not isinstance(rotate_on_restart, bool):
        raise SpecError(
            "token authority policy", (managed, rotate_on_restart),
            "managed and rotate_on_restart must be boolean",
        )
    if rotate_on_restart and not managed:
        raise SpecError(
            "token.rotate_on_restart", rotate_on_restart,
            "requires managed=True",
        )


@dataclasses.dataclass(frozen=True)
class AuthRecipe:
    """Common identity for a managed authentication recipe."""
    name: str
    kind: str

    def __post_init__(self) -> None:
        _name(self.name, "auth.name")


@dataclasses.dataclass(frozen=True)
class TokenAuth(AuthRecipe):
    """Managed bearer-token issuer and consumer declaration."""
    issuer: str = "https://issuer.test"
    audience: str = "brixtest"
    subject: str = "test-user"
    scopes: Tuple[str, ...] = ("storage.read:/",)
    claims: Mapping[str, object] = dataclasses.field(default_factory=dict)
    secret: str = ""
    lifetime: int = 3600
    algorithm: str = "HS256"
    key_bits: int = 2048
    key_id: str = "brixtest-signing-key"
    managed: bool = False
    rotate_on_restart: bool = False

    def __post_init__(self) -> None:
        super().__post_init__()
        _kind(self.kind, "token")
        if not isinstance(self.issuer, str) or not self.issuer.startswith(("https://", "http://")):
            raise SpecError("token.issuer", self.issuer, "must be an HTTP(S) issuer URL")
        _token_identity(self.audience, "token.audience")
        _token_identity(self.subject, "token.subject")
        if not isinstance(self.secret, str):
            raise SpecError("token.secret", self.secret, "must be text")
        _positive_int(self.lifetime, "token.lifetime")
        _token_key_policy(self.algorithm, self.key_bits, self.key_id, self.secret)
        _token_authority_policy(self.managed, self.rotate_on_restart)
        object.__setattr__(self, "scopes", _token_scopes(self.scopes))
        object.__setattr__(self, "claims", _token_claims(self.claims))


@dataclasses.dataclass(frozen=True)
class TLSAuth(AuthRecipe):
    """Managed private CA, CRL, and mutual-TLS identity declaration."""
    hostname: str = "server.test"
    aliases: Tuple[str, ...] = ()
    client_name: str = "brixtest-client"
    days: int = 2
    key_bits: int = 2048

    def __post_init__(self) -> None:
        super().__post_init__()
        _kind(self.kind, "tls")
        object.__setattr__(self, "hostname", _hostname(self.hostname, "tls.hostname"))
        if isinstance(self.aliases, (str, bytes)) or not isinstance(self.aliases, Sequence):
            raise SpecError("tls.aliases", self.aliases, "must be a hostname sequence")
        aliases = tuple(_hostname(value, "tls.alias") for value in self.aliases)
        if len(set(aliases)) != len(aliases) or self.hostname in aliases:
            raise SpecError("tls.aliases", self.aliases, "must be unique and exclude hostname")
        object.__setattr__(self, "aliases", aliases)
        _common_name(self.client_name, "tls.client_name")
        _key_policy(self.days, self.key_bits, "tls")


@dataclasses.dataclass(frozen=True)
class VOMSAuth(AuthRecipe):
    """Managed VOMS/GSI PKI and proxy declaration."""
    vo: str = "brixtest"
    hostname: str = "voms.test"
    user_name: str = "brixtest-user"
    fqans: Tuple[str, ...] = ()
    port: int = 15000
    days: int = 2
    key_bits: int = 2048

    def __post_init__(self) -> None:
        super().__post_init__()
        _kind(self.kind, "voms")
        if not isinstance(self.vo, str) or _VO.fullmatch(self.vo) is None:
            raise SpecError("voms.vo", self.vo, "must be a safe VO name")
        object.__setattr__(self, "hostname", _hostname(self.hostname, "voms.hostname"))
        object.__setattr__(self, "fqans", _voms_fqans(self.vo, self.fqans))
        _common_name(self.user_name, "voms.user_name")
        if not _tcp_port(self.port):
            raise SpecError("voms.port", self.port, "must be a TCP port")
        _key_policy(self.days, self.key_bits, "voms")


@dataclasses.dataclass(frozen=True)
class KerberosAuth(AuthRecipe):
    """Managed Kerberos realm and credential declaration."""
    realm: str = "BRIXTEST.TEST"
    domain: str = "brixtest.test"
    hostname: str = "kdc.brixtest.test"
    user: str = "test-user"
    service: str = "host/server.brixtest.test"
    password: str = "brixtest-password"
    master_password: str = "brixtest-master-password"
    port: int = 0
    start_kdc: bool = True

    def __post_init__(self) -> None:
        super().__post_init__()
        if self.kind != "kerberos":
            raise SpecError("auth.kind", self.kind, "KerberosAuth kind must be kerberos")
        if not isinstance(self.realm, str) or _REALM.fullmatch(self.realm) is None:
            raise SpecError("kerberos.realm", self.realm, "must be an uppercase Kerberos realm")
        domain = _hostname(self.domain, "kerberos.domain")
        hostname = _hostname(self.hostname, "kerberos.hostname")
        object.__setattr__(self, "domain", domain)
        object.__setattr__(self, "hostname", hostname)
        _kerberos_principal(self.user, self.service)
        _kerberos_secrets(self.password, self.master_password)
        _kerberos_runtime(self.port, self.start_kdc)


def token_auth(
    name: str = "token", *, issuer: str = "https://issuer.test", audience: str = "brixtest",
    subject: str = "test-user", scopes: Tuple[str, ...] = ("storage.read:/",),
    claims: Optional[Mapping[str, object]] = None, secret: str = "", lifetime: int = 3600,
    algorithm: str = "HS256", key_bits: int = 2048,
    key_id: str = "brixtest-signing-key", managed: bool = False,
    rotate_on_restart: bool = False,
) -> TokenAuth:
    """Declare a managed HS256, ES256, or RS256 token authority."""
    return TokenAuth(
        name, "token", issuer, audience, subject, scopes,
        claims if claims is not None else {}, secret, lifetime,
        algorithm, key_bits, key_id, managed, rotate_on_restart,
    )


def tls_auth(
    name: str = "tls", *, hostname: str = "server.test", aliases: Tuple[str, ...] = (),
    client_name: str = "brixtest-client", days: int = 2, key_bits: int = 2048,
) -> TLSAuth:
    """Declare a disposable CA, CRL, host identity, and client identity."""
    return TLSAuth(name, "tls", hostname, aliases, client_name, days, key_bits)


def voms_auth(
    name: str = "voms", *, vo: str = "brixtest", hostname: str = "voms.test",
    user_name: str = "brixtest-user", fqans: Tuple[str, ...] = (), port: int = 15000,
    days: int = 2, key_bits: int = 2048,
) -> VOMSAuth:
    """Declare a disposable VOMS/GSI PKI and proxy credential stack."""
    return VOMSAuth(name, "voms", vo, hostname, user_name, fqans, port, days, key_bits)


def kerberos_auth(
    name: str = "kerberos", *, realm: str = "BRIXTEST.TEST", domain: str = "brixtest.test",
    hostname: str = "kdc.brixtest.test", user: str = "test-user",
    service: str = "host/server.brixtest.test", password: str = "brixtest-password",
    master_password: str = "brixtest-master-password", port: int = 0,
    start_kdc: bool = True,
) -> KerberosAuth:
    """Declare an isolated Kerberos realm, principals, keytab, and ticket."""
    return KerberosAuth(
        name, "kerberos", realm, domain, hostname, user, service, password,
        master_password, port, start_kdc,
    )
