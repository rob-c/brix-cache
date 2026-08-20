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

    def __post_init__(self) -> None:
        super().__post_init__()
        if self.kind != "token":
            raise SpecError("auth.kind", self.kind, "TokenAuth kind must be token")
        if not isinstance(self.issuer, str) or not self.issuer.startswith(("https://", "http://")):
            raise SpecError("token.issuer", self.issuer, "must be an HTTP(S) issuer URL")
        if not isinstance(self.audience, str) or not isinstance(self.subject, str) \
                or not self.audience or not self.subject:
            raise SpecError("token", self.name, "audience and subject must not be empty")
        if not isinstance(self.secret, str):
            raise SpecError("token.secret", self.secret, "must be text")
        if isinstance(self.lifetime, bool) or not isinstance(self.lifetime, int) or self.lifetime <= 0:
            raise SpecError("token.lifetime", self.lifetime, "must be a positive integer")
        if isinstance(self.scopes, (str, bytes)) or not all(
            isinstance(scope, str) and scope for scope in self.scopes
        ):
            raise SpecError("token.scopes", self.scopes, "must contain non-empty strings")
        if not isinstance(self.claims, Mapping) or not all(
            isinstance(key, str) for key in self.claims
        ):
            raise SpecError("token.claims", self.claims, "claim names must be strings")
        protected = {"iss", "aud", "sub", "iat", "exp", "scope"}
        if protected.intersection(self.claims):
            raise SpecError("token.claims", sorted(protected.intersection(self.claims)), "cannot override standard claims")
        object.__setattr__(self, "scopes", tuple(self.scopes))
        object.__setattr__(self, "claims", freeze_mapping(self.claims))


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
        if self.kind != "tls":
            raise SpecError("auth.kind", self.kind, "TLSAuth kind must be tls")
        object.__setattr__(self, "hostname", _hostname(self.hostname, "tls.hostname"))
        if isinstance(self.aliases, (str, bytes)) or not isinstance(self.aliases, Sequence):
            raise SpecError("tls.aliases", self.aliases, "must be a hostname sequence")
        aliases = tuple(_hostname(value, "tls.alias") for value in self.aliases)
        if len(set(aliases)) != len(aliases) or self.hostname in aliases:
            raise SpecError("tls.aliases", self.aliases, "must be unique and exclude hostname")
        object.__setattr__(self, "aliases", aliases)
        if not isinstance(self.client_name, str) or not self.client_name \
                or any(char in self.client_name for char in "/\n\r"):
            raise SpecError("tls.client_name", self.client_name, "must be a safe certificate common name")
        if isinstance(self.days, bool) or not isinstance(self.days, int) or self.days <= 0 \
                or isinstance(self.key_bits, bool) or self.key_bits not in (2048, 3072, 4096):
            raise SpecError("tls", self.name, "days must be positive and key_bits must be 2048, 3072, or 4096")


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
        if self.kind != "voms":
            raise SpecError("auth.kind", self.kind, "VOMSAuth kind must be voms")
        if not isinstance(self.vo, str) or _VO.fullmatch(self.vo) is None:
            raise SpecError("voms.vo", self.vo, "must be a safe VO name")
        object.__setattr__(self, "hostname", _hostname(self.hostname, "voms.hostname"))
        if isinstance(self.fqans, (str, bytes)) or not isinstance(self.fqans, Sequence):
            raise SpecError("voms.fqans", self.fqans, "must be an FQAN sequence")
        fqans = tuple(self.fqans) or ("/%s/Role=NULL/Capability=NULL" % self.vo,)
        if not all(
            isinstance(value, str) and value.startswith("/%s/" % self.vo) and "\n" not in value
            for value in fqans
        ):
            raise SpecError("voms.fqans", fqans, "must be absolute FQANs beneath the declared VO")
        object.__setattr__(self, "fqans", fqans)
        if not isinstance(self.user_name, str) or not self.user_name \
                or any(char in self.user_name for char in "/\n\r"):
            raise SpecError("voms.user_name", self.user_name, "must be a safe common name")
        if isinstance(self.port, bool) or not isinstance(self.port, int) or not 0 < self.port < 65536:
            raise SpecError("voms.port", self.port, "must be a TCP port")
        if isinstance(self.days, bool) or not isinstance(self.days, int) or self.days <= 0 \
                or isinstance(self.key_bits, bool) or self.key_bits not in (2048, 3072, 4096):
            raise SpecError("voms", self.name, "invalid validity or RSA key size")


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
        if not isinstance(self.user, str) or not self.user \
                or any(char in self.user for char in "@/\n\r"):
            raise SpecError("kerberos.user", self.user, "must be a simple principal component")
        if not isinstance(self.service, str) or "/" not in self.service \
                or any(char in self.service for char in "@\n\r"):
            raise SpecError("kerberos.service", self.service, "must be service/hostname without a realm")
        if not isinstance(self.password, str) or not isinstance(self.master_password, str) \
                or not self.password or not self.master_password:
            raise SpecError("kerberos.password", "", "passwords must not be empty")
        if isinstance(self.port, bool) or not isinstance(self.port, int) or not 0 <= self.port < 65536:
            raise SpecError("kerberos.port", self.port, "must be zero or a TCP port")
        if not isinstance(self.start_kdc, bool):
            raise SpecError("kerberos.start_kdc", self.start_kdc, "must be boolean")


def token_auth(
    name: str = "token", *, issuer: str = "https://issuer.test", audience: str = "brixtest",
    subject: str = "test-user", scopes: Tuple[str, ...] = ("storage.read:/",),
    claims: Optional[Mapping[str, object]] = None, secret: str = "", lifetime: int = 3600,
) -> TokenAuth:
    """Declare a managed HS256 bearer-token issuer and test credential."""
    return TokenAuth(
        name, "token", issuer, audience, subject, scopes,
        claims if claims is not None else {}, secret, lifetime,
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
