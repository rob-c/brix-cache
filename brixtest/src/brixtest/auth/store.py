"""Materialize authentication recipes and hand each role only its credentials."""

from __future__ import annotations

import dataclasses
import hashlib
import json
import secrets
import shutil
import stat
import subprocess
from pathlib import Path
from typing import Dict, Iterable, Mapping, Optional, Tuple

from brixtest.auth.kerberos import KerberosRealm, create_realm
from brixtest.auth.models import AuthRecipe, KerberosAuth, TLSAuth, TokenAuth, VOMSAuth
from brixtest.auth.pki import OpenSSL, create_pki
from brixtest.auth.token import issue_token
from brixtest.errors import SpecError
from brixtest.util.immutable import freeze_mapping

__all__ = ["AuthStore", "MaterializedAuth"]


def _digest(path: Path) -> str:
    value = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1 << 20), b""):
            value.update(block)
    return value.hexdigest()


def _is_within(path: Path, root: Path) -> bool:
    try:
        path.resolve().relative_to(root.resolve())
        return True
    except ValueError:
        return False


def _close_realm(name: str, realm: KerberosRealm) -> str:
    try:
        realm.close()
    except Exception as exc:
        return "%s: %s" % (name, exc)
    return ""


@dataclasses.dataclass(frozen=True)
class MaterializedAuth:
    """Files, metadata, and role-specific environments for one auth stack."""
    name: str
    kind: str
    root: Path
    files: Mapping[str, Path]
    test_env: Mapping[str, str]
    server_env: Mapping[str, str]
    client_env: Mapping[str, str]
    metadata: Mapping[str, object]

    def __post_init__(self) -> None:
        _validate_auth_text("name", self.name)
        _validate_auth_text("kind", self.kind)
        object.__setattr__(self, "root", _auth_root(self.root))
        _freeze_auth_mappings(self)

    def path(self, name: str) -> Path:
        """Resolve one named file or raise an error listing available names."""
        try:
            return self.files[name]
        except KeyError:
            raise SpecError("auth file", name, "known: %s" % ", ".join(sorted(self.files))) from None

    def environment(self, target: str = "test") -> Mapping[str, str]:
        """Return a copy of the environment intended for one consumer role."""
        environments = {
            "test": self.test_env, "server": self.server_env, "client": self.client_env,
        }
        try:
            return dict(environments[target])
        except KeyError:
            raise SpecError(
                "auth environment target", target, "must be test, server, or client",
            ) from None

    def as_dict(self) -> Dict[str, object]:
        """Return JSON-safe auth provenance without credential values."""
        return {
            "name": self.name, "kind": self.kind, "root": str(self.root),
            "files": {name: str(path) for name, path in sorted(self.files.items())},
            "test_environment_names": sorted(self.test_env),
            "server_environment_names": sorted(self.server_env),
            "client_environment_names": sorted(self.client_env),
            "metadata": dict(self.metadata),
        }


def _replace_root(value: str, old: Path, new: Path) -> str:
    path = Path(value)
    if path.is_absolute() and _is_within(path, old):
        return str(new / path.resolve().relative_to(old.resolve()))
    return value


def _token(root: Path, recipe: TokenAuth) -> MaterializedAuth:
    root.mkdir(parents=True, exist_ok=False)
    secret = recipe.secret or secrets.token_urlsafe(32)
    token = issue_token(
        secret=secret, issuer=recipe.issuer, audience=recipe.audience,
        subject=recipe.subject, scopes=recipe.scopes, claims=recipe.claims,
        lifetime=recipe.lifetime,
    )
    secret_path, token_path = root / "verification.key", root / "access.token"
    secret_path.write_text(secret)
    token_path.write_text(token)
    secret_path.chmod(stat.S_IRUSR | stat.S_IWUSR)
    token_path.chmod(stat.S_IRUSR | stat.S_IWUSR)
    discovery = root / "issuer.json"
    discovery.write_text(json.dumps({
        "issuer": recipe.issuer, "audience": recipe.audience,
        "token_endpoint": "brixtest://managed/%s" % recipe.name,
        "algorithms": ["HS256"],
    }, indent=2, sort_keys=True) + "\n")
    files = {"secret": secret_path, "token": token_path, "issuer": discovery}
    server = {
        "BRIXTEST_TOKEN_SECRET_FILE": str(secret_path),
        "BRIXTEST_TOKEN_ISSUER": recipe.issuer,
        "BRIXTEST_TOKEN_AUDIENCE": recipe.audience,
    }
    consumer = {
        "BEARER_TOKEN": token, "BEARER_TOKEN_FILE": str(token_path),
        "BRIXTEST_TOKEN_ISSUER": recipe.issuer,
        "BRIXTEST_TOKEN_AUDIENCE": recipe.audience,
    }
    return MaterializedAuth(
        recipe.name, recipe.kind, root, files, consumer, server, consumer,
        {"issuer": recipe.issuer, "audience": recipe.audience, "subject": recipe.subject},
    )


def _tls(root: Path, recipe: TLSAuth) -> MaterializedAuth:
    files = dict(create_pki(
        root, authority_name="BriXTest %s CA" % recipe.name,
        hostnames=(recipe.hostname, *recipe.aliases), client_name=recipe.client_name,
        days=recipe.days, key_bits=recipe.key_bits,
    ))
    server = {
        "BRIXTEST_TLS_CA": str(files["ca_cert"]),
        "BRIXTEST_TLS_CRL": str(files["crl"]),
        "BRIXTEST_TLS_CERT": str(files["host_cert"]),
        "BRIXTEST_TLS_KEY": str(files["host_key"]),
        "SSL_CERT_DIR": str(files["trust_dir"]),
    }
    consumer = {
        "SSL_CERT_FILE": str(files["ca_cert"]),
        "SSL_CERT_DIR": str(files["trust_dir"]),
        "BRIXTEST_TLS_CLIENT_CERT": str(files["client_cert"]),
        "BRIXTEST_TLS_CLIENT_KEY": str(files["client_key"]),
        "REQUESTS_CA_BUNDLE": str(files["ca_cert"]),
    }
    return MaterializedAuth(
        recipe.name, recipe.kind, root, files, consumer, server, consumer,
        {"hostname": recipe.hostname, "aliases": list(recipe.aliases)},
    )


def _command(argv, field: str) -> str:
    try:
        result = subprocess.run(
            argv, capture_output=True, text=True, timeout=30.0, check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise SpecError(field, argv[0], str(exc)) from exc
    if result.returncode:
        raise SpecError(field, " ".join(argv), (result.stderr or result.stdout).strip())
    return result.stdout.strip()


def _certificate_subject(openssl: OpenSSL, certificate: Path) -> str:
    value = openssl.run("x509", "-in", str(certificate), "-noout", "-subject", "-nameopt", "compat")
    return value.split("=", 1)[1].strip() if "=" in value else value.strip()


def _voms(root: Path, recipe: VOMSAuth) -> MaterializedAuth:
    openssl = OpenSSL()
    files = dict(create_pki(
        root, authority_name="BriXTest %s VOMS CA" % recipe.name,
        hostnames=(recipe.hostname,), client_name=recipe.user_name,
        days=recipe.days, key_bits=recipe.key_bits, voms_name=recipe.hostname,
        openssl=openssl,
    ))
    vomsdir = root / "vomsdir" / recipe.vo
    vomsdir.mkdir(parents=True)
    voms_subject = _certificate_subject(openssl, files["voms_cert"])
    ca_subject = _certificate_subject(openssl, files["ca_cert"])
    lsc = vomsdir / (recipe.hostname + ".lsc")
    lsc.write_text("%s\n%s\n" % (voms_subject, ca_subject))
    vomses = root / "vomses"
    vomses.write_text(
        '"%s" "%s" "%d" "%s" "%s"\n'
        % (recipe.vo, recipe.hostname, recipe.port, voms_subject, recipe.vo)
    )
    proxy = root / "x509up"
    fake = shutil.which("voms-proxy-fake")
    if fake is None:
        raise SpecError("VOMS recipe", "voms-proxy-fake", "is not installed or not on PATH")
    argv = [
        fake, "-quiet", "-rfc", "-newformat", "-cert", str(files["client_cert"]),
        "-key", str(files["client_key"]), "-hostcert", str(files["voms_cert"]),
        "-hostkey", str(files["voms_key"]), "-out", str(proxy),
        "-uri", "%s:%d" % (recipe.hostname, recipe.port), "-voms", recipe.vo,
    ]
    for fqan in recipe.fqans:
        argv.extend(("-fqan", fqan))
    _command(argv, "VOMS proxy")
    proxy.chmod(stat.S_IRUSR | stat.S_IWUSR)
    files.update({"voms_lsc": lsc, "vomses": vomses, "proxy": proxy, "voms_dir": vomsdir.parent})
    server = {
        "X509_CERT_DIR": str(files["trust_dir"]),
        "X509_VOMS_DIR": str(files["voms_dir"]),
        "BRIXTEST_GSI_HOST_CERT": str(files["host_cert"]),
        "BRIXTEST_GSI_HOST_KEY": str(files["host_key"]),
    }
    consumer = {
        "X509_CERT_DIR": str(files["trust_dir"]),
        "X509_VOMS_DIR": str(files["voms_dir"]),
        "X509_USER_CERT": str(files["client_cert"]),
        "X509_USER_KEY": str(files["client_key"]),
        "X509_USER_PROXY": str(proxy),
        "VOMS_USERCONF": str(vomses),
    }
    return MaterializedAuth(
        recipe.name, recipe.kind, root, files, consumer, server, consumer,
        {"vo": recipe.vo, "hostname": recipe.hostname, "fqans": list(recipe.fqans)},
    )


def _kerberos(root: Path, recipe: KerberosAuth) -> Tuple[MaterializedAuth, KerberosRealm]:
    realm = create_realm(root, recipe)
    files = dict(realm.files)
    server = {
        "KRB5_CONFIG": str(files["config"]),
        "KRB5_KDC_PROFILE": str(files["kdc_config"]),
        "KRB5_KTNAME": str(files["keytab"]),
    }
    consumer = {
        "KRB5_CONFIG": str(files["config"]),
        "KRB5CCNAME": "FILE:%s" % files["cache"],
    }
    materialized = MaterializedAuth(
        recipe.name, recipe.kind, root, files, consumer, server, consumer,
        realm.metadata,
    )
    return materialized, realm


class AuthStore:
    """Own authentication files and service processes for exactly one case."""

    def __init__(self, root: Path) -> None:
        self.root = Path(root)
        self._items: Dict[str, MaterializedAuth] = {}
        self._realms: Dict[str, KerberosRealm] = {}

    def materialize_all(self, recipes: Iterable[AuthRecipe]) -> Mapping[str, MaterializedAuth]:
        self.root.mkdir(parents=True, exist_ok=True)
        for recipe in recipes:
            self.materialize(recipe)
        self._write_manifest()
        return dict(self._items)

    def materialize(self, recipe: AuthRecipe) -> MaterializedAuth:
        if recipe.name in self._items:
            raise SpecError("auth", recipe.name, "is declared more than once")
        root = self.root / recipe.name
        if isinstance(recipe, TokenAuth):
            item = _token(root, recipe)
        elif isinstance(recipe, TLSAuth):
            item = _tls(root, recipe)
        elif isinstance(recipe, VOMSAuth):
            item = _voms(root, recipe)
        elif isinstance(recipe, KerberosAuth):
            item, realm = _kerberos(root, recipe)
            self._realms[recipe.name] = realm
        else:
            raise SpecError("auth", recipe, "has an unsupported recipe type")
        self._items[item.name] = item
        return item

    def get(self, name: str) -> MaterializedAuth:
        try:
            return self._items[name]
        except KeyError:
            raise SpecError("auth", name, "not materialized — known: %s" % ", ".join(sorted(self._items))) from None

    def environment(self, target: str, base: Optional[Path] = None) -> Mapping[str, str]:
        if target not in ("test", "server", "client"):
            raise SpecError("auth target", target, "must be test, server, or client")
        merged: Dict[str, str] = {}
        for item in self._items.values():
            values = _environment_values(item, target, self.root, base)
            _merge_environment(merged, values)
        return merged

    def values(self, base: Optional[Path] = None) -> Mapping[str, object]:
        values: Dict[str, object] = {}
        for item in self._items.values():
            values.update(_auth_values(item, base))
        return values

    def files_for(self, target: str) -> Mapping[str, Path]:
        selected: Dict[str, Path] = {}
        for item in self._items.values():
            selected.update(_auth_files(item, target))
        return selected

    def close(self) -> None:
        errors = [
            error
            for name, realm in reversed(tuple(self._realms.items()))
            if (error := _close_realm(name, realm))
        ]
        self._realms.clear()
        if errors:
            raise SpecError("auth teardown", "kerberos", "; ".join(errors))

    def _write_manifest(self) -> None:
        rows = {}
        for name, item in sorted(self._items.items()):
            rows[name] = {
                "kind": item.kind, "root": str(item.root), "metadata": dict(item.metadata),
                "files": {
                    key: {"path": str(path), "sha256": _digest(path) if path.is_file() else None}
                    for key, path in sorted(item.files.items())
                },
                "test_env": sorted(item.test_env), "server_env": sorted(item.server_env),
                "client_env": sorted(item.client_env),
            }
        (self.root / "manifest.json").write_text(json.dumps({"auth": rows}, indent=2, sort_keys=True) + "\n")


def _validate_auth_text(field: str, value: object) -> None:
    if not isinstance(value, str) or not value:
        raise SpecError("auth.%s" % field, value, "must be non-empty text")


def _auth_root(value: object) -> Path:
    if not isinstance(value, (str, Path)) or not str(value):
        raise SpecError("auth.root", value, "must be a file-system path")
    return Path(value)


def _freeze_auth_mappings(item: MaterializedAuth) -> None:
    for field in ("files", "test_env", "server_env", "client_env", "metadata"):
        value = getattr(item, field)
        if not isinstance(value, Mapping):
            raise SpecError("auth.%s" % field, value, "must be a mapping")
        object.__setattr__(item, field, freeze_mapping(value))


def _environment_values(item, target: str, root: Path, base: Optional[Path]) -> dict:
    values = getattr(item, target + "_env")
    if base is None:
        return dict(values)
    destination = Path(base)
    return {
        key: _replace_root(value, root, destination)
        for key, value in values.items()
    }


def _merge_environment(merged: Dict[str, str], values: Mapping[str, str]) -> None:
    for key, rendered in values.items():
        if key in merged and merged[key] != rendered:
            raise SpecError(
                "auth environment", key, "is supplied by multiple active recipes",
            )
        merged[key] = rendered


def _auth_values(item: MaterializedAuth, base: Optional[Path]) -> dict[str, object]:
    root = item.root if base is None else Path(base) / item.name
    values: dict[str, object] = {"auth_%s" % item.name: root}
    for key, path in item.files.items():
        relative = path.relative_to(item.root)
        values["auth_%s_%s" % (item.name, key)] = root / relative
    for key, value in item.metadata.items():
        values["auth_%s_%s" % (item.name, key)] = value
    return values


def _auth_files(item: MaterializedAuth, target: str) -> dict[str, Path]:
    selected = {}
    environment = getattr(item, target + "_env")
    for value in environment.values():
        path = Path(value.removeprefix("FILE:"))
        if path.is_absolute() and _is_within(path, item.root):
            selected.update(_contained_files(item, path))
    return selected


def _contained_files(item: MaterializedAuth, path: Path) -> dict[str, Path]:
    candidates = path.rglob("*") if path.is_dir() else (path,)
    return {
        (Path(item.name) / candidate.relative_to(item.root)).as_posix(): candidate
        for candidate in candidates
        if candidate.is_file()
    }
