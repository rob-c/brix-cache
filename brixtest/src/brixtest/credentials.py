"""First-class custom credential declarations and confined materialization."""

from __future__ import annotations

import base64
import dataclasses
import hashlib
import hmac
import json
import re
import shutil
from collections.abc import Iterable as IterableABC
from pathlib import Path
from typing import Dict, IO, Iterable, Mapping, Optional, Sequence, Tuple, Union

from brixtest.design import Artifact, _name
from brixtest.errors import SpecError
from brixtest.resources import Reference, credential_ref
from brixtest.runtime.artifacts import ArtifactStore

__all__ = [
    "Credential", "CredentialStore", "MaterializedCredential", "checksum_credential",
    "credential", "signed_credential",
]

_ENV_NAME = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
_KINDS = frozenset({"text", "file", "checksum", "signed"})
_TARGETS = frozenset({"test", "server", "client"})
_ENV_VALUES = frozenset({"path", "content"})
_HASHES = frozenset(hashlib.algorithms_guaranteed - {"shake_128", "shake_256"})


def _destination(value: str) -> str:
    if not isinstance(value, str):
        raise SpecError("credential.destination", value, "must be text")
    path = Path(value)
    if not value or path.is_absolute() or ".." in path.parts or path.name in ("", "."):
        raise SpecError("credential.destination", value, "must be a confined relative file path")
    return path.as_posix()


@dataclasses.dataclass(frozen=True)
class Credential:
    """One generated or copied secret with explicit consumers and exposure."""

    name: str
    kind: str
    value: str = ""
    source: Optional[Union[str, Path]] = None
    artifact: Optional[Artifact] = None
    secret: str = ""
    algorithm: str = "sha256"
    destination: str = ""
    env: Optional[str] = None
    env_value: str = "path"
    targets: Tuple[str, ...] = ("test", "server", "client")
    mode: int = 0o600

    def ref(self, *, directory: bool = False) -> Reference:
        """Reference this credential's role-approved runtime path."""
        return credential_ref(self, directory=directory)

    def __post_init__(self) -> None:
        _name(self.name, "credential.name")
        if not isinstance(self.kind, str) or self.kind not in _KINDS:
            raise SpecError("credential.kind", self.kind, "must be text, file, checksum, or signed")
        if self.kind == "file" and self.source is None:
            raise SpecError("credential.source", self.source, "is required for file credentials")
        if self.kind == "checksum" and not isinstance(self.artifact, Artifact):
            raise SpecError("credential.artifact", self.artifact, "must be an Artifact declaration")
        if self.kind == "signed" and not self.secret:
            raise SpecError("credential.secret", self.secret, "is required for signed credentials")
        if not isinstance(self.value, str) or not isinstance(self.secret, str):
            raise SpecError("credential content", self.name, "value and secret must be text")
        if not isinstance(self.algorithm, str) or self.algorithm not in _HASHES:
            raise SpecError("credential.algorithm", self.algorithm, "must be a fixed-length secure hash")
        destination = self.destination or "credentials/%s.cred" % self.name
        object.__setattr__(self, "destination", _destination(destination))
        if self.env is not None and (
            not isinstance(self.env, str) or _ENV_NAME.fullmatch(self.env) is None
        ):
            raise SpecError("credential.env", self.env, "must be a valid environment name")
        if not isinstance(self.env_value, str) or self.env_value not in _ENV_VALUES:
            raise SpecError("credential.env_value", self.env_value, "must be path or content")
        if isinstance(self.targets, (str, bytes)) or not isinstance(self.targets, IterableABC):
            raise SpecError("credential.targets", self.targets, "must be a target sequence")
        raw_targets = tuple(self.targets)
        if not raw_targets or not all(isinstance(target, str) for target in raw_targets):
            raise SpecError("credential.targets", self.targets, "must select test, server, or client")
        targets = tuple(dict.fromkeys(raw_targets))
        if set(targets) - _TARGETS:
            raise SpecError("credential.targets", self.targets, "must select test, server, or client")
        object.__setattr__(self, "targets", targets)
        if isinstance(self.mode, bool) or not isinstance(self.mode, int) or not 0 <= self.mode <= 0o777:
            raise SpecError("credential.mode", self.mode, "must be an integer file mode")
        if self.mode & 0o022:
            raise SpecError("credential.mode", oct(self.mode), "must not be group/world writable")


def credential(
    name: str, value: str = "", *, source: Optional[Union[str, Path]] = None,
    destination: str = "", env: Optional[str] = None, env_value: str = "path",
    targets: Iterable[str] = ("test", "server", "client"), mode: int = 0o600,
) -> Credential:
    """Declare a text or copied-file credential and its permitted consumers."""
    if source is not None and value:
        raise SpecError("credential", name, "value and source are mutually exclusive")
    if isinstance(targets, (str, bytes)) or not isinstance(targets, IterableABC):
        raise SpecError("credential.targets", targets, "must be a target sequence")
    return Credential(
        name, "file" if source is not None else "text", value=value, source=source,
        destination=destination, env=env, env_value=env_value,
        targets=tuple(targets), mode=mode,
    )


def checksum_credential(
    name: str, artifact: Artifact, *, algorithm: str = "sha256", destination: str = "",
    env: Optional[str] = None, env_value: str = "path",
    targets: Iterable[str] = ("test", "server", "client"), mode: int = 0o600,
) -> Credential:
    """Declare a checksum file derived from a materialized input artifact."""
    if isinstance(targets, (str, bytes)) or not isinstance(targets, IterableABC):
        raise SpecError("credential.targets", targets, "must be a target sequence")
    return Credential(
        name, "checksum", artifact=artifact, algorithm=algorithm,
        destination=destination, env=env, env_value=env_value,
        targets=tuple(targets), mode=mode,
    )


def signed_credential(
    name: str, payload: str, *, secret: str, algorithm: str = "sha256",
    destination: str = "", env: Optional[str] = None, env_value: str = "content",
    targets: Iterable[str] = ("test", "server", "client"), mode: int = 0o600,
) -> Credential:
    """Declare a compact HMAC-signed payload for selected consumer roles."""
    if isinstance(targets, (str, bytes)) or not isinstance(targets, IterableABC):
        raise SpecError("credential.targets", targets, "must be a target sequence")
    return Credential(
        name, "signed", value=payload, secret=secret, algorithm=algorithm,
        destination=destination, env=env, env_value=env_value,
        targets=tuple(targets), mode=mode,
    )


def _digest(path: Path, algorithm: str = "sha256") -> str:
    digest = hashlib.new(algorithm)
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1 << 20), b""):
            digest.update(block)
    return digest.hexdigest()


def _source(value: object, source_root: Path) -> Path:
    candidate = Path(str(value))
    resolved = (source_root / candidate).resolve() if not candidate.is_absolute() else candidate.resolve()
    if not resolved.is_file():
        raise SpecError("credential.source", str(value), "does not resolve to a file")
    return resolved


def _signed(payload: str, secret: str, algorithm: str) -> str:
    body = base64.urlsafe_b64encode(payload.encode()).rstrip(b"=").decode()
    signature = hmac.new(secret.encode(), body.encode(), algorithm).digest()
    encoded = base64.urlsafe_b64encode(signature).rstrip(b"=").decode()
    return "%s.%s" % (body, encoded)


@dataclasses.dataclass(frozen=True)
class MaterializedCredential:
    """A confined credential file available to the current helper role."""
    name: str
    path: Path
    sha256: str
    kind: str
    destination: str
    env: Optional[str]
    env_value: str
    targets: Tuple[str, ...]

    def __post_init__(self) -> None:
        if not isinstance(self.name, str) or not self.name:
            raise SpecError("credential.name", self.name, "must be non-empty text")
        if not isinstance(self.path, (str, Path)) or not str(self.path):
            raise SpecError("credential.path", self.path, "must be a file-system path")
        if not isinstance(self.sha256, str) or len(self.sha256) != 64 \
                or any(char not in "0123456789abcdefABCDEF" for char in self.sha256):
            raise SpecError("credential.sha256", self.sha256, "must be a SHA-256 hex digest")
        if not isinstance(self.kind, str) or not self.kind:
            raise SpecError("credential.kind", self.kind, "must be non-empty text")
        if not isinstance(self.destination, str) or not self.destination:
            raise SpecError("credential.destination", self.destination, "must be non-empty text")
        if self.env is not None and not isinstance(self.env, str):
            raise SpecError("credential.env", self.env, "must be text or None")
        if not isinstance(self.env_value, str) or self.env_value not in _ENV_VALUES:
            raise SpecError("credential.env_value", self.env_value, "must be path or content")
        if isinstance(self.targets, (str, bytes)) or not isinstance(self.targets, Sequence) or not all(
            isinstance(target, str) and target in _TARGETS for target in self.targets
        ) or not self.targets:
            raise SpecError("credential.targets", self.targets, "must select consumer roles")
        object.__setattr__(self, "path", Path(self.path))
        object.__setattr__(self, "targets", tuple(self.targets))

    def __fspath__(self) -> str:
        return str(self.path)

    @property
    def content(self) -> str:
        """Read credential text using UTF-8; prefer ``read_text`` for control."""
        return self.path.read_text()

    def read_text(self, encoding: str = "utf-8", errors: str = "strict") -> str:
        """Read and decode the complete role-approved credential file."""
        return self.path.read_text(encoding=encoding, errors=errors)

    def read_bytes(self) -> bytes:
        """Read the complete role-approved credential file as bytes."""
        return self.path.read_bytes()

    def open(self, mode: str = "rb", *, encoding: Optional[str] = None) -> IO:
        """Open the credential file in binary mode or decoded text mode."""
        if "b" in mode:
            return self.path.open(mode)
        return self.path.open(mode, encoding=encoding or "utf-8")

    def as_dict(self) -> Dict[str, object]:
        """Return secret-free credential provenance and exposure metadata."""
        return {
            "name": self.name, "path": str(self.path), "sha256": self.sha256,
            "kind": self.kind, "destination": self.destination, "env": self.env,
            "env_value": self.env_value, "targets": list(self.targets),
        }

    def verify(self) -> bool:
        """Return whether the credential still matches its captured SHA-256."""
        try:
            return self.path.is_file() and _digest(self.path) == self.sha256
        except OSError:
            return False


class CredentialStore:
    """Own credentials beneath one run and expose only declared targets."""

    def __init__(self, root: Path, source_root: Path, artifacts: ArtifactStore) -> None:
        self.root = Path(root)
        self.source_root = Path(source_root)
        self.artifacts = artifacts
        self._items: Dict[str, MaterializedCredential] = {}

    def materialize_all(self, declarations: Iterable[Credential]) -> Mapping[str, MaterializedCredential]:
        declared = tuple(declarations)
        names = [item.name for item in declared]
        destinations = [item.destination for item in declared]
        duplicate_names = sorted({name for name in names if names.count(name) > 1})
        duplicate_destinations = sorted({
            path for path in destinations if destinations.count(path) > 1
        })
        if duplicate_names:
            raise SpecError("credential", duplicate_names, "is declared more than once")
        if duplicate_destinations:
            raise SpecError(
                "credential.destination", duplicate_destinations,
                "is used more than once",
            )
        self.root.mkdir(parents=True, exist_ok=True)
        for declaration in declared:
            self.materialize(declaration)
        self._write_manifest()
        return dict(self._items)

    def materialize(self, declaration: Credential) -> MaterializedCredential:
        if declaration.name in self._items:
            raise SpecError("credential", declaration.name, "is declared more than once")
        destination = self.root / declaration.destination
        destination.parent.mkdir(parents=True, exist_ok=True)
        if declaration.kind == "file":
            source = _source(declaration.source, self.source_root)
            before = (source.stat().st_size, source.stat().st_mtime_ns, _digest(source))
            shutil.copy2(source, destination)
            after = (source.stat().st_size, source.stat().st_mtime_ns, _digest(source))
            if before != after or _digest(destination) != before[2]:
                raise SpecError("credential.source", str(source), "changed during capture")
        elif declaration.kind == "checksum":
            assert declaration.artifact is not None
            artifact = self.artifacts.get(declaration.artifact.name)
            destination.write_text("%s  %s\n" % (_digest(artifact.path, declaration.algorithm), artifact.path.name))
        elif declaration.kind == "signed":
            destination.write_text(_signed(declaration.value, declaration.secret, declaration.algorithm))
        else:
            destination.write_text(declaration.value)
        destination.chmod(declaration.mode)
        item = MaterializedCredential(
            declaration.name, destination, _digest(destination), declaration.kind,
            declaration.destination, declaration.env, declaration.env_value,
            declaration.targets,
        )
        self._items[item.name] = item
        return item

    def get(self, name: str) -> MaterializedCredential:
        try:
            return self._items[name]
        except KeyError:
            raise SpecError("credential", name, "not materialized — known: %s" % ", ".join(sorted(self._items))) from None

    def values(self, base: Optional[Path] = None) -> Mapping[str, object]:
        values: Dict[str, object] = {}
        for name, item in self._items.items():
            path = (Path(base) / item.destination) if base is not None else item.path
            values["credential_%s" % name] = path
            values["credential_%s_dir" % name] = path.parent
        return values

    def environment(self, target: str, base: Optional[Path] = None) -> Mapping[str, str]:
        result = {}
        for item in self._items.values():
            if target not in item.targets or item.env is None:
                continue
            path = (Path(base) / item.destination) if base is not None else item.path
            result[item.env] = item.content if item.env_value == "content" else str(path)
        return result

    def files_for(self, target: str) -> Mapping[str, Path]:
        return {
            item.destination: item.path for item in self._items.values()
            if target in item.targets
        }

    def _write_manifest(self) -> None:
        rows = {
            name: {
                "path": str(item.path), "sha256": item.sha256, "kind": item.kind,
                "destination": item.destination, "env": item.env,
                "env_value": item.env_value, "targets": list(item.targets),
            }
            for name, item in sorted(self._items.items())
        }
        (self.root / "manifest.json").write_text(json.dumps({"credentials": rows}, indent=2, sort_keys=True) + "\n")
