"""Case-owned credentials, authentication stacks, and hostname mappings."""

from __future__ import annotations

import os
from pathlib import Path
from typing import Dict, Mapping, Optional, Sequence

from brixtest.auth.models import AuthRecipe
from brixtest.auth.store import AuthStore, MaterializedAuth
from brixtest.credentials import Credential, CredentialStore, MaterializedCredential
from brixtest.errors import SpecError
from brixtest.network import HostMapping
from brixtest.runtime.artifacts import ArtifactStore

__all__ = ["SecurityResources"]

_MISSING = object()


def _merge(*environments: Mapping[str, str]) -> Mapping[str, str]:
    result: Dict[str, str] = {}
    for environment in environments:
        for key, value in environment.items():
            if key in result and result[key] != value:
                raise SpecError("security environment", key, "has conflicting declarations")
            result[key] = value
    return result


class SecurityResources:
    """Materialize, expose, summarize, and tear down all case security inputs."""

    def __init__(
        self, root: Path, source_root: Path, artifacts: ArtifactStore,
        credentials: Sequence[Credential], auth: Sequence[AuthRecipe],
        hosts: Sequence[HostMapping],
    ) -> None:
        self.root = Path(root)
        self.credentials = CredentialStore(self.root / "credentials", source_root, artifacts)
        self.auth = AuthStore(self.root / "auth")
        self.credential_declarations = tuple(credentials)
        self.auth_declarations = tuple(auth)
        self.hosts = tuple(hosts)
        self._previous: Dict[str, object] = {}

    def materialize(self) -> None:
        try:
            self.credentials.materialize_all(self.credential_declarations)
            self.auth.materialize_all(self.auth_declarations)
            environment = self.environment("test")
            self._previous = {key: os.environ.get(key, _MISSING) for key in environment}
            os.environ.update(environment)
        except Exception:
            self.auth.close()
            raise

    def values(
        self, *, credential_base: Optional[Path] = None,
        auth_base: Optional[Path] = None,
    ) -> Mapping[str, object]:
        values = dict(self.credentials.values(credential_base))
        values.update(self.auth.values(auth_base))
        for item in self.hosts:
            values["host_%s" % item.name] = item.hostname
            values["host_%s_address" % item.name] = item.address
        return values

    def environment(
        self, target: str, *, credential_base: Optional[Path] = None,
        auth_base: Optional[Path] = None,
    ) -> Mapping[str, str]:
        return _merge(
            self.credentials.environment(target, credential_base),
            self.auth.environment(target, auth_base),
        )

    def credential(self, name: str) -> MaterializedCredential:
        return self.credentials.get(name)

    def auth_stack(self, name: str) -> MaterializedAuth:
        return self.auth.get(name)

    def resolve(self, hostname: str) -> str:
        normalized = hostname.rstrip(".").lower()
        for item in self.hosts:
            if normalized in item.hostnames:
                return item.address
        raise SpecError("hostname", hostname, "is not declared by this case")

    def reverse(self, address: str) -> str:
        for item in self.hosts:
            if item.reverse and item.address == address:
                return item.hostname
        raise SpecError("reverse address", address, "is not declared for reverse lookup")

    def secure_files(self, target: str) -> Mapping[str, Path]:
        files = {
            (Path("credentials") / name).as_posix(): path
            for name, path in self.credentials.files_for(target).items()
        }
        files.update({
            (Path("auth") / name).as_posix(): path
            for name, path in self.auth.files_for(target).items()
        })
        return files

    def summary(self) -> Mapping[str, object]:
        return {
            "credentials": {
                name: {"path": str(item.path), "sha256": item.sha256, "kind": item.kind}
                for name, item in sorted(self.credentials._items.items())
            },
            "auth": {
                name: {
                    "kind": item.kind, "root": str(item.root),
                    "files": {key: str(path) for key, path in sorted(item.files.items())},
                    "metadata": dict(item.metadata),
                }
                for name, item in sorted(self.auth._items.items())
            },
            "hosts": {
                item.name: {
                    "hostname": item.hostname, "address": item.address,
                    "aliases": list(item.aliases), "reverse": item.reverse,
                }
                for item in self.hosts
            },
        }

    def close(self) -> None:
        error = None
        try:
            self.auth.close()
        except Exception as exc:
            error = exc
        for key, previous in self._previous.items():
            if previous is _MISSING:
                os.environ.pop(key, None)
            else:
                os.environ[key] = str(previous)
        self._previous.clear()
        if error is not None:
            raise error
