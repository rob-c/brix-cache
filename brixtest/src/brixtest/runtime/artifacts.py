"""Case input materialization: deterministic noise, copied files, and text."""

from __future__ import annotations

import contextlib
import dataclasses
import hashlib
import json
import shutil
from pathlib import Path
from typing import IO, Dict, Iterable, Mapping, Optional

from brixtest.design import Artifact
from brixtest.errors import SpecError
from brixtest.extensions import get_extension, register_extension
from brixtest.services.payloads import make_payload

__all__ = ["ArtifactProviderContext", "ArtifactStore", "MaterializedArtifact"]

_CHUNK = 1 << 20


@dataclasses.dataclass(frozen=True)
class ArtifactProviderContext:
    """Confined, immutable paths supplied to an artifact provider extension."""

    root: Path
    source_root: Path

    def __post_init__(self) -> None:
        if not isinstance(self.root, (str, Path)) or not str(self.root):
            raise SpecError("artifact provider root", self.root, "must be a path")
        if not isinstance(self.source_root, (str, Path)) or not str(self.source_root):
            raise SpecError(
                "artifact provider source_root", self.source_root, "must be a path",
            )
        object.__setattr__(self, "root", Path(self.root).resolve())
        object.__setattr__(self, "source_root", Path(self.source_root).resolve())


def _digest(path: Path) -> str:
    sha256 = hashlib.sha256()
    with path.open("rb") as handle:
        while True:
            block = handle.read(_CHUNK)
            if not block:
                return sha256.hexdigest()
            sha256.update(block)


def _source(path: object, base: Path) -> Path:
    candidate = Path(str(path))
    if not candidate.is_absolute():
        candidate = base / candidate
    resolved = candidate.resolve()
    if not resolved.is_file():
        raise SpecError("artifact source", str(path), "does not resolve to a file")
    return resolved


def _sha256(value: object) -> bool:
    return (
        isinstance(value, str)
        and len(value) == 64
        and all(char in "0123456789abcdefABCDEF" for char in value)
    )


def _non_empty_text(value: object) -> bool:
    return isinstance(value, str) and bool(value)


def _integer(value: object, *, minimum: Optional[int] = None) -> bool:
    if isinstance(value, bool) or not isinstance(value, int):
        return False
    return minimum is None or value >= minimum


@dataclasses.dataclass(frozen=True)
class MaterializedArtifact:
    """A checksum-backed run-local artifact with direct IO conveniences."""
    name: str
    path: Path
    size: int
    sha256: str
    kind: str
    seed: int = 0

    def __post_init__(self) -> None:
        if not _non_empty_text(self.name):
            raise SpecError("artifact.name", self.name, "must be non-empty text")
        if not isinstance(self.path, (str, Path)):
            raise SpecError("artifact.path", self.path, "must be a file-system path")
        if not str(self.path):
            raise SpecError("artifact.path", self.path, "must be a file-system path")
        if not _integer(self.size, minimum=0):
            raise SpecError("artifact.size", self.size, "must be an integer >= 0")
        if not _sha256(self.sha256):
            raise SpecError("artifact.sha256", self.sha256, "must be a SHA-256 hex digest")
        if not _non_empty_text(self.kind):
            raise SpecError("artifact.kind", self.kind, "must be non-empty text")
        if not _integer(self.seed):
            raise SpecError("artifact.seed", self.seed, "must be an integer")
        object.__setattr__(self, "path", Path(self.path))

    def __fspath__(self) -> str:
        return str(self.path)

    def read_text(self, encoding: str = "utf-8", errors: str = "strict") -> str:
        """Read and decode the complete captured artifact."""
        return self.path.read_text(encoding=encoding, errors=errors)

    def read_bytes(self) -> bytes:
        """Read the complete captured artifact as bytes."""
        return self.path.read_bytes()

    def open(self, mode: str = "rb", *, encoding: Optional[str] = None) -> IO:
        """Open the captured file in binary mode or decoded text mode."""
        if "b" in mode:
            return self.path.open(mode)
        return self.path.open(mode, encoding=encoding or "utf-8")

    def as_dict(self) -> Dict[str, object]:
        """Return a JSON-safe provenance record."""
        return {
            "name": self.name, "path": str(self.path), "size": self.size,
            "sha256": self.sha256, "kind": self.kind, "seed": self.seed,
        }

    def read_json(self, *, encoding: str = "utf-8") -> object:
        """Decode a text artifact as JSON with a BriXTest-native error."""
        try:
            return json.loads(self.read_text(encoding=encoding))
        except (OSError, UnicodeError, ValueError) as exc:
            raise SpecError(
                "artifact %s JSON" % self.name, str(self.path),
                "must contain valid encoded JSON",
            ) from exc

    def verify(self) -> bool:
        """Return whether size and SHA-256 still match the captured manifest."""
        try:
            return self.path.stat().st_size == self.size and _digest(self.path) == self.sha256
        except OSError:
            return False


class ArtifactStore:
    def __init__(self, root: Path, source_root: Path) -> None:
        self.root = Path(root)
        self.source_root = Path(source_root)
        self._items: Dict[str, MaterializedArtifact] = {}

    def materialize_all(
        self, declarations: Iterable[Artifact]
    ) -> Mapping[str, MaterializedArtifact]:
        self.root.mkdir(parents=True, exist_ok=True)
        for declaration in declarations:
            self.materialize(declaration)
        self._write_manifest()
        return dict(self._items)

    def materialize(self, declaration: Artifact) -> MaterializedArtifact:
        if declaration.name in self._items:
            raise SpecError("artifact", declaration.name, "is declared more than once")
        directory = self.root / declaration.name
        directory.mkdir(parents=True, exist_ok=False)
        destination = directory / declaration.filename
        provider = get_extension("provider", declaration.kind)
        provider.validate(declaration)
        result = provider.materialize(
            declaration, destination,
            ArtifactProviderContext(directory, self.source_root),
        )
        selected = _provider_result(result, destination, directory)
        item = MaterializedArtifact(
            declaration.name, selected, selected.stat().st_size,
            _digest(selected), declaration.kind, declaration.seed,
        )
        self._items[declaration.name] = item
        return item

    def get(self, name: str) -> MaterializedArtifact:
        try:
            return self._items[name]
        except KeyError:
            raise SpecError(
                "artifact", name,
                "not materialized — known: %s" % ", ".join(sorted(self._items)),
            ) from None

    def _write_manifest(self) -> None:
        rows = {
            name: dataclasses.asdict(item) for name, item in sorted(self._items.items())
        }
        (self.root / "manifest.json").write_text(
            json.dumps({"artifacts": rows}, indent=2, sort_keys=True, default=str) + "\n"
        )


def _provider_result(result: object, destination: Path, root: Path) -> Path:
    """Normalize provider output while keeping the selected file confined."""
    selected = _selected_provider_path(result, destination, root)
    return _confined_provider_path(selected, root)


def _selected_provider_path(result: object, destination: Path, root: Path) -> Path:
    if isinstance(result, bytes):
        destination.write_bytes(result)
        return destination
    if isinstance(result, str):
        destination.write_text(result)
        return destination
    if result is None:
        return destination
    if isinstance(result, Path):
        return result if result.is_absolute() else root / result
    raise SpecError(
        "artifact provider result", type(result).__name__,
        "must be bytes, text, a confined Path, or None",
    )


def _confined_provider_path(selected: Path, root: Path) -> Path:
    try:
        resolved = selected.resolve()
        resolved.relative_to(root.resolve())
    except ValueError:
        raise SpecError(
            "artifact provider result", str(selected),
            "must remain inside the artifact run directory",
        ) from None
    if selected.is_symlink() or not resolved.is_file():
        raise SpecError(
            "artifact provider result", str(selected),
            "must be a regular non-symlink file",
        )
    return resolved


class _NoiseProvider:
    brixtest_api_version = 1
    brixtest_capabilities = ("checksum", "confined", "provenance")

    def validate(self, declaration: Artifact) -> None:
        return None

    def materialize(
        self, declaration: Artifact, destination: Path, context: ArtifactProviderContext,
    ) -> Path:
        return make_payload(
            context.root, size=declaration.size, seed=declaration.seed,
            name=destination.name,
        ).path


class _TextProvider:
    brixtest_api_version = 1
    brixtest_capabilities = ("checksum", "confined", "provenance")

    def validate(self, declaration: Artifact) -> None:
        return None

    def materialize(
        self, declaration: Artifact, destination: Path, context: ArtifactProviderContext,
    ) -> str:
        return declaration.text


class _FileProvider:
    brixtest_api_version = 1
    brixtest_capabilities = ("checksum", "confined", "provenance")

    def validate(self, declaration: Artifact) -> None:
        return None

    def materialize(
        self, declaration: Artifact, destination: Path, context: ArtifactProviderContext,
    ) -> Path:
        source = _source(declaration.source, context.source_root)
        before = (source.stat().st_size, source.stat().st_mtime_ns, _digest(source))
        shutil.copy2(source, destination)
        after = (source.stat().st_size, source.stat().st_mtime_ns, _digest(source))
        if before != after or _digest(destination) != before[2]:
            raise SpecError(
                "artifact source", str(source),
                "changed while being captured; retry with stable inputs",
            )
        return destination


for _provider_name, _provider in (
    ("noise", _NoiseProvider()), ("text", _TextProvider()), ("file", _FileProvider()),
):
    with contextlib.suppress(SpecError):
        register_extension(
            "provider", _provider_name, _provider, origin="brixtest",
            capabilities=("checksum", "confined", "provenance"),
        )
