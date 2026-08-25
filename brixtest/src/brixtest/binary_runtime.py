"""Validation and immutable capture for binary runtime-data files."""

from __future__ import annotations

import hashlib
import shutil
from pathlib import Path
from typing import Mapping, Sequence

from brixtest.errors import SpecError
from brixtest.util.immutable import freeze_mapping


def runtime_file_declarations(value: object) -> Mapping[str, object]:
    """Normalize image destination to local source declarations."""
    if not isinstance(value, Mapping):
        raise SpecError("binary.runtime_files", value, "must map image paths to source paths")
    selected = {}
    for destination, source in value.items():
        selected[_destination(destination)] = _declared_source(source)
    return freeze_mapping(selected)


def _destination(value: object) -> str:
    if not _valid_destination(value):
        raise SpecError(
            "binary.runtime_files destination", value,
            "must be a normalized absolute file path",
        )
    return value


def _valid_destination(value: object) -> bool:
    if not isinstance(value, str):
        return False
    path = Path(value)
    checks = (str(path) == value, path.is_absolute(), ".." not in path.parts, value != "/")
    return all(checks)


def _declared_source(value: object) -> object:
    if not isinstance(value, (str, Path)) or not str(value):
        raise SpecError("binary.runtime_files source", value, "must be a file path")
    return value


def _digest(path: Path) -> str:
    value = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1 << 20), b""):
            value.update(block)
    return value.hexdigest()


def _source(value: object, source_root: Path) -> Path:
    path = Path(str(value))
    selected = (path if path.is_absolute() else source_root / path).resolve()
    if not selected.is_file():
        raise SpecError("binary.runtime_files source", value, "must resolve to a regular file")
    return selected


def _capture(source: Path, destination: Path) -> Path:
    before = source.stat()
    digest = _digest(source)
    destination.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(source, destination)
    stable = (
        (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns)
        == (source.stat().st_dev, source.stat().st_ino, source.stat().st_size, source.stat().st_mtime_ns)
    )
    if not stable or _digest(source) != digest or _digest(destination) != digest:
        raise SpecError("binary.runtime_files source", source, "changed while being captured")
    return destination


def capture_runtime_files(
    declarations: Mapping[str, object], source_root: Path, capture_root: Path,
) -> Mapping[str, Path]:
    """Copy each runtime input once while preserving its image destination."""
    return freeze_mapping({
        destination: _capture(
            _source(source, source_root), capture_root / destination.lstrip("/"),
        )
        for destination, source in declarations.items()
    })


def runtime_file_digests(values: Mapping[str, Path]) -> Mapping[str, str]:
    """Return destination-keyed hashes for verification and provenance."""
    return freeze_mapping({destination: _digest(path) for destination, path in values.items()})


def captured_runtime_files(value: object) -> Mapping[str, Path]:
    """Normalize destination-keyed paths held by a captured binary."""
    declared = runtime_file_declarations(value)
    return freeze_mapping({destination: Path(str(source)) for destination, source in declared.items()})


def replay_runtime_files(value: object) -> Mapping[str, Path]:
    """Validate archived runtime-file identities and return their sources."""
    if not isinstance(value, Sequence) or isinstance(value, (str, bytes)):
        raise SpecError("replay binary runtime_files", value, "must be an identity list")
    selected = {}
    for row in value:
        destination, source = _replay_identity(row)
        if destination in selected:
            raise SpecError(
                "replay binary runtime_files", destination,
                "contains a duplicate image destination",
            )
        selected[destination] = source
    return freeze_mapping(selected)


def _replay_identity(value: object) -> tuple[str, Path]:
    if not isinstance(value, Mapping):
        raise SpecError("replay binary runtime file", value, "must be an identity object")
    declared = runtime_file_declarations({value.get("destination"): value.get("path")})
    destination, raw_source = next(iter(declared.items()))
    source = _source(raw_source, Path.cwd())
    digest = value.get("sha256")
    if not _valid_digest(digest) or _digest(source) != digest:
        raise SpecError(
            "replay binary runtime file", str(source), "does not match its SHA-256",
        )
    return destination, source


def _valid_digest(value: object) -> bool:
    return (
        isinstance(value, str) and len(value) == 64
        and all(char in "0123456789abcdefABCDEF" for char in value)
    )
