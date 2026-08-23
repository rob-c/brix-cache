"""Immutable, run-scoped capture of declared executables and shared libraries."""

from __future__ import annotations

import dataclasses
import hashlib
import json
import os
import shutil
import subprocess
from pathlib import Path
from typing import Dict, Iterable, List, Mapping, Optional, Sequence, Tuple

from brixtest.design import Binary
from brixtest.errors import SpecError

__all__ = ["BinaryStore", "CapturedBinary"]

_CHUNK = 1 << 20


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while True:
            block = handle.read(_CHUNK)
            if not block:
                return digest.hexdigest()
            digest.update(block)


def _resolve(path: object, base: Path, *, executable: bool) -> Path:
    raw = str(path)
    candidate = _binary_candidate(raw, base, executable)
    resolved = candidate.resolve()
    _validate_binary_path(resolved, raw, executable)
    return resolved


def _binary_candidate(raw: str, base: Path, executable: bool) -> Path:
    if executable and os.sep not in raw:
        found = shutil.which(raw)
        return Path(found) if found else base / raw
    candidate = Path(raw)
    return candidate if candidate.is_absolute() else base / candidate


def _validate_binary_path(resolved: Path, raw: str, executable: bool) -> None:
    if not resolved.is_file():
        raise SpecError("binary path", raw, "does not resolve to a regular file")
    if executable and not os.access(str(resolved), os.X_OK):
        raise SpecError("binary path", raw, "is not executable")


def _ldd_libraries(executable: Path) -> Tuple[Path, ...]:
    try:
        result = subprocess.run(
            ["ldd", str(executable)], capture_output=True, text=True,
            timeout=10.0, check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return ()
    if result.returncode != 0:
        return ()
    paths = []
    for raw in result.stdout.splitlines():
        line = raw.strip()
        candidate = ""
        if "=>" in line:
            candidate = line.split("=>", 1)[1].strip().split(" ", 1)[0]
        elif line.startswith("/"):
            candidate = line.split(" ", 1)[0]
        if candidate and candidate != "not" and Path(candidate).is_file():
            paths.append(Path(candidate).resolve())
    return tuple(sorted(set(paths)))


def _captured_path(value: object, field: str) -> Path:
    if not isinstance(value, (str, Path)) or not str(value):
        raise SpecError("binary.%s" % field, value, "must be a file-system path")
    return Path(value)


def _captured_digest(value: object, *, required: bool) -> None:
    if not _valid_digest(value):
        raise SpecError("binary.sha256", value, "must be empty or a SHA-256 digest")
    if required and not value:
        raise SpecError("binary.sha256", value, "is required for a local capture")


def _valid_digest(value: object) -> bool:
    if not isinstance(value, str):
        return False
    if not value:
        return True
    return len(value) == 64 and all(char in "0123456789abcdefABCDEF" for char in value)


def _captured_libraries(value: object) -> Tuple[Path, ...]:
    if isinstance(value, (str, bytes)) or not isinstance(value, Sequence) \
            or not all(isinstance(path, (str, Path)) for path in value):
        raise SpecError("binary.libraries", value, "must contain paths")
    return tuple(Path(path) for path in value)


def _captured_metadata(item: "CapturedBinary") -> None:
    if item.image is not None and not isinstance(item.image, str):
        raise SpecError("binary.image", item.image, "must be text or None")
    if item.image_path is not None and not isinstance(item.image_path, str):
        raise SpecError("binary.image_path", item.image_path, "must be text or None")
    if not isinstance(item.overridden, bool):
        raise SpecError("binary.overridden", item.overridden, "must be boolean")


def _binary_overrides() -> Mapping[str, object]:
    try:
        value = json.loads(os.environ.get("BRIXTEST_BINARY_OVERRIDES_JSON", "{}"))
    except (TypeError, ValueError):
        return {}
    return value if isinstance(value, dict) else {}


def _file_identity(stat: os.stat_result) -> tuple[int, int, int, int]:
    return stat.st_dev, stat.st_ino, stat.st_size, stat.st_mtime_ns


def _verify_stable(path: Path, before: os.stat_result, digest: str, field: str) -> None:
    if _file_identity(before) != _file_identity(path.stat()) or _sha256(path) != digest:
        raise SpecError(field, str(path), "changed while being captured or its copy hash differs")


def _library_sources(declaration: Binary, source: Path, source_root: Path) -> List[Path]:
    declared = [_resolve(path, source_root, executable=False) for path in declaration.libraries]
    sources = list(declared)
    if not declaration.discover_libraries:
        return sources
    pending = [source, *declared]
    inspected = set()
    while pending:
        owner = pending.pop()
        if owner in inspected:
            continue
        inspected.add(owner)
        discovered = _ldd_libraries(owner)
        pending.extend(_new_libraries(discovered, inspected))
        sources.extend(discovered)
        _validate_graph_size(declaration.name, inspected, pending)
    return sources


def _new_libraries(discovered: Sequence[Path], inspected: set[Path]) -> list[Path]:
    return [library for library in discovered if library not in inspected]


def _validate_graph_size(name: str, inspected: set, pending: Sequence[Path]) -> None:
    if len(inspected) + len(pending) > 4096:
        raise SpecError(
            "binary libraries", name,
            "dependency graph exceeds the 4096-file safety bound",
        )


def _copy_library(library: Path, destination: Path, digest: str) -> None:
    before = library.stat()
    shutil.copy2(library, destination)
    _verify_stable(library, before, digest, "binary library")
    if _sha256(destination) != digest:
        raise SpecError("binary library", str(library), "copy hash differs from its source")


def _capture_libraries(sources: Iterable[Path], lib_dir: Path) -> List[Path]:
    captured: List[Path] = []
    seen: Dict[str, str] = {}
    for library in sorted(set(sources)):
        digest = _sha256(library)
        previous = seen.get(library.name)
        if previous is not None and previous != digest:
            raise SpecError(
                "binary libraries", library.name,
                "two different libraries have the same basename",
            )
        if previous is not None:
            continue
        destination = lib_dir / library.name
        _copy_library(library, destination, digest)
        captured.append(destination)
        seen[library.name] = digest
    return captured


def _validate_captured_name(value: object) -> None:
    if not isinstance(value, str) or not value:
        raise SpecError("binary.name", value, "must be non-empty text")


def _captured_source(value: object) -> Optional[Path]:
    if value is None:
        return None
    return _captured_path(value, "source")


def _library_digests(libraries: Sequence[Path]) -> dict[str, str]:
    return {
        str(path): _sha256(path) if path.is_file() else ""
        for path in libraries
    }


@dataclasses.dataclass(frozen=True)
class CapturedBinary:
    """An immutable executable snapshot and its captured shared libraries."""
    name: str
    path: Path
    library_dir: Path
    sha256: str
    libraries: Tuple[Path, ...]
    image: Optional[str] = None
    image_path: Optional[str] = None
    source: Optional[Path] = None
    overridden: bool = False

    def __post_init__(self) -> None:
        _validate_captured_name(self.name)
        for field in ("path", "library_dir"):
            object.__setattr__(self, field, _captured_path(getattr(self, field), field))
        object.__setattr__(self, "source", _captured_source(self.source))
        _captured_digest(self.sha256, required=not bool(self.image))
        object.__setattr__(self, "libraries", _captured_libraries(self.libraries))
        object.__setattr__(self, "_library_sha256", _library_digests(self.libraries))
        _captured_metadata(self)

    def __fspath__(self) -> str:
        return str(self.path)

    def as_dict(self) -> Dict[str, object]:
        """Return a JSON-safe executable and library provenance record."""
        return {
            "name": self.name, "path": str(self.path),
            "library_dir": str(self.library_dir), "sha256": self.sha256,
            "libraries": [str(path) for path in self.libraries],
            "library_sha256": dict(getattr(self, "_library_sha256", {})),
            "image": self.image, "image_path": self.image_path,
            "source": str(self.source) if self.source is not None else None,
            "overridden": self.overridden,
        }

    def verify(self) -> bool:
        """Return whether a local executable still matches its captured SHA-256."""
        if not self.sha256:
            return False
        try:
            expected = dict(getattr(self, "_library_sha256", {}))
            return (
                self.path.is_file() and _sha256(self.path) == self.sha256
                and all(
                    digest and Path(path).is_file() and _sha256(Path(path)) == digest
                    for path, digest in expected.items()
                )
            )
        except OSError:
            return False


class BinaryStore:
    """Capture once before any server starts; every command uses the snapshot."""

    def __init__(self, root: Path, source_root: Path) -> None:
        self.root = Path(root)
        self.source_root = Path(source_root)
        self._captured: Dict[str, CapturedBinary] = {}
        self._declarations: Dict[str, Binary] = {}

    def capture_all(self, binaries: Iterable[Binary]) -> Mapping[str, CapturedBinary]:
        for declaration in binaries:
            self.capture(declaration)
        self._write_manifest()
        return dict(self._captured)

    def capture(self, declaration: Binary) -> CapturedBinary:
        held = self._captured.get(declaration.name)
        if held is not None:
            if declaration != self._declaration_for(held.name):
                raise SpecError(
                    "binary", declaration.name,
                    "same name was declared with different capture settings",
                )
            return held
        overrides = _binary_overrides()
        source_value = overrides.get(declaration.name, declaration.path)
        overridden = declaration.name in overrides
        if source_value is None:
            captured = CapturedBinary(
                name=declaration.name,
                path=Path(declaration.image_path or declaration.name),
                library_dir=Path(), sha256="", libraries=(),
                image=declaration.image, image_path=declaration.image_path,
            )
            self._captured[declaration.name] = captured
            self._declarations[declaration.name] = declaration
            return captured

        source = _resolve(source_value, self.source_root, executable=True)
        before = source.stat()
        before_hash = _sha256(source)
        target_root = self.root / declaration.name
        bin_dir = target_root / "bin"
        lib_dir = target_root / "lib"
        bin_dir.mkdir(parents=True, exist_ok=False)
        lib_dir.mkdir(parents=True, exist_ok=False)
        target = bin_dir / source.name
        shutil.copy2(source, target)
        target.chmod(target.stat().st_mode | 0o111)

        sources = _library_sources(declaration, source, self.source_root)
        libraries = _capture_libraries(sources, lib_dir)

        after = source.stat()
        after_hash = _sha256(source)
        if _file_identity(before) != _file_identity(after) or before_hash != after_hash:
            raise SpecError(
                "binary path", str(source),
                "changed while it was being captured; retry after the build is stable",
            )
        if _sha256(target) != before_hash:
            raise SpecError("binary copy", str(target), "hash differs from its source")

        captured = CapturedBinary(
            name=declaration.name, path=target, library_dir=lib_dir,
            sha256=before_hash, libraries=tuple(libraries),
            image=declaration.image, image_path=declaration.image_path,
            source=source, overridden=overridden,
        )
        self._captured[declaration.name] = captured
        self._declarations[declaration.name] = declaration
        return captured

    def get(self, name: str) -> CapturedBinary:
        try:
            return self._captured[name]
        except KeyError:
            raise SpecError(
                "binary", name,
                "not captured — known: %s" % ", ".join(sorted(self._captured)),
            ) from None

    def _declaration_for(self, name: str) -> Binary:
        return self._declarations[name]

    def _write_manifest(self) -> None:
        self.root.mkdir(parents=True, exist_ok=True)
        rows = {
            name: {
                "path": str(item.path),
                "sha256": item.sha256,
                "library_dir": str(item.library_dir),
                "libraries": [str(path) for path in item.libraries],
                "library_sha256": dict(getattr(item, "_library_sha256", {})),
                "image": item.image,
                "image_path": item.image_path,
                "source": str(item.source) if item.source else None,
                "overridden": item.overridden,
            }
            for name, item in sorted(self._captured.items())
        }
        (self.root / "manifest.json").write_text(
            json.dumps({"binaries": rows}, indent=2, sort_keys=True) + "\n"
        )
