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
    if executable and os.sep not in raw:
        found = shutil.which(raw)
        candidate = Path(found) if found else base / raw
    else:
        candidate = Path(raw)
        if not candidate.is_absolute():
            candidate = base / candidate
    resolved = candidate.resolve()
    if not resolved.is_file():
        raise SpecError("binary path", raw, "does not resolve to a regular file")
    if executable and not os.access(str(resolved), os.X_OK):
        raise SpecError("binary path", raw, "is not executable")
    return resolved


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
        if not isinstance(self.name, str) or not self.name:
            raise SpecError("binary.name", self.name, "must be non-empty text")
        for field in ("path", "library_dir"):
            value = getattr(self, field)
            if not isinstance(value, (str, Path)) or not str(value):
                raise SpecError("binary.%s" % field, value, "must be a file-system path")
            object.__setattr__(self, field, Path(value))
        if self.source is not None:
            if not isinstance(self.source, (str, Path)) or not str(self.source):
                raise SpecError("binary.source", self.source, "must be a file-system path")
            object.__setattr__(self, "source", Path(self.source))
        if not isinstance(self.sha256, str) or self.sha256 and (
            len(self.sha256) != 64
            or any(char not in "0123456789abcdefABCDEF" for char in self.sha256)
        ):
            raise SpecError("binary.sha256", self.sha256, "must be empty or a SHA-256 digest")
        if not self.sha256 and not self.image:
            raise SpecError("binary.sha256", self.sha256, "is required for a local capture")
        if isinstance(self.libraries, (str, bytes)) or not isinstance(self.libraries, Sequence) or not all(
            isinstance(path, (str, Path)) for path in self.libraries
        ):
            raise SpecError("binary.libraries", self.libraries, "must contain paths")
        object.__setattr__(self, "libraries", tuple(Path(path) for path in self.libraries))
        object.__setattr__(self, "_library_sha256", {
            str(path): _sha256(path) if path.is_file() else ""
            for path in self.libraries
        })
        if self.image is not None and not isinstance(self.image, str):
            raise SpecError("binary.image", self.image, "must be text or None")
        if self.image_path is not None and not isinstance(self.image_path, str):
            raise SpecError("binary.image_path", self.image_path, "must be text or None")
        if not isinstance(self.overridden, bool):
            raise SpecError("binary.overridden", self.overridden, "must be boolean")

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
        try:
            raw_overrides = json.loads(os.environ.get("BRIXTEST_BINARY_OVERRIDES_JSON", "{}"))
            overrides = raw_overrides if isinstance(raw_overrides, dict) else {}
        except (TypeError, ValueError):
            overrides = {}
        source_value = overrides.get(declaration.name, declaration.path)
        overridden = declaration.name in overrides
        if source_value is None:
            captured = CapturedBinary(
                name=declaration.name,
                path=Path(declaration.image_path or declaration.name),
                library_dir=Path("."), sha256="", libraries=(),
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

        libraries: List[Path] = []
        declared_sources = [
            _resolve(path, self.source_root, executable=False)
            for path in declaration.libraries
        ]
        sources = list(declared_sources)
        if declaration.discover_libraries:
            pending = [source, *declared_sources]
            inspected = set()
            while pending:
                dependency_owner = pending.pop()
                if dependency_owner in inspected:
                    continue
                inspected.add(dependency_owner)
                discovered = _ldd_libraries(dependency_owner)
                for library in discovered:
                    if library not in inspected:
                        pending.append(library)
                    sources.append(library)
                if len(inspected) + len(pending) > 4096:
                    raise SpecError(
                        "binary libraries", declaration.name,
                        "dependency graph exceeds the 4096-file safety bound",
                    )
        seen: Dict[str, str] = {}
        for library in sorted(set(sources)):
            library_before = library.stat()
            digest = _sha256(library)
            previous = seen.get(library.name)
            if previous is not None and previous != digest:
                raise SpecError(
                    "binary libraries", library.name,
                    "two different libraries have the same basename",
                )
            if previous is None:
                destination = lib_dir / library.name
                shutil.copy2(library, destination)
                library_after = library.stat()
                before_identity = (
                    library_before.st_dev, library_before.st_ino,
                    library_before.st_size, library_before.st_mtime_ns,
                )
                after_identity = (
                    library_after.st_dev, library_after.st_ino,
                    library_after.st_size, library_after.st_mtime_ns,
                )
                if (
                    before_identity != after_identity
                    or _sha256(library) != digest
                    or _sha256(destination) != digest
                ):
                    raise SpecError(
                        "binary library", str(library),
                        "changed while being captured or its copy hash differs",
                    )
                libraries.append(destination)
                seen[library.name] = digest

        after = source.stat()
        after_hash = _sha256(source)
        identity_before = (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns)
        identity_after = (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns)
        if identity_before != identity_after or before_hash != after_hash:
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
