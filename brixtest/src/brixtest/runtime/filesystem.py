"""Backend-neutral service filesystem facade and confined native transport."""

from __future__ import annotations

import hashlib
import os
import shutil
import stat as stat_module
import tempfile
from pathlib import Path
from typing import Callable, Mapping, Optional, Sequence, Union

from brixtest.errors import SpecError
from brixtest.util.immutable import freeze_mapping


def _digest(path: Path) -> str:
    if not path.is_file():
        return ""
    value = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1 << 20), b""):
            value.update(block)
    return value.hexdigest()


def _path_text(value: object, field: str) -> str:
    if not isinstance(value, (str, Path)) or not str(value) or "\x00" in str(value):
        raise SpecError(field, value, "must be a non-empty NUL-free path")
    return str(value)


def _inside(path: Path, roots: Sequence[Path]) -> bool:
    return any(path == root or root in path.parents for root in roots)


def _mode(value: object) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value <= 0o7777:
        raise SpecError("filesystem mode", value, "must be an integer from 0 through 0o7777")
    return value


def _owner_id(value: object, field: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < -1:
        raise SpecError(field, value, "must be -1 or a non-negative integer")
    return value


def _xattr_name(value: object) -> str:
    if not isinstance(value, str) or not value.startswith("user.") or "\x00" in value:
        raise SpecError("filesystem xattr", value, "must be a NUL-free user.* attribute")
    return value


class NativeFilesystem:
    """Perform native operations within explicit service-owned roots."""

    def __init__(
        self, roots: Sequence[Path], *,
        observer: Optional[Callable[[str, Mapping[str, object]], None]] = None,
    ) -> None:
        self.roots = tuple(Path(root).resolve() for root in roots)
        if not self.roots:
            raise SpecError("filesystem roots", roots, "must not be empty")
        self.observer = observer

    def _path(self, value: object, *, follow: bool = True) -> Path:
        text = _path_text(value, "filesystem path")
        raw = Path(text)
        candidate = raw if raw.is_absolute() else self.roots[0] / raw
        selected = candidate.resolve() if follow else candidate.parent.resolve() / candidate.name
        if not _inside(selected, self.roots):
            raise SpecError("filesystem path", text, "escapes the declared service roots")
        return selected

    def _mutable(self, value: object, *, follow: bool = True) -> Path:
        selected = self._path(value, follow=follow)
        if selected in self.roots:
            raise SpecError("filesystem path", str(value), "cannot mutate a service root")
        return selected

    def _record(self, operation: str, path: Path, *, mutation: bool) -> None:
        if self.observer is None:
            return
        payload = {
            "operation": operation, "path": str(path), "mutation": mutation,
            "exists": path.exists(), "sha256": _digest(path) if path.exists() else "",
        }
        self.observer(operation, payload)

    def read_bytes(self, path: object) -> bytes:
        selected = self._path(path)
        value = selected.read_bytes()
        self._record("read", selected, mutation=False)
        return value

    def write_bytes(self, path: object, value: object) -> None:
        if not isinstance(value, bytes):
            raise SpecError("filesystem bytes", type(value).__name__, "must be bytes")
        selected = self._mutable(path)
        selected.parent.mkdir(parents=True, exist_ok=True)
        descriptor, temporary = tempfile.mkstemp(dir=str(selected.parent), prefix=".brixtest-")
        try:
            with os.fdopen(descriptor, "wb") as handle:
                handle.write(value)
                handle.flush()
                os.fsync(handle.fileno())
            Path(temporary).replace(selected)
        finally:
            Path(temporary).unlink(missing_ok=True)
        self._record("write", selected, mutation=True)

    def stat(self, path: object, *, follow_symlinks: bool = True) -> Mapping[str, object]:
        selected = self._path(path, follow=follow_symlinks)
        value = selected.stat() if follow_symlinks else selected.lstat()
        self._record("stat", selected, mutation=False)
        return freeze_mapping({
            "path": str(selected), "mode": stat_module.S_IMODE(value.st_mode),
            "size": value.st_size, "uid": value.st_uid, "gid": value.st_gid,
            "mtime_ns": value.st_mtime_ns, "is_file": stat_module.S_ISREG(value.st_mode),
            "is_dir": stat_module.S_ISDIR(value.st_mode),
            "is_symlink": stat_module.S_ISLNK(value.st_mode),
        })

    def list(self, path: object = ".") -> tuple[str, ...]:
        selected = self._path(path)
        value = tuple(sorted(item.name for item in selected.iterdir()))
        self._record("list", selected, mutation=False)
        return value

    def mkdir(
        self, path: object, *, parents: bool = False, exist_ok: bool = False,
    ) -> None:
        selected = self._mutable(path, follow=False)
        selected.mkdir(parents=parents, exist_ok=exist_ok)
        self._record("mkdir", selected, mutation=True)

    def remove(self, path: object, *, recursive: bool = False) -> None:
        selected = self._mutable(path, follow=False)
        if selected.is_dir() and not selected.is_symlink():
            if not recursive:
                selected.rmdir()
            else:
                shutil.rmtree(selected)
        else:
            selected.unlink()
        self._record("remove", selected, mutation=True)

    def chmod(self, path: object, mode: int) -> None:
        selected = self._mutable(path)
        selected.chmod(_mode(mode))
        self._record("chmod", selected, mutation=True)

    def chown(self, path: object, uid: int = -1, gid: int = -1) -> None:
        selected = self._mutable(path)
        os.chown(
            selected, _owner_id(uid, "filesystem uid"),
            _owner_id(gid, "filesystem gid"), follow_symlinks=False,
        )
        self._record("chown", selected, mutation=True)

    def symlink(self, target: object, path: object) -> None:
        selected = self._mutable(path, follow=False)
        target_text = _path_text(target, "filesystem symlink target")
        raw_target = Path(target_text)
        resolved = (
            raw_target.resolve() if raw_target.is_absolute()
            else (selected.parent / raw_target).resolve()
        )
        if not _inside(resolved, self.roots):
            raise SpecError(
                "filesystem symlink target", target_text,
                "must remain inside the declared service roots",
            )
        selected.symlink_to(raw_target)
        self._record("symlink", selected, mutation=True)

    def getxattr(self, path: object, name: str) -> bytes:
        selected = self._path(path)
        value = os.getxattr(selected, _xattr_name(name))
        self._record("getxattr", selected, mutation=False)
        return value

    def setxattr(self, path: object, name: str, value: object) -> None:
        if not isinstance(value, bytes):
            raise SpecError("filesystem xattr value", type(value).__name__, "must be bytes")
        selected = self._mutable(path)
        os.setxattr(selected, _xattr_name(name), value)
        self._record("setxattr", selected, mutation=True)

    def listxattr(self, path: object) -> tuple[str, ...]:
        selected = self._path(path)
        value = tuple(sorted(os.listxattr(selected)))
        self._record("listxattr", selected, mutation=False)
        return value

    def removexattr(self, path: object, name: str) -> None:
        selected = self._mutable(path)
        os.removexattr(selected, _xattr_name(name))
        self._record("removexattr", selected, mutation=True)


class ServiceFilesystem:
    """Simple binary-safe filesystem operations for one managed service."""

    def __init__(self, transport: object) -> None:
        self._transport = transport

    def read_bytes(self, path: Union[str, Path]) -> bytes:
        """Read a confined file without a shell or encoding conversion."""
        return self._transport.read_bytes(path)

    def read_text(
        self, path: Union[str, Path], *, encoding: str = "utf-8",
        errors: str = "strict",
    ) -> str:
        """Read and decode a confined service file."""
        return self.read_bytes(path).decode(encoding, errors=errors)

    def write_bytes(self, path: Union[str, Path], value: bytes) -> None:
        """Atomically write binary content inside a declared service root."""
        self._transport.write_bytes(path, value)

    def write_text(
        self, path: Union[str, Path], value: str, *, encoding: str = "utf-8",
    ) -> None:
        """Encode and atomically write text inside a declared service root."""
        if not isinstance(value, str):
            raise SpecError("filesystem text", type(value).__name__, "must be text")
        self.write_bytes(path, value.encode(encoding))

    def stat(self, path: Union[str, Path], *, follow_symlinks: bool = True):
        """Return immutable portable metadata for a confined path."""
        return self._transport.stat(path, follow_symlinks=follow_symlinks)

    def list(self, path: Union[str, Path] = ".") -> tuple[str, ...]:
        """List direct children in stable lexical order."""
        return self._transport.list(path)

    def mkdir(
        self, path: Union[str, Path], *, parents: bool = False,
        exist_ok: bool = False,
    ) -> None:
        """Create a confined directory."""
        self._transport.mkdir(path, parents=parents, exist_ok=exist_ok)

    def remove(self, path: Union[str, Path], *, recursive: bool = False) -> None:
        """Remove one confined path, requiring explicit recursion for trees."""
        self._transport.remove(path, recursive=recursive)

    def chmod(self, path: Union[str, Path], mode: int) -> None:
        """Change confined POSIX permission bits."""
        self._transport.chmod(path, mode)

    def chown(self, path: Union[str, Path], uid: int = -1, gid: int = -1) -> None:
        """Change confined ownership through the selected backend identity."""
        self._transport.chown(path, uid, gid)

    def symlink(self, target: Union[str, Path], path: Union[str, Path]) -> None:
        """Create a symlink only when its resolved target remains confined."""
        self._transport.symlink(target, path)

    def getxattr(self, path: Union[str, Path], name: str) -> bytes:
        """Read one user.* extended attribute as bytes."""
        return self._transport.getxattr(path, name)

    def setxattr(self, path: Union[str, Path], name: str, value: bytes) -> None:
        """Set one user.* extended attribute from bytes."""
        self._transport.setxattr(path, name, value)

    def listxattr(self, path: Union[str, Path]) -> tuple[str, ...]:
        """List extended-attribute names."""
        return self._transport.listxattr(path)

    def removexattr(self, path: Union[str, Path], name: str) -> None:
        """Remove one user.* extended attribute."""
        self._transport.removexattr(path, name)


__all__ = ["ServiceFilesystem"]
