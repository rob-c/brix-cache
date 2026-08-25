"""Binary-safe framed filesystem transport for managed remote services."""

from __future__ import annotations

import json
import subprocess
from typing import Callable, Mapping, Optional, Sequence

from brixtest.errors import SpecError
from brixtest.runtime.filesystem import _mode, _owner_id, _path_text, _xattr_name
from brixtest.util.immutable import freeze_mapping

_MAGIC = b"BRIXFS1\n"
_AGENT = r'''
import hashlib,json,os,shutil,stat,sys,tempfile
from pathlib import Path

MAGIC=b"BRIXFS1\n"
request=json.loads(sys.argv[1])
roots=tuple(Path(value).resolve() for value in request["roots"])

def inside(path):
    return any(path == root or root in path.parents for root in roots)

def select(value, follow=True, mutable=False):
    raw=Path(value)
    candidate=raw if raw.is_absolute() else roots[0]/raw
    chosen=candidate.resolve() if follow else candidate.parent.resolve()/candidate.name
    if not inside(chosen):
        raise ValueError("path escapes the declared service roots")
    if mutable and chosen in roots:
        raise ValueError("cannot mutate a service root")
    return chosen

def digest(path):
    if not path.is_file():
        return ""
    value=hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda:handle.read(1<<20),b""):
            value.update(block)
    return value.hexdigest()

def metadata(path):
    return {"path":str(path),"exists":path.exists(),"sha256":digest(path)}

def stat_value(path, follow):
    value=path.stat() if follow else path.lstat()
    return {
        "path":str(path),"mode":stat.S_IMODE(value.st_mode),"size":value.st_size,
        "uid":value.st_uid,"gid":value.st_gid,"mtime_ns":value.st_mtime_ns,
        "is_file":stat.S_ISREG(value.st_mode),"is_dir":stat.S_ISDIR(value.st_mode),
        "is_symlink":stat.S_ISLNK(value.st_mode),
    }

def write_atomic(path, payload):
    path.parent.mkdir(parents=True,exist_ok=True)
    descriptor,temporary=tempfile.mkstemp(dir=str(path.parent),prefix=".brixtest-")
    try:
        with os.fdopen(descriptor,"wb") as handle:
            handle.write(payload);handle.flush();os.fsync(handle.fileno())
        Path(temporary).replace(path)
    finally:
        Path(temporary).unlink(missing_ok=True)

def operate():
    operation=request["operation"]
    options=request.get("options",{})
    path=select(request["path"],follow=options.get("follow",True),
                mutable=operation in {"write","mkdir","remove","chmod","chown",
                                      "symlink","setxattr","removexattr"})
    payload=sys.stdin.buffer.read()
    value=None
    output=b""
    if operation == "read": output=path.read_bytes()
    elif operation == "write": write_atomic(path,payload)
    elif operation == "stat": value=stat_value(path,options.get("follow",True))
    elif operation == "list": value=sorted(item.name for item in path.iterdir())
    elif operation == "mkdir": path.mkdir(parents=options["parents"],exist_ok=options["exist_ok"])
    elif operation == "remove":
        if path.is_dir() and not path.is_symlink():
            shutil.rmtree(path) if options["recursive"] else path.rmdir()
        else: path.unlink()
    elif operation == "chmod": path.chmod(options["mode"])
    elif operation == "chown": os.chown(path,options["uid"],options["gid"],follow_symlinks=False)
    elif operation == "symlink":
        target=Path(options["target"])
        resolved=target.resolve() if target.is_absolute() else (path.parent/target).resolve()
        if not inside(resolved): raise ValueError("symlink target must remain inside declared roots")
        path.symlink_to(target)
    elif operation == "getxattr": output=os.getxattr(path,options["name"])
    elif operation == "setxattr": os.setxattr(path,options["name"],payload)
    elif operation == "listxattr": value=sorted(os.listxattr(path))
    elif operation == "removexattr": os.removexattr(path,options["name"])
    else: raise ValueError("unknown filesystem operation")
    return output,{"ok":True,"value":value,**metadata(path)}

def packet(header,payload=b""):
    encoded=json.dumps(header,sort_keys=True,separators=(",",":")).encode()
    sys.stdout.buffer.write(MAGIC+len(encoded).to_bytes(4,"big")+encoded+payload)

try:
    data,header=operate();packet(header,data)
except Exception as error:
    packet({"ok":False,"error":type(error).__name__,"detail":str(error)})
'''


def _request(
    roots: Sequence[str], operation: str, path: object,
    options: Optional[Mapping[str, object]],
) -> str:
    selected = _path_text(path, "filesystem path")
    return json.dumps({
        "roots": list(roots), "operation": operation, "path": selected,
        "options": dict(options or {}),
    }, sort_keys=True, separators=(",", ":"))


def _packet(value: bytes, path: object) -> tuple[Mapping[str, object], bytes]:
    if not value.startswith(_MAGIC) or len(value) < len(_MAGIC) + 4:
        raise SpecError("remote filesystem response", str(path), "has invalid framing")
    offset = len(_MAGIC)
    size = int.from_bytes(value[offset:offset + 4], "big")
    boundary = offset + 4 + size
    if boundary > len(value):
        raise SpecError("remote filesystem response", str(path), "is truncated")
    try:
        header = json.loads(value[offset + 4:boundary])
    except (UnicodeDecodeError, ValueError) as exc:
        raise SpecError(
            "remote filesystem response", str(path), "has invalid metadata",
        ) from exc
    if not isinstance(header, Mapping):
        raise SpecError("remote filesystem response", str(path), "has invalid metadata")
    return header, value[boundary:]


class RemoteFilesystem:
    """Execute confined operations through a framework-owned Python sidecar."""

    brixtest_api_version = 1
    brixtest_capabilities = (
        "filesystem.binary", "filesystem.metadata", "filesystem.mutate",
        "filesystem.symlink", "filesystem.xattr", "transport.remote",
    )

    def __init__(
        self, command_prefix: Sequence[str], roots: Sequence[str], *,
        observer: Optional[Callable[[str, Mapping[str, object]], None]] = None,
        timeout: float = 30.0,
    ) -> None:
        self.command_prefix = tuple(command_prefix)
        self.roots = tuple(roots)
        self.observer = observer
        self.timeout = timeout
        if not self.command_prefix or not self.roots:
            raise SpecError("remote filesystem", (), "needs a command prefix and roots")

    def _invoke(
        self, operation: str, path: object, *, payload: bytes = b"",
        options: Optional[Mapping[str, object]] = None,
    ) -> tuple[Mapping[str, object], bytes]:
        request = _request(self.roots, operation, path, options)
        try:
            result = subprocess.run(
                (*self.command_prefix, "python3", "-c", _AGENT, request),
                input=payload, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                timeout=self.timeout, check=False,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise SpecError("remote filesystem", str(path), str(exc)) from exc
        header, output = _packet(result.stdout, path)
        if result.returncode or header.get("ok") is not True:
            detail = str(header.get("detail") or result.stderr.decode(errors="replace"))
            if header.get("error"):
                detail = "%s: %s" % (header["error"], detail)
            raise SpecError("remote filesystem %s" % operation, str(path), detail)
        if self.observer is not None:
            self.observer(operation, {
                "operation": operation, "mutation": operation in _MUTATIONS,
                "path": str(header.get("path", path)),
                "exists": header.get("exists") is True,
                "sha256": str(header.get("sha256", "")),
            })
        return header, output

    def read_bytes(self, path: object) -> bytes:
        return self._invoke("read", path)[1]

    def write_bytes(self, path: object, value: object) -> None:
        if not isinstance(value, bytes):
            raise SpecError("filesystem bytes", type(value).__name__, "must be bytes")
        self._invoke("write", path, payload=value)

    def stat(self, path: object, *, follow_symlinks: bool = True) -> Mapping[str, object]:
        return freeze_mapping(self._invoke(
            "stat", path, options={"follow": follow_symlinks},
        )[0].get("value", {}))

    def list(self, path: object = ".") -> tuple[str, ...]:
        return tuple(self._invoke("list", path)[0].get("value", ()))

    def mkdir(self, path: object, *, parents: bool = False, exist_ok: bool = False) -> None:
        self._invoke("mkdir", path, options={
            "follow": False, "parents": parents, "exist_ok": exist_ok,
        })

    def remove(self, path: object, *, recursive: bool = False) -> None:
        self._invoke("remove", path, options={"follow": False, "recursive": recursive})

    def chmod(self, path: object, mode: int) -> None:
        self._invoke("chmod", path, options={"mode": _mode(mode)})

    def chown(self, path: object, uid: int = -1, gid: int = -1) -> None:
        self._invoke("chown", path, options={
            "uid": _owner_id(uid, "filesystem uid"),
            "gid": _owner_id(gid, "filesystem gid"),
        })

    def symlink(self, target: object, path: object) -> None:
        self._invoke("symlink", path, options={
            "follow": False, "target": _path_text(target, "filesystem symlink target"),
        })

    def getxattr(self, path: object, name: str) -> bytes:
        return self._invoke("getxattr", path, options={"name": _xattr_name(name)})[1]

    def setxattr(self, path: object, name: str, value: bytes) -> None:
        if not isinstance(value, bytes):
            raise SpecError("filesystem xattr value", type(value).__name__, "must be bytes")
        self._invoke(
            "setxattr", path, payload=value, options={"name": _xattr_name(name)},
        )

    def listxattr(self, path: object) -> tuple[str, ...]:
        return tuple(self._invoke("listxattr", path)[0].get("value", ()))

    def removexattr(self, path: object, name: str) -> None:
        self._invoke("removexattr", path, options={"name": _xattr_name(name)})


_MUTATIONS = frozenset({
    "write", "mkdir", "remove", "chmod", "chown", "symlink", "setxattr",
    "removexattr",
})


__all__ = ["RemoteFilesystem"]
