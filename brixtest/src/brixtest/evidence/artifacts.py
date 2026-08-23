"""Content-addressed, confined output attachments and optional S3 publication."""

from __future__ import annotations

import contextlib
import hashlib
import json
import mimetypes
import os
import shutil
import stat
import tempfile
from pathlib import Path
from typing import Union

from brixtest.errors import SpecError


def _sha256(path: Path) -> tuple[str, int]:
    digest = hashlib.sha256()
    size = 0
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
            size += len(chunk)
    return digest.hexdigest(), size


def _confined(path: Path, root: Path) -> Path:
    if path.is_symlink():
        raise SpecError("attachment", str(path), "must be a regular file inside the run root")
    resolved = path.resolve()
    try:
        inside = resolved.is_relative_to(root.resolve())
    except AttributeError:
        inside = resolved == root.resolve() or root.resolve() in resolved.parents
    if not inside or not resolved.is_file() or resolved.is_symlink():
        raise SpecError("attachment", str(path), "must be a regular file inside the run root")
    return resolved


def _name(value: str, fallback: str) -> str:
    result = value or fallback
    if not isinstance(result, str) or not result or len(result) > 255 \
            or Path(result).name != result or any(ord(char) < 32 for char in result):
        raise SpecError("attachment name", result, "must be a printable basename up to 255 characters")
    return result


class ContentStore:
    """Deduplicated output store whose manifests are safe to archive."""

    def __init__(self, root: Path, run_root: Path, *, max_bytes: int = 1 << 30) -> None:
        self.root = Path(root)
        self.run_root = Path(run_root).resolve()
        self.max_bytes = int(max_bytes)
        self._items: list[dict] = []

    @property
    def items(self) -> list[dict]:
        return [dict(item) for item in self._items]

    def attach(
        self, path: Union[str, Path], *, name: str = "", media_type: str = "",
        description: str = "", role: str = "output",
    ) -> dict:
        source = _confined(Path(path), self.run_root)
        digest, size = _sha256(source)
        if size > self.max_bytes:
            raise SpecError("attachment", str(source), "exceeds the configured size limit")
        target = self.root / "sha256" / digest[:2] / digest
        target.parent.mkdir(parents=True, exist_ok=True)
        if not target.exists():
            temporary = target.with_name(".%s.%d" % (target.name, os.getpid()))
            shutil.copyfile(source, temporary)
            temporary.replace(target)
            target.chmod(stat.S_IRUSR | stat.S_IWUSR)
        item = {
            "name": _name(name, source.name),
            "description": description,
            "role": role,
            "media_type": media_type or mimetypes.guess_type(source.name)[0]
                          or "application/octet-stream",
            "size": size,
            "sha256": digest,
            "object": str(target.relative_to(self.root.parent)),
            "source": str(source.relative_to(self.run_root)),
        }
        self._items.append(item)
        return dict(item)

    def attach_text(
        self, name: str, text: str, *, media_type: str = "text/plain; charset=utf-8",
        description: str = "", role: str = "output",
    ) -> dict:
        if not isinstance(text, str):
            raise SpecError("attachment text", type(text).__name__, "must be a string")
        _name(name, "")
        self.run_root.mkdir(parents=True, exist_ok=True)
        directory = self.run_root / ".evidence-staging"
        directory.mkdir(parents=True, exist_ok=True)
        descriptor, raw_path = tempfile.mkstemp(dir=str(directory), prefix="attachment-")
        path = Path(raw_path)
        try:
            with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
                handle.write(text)
                handle.flush()
                os.fsync(handle.fileno())
            return self.attach(path, name=name, media_type=media_type,
                               description=description, role=role)
        finally:
            with contextlib.suppress(OSError):
                path.unlink()

    def attach_json(
        self, name: str, value: object, *, description: str = "", role: str = "output",
    ) -> dict:
        return self.attach_text(
            name, json.dumps(value, indent=2, sort_keys=True) + "\n",
            media_type="application/json", description=description, role=role,
        )


def upload_s3(path: Path, destination: str) -> str:
    """Upload one archive using botocore; destination is s3://bucket/prefix."""
    if not destination.startswith("s3://"):
        raise SpecError("S3 destination", destination, "must start with s3://")
    bucket_and_key = destination[5:].split("/", 1)
    bucket = bucket_and_key[0]
    prefix = bucket_and_key[1].strip("/") if len(bucket_and_key) == 2 else ""
    if not bucket:
        raise SpecError("S3 destination", destination, "must include a bucket")
    try:
        import botocore.session
    except ImportError as exc:
        raise SpecError("S3 export", destination, "install brixtest[s3]") from exc
    key = "/".join(value for value in (prefix, Path(path).name) if value)
    client = botocore.session.get_session().create_client("s3")
    with Path(path).open("rb") as handle:
        client.put_object(Bucket=bucket, Key=key, Body=handle)
    return "s3://%s/%s" % (bucket, key)
