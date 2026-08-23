"""Reproducibility metadata captured without recording secret values."""

from __future__ import annotations

import hashlib
import json
import os
import platform
import shutil
import subprocess
from pathlib import Path
from typing import Iterable, Mapping


def file_identity(path: Path) -> dict:
    candidate = Path(path)
    try:
        stat = candidate.stat()
        digest = hashlib.sha256()
        with candidate.open("rb") as handle:
            for chunk in iter(lambda: handle.read(1 << 20), b""):
                digest.update(chunk)
        return {"path": str(candidate), "size": stat.st_size, "sha256": digest.hexdigest()}
    except OSError as exc:
        return {"path": str(candidate), "error": str(exc)}


def _command(argv: list[str], cwd: Path) -> str:
    try:
        result = subprocess.run(
            argv, cwd=str(cwd), capture_output=True, text=True, check=False, timeout=3.0,
        )
    except (OSError, subprocess.TimeoutExpired):
        return ""
    return result.stdout.strip() if result.returncode == 0 else ""


def source_identity(source_root: Path) -> dict:
    root = Path(source_root).resolve()
    commit = _command(["git", "rev-parse", "HEAD"], root)
    status = _command(["git", "status", "--porcelain=v1", "--untracked-files=no"], root)
    remote = _command(["git", "config", "--get", "remote.origin.url"], root)
    return {
        "root": str(root),
        "git_commit": commit,
        "git_dirty": bool(status),
        "git_remote": remote,
    }


def _cpu_info() -> dict:
    model = ""
    try:
        for line in Path("/proc/cpuinfo").read_text(errors="replace").splitlines():
            if line.lower().startswith("model name"):
                model = line.partition(":")[2].strip()
                break
    except OSError:
        pass
    return {"logical_count": os.cpu_count(), "model": model}


def _memory_info() -> dict:
    result = {}
    try:
        for line in Path("/proc/meminfo").read_text(errors="replace").splitlines():
            name, _, value = line.partition(":")
            if name in ("MemTotal", "SwapTotal"):
                result[name.lower() + "_kib"] = int(value.split()[0])
    except (OSError, ValueError, IndexError):
        pass
    return result


def environment_contract(names: Iterable[str]) -> dict:
    """Record presence and hashes, never potentially secret values."""
    rows = {}
    for name in sorted({str(item) for item in names}):
        value = os.environ.get(name)
        rows[name] = {
            "present": value is not None,
            "sha256": hashlib.sha256(value.encode()).hexdigest() if value is not None else "",
        }
    return rows


def capture(
    *, source_root: Path, backend: str, isolation: str,
    binaries: Mapping[str, object] = {}, configs: Mapping[str, Path] = {},
    environment_names: Iterable[str] = (), extra: Mapping[str, object] = {},
) -> dict:
    binary_rows = {name: _binary_identity(item) for name, item in sorted(binaries.items())}
    config_rows = {name: file_identity(Path(path)) for name, path in sorted(configs.items())}
    return {
        "source": source_identity(source_root),
        "runtime": _runtime_identity(backend, isolation),
        "hardware": {"cpu": _cpu_info(), "memory": _memory_info()},
        "tools": _tool_identity(),
        "binaries": binary_rows,
        "configs": config_rows,
        "environment": environment_contract(environment_names),
        "extra": json.loads(json.dumps(dict(extra), default=str)),
    }


def _binary_identity(item: object) -> dict:
    row = file_identity(Path(getattr(item, "path", item)))
    libraries = getattr(item, "libraries", ())
    if libraries:
        row["libraries"] = [file_identity(Path(value)) for value in libraries]
    return row


def _runtime_identity(backend: str, isolation: str) -> dict:
    return {
        "python": platform.python_version(),
        "implementation": platform.python_implementation(),
        "platform": platform.platform(),
        "kernel": platform.release(),
        "architecture": platform.machine(),
        "hostname": platform.node(),
        "backend": backend,
        "isolation": isolation,
        "container": Path("/.dockerenv").exists(),
    }


def _tool_identity() -> dict:
    return {
        name: shutil.which(name) or ""
        for name in ("docker", "podman", "runc", "nsenter", "kubectl")
    }
