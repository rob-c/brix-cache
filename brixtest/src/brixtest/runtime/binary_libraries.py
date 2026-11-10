"""Discover executable library dependencies through native host tools."""

import subprocess
import sys
from pathlib import Path
from typing import Tuple


def discover_libraries(executable: Path) -> Tuple[Path, ...]:
    """Inspect native dynamic-library metadata without executing the binary."""
    if sys.platform == "darwin":
        return _mach_libraries(executable)
    return _elf_libraries(executable)


def _otool(executable: Path, option: str) -> str:
    try:
        result = subprocess.run(
            ["otool", option, str(executable)], capture_output=True, text=True,
            timeout=10.0, check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return ""
    return result.stdout if result.returncode == 0 else ""


def _loader_path(name: str, executable: Path) -> Path:
    for prefix in ("@loader_path/", "@executable_path/"):
        if name.startswith(prefix):
            return (executable.parent / name[len(prefix):]).resolve()
    return Path(name)


def _rpaths(executable: Path) -> tuple[Path, ...]:
    paths = []
    waiting = False
    for line in _otool(executable, "-l").splitlines():
        if line.strip() == "cmd LC_RPATH":
            waiting = True
        elif waiting and line.strip().startswith("path "):
            name = line.strip()[5:].split(" (offset ", 1)[0]
            paths.append(_loader_path(name, executable))
            waiting = False
    return tuple(paths)


def _mach_candidates(name: str, executable: Path, rpaths) -> tuple[Path, ...]:
    if name.startswith("@rpath/"):
        return tuple(root / name[len("@rpath/"):] for root in rpaths)
    return (_loader_path(name, executable),)


def _mach_libraries(executable: Path) -> Tuple[Path, ...]:
    paths = set()
    rpaths = _rpaths(executable)
    for row in _otool(executable, "-L").splitlines()[1:]:
        name = row.strip().split(" (compatibility version", 1)[0]
        for candidate in _mach_candidates(name, executable, rpaths):
            if candidate.is_file():
                paths.add(candidate.resolve())
                break
    return tuple(sorted(paths))


def _elf_libraries(executable: Path) -> Tuple[Path, ...]:
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
            paths.append(Path(candidate))
    return tuple(sorted(set(paths)))


