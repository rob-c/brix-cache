"""Exec one command in a mapped Linux user namespace without a shell."""

from __future__ import annotations

import argparse
import ctypes
import errno
import os
import shutil
import signal
import subprocess
import sys
from typing import Optional, Sequence


_CLONE_NEWUSER = 0x10000000


def _mapping(value: str) -> tuple[int, int, int]:
    try:
        row = tuple(int(item) for item in value.split(":"))
    except ValueError as exc:
        raise argparse.ArgumentTypeError("maps must use inside:outside:count") from exc
    if len(row) != 3 or min(row) < 0 or row[2] == 0:
        raise argparse.ArgumentTypeError("maps require non-negative IDs and count > 0")
    return row


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="brixtest-userns-exec")
    parser.add_argument("--uid", type=int, required=True)
    parser.add_argument("--gid", type=int, required=True)
    parser.add_argument("--group", type=int, action="append", default=[])
    parser.add_argument("--uid-map", type=_mapping, action="append", required=True)
    parser.add_argument("--gid-map", type=_mapping, action="append", required=True)
    parser.add_argument("command", nargs=argparse.REMAINDER)
    return parser


def _unshare() -> None:
    library = ctypes.CDLL(None, use_errno=True)
    if library.unshare(_CLONE_NEWUSER) != 0:
        error = ctypes.get_errno()
        raise OSError(error, os.strerror(error))


def _map_command(kind: str, pid: int, rows: Sequence[tuple[int, int, int]]) -> list[str]:
    executable = shutil.which("new%smap" % kind)
    if executable is None:
        raise OSError(errno.ENOENT, "new%smap is not installed" % kind)
    return [executable, str(pid), *(str(value) for row in rows for value in row)]


def _apply_maps(
    pid: int, uid_rows: Sequence[tuple[int, int, int]],
    gid_rows: Sequence[tuple[int, int, int]],
) -> None:
    for kind, rows in (("uid", uid_rows), ("gid", gid_rows)):
        result = subprocess.run(
            _map_command(kind, pid, rows), capture_output=True, text=True, check=False,
        )
        if result.returncode:
            detail = (result.stderr or result.stdout or "mapping failed").strip()
            raise OSError("new%smap: %s" % (kind, detail))


def _child(
    ready: int, release: int, uid: int, gid: int, groups: Sequence[int],
    command: Sequence[str],
) -> None:
    try:
        _unshare()
        os.write(ready, b"R")
        if os.read(release, 1) != b"G":
            raise OSError("mapping parent closed before release")
        os.setgroups(groups)
        os.setresgid(gid, gid, gid)
        os.setresuid(uid, uid, uid)
        os.execvp(command[0], command)
    except BaseException as exc:
        os.write(2, ("brixtest user namespace: %s\n" % exc).encode(errors="replace"))
    os._exit(126)


def _status_code(status: int) -> int:
    if os.WIFEXITED(status):
        return os.WEXITSTATUS(status)
    if os.WIFSIGNALED(status):
        return 128 + os.WTERMSIG(status)
    return 125


def execute(
    command: Sequence[str], *, uid: int, gid: int, groups: Sequence[int],
    uid_rows: Sequence[tuple[int, int, int]],
    gid_rows: Sequence[tuple[int, int, int]],
) -> int:
    """Fork, map, release, and wait for one user-namespace child."""
    ready_read, ready_write = os.pipe()
    release_read, release_write = os.pipe()
    pid = os.fork()
    if pid == 0:
        os.close(ready_read)
        os.close(release_write)
        _child(ready_write, release_read, uid, gid, groups, command)
    os.close(ready_write)
    os.close(release_read)
    try:
        if os.read(ready_read, 1) != b"R":
            raise OSError("child failed before requesting UID/GID maps")
        _apply_maps(pid, uid_rows, gid_rows)
        os.write(release_write, b"G")
    except BaseException:
        os.kill(pid, signal.SIGKILL)
        os.waitpid(pid, 0)
        raise
    finally:
        os.close(ready_read)
        os.close(release_write)
    return _status_code(os.waitpid(pid, 0)[1])


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = _parser().parse_args(argv)
    command = args.command[1:] if args.command[:1] == ["--"] else args.command
    if not command:
        _parser().error("a command is required after --")
    try:
        return execute(
            command, uid=args.uid, gid=args.gid, groups=args.group,
            uid_rows=args.uid_map, gid_rows=args.gid_map,
        )
    except OSError as exc:
        print("brixtest user namespace: %s" % exc, file=sys.stderr)
        return 125


if __name__ == "__main__":
    raise SystemExit(main())


__all__ = ["execute", "main"]
