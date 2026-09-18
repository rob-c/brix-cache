"""Create operator programs that snapshot their inherited descriptor table.

The probe takes its snapshot before opening its output file.  A shell-based
``ls ... > file`` probe is unsuitable: shell redirection duplicates permitted
standard streams into high-numbered descriptors, creating false leak reports.
"""

import sys
from pathlib import Path


def write_fd_probe(path: Path, output: Path, decision_arg: int | None = None) -> Path:
    """Write an executable probe and return its path.

    ``decision_arg`` creates that one-based argv file after the snapshot for
    policy programs whose successful contract requires an empty decision file.
    """
    source = f'''#!{sys.executable}
import fcntl
import os
import stat
import sys

# Linux exposes a process's own descriptors as symlinks under /proc/self/fd;
# macOS has no procfs and lists them under /dev/fd, where the entries are the
# objects themselves rather than links, so the target comes from F_GETPATH
# (regular files only) and the KIND comes from fstat — which is what the
# caller actually tests: a socket, pipe or epoll object must never be here.
_F_GETPATH = 50


def _path_of(fd):
    try:
        return os.readlink("/proc/self/fd/%d" % fd)
    except OSError:
        pass
    try:
        # fcntl(2) copies the argument and RETURNS the result; it does not
        # write through the buffer passed in.
        out = fcntl.fcntl(fd, _F_GETPATH, bytes(1024))
        return out.split(b"\\0", 1)[0].decode("utf-8", "replace") or "?"
    except OSError:
        return "?"


def _describe(fd):
    mode = os.fstat(fd).st_mode          # raises for the listdir fd, now closed
    if stat.S_ISSOCK(mode):
        return "socket:[?]"
    if stat.S_ISFIFO(mode):
        return "pipe:[?]"
    return _path_of(fd)


_fd_dir = "/proc/self/fd" if os.path.isdir("/proc/self/fd") else "/dev/fd"
entries = []
for name in os.listdir(_fd_dir):
    if not name.isdigit():
        continue
    try:
        entries.append((int(name), _describe(int(name))))
    except OSError:
        pass

with open({str(output)!r}, "w", encoding="utf-8") as listing:
    for number, target in sorted(entries):
        listing.write(f"{{number}} -> {{target}}\\n")
'''
    if decision_arg is not None:
        source += f'''\nwith open(sys.argv[{decision_arg}], "w", encoding="utf-8"):\n    pass\n'''
    path.write_text(source, encoding="utf-8")
    path.chmod(0o755)
    return path

#: A probe that reports the identity a spawned operator program inherited:
#: its own pid, process group, session and whether a controlling terminal
#: survived.  Portable by construction — Linux's /proc/<pid>/stat carries the
#: same four fields, macOS has no procfs at all, and opening /dev/tty is the
#: POSIX way to ask whether a controlling terminal exists (ENXIO after
#: setsid()).  The caller runs it as a CHILD of the program under test, so the
#: group and session it prints are the ones that program leads.
IDENTITY_PROBE = (
    "import os\n"
    "tty = 1\n"
    "try:\n"
    "    os.close(os.open('/dev/tty', os.O_RDONLY))\n"
    "except OSError:\n"
    "    tty = 0\n"
    "print(os.getpid(), os.getpgrp(), os.getsid(0), tty)\n"
)


def write_identity_probe(path: Path) -> Path:
    """Write IDENTITY_PROBE as an executable program and return its path."""
    path.write_text(f"#!{sys.executable}\n" + IDENTITY_PROBE, encoding="utf-8")
    path.chmod(0o755)
    return path


def parse_identity(text: str):
    """``(program_pid, pgrp, sid, has_tty)`` from the two recorded lines: the
    program's own pid, then its child probe's view of what it inherited."""
    program, probe = text.split("\n", 1)
    _probe_pid, pgrp, sid, tty = (int(v) for v in probe.split())
    return int(program), pgrp, sid, tty

