"""Create operator programs that snapshot their inherited descriptor table.

The probe takes its snapshot before opening its output file.  A shell-based
``ls ... > file`` probe is unsuitable: shell redirection duplicates permitted
standard streams into high-numbered descriptors, creating false leak reports.
"""

from pathlib import Path


def write_fd_probe(path: Path, output: Path, decision_arg: int | None = None) -> Path:
    """Write an executable probe and return its path.

    ``decision_arg`` creates that one-based argv file after the snapshot for
    policy programs whose successful contract requires an empty decision file.
    """
    source = f'''#!/usr/bin/python3
import os
import sys

entries = []
for name in os.listdir("/proc/self/fd"):
    if not name.isdigit():
        continue
    try:
        entries.append((int(name), os.readlink("/proc/self/fd/" + name)))
    except FileNotFoundError:
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
