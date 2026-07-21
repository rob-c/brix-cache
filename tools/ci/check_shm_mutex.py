#!/usr/bin/env python3
#
# check_shm_mutex.py — enforce INVARIANT #10: SHM tables are created via the
# brix_shm_table_* helpers, never a bare ngx_shmtx_create().
#
# WHAT: Fails (exit 1) on any CALL of ngx_shmtx_create( in src/ outside the
#       one sanctioned implementation site, src/core/compat/shm_slots.c.
#
# WHY:  brix_shm_table_alloc() binds the mutex to the slab pool's recoverable
#       lock word (spin+yield, crash-recoverable, reload-safe fresh/reattach
#       detection).  A bare ngx_shmtx_create() against a table-embedded lock
#       word skips all of that: a worker crash while holding it deadlocks the
#       zone forever, and reload re-init races the surviving workers.
#       (Phase-61/89 CI gate — mandated with PR-5, the first phase to add a
#       new SHM zone after the invariant was written.)
#
# HOW:  grep call sites of ngx_shmtx_create( across src/, drop comment/doc
#       lines (no '(' adjacency in prose is not enough — we drop lines whose
#       first non-blank char is '*' or that start a comment), then drop the
#       ALLOW file.  Anything left is a violation → fail.
#
# USAGE:
#   tools/ci/check_shm_mutex.py          # exit 1 on a bare create outside ALLOW

import os
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
ALLOW = "src/core/compat/shm_slots.c"

# BRE `ngx_shmtx_create *(` → literal name, zero-or-more spaces, literal '('.
_CALL = re.compile(r"ngx_shmtx_create *\(")
# ERE `:[0-9]+: *(\*|/\*|//)` — a grep -n `:line:` field followed by optional
# blanks and a comment lead ('*', '/*' or '//').
_COMMENT = re.compile(r":[0-9]+: *(\*|/\*|//)")


def run(root: Path = ROOT) -> tuple[bool, list[str]]:
    """Return (ok, violations). Each violation is a `path:line:text` string,
    ROOT-relative, mirroring `grep -rn … | sed | grep -v | grep -vE`."""
    src = root / "src"
    hits: list[str] = []
    for dirpath, dirnames, filenames in os.walk(src):
        dirnames.sort()
        for name in sorted(filenames):
            if not (name.endswith(".c") or name.endswith(".h")):
                continue
            path = Path(dirpath) / name
            rel = path.relative_to(root).as_posix()
            try:
                text = path.read_text(errors="replace")
            except OSError:
                continue
            for lineno, line in enumerate(text.splitlines(), start=1):
                if not _CALL.search(line):
                    continue
                entry = f"{rel}:{lineno}:{line}"
                if rel == ALLOW:
                    continue
                if _COMMENT.search(entry):
                    continue
                hits.append(entry)
    return (not hits, hits)


def main() -> int:
    ok, viol = run()
    if not ok:
        print(
            f"check_shm_mutex: INVARIANT #10 violation — bare ngx_shmtx_create() outside {ALLOW}:",
            file=sys.stderr,
        )
        print("\n".join(viol), file=sys.stderr)
        print(
            "Use brix_shm_table_alloc() (src/core/compat/shm_slots.h) instead.",
            file=sys.stderr,
        )
        return 1
    print(f"check_shm_mutex: OK (no bare ngx_shmtx_create outside {ALLOW})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
