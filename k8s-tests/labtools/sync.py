"""sync — fork the repo suite into remote-suite/, never clobbering a file already
adapted for remote execution (first line is a brix-remote marker). Was
tools/sync-remote-suite.sh.
"""
import shutil
import sys
from pathlib import Path

from . import LAB, REPO

DEST = LAB / "remote-suite"
MARKERS = {"# brix-remote-adapted", "# brix-remote-skip", "# brix-remote-ok"}
_SKIP_PARTS = {"__pycache__", ".pytest_cache"}


def is_protected(path):
    """True if <path> exists and its first line is a brix-remote marker."""
    p = Path(path)
    if not p.exists():
        return False
    with p.open(encoding="utf-8", errors="replace") as f:
        return f.readline().strip() in MARKERS


def _copy_candidate(source, repo, dest):
    relative = source.relative_to(repo)
    if not source.is_file() or source.suffix == ".pyc":
        return
    if _SKIP_PARTS & set(relative.parts):
        return
    output = dest / relative
    if is_protected(output):
        return
    output.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(source, output)


def _copy_subtree(repo, dest, sub):
    for source in (repo / sub).rglob("*"):
        _copy_candidate(source, repo, dest)


def _remove_caches(dest):
    for cache in dest.rglob("__pycache__"):
        shutil.rmtree(cache, ignore_errors=True)
    for pyc in dest.rglob("*.pyc"):
        pyc.unlink(missing_ok=True)


def sync(repo=REPO, dest=DEST, subs=("tests", "utils")):
    """Copy repo <subs> into <dest>, skipping protected files + caches."""
    repo, dest = Path(repo), Path(dest)
    for sub in subs:
        _copy_subtree(repo, dest, sub)
    _remove_caches(dest)


def main(argv):
    sync()
    print(f"remote-suite synced from {REPO} (tests + utils)")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
