"""coverage — classify each forked remote-suite test file into the burn-down
buckets. Was tools/remote-coverage.sh.
"""
import re
import sys
from pathlib import Path

from . import SUITE

_MARKER = {
    "# brix-remote-adapted": "adapted",
    "# brix-remote-ok":      "verified_ok",
    "# brix-remote-skip":    "remote_skip",
}
_SERVER_LOCAL = re.compile(r"DATA_DIR|CACHE_ROOT|os\.listdir|CHAOS_TIER|_ROOT\b")


def classify(suite=SUITE):
    """Return {bucket: count} over remote-suite/tests/test_*.py."""
    counts = dict(pure_remote=0, adapted=0, verified_ok=0, remote_skip=0, server_local=0)
    for f in sorted(Path(suite).glob("test_*.py")):
        text = f.read_text()
        first = text.splitlines()[0] if text else ""
        if first in _MARKER:
            counts[_MARKER[first]] += 1
        elif _SERVER_LOCAL.search(text):
            counts["server_local"] += 1
        else:
            counts["pure_remote"] += 1
    return counts


def main(argv):
    c = classify()
    handled = c["pure_remote"] + c["adapted"] + c["verified_ok"] + c["remote_skip"]
    print(f"pure-remote: {c['pure_remote']}  adapted: {c['adapted']}  "
          f"verified-ok: {c['verified_ok']}  remote-skip: {c['remote_skip']}  "
          f"server-local(unadapted): {c['server_local']}")
    print(f"handled: {handled} / {handled + c['server_local']}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
