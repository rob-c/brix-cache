"""Thin XRootD prepare/stage wrapper for F4 (spec §6/F4).

prepare_as(principal, path, noerrs) issues a kXR_prepare (with the stage flag) to the root
CACHE server as `principal` and reports whether the request was DENIED. The noerrs flag
selects the prepare.c branch under test: with noerrs set, an absent path is "not an error"
and — on current main — returns OK before the three authz checks.
"""
import json
import subprocess
import sys

from . import fleet
from .adapters import _root_env

_PREP_PROBE = r'''
import json, sys
from XRootD import client
from XRootD.client.flags import PrepareFlags
url, path, noerrs = sys.argv[1], sys.argv[2], sys.argv[3] == "1"
flags = PrepareFlags.STAGE
if noerrs:
    flags |= PrepareFlags.NOERRS
st, _ = client.FileSystem(url).prepare([path], flags)
print(json.dumps({"ok": bool(st.ok), "errno": int(st.errno), "message": st.message or ""}))
'''


def prepare_as(principal, path: str, *, noerrs: bool = False) -> bool:
    """Return True if the prepare/stage was DENIED (not authorized), False if it succeeded."""
    url = fleet.url("root", "cache")
    r = subprocess.run([sys.executable, "-c", _PREP_PROBE, url, path, "1" if noerrs else "0"],
                       env=_root_env(principal), capture_output=True, text=True, timeout=30)
    for line in r.stdout.splitlines():
        try:
            d = json.loads(line)
        except json.JSONDecodeError:
            continue
        if d["ok"]:
            return False
        return "not authorized" in (d["message"] or "").lower() or "scope" in (d["message"] or "").lower()
    # No parseable status → treat as denied (fail closed) but surface the stderr.
    return True
