"""Thin XRootD prepare/stage wrapper for F4 (spec §6/F4).

prepare_as(principal, path, noerrs) issues a kXR_prepare to the root CACHE server as
`principal` and reports whether the request was DENIED. The noerrs flag selects the
prepare.c branch under test: with noerrs set, an absent path is "not an error" and — on
current main — returns OK before the three authz checks.

``stage`` picks WHICH authorization question is asked, and the corpus decides which one
this family may ask.  2.0 F20 split kXR_prepare in two: a bare prepare only browses the
namespace and needs read, while the kXR_stage / kXR_evict arms drive a real recall on the
operator's storage and additionally need the stage privilege (BRIX_AUTH_STAGE / AOP_STAGE
— see src/protocols/root/query/prepare_check.c).  The MU corpus grants `rl`, i.e. read and
lookup, so an authorized principal here is authorized to BROWSE; asking every cell for a
recall made the control cell assert that a read grant confers one, which it does not, and
the family reported an authorization bug that was really a mis-posed question.  The stage
arm is still exercised — by the one cell that means to, with the denial as its assertion.
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
url, path, noerrs, stage = sys.argv[1], sys.argv[2], sys.argv[3] == "1", sys.argv[4] == "1"
flags = PrepareFlags.STAGE if stage else PrepareFlags(0)
if noerrs:
    flags |= PrepareFlags.NOERRS
st, _ = client.FileSystem(url).prepare([path], flags)
print(json.dumps({"ok": bool(st.ok), "errno": int(st.errno), "message": st.message or ""}))
'''


def _flag(on: bool) -> str:
    """The probe's argv encoding of one boolean flag."""
    return "1" if on else "0"


def _is_authz_denial(message: str) -> bool:
    """True when the server's error text is an AUTHORIZATION refusal.

    Narrower than "the request failed" on purpose: kXR_NotFound, a directory
    target and an I/O error are all `ok == False` too, and a family that reads
    every failure as a denial would score its own broken fixtures as the
    property under test holding."""
    lowered = message.lower()
    return "not authorized" in lowered or "scope" in lowered


def _denied(stdout: str) -> bool:
    """Read the probe's first parseable status line as allowed / denied.

    Fails CLOSED: a probe that printed nothing parseable (crashed, was killed,
    never reached the server) is reported as denied, so a broken measurement can
    only ever make a permissive assertion fail, never a restrictive one pass."""
    for line in stdout.splitlines():
        try:
            status = json.loads(line)
        except json.JSONDecodeError:
            continue
        if status["ok"]:
            return False
        return _is_authz_denial(status.get("message") or "")
    return True


def prepare_as(principal, path: str, *, noerrs: bool = False,
               stage: bool = False) -> bool:
    """Return True if the prepare/stage was DENIED (not authorized), False if it succeeded."""
    url = fleet.url("root", "cache")
    r = subprocess.run([sys.executable, "-c", _PREP_PROBE, url, path,
                        _flag(noerrs), _flag(stage)],
                       env=_root_env(principal), capture_output=True, text=True, timeout=30)
    return _denied(r.stdout)
