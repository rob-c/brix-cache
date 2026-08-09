"""Phase-95 dead-code pins.

The parity audit (docs/refactor/xrootd-feature-parity-audit-2026-08-04.md §9.2)
found engines that were fully implemented but had zero call sites: they enforced
nothing while reading, in config and in review, like they did.  Phase-95 removed
them.  These tests fail if any of them is reintroduced *without* the call site
that makes it live, which is the only way the class of bug comes back.

They are grep-shaped on purpose: the point is the absence of a symbol from the
tree, which no runtime assertion can observe.
"""

import re
import subprocess
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent

# symbol -> what it was, and what reintroducing it must come with
REMOVED = {
    "xrdhttp_send_redirect": "HTTP redirect dialect; needs a mesh-selection call site",
    "brix_throttle_charge_io": "IO-load metric; needs a per-IO completion charge point",
    "brix_throttle_ioload_over": "IO-load gate; needs an admission point",
    "brix_throttle_userconfig_load": "userconfig INI; needs a directive exposing the path",
    "brix_throttle_userconfig_match": "userconfig precedence; needs an enforcement point",
    "brix_protbind_proto_name": "protbind id->name; every &P= block spells its own name",
    "max_active_conn": "parsed-never-read connection cap; needs a login admission point",
}

SEARCH_ROOTS = ["src", "client", "shared"]


def _grep(symbol):
    """Every occurrence of `symbol` in the buildable tree, as 'path:line: text'."""
    proc = subprocess.run(
        ["grep", "-rn", "--include=*.c", "--include=*.h", "--include=*.h",
         "-w", symbol, *SEARCH_ROOTS],
        cwd=REPO, capture_output=True, text=True,
    )
    # grep exits 1 for "no matches", which is the passing case here.
    assert proc.returncode in (0, 1), proc.stderr
    return [ln for ln in proc.stdout.splitlines() if ln.strip()]


# A comment may name a removed symbol (the deletions leave a note saying why),
# but a declaration, definition or call may not.
_COMMENT = re.compile(r"^\s*(/\*|\*|//)")


@pytest.mark.parametrize("symbol", sorted(REMOVED))
def test_removed_symbol_absent_from_code(symbol):
    """Success case: the symbol survives only in explanatory comments."""
    code_hits = []
    for hit in _grep(symbol):
        _path, _line, text = hit.split(":", 2)
        if not _COMMENT.match(text):
            code_hits.append(hit)

    assert not code_hits, (
        f"{symbol} is back in the tree as code — {REMOVED[symbol]}.\n"
        + "\n".join(code_hits)
    )


def test_grep_helper_finds_a_symbol_that_is_present():
    """Error case: a pin that can never fail is worthless.

    Pins the helper itself against a symbol that must exist, so a broken grep
    invocation (wrong cwd, wrong --include) shows up as this test failing rather
    than as every other test silently passing.
    """
    assert _grep("brix_throttle_open_inc"), "grep helper found nothing for a live symbol"


def test_throttle_open_files_cap_is_still_wired():
    """Security-negative: the one throttle engine that IS live stays live.

    The per-user open-files cap is the surviving half of throttle_compat.  If a
    future cleanup deletes its call sites the cap silently stops applying — the
    exact failure mode phase-95 removed the other engines to prevent — so assert
    the charge and both release points, not just the symbol.
    """
    inc = _grep("brix_throttle_open_inc")
    dec = _grep("brix_throttle_open_dec")

    callers = {hit.split(":", 1)[0] for hit in inc + dec
               if "throttle_compat" not in hit}
    assert any("open_resolved_file_finalize.c" in c for c in callers), \
        f"open-files cap is no longer charged at open: {sorted(callers)}"
    assert any("close.c" in c for c in callers), \
        f"open-files cap is no longer released on close: {sorted(callers)}"
    assert any("disconnect.c" in c for c in callers), \
        f"open-files cap is no longer released on disconnect: {sorted(callers)}"
