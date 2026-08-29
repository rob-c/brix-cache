"""Phase-49 W1 tail — the xrdfs per-handler ``brix_report_err`` sweep.

Source-contract guard: every single-path op-error site in the xrdfs handlers
must route through the shared reporter (``xrdfs_report_err`` /
``xrdfs_web_report_err`` → ``brix_report_err``) instead of the historical
hand-rolled ``fprintf("xrdfs: <op> <path>: <msg>")`` + hints + shellcode
block.  Behaviour (message text, hint chain, exit codes) is covered by the
live xrdfs suites; this file pins the structural invariant so the
duplication cannot silently creep back.

3-test ritual:
  success      — zero hand-rolled single-path error blocks remain in the
                 xrdfs sources, and the sweep actually adopted the helper
                 at scale (>= 40 call sites);
  error        — the wrappers delegate to the shared brix_report_err helper
                 (they never reimplement the fprintf themselves), so the
                 error-line format lives in exactly one place (cli_conn.c);
  security-neg — no endpoint-less straggler hint calls remain: every swept
                 site carries the full WS-3/WS-7 chain via the wrapper, and
                 the two-path formats that legitimately stay hand-rolled
                 still emit hints through xrdfs_op_hints.
"""

from __future__ import annotations

import re
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
FS_DIR = REPO_ROOT / "client/apps/fs"

XRDFS_SOURCES = sorted(FS_DIR.glob("xrdfs*.c")) + [FS_DIR / "xrdfs_internal.h"]

# The historical single-path idiom: 'xrdfs: <op words> %s: %s\n'.  Op words
# never contain '%', so two-path formats ("ln -s %s %s: %s") and bracketed
# xattr names ("xattr get %s [%s]: %s") do not match and stay hand-rolled
# by design (they don't fit the single-path helper).
HAND_ROLLED = re.compile(r'fprintf\(stderr, "xrdfs: [\w -]+ %s: %s\\n"')


def _read(path: Path) -> str:
    assert path.is_file(), f"missing xrdfs source: {path}"
    return path.read_text()


# ---------------------------------------------------------------- success --

def test_no_hand_rolled_single_path_error_blocks_remain():
    offenders = []
    for src in XRDFS_SOURCES:
        for i, line in enumerate(_read(src).splitlines(), 1):
            if HAND_ROLLED.search(line):
                offenders.append(f"{src.name}:{i}: {line.strip()}")
    assert offenders == [], (
        "hand-rolled xrdfs single-path error blocks reintroduced — use "
        "xrdfs_report_err()/xrdfs_web_report_err() instead:\n"
        + "\n".join(offenders))


def test_sweep_adopted_the_helper_at_scale():
    calls = sum(
        len(re.findall(r"\bxrdfs(?:_web)?_report_err\(", _read(src)))
        for src in XRDFS_SOURCES if src.suffix == ".c")
    assert calls >= 40, (
        f"expected the swept handlers to call the shared reporter at >=40 "
        f"sites, found {calls} — was the sweep partially reverted?")


# ------------------------------------------------------------------ error --

def test_wrappers_delegate_to_brix_report_err():
    """The wrappers are adapters, not reimplementations: each must call
    brix_report_err and neither may fprintf the error line itself."""
    header = _read(FS_DIR / "xrdfs_internal.h")
    for wrapper in ("xrdfs_report_err", "xrdfs_web_report_err"):
        m = re.search(
            rf"^static inline int\n{wrapper}\(.*?^\}}", header,
            re.MULTILINE | re.DOTALL)
        assert m, f"{wrapper} missing from xrdfs_internal.h"
        body = m.group(0)
        assert "brix_report_err(stderr, \"xrdfs\"" in body, (
            f"{wrapper} must delegate to the shared brix_report_err helper")
        assert "fprintf" not in body, (
            f"{wrapper} reimplements the error line instead of delegating")


# ----------------------------------------------------------- security-neg --

def test_no_endpointless_hint_stragglers():
    """The pre-sweep straggler called brix_cred_hint_for_status (no endpoint,
    no WS-3/WS-7 chain).  Only the _url variant — reached via the wrappers or
    xrdfs_op_hints — is allowed in the handlers."""
    for src in XRDFS_SOURCES:
        # Strip comments: the wrapper docs legitimately name the old call.
        text = re.sub(r"/\*.*?\*/", "", _read(src), flags=re.DOTALL)
        bare = re.findall(r"brix_cred_hint_for_status\(", text)
        assert not bare, (
            f"{src.name}: endpoint-less brix_cred_hint_for_status() call — "
            "route the site through xrdfs_report_err (or xrdfs_op_hints for "
            "multi-path formats) so WS-3/WS-7 hints stay uniform")


def test_two_path_formats_still_emit_hints():
    """mv/ln keep their own fprintf (two-path / no-path formats) but must
    still follow it with xrdfs_op_hints so hint coverage has no holes.

    The mv handler lives in the xrdfs_meta_* split family (phase-103 moved it
    from xrdfs_meta.c to xrdfs_meta_ns.c), so search the whole family rather
    than pinning one shard name."""
    meta = "\n".join(_read(p) for p in sorted(FS_DIR.glob("xrdfs_meta*.c")))
    attr = _read(FS_DIR / "xrdfs_attr.c")
    for text, op_line in ((meta, r'"xrdfs: mv: %s\\n"'),
                          (attr, r'"xrdfs: ln -s %s %s: %s\\n"'),
                          (attr, r'"xrdfs: ln %s %s: %s\\n"')):
        m = re.search(op_line + r".*?\n(.*?)\n", text, re.DOTALL)
        assert m, f"expected hand-rolled two-path site {op_line} to exist"
        assert "xrdfs_op_hints" in m.group(1), (
            f"two-path site {op_line} lost its xrdfs_op_hints follow-up")
