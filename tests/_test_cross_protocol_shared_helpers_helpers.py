# _test_cross_protocol_shared_helpers_helpers.py - shared header/helpers/fixtures/constants for the Phase-38
# split of test_cross_protocol_shared_helpers.py.  `from _test_cross_protocol_shared_helpers_helpers import *` re-exports EVERYTHING via
# the __all__ below so the test functions keep their exact module namespace.


"""
Cross-protocol shared-helper inventory.

These tests keep the source-sharing work honest without starting nginx.  The
behavioral coverage lives in the WebDAV, S3, TPC, query, and metrics suites;
this file verifies that the protocol handlers remain wired through the shared
helpers instead of silently growing private copies again.
"""

from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


import re as _re


def _read(relpath):
    path = ROOT / relpath
    assert path.exists(), f"missing expected file: {relpath}"
    text = path.read_text(encoding="utf-8")
    # Several refactors split source out of umbrella files that #include the
    # fragments back: the directive table into directives_*.inc, the big
    # brix_ctx_t/conf structs into *_structs.h, and webdav.h into per-concern
    # webdav_*.h headers.  Inline those siblings so a marker check against the
    # umbrella (module.c / context.h / webdav.h) sees the full effective source.
    def _inc(m):
        frag = path.parent / m.group(1)
        return frag.read_text(encoding="utf-8") if frag.exists() else m.group(0)
    return _re.sub(
        r'#include "(directives_[a-z0-9_]+\.inc|[a-z0-9_]+_structs\.h'
        r'|webdav_[a-z0-9_]+\.h)"',
        _inc, text)


def _assert_markers(relpath, markers):
    text = _read(relpath)
    missing = [marker for marker in markers if marker not in text]
    assert not missing, f"{relpath} is missing markers: {missing}"


def _assert_absent(relpath, markers):
    text = _read(relpath)
    present = [marker for marker in markers if marker in text]
    assert not present, f"{relpath} still has private helper markers: {present}"

__all__ = [n for n in dir() if not n.startswith('__')]
