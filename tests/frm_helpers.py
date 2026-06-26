"""
frm_helpers.py — shared primitives for the FRM / tape-staging test suite.

Centralizes the two helpers that every test_frm_*.py + test_tape_rest.py had
re-derived verbatim:

  * xattr_ok()       — a user-xattr capability probe used as a skip guard (FRM
                       residency markers are stored as user.frm.* xattrs).
  * res_stub_path()  — the control-dir residency stub name, which MUST match
                       src/frm/residency.c frm_res_marker_path() (FNV-1a-64 over
                       the absolute path → "<control_dir>/<016x>.res").
"""

import os


def xattr_ok(tmp):
    """True if `tmp`'s filesystem supports user xattrs (else FRM residency
    markers cannot be written and the caller should skip)."""
    try:
        p = os.path.join(str(tmp), ".xattrprobe")
        open(p, "w").close()
        os.setxattr(p, "user.frm.test", b"1")
        os.remove(p)
        return True
    except Exception:
        return False


def res_stub_path(control_dir, abs_path):
    """Filesystem path of the control-dir residency stub for `abs_path`, matching
    src/frm/residency.c (FNV-1a-64 over the absolute path)."""
    h = 1469598103934665603
    for b in abs_path.encode():
        h ^= b
        h = (h * 1099511628211) & 0xFFFFFFFFFFFFFFFF
    return os.path.join(control_dir, f"{h:016x}.res")
