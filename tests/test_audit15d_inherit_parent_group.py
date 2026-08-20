"""
test_audit15d_inherit_parent_group.py — `brix_inherit_parent_group` group
policy (audit §A2, testsuite-combinatorial-coverage-audit 2026-08-15: the
directive had zero coverage — src/auth/authz/group_policy.c's chown/chmod
enforcement had never executed under test).

A rule `brix_inherit_parent_group /shared` makes entries created under the
prefix take the PARENT directory's gid and parent-derived group mode bits,
enforced by explicit chown/chmod — NOT by the kernel's setgid-bit semantic.
To prove the policy (and not the kernel) does the work, the parent dirs here
carry a supplementary gid WITHOUT the setgid bit: the kernel default would
give new entries the process egid.

DEFECT-CANDIDATE PIN — mkdir never inherits.  The policy has two consumers:

  * file create — applied UNGATED on the freshly-created fd
    (src/protocols/root/read/open_resolved_file_finalize.c) — works;
  * kXR_mkdir — src/protocols/root/write/mkdir.c gates the post-mkdir
    application on `brix_vfs_backend_resolve(root_canon) == NULL`, written
    when a registered VFS backend implied a catalog namespace.  Phase-68's
    census registration (src/fs/vfs/vfs_backend_config.c) now registers
    EVERY posix export — explicit `posix:` and the bare-`brix_export`
    default — so the gate is never NULL and the policy is skipped for the
    very backend it was designed for.  The recursive branch is no better:
    sd_posix_ns.c passes NULL rules to brix_mkdir_recursive_confined_canon.

So today the same directive on the same server chowns new FILES but not new
DIRECTORIES.  test_mkdir_group_policy_skipped_defect_pin asserts that skew
and must be inverted when the mkdir gate keys on backend KIND rather than
registry presence (or the driver walker gets the rules).

Needs a supplementary group: skipped when the test user belongs to only one.

Cases:
  * success — a wire create (write-open kXR_new + write + close) under the
    rule prefix inherits the parent's gid with file-grain group bits
  * defect pin — a wire mkdir under the same prefix keeps the process egid
  * security-negative — a create OUTSIDE the rule prefix keeps the process
    egid: the rule is path-scoped, not server-wide
  * error — a relative rule path is refused at nginx -t
"""

import os
import stat
import struct

import pytest

from settings import HOST
from test_phase25_ratelimit import KXR_OK, _xrd_recv_status
from test_tls_require import (_connect, _parse, _send_protocol, _start,
                              _xrd_login)

pytestmark = [pytest.mark.uses_lifecycle_harness,
              pytest.mark.xdist_group("lc-audit15d-inherit")]


def _supplementary_gid():
    gids = [g for g in os.getgroups() if g != os.getgid()]
    if not gids:
        pytest.skip("test user has no supplementary group")
    return gids[0]


@pytest.fixture()
def inherit(lifecycle, tmp_path):
    """(port, data, supp_gid): a posix export whose /shared subtree carries
    the inheritance rule; /other is the identically-owned unruled control."""
    supp = _supplementary_gid()
    data = tmp_path / "data"
    data.mkdir()
    for name in ("shared", "other"):
        d = data / name
        d.mkdir()
        os.chown(d, -1, supp)
        # 0770 and explicitly NO setgid: gid inheritance below must come from
        # the policy's chown, never from the kernel's setgid semantic.
        os.chmod(d, 0o770)
    port = _start(lifecycle, data, "lc-audit15d-inherit",
                  tls=False, auth="none", tls_require="none",
                  auth_lines=("        brix_allow_write on;\n"
                              "        brix_inherit_parent_group /shared;\n"))
    return port, data, supp


def _session(port):
    s = _connect(port)
    _send_protocol(s)
    status, body = _xrd_login(s)
    assert status == KXR_OK, ("login refused", status, body)
    return s


def _xrd_mkdir(s, path, mode=0o755):
    """kXR_mkdir, non-recursive (options byte 0), explicit mode."""
    body = struct.pack(">B13xH", 0, mode)
    payload = path.encode()
    s.sendall(struct.pack(">BBH", 0, 1, 3008) + body
              + struct.pack(">I", len(payload)) + payload)
    return _xrd_recv_status(s)


def _xrd_put(s, path, payload, mode=0o644):
    """Create + write + close: the staged create only commits at kXR_close,
    so a bare open would leave nothing on disk to stat."""
    # kXR_new | kXR_open_wrto
    body = struct.pack(">HH12s", mode, 0x0008 | 0x4000, b"\x00" * 12)
    wire = path.encode()
    s.sendall(struct.pack(">BBH", 0, 1, 3010) + body
              + struct.pack(">I", len(wire)) + wire)
    status, obody = _xrd_recv_status(s)
    assert status == KXR_OK, ("create open refused", status, obody)
    fh = obody[:4]
    s.sendall(struct.pack(">BB H 4s 8s B 3x I", 0, 1, 3019, fh, b"\x00" * 8,
                          0, len(payload)) + payload)
    status, wbody = _xrd_recv_status(s)
    assert status == KXR_OK, ("write refused", status, wbody)
    s.sendall(struct.pack(">BBH", 0, 1, 3003) + fh + b"\x00" * 12
              + struct.pack(">I", 0))
    status, cbody = _xrd_recv_status(s)
    assert status == KXR_OK, ("close refused", status, cbody)


def test_create_under_rule_inherits_parent_gid(inherit):
    port, data, supp = inherit
    s = _session(port)
    _xrd_put(s, "/shared/f1.dat", b"payload\n")
    s.close()
    fpath = data / "shared" / "f1.dat"
    assert fpath.read_bytes() == b"payload\n"
    st = os.stat(fpath)
    assert st.st_gid == supp, \
        (f"file gid {st.st_gid} != parent gid {supp} — the policy chown "
         f"never ran (kernel default would be egid {os.getgid()})")
    # File grain: group rw, and never group-execute from a 0644 create.
    assert st.st_mode & (stat.S_IRGRP | stat.S_IWGRP) \
        == (stat.S_IRGRP | stat.S_IWGRP), oct(st.st_mode)
    assert not st.st_mode & stat.S_IXGRP, oct(st.st_mode)


def test_mkdir_group_policy_skipped_defect_pin(inherit):
    # DEFECT-CANDIDATE PIN (see module docstring): the mkdir-side gate
    # `brix_vfs_backend_resolve(...) == NULL` is defeated by phase-68's
    # census registration of every posix export, so the SAME rule that just
    # chowned a new file leaves a new directory on the process egid.  Invert
    # to `st.st_gid == supp` when the gate keys on backend kind.
    port, data, supp = inherit
    s = _session(port)
    status, body = _xrd_mkdir(s, "/shared/d1")
    s.close()
    assert status == KXR_OK, (status, body)
    st = os.stat(data / "shared" / "d1")
    assert st.st_gid == os.getgid(), \
        (f"mkdir inherited gid {st.st_gid} — mkdir-side policy fixed? "
         f"invert this pin (expected egid {os.getgid()}, parent {supp})")


def test_create_outside_rule_keeps_process_egid(inherit):
    # /other has the SAME supplementary gid on the parent, so any inheritance
    # here would be indistinguishable from the ruled case — its absence pins
    # the rule's path scoping on the (working) file-create consumer.
    port, data, supp = inherit
    s = _session(port)
    _xrd_put(s, "/other/f1.dat", b"payload\n")
    s.close()
    assert os.stat(data / "other" / "f1.dat").st_gid == os.getgid()


def test_relative_rule_path_refused_at_parse(tmp_path):
    rc, out = _parse(tmp_path,
                     "none;\n"
                     "        brix_allow_write on;\n"
                     "        brix_inherit_parent_group ../escape")
    assert rc != 0
    assert "brix_inherit_parent_group: invalid path" in out, out
