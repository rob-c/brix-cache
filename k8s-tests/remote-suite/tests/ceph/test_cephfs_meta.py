#!/usr/bin/env python3
"""Unit tests for the pymigrate package (no cluster required).

Covers the pure-Python CephFS metadata decoders (pymigrate.cephfs_meta) against
both synthetic buffers and the real reef-18.2.4 byte fixtures, plus the shared
CLI plumbing (pymigrate.common). The ceph-dencoder-derived ground truth for the
fixtures is recorded in tests/ceph/fixtures/reef-18.2.4/README.md.

Run:  python3 -m pytest tests/ceph/test_cephfs_meta.py -v
"""

import json
import os
import struct
import sys
import zlib

import pytest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from pymigrate.cephfs_meta import (  # noqa: E402
    Denc,
    DecodeError,
    WalkStats,
    decode_dentry,
    decode_file_layout,
    decode_fragtree,
    decode_inode,
    decode_xattrs,
    frag_oid,
    mode_is_dir,
    mode_is_link,
    mode_is_reg,
    snap_dentry,
    snaptable_last_snap,
    walk_namespace,
)

FIXDIR = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                      "fixtures", "reef-18.2.4")


# ---------------------------------------------------------------------------
# Task 1: denc cursor
# ---------------------------------------------------------------------------

def test_denc_ints():
    d = Denc(struct.pack("<BHIQq", 7, 0x1234, 0xDEADBEEF, 2 ** 60, -5))
    assert (d.u8(), d.u16(), d.u32(), d.u64(), d.s64()) == \
        (7, 0x1234, 0xDEADBEEF, 2 ** 60, -5)
    assert d.remaining() == 0


def test_denc_overrun_raises():
    d = Denc(b"\x01")
    with pytest.raises(DecodeError):
        d.u32()


def test_denc_str_and_frame():
    payload = struct.pack("<I", 3) + b"abc"
    frame = bytes([9, 1]) + struct.pack("<I", len(payload) + 4) \
        + payload + struct.pack("<I", 0xFFFFFFFF)
    d = Denc(frame)
    f = d.start()
    assert f.struct_v == 9
    assert d.str() == b"abc"
    d.finish(f)                    # skips the trailing u32 inside the frame
    assert d.remaining() == 0


def test_denc_frame_length_overrun():
    with pytest.raises(DecodeError):
        Denc(bytes([1, 1]) + struct.pack("<I", 999)).start()


def test_denc_bytes_and_skip():
    d = Denc(b"abcdef")
    assert d.bytes(3) == b"abc"
    d.skip(2)
    assert d.bytes(1) == b"f"
    with pytest.raises(DecodeError):
        d.skip(1)


# ---------------------------------------------------------------------------
# Task 2: typed decoders — synthetic encoder (ports cephfs_layout_unittest.c)
# ---------------------------------------------------------------------------

def enc_frame(v, compat, payload):
    return bytes([v, compat]) + struct.pack("<I", len(payload)) + payload


def enc_layout(su=0x400000, sc=1, osz=0x400000, pool=7):
    return enc_frame(2, 2, struct.pack("<IIIq", su, sc, osz, pool)
                     + struct.pack("<I", 0))          # empty pool_ns string


def enc_inode(v, ino=0x1234, mode=0o100644, size=4096, mtime=555):
    b = struct.pack("<QIII", ino, 0, 100, 0)          # ino, rdev, ctime
    b += struct.pack("<IIII", mode, 0, 0, 1)          # mode, uid, gid, nlink
    b += b"\0"                                        # anchored (bool)
    if v >= 4:
        b += b"\0" * 8                                # dir_layout
    b += enc_layout()
    b += struct.pack("<QIQQ", size, 1, 0xFFFFFFFFFFFFFFFF, 0)
    if v >= 5:
        b += struct.pack("<I", 0)                     # truncate_pending
    b += struct.pack("<II", mtime, 0)                 # mtime
    b += b"\0" * 16                                   # trailing fields to frame-skip
    return enc_frame(v, 6, b)


@pytest.mark.parametrize("v", [2, 3, 4, 5, 11, 14, 19])
def test_inode_versions(v):
    ino = decode_inode(Denc(enc_inode(v)))
    assert (ino.struct_v, ino.ino, ino.size, ino.mtime_sec) == (v, 0x1234, 4096, 555)
    assert mode_is_reg(ino.mode)
    assert ino.layout.object_size == 0x400000
    assert ino.layout.stripe_count == 1
    assert ino.layout.pool_id == 7


def test_file_layout_direct():
    lo = decode_file_layout(Denc(enc_layout(su=1, sc=2, osz=3, pool=-1)))
    assert (lo.stripe_unit, lo.stripe_count, lo.object_size, lo.pool_id) == (1, 2, 3, -1)


def test_fragtree_empty_and_split():
    leaves, tr = decode_fragtree(Denc(struct.pack("<I", 0)))
    assert leaves == [0] and not tr
    leaves, tr = decode_fragtree(Denc(struct.pack("<III", 1, 0, 1)))
    assert sorted(leaves) == [0x01000000, 0x01000001] and not tr


def test_fragtree_implausible_count():
    with pytest.raises(DecodeError):
        decode_fragtree(Denc(struct.pack("<I", 100000)))


def test_xattr_map():
    def s(x):
        return struct.pack("<I", len(x)) + x
    xs, tr = decode_xattrs(Denc(struct.pack("<I", 2)
                                + s(b"user.a") + s(b"1")
                                + s(b"user.bb") + s(b"22")))
    assert xs == {b"user.a": b"1", b"user.bb": b"22"} and not tr


# ---------------------------------------------------------------------------
# Task 2: typed decoders — real reef fixtures
# ---------------------------------------------------------------------------

def _fx(name):
    with open(os.path.join(FIXDIR, name), "rb") as f:
        return f.read()


def test_fixture_file():
    dn = decode_dentry(_fx("fx_dir1_hello.bin"))
    assert dn.kind == "primary"
    assert dn.inode.ino == 0x100000001F7
    assert dn.inode.size == 27
    assert mode_is_reg(dn.inode.mode)
    assert dn.inode.layout.object_size == 0x400000
    assert dn.inode.layout.stripe_count == 1


def test_fixture_dirs_and_top():
    d1 = decode_dentry(_fx("fx_root_dir1.bin"))
    assert d1.inode.ino == 0x10000000000 and mode_is_dir(d1.inode.mode)
    assert mode_is_dir(decode_dentry(_fx("fx_dir1_sub.bin")).inode.mode)
    top = decode_dentry(_fx("fx_root_top.bin"))
    assert top.inode.ino == 0x10000000002 and top.inode.size == 15


def test_fixture_symlink():
    dn = decode_dentry(_fx("fx_link_symlink.bin"))
    assert mode_is_link(dn.inode.mode)
    assert dn.symlink == b"hello.txt"
    assert dn.inode.ino == 0x10000000003


def test_fixture_xattrs():
    dn = decode_dentry(_fx("fx_hello_xattr.bin"))
    assert dn.xattrs == {b"user.color": b"blue", b"user.shape": b"round"}
    assert dn.inode.size == 27


def test_dentry_garbage_refused():
    with pytest.raises(DecodeError):
        decode_dentry(b"\0" * 8 + b"Z" + b"\0" * 32)   # unknown type marker
    with pytest.raises(DecodeError):
        decode_dentry(b"\x01")                         # short buffer


# ---------------------------------------------------------------------------
# Task 3: namespace walker + snaptable
# ---------------------------------------------------------------------------

def enc_primary_dentry(v_inode, mode, ino, size=0, symlink=None):
    body = enc_inode(v_inode, ino=ino, mode=mode, size=size)
    if (mode & 0o170000) == 0o120000:
        body += struct.pack("<I", len(symlink)) + symlink
    body += struct.pack("<I", 0)                       # empty fragtree
    body += struct.pack("<I", 0)                       # empty xattr map
    return struct.pack("<Q", 2) + b"I" + body          # snapid, 'I' bare InodeStore


def enc_remote_dentry(ino, d_type=8):
    return struct.pack("<Q", 2) + b"L" + struct.pack("<QB", ino, d_type)


def test_walk_namespace():
    omaps = {
        frag_oid(1, 0): [
            (b"f1_head", enc_primary_dentry(19, 0o100644, 0x100, size=7)),
            (b"sub_head", enc_primary_dentry(19, 0o040755, 0x200)),
            (b"old_1a_1f", b"whatever"),               # snap dentry: skipped+counted
            (b"bad_head", b"\0\0"),                    # undecodable
        ],
        frag_oid(0x200, 0): [
            (b"f2_head", enc_primary_dentry(19, 0o100644, 0x300, size=9)),
            (b"ln_head", enc_primary_dentry(19, 0o120777, 0x400, symlink=b"f2")),
            (b"hl_head", enc_remote_dentry(0x300)),
        ],
    }

    def rd(oid, start):
        return ([e for e in omaps.get(oid, []) if e[0] > start], False)

    st = WalkStats()
    entries = list(walk_namespace(rd, stats=st))
    got = {e.path: e.kind for e in entries if not e.undecodable}
    assert got == {"/f1": "file", "/sub": "dir", "/sub/f2": "file",
                   "/sub/ln": "symlink", "/sub/hl": "remote"}
    assert st.snap_dentries == 1
    assert st.undecodable == 1


def test_walk_namespace_paging():
    """The walker must keep paging while more=True, keyed on the last key."""
    entries = [(("k%02d" % i).encode() + b"_head",
                enc_primary_dentry(19, 0o100644, 0x100 + i, size=i))
               for i in range(10)]

    def rd(oid, start):
        if oid != frag_oid(1, 0):
            return ([], False)
        after = [e for e in entries if e[0] > start]
        return (after[:3], len(after) > 3)

    st = WalkStats()
    got = [e.path for e in walk_namespace(rd, stats=st)]
    assert len(got) == 10


def test_snap_dentry_classifier():
    assert snap_dentry(b"name_1a")
    assert not snap_dentry(b"name_head")
    assert not snap_dentry(b"name_zz")
    assert not snap_dentry(b"plain")


def test_snaptable_last_snap():
    payload = struct.pack("<Q", 5) + b"\1\1" + struct.pack("<I", 8) \
        + struct.pack("<Q", 3)
    assert snaptable_last_snap(payload) == 3
    assert snaptable_last_snap(b"junk") == 0


# ---------------------------------------------------------------------------
# Task 4: common plumbing
# ---------------------------------------------------------------------------

def test_adler32_hex_seed1():
    from pymigrate.common import adler32_hex
    assert adler32_hex([b"hello ", b"world"]) == "%08x" % zlib.adler32(b"hello world", 1)
    assert adler32_hex([]) == "%08x" % 1


def test_filter_worklist(tmp_path):
    from pymigrate.common import filter_worklist
    items = ["rm/a", "rm/b", "cp/x"]
    lf = tmp_path / "l"
    lf.write_text("rm/a\r\ncp/x \nzz/gone \n\n")
    # --list replaces enumeration verbatim: entries survive even when the
    # enumerated items no longer contain them (rollback of deleted sources)
    assert filter_worklist(items, str(lf), None, None) == ["rm/a", "cp/x", "zz/gone"]
    assert filter_worklist(items, None, "rm/", None) == ["rm/a", "rm/b"]
    assert filter_worklist(items, None, None, "*/b") == ["rm/b"]
    assert filter_worklist(items, str(lf), "rm/", None) == ["rm/a"]
    assert filter_worklist(items, None, None, None) == items


def test_state_manifest_roundtrip(tmp_path):
    from pymigrate.common import StateManifest
    p = str(tmp_path / "state.jsonl")
    m = StateManifest(p)
    m.record("a", "migrate", "redirect", "fail")
    m.record("a", "migrate", "redirect", "ok")
    m.record("b", "migrate", "redirect", "fail")
    m2 = StateManifest(p)                              # reload from disk
    assert m2.done_ok("a", "migrate", "redirect")
    assert not m2.done_ok("b", "migrate", "redirect")
    assert not m2.done_ok("a", "rollback", "redirect")  # keyed on action too
    assert not m2.done_ok("a", "migrate", "copy")       # ...and on mode
    assert not StateManifest(None).done_ok("a", "migrate", "redirect")


def test_reporter_json(capsys):
    from pymigrate.common import Reporter
    r = Reporter(json_mode=True, progress=False, total=2)
    r.item("s1", "migrate", "ok", nbytes=10, objects=2, dest="/d/s1")
    r.item("s2", "migrate", "fail", error="boom")
    rc = r.summary()
    out = [json.loads(l) for l in capsys.readouterr().out.strip().splitlines()]
    assert out[0]["result"] == "ok" and out[0]["bytes"] == 10
    assert out[1]["error"] == "boom"
    assert out[-1]["summary"]["ok"] == 1 and out[-1]["summary"]["fail"] == 1
    assert rc == 1


def test_reporter_human_and_exit0(capsys):
    from pymigrate.common import Reporter
    r = Reporter(json_mode=False, progress=False, total=1)
    r.item("s1", "migrate", "ok", nbytes=10, objects=2, dest="/d/s1")
    assert r.summary() == 0
    out = capsys.readouterr().out
    assert "OK" in out and "s1" in out


def test_load_tool_config(tmp_path):
    from pymigrate.common import load_tool_config
    p = tmp_path / "site.conf"
    p.write_text(
        "# site profile\n"
        "striper_pool = xrdtest\n"
        "meta_pool= cephfs.cephfs.meta\n"
        "data_pool =cephfs.cephfs.data   # inline comment\n"
        "client\t=\tadmin\n"
        "fs_name =\n"                     # empty value = unset
        "\n"
        "dest_prefix = /migrated\n")
    cfg = load_tool_config(str(p))
    assert cfg == {"striper_pool": "xrdtest",
                   "meta_pool": "cephfs.cephfs.meta",
                   "data_pool": "cephfs.cephfs.data",
                   "client": "admin",
                   "dest_prefix": "/migrated"}


def test_load_tool_config_rejects_unknown_key(tmp_path):
    from pymigrate.common import load_tool_config
    p = tmp_path / "bad.conf"
    p.write_text("meta_pol = typo\n")
    with pytest.raises(ValueError, match="meta_pol"):
        load_tool_config(str(p))
    p2 = tmp_path / "junk.conf"
    p2.write_text("not a key value line\n")
    with pytest.raises(ValueError):
        load_tool_config(str(p2))


def test_resolve_setting_precedence():
    from pymigrate.common import resolve_setting
    cfg = {"client": "site", "conf": "/site/ceph.conf"}
    assert resolve_setting("cli", cfg, "client", "admin") == "cli"
    assert resolve_setting(None, cfg, "client", "admin") == "site"
    assert resolve_setting(None, cfg, "fs_name", None) is None
    assert resolve_setting(None, {}, "client", "admin") == "admin"
    assert resolve_setting("", cfg, "client", "admin") == "site"  # empty CLI = unset


def test_run_parallel_isolates_exceptions():
    from pymigrate.common import run_parallel
    seen = []

    def fn(x):
        if x == 2:
            raise RuntimeError("boom")
        seen.append(x)

    errors = run_parallel([1, 2, 3], fn, threads=2)
    assert sorted(seen) == [1, 3]
    assert len(errors) == 1 and errors[0][0] == 2


if __name__ == "__main__":
    sys.exit(pytest.main([__file__, "-v"]))
