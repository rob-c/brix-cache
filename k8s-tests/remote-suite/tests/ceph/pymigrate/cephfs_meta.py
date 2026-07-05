"""cephfs_meta — pure-Python decoders for CephFS on-RADOS metadata.

WHAT: A Python port of the C decode core (src/fs/backend/rados/cephfs_denc.{c,h}
      + cephfs_layout.{c,h}): Ceph's wire/disk encoding primitives (fixed-width
      little-endian ints, length-prefixed strings, ENCODE_START/DECODE_FINISH
      struct framing) and the typed decoders built on them (directory-entry
      values, inode_t, file_layout_t, fragtree, xattr map), plus the namespace
      walker the CephFS->striper migration tool uses to enumerate a quiesced
      CephFS straight from its metadata-pool omaps.

WHY:  The Python migration tools read a CephFS with no mount/MDS/libcephfs, so
      they must parse exactly what the MDS wrote. Keeping the port faithful to
      the C decoders (same field order, same struct_v guards, same caps) means
      the two implementations validate each other against the same byte
      fixtures (tests/ceph/fixtures/reef-18.2.4).

HOW:  Denc is a bounded cursor that raises DecodeError on any overrun (the
      Python idiom for the C version's sticky error), so a malformed or
      too-new encoding is always a clean refusal, never a wild parse. Version
      coverage matches the C decoder: inode_t struct_v 2..19 (reef),
      file_layout_t framed v2.

Pure stdlib; no rados/cephfs imports here by design (unit-testable anywhere).
"""

from __future__ import annotations

import struct
from collections import namedtuple
from dataclasses import dataclass, field
from typing import Optional

MAX_FRAGS = 256      # leaf-fragment cap per directory (flagged truncated past it)
MAX_XATTRS = 64      # xattr cap per inode (flagged truncated past it)

ROOT_INO = 1         # the CephFS root directory inode


class DecodeError(Exception):
    """A buffer overrun, malformed field, or unsupported encoding."""


Frame = namedtuple("Frame", "struct_v struct_compat payload_end")


class Denc:
    """Read-only bounded cursor over a Ceph-encoded buffer.

    Every accessor validates remaining space and raises DecodeError on
    overrun; `start()`/`finish()` implement the ENCODE_START framing so
    callers can forward-skip trailing fields newer encoders added.
    """

    __slots__ = ("buf", "pos", "end")

    def __init__(self, buf: bytes, pos: int = 0, end: Optional[int] = None):
        self.buf = buf
        self.pos = pos
        self.end = len(buf) if end is None else end
        if self.end > len(buf) or self.pos > self.end:
            raise DecodeError("cursor bounds outside buffer")

    def remaining(self) -> int:
        return self.end - self.pos

    def _take(self, n: int) -> int:
        if self.end - self.pos < n:
            raise DecodeError("buffer overrun (need %d, have %d)"
                              % (n, self.end - self.pos))
        p = self.pos
        self.pos += n
        return p

    def u8(self) -> int:
        return self.buf[self._take(1)]

    def u16(self) -> int:
        p = self._take(2)
        return struct.unpack_from("<H", self.buf, p)[0]

    def u32(self) -> int:
        p = self._take(4)
        return struct.unpack_from("<I", self.buf, p)[0]

    def u64(self) -> int:
        p = self._take(8)
        return struct.unpack_from("<Q", self.buf, p)[0]

    def s64(self) -> int:
        p = self._take(8)
        return struct.unpack_from("<q", self.buf, p)[0]

    def bytes(self, n: int) -> bytes:
        p = self._take(n)
        return self.buf[p:p + n]

    def skip(self, n: int) -> None:
        self._take(n)

    def str(self) -> bytes:
        """A Ceph string/bufferlist/bufferptr: u32 length prefix + payload."""
        return self.bytes(self.u32())

    def start(self) -> Frame:
        """Read an ENCODE_START header: struct_v u8, compat u8, len u32."""
        v = self.u8()
        compat = self.u8()
        length = self.u32()
        payload_end = self.pos + length
        if payload_end > self.end:
            raise DecodeError("frame length %d overruns buffer" % length)
        return Frame(v, compat, payload_end)

    def finish(self, f: Frame) -> None:
        """Jump to the end of a frame's payload (skip unread trailing fields)."""
        if self.pos > f.payload_end:
            raise DecodeError("decoded past frame end")
        self.pos = f.payload_end


# ---------------------------------------------------------------------------
# Typed decoders (port of cephfs_layout.c; field order/guards verbatim from
# Ceph v18.2.4 — inode_t::decode in src/include/cephfs/types.h,
# InodeStoreBase::decode_bare in src/mds/CInode.cc, CDir::_load_dentry).
# ---------------------------------------------------------------------------

S_IFMT = 0o170000
S_IFDIR = 0o040000
S_IFREG = 0o100000
S_IFLNK = 0o120000


def mode_is_dir(m: int) -> bool:
    return (m & S_IFMT) == S_IFDIR


def mode_is_reg(m: int) -> bool:
    return (m & S_IFMT) == S_IFREG


def mode_is_link(m: int) -> bool:
    return (m & S_IFMT) == S_IFLNK


@dataclass
class Layout:
    """file_layout_t: how a file's bytes stripe across RADOS objects."""
    stripe_unit: int = 0
    stripe_count: int = 0
    object_size: int = 0
    pool_id: int = -1


@dataclass
class Inode:
    """The inode_t subset the migration tools need."""
    ino: int = 0
    mode: int = 0
    uid: int = 0
    gid: int = 0
    nlink: int = 0
    size: int = 0
    mtime_sec: int = 0
    mtime_nsec: int = 0
    ctime_sec: int = 0
    ctime_nsec: int = 0
    layout: Layout = field(default_factory=Layout)
    struct_v: int = 0


@dataclass
class Dentry:
    """A decoded directory-entry omap value (primary or remote)."""
    kind: str = "primary"              # "primary" | "remote"
    remote_ino: int = 0
    remote_d_type: int = 0
    inode: Inode = field(default_factory=Inode)
    symlink: Optional[bytes] = None
    frags: "list[int]" = field(default_factory=list)   # leaf frag _enc values
    frags_truncated: bool = False
    xattrs: "dict[bytes, bytes]" = field(default_factory=dict)
    xattrs_truncated: bool = False


def decode_file_layout(d: Denc) -> Layout:
    """Decode a framed file_layout_t (long-stable v2); pool_ns frame-skipped."""
    f = d.start()
    out = Layout(stripe_unit=d.u32(), stripe_count=d.u32(),
                 object_size=d.u32(), pool_id=d.s64())
    d.finish(f)                        # pool_ns string not needed
    return out


def decode_inode(d: Denc) -> Inode:
    """Decode a framed inode_t up to mtime, honouring the version guards
    (v>=4: dir_layout present; v>=5: truncate_pending present), then
    frame-skip the trailing fields (atime, rstat, quota, fscrypt, ...)."""
    f = d.start()
    out = Inode(struct_v=f.struct_v)

    out.ino = d.u64()
    d.u32()                            # rdev
    out.ctime_sec = d.u32()            # utime_t: sec, nsec (both u32)
    out.ctime_nsec = d.u32()
    out.mode = d.u32()
    out.uid = d.u32()
    out.gid = d.u32()
    out.nlink = d.u32()
    d.u8()                             # anchored (bool)

    if f.struct_v >= 4:
        d.skip(8)                      # dir_layout

    out.layout = decode_file_layout(d)

    out.size = d.u64()
    d.u32()                            # truncate_seq
    d.u64()                            # truncate_size
    d.u64()                            # truncate_from
    if f.struct_v >= 5:
        d.u32()                        # truncate_pending
    out.mtime_sec = d.u32()
    out.mtime_nsec = d.u32()

    d.finish(f)                        # skip everything after mtime
    return out


def _frag_child(enc: int, nbits: int, i: int) -> int:
    """frag_t child: _enc = (bits << 24) | value."""
    bits = (enc >> 24) + nbits
    value = (((enc & 0x00FFFFFF) << nbits) | i) & 0x00FFFFFF
    return (bits << 24) | value


def decode_fragtree(d: Denc) -> "tuple[list[int], bool]":
    """Decode a fragtree_t (unframed compact_map<frag_t,int32_t>) and resolve
    it to its LEAF fragments. Empty split map -> the single leaf 0. Returns
    (leaves, truncated); an implausible split count raises DecodeError."""
    nsplit = d.u32()
    if nsplit > MAX_FRAGS:
        raise DecodeError("implausible fragtree split count %d" % nsplit)
    splits = {}
    for _ in range(nsplit):
        enc = d.u32()
        nway = d.u32()
        splits[enc] = nway

    leaves = []
    truncated = False
    stack = [0]
    while stack:
        f = stack.pop()
        nb = splits.get(f, 0)
        if nb <= 0:                    # leaf
            if len(leaves) < MAX_FRAGS:
                leaves.append(f)
            else:
                truncated = True
        else:
            nb = min(nb, 8)            # cap fan-out at 2^8
            for c in range(1 << nb):
                if len(stack) < MAX_FRAGS:
                    stack.append(_frag_child(f, nb, c))
                else:
                    truncated = True
    return leaves, truncated


def decode_xattrs(d: Denc) -> "tuple[dict[bytes, bytes], bool]":
    """Decode an inode xattr map (u32 count + (name, bufferptr value) pairs).
    Returns ({name: value}, truncated) capped at MAX_XATTRS."""
    n = d.u32()
    out = {}
    truncated = False
    for _ in range(n):
        name = d.str()
        val = d.str()
        if len(out) < MAX_XATTRS:
            out[name] = val
        else:
            truncated = True
    return out, truncated


def _decode_primary_body(d: Denc, out: Dentry) -> None:
    """InodeStore decode_bare prefix: framed inode; symlink target when the
    inode is a symlink; fragtree; xattr map. Trailing fields (snap_blob,
    old_inodes, ...) are the caller's frame-skip."""
    out.kind = "primary"
    out.inode = decode_inode(d)
    if mode_is_link(out.inode.mode):
        out.symlink = d.str()
    out.frags, out.frags_truncated = decode_fragtree(d)
    out.xattrs, out.xattrs_truncated = decode_xattrs(d)


def decode_dentry(buf: bytes) -> Dentry:
    """Decode a whole `<name>_head` directory-entry omap value: u64 snapid,
    u8 type marker, then a remote ('L'/'l') or primary ('i' wrapped /
    'I' bare InodeStore) body. Raises DecodeError on anything else."""
    d = Denc(buf)
    out = Dentry()

    d.u64()                            # snapid_t `first`
    marker = d.u8()

    if marker in (ord("L"), ord("l")):
        out.kind = "remote"
        out.remote_ino = d.u64()
        out.remote_d_type = d.u8()
        return out

    if marker == ord("i"):
        wrap = d.start()               # dentry wrapper frame
        if wrap.struct_v >= 2:
            d.str()                    # alternate_name (discard)
        store = d.start()              # InodeStore frame
        _decode_primary_body(d, out)
        d.finish(store)
        d.finish(wrap)
        return out

    if marker == ord("I"):             # InodeStore stored bare
        _decode_primary_body(d, out)
        return out

    raise DecodeError("unknown dentry type marker 0x%02x" % marker)


# ---------------------------------------------------------------------------
# Namespace walker (port of the xrdceph_cephfs_to_striper.cpp walk) + the
# SnapServer table probe. RADOS access is abstracted behind `omap_reader` so
# the walker unit-tests with an in-memory dict and runs live via python-rados.
# ---------------------------------------------------------------------------

@dataclass
class WalkStats:
    """Counters the walker accumulates for the classification report."""
    snap_dentries: int = 0             # non-_head omap keys => snapshots exist
    undecodable: int = 0               # dentry values decode_dentry refused


@dataclass
class WalkEntry:
    """One namespace entry the walker yielded."""
    path: str = ""
    kind: str = "file"                 # file|dir|symlink|remote|special
    dentry: Dentry = field(default_factory=Dentry)
    undecodable: bool = False


def frag_oid(ino: int, frag: int) -> str:
    """Metadata-pool object holding a directory fragment's dentry omap."""
    return "%x.%08x" % (ino, frag)


def snap_dentry(key: bytes) -> bool:
    """True for a snapshotted dentry key: CephFS keys are `<name>_<snapid>`,
    so a non-`_head` key whose final '_'-segment is hex marks a snapshot."""
    us = key.rfind(b"_")
    if us < 0 or us + 1 >= len(key):
        return False
    suffix = key[us + 1:]
    if suffix == b"head":
        return False
    try:
        int(suffix, 16)
    except ValueError:
        return False
    return True


def _classify(dn: Dentry) -> str:
    if dn.kind == "remote":
        return "remote"
    if mode_is_dir(dn.inode.mode):
        return "dir"
    if mode_is_link(dn.inode.mode):
        return "symlink"
    if mode_is_reg(dn.inode.mode):
        return "file"
    return "special"


def walk_namespace(omap_reader, stats: WalkStats, root_ino: int = ROOT_INO):
    """Depth-first walk of a CephFS namespace from its metadata-pool omaps.

    `omap_reader(oid: str, start_after: bytes) -> (list[(key, value)], more)`
    pages one fragment object's omap. Yields WalkEntry for every `_head`
    dentry (dirs are yielded before their children); undecodable values are
    yielded with undecodable=True (and counted) so callers can report them.
    """
    stack = [(root_ino, [0], "")]
    while stack:
        dirino, frags, path = stack.pop()
        for frag in frags:
            oid = frag_oid(dirino, frag)
            start = b""
            more = True
            while more:
                entries, more = omap_reader(oid, start)
                if not entries:
                    break
                for key, val in entries:
                    start = key
                    if not key.endswith(b"_head"):
                        if snap_dentry(key):
                            stats.snap_dentries += 1
                        continue
                    name = key[:-5].decode("utf-8", "surrogateescape")
                    child = path + "/" + name
                    try:
                        dn = decode_dentry(bytes(val))
                    except DecodeError:
                        stats.undecodable += 1
                        yield WalkEntry(path=child, undecodable=True)
                        continue
                    kind = _classify(dn)
                    yield WalkEntry(path=child, kind=kind, dentry=dn)
                    if kind == "dir":
                        stack.append((dn.inode.ino, dn.frags or [0], child))


def snaptable_last_snap(buf: bytes) -> int:
    """Decode the SnapServer table (`mds_snaptable` object) just enough to
    read last_snap: [u64 MDSTable version][frame][u64 last_snap ...]. A value
    >= 2 means CephFS snapshots have been created. Returns 0 on any decode
    failure (probe is best-effort)."""
    try:
        d = Denc(buf)
        d.u64()                        # MDSTable version
        d.start()
        return d.u64()
    except DecodeError:
        return 0
