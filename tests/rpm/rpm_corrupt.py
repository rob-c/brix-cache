# tests/rpm/rpm_corrupt.py — surgical mutations of a real .rpm container, for
# the phase-104 D12.4 error and security-negative legs.
#
# WHAT: parse just enough of the rpm.org container (lead → signature header →
#       main header) to address individual index entries, then hand back a
#       mutated copy of the file bytes: an offset past `dl`, a type confusion,
#       a `count * size` wrap, an absurd `il`, a truncated body, a DIRNAMES
#       entry rewritten to a `../` traversal.
# WHY:  the reader in shared/rpm/rpmhdr.c is a clean-room parser of attacker-
#       supplied bytes. Its bounds arithmetic can only be trusted if something
#       actually drives it off the end — and fixtures built by rpmbuild never
#       will. Mutating a *real* package (rather than synthesising one) keeps
#       every other field valid, so a refusal proves the specific check fired
#       and not merely that the file looked odd.
# HOW:  the container is lead(96) + region(sig) + pad-to-8 + region(main).
#       A region is a 16-byte preamble (magic 8e ad e8 01, 4 reserved,
#       il:BE32, dl:BE32), then il × 16-byte index entries {tag,type,offset,
#       count}, then dl bytes of data. Mutations are byte-for-byte in place
#       unless named otherwise, so no offset downstream of the edit shifts.
#
# Standalone smoke test: `python3 tests/rpm/rpm_corrupt.py <some.rpm>`.
import struct
import sys
from pathlib import Path

LEAD_LEN = 96
PREAMBLE_LEN = 16
ENTRY_LEN = 16
HDR_MAGIC = b"\x8e\xad\xe8\x01"

# Tags and types we address by name (rpm.org numbering; mirrors shared/rpm/rpmhdr.h).
TAG_SIZE = 1009
TAG_DIRNAMES = 1118
TAG_DIRINDEXES = 1116
TYPE_INT32 = 4
TYPE_STRING = 6
TYPE_STRING_ARRAY = 8


class RpmShape:
    """Byte offsets of one header region inside a .rpm."""

    def __init__(self, off: int, il: int, dl: int):
        self.off = off                            # region start (preamble)
        self.il = il
        self.dl = dl
        self.index_off = off + PREAMBLE_LEN       # first index entry
        self.data_off = self.index_off + il * ENTRY_LEN
        self.end = self.data_off + dl

    def entry_off(self, i: int) -> int:
        return self.index_off + i * ENTRY_LEN


def _region(data: bytes, off: int) -> RpmShape:
    if data[off:off + 4] != HDR_MAGIC:
        raise ValueError(f"no header magic at offset {off}")
    il, dl = struct.unpack_from(">II", data, off + 8)
    return RpmShape(off, il, dl)


def shapes(data: bytes) -> tuple[RpmShape, RpmShape]:
    """Return (signature region, main region)."""
    sig = _region(data, LEAD_LEN)
    main_off = (sig.end + 7) & ~7               # regions are 8-byte aligned
    return sig, _region(data, main_off)


def entries(data: bytes, r: RpmShape) -> list[tuple[int, int, int, int]]:
    """[(tag, type, offset, count), …] for one region, index order."""
    return [struct.unpack_from(">IIII", data, r.entry_off(i)) for i in range(r.il)]


def find(data: bytes, r: RpmShape, tag: int) -> int:
    """Index of `tag` in region `r`; raises if the fixture lacks it."""
    for i, e in enumerate(entries(data, r)):
        if e[0] == tag:
            return i
    raise KeyError(f"tag {tag} not present in region at {r.off}")


def _patch_entry(data: bytes, r: RpmShape, idx: int, *, tag=None, typ=None,
                 offset=None, count=None) -> bytes:
    cur = list(struct.unpack_from(">IIII", data, r.entry_off(idx)))
    for slot, val in ((0, tag), (1, typ), (2, offset), (3, count)):
        if val is not None:
            cur[slot] = val
    out = bytearray(data)
    struct.pack_into(">IIII", out, r.entry_off(idx), *cur)
    return bytes(out)


def _patch_preamble(data: bytes, r: RpmShape, *, il=None, dl=None) -> bytes:
    out = bytearray(data)
    struct.pack_into(">II", out, r.off + 8,
                     r.il if il is None else il,
                     r.dl if dl is None else dl)
    return bytes(out)


# ---- the mutations -------------------------------------------------------
# Each takes the original file bytes and returns a mutated copy. Names match
# the D12.4 roster so a failing lane says which check did not fire.

def offset_past_dl(data: bytes, tag: int = TAG_SIZE) -> bytes:
    """Point an entry's data offset a kilobyte beyond the data region."""
    _, main = shapes(data)
    return _patch_entry(data, main, find(data, main, tag), offset=main.dl + 1024)


def offset_wraps(data: bytes, tag: int = TAG_SIZE) -> bytes:
    """Offset near 2^32 — catches `off + len` computed in 32 bits."""
    _, main = shapes(data)
    return _patch_entry(data, main, find(data, main, tag), offset=0xFFFFFFF0)


def type_confusion(data: bytes, tag: int = TAG_SIZE) -> bytes:
    """Declare an INT32 tag as STRING: the reader must not walk for a NUL."""
    _, main = shapes(data)
    return _patch_entry(data, main, find(data, main, tag), typ=TYPE_STRING)


def count_wrap(data: bytes, tag: int = TAG_SIZE) -> bytes:
    """count × sizeof(INT32) overflows 32 bits (0x40000001 × 4 == 4)."""
    _, main = shapes(data)
    return _patch_entry(data, main, find(data, main, tag), count=0x40000001)


def il_absurd(data: bytes) -> bytes:
    """il = 2^32-1: index alone would be 64 GiB. Must trip BRIX_RPM_IL_MAX."""
    _, main = shapes(data)
    return _patch_preamble(data, main, il=0xFFFFFFFF)


def dl_absurd(data: bytes) -> bytes:
    """dl = 2^32-1: must trip BRIX_RPM_DL_MAX, not a 4 GiB malloc."""
    _, main = shapes(data)
    return _patch_preamble(data, main, dl=0xFFFFFFFF)


def truncate_main_body(data: bytes) -> bytes:
    """Keep a well-formed main preamble, cut the index/data short."""
    _, main = shapes(data)
    return data[:main.data_off + max(1, main.dl // 2)]


def truncate_sig_body(data: bytes) -> bytes:
    """Cut inside the signature region — the first thing the reader loads."""
    sig, _ = shapes(data)
    return data[:sig.data_off + max(1, sig.dl // 2)]


def truncate_lead(data: bytes) -> bytes:
    return data[:LEAD_LEN // 2]


def bad_magic(data: bytes) -> bytes:
    """Valid lead, garbage where the main header magic belongs."""
    _, main = shapes(data)
    out = bytearray(data)
    out[main.off:main.off + 4] = b"\x00\x00\x00\x00"
    return bytes(out)


def traversal_dirnames(data: bytes) -> bytes:
    """
    Rewrite one DIRNAMES string to an equal-length `../` traversal.

    Equal length is the whole trick: every offset in the header stays valid,
    so the package parses cleanly and the ONLY thing wrong is the path. That
    isolates brix_rpm_path_sane() — the entry must be dropped from the XML and
    counted in `paths-sanitized`, not merely rejected along with the package.
    Signatures are never verified by brixrpm, so a patched header is fine here.
    """
    _, main = shapes(data)
    idx = find(data, main, TAG_DIRNAMES)
    _tag, _typ, off, count = struct.unpack_from(">IIII", data, main.entry_off(idx))
    base = main.data_off + off

    pos = base
    for _ in range(count):
        end = data.index(b"\x00", pos)
        n = end - pos
        if n >= 6:                       # room for "/../" + filler + "/"
            evil = b"/../" + b"a" * (n - 5) + b"/"
            assert len(evil) == n
            out = bytearray(data)
            out[pos:end] = evil
            return bytes(out)
        pos = end + 1
    raise ValueError("no DIRNAMES entry long enough to rewrite")


def dirindex_out_of_range(data: bytes) -> bytes:
    """First DIRINDEXES entry points past the end of DIRNAMES."""
    _, main = shapes(data)
    idx = find(data, main, TAG_DIRINDEXES)
    _tag, _typ, off, _count = struct.unpack_from(">IIII", data, main.entry_off(idx))
    out = bytearray(data)
    struct.pack_into(">I", out, main.data_off + off, 0xFFFF)
    return bytes(out)


NOT_AN_RPM = b"this is not an rpm, it is a text file with an .rpm suffix\n"

# name -> mutator. The lane iterates this so a new mutation is one line here.
CORRUPTIONS = {
    "offset_past_dl": offset_past_dl,
    "offset_wraps": offset_wraps,
    "type_confusion": type_confusion,
    "count_wrap": count_wrap,
    "il_absurd": il_absurd,
    "dl_absurd": dl_absurd,
    "truncate_main_body": truncate_main_body,
    "truncate_sig_body": truncate_sig_body,
    "truncate_lead": truncate_lead,
    "bad_magic": bad_magic,
    "dirindex_out_of_range": dirindex_out_of_range,
}


def write_corpus(src: Path, out_dir: Path) -> dict[str, Path]:
    """Materialise every CORRUPTIONS entry plus a non-RPM into out_dir."""
    out_dir.mkdir(parents=True, exist_ok=True)
    data = src.read_bytes()
    made = {}
    for name, fn in CORRUPTIONS.items():
        p = out_dir / f"{name}.rpm"
        p.write_bytes(fn(data))
        made[name] = p
    p = out_dir / "not_an_rpm.rpm"
    p.write_bytes(NOT_AN_RPM)
    made["not_an_rpm"] = p
    return made


if __name__ == "__main__":
    ref = Path(sys.argv[1])
    sig, main = shapes(ref.read_bytes())
    print(f"sig  il={sig.il} dl={sig.dl} data@{sig.data_off} end={sig.end}")
    print(f"main il={main.il} dl={main.dl} data@{main.data_off} end={main.end}")
    for name, path in write_corpus(ref, Path(sys.argv[2])).items():
        print(f"{name:24s} {path.stat().st_size:8d}  {path}")
