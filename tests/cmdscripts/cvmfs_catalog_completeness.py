"""Phase-96 Wave C — catalog completeness + `brixcvmfs repo fsck` (S8).

Drives the standalone repotool and verifies, independently in Python (sqlite3
over zlib-inflated CAS catalogs), the S8 fidelity surface:

  hardlinks   same nonzero group + hardlinks column == (group<<32)|linkcount
  xattrs      user.* BLOBs round-trip (version/keys/values), symlinks skip,
              oversized set refused fail-closed (when the FS can stage one)
  properties  schema / schema_revision / last_modified / revision on EVERY
              catalog (root and nested), previous_revision root-only
  counters    subtree_* == Σ direct children (self_* + subtree_*)
  markers     a .cvmfscatalog file births a nested catalog; whiting it out
              dissolves the mount back into the parent
  fsck        green on a healthy repo; counter drift and malformed xattr
              BLOBs in a re-stored catalog are reported (security-negative)
"""

from __future__ import annotations

import hashlib
import os
import sqlite3
import zlib
from pathlib import Path

from cmdscripts.cvmfs_publish_txn import (
    FLAG_DIR, FLAG_DIR_NESTED_MOUNT, FLAG_FILE, FLAG_LINK, FLAG_FILE_CHUNK,
    _build_repotool, _mkfs, _upper, cas_path, lookup, nested_rows,
    open_catalog, parse_manifest, repotool,
)


# ---- verification helpers ---------------------------------------------------

def unpack_xattrs(blob: bytes) -> dict[str, bytes]:
    """Decode the packed BLOB (u8 version, u8 count, then per entry
    u8 key_len, u16le value_len, key, value)."""
    assert blob[0] == 1, f"xattr BLOB version {blob[0]}"
    out: dict[str, bytes] = {}
    off = 2
    for _ in range(blob[1]):
        klen = blob[off]
        vlen = blob[off + 1] | (blob[off + 2] << 8)
        off += 3
        key = blob[off:off + klen].decode()
        off += klen
        out[key] = blob[off:off + vlen]
        off += vlen
    assert off == len(blob), "trailing bytes in xattr BLOB"
    return out


def row_extra(cat: sqlite3.Connection, path: str):
    """(hardlinks, xattr) columns of a row."""
    from repo_forge import md5path
    m1, m2 = md5path(path)
    return cat.execute(
        "SELECT hardlinks, xattr FROM catalog"
        " WHERE md5path_1=? AND md5path_2=?", (m1, m2)).fetchone()


def props(cat: sqlite3.Connection) -> dict[str, str]:
    return dict(cat.execute("SELECT key, value FROM properties"))


def stats(cat: sqlite3.Connection) -> dict[str, int]:
    return dict(cat.execute("SELECT counter, value FROM statistics"))


def try_setxattr(path, name: str, value: bytes) -> bool:
    try:
        os.setxattr(path, name, value)
        return True
    except OSError:
        return False


def restore_catalog(repo: Path, hex_: str, mutate) -> str:
    """Inflate catalog `hex_`, run `mutate(sqlite3.Connection)`, re-store the
    result under its OWN stored-bytes sha1 and return the new hex."""
    plain = zlib.decompress(cas_path(repo, hex_, "C").read_bytes())
    tmp = repo / ".tamper.db"
    tmp.write_bytes(plain)
    db = sqlite3.connect(tmp)
    mutate(db)
    db.commit()
    db.close()
    stored = zlib.compress(tmp.read_bytes())
    tmp.unlink()
    new_hex = hashlib.sha1(stored).hexdigest()
    out = cas_path(repo, new_hex, "C")
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_bytes(stored)
    return new_hex


def patch_manifest_root(repo: Path, old_hex: str, new_hex: str) -> bytes:
    """Point the manifest C line at `new_hex` (signature left stale — fsck is
    reader-only and must still catch the drift). Returns the original bytes."""
    mf = repo / ".cvmfspublished"
    original = mf.read_bytes()
    patched = original.replace(b"C" + old_hex.encode() + b"\n",
                               b"C" + new_hex.encode() + b"\n", 1)
    assert patched != original, "manifest C line not found"
    mf.write_bytes(patched)
    return original


# ---- hardlinks + xattrs + properties ---------------------------------------

def check_identity(binary: Path, base: Path, results: list) -> None:
    repo = base / "s8a"
    ck = lambda name, ok, msg="": results.append((bool(ok), f"s8a:{name} {msg}".rstrip()))

    ck("mkfs", _mkfs(binary, repo).returncode == 0)
    mk_props = props(open_catalog(repo, parse_manifest(repo)["C"], base))
    ck("mkfs-props", mk_props.get("schema") == "2.5"
       and mk_props.get("schema_revision") == "2"
       and "last_modified" in mk_props, str(mk_props))

    ck("txn", repotool(binary, "transaction", str(repo)).returncode == 0)
    up = _upper(repo)
    (up / "a.txt").write_bytes(b"hardlinked payload\n")
    os.link(up / "a.txt", up / "b.txt")
    (up / "solo.txt").write_bytes(b"solo\n")
    (up / "xd").mkdir()
    (up / "xd" / "inner.txt").write_bytes(b"inner\n")
    os.symlink("solo.txt", up / "ln")
    xattr_ok = (try_setxattr(up / "a.txt", "user.k1", b"v1")
                and try_setxattr(up / "xd", "user.tag", b"blue"))

    pub = repotool(binary, "publish", str(repo))
    ck("publish", pub.returncode == 0, pub.stderr)
    man = parse_manifest(repo)
    cat = open_catalog(repo, man["C"], base)

    hl_a, x_a = row_extra(cat, "/a.txt")
    hl_b, x_b = row_extra(cat, "/b.txt")
    hl_solo, _ = row_extra(cat, "/solo.txt")
    group = hl_a >> 32
    ck("hl-group-nonzero", group != 0, str(hl_a))
    ck("hl-encoding", hl_a == (group << 32) | 2, str(hl_a))
    ck("hl-pair-same", hl_a == hl_b, f"{hl_a} vs {hl_b}")
    ck("hl-solo", hl_solo == 1, str(hl_solo))

    if xattr_ok:
        ck("xattr-file", x_a is not None
           and unpack_xattrs(x_a).get("user.k1") == b"v1")
        ck("xattr-hl-shared", x_b is not None
           and unpack_xattrs(x_b).get("user.k1") == b"v1")
        _, x_dir = row_extra(cat, "/xd")
        ck("xattr-dir", x_dir is not None
           and unpack_xattrs(x_dir).get("user.tag") == b"blue")
    else:
        ck("xattr-file", True, "skipped (fs lacks user.* xattrs)")
    _, x_ln = row_extra(cat, "/ln")
    ck("xattr-symlink-none", x_ln is None)
    ck("symlink-row", (lookup(cat, "/ln") or (0,))[0] == FLAG_LINK)

    p = props(cat)
    ck("props", p.get("schema") == "2.5" and p.get("schema_revision") == "2"
       and p.get("revision") == "2" and "last_modified" in p
       and "previous_revision" in p, str(p))
    st = stats(cat)
    ck("self-counters", st.get("self_regular") == 4 and st.get("self_dir") == 1
       and st.get("self_symlink") == 1, str(st))
    if xattr_ok:
        ck("self-xattr", st.get("self_xattr") == 3, str(st.get("self_xattr")))
    cat.close()

    fsck = repotool(binary, "fsck", str(repo))
    ck("fsck-clean", fsck.returncode == 0 and "fsck clean" in fsck.stdout,
       fsck.stderr)

    # security: an oversized xattr must fail the publish, never be dropped
    ck("txn-2", repotool(binary, "transaction", str(repo)).returncode == 0)
    (up / "big.txt").write_bytes(b"big\n")
    if try_setxattr(up / "big.txt", "user.big", b"A" * 70000):
        bad = repotool(binary, "publish", str(repo))
        ck("oversized-refused", bad.returncode != 0 and "xattr" in bad.stderr,
           bad.stderr)
        ck("oversized-rev-intact", parse_manifest(repo)["S"] == "2")
    else:
        ck("oversized-refused", True, "skipped (fs refuses >64KiB xattr)")
    ck("abort", repotool(binary, "abort", str(repo)).returncode == 0)


# ---- subtree counters + markers + fsck negatives ---------------------------

def check_counters_markers(binary: Path, base: Path, results: list) -> None:
    repo = base / "s8b"
    ck = lambda name, ok, msg="": results.append((bool(ok), f"s8b:{name} {msg}".rstrip()))
    dirtab = base / "dirtab8"
    dirtab.write_text("/nest\n")

    ck("mkfs", _mkfs(binary, repo).returncode == 0)
    ck("txn", repotool(binary, "transaction", str(repo)).returncode == 0)
    up = _upper(repo)
    (up / "nest").mkdir()
    (up / "nest" / "one.txt").write_bytes(b"one\n")
    (up / "nest" / "big.bin").write_bytes(bytes(range(256)) * 40)   # 10240 → 3 chunks
    (up / "plain").mkdir()
    (up / "plain" / "two.txt").write_bytes(b"two\n")
    pub = repotool(binary, "publish", str(repo), "--dirtab", str(dirtab),
                   "--chunk-size", "4096")
    ck("publish", pub.returncode == 0, pub.stderr)

    man = parse_manifest(repo)
    root = open_catalog(repo, man["C"], base)
    nested = nested_rows(root)
    ck("nest-mounted", "/nest" in nested, str(nested))
    child = open_catalog(repo, nested["/nest"], base)
    cp = props(child)
    ck("child-props", cp.get("schema") == "2.5" and cp.get("schema_revision") == "2"
       and cp.get("revision") == "2" and "last_modified" in cp
       and "previous_revision" not in cp, str(cp))
    cst, rst = stats(child), stats(root)
    ck("child-self", cst.get("self_regular") == 1 and cst.get("self_chunked") == 1
       and cst.get("self_chunks") == 3 and cst.get("self_dir") == 1, str(cst))
    for name in ("regular", "chunked", "chunks", "dir", "symlink", "nested",
                 "file_size", "chunked_size", "xattr"):
        ck(f"subtree-{name}",
           rst.get(f"subtree_{name}")
           == cst.get(f"self_{name}", 0) + cst.get(f"subtree_{name}", 0),
           f"root {rst.get('subtree_' + name)} vs child "
           f"{cst.get('self_' + name, 0)}+{cst.get('subtree_' + name, 0)}")
    child.close()
    root.close()
    ck("fsck-1", repotool(binary, "fsck", str(repo)).returncode == 0)

    # marker birth: a .cvmfscatalog file nests its dir without any dirtab
    ck("txn-2", repotool(binary, "transaction", str(repo)).returncode == 0)
    (up / "m1").mkdir()
    (up / "m1" / ".cvmfscatalog").write_bytes(b"")
    (up / "m1" / "blob.txt").write_bytes(b"marker-nested\n")
    pub2 = repotool(binary, "publish", str(repo))
    ck("publish-2", pub2.returncode == 0, pub2.stderr)
    root2 = open_catalog(repo, parse_manifest(repo)["C"], base)
    nested2 = nested_rows(root2)
    ck("marker-born", "/m1" in nested2 and "/nest" in nested2, str(nested2))
    ck("marker-flag", (lookup(root2, "/m1") or (0,))[0]
       == FLAG_DIR | FLAG_DIR_NESTED_MOUNT)
    m1 = open_catalog(repo, nested2["/m1"], base)
    ck("marker-file-in-child",
       (lookup(m1, "/m1/.cvmfscatalog") or (0,))[0] == FLAG_FILE
       and (lookup(m1, "/m1/blob.txt") or (0,))[0] == FLAG_FILE)
    m1.close()
    root2.close()
    ck("fsck-2", repotool(binary, "fsck", str(repo)).returncode == 0)

    # marker whiteout: dissolve back into the parent
    ck("txn-3", repotool(binary, "transaction", str(repo)).returncode == 0)
    (up / "m1").mkdir()
    (up / "m1" / ".brix.wh..cvmfscatalog").write_bytes(b"")
    pub3 = repotool(binary, "publish", str(repo))
    ck("publish-3", pub3.returncode == 0, pub3.stderr)
    root3 = open_catalog(repo, parse_manifest(repo)["C"], base)
    ck("dissolved", "/m1" not in nested_rows(root3)
       and (lookup(root3, "/m1") or (0,))[0] == FLAG_DIR)
    ck("dissolved-inline", (lookup(root3, "/m1/blob.txt") or (0,))[0] == FLAG_FILE)
    ck("marker-row-gone", lookup(root3, "/m1/.cvmfscatalog") is None)
    root3.close()
    fsck3 = repotool(binary, "fsck", str(repo))
    ck("fsck-3", fsck3.returncode == 0, fsck3.stderr)

    # error: counter drift in a re-stored root catalog is reported
    man3 = parse_manifest(repo)
    drift_hex = restore_catalog(repo, man3["C"], lambda db: db.execute(
        "UPDATE statistics SET value = value + 5 WHERE counter='self_regular'"))
    original = patch_manifest_root(repo, man3["C"], drift_hex)
    drift = repotool(binary, "fsck", str(repo))
    ck("drift-detected", drift.returncode != 0 and "counter drift" in drift.stderr
       and "self_regular" in drift.stderr, drift.stderr)
    (repo / ".cvmfspublished").write_bytes(original)

    # security: a malformed xattr BLOB in a re-stored catalog is flagged
    def bad_xattr(db: sqlite3.Connection) -> None:
        from repo_forge import md5path
        m1_, m2_ = md5path("/plain/two.txt")
        db.execute("UPDATE catalog SET xattr=? WHERE md5path_1=? AND md5path_2=?",
                   (b"\x01\x02\x05", m1_, m2_))   # count 2, truncated

    bad_hex = restore_catalog(repo, man3["C"], bad_xattr)
    original = patch_manifest_root(repo, man3["C"], bad_hex)
    bad = repotool(binary, "fsck", str(repo))
    ck("malformed-xattr-flagged", bad.returncode != 0
       and "malformed xattr" in bad.stderr, bad.stderr)
    (repo / ".cvmfspublished").write_bytes(original)
    ck("fsck-restored", repotool(binary, "fsck", str(repo)).returncode == 0)


def run_checks(base: Path) -> list[tuple[bool, str]]:
    binary, err = _build_repotool(base)
    if binary is None:
        return [(False, f"repotool build failed: {err}")]
    results: list[tuple[bool, str]] = []
    check_identity(binary, base, results)
    check_counters_markers(binary, base, results)
    return results


def entry(argv: list[str]) -> int:
    import tempfile

    del argv
    with tempfile.TemporaryDirectory(prefix="cvmfs_catalog_completeness.") as tmp:
        results = run_checks(Path(tmp))
    for ok, message in results:
        print(f"  {'ok  ' if ok else 'FAIL'} {message}")
    return 0 if all(ok for ok, _ in results) else 1


if __name__ == "__main__":
    from cmdscripts import main

    raise SystemExit(main(entry))
