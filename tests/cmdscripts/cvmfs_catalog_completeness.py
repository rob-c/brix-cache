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


def _check(results, prefix, name, ok, message=""):
    results.append((bool(ok), f"{prefix}:{name} {message}".rstrip()))


# ---- hardlinks + xattrs + properties ---------------------------------------

def check_identity(binary: Path, base: Path, results: list) -> None:
    repo = base / "s8a"
    ck = lambda name, ok, msg="": _check(results, "s8a", name, ok, msg)

    _identity_mkfs(binary, repo, base, ck)
    up, cat, xattr_ok = _identity_publish(binary, repo, base, ck)
    _identity_rows(cat, xattr_ok, ck)
    _identity_properties(cat, xattr_ok, ck)
    cat.close()
    _identity_fsck_and_oversized(binary, repo, up, ck)


def _identity_mkfs(binary, repo, base, check):
    check("mkfs", _mkfs(binary, repo).returncode == 0)
    properties = props(open_catalog(repo, parse_manifest(repo)["C"], base))
    valid = properties.get("schema") == "2.5"
    valid = valid and properties.get("schema_revision") == "2"
    valid = valid and "last_modified" in properties
    check("mkfs-props", valid, str(properties))


def _identity_publish(binary, repo, base, check):
    check("txn", repotool(binary, "transaction", str(repo)).returncode == 0)
    up = _upper(repo)
    (up / "a.txt").write_bytes(b"hardlinked payload\n")
    os.link(up / "a.txt", up / "b.txt")
    (up / "solo.txt").write_bytes(b"solo\n")
    (up / "xd").mkdir()
    (up / "xd" / "inner.txt").write_bytes(b"inner\n")
    os.symlink("solo.txt", up / "ln")
    file_xattr = try_setxattr(up / "a.txt", "user.k1", b"v1")
    dir_xattr = try_setxattr(up / "xd", "user.tag", b"blue")
    publish = repotool(binary, "publish", str(repo))
    check("publish", publish.returncode == 0, publish.stderr)
    manifest = parse_manifest(repo)
    return up, open_catalog(repo, manifest["C"], base), file_xattr and dir_xattr


def _identity_rows(cat, xattr_ok, check):
    hl_a, x_a = row_extra(cat, "/a.txt")
    hl_b, x_b = row_extra(cat, "/b.txt")
    hl_solo, _ = row_extra(cat, "/solo.txt")
    group = hl_a >> 32
    check("hl-group-nonzero", group != 0, str(hl_a))
    check("hl-encoding", hl_a == (group << 32) | 2, str(hl_a))
    check("hl-pair-same", hl_a == hl_b, f"{hl_a} vs {hl_b}")
    check("hl-solo", hl_solo == 1, str(hl_solo))
    _identity_xattrs(cat, xattr_ok, x_a, x_b, check)
    _, x_ln = row_extra(cat, "/ln")
    check("xattr-symlink-none", x_ln is None)
    check("symlink-row", (lookup(cat, "/ln") or (0,))[0] == FLAG_LINK)


def _identity_xattrs(cat, available, file_blob, link_blob, check):
    if not available:
        check("xattr-file", True, "skipped (fs lacks user.* xattrs)")
        return
    check("xattr-file", _xattr_equals(file_blob, "user.k1", b"v1"))
    check("xattr-hl-shared", _xattr_equals(link_blob, "user.k1", b"v1"))
    _, directory_blob = row_extra(cat, "/xd")
    check("xattr-dir", _xattr_equals(directory_blob, "user.tag", b"blue"))


def _xattr_equals(blob, key, expected):
    return blob is not None and unpack_xattrs(blob).get(key) == expected


def _identity_properties(cat, xattr_ok, check):
    properties = props(cat)
    valid = all((properties.get("schema") == "2.5",
                 properties.get("schema_revision") == "2",
                 properties.get("revision") == "2",
                 "last_modified" in properties,
                 "previous_revision" in properties))
    check("props", valid, str(properties))
    counters = stats(cat)
    valid = all((counters.get("self_regular") == 4,
                 counters.get("self_dir") == 1,
                 counters.get("self_symlink") == 1))
    check("self-counters", valid, str(counters))
    if xattr_ok:
        check("self-xattr", counters.get("self_xattr") == 3,
              str(counters.get("self_xattr")))


def _identity_fsck_and_oversized(binary, repo, up, check):
    fsck = repotool(binary, "fsck", str(repo))
    check("fsck-clean", fsck.returncode == 0 and "fsck clean" in fsck.stdout,
          fsck.stderr)
    check("txn-2", repotool(binary, "transaction", str(repo)).returncode == 0)
    (up / "big.txt").write_bytes(b"big\n")
    _check_oversized_xattr(binary, repo, up, check)
    check("abort", repotool(binary, "abort", str(repo)).returncode == 0)


def _check_oversized_xattr(binary, repo, upper, check):
    if not try_setxattr(upper / "big.txt", "user.big", b"A" * 70000):
        check("oversized-refused", True, "skipped (fs refuses >64KiB xattr)")
        return
    result = repotool(binary, "publish", str(repo))
    check("oversized-refused", result.returncode != 0 and "xattr" in result.stderr,
          result.stderr)
    check("oversized-rev-intact", parse_manifest(repo)["S"] == "2")


# ---- subtree counters + markers + fsck negatives ---------------------------

def check_counters_markers(binary: Path, base: Path, results: list) -> None:
    repo = base / "s8b"
    ck = lambda name, ok, msg="": _check(results, "s8b", name, ok, msg)
    upper = _counter_initial_publish(binary, base, repo, ck)
    _counter_verify_nested(binary, base, repo, ck)
    _marker_birth(binary, base, repo, upper, ck)
    _marker_dissolve(binary, base, repo, upper, ck)
    _fsck_negatives(binary, base, repo, ck)


def _counter_initial_publish(binary, base, repo, check):
    dirtab = base / "dirtab8"
    dirtab.write_text("/nest\n")

    check("mkfs", _mkfs(binary, repo).returncode == 0)
    check("txn", repotool(binary, "transaction", str(repo)).returncode == 0)
    up = _upper(repo)
    (up / "nest").mkdir()
    (up / "nest" / "one.txt").write_bytes(b"one\n")
    (up / "nest" / "big.bin").write_bytes(bytes(range(256)) * 40)   # 10240 → 3 chunks
    (up / "plain").mkdir()
    (up / "plain" / "two.txt").write_bytes(b"two\n")
    pub = repotool(binary, "publish", str(repo), "--dirtab", str(dirtab),
                   "--chunk-size", "4096")
    check("publish", pub.returncode == 0, pub.stderr)
    return up


def _counter_verify_nested(binary, base, repo, check):
    man = parse_manifest(repo)
    root = open_catalog(repo, man["C"], base)
    nested = nested_rows(root)
    check("nest-mounted", "/nest" in nested, str(nested))
    child = open_catalog(repo, nested["/nest"], base)
    properties = props(child)
    check("child-props", _valid_child_properties(properties), str(properties))
    cst, rst = stats(child), stats(root)
    check("child-self", _valid_child_stats(cst), str(cst))
    for name in ("regular", "chunked", "chunks", "dir", "symlink", "nested",
                 "file_size", "chunked_size", "xattr"):
        _check_subtree_counter(check, name, rst, cst)
    child.close()
    root.close()
    check("fsck-1", repotool(binary, "fsck", str(repo)).returncode == 0)


def _valid_child_properties(properties):
    return all((properties.get("schema") == "2.5",
                properties.get("schema_revision") == "2",
                properties.get("revision") == "2",
                "last_modified" in properties,
                "previous_revision" not in properties))


def _valid_child_stats(counters):
    return all((counters.get("self_regular") == 1,
                counters.get("self_chunked") == 1,
                counters.get("self_chunks") == 3,
                counters.get("self_dir") == 1))


def _check_subtree_counter(check, name, root, child):
    actual = root.get(f"subtree_{name}")
    direct = child.get(f"self_{name}", 0)
    nested = child.get(f"subtree_{name}", 0)
    check(f"subtree-{name}", actual == direct + nested,
          f"root {actual} vs child {direct}+{nested}")


def _marker_birth(binary, base, repo, upper, check):
    check("txn-2", repotool(binary, "transaction", str(repo)).returncode == 0)
    (upper / "m1").mkdir()
    (upper / "m1" / ".cvmfscatalog").write_bytes(b"")
    (upper / "m1" / "blob.txt").write_bytes(b"marker-nested\n")
    pub2 = repotool(binary, "publish", str(repo))
    check("publish-2", pub2.returncode == 0, pub2.stderr)
    root2 = open_catalog(repo, parse_manifest(repo)["C"], base)
    nested2 = nested_rows(root2)
    check("marker-born", {"/m1", "/nest"} <= set(nested2), str(nested2))
    check("marker-flag", (lookup(root2, "/m1") or (0,))[0]
          == FLAG_DIR | FLAG_DIR_NESTED_MOUNT)
    m1 = open_catalog(repo, nested2["/m1"], base)
    marker_file = (lookup(m1, "/m1/.cvmfscatalog") or (0,))[0] == FLAG_FILE
    payload_file = (lookup(m1, "/m1/blob.txt") or (0,))[0] == FLAG_FILE
    check("marker-file-in-child", all((marker_file, payload_file)))
    m1.close()
    root2.close()
    check("fsck-2", repotool(binary, "fsck", str(repo)).returncode == 0)


def _marker_dissolve(binary, base, repo, upper, check):
    check("txn-3", repotool(binary, "transaction", str(repo)).returncode == 0)
    (upper / "m1").mkdir()
    (upper / "m1" / ".brix.wh..cvmfscatalog").write_bytes(b"")
    pub3 = repotool(binary, "publish", str(repo))
    check("publish-3", pub3.returncode == 0, pub3.stderr)
    root3 = open_catalog(repo, parse_manifest(repo)["C"], base)
    inline = (lookup(root3, "/m1") or (0,))[0] == FLAG_DIR
    check("dissolved", "/m1" not in nested_rows(root3) and inline)
    check("dissolved-inline", (lookup(root3, "/m1/blob.txt") or (0,))[0] == FLAG_FILE)
    check("marker-row-gone", lookup(root3, "/m1/.cvmfscatalog") is None)
    root3.close()
    fsck3 = repotool(binary, "fsck", str(repo))
    check("fsck-3", fsck3.returncode == 0, fsck3.stderr)


def _fsck_negatives(binary, base, repo, check):
    man3 = parse_manifest(repo)
    drift_hex = restore_catalog(repo, man3["C"], lambda db: db.execute(
        "UPDATE statistics SET value = value + 5 WHERE counter='self_regular'"))
    original = patch_manifest_root(repo, man3["C"], drift_hex)
    drift = repotool(binary, "fsck", str(repo))
    drift_found = drift.returncode != 0 and "counter drift" in drift.stderr
    check("drift-detected", drift_found and "self_regular" in drift.stderr,
          drift.stderr)
    (repo / ".cvmfspublished").write_bytes(original)
    bad_hex = restore_catalog(repo, man3["C"], _write_bad_xattr)
    original = patch_manifest_root(repo, man3["C"], bad_hex)
    bad = repotool(binary, "fsck", str(repo))
    check("malformed-xattr-flagged", bad.returncode != 0
          and "malformed xattr" in bad.stderr, bad.stderr)
    (repo / ".cvmfspublished").write_bytes(original)
    check("fsck-restored", repotool(binary, "fsck", str(repo)).returncode == 0)


def _write_bad_xattr(db: sqlite3.Connection) -> None:
    from repo_forge import md5path
    m1_, m2_ = md5path("/plain/two.txt")
    db.execute("UPDATE catalog SET xattr=? WHERE md5path_1=? AND md5path_2=?",
               (b"\x01\x02\x05", m1_, m2_))


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
