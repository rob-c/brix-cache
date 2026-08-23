"""Phase-96 Wave B — `brixcvmfs repo transaction/abort/publish` (S4–S7).

Drives the standalone repotool through full publish transactions against a
freshly minted repository and verifies the on-disk results independently in
Python (manifest parse, zlib-inflated catalogs via sqlite3, CAS sha1 checks):

  S4  transaction lifecycle: two publishes, crash-safety re-run, lock refusal,
      corrupted-root refusal (fail-closed).
  S5  incremental catalogs: touching one nested subtree rewrites only that
      catalog chain; upper-tree symlinks are recorded, never followed.
  S6  .cvmfsdirtab: split to NESTED_MOUNT, dissolve back, malformed/unsafe
      pattern refusals (line-numbered).
  S7  chunking: split + byte-exact reassembly, floor refusal, per-chunk CAS
      verifiability.
"""

from __future__ import annotations

import hashlib
import os
import sqlite3
import subprocess
import sys
import zlib
from pathlib import Path

from cmdscripts.compile_run import REPO_ROOT
from cmdscripts.cvmfs_repo_cli import _build_repotool

sys.path.insert(0, str(REPO_ROOT / "tests" / "cvmfs"))
from repo_forge import md5path  # noqa: E402

FQRN = "txn.brix.io"

FLAG_DIR = 1
FLAG_DIR_NESTED_MOUNT = 2
FLAG_FILE = 4
FLAG_LINK = 8
FLAG_FILE_CHUNK = 64


# ---- verification helpers (independent of the C read stack) ----------------

def parse_manifest(repo: Path) -> dict[str, str]:
    fields: dict[str, str] = {}
    for line in (repo / ".cvmfspublished").read_bytes().split(b"\n"):
        if line == b"--":
            break
        if line:
            fields[chr(line[0])] = line[1:].decode()
    return fields


def cas_path(repo: Path, hex_: str, suffix: str = "") -> Path:
    return repo / "data" / hex_[:2] / (hex_[2:] + suffix)


def open_catalog(repo: Path, hex_: str, base: Path) -> sqlite3.Connection:
    plain = zlib.decompress(cas_path(repo, hex_, "C").read_bytes())
    db = base / f"peek.{hex_}.db"
    db.write_bytes(plain)
    return sqlite3.connect(db)


def lookup(cat: sqlite3.Connection, path: str):
    m1, m2 = md5path(path)
    return cat.execute(
        "SELECT flags, size, symlink, hash FROM catalog"
        " WHERE md5path_1=? AND md5path_2=?", (m1, m2)).fetchone()


def nested_rows(cat: sqlite3.Connection) -> dict[str, str]:
    return {p: h for p, h in cat.execute("SELECT path, sha1 FROM nested_catalogs")}


def repotool(binary: Path, *args: str, env: dict | None = None):
    full_env = dict(os.environ)
    if env:
        full_env.update(env)
    return subprocess.run([str(binary), *args], capture_output=True, text=True,
                         env=full_env)


def _mkfs(binary: Path, repo: Path):
    return repotool(binary, "mkfs", FQRN, str(repo))


def _upper(repo: Path) -> Path:
    return repo / ".brixtxn" / "upper"


# ---- S4: transaction lifecycle ---------------------------------------------

def _record(results, section, name, condition, message=""):
    detail = f" {message}".rstrip()
    results.append((bool(condition), f"{section}:{name}{detail}"))


def _s4_create_fixture(repo):
    upper = _upper(repo)
    (upper / "docs").mkdir()
    (upper / "docs" / "guide.md").write_bytes(b"guide-v1\n")
    (upper / "hello.txt").write_bytes(b"hello world\n")
    os.symlink("hello.txt", upper / "link")
    return upper


def _s4_check_initial_commands(binary, repo, upper, results):
    second = repotool(binary, "transaction", str(repo))
    refused = all((second.returncode != 0, "in a transaction" in second.stderr))
    _record(results, "s4", "second-txn-refused", refused, second.stderr)
    crash = repotool(
        binary, "publish", str(repo), env={"BRIXCVMFS_PUBLISH_CRASH": "1"})
    _record(results, "s4", "crash-exit-66", crash.returncode == 66, crash.returncode)
    _record(results, "s4", "crash-rev-intact", parse_manifest(repo)["S"] == "1")
    _record(results, "s4", "crash-txn-survives", upper.is_dir())


def _s4_check_file_row(repo, row, results):
    valid = row is not None and row[0] == FLAG_FILE and row[1] == 12
    _record(results, "s4", "file-row", valid)
    if row is None:
        return
    stored = cas_path(repo, row[3].hex()).read_bytes()
    _record(
        results, "s4", "file-bytes",
        zlib.decompress(stored) == b"hello world\n")
    _record(
        results, "s4", "file-cas-id",
        hashlib.sha1(stored).hexdigest() == row[3].hex())


def _s4_check_first_catalog(repo, manifest, base, results):
    catalog = open_catalog(repo, manifest["C"], base)
    try:
        _s4_check_file_row(repo, lookup(catalog, "/hello.txt"), results)
        link = lookup(catalog, "/link")
        link_valid = all((
            link is not None,
            link[0] == FLAG_LINK if link is not None else False,
            link[2] == "hello.txt" if link is not None else False,
        ))
        _record(results, "s4", "link-row", link_valid)
        _record(
            results, "s4", "dir-row",
            (lookup(catalog, "/docs") or (0,))[0] == FLAG_DIR)
        revision = catalog.execute(
            "SELECT value FROM properties WHERE key='revision'").fetchone()[0]
        _record(results, "s4", "rev-prop", revision == "2")
    finally:
        catalog.close()


def _s4_first_publish(binary, repo, base, results):
    publish = repotool(binary, "publish", str(repo))
    _record(results, "s4", "publish-1", publish.returncode == 0, publish.stderr)
    manifest = parse_manifest(repo)
    _record(results, "s4", "rev-2", manifest["S"] == "2", manifest["S"])
    _s4_check_first_catalog(repo, manifest, base, results)
    return manifest


def _s4_second_publish(binary, repo, base, previous, results):
    upper = _upper(repo)
    _record(
        results, "s4", "txn-2",
        repotool(binary, "transaction", str(repo)).returncode == 0)
    (upper / "docs").mkdir()
    (upper / "docs" / "guide.md").write_bytes(b"guide-v2\n")
    (upper / ".brix.wh.hello.txt").write_bytes(b"")
    publish = repotool(binary, "publish", str(repo))
    _record(results, "s4", "publish-2", publish.returncode == 0, publish.stderr)
    manifest = parse_manifest(repo)
    _record(results, "s4", "rev-3", manifest["S"] == "3", manifest["S"])
    _s4_check_second_catalog(repo, manifest, previous, base, results)
    return manifest


def _s4_check_second_catalog(repo, manifest, previous, base, results):
    catalog = open_catalog(repo, manifest["C"], base)
    try:
        _record(
            results, "s4", "deleted-gone",
            lookup(catalog, "/hello.txt") is None)
        guide = lookup(catalog, "/docs/guide.md")
        modified = guide is not None and zlib.decompress(
            cas_path(repo, guide[3].hex()).read_bytes()) == b"guide-v2\n"
        _record(results, "s4", "modified", modified)
        prior = catalog.execute(
            "SELECT value FROM properties WHERE key='previous_revision'"
        ).fetchone()[0]
        _record(results, "s4", "prev-rev-prop", prior == previous["C"])
    finally:
        catalog.close()


def _s4_tamper_and_abort(binary, repo, manifest, results):
    info = repotool(binary, "info", str(repo))
    _record(results, "s4", "info-green", info.returncode == 0, info.stderr)
    _record(
        results, "s4", "txn-3",
        repotool(binary, "transaction", str(repo)).returncode == 0)
    (_upper(repo) / "x.txt").write_bytes(b"x\n")
    victim = cas_path(repo, manifest["C"], "C")
    original = victim.read_bytes()
    victim.write_bytes(original[:20] + bytes([original[20] ^ 0xFF]) + original[21:])
    refused = repotool(binary, "publish", str(repo))
    rejected = all((refused.returncode != 0, "verification" in refused.stderr))
    _record(results, "s4", "tamper-refused", rejected, refused.stderr)
    _record(results, "s4", "tamper-rev-intact", parse_manifest(repo)["S"] == "3")
    victim.write_bytes(original)
    _record(
        results, "s4", "abort",
        repotool(binary, "abort", str(repo)).returncode == 0)
    _record(results, "s4", "abort-clears", not (repo / ".brixtxn").exists())


def check_s4(binary: Path, base: Path, results: list) -> None:
    repo = base / "s4"
    _record(results, "s4", "mkfs", _mkfs(binary, repo).returncode == 0)
    _record(
        results, "s4", "txn-open",
        repotool(binary, "transaction", str(repo)).returncode == 0)
    upper = _s4_create_fixture(repo)
    _s4_check_initial_commands(binary, repo, upper, results)
    first = _s4_first_publish(binary, repo, base, results)
    second = _s4_second_publish(binary, repo, base, first, results)
    _s4_tamper_and_abort(binary, repo, second, results)


def _s5_create_fixture(binary, repo, dirtab, results):
    dirtab.write_text("/sub\n/other\n")
    _record(results, "s5s6", "mkfs", _mkfs(binary, repo).returncode == 0)
    _record(
        results, "s5s6", "txn",
        repotool(binary, "transaction", str(repo)).returncode == 0)
    upper = _upper(repo)
    for directory in ("sub", "other"):
        (upper / directory).mkdir()
        (upper / directory / "data.txt").write_bytes(
            f"{directory}-v1\n".encode())
    return upper


def _s5_first_publish(binary, repo, dirtab, base, results):
    publish = repotool(binary, "publish", str(repo), "--dirtab", str(dirtab))
    _record(results, "s5s6", "publish", publish.returncode == 0, publish.stderr)
    root = open_catalog(repo, parse_manifest(repo)["C"], base)
    try:
        nested = nested_rows(root)
        _record(
            results, "s5s6", "two-mounts",
            sorted(nested) == ["/other", "/sub"], nested)
        flag = (lookup(root, "/sub") or (0,))[0]
        _record(
            results, "s5s6", "mount-flag",
            flag == FLAG_DIR | FLAG_DIR_NESTED_MOUNT)
        _record(
            results, "s5s6", "content-in-child",
            lookup(root, "/sub/data.txt") is None)
    finally:
        root.close()
    child = open_catalog(repo, nested["/sub"], base)
    try:
        _record(
            results, "s5s6", "child-row",
            lookup(child, "/sub/data.txt") is not None)
    finally:
        child.close()
    return nested


def _s5_incremental(binary, repo, dirtab, base, previous, results):
    upper = _upper(repo)
    _record(
        results, "s5s6", "txn-2",
        repotool(binary, "transaction", str(repo)).returncode == 0)
    (upper / "sub").mkdir()
    (upper / "sub" / "data.txt").write_bytes(b"sub-v2\n")
    publish = repotool(binary, "publish", str(repo), "--dirtab", str(dirtab))
    _record(results, "s5s6", "publish-2", publish.returncode == 0, publish.stderr)
    root = open_catalog(repo, parse_manifest(repo)["C"], base)
    try:
        current = nested_rows(root)
        _record(
            results, "s5s6", "sub-rewritten",
            current["/sub"] != previous["/sub"])
        _record(
            results, "s5s6", "other-untouched",
            current["/other"] == previous["/other"])
    finally:
        root.close()


def _s5_symlink_publish(binary, repo, dirtab, base, results):
    upper = _upper(repo)
    _record(
        results, "s5s6", "txn-3",
        repotool(binary, "transaction", str(repo)).returncode == 0)
    outside = base / "outside"
    outside.mkdir()
    (outside / "secret.txt").write_bytes(b"outside-secret\n")
    os.symlink(outside / "secret.txt", upper / "filelink")
    os.symlink(outside, upper / "dirlink")
    publish = repotool(binary, "publish", str(repo), "--dirtab", str(dirtab))
    _record(results, "s5s6", "publish-3", publish.returncode == 0, publish.stderr)
    _s5_check_symlinks(repo, base, results)


def _s5_check_symlinks(repo, base, results):
    root = open_catalog(repo, parse_manifest(repo)["C"], base)
    try:
        for name in ("/filelink", "/dirlink"):
            row = lookup(root, name)
            valid = row is not None and row[0] == FLAG_LINK
            _record(results, "s5s6", f"symlink{name}", valid)
        _record(
            results, "s5s6", "dirlink-not-descended",
            lookup(root, "/dirlink/secret.txt") is None)
        compressed = zlib.compress(b"outside-secret\n")
        ingested = cas_path(
            repo, hashlib.sha1(compressed).hexdigest()).exists()
        _record(results, "s5s6", "target-not-ingested", not ingested)
    finally:
        root.close()


def _s6_dissolve(binary, repo, dirtab, base, results):
    dirtab.write_text("/other\n")
    _record(
        results, "s5s6", "txn-4",
        repotool(binary, "transaction", str(repo)).returncode == 0)
    (_upper(repo) / "keep.txt").write_bytes(b"keep\n")
    publish = repotool(binary, "publish", str(repo), "--dirtab", str(dirtab))
    _record(results, "s5s6", "publish-4", publish.returncode == 0, publish.stderr)
    root = open_catalog(repo, parse_manifest(repo)["C"], base)
    try:
        _s6_check_dissolved(root, repo, results)
    finally:
        root.close()


def _s6_check_dissolved(root, repo, results):
    _record(
        results, "s5s6", "dissolved-flag",
        (lookup(root, "/sub") or (0,))[0] == FLAG_DIR)
    row = lookup(root, "/sub/data.txt")
    inline = row is not None and zlib.decompress(
        cas_path(repo, row[3].hex()).read_bytes()) == b"sub-v2\n"
    _record(results, "s5s6", "dissolved-inline", inline)
    nested = nested_rows(root)
    _record(results, "s5s6", "dissolved-nested-gone", "/sub" not in nested)
    _record(results, "s5s6", "other-still-mounted", "/other" in nested)


def _s6_bad_pattern(binary, repo, upper, base, pattern, tag, results):
    bad_tab = base / f"dirtab.{tag}"
    bad_tab.write_text("# comment\n" + pattern)
    _record(
        results, "s5s6", f"txn-{tag}",
        repotool(binary, "transaction", str(repo)).returncode == 0)
    (upper / "z.txt").write_bytes(b"z\n")
    refused = repotool(
        binary, "publish", str(repo), "--dirtab", str(bad_tab))
    rejected = all((refused.returncode != 0, "dirtab line 2" in refused.stderr))
    _record(results, "s5s6", f"refused-{tag}", rejected, refused.stderr)
    _record(
        results, "s5s6", f"abort-{tag}",
        repotool(binary, "abort", str(repo)).returncode == 0)


def check_s5_s6(binary: Path, base: Path, results: list) -> None:
    repo = base / "s5"
    dirtab = base / "dirtab"
    upper = _s5_create_fixture(binary, repo, dirtab, results)
    nested = _s5_first_publish(binary, repo, dirtab, base, results)
    _s5_incremental(binary, repo, dirtab, base, nested, results)
    _s5_symlink_publish(binary, repo, dirtab, base, results)
    _s6_dissolve(binary, repo, dirtab, base, results)
    for pattern, tag in (("sub\n", "relative"), ("/a/../b\n", "dotdot")):
        _s6_bad_pattern(binary, repo, upper, base, pattern, tag, results)


def _s7_start(binary, repo, payload, results):
    _record(results, "s7", "mkfs", _mkfs(binary, repo).returncode == 0)
    _record(
        results, "s7", "txn",
        repotool(binary, "transaction", str(repo)).returncode == 0)
    (_upper(repo) / "big.bin").write_bytes(payload)
    refused = repotool(binary, "publish", str(repo), "--chunk-size", "1024")
    rejected = all((refused.returncode != 0, "floor" in refused.stderr))
    _record(results, "s7", "floor-refused", rejected, refused.stderr)
    _record(results, "s7", "floor-rev-intact", parse_manifest(repo)["S"] == "1")


def _s7_publish(binary, repo, base, payload, results):
    publish = repotool(binary, "publish", str(repo), "--chunk-size", "4096")
    _record(results, "s7", "publish", publish.returncode == 0, publish.stderr)
    catalog = open_catalog(repo, parse_manifest(repo)["C"], base)
    try:
        row = lookup(catalog, "/big.bin")
        valid = all((
            row is not None,
            row[0] == FLAG_FILE | FLAG_FILE_CHUNK if row is not None else False,
            row[1] == len(payload) if row is not None else False,
        ))
        _record(results, "s7", "chunk-flags", valid)
        md5_first, md5_second = md5path("/big.bin")
        chunks = catalog.execute(
            "SELECT offset, size, hash FROM chunks"
            " WHERE md5path_1=? AND md5path_2=? ORDER BY offset",
            (md5_first, md5_second)).fetchall()
    finally:
        catalog.close()
    _record(results, "s7", "chunk-count", len(chunks) == 3, len(chunks))
    _record(
        results, "s7", "chunk-sizes",
        [chunk[1] for chunk in chunks] == [4096, 4096, 2052])
    return chunks


def _s7_read_chunk(repo, chunk, results):
    offset, size, chunk_hash = chunk
    stored = cas_path(repo, chunk_hash.hex(), "P").read_bytes()
    identity = hashlib.sha1(stored).hexdigest()
    _record(results, "s7", f"chunk-cas-{offset}", identity == chunk_hash.hex())
    plain = zlib.decompress(stored)
    _record(results, "s7", f"chunk-len-{offset}", len(plain) == size)
    return chunk_hash.hex(), stored, plain


def _s7_reassemble(repo, chunks, payload, results):
    stored_chunks = []
    plaintext = []
    for chunk in chunks:
        hex_digest, stored, plain = _s7_read_chunk(repo, chunk, results)
        stored_chunks.append((hex_digest, stored))
        plaintext.append(plain)
    _record(results, "s7", "reassembly", b"".join(plaintext) == payload)
    return stored_chunks


def _s7_tamper(stored_chunks, results):
    first_digest, first = stored_chunks[0]
    tampered = first[:10] + bytes([first[10] ^ 0x55]) + first[11:]
    _record(
        results, "s7", "tamper-detected",
        hashlib.sha1(tampered).hexdigest() != first_digest)
    for digest, stored in stored_chunks[1:]:
        _record(
            results, "s7", f"others-intact-{digest[:8]}",
            hashlib.sha1(stored).hexdigest() == digest)


def check_s7(binary: Path, base: Path, results: list) -> None:
    repo = base / "s7"
    payload = bytes(range(256)) * 40 + b"tail"
    _s7_start(binary, repo, payload, results)
    chunks = _s7_publish(binary, repo, base, payload, results)
    stored_chunks = _s7_reassemble(repo, chunks, payload, results)
    _s7_tamper(stored_chunks, results)
def run_checks(base: Path) -> list[tuple[bool, str]]:
    binary, err = _build_repotool(base)
    if binary is None:
        return [(False, f"repotool build failed: {err}")]
    results: list[tuple[bool, str]] = []
    check_s4(binary, base, results)
    check_s5_s6(binary, base, results)
    check_s7(binary, base, results)
    return results


def entry(argv: list[str]) -> int:
    import tempfile

    del argv
    with tempfile.TemporaryDirectory(prefix="cvmfs_publish_txn.") as tmp:
        results = run_checks(Path(tmp))
    for ok, message in results:
        print(f"  {'ok  ' if ok else 'FAIL'} {message}")
    return 0 if all(ok for ok, _ in results) else 1


if __name__ == "__main__":
    from cmdscripts import main

    raise SystemExit(main(entry))
