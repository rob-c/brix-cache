"""Writer ↔ repo_forge.py agreement guard (phase-96 Wave-A exit criterion).

`repo_forge.py` (and `brix_mkrepo.c`) are the corpus fixtures whose output the
read stack was hardened against.  The phase-96 PRODUCT writers (sign.c,
object_write.c, catalog_write.c) must agree with them byte-for-byte on an
identical input — this guard pins that: the forge becomes a conformance
fixture *for the writer*, not the only writer.

Byte-identical surfaces: manifest, whitelist (deterministic PKCS#1 v1.5 over
the same body with the same key), and CAS objects (same zlib default level →
identical stored bytes → identical SHA1 identity/path).  Catalogs are SQLite
files — page bytes never match — so they are compared SEMANTICALLY: full
row-sets of every table both writers own (catalog, nested_catalogs, chunks,
properties); the C-only `statistics` table is sanity-checked separately.
"""

from __future__ import annotations

import hashlib
import os
import sqlite3
import subprocess
import sys
import zlib
from pathlib import Path

from cmdscripts.compile_run import REPO_ROOT, compile_binary, result, run

sys.path.insert(0, os.path.join(REPO_ROOT, "tests", "cvmfs"))
from repo_forge import (Chunk, Chunked, Dir, File, RepoForge, Symlink,  # noqa: E402
                        FLAG_DIR, FLAG_DIR_NESTED_MOUNT, FLAG_FILE,
                        FLAG_FILE_CHUNK, FLAG_LINK)

FQRN = "unit.brix.io"

CONFORMANCE_SOURCES = [
    "tests/cvmfs/writer_conformance.c",
    "shared/cvmfs/signature/sign.c",
    "shared/cvmfs/catalog/catalog_write.c",
    "shared/cvmfs/catalog/catalog.c",
    "shared/cvmfs/object/object_write.c",
    "shared/cvmfs/object/object.c",
    "shared/cvmfs/grammar/hash.c",
    "shared/cache/cas_store.c",
    "shared/cache/cas_pack.c",
    "shared/cvmfs/platform/platform.c",
]
CONFORMANCE_LIBS = ["-lcrypto", "-lz", "-lzstd", "-lsqlite3"]

_IFDIR, _IFREG, _IFLNK = 0o040000, 0o100000, 0o120000

# The product manifest field order (sign.c): C B R X [H] [Y] G A S N T D.
_R_CONST = "d41d8cd98f00b204e9800998ecf8427e"

CONTENT_TXT = b"hello stratum zero\n" * 8
CONTENT_RAW = bytes(range(256)) * 4
CONTENT_MD = b"# guide\nnested docs payload\n"
CONTENT_SUB = b"inside the nested catalog\n"
CHUNK_1, CHUNK_2 = b"a" * 4096, b"b" * 1500


def _tree() -> dict:
    """Fixture tree: plain file, uncompressed file with odd attrs, subdir,
    symlink, chunked file, nested-catalog mountpoint."""
    return {
        "readme.txt": File(CONTENT_TXT),
        "raw.bin": File(CONTENT_RAW, compressed=False, mode=0o600,
                        uid=12, gid=34, mtime=1700000123),
        "docs": Dir({"guide.md": File(CONTENT_MD)}),
        "link": Symlink("readme.txt"),
        "big.bin": Chunked([Chunk(CHUNK_1), Chunk(CHUNK_2)]),
        "sub": Dir({"inner.txt": File(CONTENT_SUB)}, nested=True),
    }


def _stored_hex(plain: bytes, compressed: bool = True) -> str:
    stored = zlib.compress(plain) if compressed else plain
    return hashlib.sha1(stored).hexdigest()


def _build_driver(base: Path) -> tuple[Path | None, str]:
    binary = base / "wconf"
    built = compile_binary(
        binary,
        ["-Wall", "-Wextra", "-Werror", "-I", "shared"]
        + CONFORMANCE_SOURCES + CONFORMANCE_LIBS,
        cwd=REPO_ROOT,
    )
    if built.returncode != 0:
        return None, (built.stderr or built.stdout)[-2000:]
    return binary, ""


# ---- catalog spec: the SAME tree, expressed as driver stdin lines ----------

def _row(path: str, flags: int, mode: int, size: int, mtime: int, uid: int,
         gid: int, linkcount: int, hash_hex: str = "-", symlink: str = "-") -> str:
    return "\t".join(["row", path, str(flags), str(mode), str(size), str(mtime),
                      str(uid), str(gid), str(linkcount), "0", hash_hex, symlink])


def _catalog_spec(nested_hash: str, nested_size: int) -> str:
    """The root-catalog rows for _tree(), leaving md5path/parent/hardlink
    encoding entirely to the C writer.  Node attrs mirror the forge defaults
    (mtime=1700000000, uid=0, gid=0); hashes are the shared zlib identity."""
    t = 1700000000
    lines = [
        _row("", FLAG_DIR, 0o755 | _IFDIR, 0, t, 0, 0, 1),
        _row("/readme.txt", FLAG_FILE, 0o644 | _IFREG, len(CONTENT_TXT), t, 0, 0, 1,
             _stored_hex(CONTENT_TXT)),
        _row("/raw.bin", FLAG_FILE, 0o600 | _IFREG, len(CONTENT_RAW), 1700000123,
             12, 34, 1, _stored_hex(CONTENT_RAW, compressed=False)),
        _row("/docs", FLAG_DIR, 0o755 | _IFDIR, 0, t, 0, 0, 1),
        _row("/docs/guide.md", FLAG_FILE, 0o644 | _IFREG, len(CONTENT_MD), t, 0, 0, 1,
             _stored_hex(CONTENT_MD)),
        _row("/link", FLAG_LINK, 0o777 | _IFLNK, len("readme.txt"), t, 0, 0, 1,
             "-", "readme.txt"),
        _row("/big.bin", FLAG_FILE | FLAG_FILE_CHUNK, 0o644 | _IFREG,
             len(CHUNK_1) + len(CHUNK_2), t, 0, 0, 1),
        _row("/sub", FLAG_DIR | FLAG_DIR_NESTED_MOUNT, 0o755 | _IFDIR, 0, t, 0, 0, 1),
        "\t".join(["chunk", "/big.bin", "0", str(len(CHUNK_1)), _stored_hex(CHUNK_1)]),
        "\t".join(["chunk", "/big.bin", str(len(CHUNK_1)), str(len(CHUNK_2)),
                   _stored_hex(CHUNK_2)]),
        "\t".join(["nested", "/sub", nested_hash, str(nested_size)]),
        "\t".join(["prop", "revision", "1"]),
    ]
    return "\n".join(lines) + "\n"


def _table_rows(db_path: Path, sql: str) -> list:
    db = sqlite3.connect(str(db_path))
    try:
        return sorted(db.execute(sql).fetchall())
    finally:
        db.close()


def _compare_catalogs(forge_db: Path, c_db: Path) -> list[tuple[bool, str]]:
    tables = [
        ("catalog", "SELECT md5path_1,md5path_2,parent_1,parent_2,hardlinks,hash,"
                    "size,mode,mtime,flags,name,symlink,uid,gid,xattr FROM catalog"),
        ("nested_catalogs", "SELECT path,sha1,size FROM nested_catalogs"),
        ("chunks", "SELECT md5path_1,md5path_2,offset,size,hash FROM chunks"),
        ("properties", "SELECT key,value FROM properties"),
    ]
    results = [_compare_table(forge_db, c_db, table, sql) for table, sql in tables]
    results.append(_statistics_result(c_db))
    return results


def _compare_table(forge_db, c_db, table, sql):
    forge_rows, c_rows = _table_rows(forge_db, sql), _table_rows(c_db, sql)
    if forge_rows == c_rows:
        return result(True, f"catalog table `{table}` agrees ({len(forge_rows)} rows)")
    return result(False, f"catalog table `{table}` differs: forge={forge_rows} c={c_rows}")


def _statistics_result(c_db):
    stats = dict(_table_rows(c_db, "SELECT counter,value FROM statistics"))
    expected = {"self_regular": 3, "self_dir": 2, "self_symlink": 1,
                "self_chunked": 1, "self_chunks": 2, "self_nested": 1}
    return result(all(stats.get(key) == value for key, value in expected.items()),
                  f"C-side statistics counters match the fixture tree: {stats}")


def run_checks(base: Path) -> list[tuple[bool, str]]:
    results: list[tuple[bool, str]] = []
    driver, err = _build_driver(base)
    results.append(result(driver is not None, f"conformance driver builds {err}"))
    if driver is None:
        return results

    with RepoForge(FQRN, base / "forge") as forge:
        forge.build(_tree(), base / "master.pub")
        _check_cas_objects(base, driver, forge, results)
        _check_manifest(base, driver, forge, results)
        _check_whitelist(base, driver, forge, results)
        _check_catalog(base, driver, forge, results)
        _check_malformed_inputs(base, driver, forge, results)
        _check_security_negatives(base, driver, forge, results)
    return results


def _check_cas_objects(base, driver, forge, results):
    casrepo = base / "casrepo"
    casrepo.mkdir()
    cases = [
            ("compressed content", CONTENT_TXT, "-", 1),
            ("uncompressed content", CONTENT_RAW, "-", 0),
            ("chunk (P)", CHUNK_1, "P", 1),
            ("certificate (X)", forge.cert_pem.read_bytes(), "X", 1),
    ]
    for case in cases:
        results.append(_check_cas_case(base, driver, forge, casrepo, case))


def _check_cas_case(base, driver, forge, casrepo, case):
    label, plain, suffix, compress = case
    source = base / "cas.in"
    source.write_bytes(plain)
    output = run([str(driver), "cas", str(casrepo), suffix, str(compress), str(source)])
    digest = _cas_digest(output)
    forge_object, c_object = _cas_objects(forge, casrepo, digest, suffix)
    agrees = _cas_objects_agree(forge_object, c_object)
    return result(agrees, f"CAS {label}: identity + bytes agree ({digest[:12]})")


def _cas_digest(output):
    if output.returncode != 0 or not output.stdout:
        return ""
    return output.stdout.split()[0]


def _cas_objects(forge, casrepo, digest, suffix):
    suffix_value = "" if suffix == "-" else suffix
    key = digest + suffix_value
    forge_object = Path(forge.cas[key]) if key in forge.cas else None
    c_object = casrepo / "data" / digest[:2] / (digest[2:] + suffix_value)
    return forge_object, c_object


def _cas_objects_agree(forge_object, c_object):
    if forge_object is None or not c_object.is_file():
        return False
    return c_object.read_bytes() == forge_object.read_bytes()


def _check_manifest(base, driver, forge, results):
    fields = {"C": forge.root_catalog_hash, "B": str(forge.root_catalog_size),
                  "R": _R_CONST, "X": forge.cert_hash, "G": "yes", "A": "no",
                  "S": "1", "N": FQRN, "T": "1700000000", "D": "240"}
    forge.rewrite_manifest(fields)
    c_manifest = base / "manifest.c-writer"
    rc = run([str(driver), "manifest", str(forge.cert_key), str(c_manifest),
                  forge.root_catalog_hash, str(forge.root_catalog_size),
                  forge.cert_hash, "1", FQRN, "1700000000", "240"])
    agrees = rc.returncode == 0
    agrees = agrees and c_manifest.read_bytes() == forge.artifact_path("manifest").read_bytes()
    results.append(result(agrees, "manifest writers agree byte-for-byte"))


def _check_whitelist(base, driver, forge, results):
    c_whitelist = base / "whitelist.c-writer"
    rc = run([str(driver), "whitelist", str(forge.master_key), str(c_whitelist),
                  forge.whitelist_created, forge.whitelist_expiry, FQRN,
                  forge.fingerprint])
    agrees = rc.returncode == 0
    agrees = agrees and c_whitelist.read_bytes() == forge.artifact_path("whitelist").read_bytes()
    results.append(result(agrees, "whitelist writers agree byte-for-byte"))


def _check_catalog(base, driver, forge, results):
    forge_db = base / "forge_root.db"
    forge_db.write_bytes(zlib.decompress(
            Path(forge.cas[forge.root_catalog_hash + "C"]).read_bytes()))
    nested = _table_rows(forge_db, "SELECT path,sha1,size FROM nested_catalogs")
    c_db = base / "c_root.db"
    catalog = subprocess.run(
        [str(driver), "catalog", str(c_db)],
        input=_catalog_spec(nested[0][1], nested[0][2]).encode(),
        capture_output=True)
    results.append(result(catalog.returncode == 0,
                          f"C catalog accepts spec: {catalog.stderr.decode()[-200:]}"))
    if catalog.returncode == 0:
        results.extend(_compare_catalogs(forge_db, c_db))


def _check_malformed_inputs(base, driver, forge, results):
    bad = run([str(driver), "manifest", str(forge.cert_key), str(base / "x"),
                   "nothex", "1", forge.cert_hash, "1", FQRN, "0", "240"])
    results.append(result(bad.returncode != 0, "malformed hash argument is refused"))
    badcat = subprocess.run([str(driver), "catalog", str(base / "bad.db")],
                                input=b"row\tonly-two-fields\n", capture_output=True)
    results.append(result(badcat.returncode != 0 and b"bad spec line" in badcat.stderr,
                          "malformed catalog spec aborts catalog"))


def _check_security_negatives(base, driver, forge, results):
    wrongkey = base / "manifest.wrongkey"
    rc = run([str(driver), "manifest", str(forge.master_key), str(wrongkey),
                  forge.root_catalog_hash, str(forge.root_catalog_size),
                  forge.cert_hash, "1", FQRN, "1700000000", "240"])
    differs = rc.returncode == 0
    differs = differs and wrongkey.read_bytes() != forge.artifact_path("manifest").read_bytes()
    results.append(result(differs, "wrong signing key creates a different manifest"))
    drift = base / "manifest.drift"
    rc = run([str(driver), "manifest", str(forge.cert_key), str(drift),
                  forge.root_catalog_hash, str(forge.root_catalog_size),
                  forge.cert_hash, "1", FQRN, "1700000001", "240"])
    differs = rc.returncode == 0
    differs = differs and drift.read_bytes() != forge.artifact_path("manifest").read_bytes()
    results.append(result(differs, "one-field drift creates a different manifest"))


def entry(argv: list[str]) -> int:
    import tempfile

    del argv
    with tempfile.TemporaryDirectory(prefix="cvmfs_writer_conf.") as tmp:
        results = run_checks(Path(tmp))
    _print_results(results)
    return 0 if all(ok for ok, _ in results) else 1


def _print_results(results):
    for passed, message in results:
        label = "ok  " if passed else "FAIL"
        print(f"  {label} {message}")


if __name__ == "__main__":
    from cmdscripts import main

    raise SystemExit(main(entry))
