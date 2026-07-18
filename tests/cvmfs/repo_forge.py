"""repo_forge.py — pure-Python signed CVMFS repository builder for the fuse corpus.

Replicates the on-disk formats of tests/cvmfs/brix_mkrepo.c *exactly* so that
client/bin/brixMount mounts a forged tree, and adds post-build tamper knobs for
the trust / negative-path conformance corpus. Verified against the client-side
parsers in shared/cvmfs/{signature,catalog,object,grammar}.

Format facts pinned from the parsers (see the module docstring in the design doc):
  - CAS object identity == SHA1 of the STORED bytes (compressed form for a
    compressed object); path is data/<hex[:2]>/<hex[2:]><suffix>. Suffixes:
    '' content, 'C' catalog, 'X' certificate, 'P' file chunk.
  - md5path_{1,2} = the two little-endian signed int64 halves of MD5(path),
    path repo-root-relative with a leading slash ("" for the catalog root).
  - Manifest/whitelist sign the *printed hash-line text* (the ASCII line after
    "\\n--\\n") with raw RSA-PKCS#1-v1.5 (no DigestInfo) — the client never binds
    that printed hash to the real digest of the signed body, so the hash text is
    a free-form literal (mkrepo uses "111...").
  - Fingerprint == SHA1 over the cert DER, colon-separated UPPERCASE hex; the
    manifest 'X' field is the hash of the STORED (compressed) cert object.
"""

from __future__ import annotations

import hashlib
import os
import shutil
import sqlite3
import subprocess
import tempfile
import zlib
from dataclasses import dataclass, field
from pathlib import Path

# catalog `flags` bits — mirror shared/cvmfs/catalog/catalog.h.
FLAG_DIR = 1
FLAG_DIR_NESTED_MOUNT = 2
FLAG_FILE = 4
FLAG_LINK = 8
FLAG_DIR_NESTED_ROOT = 32
FLAG_FILE_CHUNK = 64

# S_IFMT type bits OR'd into the stored `mode` (row carries the full st_mode).
_IFDIR, _IFREG, _IFLNK = 0o040000, 0o100000, 0o120000


# ---- declarative node model ------------------------------------------------

@dataclass
class File:
    content: bytes
    mode: int = 0o644
    uid: int = 0
    gid: int = 0
    mtime: int = 1700000000
    linkcount: int = 1
    compressed: bool = True


@dataclass
class Symlink:
    target: str
    mode: int = 0o777
    uid: int = 0
    gid: int = 0
    mtime: int = 1700000000


@dataclass
class Chunk:
    content: bytes
    offset: int | None = None   # None → laid out sequentially
    size: int | None = None     # None → len(content); override to forge gaps/overlaps
    compressed: bool = True


@dataclass
class Chunked:
    chunks: list                # list[Chunk] (or raw bytes, wrapped on build)
    mode: int = 0o644
    uid: int = 0
    gid: int = 0
    mtime: int = 1700000000
    linkcount: int = 1
    size: int | None = None     # None → sum/last-offset; override for a lying size


@dataclass
class Dir:
    entries: dict = field(default_factory=dict)   # name -> node (empty = empty dir)
    mode: int = 0o755
    uid: int = 0
    gid: int = 0
    mtime: int = 1700000000
    nested: bool = False        # this dir is a nested-catalog mountpoint/root


def md5path(path: str) -> tuple[int, int]:
    """The two little-endian *signed* int64 halves of MD5(path) — CVMFS
    Md5::ToIntPair, matching cvmfs_catalog_md5path()."""
    d = hashlib.md5(path.encode()).digest()
    return (int.from_bytes(d[:8], "little", signed=True),
            int.from_bytes(d[8:], "little", signed=True))


_CATALOG_DDL = (
    "CREATE TABLE catalog (md5path_1 INTEGER,md5path_2 INTEGER,parent_1 INTEGER,parent_2 INTEGER,"
    "hardlinks INTEGER,hash BLOB,size INTEGER,mode INTEGER,mtime INTEGER,flags INTEGER,name TEXT,"
    "symlink TEXT,uid INTEGER,gid INTEGER,xattr BLOB,PRIMARY KEY(md5path_1,md5path_2));"
    "CREATE TABLE nested_catalogs (path TEXT,sha1 TEXT,size INTEGER,PRIMARY KEY(path));"
    "CREATE TABLE properties (key TEXT,value TEXT,PRIMARY KEY(key));"
    "CREATE TABLE chunks (md5path_1 INTEGER,md5path_2 INTEGER,offset INTEGER,size INTEGER,hash BLOB,"
    "PRIMARY KEY(md5path_1,md5path_2,offset));"
)


class RepoForge:
    """Build a complete signed webroot for `fqrn` under `webroot`, then mutate it."""

    def __init__(self, fqrn: str, webroot: str | os.PathLike, *,
                 revision: int = 1, ttl: int = 240, timestamp: int = 1700000000,
                 manifest_hash: str | None = None, whitelist_hash: str | None = None,
                 whitelist_expiry: str = "20991231235959", properties: dict | None = None):
        self.fqrn = fqrn
        self.webroot = Path(webroot)
        self.repo_dir = self.webroot / "cvmfs" / fqrn
        self.data_dir = self.repo_dir / "data"
        self.revision = revision
        self.ttl = ttl
        self.timestamp = timestamp
        # Hash-line literal for the manifest/whitelist. None => compute the real
        # SHA1(body) so the artifact is signature-body-bound (the client now
        # recomputes+compares it). Pass an explicit string only to forge a WRONG
        # hash line for a negative test.
        self.manifest_hash = manifest_hash
        self.whitelist_hash = whitelist_hash
        self.whitelist_expiry = whitelist_expiry
        self.properties = dict(properties or {})
        # The root catalog records its own revision; the client cross-checks it
        # against the manifest 'S' to catch a rolled-back manifest (rollback/replay).
        self.properties.setdefault("revision", str(revision))
        self._work = Path(tempfile.mkdtemp(prefix="repo_forge."))
        self.master_key = self._work / "master.key"
        self.cert_key = self._work / "cert.key"
        self.cert_pem = self._work / "cert.pem"
        self.cert_der = self._work / "cert.der"
        # populated by build()
        self.fingerprint = ""
        self.cert_hash = ""
        self.root_catalog_hash = ""
        self.root_catalog_size = 0
        self.cas: dict[str, str] = {}          # "<hex><suffix>" -> absolute path
        self._sign_master = self.master_key    # keys currently used to sign wl / manifest
        self._sign_cert = self.cert_key

    # ---- key + cert material ----------------------------------------------

    @staticmethod
    def gen_key(path: str | os.PathLike) -> Path:
        subprocess.run(["openssl", "genpkey", "-algorithm", "RSA",
                        "-pkeyopt", "rsa_keygen_bits:2048", "-out", str(path)],
                       check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        return Path(path)

    @staticmethod
    def _pubkey_pem(key: str | os.PathLike) -> bytes:
        return subprocess.run(["openssl", "pkey", "-in", str(key), "-pubout"],
                              check=True, stdout=subprocess.PIPE).stdout

    def _make_cert(self) -> None:
        self.gen_key(self.master_key)
        self.gen_key(self.cert_key)
        subprocess.run(["openssl", "req", "-x509", "-new", "-key", str(self.cert_key),
                        "-days", "1", "-subj", f"/CN={self.fqrn}",
                        "-out", str(self.cert_pem)],
                       check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        der = subprocess.run(["openssl", "x509", "-in", str(self.cert_pem),
                              "-outform", "DER"], check=True, stdout=subprocess.PIPE).stdout
        self.cert_der.write_bytes(der)
        digest = hashlib.sha1(der).hexdigest().upper()
        self.fingerprint = ":".join(digest[i:i + 2] for i in range(0, len(digest), 2))

    # ---- CAS + signing primitives -----------------------------------------

    def _write_cas(self, plain: bytes, suffix: str, *, compressed: bool = True) -> str:
        stored = zlib.compress(plain) if compressed else plain
        hexd = hashlib.sha1(stored).hexdigest()
        obj = self.data_dir / hexd[:2] / (hexd[2:] + suffix)
        obj.parent.mkdir(parents=True, exist_ok=True)
        obj.write_bytes(stored)
        self.cas[hexd + suffix] = str(obj)
        return hexd

    @staticmethod
    def _rsa_sign(key: str | os.PathLike, msg: bytes) -> bytes:
        """Raw RSA-PKCS#1-v1.5 over `msg` with no DigestInfo — real CVMFS scheme,
        the exact EVP_PKEY_sign(RSA_PKCS1_PADDING, no md) path of brix_mkrepo.c."""
        return subprocess.run(["openssl", "pkeyutl", "-sign", "-inkey", str(key),
                               "-pkeyopt", "rsa_padding_mode:pkcs1"],
                              input=msg, check=True, stdout=subprocess.PIPE).stdout

    # ---- catalog serialisation --------------------------------------------

    def _catalog_bytes(self, rows: list, nested: list, chunks: list, props: dict) -> bytes:
        db_path = self._work / f"cat.{len(self.cas)}.{os.getpid()}.db"
        if db_path.exists():
            db_path.unlink()
        db = sqlite3.connect(str(db_path))
        db.executescript(_CATALOG_DDL)
        db.executemany(
            "INSERT INTO catalog (md5path_1,md5path_2,parent_1,parent_2,hardlinks,hash,"
            "size,mode,mtime,flags,name,symlink,uid,gid,xattr) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,NULL)",
            rows)
        if nested:
            db.executemany("INSERT INTO nested_catalogs (path,sha1,size) VALUES (?,?,?)", nested)
        if chunks:
            db.executemany("INSERT INTO chunks (md5path_1,md5path_2,offset,size,hash) "
                           "VALUES (?,?,?,?,?)", chunks)
        if props:
            db.executemany("INSERT INTO properties (key,value) VALUES (?,?)", list(props.items()))
        db.commit()
        db.close()
        data = db_path.read_bytes()
        db_path.unlink()
        return data

    def _dir_row(self, path: str, name: str, node: Dir, flags: int) -> tuple:
        m1, m2 = md5path(path)
        p1, p2 = md5path(_parent(path))
        return (m1, m2, p1, p2, 1, None, 0, node.mode | _IFDIR, node.mtime, flags, name, None,
                node.uid, node.gid)

    def _build_catalog(self, root_path: str, root_name: str, node: Dir, *,
                       is_nested: bool, props: dict) -> tuple[str, int]:
        """Emit every entry owned by this catalog (stopping at nested mountpoints),
        write its CAS 'C' object, and return (hash_hex, size)."""
        rows: list = []
        nested: list = []
        chunks: list = []
        root_flags = FLAG_DIR | (FLAG_DIR_NESTED_ROOT if is_nested else 0)
        rows.append(self._dir_row(root_path, root_name, node, root_flags))
        self._walk(node.entries, root_path, rows, nested, chunks)
        blob = self._catalog_bytes(rows, nested, chunks, props)
        h = self._write_cas(blob, "C")
        return h, len(blob)

    def _walk(self, entries: dict, parent_path: str, rows: list, nested: list, chunks: list) -> None:
        for name, node in entries.items():
            path = parent_path + "/" + name
            m1, m2 = md5path(path)
            p1, p2 = md5path(parent_path)
            if isinstance(node, Dir) and node.nested:
                ch, sz = self._build_catalog(path, name, node, is_nested=True, props={})
                nested.append((path, ch, sz))
                rows.append(self._dir_row(path, name, node, FLAG_DIR | FLAG_DIR_NESTED_MOUNT))
            elif isinstance(node, Dir):
                rows.append(self._dir_row(path, name, node, FLAG_DIR))
                self._walk(node.entries, path, rows, nested, chunks)
            elif isinstance(node, Symlink):
                rows.append((m1, m2, p1, p2, 1, None, len(node.target), node.mode | _IFLNK,
                             node.mtime, FLAG_LINK, name, node.target, node.uid, node.gid))
            elif isinstance(node, Chunked):
                total = self._emit_chunks(node, m1, m2, chunks)
                rows.append((m1, m2, p1, p2, node.linkcount, None, total, node.mode | _IFREG,
                             node.mtime, FLAG_FILE | FLAG_FILE_CHUNK, name, None, node.uid, node.gid))
            elif isinstance(node, File):
                h = self._write_cas(node.content, "", compressed=node.compressed)
                rows.append((m1, m2, p1, p2, node.linkcount, bytes.fromhex(h), len(node.content),
                             node.mode | _IFREG, node.mtime, FLAG_FILE, name, None, node.uid, node.gid))
            else:
                raise TypeError(f"unknown node for {path!r}: {node!r}")

    def _emit_chunks(self, node: Chunked, m1: int, m2: int, chunks: list) -> int:
        cursor, last_end = 0, 0
        for c in node.chunks:
            if isinstance(c, (bytes, bytearray)):
                c = Chunk(bytes(c))
            off = cursor if c.offset is None else c.offset
            size = len(c.content) if c.size is None else c.size
            h = self._write_cas(c.content, "P", compressed=c.compressed)
            chunks.append((m1, m2, off, size, bytes.fromhex(h)))
            cursor = off + len(c.content)
            last_end = max(last_end, off + size)
        return last_end if node.size is None else node.size

    # ---- artifact writers -------------------------------------------------

    def _manifest_fields(self) -> dict:
        return {"C": self.root_catalog_hash, "B": str(self.root_catalog_size),
                "X": self.cert_hash, "S": str(self.revision), "N": self.fqrn,
                "T": str(self.timestamp), "D": str(self.ttl)}

    def _write_manifest(self, fields: dict, *, hash_text: str | None, sign_key,
                        stale_sig: bool) -> None:
        body = "".join(f"{k}{v}\n" for k, v in fields.items()) + "--\n"
        # Stock CVMFS hashes the body up to but EXCLUDING the "--\n" separator.
        ht = hashlib.sha1(body[:-3].encode()).hexdigest() if hash_text is None else hash_text
        raw = body.encode() + ht.encode() + b"\n"
        sig = b"\x00" * 256 if stale_sig else self._rsa_sign(sign_key, ht.encode())
        (self.repo_dir / ".cvmfspublished").write_bytes(raw + sig)

    def _write_whitelist(self, *, expiry: str, fingerprints: list, repo: str,
                         hash_text: str | None, sign_key, stale_sig: bool) -> None:
        lines = [expiry, "N" + repo, *fingerprints]
        body = "".join(l + "\n" for l in lines) + "--\n"
        # Stock CVMFS hashes the body up to but EXCLUDING the "--\n" separator.
        ht = hashlib.sha1(body[:-3].encode()).hexdigest() if hash_text is None else hash_text
        raw = body.encode() + ht.encode() + b"\n"
        sig = b"\x00" * 256 if stale_sig else self._rsa_sign(sign_key, ht.encode())
        (self.repo_dir / ".cvmfswhitelist").write_bytes(raw + sig)

    # ---- top-level build --------------------------------------------------

    def build(self, tree: dict, pubkey_out: str | os.PathLike, *,
              extra_master_pub: bytes = b"") -> "RepoForge":
        self.data_dir.mkdir(parents=True, exist_ok=True)
        self._make_cert()
        self.cert_hash = self._write_cas(self.cert_pem.read_bytes(), "X")

        root = Dir(entries=tree)
        self.root_catalog_hash, self.root_catalog_size = self._build_catalog(
            "", "", root, is_nested=False, props=self.properties)

        Path(pubkey_out).write_bytes(self._pubkey_pem(self.master_key) + extra_master_pub)

        self._write_whitelist(expiry=self.whitelist_expiry, fingerprints=[self.fingerprint],
                              repo=self.fqrn, hash_text=self.whitelist_hash,
                              sign_key=self.master_key, stale_sig=False)
        self._write_manifest(self._manifest_fields(), hash_text=self.manifest_hash,
                             sign_key=self.cert_key, stale_sig=False)
        return self

    def close(self) -> None:
        shutil.rmtree(self._work, ignore_errors=True)

    def __enter__(self) -> "RepoForge":
        return self

    def __exit__(self, *_: object) -> None:
        self.close()

    # ---- tamper knobs (post-build mutators) -------------------------------

    def artifact_path(self, which: str) -> Path:
        """'manifest'/'whitelist'/'cert', a 'data/..'-relative path, or a
        '<hex><suffix>' CAS key → an absolute path."""
        if which == "manifest":
            return self.repo_dir / ".cvmfspublished"
        if which == "whitelist":
            return self.repo_dir / ".cvmfswhitelist"
        if which == "cert":
            return Path(self.cas[self.cert_hash + "X"])
        if which in self.cas:
            return Path(self.cas[which])
        return self.repo_dir / which

    def flip_byte(self, which: str, n: int, *, mask: int = 0xFF) -> None:
        p = self.artifact_path(which)
        b = bytearray(p.read_bytes())
        b[n % len(b)] ^= mask
        p.write_bytes(bytes(b))

    def delete_cas(self, key: str) -> None:
        """Drop a CAS object by '<hex><suffix>' key or a data-relative path."""
        path = Path(self.cas.pop(key)) if key in self.cas else self.repo_dir / key
        path.unlink(missing_ok=True)

    def store_uncompressed(self, plain: bytes, suffix: str = "") -> str:
        """Re-store an object uncompressed (hash-of-plain identity); returns hex."""
        return self._write_cas(plain, suffix, compressed=False)

    def append_whitelist_fp_unsigned(self, fp: str) -> None:
        """Add a fingerprint to the whitelist BODY without re-signing — models a
        KEYLESS attacker. The original signed hash-line and master signature are
        left untouched, so this is caught ONLY if the body is signature-bound
        (SHA1(body) no longer matches the signed hash-line). This is the honest
        substitute-cert forgery: the attacker has no master key."""
        p = self.repo_dir / ".cvmfswhitelist"
        raw = p.read_bytes()
        marker = raw.index(b"\n--\n") + 1          # first byte of "--\n"
        p.write_bytes(raw[:marker] + (fp + "\n").encode() + raw[marker:])

    def rewrite_manifest(self, fields: dict, *, hash_text: str | None = None,
                         sign_key: str | os.PathLike | None = None, stale_sig: bool = False) -> None:
        # hash_text=None → _write_manifest recomputes the honest body digest.
        # Pinning the previous body's hash here would break body-binding on any
        # rewrite that changes a field; callers forging a stale/bogus hash-line
        # must pass hash_text explicitly.
        self._write_manifest(fields, hash_text=hash_text,
                             sign_key=sign_key or self.cert_key, stale_sig=stale_sig)

    def rewrite_whitelist(self, *, expiry: str | None = None, fingerprints: list | None = None,
                          repo: str | None = None, hash_text: str | None = None,
                          sign_key: str | os.PathLike | None = None, stale_sig: bool = False) -> None:
        self._write_whitelist(
            expiry=expiry if expiry is not None else self.whitelist_expiry,
            fingerprints=self.fingerprints() if fingerprints is None else fingerprints,
            repo=repo if repo is not None else self.fqrn,
            hash_text=hash_text,   # None → honest recompute (see rewrite_manifest)
            sign_key=sign_key or self.master_key, stale_sig=stale_sig)

    def fingerprints(self) -> list:
        return [self.fingerprint]

    def resign_with(self, master_key: str | os.PathLike | None = None,
                    cert_key: str | os.PathLike | None = None) -> None:
        """Re-sign whitelist (master) and/or manifest (cert) with a foreign key —
        signatures that no longer chain to the pinned pubkey/cert."""
        if master_key is not None:
            self.rewrite_whitelist(sign_key=master_key)
        if cert_key is not None:
            self.rewrite_manifest(self._manifest_fields(), sign_key=cert_key)


def _parent(path: str) -> str:
    """Repo-root-relative parent path; the root ('') is its own parent (mkrepo)."""
    if path in ("", "/"):
        return ""
    return path.rsplit("/", 1)[0]


__all__ = ["RepoForge", "File", "Symlink", "Dir", "Chunk", "Chunked", "md5path",
           "FLAG_DIR", "FLAG_DIR_NESTED_MOUNT", "FLAG_FILE", "FLAG_LINK",
           "FLAG_DIR_NESTED_ROOT", "FLAG_FILE_CHUNK"]
