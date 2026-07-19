"""Phase-84 conformance corpus: fuse_catalog — forged-catalog namespace semantics.

Theme
-----
Mount forged, fully-signed repos (tests/cvmfs/repo_forge.py) via brixMount and
assert everything the FUSE layer derives from the SQLite catalog: lookup/getattr
truth (types, sizes, mode bits, uid/gid squash, mtime, link counts), a hostile
name corpus, deep paths, readdir completeness vs the forged spec, symlink
semantics, nested-catalog transitions (incl. tampered nested tables), and
md5path sign edge cases (paths whose MD5 halves are negative int64s).

Layout: five module-scoped mounts (mounts are the expensive resource), each a
rich repo serving one theme cluster:
  main_mnt   — getattr/lookup, names, deep paths, symlinks, md5path, stat walk
  rdir_mnt   — readdir completeness (0/1/100/1000 entries), d_type, stability
  nest_mnt   — known-good nested-catalog transitions + the pinned Wave-1
               readdir divergence
  evil_mnt   — nested catalog CAS object missing / corrupted
  craft_mnt  — hand-built root catalog: mountpoint-flag-without-row, nested row
               pointing at a nonexistent hash

Source citations
----------------
* getattr/readdir/readlink ops: client/apps/fs/brixcvmfs.c:198-262
  (st_uid = e.uid ? e.uid : getuid(); dirs st_nlink=2; readdir uses ONLY
  g_cl->root_catalog — the pinned nested-readdir divergence).
* resolve + nested descent: shared/cvmfs/client/client.c:80-134
  (longest_nested_prefix iterates strict '/'-prefixes; failed descent falls
  back to lookup in the current catalog).
* catalog schema/flags + md5path convention: shared/cvmfs/catalog/catalog.[ch].

DIVERGENCE summary (each pinned strict-xfail below):
* readdir at/below a nested-catalog mountpoint returns empty — official CVMFS
  lists children (brixcvmfs_op_readdir never descends nested catalogs).
* nonzero catalog uid/gid are surfaced verbatim — official CVMFS by default
  shows every entry owned by the mount user (docs 2.11 "Repository Contents":
  ownership is claimed by the mounting user; catalog uid/gid ignored).
"""

# PEP 563 (deferred annotations): this module uses PEP 604 `X | None` unions in
# function annotations, which stock EL9 Python 3.9 evaluates at def-time and
# rejects (TypeError) without this. See TESTING.md §2.
from __future__ import annotations

import errno
import os
import shutil
import stat as st_mod
import sqlite3
import subprocess
import sys
import tempfile
import zlib
from pathlib import Path

import pytest

# conftest chdir()s into a scratch dir — anchor imports on this file's dir.
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "cvmfs"))

from conformance_common import BRIXMOUNT, MOCK, PortBlock, fuse_mount
from lib_py.util import wait_tcp
from repo_forge import Dir, File, RepoForge, Symlink, md5path
from repo_forge import (FLAG_DIR, FLAG_DIR_NESTED_MOUNT, FLAG_FILE)

_IFDIR, _IFREG = 0o040000, 0o100000

_FUSE_READY = (os.path.exists("/dev/fuse") and shutil.which("fusermount3") is not None
               and os.path.exists(BRIXMOUNT))
pytestmark = pytest.mark.skipif(not _FUSE_READY,
                                reason="fuse mount prerequisites missing")

# --------------------------------------------------------------------------- #
# Forged trees (module constants so the stat-walk test shares the spec)
# --------------------------------------------------------------------------- #

SIZES = [0, 1, 123, 4095, 4096, 4097, 65537]

FILE_MODES = {"m644": 0o644, "m755": 0o755, "m400": 0o400, "m777": 0o777,
              "suid": 0o4755, "sgid": 0o2755, "sticky_f": 0o1644}
DIR_MODES = {"sticky_d": 0o1777, "sgid_d": 0o2755}

ALIEN_UID, ALIEN_GID = 54321, 54322

# (id, name) — content is name.encode() so each read is bound to its entry.
NAME_CORPUS = [
    ("plain", "plain.txt"),
    ("space", "with space"),
    ("spaces2", "two  spaces .txt"),
    ("hidden", ".hidden"),
    ("dotdot_prefix", "..almost-hidden"),
    ("hash", "#hash#tag"),
    ("percent", "%percent%2Fenc"),
    ("utf8", "café-münchen-π"),
    ("combining", "café-combining"),
    ("case_upper", "Case"),
    ("case_lower", "case"),
    ("tab", "tab\there"),
    ("dash", "-leading-dash"),
    ("tilde", "~tilde"),
    ("name255", "n" * 255),
]

DEEP_LEVELS = 34
LONG_TARGET = "t/" * 499 + "x"          # 999 bytes, near the 1024 dirent cap


def _neg_names(half: int, count: int) -> list:
    """Names under /m whose md5path half `half` is a NEGATIVE int64 —
    the signed high-bit edge of the md5path convention (catalog.c:16-31)."""
    out, i = [], 0
    while len(out) < count:
        nm = f"hb{half}-{i}"
        if md5path(f"/m/{nm}")[half] < 0:
            out.append(nm)
        i += 1
    return out


def _both_neg_name() -> str:
    i = 0
    while True:
        nm = f"hbb-{i}"
        m1, m2 = md5path(f"/m/{nm}")
        if m1 < 0 and m2 < 0:
            return nm
        i += 1


NEG_M1, NEG_M2, NEG_BOTH = _neg_names(0, 3), _neg_names(1, 3), _both_neg_name()


def _main_tree() -> dict:
    deep: dict = {"leaf.txt": File(b"deep leaf\n")}
    for i in reversed(range(DEEP_LEVELS)):
        deep = {f"d{i:02d}": Dir(deep)}
    return {
        "sizes": Dir({f"s{n}": File(b"x" * n) for n in SIZES}),
        "modes": Dir({**{k: File(b"mode\n", mode=m) for k, m in FILE_MODES.items()},
                      **{k: Dir({}, mode=m) for k, m in DIR_MODES.items()}}),
        "owner": Dir({"squash": File(b"squash\n", uid=0, gid=0),
                      "alien": File(b"alien\n", uid=ALIEN_UID, gid=ALIEN_GID)}),
        "times": Dir({"epoch": File(b"t\n", mtime=1234567890)}, mtime=1111111111),
        "links": Dir({"one": File(b"1\n"), "five": File(b"5\n", linkcount=5)}),
        "names": Dir({name: File(name.encode()) for _, name in NAME_CORPUS}),
        "m": Dir({nm: File(nm.encode())
                  for nm in (*NEG_M1, *NEG_M2, NEG_BOTH)}),
        "deep": Dir(deep),
        "sym": Dir({
            "target.txt": File(b"sym target\n"),
            "rel": Symlink("target.txt"),
            "abs": Symlink("/absolutely/nowhere"),
            "dang": Symlink("missing-target"),
            "realdir": Dir({"inside.txt": File(b"inside\n")}),
            "dirlink": Symlink("realdir"),
            "loopa": Symlink("loopb"),
            "loopb": Symlink("loopa"),
            "self": Symlink("self"),
            "long": Symlink(LONG_TARGET),
        }),
    }


def _rdir_tree() -> dict:
    return {
        "empty": Dir({}),
        "one": Dir({"only": File(b"only\n")}),
        "hundred": Dir({f"f{i:03d}": File(b"") for i in range(100)}),
        "thousand": Dir({f"g{i:04d}": File(b"") for i in range(1000)}),
        "mixed": Dir({"f": File(b"f\n"), "d": Dir({}), "l": Symlink("f")}),
    }


def _nest_tree() -> dict:
    return {
        "marker.txt": File(b"root level\n"),
        "n1": Dir({
            "inner.txt": File(b"one deep\n"),
            "sub": Dir({"deep.txt": File(b"below mount\n")}),
            "n2": Dir({
                "two.txt": File(b"two deep\n"),
                "d": Dir({"leaf.txt": File(b"nested leaf\n")}),
            }, nested=True),
        }, nested=True),
    }


def _evil_tree() -> dict:
    return {nm: Dir({"f": File(f"{nm} payload\n".encode())}, nested=True)
            for nm in ("gone", "corrupt", "ok")}


# --------------------------------------------------------------------------- #
# Local forge helpers (kept here — shared files are frozen for Wave-3)
# --------------------------------------------------------------------------- #

def _nested_rows(forge: RepoForge) -> dict:
    """path -> sha1 from the built root catalog's nested_catalogs table."""
    blob = zlib.decompress(
        Path(forge.cas[forge.root_catalog_hash + "C"]).read_bytes())
    with tempfile.NamedTemporaryFile(suffix=".db") as f:
        f.write(blob)
        f.flush()
        con = sqlite3.connect(f.name)
        try:
            return dict(con.execute("SELECT path, sha1 FROM nested_catalogs"))
        finally:
            con.close()


def _row(path: str, name: str, *, flags: int, mode: int, size: int = 0,
         hashhex: str | None = None, uid: int = 0, gid: int = 0) -> tuple:
    """A raw `catalog` row in repo_forge column order (root '' is its own parent)."""
    m1, m2 = md5path(path)
    parent = "" if path in ("", "/") else path.rsplit("/", 1)[0]
    p1, p2 = md5path(parent)
    return (m1, m2, p1, p2, 1, bytes.fromhex(hashhex) if hashhex else None,
            size, mode, 1700000000, flags, name, None, uid, gid)


def _install_root_catalog(forge: RepoForge, rows: list, nested: list) -> None:
    """Replace the root catalog with hand-built rows and re-sign the manifest."""
    blob = forge._catalog_bytes(rows, nested, [], {})
    forge.root_catalog_hash = forge._write_cas(blob, "C")
    forge.root_catalog_size = len(blob)
    forge.rewrite_manifest(forge._manifest_fields())


# --------------------------------------------------------------------------- #
# Fixtures: one mock + one mount per themed repo, all module-scoped
# --------------------------------------------------------------------------- #

@pytest.fixture(scope="module")
def spawn():
    procs = []

    def _spawn(argv):
        p = subprocess.Popen(argv, stdout=subprocess.DEVNULL,
                             stderr=subprocess.DEVNULL)
        procs.append(p)
        return p

    yield _spawn
    for p in reversed(procs):
        if p.poll() is None:
            p.terminate()
    for p in procs:
        try:
            p.wait(3)
        except subprocess.TimeoutExpired:
            p.kill()


@pytest.fixture(scope="module")
def ports():
    return PortBlock("fuse_catalog")           # 13320-13339 (mocks: +0..9)


def _serve(spawn, web: Path, port: int, fqrn: str) -> None:
    spawn([sys.executable, MOCK, "--port", str(port), "--repo", fqrn,
           "--webroot", str(web)])
    assert wait_tcp("127.0.0.1", port, 10), f"mock did not listen on {port}"


def _mounted_repo(spawn, ports, tmp_path_factory, fqrn, tree, mutate=None):
    """Build+serve+mount one forged repo; generator yields the mountpoint."""
    root = tmp_path_factory.mktemp(fqrn.split(".")[0])
    pub = root / "repo.pub"
    forge = RepoForge(fqrn, root / "web").build(tree, pub)
    if mutate is not None:
        mutate(forge)
    port = ports.mock()
    _serve(spawn, root / "web", port, fqrn)
    try:
        url = f"http://127.0.0.1:{port}/cvmfs/{fqrn}"
        with fuse_mount(fqrn, url, pub) as (mnt, _):
            if not os.path.ismount(str(mnt)):
                pytest.fail(f"brixMount failed to mount forged repo {fqrn}")
            yield mnt
    finally:
        forge.close()


@pytest.fixture(scope="module")
def main_mnt(spawn, ports, tmp_path_factory):
    yield from _mounted_repo(spawn, ports, tmp_path_factory,
                             "main.cat84.brix", _main_tree())


@pytest.fixture(scope="module")
def rdir_mnt(spawn, ports, tmp_path_factory):
    yield from _mounted_repo(spawn, ports, tmp_path_factory,
                             "rdir.cat84.brix", _rdir_tree())


@pytest.fixture(scope="module")
def nest_mnt(spawn, ports, tmp_path_factory):
    yield from _mounted_repo(spawn, ports, tmp_path_factory,
                             "nest.cat84.brix", _nest_tree())


@pytest.fixture(scope="module")
def evil_mnt(spawn, ports, tmp_path_factory):
    def mutate(forge):
        rows = _nested_rows(forge)
        forge.delete_cas(rows["/gone"] + "C")       # nested CAS object absent
        forge.flip_byte(rows["/corrupt"] + "C", 20)  # nested CAS hash-mismatch

    yield from _mounted_repo(spawn, ports, tmp_path_factory,
                             "evil.cat84.brix", _evil_tree(), mutate)


@pytest.fixture(scope="module")
def craft_mnt(spawn, ports, tmp_path_factory):
    def mutate(forge):
        # Hand-built root catalog:
        #   /plain  — ordinary file (control: the crafted catalog is valid)
        #   /norow  — dir flagged DIR_NESTED_MOUNT but NO nested_catalogs row
        #   /bogus  — dir + nested row pointing at a nonexistent catalog hash
        h = forge._write_cas(b"plain payload\n", "")
        rows = [
            _row("", "", flags=FLAG_DIR, mode=0o755 | _IFDIR),
            _row("/plain", "plain", flags=FLAG_FILE, mode=0o644 | _IFREG,
                 size=14, hashhex=h),
            _row("/norow", "norow", flags=FLAG_DIR | FLAG_DIR_NESTED_MOUNT,
                 mode=0o755 | _IFDIR),
            _row("/bogus", "bogus", flags=FLAG_DIR | FLAG_DIR_NESTED_MOUNT,
                 mode=0o755 | _IFDIR),
        ]
        _install_root_catalog(forge, rows, [("/bogus", "e" * 40, 1000)])

    yield from _mounted_repo(spawn, ports, tmp_path_factory,
                             "craft.cat84.brix", {"seed": File(b"replaced\n")},
                             mutate)


# --------------------------------------------------------------------------- #
# getattr: types, sizes, modes, ownership, times, link counts
# --------------------------------------------------------------------------- #

def test_getattr_regular_file_type(main_mnt):
    assert st_mod.S_ISREG(os.lstat(main_mnt / "sizes" / "s1").st_mode)


def test_getattr_directory_type(main_mnt):
    assert st_mod.S_ISDIR(os.lstat(main_mnt / "sizes").st_mode)


def test_getattr_symlink_type(main_mnt):
    assert st_mod.S_ISLNK(os.lstat(main_mnt / "sym" / "rel").st_mode)


def test_getattr_root_is_directory(main_mnt):
    # FUSE "/" maps to the catalog root entry "" (brixcvmfs.c cat_path).
    st = os.stat(main_mnt)
    assert st_mod.S_ISDIR(st.st_mode)
    assert st_mod.S_IMODE(st.st_mode) == 0o755
    assert st.st_nlink == 2


@pytest.mark.parametrize("n", SIZES)
def test_getattr_size_exact(main_mnt, n):
    assert os.stat(main_mnt / "sizes" / f"s{n}").st_size == n


def test_read_matches_size(main_mnt):
    assert (main_mnt / "sizes" / "s65537").read_bytes() == b"x" * 65537
    assert (main_mnt / "sizes" / "s0").read_bytes() == b""


@pytest.mark.parametrize("name,mode", sorted(FILE_MODES.items()))
def test_getattr_file_mode_bits_surfaced(main_mnt, name, mode):
    # brixcvmfs surfaces st_mode verbatim from the catalog (brixcvmfs.c:209),
    # including setuid/setgid/sticky. The mount itself is nosuid (unprivileged
    # FUSE), so the bits are visible in stat but never effective — matching
    # official CVMFS, which also stores/serves the published mode bits.
    assert st_mod.S_IMODE(os.lstat(main_mnt / "modes" / name).st_mode) == mode


@pytest.mark.parametrize("name,mode", sorted(DIR_MODES.items()))
def test_getattr_dir_mode_bits_surfaced(main_mnt, name, mode):
    assert st_mod.S_IMODE(os.lstat(main_mnt / "modes" / name).st_mode) == mode


def test_getattr_uid0_squashed_to_mount_user(main_mnt):
    # catalog uid 0 -> getuid() (brixcvmfs.c:212) — matches official's
    # mount-user ownership for the common publish-as-root case.
    assert os.stat(main_mnt / "owner" / "squash").st_uid == os.getuid()


def test_getattr_gid0_squashed_to_mount_group(main_mnt):
    assert os.stat(main_mnt / "owner" / "squash").st_gid == os.getgid()


def test_getattr_nonzero_uid_surfaced_verbatim(main_mnt):
    # Actual brix behavior: st_uid = e.uid ? e.uid : getuid().
    assert os.stat(main_mnt / "owner" / "alien").st_uid == ALIEN_UID
    assert os.stat(main_mnt / "owner" / "alien").st_gid == ALIEN_GID


@pytest.mark.xfail(strict=True, reason="brix surfaces nonzero catalog uid")
def test_official_uid_squash_all_entries(main_mnt):
    # DIVERGENCE: official CVMFS by default presents EVERY entry as owned by
    # the mounting user (catalog uid/gid ignored; cvmfs docs "Repository
    # Contents"/claim_ownership). brix squashes only uid==0 and surfaces
    # nonzero catalog uids verbatim (brixcvmfs.c:212).
    assert os.stat(main_mnt / "owner" / "alien").st_uid == os.getuid()


@pytest.mark.xfail(strict=True, reason="brix surfaces nonzero catalog gid")
def test_official_gid_squash_all_entries(main_mnt):
    # DIVERGENCE: same as uid — official squashes gid to the mount user's group.
    assert os.stat(main_mnt / "owner" / "alien").st_gid == os.getgid()


def test_getattr_file_mtime_surfaced(main_mnt):
    assert os.stat(main_mnt / "times" / "epoch").st_mtime == 1234567890


def test_getattr_dir_mtime_surfaced(main_mnt):
    assert os.stat(main_mnt / "times").st_mtime == 1111111111


def test_getattr_linkcount_default_one(main_mnt):
    assert os.stat(main_mnt / "links" / "one").st_nlink == 1


def test_getattr_linkcount_surfaced(main_mnt):
    # low 32 bits of the hardlinks column (catalog.c:63-65)
    assert os.stat(main_mnt / "links" / "five").st_nlink == 5


def test_getattr_dir_nlink_always_two(main_mnt):
    # brixcvmfs hardcodes st_nlink=2 for dirs regardless of child count
    # (brixcvmfs.c:211); official cvmfs does the same for catalog dirs.
    assert os.stat(main_mnt / "names").st_nlink == 2
    assert os.stat(main_mnt / "modes" / "sticky_d").st_nlink == 2


def test_getattr_missing_path_enoent(main_mnt):
    with pytest.raises(FileNotFoundError):
        os.stat(main_mnt / "no-such-entry")


def test_stat_follows_symlink_lstat_does_not(main_mnt):
    s, l = os.stat(main_mnt / "sym" / "rel"), os.lstat(main_mnt / "sym" / "rel")
    assert st_mod.S_ISREG(s.st_mode) and st_mod.S_ISLNK(l.st_mode)
    assert s.st_size == len(b"sym target\n")


# --------------------------------------------------------------------------- #
# name corpus
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize("name", [n for _, n in NAME_CORPUS],
                         ids=[i for i, _ in NAME_CORPUS])
def test_name_lookup_and_read(main_mnt, name):
    p = main_mnt / "names" / name
    assert os.stat(p).st_size == len(name.encode())
    assert p.read_bytes() == name.encode()


def test_names_readdir_set_equality(main_mnt):
    # dot-prefixed names MUST be listed (readdir hides nothing).
    assert sorted(os.listdir(main_mnt / "names")) == sorted(n for _, n in NAME_CORPUS)


def test_case_sensitive_names_coexist(main_mnt):
    assert (main_mnt / "names" / "Case").read_bytes() == b"Case"
    assert (main_mnt / "names" / "case").read_bytes() == b"case"


def test_unicode_composed_and_combining_are_distinct(main_mnt):
    # NFC "café…" and the NFD combining variant are different byte strings —
    # both coexist and each resolves to its own content (no normalization).
    names = dict(NAME_CORPUS)
    for name in (names["utf8"], names["combining"]):
        assert (main_mnt / "names" / name).read_bytes() == name.encode()


def test_255_byte_name_round_trips(main_mnt):
    # catalog.h dirent name[256] holds exactly 255 bytes + NUL.
    name = "n" * 255
    assert os.stat(main_mnt / "names" / name).st_size == 255
    assert name in os.listdir(main_mnt / "names")


# --------------------------------------------------------------------------- #
# md5path sign edge cases
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize("name", [*NEG_M1, *NEG_M2, NEG_BOTH])
def test_md5path_negative_int64_lookup(main_mnt, name):
    # md5path halves are SIGNED little-endian int64 (catalog.c:26-31); a lookup
    # failure here would be the classic unsigned-vs-signed key mismatch bug.
    half = 0 if name.startswith("hb0") else 1
    if name.startswith("hbb"):
        assert md5path(f"/m/{name}")[0] < 0 and md5path(f"/m/{name}")[1] < 0
    else:
        assert md5path(f"/m/{name}")[half] < 0
    assert (main_mnt / "m" / name).read_bytes() == name.encode()


def test_md5path_negative_dir_readdir(main_mnt):
    assert sorted(os.listdir(main_mnt / "m")) == sorted([*NEG_M1, *NEG_M2, NEG_BOTH])


# --------------------------------------------------------------------------- #
# deep paths
# --------------------------------------------------------------------------- #

def _deep_path(mnt):
    p = mnt / "deep"
    for i in range(DEEP_LEVELS):
        p = p / f"d{i:02d}"
    return p


def test_deep_path_stat(main_mnt):
    st = os.stat(_deep_path(main_mnt) / "leaf.txt")
    assert st.st_size == len(b"deep leaf\n")


def test_deep_path_read(main_mnt):
    assert (_deep_path(main_mnt) / "leaf.txt").read_bytes() == b"deep leaf\n"


def test_deep_path_mid_level_readdir(main_mnt):
    mid = main_mnt / "deep"
    for i in range(DEEP_LEVELS // 2):
        mid = mid / f"d{i:02d}"
    assert os.listdir(mid) == [f"d{DEEP_LEVELS // 2:02d}"]


# --------------------------------------------------------------------------- #
# symlinks
# --------------------------------------------------------------------------- #

def test_readlink_relative_exact(main_mnt):
    assert os.readlink(main_mnt / "sym" / "rel") == "target.txt"


def test_read_through_relative_symlink(main_mnt):
    assert (main_mnt / "sym" / "rel").read_bytes() == b"sym target\n"


def test_readlink_absolute_exact(main_mnt):
    assert os.readlink(main_mnt / "sym" / "abs") == "/absolutely/nowhere"


def test_dangling_symlink_lstat_ok_stat_enoent(main_mnt):
    assert st_mod.S_ISLNK(os.lstat(main_mnt / "sym" / "dang").st_mode)
    with pytest.raises(FileNotFoundError):
        os.stat(main_mnt / "sym" / "dang")


def test_symlink_to_dir_traversal(main_mnt):
    assert (main_mnt / "sym" / "dirlink" / "inside.txt").read_bytes() == b"inside\n"
    assert os.listdir(main_mnt / "sym" / "dirlink") == ["inside.txt"]


def test_symlink_loop_eloop_not_hang(main_mnt):
    with pytest.raises(OSError) as e:
        os.stat(main_mnt / "sym" / "loopa")
    assert e.value.errno == errno.ELOOP


def test_symlink_self_loop_eloop(main_mnt):
    with pytest.raises(OSError) as e:
        os.stat(main_mnt / "sym" / "self")
    assert e.value.errno == errno.ELOOP


def test_long_symlink_target_exact(main_mnt):
    # 999-byte target, just under the 1024-byte dirent symlink cap
    assert os.readlink(main_mnt / "sym" / "long") == LONG_TARGET


def test_symlink_size_is_target_length(main_mnt):
    assert os.lstat(main_mnt / "sym" / "long").st_size == len(LONG_TARGET)
    assert os.lstat(main_mnt / "sym" / "rel").st_size == len("target.txt")


# --------------------------------------------------------------------------- #
# readdir completeness
# --------------------------------------------------------------------------- #

def test_readdir_empty_dir(rdir_mnt):
    assert os.listdir(rdir_mnt / "empty") == []
    assert st_mod.S_ISDIR(os.stat(rdir_mnt / "empty").st_mode)


def test_readdir_single_entry(rdir_mnt):
    assert os.listdir(rdir_mnt / "one") == ["only"]


def test_readdir_100_entries(rdir_mnt):
    assert set(os.listdir(rdir_mnt / "hundred")) == {f"f{i:03d}" for i in range(100)}


def test_readdir_1000_entries(rdir_mnt):
    names = os.listdir(rdir_mnt / "thousand")
    assert len(names) == 1000
    assert set(names) == {f"g{i:04d}" for i in range(1000)}


def test_readdir_root_set_equality(rdir_mnt):
    assert sorted(os.listdir(rdir_mnt)) == ["empty", "hundred", "mixed", "one",
                                            "thousand"]


def test_readdir_stable_across_rereads(rdir_mnt):
    a, b = sorted(os.listdir(rdir_mnt / "hundred")), sorted(os.listdir(rdir_mnt / "hundred"))
    assert a == b


def test_readdir_emits_dot_and_dotdot(rdir_mnt):
    # brixcvmfs_op_readdir fills "." and ".." explicitly (brixcvmfs.c:229-230);
    # python's listdir filters them, so ask ls -a.
    out = subprocess.run(["ls", "-a", str(rdir_mnt / "one")],
                         capture_output=True, text=True, check=True).stdout.split()
    assert "." in out and ".." in out and "only" in out


def test_readdir_entry_types(rdir_mnt):
    # readdir passes a NULL stat to the filler (d_type DT_UNKNOWN), so type
    # classification falls back to per-entry stat — assert it lands right.
    ents = {e.name: e for e in os.scandir(rdir_mnt / "mixed")}
    assert set(ents) == {"f", "d", "l"}
    assert ents["f"].is_file(follow_symlinks=False)
    assert ents["d"].is_dir(follow_symlinks=False)
    assert ents["l"].is_symlink()


# --------------------------------------------------------------------------- #
# nested catalogs — known-good transitions
# --------------------------------------------------------------------------- #

def test_nested_mountpoint_stats_as_dir(nest_mnt):
    st = os.stat(nest_mnt / "n1")
    assert st_mod.S_ISDIR(st.st_mode) and st_mod.S_IMODE(st.st_mode) == 0o755


def test_nested_root_readdir_lists_mountpoint(nest_mnt):
    assert sorted(os.listdir(nest_mnt)) == ["marker.txt", "n1"]


def test_nested_one_level_file_read(nest_mnt):
    assert (nest_mnt / "n1" / "inner.txt").read_bytes() == b"one deep\n"


def test_nested_subdir_stat(nest_mnt):
    assert st_mod.S_ISDIR(os.stat(nest_mnt / "n1" / "sub").st_mode)


def test_nested_subdir_file_read(nest_mnt):
    assert (nest_mnt / "n1" / "sub" / "deep.txt").read_bytes() == b"below mount\n"


def test_nested_two_levels_file_read(nest_mnt):
    # crosses two transitions: root -> /n1 -> /n1/n2 (client.c resolve loop)
    assert (nest_mnt / "n1" / "n2" / "two.txt").read_bytes() == b"two deep\n"


def test_nested_two_levels_deep_stat(nest_mnt):
    st = os.stat(nest_mnt / "n1" / "n2" / "d" / "leaf.txt")
    assert st.st_size == len(b"nested leaf\n")


def test_inner_mountpoint_stats_as_dir(nest_mnt):
    # /n1/n2's mount row lives in n1's catalog — one descent, then lookup
    assert st_mod.S_ISDIR(os.stat(nest_mnt / "n1" / "n2").st_mode)


def test_readdir_nested_mountpoint_lists_children(nest_mnt):
    # Official CVMFS lists a nested mountpoint's children (it attaches the
    # nested catalog for the listing). cvmfs_client_readdir descends via
    # longest_nested_prefix(include_self=1) so /n1 lists from n1's catalog.
    assert sorted(os.listdir(nest_mnt / "n1")) == ["inner.txt", "n2", "sub"]


def test_readdir_below_nested_mountpoint_lists_children(nest_mnt):
    # Same descent one level down — /n1/sub's children live in n1's catalog,
    # and readdir now resolves into it.
    assert os.listdir(nest_mnt / "n1" / "sub") == ["deep.txt"]


# --------------------------------------------------------------------------- #
# nested catalogs — tampered (never crash, never wrong bytes)
# --------------------------------------------------------------------------- #

def test_tamper_control_intact_nested_works(evil_mnt):
    assert (evil_mnt / "ok" / "f").read_bytes() == b"ok payload\n"


def test_tamper_missing_nested_cas_object_enoent(evil_mnt):
    # nested row present, CAS 'C' object deleted: descent fails, fallback
    # lookup in the root catalog misses -> ENOENT (client.c:113 break path).
    with pytest.raises(OSError) as e:
        os.stat(evil_mnt / "gone" / "f")
    assert e.value.errno in (errno.ENOENT, errno.EIO)


def test_tamper_missing_nested_cas_mountpoint_still_dir(evil_mnt):
    # the mountpoint row itself lives in the (intact) root catalog
    assert st_mod.S_ISDIR(os.stat(evil_mnt / "gone").st_mode)


def test_tamper_corrupt_nested_cas_refused(evil_mnt):
    # stored nested-catalog bytes flipped: content hash mismatch -> the fetch
    # layer refuses the object; children are unreachable, never wrong bytes.
    with pytest.raises(OSError) as e:
        os.stat(evil_mnt / "corrupt" / "f")
    assert e.value.errno in (errno.ENOENT, errno.EIO)


def test_tamper_root_listing_survives(evil_mnt):
    assert sorted(os.listdir(evil_mnt)) == ["corrupt", "gone", "ok"]


def test_craft_control_plain_file_reads(craft_mnt):
    # proves the hand-built root catalog itself is well-formed
    assert (craft_mnt / "plain").read_bytes() == b"plain payload\n"


def test_craft_mountpoint_flag_without_row_stats(craft_mnt):
    # DIR_NESTED_MOUNT flag set but no nested_catalogs row: the dir must still
    # stat cleanly (longest_nested_prefix simply finds no row).
    assert st_mod.S_ISDIR(os.stat(craft_mnt / "norow").st_mode)


def test_craft_mountpoint_without_row_child_enoent(craft_mnt):
    with pytest.raises(FileNotFoundError):
        os.stat(craft_mnt / "norow" / "child")


def test_craft_bogus_nested_hash_mountpoint_stats(craft_mnt):
    assert st_mod.S_ISDIR(os.stat(craft_mnt / "bogus").st_mode)


def test_craft_bogus_nested_hash_child_refused(craft_mnt):
    # nested row points at a nonexistent catalog hash: descent fetch 404s,
    # fallback root lookup misses -> ENOENT/EIO, never fabricated entries.
    with pytest.raises(OSError) as e:
        os.stat(craft_mnt / "bogus" / "deep" / "file")
    assert e.value.errno in (errno.ENOENT, errno.EIO)


def test_craft_bogus_nested_hash_readdir_empty_not_crash(craft_mnt):
    assert os.listdir(craft_mnt / "bogus") == []
    assert sorted(os.listdir(craft_mnt)) == ["bogus", "norow", "plain"]


# --------------------------------------------------------------------------- #
# whole-tree stat walk vs forged truth
# --------------------------------------------------------------------------- #

def _assert_subtree(mnt_dir: Path, spec: dict) -> int:
    checked = 0
    listing = set(os.listdir(mnt_dir))
    assert listing == set(spec), f"readdir mismatch in {mnt_dir}"
    for name, node in spec.items():
        p = mnt_dir / name
        st = os.lstat(p)
        if isinstance(node, Dir):
            assert st_mod.S_ISDIR(st.st_mode) and st.st_nlink == 2
            assert st_mod.S_IMODE(st.st_mode) == node.mode
            assert st.st_mtime == node.mtime
            checked += 1 + _assert_subtree(p, node.entries)
        elif isinstance(node, File):
            assert st_mod.S_ISREG(st.st_mode)
            assert st.st_size == len(node.content)
            assert st_mod.S_IMODE(st.st_mode) == node.mode
            assert st.st_mtime == node.mtime
            assert st.st_nlink == node.linkcount
            assert st.st_uid == (node.uid or os.getuid())
            assert st.st_gid == (node.gid or os.getgid())
            checked += 1
        elif isinstance(node, Symlink):
            assert st_mod.S_ISLNK(st.st_mode)
            assert os.readlink(p) == node.target
            checked += 1
        else:  # pragma: no cover — main tree has no Chunked nodes
            raise AssertionError(f"unexpected node {node!r}")
    return checked


def test_stat_walk_whole_tree_matches_forged_truth(main_mnt):
    # every lstat field across the entire main tree vs the forge spec
    checked = _assert_subtree(main_mnt, _main_tree())
    assert checked > 80          # sanity: the walk actually covered the tree
