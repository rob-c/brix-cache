"""Phase-115 §P5 — COPY/MOVE onto the source, on a backend that HAS inodes.

WebDAV refuses a COPY or MOVE whose destination names the source (RFC 4918
§9.8.5 / §9.9.4 -> 403), and the refusal is not a formality: the copy engine
publishes by writing a temp object and renaming it over the destination, so a
copy onto the source destroys the only copy of a file the caller never asked to
modify, and a failure part-way through destroys it permanently.

That guard used to be `st_ino == st_ino && st_dev == st_dev` and nothing else,
which was wrong in a way no local test could see.  A REMOTE namespace has no
inodes to compare: the gsiftp, http, s3 and xroot drivers never fill
`brix_vfs_stat_t.ino/.dev`, so every path on such an export stats as (0,0) and
the guard read "source and destination are the same file" for EVERY destination
that already existed.  Ordinary overwrites answered 403 on every remote-backed
export.  The remote half of that story, and the fix's effect there, is pinned
next to the driver in test_phase115_gsiftp_server_copy.py.

What is pinned HERE is the arm that is easy to lose while fixing the other one.
`brix_webdav_same_object` (src/protocols/webdav/webdav_path.h) now answers on
path equality first and consults (dev,ino) only when the backend supplied an
identity — and the tempting simplification is to drop the inode comparison
altogether, since the path arm alone passes every test written against a remote
export.  On a POSIX export it does not: a hardlink is a second NAME for one
object, the paths differ, and a copy onto it would destroy the object through
its other name.  This suite runs on the shared fleet's plain-HTTP POSIX export
precisely because it is a backend with real inodes.
"""

import os
import re
import subprocess
import uuid
from pathlib import Path

import pytest
import requests

from csource_scan import strip_comments

REPO_ROOT = Path(__file__).resolve().parents[1]
WEBDAV = REPO_ROOT / "src/protocols/webdav"
BACKEND = REPO_ROOT / "src/fs/backend"

# The namespaces that reach their objects over a wire.  Naming them is the
# load-bearing part of the census below: if one of these ever grew a synthetic
# inode, the predicate's "no identity to compare" branch would stop being
# reached there and the reason it exists would need re-checking.
REMOTE_BACKENDS = ("gsiftp", "http", "s3", "xroot")
INODE_FILL = re.compile(r"\bino\s*=|\bdev\s*=")

pytestmark = [
    pytest.mark.registry_server("main"),
    pytest.mark.requires_local_server,
]

PAYLOAD = bytes(range(256)) * 8             # 2048 bytes, position-revealing
OTHER = b"the destination's previous contents"
TIMEOUT = 15


class _Export:
    """Three names on one POSIX export: a source, its hardlink, and a stranger.

    The hardlink is made through the filesystem rather than through WebDAV
    because WebDAV has no verb for it — and it is the whole point of the inode
    arm, so it cannot be approximated by a second copy.
    """

    def __init__(self, base: str, root: str, uid: str):
        self.base = base
        self.root = root
        self.src = f"/p115same_src_{uid}.bin"
        self.link = f"/p115same_link_{uid}.bin"
        self.other = f"/p115same_other_{uid}.bin"
        self.fresh = f"/p115same_fresh_{uid}.bin"

    def local(self, path: str) -> str:
        return os.path.join(self.root, path.lstrip("/"))

    def put(self, path: str, body: bytes):
        status = requests.put(self.base + path, data=body,
                              timeout=TIMEOUT).status_code
        assert status in (200, 201), f"PUT {path} -> {status}"

    def body(self, path: str) -> bytes:
        with open(self.local(path), "rb") as handle:
            return handle.read()

    def exists(self, path: str) -> bool:
        return os.path.exists(self.local(path))

    def dav(self, method: str, src: str, dst: str, overwrite: str = "T") -> int:
        return requests.request(
            method, self.base + src, timeout=TIMEOUT,
            headers={"Destination": self.base + dst,
                     "Overwrite": overwrite}).status_code


@pytest.fixture
def export(test_env):
    """A fresh triple per test — COPY and MOVE both mutate what they touch."""
    ex = _Export(test_env["http_webdav_url"], test_env["data_dir"],
                 uuid.uuid4().hex)
    ex.put(ex.src, PAYLOAD)
    ex.put(ex.other, OTHER)
    os.link(ex.local(ex.src), ex.local(ex.link))
    yield ex
    for path in (ex.src, ex.link, ex.other, ex.fresh):
        if ex.exists(path):
            os.unlink(ex.local(path))


# ---- the path arm: the destination is spelled as the source ------------------

def test_a_copy_onto_its_own_path_is_refused(export):
    """403, and — the assertion that matters more — the source is intact.

    A status code alone would be satisfied by a guard that refused after the
    engine had already renamed a partial temp object over the original.
    """
    assert export.dav("COPY", export.src, export.src) == 403
    assert export.body(export.src) == PAYLOAD


def test_a_move_onto_its_own_path_is_refused(export):
    """MOVE reaches the same predicate; a rename onto itself is a no-op at
    best and, through the overwrite-a-directory path, a deletion at worst."""
    assert export.dav("MOVE", export.src, export.src) == 403
    assert export.body(export.src) == PAYLOAD


def test_an_aliased_spelling_of_the_source_is_still_refused(export):
    """The comparison is of RESOLVED paths, not of the Destination header.

    `/./x` and `//x` name the same object as `/x`.  If the predicate compared
    the header text it would let both through, and each would run the full
    destroy-and-republish over a healthy file.
    """
    for alias in ("/." + export.src, "/" + export.src):
        assert export.dav("COPY", export.src, alias) == 403, alias
        assert export.body(export.src) == PAYLOAD, alias


# ---- the inode arm: a second NAME for the same object ------------------------

def test_a_copy_onto_a_hardlink_of_the_source_is_refused(export):
    """THE reason the inode comparison must survive the remote-export fix.

    The two paths differ, so the path arm says nothing.  They are one object,
    so copying either onto the other rewrites the file being read.
    """
    assert export.dav("COPY", export.src, export.link) == 403
    assert export.body(export.src) == PAYLOAD
    assert export.body(export.link) == PAYLOAD


def test_a_move_onto_a_hardlink_of_the_source_is_refused(export):
    """Same object, same refusal — and both names still resolve afterwards."""
    assert export.dav("MOVE", export.src, export.link) == 403
    assert export.exists(export.src) and export.exists(export.link)
    assert export.body(export.src) == PAYLOAD


def test_the_two_names_really_are_one_object(export):
    """The named negative: without it the two rows above prove nothing.

    If `os.link` had silently produced a copy — a different filesystem, a
    backend that does not support links — the refusals above would be about
    two unrelated files and would pass for the wrong reason.
    """
    src = os.stat(export.local(export.src))
    link = os.stat(export.local(export.link))
    assert (src.st_ino, src.st_dev) == (link.st_ino, link.st_dev)
    assert src.st_ino != 0, "this export has no inodes, so it cannot test the "\
                            "inode arm at all"


# ---- discrimination: an ordinary overwrite is not a self-copy ----------------

def test_a_copy_onto_a_different_existing_file_replaces_it(export):
    """The regression defect #4 actually was, in its local form.

    Every row above is a refusal, and a guard that refused EVERYTHING would
    pass all of them.  This is the row that fails when the predicate stops
    discriminating — which is exactly what happened on remote exports, where
    the inode-only guard could not tell two objects apart at all.
    """
    assert export.dav("COPY", export.src, export.other) in (201, 204)
    assert export.body(export.other) == PAYLOAD
    assert export.body(export.src) == PAYLOAD


def test_a_move_onto_a_different_existing_file_replaces_it(export):
    """The same discrimination for MOVE: the destination exists and loses."""
    assert export.dav("MOVE", export.other, export.fresh) in (201, 204)
    assert export.body(export.fresh) == OTHER
    assert not export.exists(export.other)


# ---- the shape: one predicate, and the premise it rests on -------------------

def _source(path: Path) -> str:
    return strip_comments(path.read_text(encoding="utf-8", errors="replace"))


def test_copy_and_move_reach_one_predicate():
    """Neither verb may keep a private copy of the comparison.

    They had one each, both inode-only, and only one of them was found the
    first time.  A predicate that exists twice gets fixed once.
    """
    for name in ("copy.c", "move.c"):
        body = _source(WEBDAV / name)
        assert "brix_webdav_same_object" in body, \
            f"{name} no longer uses the shared same-object predicate"
        assert "st_ino ==" not in body, \
            f"{name} has grown its own inode comparison again"


def test_the_predicate_answers_on_the_path_before_the_inode():
    """Order matters: the path arm is the one that holds everywhere.

    On a remote export the inode arm cannot answer at all, so a predicate that
    consulted it first — or only — is the defect, not a variant of the fix.
    """
    body = _source(WEBDAV / "webdav_path.h")
    body = body[body.index("brix_webdav_same_object"):]
    path_arm = body.index("ngx_strcmp(src_path, dst_path)")
    inode_arm = body.index("st_ino == dst_sb->st_ino")
    assert path_arm < inode_arm, body
    assert "src_sb->st_ino == 0 && src_sb->st_dev == 0" in body, \
        "the predicate no longer checks whether the backend gave it an identity"


def test_no_remote_backend_supplies_an_inode():
    """The premise, read out of the tree rather than asserted from memory.

    This is the fact that made an inode-only guard answer "same file" for every
    existing destination on a gsiftp, http, s3 or xroot export.
    """
    for name in REMOTE_BACKENDS:
        directory = BACKEND / name
        assert directory.is_dir(), f"{name} backend moved; this census is stale"
        filling = [source for source in sorted(directory.rglob("*.c"))
                   if INODE_FILL.search(_source(source))]
        assert not filling, \
            f"{name} now fills an inode: {[str(p) for p in filling]} — the "\
            "predicate's no-identity branch may no longer be reached there"


def test_a_local_backend_does_supply_one():
    """The named negative, so the census above cannot pass by being empty.

    If nothing anywhere filled an inode the test above would be green and the
    inode arm would be dead code — which is a different bug with the same
    silence.
    """
    filling = [source for source in sorted((BACKEND / "posix").rglob("*.c"))
               if INODE_FILL.search(_source(source))]
    assert filling, "no POSIX backend source fills an inode; the inode arm of "\
                    "brix_webdav_same_object can never be reached"


# ---- the truth table, compiled from the shipped body ------------------------

# The rows are (source path, destination path, source ino/dev, destination
# ino/dev, same object?).  Two of them cannot be produced through HTTP at all —
# a remote export refuses to hand out an inode, and a local one refuses to
# withhold one — so the predicate is exercised directly instead of inferred.
TRUTH_TABLE = (
    ("/a", "/a", (0, 0), (0, 0), 1),      # remote, self: the path arm alone
    ("/a", "/b", (0, 0), (0, 0), 0),      # DEFECT #4: inode-only said 1 here
    ("/a", "/b", (7, 3), (7, 3), 1),      # local hardlink: the inode arm
    ("/a", "/b", (7, 3), (9, 3), 0),      # two ordinary local files
    ("/a", "/a", (7, 3), (7, 3), 1),      # local self, both arms agree
    ("/a", "/b", (7, 3), (0, 0), 0),      # one identity known, one not
)

HARNESS = """
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>

#define ngx_inline  inline
#define ngx_strcmp(a, b)  strcmp((const char *) a, (const char *) b)

%s

int main(void)
{
    struct stat src, dst;
    char        sp[64], dp[64];
    long        si, sd, di, dd;

    while (scanf("%%63s %%63s %%ld %%ld %%ld %%ld", sp, dp, &si, &sd, &di, &dd)
           == 6)
    {
        memset(&src, 0, sizeof(src));
        memset(&dst, 0, sizeof(dst));
        src.st_ino = si;  src.st_dev = sd;
        dst.st_ino = di;  dst.st_dev = dd;
        printf("%%d\\n", brix_webdav_same_object(sp, dp, &src, &dst));
    }
    return 0;
}
"""


def _predicate_body() -> str:
    """The shipped `brix_webdav_same_object`, lifted out of webdav_path.h.

    Lifted rather than reimplemented: a model of the predicate would keep
    passing after the predicate changed, which is the one thing this must not
    do.  Only the nginx spellings are substituted (see HARNESS), so the logic
    compiled below is the logic that ships.
    """
    text = (WEBDAV / "webdav_path.h").read_text(encoding="utf-8")
    start = text.index("static ngx_inline int\nbrix_webdav_same_object")
    end = text.index("\n}\n", start) + len("\n}\n")
    return text[start:end]


def _compile_predicate(tmp_path) -> Path:
    """The shipped predicate, compiled into a table-driven probe."""
    source = tmp_path / "same_object.c"
    binary = tmp_path / "same_object"
    source.write_text(HARNESS % _predicate_body(), encoding="utf-8")
    build = subprocess.run(["cc", "-std=c11", "-Wall", "-Werror",
                            "-o", str(binary), str(source)],
                           capture_output=True, text=True)
    assert build.returncode == 0, build.stderr
    return binary


def _ask(binary: Path, rows) -> list[int]:
    """One answer per row, in order, from the compiled predicate."""
    stdin = "".join(f"{src} {dst} {si} {sd} {di} {dd}\n"
                    for src, dst, (si, sd), (di, dd), _ in rows)
    run = subprocess.run([str(binary)], input=stdin,
                         capture_output=True, text=True, timeout=30)
    assert run.returncode == 0, run.stderr
    return [int(line) for line in run.stdout.split()]


def test_the_predicate_truth_table(tmp_path):
    """Every row, including the two the wire cannot produce.

    Row 2 is defect #4 itself: two different paths on a namespace that supplies
    no identity.  An inode-only predicate answers 1 there — "the same file" —
    and every overwrite on every remote-backed export becomes a 403.
    """
    answers = _ask(_compile_predicate(tmp_path), TRUTH_TABLE)
    expected = [row[-1] for row in TRUTH_TABLE]
    assert answers == expected, (
        f"\n  rows:     {TRUTH_TABLE}"
        f"\n  expected: {expected}"
        f"\n  got:      {answers}")
