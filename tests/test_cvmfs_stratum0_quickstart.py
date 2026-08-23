"""Phase-96 — the documented unprivileged Stratum-0 quickstart, end to end.

The sibling lanes (`test_cvmfs_stratum0_serve.py`, `_scvmfs.py`) drive a
*standalone test build* of the repo writers. This lane drives the **shipped
binary** through the exact command sequence the operator runbook publishes
(docs/05-operations/cvmfs-stratum0.md), as an ordinary unprivileged user, so
a drift between what we document and what we install fails here:

  success:      the `brixcvmfs` argv[0] personality of brixMount self-IDs and
                dispatches `repo`; mkfs → transaction → publish → serve →
                mount round-trips custom files (regular, executable, nested,
                symlink, >floor chunked) with modes and link targets intact;
                a second publish adds, modifies and deletes (whiteout marker);
                tag/resign/gc/fsck all keep the repo mountable.
  error:        publishing with no open transaction, mkfs over a published
                repo, a second concurrent transaction, gc against an open
                transaction and rollback to an unknown tag are all refused
                non-zero, and the repo still verifies afterwards.
  security-neg: the served Stratum-0 refuses every write method (405), a
                tampered CAS object fails fsck and the client refuses the
                object, and no other argv[0] name gains the cvmfs
                personality (the umbrella still demands a type keyword).

Unprivileged throughout: no root, no overlayfs, no kernel automount — the
mount leg needs only /dev/fuse and skips cleanly without it.
"""

import os
import stat
import subprocess
import sys

import pytest

# conftest chdir()s into a scratch dir — anchor imports on this file's dir.
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "cvmfs"))

from conformance_common import BRIXMOUNT, NGINX_BIN, PortBlock, fuse_mount, request
from cmdscripts.live_common import LiveRun
from settings import BIND_HOST, HOST
from config_templates import render_config

FQRN = "quickstart.brix.io"

# The custom payload an operator would share: a plain file, an executable
# script, a nested tree, a symlink, and one file above the 4096-byte chunk
# floor so the chunked-object path is exercised by the documented flow.
PAYLOAD = {
    "README.md": (b"# quickstart repo\n", 0o644),
    "tools/hello.sh": (b"#!/bin/sh\necho hello from stratum-0\n", 0o755),
    "data/samples/alpha.txt": (b"alpha payload\n", 0o644),
    "data/samples/big.dat": (b"payload-block " * 4000, 0o644),
}
SYMLINK = ("run-me", "tools/hello.sh")

_BLOCK = PortBlock("srv_s0_quickstart")

_CLIENT_BIN = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "client", "bin")
BRIXCVMFS = os.environ.get("BRIXCVMFS_BIN", os.path.join(_CLIENT_BIN, "brixcvmfs"))

pytestmark = [
    pytest.mark.skipif(not os.path.exists(NGINX_BIN),
                       reason=f"nginx binary not found: {NGINX_BIN}"),
    pytest.mark.skipif(not os.path.exists(BRIXCVMFS),
                       reason="brixcvmfs not built (run `make -C client brixcvmfs`)"),
]


def repo_cmd(*args, expect_ok=True):
    """Run `brixcvmfs repo <args>` exactly as the runbook spells it."""
    r = subprocess.run([BRIXCVMFS, "repo", *args],
                       capture_output=True, text=True, timeout=180)
    if expect_ok:
        assert r.returncode == 0, f"repo {args[0]} failed: {r.stderr}{r.stdout}"
    return r


def _upper(repo):
    return repo / ".brixtxn" / "upper"


def _stage(repo):
    """Write PAYLOAD + the symlink into the open transaction's upper tree."""
    upper = _upper(repo)
    for rel, (content, mode) in PAYLOAD.items():
        target = upper / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(content)
        target.chmod(mode)
    (upper / SYMLINK[0]).symlink_to(SYMLINK[1])


def _nginx_conf(run, port, loc_lines):
    return run.write(
        run.root / f"nginx.{port}.conf",
        render_config(
            "nginx_cvmfs_stratum0_lab.conf",
            USER_LINE="user root;\n" if os.geteuid() == 0 else "",
            LOG_FILE=f"{run.root}/logs/e.{port}.log",
            PID_FILE=f"{run.root}/nginx.{port}.pid",
            BIND_HOST=BIND_HOST, PORT=port,
            LISTEN_SSL="", SSL_LINES="",
            LOCATION_LINES=loc_lines))


@pytest.fixture(scope="module")
def quickstart():
    """The runbook, verbatim: mkfs → transaction → stage → publish → serve."""
    with LiveRun("cvmfs_s0_quick", NGINX_BIN) as run:
        run.mkdir("logs")
        web = run.mkdir("web")
        repo = run.mkdir("web", "cvmfs") / FQRN     # mkfs makes only the leaf

        repo_cmd("mkfs", FQRN, str(repo))
        repo_cmd("transaction", str(repo))
        _stage(repo)
        repo_cmd("publish", str(repo), "--chunk-size", "4096")

        port = _BLOCK.nginx()
        conf = _nginx_conf(run, port, f"""
        brix_cvmfs on;
        brix_cvmfs_stratum0_root {web};""")
        run.start_nginx(run.root, conf, port)
        yield run, repo, port


def _mount(repo, port):
    return fuse_mount(FQRN, f"http://{HOST}:{port}/cvmfs/{FQRN}",
                      repo / "keys" / f"{FQRN}.pub")


def _need_fuse():
    if not (os.path.exists("/dev/fuse") and os.path.exists(BRIXMOUNT)):
        pytest.skip("no /dev/fuse or brixMount for the client leg")


# ---------------------------------------------------------------------------
# SUCCESS
# ---------------------------------------------------------------------------
def test_personality_self_ids_and_dispatches_repo():
    """`brixcvmfs` is brixMount under another name: own banner, own usage."""
    assert os.path.islink(BRIXCVMFS), "brixcvmfs should be a symlink, not a copy"
    assert os.readlink(BRIXCVMFS) == "brixMount"

    ver = subprocess.run([BRIXCVMFS, "--version"], capture_output=True, text=True)
    assert ver.returncode == 0 and ver.stdout.startswith("brixcvmfs "), ver.stdout

    hlp = subprocess.run([BRIXCVMFS, "--help"], capture_output=True, text=True)
    assert hlp.returncode == 0
    assert "usage: brixcvmfs <repo.fqrn> <mountpoint>" in hlp.stdout, hlp.stdout
    assert "man brixcvmfs" in hlp.stdout, "footer must name the invoked alias"

    # `repo` with no subcommand prints the release-manager usage (exit 2).
    bare = subprocess.run([BRIXCVMFS, "repo"], capture_output=True, text=True)
    assert bare.returncode == 2
    blob = bare.stdout + bare.stderr
    for sub in ("mkfs", "publish", "transaction", "gc", "tag", "fsck", "resign"):
        assert f"repo {sub}" in blob, (sub, blob)


def _assert_mounted_payload(mountpoint):
    assert os.path.ismount(mountpoint), "mount did not come up"
    for relative, (content, mode) in PAYLOAD.items():
        path = mountpoint / relative
        assert path.read_bytes() == content, relative
        assert stat.S_IMODE(path.lstat().st_mode) == mode, relative


def _assert_mounted_tools(mountpoint):
    link = mountpoint / SYMLINK[0]
    assert link.is_symlink() and os.readlink(link) == SYMLINK[1]
    run = subprocess.run([str(mountpoint / "tools/hello.sh")],
                         capture_output=True, text=True, timeout=30)
    assert run.returncode == 0 and "hello from stratum-0" in run.stdout


def test_published_repo_serves_and_mounts(quickstart):
    """The shared files arrive intact through nginx and a real FUSE mount."""
    _run, repo, port = quickstart

    status, _, manifest = request(HOST, port, "GET", f"/cvmfs/{FQRN}/.cvmfspublished")
    assert status == 200 and manifest == (repo / ".cvmfspublished").read_bytes()

    info = repo_cmd("info", str(repo))
    assert "revision ........ 2" in info.stdout, info.stdout
    assert "trust chain ..... OK" in info.stdout, info.stdout

    _need_fuse()
    with _mount(repo, port) as (mnt, _proc):
        _assert_mounted_payload(mnt)
        _assert_mounted_tools(mnt)


def test_second_publish_adds_modifies_and_deletes(quickstart):
    """add + modify + whiteout delete land as one new revision."""
    _run, repo, port = quickstart

    repo_cmd("transaction", str(repo))
    upper = _upper(repo)
    (upper / "data" / "samples").mkdir(parents=True, exist_ok=True)
    (upper / "data" / "samples" / "alpha.txt").write_bytes(b"alpha payload v2\n")
    (upper / "NEWS").write_bytes(b"revision three\n")
    (upper / "data" / "samples" / ".brix.wh.big.dat").touch()   # delete marker
    repo_cmd("publish", str(repo))

    assert "revision ........ 3" in repo_cmd("info", str(repo)).stdout
    assert "fsck clean" in repo_cmd("fsck", str(repo), "--data").stdout

    _need_fuse()
    with _mount(repo, port) as (mnt, _proc):
        assert os.path.ismount(mnt)
        assert (mnt / "data/samples/alpha.txt").read_bytes() == b"alpha payload v2\n"
        assert (mnt / "NEWS").read_bytes() == b"revision three\n"
        assert not (mnt / "data/samples/big.dat").exists(), "whiteout not applied"
        assert (mnt / "README.md").read_bytes() == PAYLOAD["README.md"][0]


def test_maintenance_keeps_the_repo_mountable(quickstart):
    """tag → resign → gc: the documented cron loop leaves a valid repo."""
    _run, repo, port = quickstart

    repo_cmd("tag", "add", str(repo), "v1.0", "-m", "quickstart release")
    assert "v1.0" in repo_cmd("tag", "list", str(repo)).stdout

    assert "re-signed" in repo_cmd("resign", str(repo)).stdout
    gc = repo_cmd("gc", str(repo), "--keep", "2")
    assert "kept 2 revision" in gc.stdout, gc.stdout
    # --data after gc is the assertion that matters: a sweep that took a live
    # object with it shows up here and nowhere else until a client reads it.
    assert "fsck clean" in repo_cmd("fsck", str(repo), "--data").stdout

    _need_fuse()
    with _mount(repo, port) as (mnt, _proc):
        assert os.path.ismount(mnt), "repo unmountable after tag/resign/gc"
        assert (mnt / "NEWS").read_bytes() == b"revision three\n"


# ---------------------------------------------------------------------------
# ERROR-GOLDEN
# ---------------------------------------------------------------------------
def test_lifecycle_misuse_is_refused(quickstart):
    """Every out-of-order lifecycle call fails non-zero, repo stays valid."""
    _run, repo, _port = quickstart

    assert repo_cmd("publish", str(repo), expect_ok=False).returncode != 0
    assert repo_cmd("mkfs", FQRN, str(repo), expect_ok=False).returncode != 0
    assert repo_cmd("tag", "rollback", str(repo), "no-such-tag",
                    expect_ok=False).returncode != 0

    repo_cmd("transaction", str(repo))
    try:
        second = repo_cmd("transaction", str(repo), expect_ok=False)
        assert second.returncode != 0, "concurrent transaction was allowed"
        assert repo_cmd("gc", str(repo), "--keep", "1",
                        expect_ok=False).returncode != 0, "gc ran mid-transaction"
    finally:
        repo_cmd("abort", str(repo))

    assert "trust chain ..... OK" in repo_cmd("info", str(repo)).stdout


def test_mkfs_needs_an_existing_parent(tmp_path):
    """mkfs creates the repo dir, never its parents (documented behaviour)."""
    missing = tmp_path / "no" / "such" / "parent" / FQRN
    assert repo_cmd("mkfs", FQRN, str(missing), expect_ok=False).returncode != 0
    assert not missing.exists()


# ---------------------------------------------------------------------------
# SECURITY-NEG
# ---------------------------------------------------------------------------
@pytest.mark.parametrize("method", ["PUT", "DELETE", "POST", "MKCOL", "PROPPATCH"])
def test_serve_plane_refuses_writes(quickstart, method):
    """Publishing never leaks into the serve plane — writes still 405."""
    _run, _repo, port = quickstart
    status, _, _ = request(HOST, port, method, f"/cvmfs/{FQRN}/.cvmfspublished",
                           body=b"x")
    assert status == 405, f"{method}: {status}"


def test_serve_plane_hides_keys_and_staging(quickstart):
    """Only CVMFS traffic shapes are served — keys and staging stay invisible.

    The documented layout puts `keys/` (master key included) and, mid-publish,
    `.brixtxn/upper/` INSIDE the served directory, so the gate's shape
    classifier is what makes that layout safe.
    """
    _run, repo, port = quickstart
    repo_cmd("transaction", str(repo))
    try:
        (_upper(repo) / "secret.txt").write_bytes(b"unpublished\n")
        for rel in (f"keys/{FQRN}.masterkey", f"keys/{FQRN}.pub", f"keys/{FQRN}.key",
                    ".brixtxn/upper/secret.txt", ".brixtxn/lock"):
            assert (repo / rel).exists(), f"fixture drift: {rel} not on disk"
            status, _, _ = request(HOST, port, "GET", f"/cvmfs/{FQRN}/{rel}")
            assert status == 403, f"{rel} was served: {status}"
    finally:
        repo_cmd("abort", str(repo))


def _flip(buf):
    raw = bytearray(buf)
    raw[len(raw) // 2] ^= 0xFF
    return bytes(raw)


def _live_payload_object(repo):
    """A CAS payload object the CURRENT revision references.

    gc keeps older revisions, so picking any file under data/ can land on an
    object no live catalog points at — corrupting that one proves nothing.
    `fsck --data` is the oracle for reachability, so ask it.
    """
    for cand in sorted(p for p in (repo / "data").glob("*/*")
                       if p.is_file() and not p.name.endswith(("C", "X", "H"))):
        clean = cand.read_bytes()
        cand.write_bytes(_flip(clean))
        seen = repo_cmd("fsck", str(repo), "--data", expect_ok=False).returncode != 0
        cand.write_bytes(clean)
        if seen:
            return cand, clean
    pytest.fail("no live payload object found in the published revision")


def test_tampered_object_is_caught(quickstart):
    """A flipped CAS byte fails `fsck --data` and the client refuses the object.

    Plain `fsck` is a catalog/counter check and is *expected* to stay green —
    that split is the documented reason the payload sweep is opt-in.
    """
    _run, repo, port = quickstart
    victim, clean = _live_payload_object(repo)
    corrupt = _flip(clean)
    try:
        victim.write_bytes(corrupt)
        assert "fsck clean" in repo_cmd("fsck", str(repo)).stdout, \
            "catalog-only fsck should not depend on payload objects"
        bad = repo_cmd("fsck", str(repo), "--data", expect_ok=False)
        assert bad.returncode != 0, "fsck --data accepted a tampered CAS object"
        assert "fails CAS verification" in bad.stdout + bad.stderr

        victim.unlink()                     # rot's other face: the object is gone
        gone = repo_cmd("fsck", str(repo), "--data", expect_ok=False)
        assert gone.returncode != 0, "fsck --data accepted a missing CAS object"
        assert "missing" in gone.stdout + gone.stderr

        victim.write_bytes(corrupt)         # back to tampered for the client leg
        _need_fuse()
        with _mount(repo, port) as (mnt, _proc):
            if not os.path.ismount(mnt):
                return                      # refusing to mount is also correct
            for rel in PAYLOAD:
                path = mnt / rel
                try:
                    if path.exists():
                        path.read_bytes()
                except OSError:
                    return                  # the tampered object was refused
            pytest.fail("tampered object served to the client without error")
    finally:
        victim.write_bytes(clean)
        assert "fsck clean" in repo_cmd("fsck", str(repo), "--data").stdout


def test_personality_does_not_leak_to_other_names(tmp_path):
    """Only argv[0] == brixcvmfs gets the cvmfs driver without a type token."""
    alias = tmp_path / "brixmountain"          # a name that is NOT brixcvmfs
    os.symlink(os.path.join(_CLIENT_BIN, "brixMount"), alias)
    r = subprocess.run([str(alias), "repo"], capture_output=True, text=True)
    assert r.returncode == 2
    blob = r.stdout + r.stderr
    assert "usage: brixMount <type>" in blob, blob
    assert "repo mkfs" not in blob, "release-manager surface leaked to a foreign name"
