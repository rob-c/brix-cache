"""cvmfs × gridftp — the last protocol pair that had never shared a process.

Audit §B3.17 (docs/refactor/testsuite-combinatorial-coverage-audit-2026-08-15.md):
"the only proto×proto pair with zero co-residence (every other protocol pair is
co-tested somewhere, including via the multiproto configs)".  The reason is
structural rather than accidental: ``brix_cvmfs`` is an ``http{}`` content
handler bound to a location, ``brix_gridftp`` is a ``stream{}`` server with no
location concept at all, so the two never meet in any config the tree ships.
The multiproto fronts co-host http protocols; the xrootd fronts co-host stream
protocols; nothing put one of each in a single worker.

This module does, over ONE export root — which is the realistic deployment and
the only arrangement in which the planes can disagree.  A Stratum-0 host that
also runs GridFTP is how a release manager publishes: bytes in over FTP, bytes
out over http, one directory tree.  Standing both planes on it turns three
questions into assertions:

  success:      one master, one worker, both protocols answering; the manifest
                and a CAS object are byte-identical whichever plane serves
                them; a `repo publish` against the live tree lands on both
                planes with no reload.
  error:        a well-formed but absent object is 404 on http and 550 on FTP;
                an unknown repository is refused on both; the read-only FTP
                face refuses STOR while the http plane is refusing writes with
                405 — the two "no"s have different reasons and both hold.
  security-neg: neither plane escapes the shared root; and the two planes do
                NOT agree on what is publishable — see DEFECT CANDIDATE #28.

DEFECT CANDIDATE #28 — the http plane classifies before it opens, the stream
plane does not classify at all.  ``brix_cvmfs_gate`` (src/protocols/cvmfs/
gate.c:478-489) rejects any URI that is "not a CVMFS traffic shape" with 403
BEFORE any path resolution runs, so ``keys/<fqrn>.masterkey`` — the repository's
private signing key, sitting inside the Stratum-0 root by construction
(``repo mkfs`` puts it there) — is structurally unreachable over http.
``brix_gridftp_export`` confines the tree and nothing else: the same file is one
anonymous RETR away on either FTP face.  Nothing warns at config-parse time that
an export root contains a repository's key material, and nothing in the docs
says the two roots must differ.

The counter-argument is real and worth stating: an operator who exports a
directory over FTP has exported everything in it, and no one calls that a bug
when the directory is /etc.  What makes this different is that these two modules
are *designed* to be co-hosted on one tree, and one of them carries an explicit
"these bytes never leave" rule that the other silently does not honour.  The
remedy is small — refuse (or warn on) a ``brix_gridftp_export`` whose subtree
contains a ``keys/*.masterkey``, or document the split-root requirement — so the
finding is recorded rather than assumed benign.

Run:
    PYTHONPATH=tests python3 -m pytest tests/test_audit15h_cvmfs_gridftp.py -v
"""

import ftplib
import io
import os
import sys

import pytest

# conftest chdir()s into a scratch dir — anchor the cvmfs helper import on this
# file's directory, exactly as the Stratum-0 quickstart lane does.
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "cvmfs"))

from conformance_common import request                     # noqa: E402
from server_registry import NginxInstanceSpec              # noqa: E402
from settings import BIND_HOST, NGINX_BIN, SERVER_HOST     # noqa: E402
from test_cvmfs_stratum0_quickstart import (               # noqa: E402
    BRIXCVMFS, _flip, _live_payload_object, repo_cmd)

pytestmark = [
    pytest.mark.timeout(180),
    pytest.mark.uses_lifecycle_harness,
    pytest.mark.xdist_group("audit15h_cvmfs_gridftp"),
    pytest.mark.skipif(not os.path.exists(NGINX_BIN),
                       reason=f"nginx binary not found: {NGINX_BIN}"),
    pytest.mark.skipif(not os.path.exists(BRIXCVMFS),
                       reason="brixcvmfs not built (run `make -C client brixcvmfs`)"),
]

NAME = "lc-audit15h-cvmfsftp"
FQRN = "audit15h.brix.io"

# Two payload files and a nested one: enough that `publish` produces more than a
# single CAS object, so _live_payload_object has a choice and the second
# revision has something of its own to add.
PAYLOAD = {
    "alpha.txt": b"alpha payload for the co-residence lane\n",
    "sub/beta.txt": b"beta payload, one level down\n",
}

DEFECT28 = (
    "DEFECT CANDIDATE #28 has been FIXED: the GridFTP export no longer hands "
    "out repository key material that the CVMFS plane refuses to serve.  Flip "
    "this expectation (to a refusal, or to a config-parse rejection of an "
    "export root containing keys/*.masterkey) and strike #28 from the audit.")


# ---------------------------------------------------------------------------
# fixtures
# ---------------------------------------------------------------------------
@pytest.fixture(scope="module")
def repo(tmp_path_factory):
    """One published Stratum-0 repository, built once for the whole module.

    Module scope is deliberate: `mkfs` generates an RSA master key and every
    `publish` re-signs the manifest, which is far and away the most expensive
    thing this file does.  The tests that mutate the tree (the tamper, the
    injection) restore what they touched; the one that publishes only ever adds
    a revision, and asserts against the state it read itself, so no test here
    depends on running before or after another.
    """
    web = tmp_path_factory.mktemp("cvmfsftp") / "web"
    (web / "cvmfs").mkdir(parents=True)
    path = web / "cvmfs" / FQRN                  # mkfs makes only the leaf

    repo_cmd("mkfs", FQRN, str(path))
    repo_cmd("transaction", str(path))
    upper = path / ".brixtxn" / "upper"
    for rel, content in PAYLOAD.items():
        target = upper / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(content)
    repo_cmd("publish", str(path), "--chunk-size", "4096")

    return web, path


@pytest.fixture
def planes(lifecycle, repo):
    """The co-resident instance: http Stratum-0 + two stream GridFTP faces."""
    web, _path = repo
    endpoint = lifecycle.start(NginxInstanceSpec(
        name=NAME,
        template="nginx_audit15h_cvmfsftp.conf",
        protocol="http",
        readiness="tcp",
        data_root=str(web),
        template_values={"BIND_HOST": BIND_HOST},
    ))
    _await_stream(endpoint.extra_ports["FTPRW_PORT"])
    _await_stream(endpoint.extra_ports["FTPRO_PORT"])
    return endpoint


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------
def _await_stream(port, attempts=100):
    """Readiness only probes the spec port; the stream faces need their own.

    Both planes belong to the same worker, so an http-ready worker has already
    bound the stream listeners — this is a cheap guard against the launcher
    declaring readiness on the listening socket before the worker is serving.
    """
    import socket
    import time
    for _ in range(attempts):
        try:
            with socket.create_connection((SERVER_HOST, port), timeout=1) as s:
                s.recv(64)                       # the 220 greeting
            return
        except OSError:
            time.sleep(0.05)
    pytest.fail(f"stream face on {port} never came up")


def _ftp(port):
    ftp = ftplib.FTP()
    ftp.connect(SERVER_HOST, port, timeout=30)
    ftp.login()                                  # USER anonymous / PASS
    return ftp


def _retr(port, path):
    ftp = _ftp(port)
    try:
        buf = bytearray()
        ftp.retrbinary(f"RETR {path}", buf.extend)
        return bytes(buf)
    finally:
        ftp.quit()


def _stor(port, path, data):
    ftp = _ftp(port)
    try:
        return ftp.storbinary(f"STOR {path}", io.BytesIO(data))
    finally:
        ftp.quit()


def _get(endpoint, uri):
    return request(SERVER_HOST, endpoint.port, "GET", uri)


def _rel(repo_path, obj):
    """A CAS object's path relative to the repository root."""
    return str(obj.relative_to(repo_path))


def _workers(pidfile):
    """The worker pids of the master named by `pidfile`, straight out of /proc."""
    master = int(pidfile.read_text().strip())
    kids = []
    for entry in os.listdir("/proc"):
        if not entry.isdigit():
            continue
        try:
            with open(f"/proc/{entry}/status") as fh:
                for line in fh:
                    if line.startswith("PPid:"):
                        if int(line.split()[1]) == master:
                            kids.append(int(entry))
                        break
        except OSError:
            continue                              # the process exited under us
    return master, kids


# ---------------------------------------------------------------------------
# SUCCESS — the two planes co-reside and agree
# ---------------------------------------------------------------------------
def test_one_worker_answers_on_both_planes(planes, repo):
    """A single worker process serves the http and the stream protocol at once.

    This is the claim the row exists for: not "both configs parse" but "one
    nginx worker has an http content handler and a stream server live in the
    same event loop, and both answer".
    """
    _web, path = repo
    pidfile = os.path.join(planes.prefix, "logs", "nginx.pid")
    assert os.path.exists(pidfile), "the co-resident nginx wrote no pid file"

    from pathlib import Path
    master, kids = _workers(Path(pidfile))
    assert len(kids) == 1, (
        f"expected exactly one worker under master {master}, got {kids}")

    manifest = (path / ".cvmfspublished").read_bytes()
    status, _hdrs, body = _get(planes, f"/cvmfs/{FQRN}/.cvmfspublished")
    assert status == 200 and body == manifest, (status, len(body))

    over_ftp = _retr(planes.extra_ports["FTPRW_PORT"],
                     f"cvmfs/{FQRN}/.cvmfspublished")
    assert over_ftp == manifest, "the FTP face served a different manifest"


def test_a_cas_object_is_byte_identical_on_both_planes(planes, repo):
    """The same content-addressed object, fetched two ways, is the same bytes."""
    _web, path = repo
    victim, clean = _live_payload_object(path)
    rel = _rel(path, victim)

    status, _hdrs, body = _get(planes, f"/cvmfs/{FQRN}/{rel}")
    assert status == 200, (status, rel)
    assert body == clean, "the http plane served something other than the object"

    assert _retr(planes.extra_ports["FTPRO_PORT"], f"cvmfs/{FQRN}/{rel}") == clean


def test_a_publish_lands_on_both_planes_without_a_reload(planes, repo):
    """A new revision published under a running server is live on both planes.

    Neither plane holds the tree open in a way that pins a revision: no reload,
    no cache flush, no restart between the publish and the two fetches.
    """
    _web, path = repo
    before = (path / ".cvmfspublished").read_bytes()

    repo_cmd("transaction", str(path))
    marker = b"published while both planes were serving\n"
    (path / ".brixtxn" / "upper" / "gamma.txt").write_bytes(marker)
    repo_cmd("publish", str(path))

    after = (path / ".cvmfspublished").read_bytes()
    assert after != before, "publish did not produce a new revision"

    status, _hdrs, body = _get(planes, f"/cvmfs/{FQRN}/.cvmfspublished")
    assert status == 200 and body == after, "the http plane served a stale manifest"

    assert _retr(planes.extra_ports["FTPRW_PORT"],
                 f"cvmfs/{FQRN}/.cvmfspublished") == after, \
        "the FTP face served a stale manifest"


# ---------------------------------------------------------------------------
# ERROR — each plane says no in its own dialect
# ---------------------------------------------------------------------------
def test_a_missing_object_is_a_404_on_http_and_a_550_on_ftp(planes, repo):
    """A well-formed CAS path that names nothing is absent on both planes.

    The shape matters: the http gate classifies first, so a MALFORMED path is
    403 ("not a CVMFS traffic shape") and never reaches the storage layer.  To
    prove the two planes agree about absence rather than about syntax, the
    probe keeps a real object's shape and changes only its digits.
    """
    _web, path = repo
    victim, _clean = _live_payload_object(path)
    rel = _rel(path, victim)
    head, _, name = rel.rpartition("/")
    ghost = f"{head}/{'0' * len(name)}"
    assert not (path / ghost).exists(), "the ghost object accidentally exists"

    status, _hdrs, _body = _get(planes, f"/cvmfs/{FQRN}/{ghost}")
    assert status == 404, f"absent object should be 404, got {status}"

    with pytest.raises(ftplib.error_perm) as err:
        _retr(planes.extra_ports["FTPRO_PORT"], f"cvmfs/{FQRN}/{ghost}")
    assert str(err.value).startswith("550"), str(err.value)


def test_an_unknown_repository_is_refused_on_both_planes(planes):
    """Neither plane invents a repository that was never published here."""
    status, _hdrs, _body = _get(planes, "/cvmfs/not-a-repo.brix.io/.cvmfspublished")
    assert status == 404, f"unknown repo should be 404, got {status}"

    with pytest.raises(ftplib.error_perm) as err:
        _retr(planes.extra_ports["FTPRO_PORT"],
              "cvmfs/not-a-repo.brix.io/.cvmfspublished")
    assert str(err.value).startswith("550"), str(err.value)


def test_the_http_plane_refuses_every_write_method(planes, repo):
    """The Stratum-0 front is read-only whatever verb is aimed at it.

    Co-residence widens the write surface of the tree — that is the FTP face's
    whole job — so it is worth pinning that it does NOT widen the http one.
    """
    _web, path = repo
    victim, _clean = _live_payload_object(path)
    rel = _rel(path, victim)
    for method in ("PUT", "DELETE", "MKCOL", "POST", "MOVE", "PROPPATCH"):
        status, _hdrs, _body = request(SERVER_HOST, planes.port, method,
                                       f"/cvmfs/{FQRN}/{rel}",
                                       body=b"x" if method == "PUT" else b"")
        assert status == 405, f"{method} on the Stratum-0 front returned {status}"


def test_the_read_only_ftp_face_cannot_write_into_the_repository(planes, repo):
    """`brix_gridftp_allow_write` off is the mitigation, and it holds.

    The bytes are unchanged afterwards on the http plane too — the refusal is a
    refusal to open, not a truncate-then-fail.
    """
    _web, path = repo
    victim, clean = _live_payload_object(path)
    rel = _rel(path, victim)

    with pytest.raises(ftplib.error_perm) as err:
        _stor(planes.extra_ports["FTPRO_PORT"], f"cvmfs/{FQRN}/{rel}", b"overwritten")
    assert "read-only" in str(err.value), str(err.value)

    status, _hdrs, body = _get(planes, f"/cvmfs/{FQRN}/{rel}")
    assert status == 200 and body == clean, "the refused STOR still changed the object"


# ---------------------------------------------------------------------------
# SECURITY-NEGATIVE — confinement, and where the two planes part company
# ---------------------------------------------------------------------------
def test_neither_plane_escapes_the_shared_root(planes, repo):
    """Traversal out of the export/Stratum-0 root fails on http and on FTP.

    The http probe goes out as a raw request line so the `..` segments reach
    nginx verbatim — an http.client-style API would normalise them away and the
    test would prove nothing.  On that plane the refusal is structural rather
    than a path check: any traversal breaks the CVMFS URI shape, so the gate
    turns it away before resolution — which is exactly the confinement claim.
    On the FTP faces there is no shape to break, so the export-root check is
    doing the work, and both faces are probed because only one of them is
    read-only.
    """
    web, _path = repo
    outside = web.parent / "outside.txt"
    outside.write_bytes(b"never serve me\n")
    try:
        for uri in (f"/cvmfs/{FQRN}/../../outside.txt",
                    f"/cvmfs/{FQRN}/%2e%2e/%2e%2e/outside.txt",
                    "/cvmfs/../outside.txt"):
            status, _hdrs, body = _get(planes, uri)
            assert status != 200, f"{uri} escaped the Stratum-0 root ({status})"
            assert b"never serve me" not in body, uri

        for port in (planes.extra_ports["FTPRW_PORT"],
                     planes.extra_ports["FTPRO_PORT"]):
            with pytest.raises(ftplib.error_perm):
                _retr(port, "../outside.txt")
            with pytest.raises(ftplib.error_perm):
                _retr(port, f"cvmfs/{FQRN}/../../../outside.txt")
    finally:
        outside.unlink()


def test_the_ftp_plane_hands_out_the_signing_key_the_http_plane_hides(planes, repo):
    """DEFECT CANDIDATE #28 — the planes disagree about what is publishable.

    `repo mkfs` puts the repository's master private key inside the Stratum-0
    root (keys/<fqrn>.masterkey).  The http plane will not serve it at any
    price: the gate rejects the path shape before storage is ever consulted.
    An anonymous FTP client on the very same tree reads it whole — from the
    read-only face, so this is not about write permission.
    """
    _web, path = repo
    key = path / "keys" / f"{FQRN}.masterkey"
    assert key.exists(), "mkfs did not leave a master key where it used to"

    status, _hdrs, _body = _get(planes, f"/cvmfs/{FQRN}/keys/{FQRN}.masterkey")
    assert status == 403, f"the http plane should reject the shape, got {status}"

    got = _retr(planes.extra_ports["FTPRO_PORT"], f"cvmfs/{FQRN}/keys/{FQRN}.masterkey")
    assert got == key.read_bytes(), DEFECT28
    assert b"PRIVATE KEY" in got, DEFECT28


def test_a_tampered_object_is_served_unverified_but_fsck_finds_it(planes, repo):
    """The write face can rewrite a CAS object, and http serves the new bytes.

    Content addressing is verified by the *client*, not by the origin — so the
    honest bound on this hazard is what the repository's own auditor sees.
    `repo fsck --data` catches it, which is what makes a writable export over a
    Stratum-0 root an operational risk rather than a silent one.
    """
    _web, path = repo
    victim, clean = _live_payload_object(path)
    rel = _rel(path, victim)
    try:
        _stor(planes.extra_ports["FTPRW_PORT"], f"cvmfs/{FQRN}/{rel}",
              b"TAMPERED-BY-THE-FTP-PLANE\n")
        assert victim.read_bytes() == b"TAMPERED-BY-THE-FTP-PLANE\n"

        status, _hdrs, body = _get(planes, f"/cvmfs/{FQRN}/{rel}")
        assert status == 200 and body == b"TAMPERED-BY-THE-FTP-PLANE\n", \
            "the http plane did not serve what the FTP plane wrote"

        bad = repo_cmd("fsck", str(path), "--data", expect_ok=False)
        assert bad.returncode != 0, "fsck --data accepted an FTP-tampered object"
        assert "fails CAS verification" in bad.stdout + bad.stderr
    finally:
        victim.write_bytes(clean)

    status, _hdrs, body = _get(planes, f"/cvmfs/{FQRN}/{rel}")
    assert status == 200 and body == clean, "the restore did not take"


def test_an_ftp_injected_object_is_served_under_a_name_it_does_not_own(planes, repo):
    """A brand-new object dropped in over FTP is served without verification.

    The bound is the same as above and worth stating separately: the origin
    checks the URI's *shape*, never the digest, so the FTP plane can add CAS
    entries at will.  They are inert to a real client — nothing in any signed
    catalog points at them, and a client that did ask would compute the hash and
    reject the bytes — but they are reachable, which is why the tamper path
    above needs `fsck --data` rather than the origin to notice.
    """
    _web, path = repo
    victim, _clean = _live_payload_object(path)
    head, _, name = _rel(path, victim).rpartition("/")
    forged = f"{head}/{'f' * len(name)}"
    assert not (path / forged).exists()

    try:
        _stor(planes.extra_ports["FTPRW_PORT"], f"cvmfs/{FQRN}/{forged}",
              b"injected-object\n")
        status, _hdrs, body = _get(planes, f"/cvmfs/{FQRN}/{forged}")
        assert status == 200 and body == b"injected-object\n", (status, forged)

        # ...and the repository's own auditor is untroubled: no live catalog
        # names it, so it is not part of the published revision at all.
        clean = repo_cmd("fsck", str(path), "--data")
        assert "fsck clean" in clean.stdout, clean.stdout
    finally:
        (path / forged).unlink(missing_ok=True)
