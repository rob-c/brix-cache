"""Phase-115 W5.4 — same-origin server copy on the outbound FTP/GridFTP driver.

Until this shipped, the gsiftp driver's `server_copy` slot was NULL, and a NULL
slot is not a slow path — `brix_vfs_copy_driver` turns it into ENOTSUP.  A
client that wanted /a copied to /b on a gsiftp-backed export had to GET the
whole object and PUT it back: the bytes crossed its link twice, and the copy was
only as durable as that one client's connection.

What ships is a GATEWAY RELAY, not origin-side zero-copy — the same shape as
`sd_xroot_copy_body`.  The bytes still move, they just never leave the
gateway<->origin link.  Two properties make that worth having and both are
asserted here rather than assumed:

  * **The destination appears whole or not at all.**  Publication is a STOR to a
    random temp name followed by RNFR/RNTO, so a failed copy leaves the
    destination's previous bytes untouched instead of half-replaced.  Storing
    straight onto the destination would destroy a good object for the length of
    every transfer, and permanently for a failed one.
  * **A short origin answer is never published.**  `gftp_retrieve` is a BOUNDED
    read: an origin that stops early produces a shorter file and no error of its
    own.  The size from the pre-transfer stat is therefore both the request and
    the acceptance test.

The security negative is the read-only front.  A COPY is a mutation of the
DESTINATION, so the typed VFS mutation policy must refuse it before any FTP
command is written — and the origin's own command log is what proves "before",
which no HTTP status code can.

GridFTP-over-SSH, W5.4's other half, is deferred; the reasons and the tree-level
boundary that keeps them honest live in
tests/test_phase115_gsiftp_server_copy_static.py.
"""

from __future__ import annotations

import http.client
import os
from pathlib import Path
import sys

import pytest

from fleet_lifecycle_ports import lifecycle_ports_for
from server_launcher import LifecycleHarness
from server_registry import NginxInstanceSpec
from settings import BIND_HOST, NGINX_BIN, SERVER_HOST


pytestmark = [
    pytest.mark.serial,
    pytest.mark.timeout(300),
    pytest.mark.uses_lifecycle_harness,
    pytest.mark.xdist_group("lc-p115-copy"),
]

# Position-revealing, and larger than one MODE E block so a copy that loses or
# reorders a block says WHICH one rather than merely comparing unequal.
PAYLOAD = bytes(range(256)) * 1200          # 307200 bytes


def _dav(port: int, method: str, path: str,
         headers: dict[str, str] | None = None):
    """(status, body) for one WebDAV request — no requests-lib dependency."""
    connection = http.client.HTTPConnection(SERVER_HOST, port, timeout=90)
    try:
        connection.request(method, path, headers=headers or {})
        response = connection.getresponse()
        return response.status, response.read()
    finally:
        connection.close()


def _copy(port: int, src: str, dst: str, overwrite: str = "T"):
    """COPY `src` to `dst` on one front, with the destination as a URL.

    The Destination header is absolute because that is what RFC 4918 says a
    client sends; a relative form would be testing our tolerance, not the copy.
    """
    return _dav(port, "COPY", src, {
        "Destination": f"http://{SERVER_HOST}:{port}{dst}",
        "Overwrite": overwrite,
    })


def _move(port: int, src: str, dst: str, overwrite: str = "T"):
    """MOVE, spelled exactly like _copy — the two share one refusal predicate."""
    return _dav(port, "MOVE", src, {
        "Destination": f"http://{SERVER_HOST}:{port}{dst}",
        "Overwrite": overwrite,
    })


def _get(port: int, path: str):
    return _dav(port, "GET", path)


def _audit(path: Path) -> list[str]:
    """The origin's command log — the only place "before any FTP" is a fact."""
    if not path.exists():
        return []
    return path.read_text(encoding="utf-8", errors="replace").splitlines()


def _verbs(lines: list[str], *wanted: str) -> list[str]:
    """Just the verbs of interest, in order — the shape of one copy."""
    return [line.split(" ", 1)[0] for line in lines
            if line.split(" ", 1)[0] in wanted]


class _CopyLab:
    """One origin, three fronts: read/write, read-only, and a deeper root."""

    def __init__(self, harness: LifecycleHarness, root: Path, tmp: Path):
        port, _ = lifecycle_ports_for("lc-p115-copy-origin")
        self.audit = tmp / "origin.log"
        origin = harness.start(self._origin(port, root, self.audit))
        for name in ("copy-export", "sub-export"):
            (tmp / name).mkdir()
        endpoint = harness.start(NginxInstanceSpec(
            name="lc-p115-copy",
            template="nginx_lc_gsiftp_copy.conf",
            protocol="http",
            readiness="tcp",
            template_values={
                "BIND_HOST": BIND_HOST,
                "ORIGIN_PORT": origin.port,
                "ORIGIN_BASE": "/base",
                "COPY_EXPORT": str(tmp / "copy-export"),
                "SUB_EXPORT": str(tmp / "sub-export"),
            },
            reason="three WebDAV fronts over ONE GridFTP origin: read/write, "
                   "read-only, and one rooted a directory deeper",
        ))
        self.harness = harness
        self.port = endpoint.port
        self.ro_port = endpoint.extra_ports["RO_PORT"]
        self.sub_port = endpoint.extra_ports["SUB_PORT"]
        self.error_log = Path(endpoint.prefix, "logs", "error.log")
        self.root = root

    @staticmethod
    def _origin(port, root, audit):
        argv = [sys.executable, "-m", "brix_suite.servers.ftp_origin_server",
                str(port), str(root), "--audit", str(audit)]
        return NginxInstanceSpec(
            name="lc-p115-copy-origin",
            template="",
            kind="proc",
            protocol="ftp",
            readiness="tcp",
            data_root=str(root),
            template_values={"argv": argv},
            env={"PYTHONPATH": os.path.dirname(__file__)},
            reason="confined GridFTP origin serving all three copy fronts",
        )

    def close(self):
        self.harness.close()


@pytest.fixture(scope="module")
def lab(tmp_path_factory):
    if not os.access(NGINX_BIN, os.X_OK):
        pytest.skip(f"nginx not executable: {NGINX_BIN}")
    tmp = tmp_path_factory.mktemp("p115-copy")
    root = tmp / "origin"
    (root / "base" / "sub").mkdir(parents=True)
    (root / "base" / "source.bin").write_bytes(PAYLOAD)
    (root / "base" / "victim.bin").write_bytes(b"the previous contents")
    (root / "base" / "sub" / "deep.bin").write_bytes(PAYLOAD)
    harness = LifecycleHarness()
    lab = _CopyLab(harness, root, tmp)
    yield lab
    lab.close()


# ---- success: the destination is byte-exact and the source survives ---------

def test_a_copy_lands_byte_exact(lab):
    """The whole point: /dst holds /src's bytes and /src is still there.

    Both halves, because a "copy" implemented as a rename would satisfy the
    first alone — and the driver already HAS a rename, so the confusion is a
    real one rather than a theoretical one.
    """
    status, _ = _copy(lab.port, "/source.bin", "/landed.bin")
    assert status in (201, 204), status
    assert _get(lab.port, "/landed.bin") == (200, PAYLOAD)
    assert _get(lab.port, "/source.bin") == (200, PAYLOAD)


def test_the_copy_ran_on_the_origin_and_not_through_the_client(lab):
    """The gateway relayed it: one RETR and one STOR reached the origin.

    A byte-exact destination proves nothing about WHERE the bytes went — the
    same result would follow from the client having done GET+PUT itself.  The
    origin's log is the only witness that the copy happened server-side.
    """
    before = len(_audit(lab.audit))
    status, _ = _copy(lab.port, "/source.bin", "/relayed.bin")
    assert status in (201, 204), status
    lines = _audit(lab.audit)[before:]
    assert _verbs(lines, "RETR").count("RETR") == 1, lines
    assert _verbs(lines, "STOR").count("STOR") == 1, lines


def test_the_destination_is_published_by_rename(lab):
    """STOR goes to a temp name and RNFR/RNTO publishes it.

    Visible only in the origin's log: the HTTP result of an atomic publish and
    of a bare overwriting STOR are identical, and so is the final content on a
    SUCCESSFUL copy.  The difference only shows up when a transfer fails, which
    is exactly when it is too late to find out.
    """
    before = len(_audit(lab.audit))
    status, _ = _copy(lab.port, "/source.bin", "/published.bin")
    assert status in (201, 204), status
    lines = _audit(lab.audit)[before:]
    assert _verbs(lines, "STOR", "RNFR", "RNTO") == ["STOR", "RNFR", "RNTO"], \
        f"the copy no longer publishes atomically: {lines}"
    stor = [line for line in lines if line.startswith("STOR ")][0]
    assert not stor.endswith("/published.bin"), \
        f"the copy stored directly onto its destination: {stor}"


def test_an_overwriting_copy_replaces_the_whole_object(lab):
    """The destination exists and ends up holding the source's bytes."""
    assert _get(lab.port, "/victim.bin")[1] == b"the previous contents"
    status, _ = _copy(lab.port, "/source.bin", "/victim.bin")
    assert status in (201, 204), status
    assert _get(lab.port, "/victim.bin") == (200, PAYLOAD)


def test_a_copy_between_two_exports_of_one_origin_is_still_one_session(lab):
    """"Same origin" means one driver instance, not one hostname.

    The deeper-rooted front reaches the same origin process through its own
    export, and a copy WITHIN it must still be served by the same one-session
    relay rather than falling back to anything client-mediated.
    """
    before = len(_audit(lab.audit))
    status, _ = _copy(lab.sub_port, "/deep.bin", "/deep-copy.bin")
    assert status in (201, 204), status

    # Snapshotted HERE, before the verification GET: that GET is a read of the
    # object through the same origin and issues retrieves of its own, so a
    # window that spanned it would be counting the reader's work as the
    # copier's.  The claim under test is about the COPY's command sequence.
    lines = _audit(lab.audit)[before:]
    assert _verbs(lines, "RETR").count("RETR") == 1, lines

    assert _get(lab.sub_port, "/deep-copy.bin") == (200, PAYLOAD)


# ---- error: a copy that cannot be made must not invent a destination --------

def test_a_copy_of_a_missing_source_is_a_404(lab):
    """And it costs no destination: nothing may be created from nothing."""
    status, _ = _copy(lab.port, "/not-there.bin", "/ghost.bin")
    assert status == 404, status
    assert _get(lab.port, "/ghost.bin")[0] == 404


def test_a_missing_source_is_refused_before_any_transfer(lab):
    """One stat, then stop — no scratch file and no data channel.

    The stat is deliberately taken before `tmpfile()`, so a copy of a path that
    is not there costs one round trip and no local disk.
    """
    before = len(_audit(lab.audit))
    _copy(lab.port, "/also-not-there.bin", "/ghost2.bin")
    lines = _audit(lab.audit)[before:]
    assert _verbs(lines, "RETR", "STOR") == [], \
        f"a copy of a missing source still opened a transfer: {lines}"


def test_a_copy_onto_its_own_path_is_refused(lab):
    """It would work, and it would rewrite a healthy object for no gain.

    Scratch, temp, rename over the original — and any failure in the middle
    damages the only copy of a file the caller never asked to modify.  The
    source must be intact afterwards, which is the assertion that matters more
    than the status code.
    """
    status, _ = _copy(lab.port, "/source.bin", "/source.bin")
    assert status in (403, 409, 500, 502), status
    assert _get(lab.port, "/source.bin") == (200, PAYLOAD)


def test_an_existing_destination_is_not_mistaken_for_the_source(lab):
    """Defect #4, on the namespace where it bit: a remote export has no inodes.

    The WebDAV self-target guard used to be `(dev,ino)` equality and nothing
    else.  The gsiftp driver never fills `brix_vfs_stat_t.ino/.dev`, so every
    path here stats as (0,0) and the guard answered "source and destination are
    the same file" for EVERY destination that already existed — every ordinary
    overwrite on this export was a 403.  The refusal is still correct for the
    real thing, which is why both halves are asserted together: a fix that only
    stopped refusing would have removed the guard.
    """
    assert _get(lab.port, "/source.bin")[0] == 200
    assert _copy(lab.port, "/source.bin", "/first-dst.bin")[0] in (201, 204)
    assert _copy(lab.port, "/source.bin", "/first-dst.bin")[0] in (201, 204), \
        "the second copy onto a now-EXISTING destination was refused — the "\
        "same-object guard is reading inodes this namespace does not have"
    assert _get(lab.port, "/first-dst.bin") == (200, PAYLOAD)
    assert _copy(lab.port, "/source.bin", "/source.bin")[0] in (403, 409), \
        "the guard stopped refusing a genuine copy onto the source"


def test_a_move_onto_an_existing_destination_replaces_it(lab):
    """MOVE shares the predicate, so it shared the bug.

    Asserted through the same front rather than by reading move.c: the two
    verbs reached the guard by different call paths, and only COPY's was found
    the first time.
    """
    assert _copy(lab.port, "/source.bin", "/mv-victim.bin")[0] in (201, 204)
    assert _copy(lab.port, "/source.bin", "/mv-src.bin")[0] in (201, 204)
    status, _ = _move(lab.port, "/mv-src.bin", "/mv-victim.bin")
    assert status in (201, 204), status
    assert _get(lab.port, "/mv-victim.bin") == (200, PAYLOAD)
    assert _get(lab.port, "/mv-src.bin")[0] == 404


def test_a_move_onto_its_own_path_is_still_refused(lab):
    """The security-negative for the MOVE half: the guard did not go away.

    A rename onto the source is a no-op at best; through the Overwrite:T
    replace-a-collection path it removes the destination tree BEFORE the
    rename, so a self-move is how a directory disappears.
    """
    status, _ = _move(lab.port, "/source.bin", "/source.bin")
    assert status in (403, 409), status
    assert _get(lab.port, "/source.bin") == (200, PAYLOAD)


def test_a_failed_copy_leaves_the_destination_untouched(lab):
    """A copy that cannot complete must not damage what was already there."""
    status, _ = _copy(lab.port, "/gone.bin", "/victim.bin")
    assert status == 404, status
    assert _get(lab.port, "/victim.bin") == (200, PAYLOAD)


# ---- security: the read-only export refuses before the wire ------------------

def test_the_read_only_export_refuses_the_copy(lab):
    """Same origin, same export path, one directive apart.

    A COPY is a mutation of the DESTINATION, so `brix_read_only on` must refuse
    it — and with EROFS's status, not an authentication failure, because the
    request was not unauthorised, it was impossible.
    """
    status, _ = _copy(lab.ro_port, "/source.bin", "/forbidden.bin")
    assert status in (403, 405), status
    assert _get(lab.port, "/forbidden.bin")[0] == 404, \
        "the read-only front created an object on the shared origin"


def test_the_refusal_happens_before_any_ftp_command(lab):
    """THE security assertion: the policy runs first, not the transfer.

    A refusal issued after the source had been pulled would still return 403 and
    still leave no destination — and would still have spent the origin's bytes
    and this gateway's disk on a request policy had already denied.  Only the
    origin's command log can tell the two apart.
    """
    before = len(_audit(lab.audit))
    status, _ = _copy(lab.ro_port, "/source.bin", "/forbidden2.bin")
    assert status in (403, 405), status
    lines = _audit(lab.audit)[before:]
    assert lines == [], \
        f"the read-only export reached the origin before refusing: {lines}"


def test_the_read_only_front_still_reads(lab):
    """The negative has to be about the mutation, not about a dead listener.

    Without this row a front that refused everything — a typo in the export, a
    backend that never came up — would pass the two rows above and prove
    nothing at all about the mutation policy.
    """
    assert _get(lab.ro_port, "/source.bin") == (200, PAYLOAD)
