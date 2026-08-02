"""
GridFTP gateway — VO-ACL enforcement (phase-92, audit item :605).

Drives a *cleartext* brix GridFTP gateway configured with a single VO-ACL rule
(``brix_gridftp_require_vo /vodata atlas``) via Python's ``ftplib``.  The gate
lives in the one path choke point every namespace/transfer verb flows through
(``brix_ftp_ev_resolve``): after the path is confined + canonicalised it calls
``brix_check_vo_acl_identity`` with the session identity, exactly as the HTTP and
root:// planes do.

A cleartext control channel carries no VOMS VO, so this proves the two
authorization edges that do not depend on a GSI/VOMS handshake:

  * success       -- a path NOT covered by any rule is served normally (the
                     allow-all branch: no rule matches ``/open`` → 226).
  * error         -- a missing file on an uncovered path still 550s at resolve
                     time (the gate runs AFTER resolution and never masks or
                     mangles ordinary ENOENT handling).
  * security-neg  -- a path under the VO-gated ``/vodata`` prefix is refused 550
                     for a session with no VO — the secure default, never a
                     bypass.

The authorized-VO *allow* edge (a GSI proxy whose VOMS FQAN matches the rule)
needs a VOMS-carrying proxy and is covered by the GSI plane, not this cleartext
file; see docs/refactor/phase-92-open-work-audit.md item :605.

Run:
    PYTHONPATH=tests python3 -m pytest tests/test_gridftp_vo_acl.py -v -p no:xdist
"""

import ftplib
import os

import pytest

from settings import BIND_HOST, NGINX_BIN, SERVER_HOST
from server_launcher import LifecycleHarness
from server_registry import NginxInstanceSpec

pytestmark = [pytest.mark.serial, pytest.mark.timeout(180),
              pytest.mark.uses_lifecycle_harness]


def _require():
    if not os.access(NGINX_BIN, os.X_OK):
        pytest.skip(f"nginx not executable: {NGINX_BIN}")


class _Gateway:
    """A registry-owned cleartext FTP gateway with a VO-ACL rule."""

    def __init__(self, harness, name):
        endpoint = harness.start(NginxInstanceSpec(
            name=name,
            template="nginx_gridftp_vo.conf",
            protocol="root",
            readiness="tcp",
            template_values={"BIND_HOST": BIND_HOST},
        ))
        self.harness = harness
        self.port = endpoint.port
        self.export = endpoint.data_root

    def close(self):
        self.harness.close()


@pytest.fixture(scope="module")
def gateway():
    _require()
    gw = _Gateway(LifecycleHarness(), "gridftp-vo")
    # Seed one file inside the VO-gated prefix and one outside it.
    os.makedirs(os.path.join(gw.export, "vodata"), exist_ok=True)
    os.makedirs(os.path.join(gw.export, "open"), exist_ok=True)
    with open(os.path.join(gw.export, "vodata", "secret.txt"), "wb") as fh:
        fh.write(b"vo-gated-payload")
    with open(os.path.join(gw.export, "open", "pub.txt"), "wb") as fh:
        fh.write(b"public-payload")
    yield gw
    gw.close()


def _connect(gw):
    ftp = ftplib.FTP()
    ftp.connect(SERVER_HOST, gw.port, timeout=30)
    ftp.login()                                   # USER anonymous / PASS
    return ftp


# ---- success: uncovered path served normally (allow-all branch) ------------

def test_uncovered_path_allowed(gateway):
    """A path no rule covers is served normally — the gate allows it."""
    ftp = _connect(gateway)
    try:
        chunks = []
        ftp.retrbinary("RETR open/pub.txt", chunks.append)
        assert b"".join(chunks) == b"public-payload"
    finally:
        ftp.quit()


# ---- error: missing file on an uncovered path still 550s at resolve --------

def test_uncovered_missing_file_errors_normally(gateway):
    """The gate runs after resolution: an ENOENT on an uncovered path 550s as
    usual and is not masked or turned into a VO denial."""
    ftp = _connect(gateway)
    try:
        with pytest.raises(ftplib.error_perm) as e:
            ftp.retrbinary("RETR open/does-not-exist.txt", lambda _b: None)
        assert str(e.value).startswith("550")
    finally:
        ftp.quit()


# ---- security-neg: VO-gated prefix refused for a no-VO session -------------

def test_vo_gated_prefix_denied_without_vo(gateway):
    """A cleartext session carries no VOMS VO, so a file under the VO-gated
    ``/vodata`` prefix must be refused 550 — never served."""
    ftp = _connect(gateway)
    try:
        with pytest.raises(ftplib.error_perm) as e:
            ftp.retrbinary("RETR vodata/secret.txt", lambda _b: None)
        assert str(e.value).startswith("550")
    finally:
        ftp.quit()


def test_vo_gated_listing_denied_without_vo(gateway):
    """The gate covers every verb via the shared resolve choke point: listing
    the VO-gated directory is refused for a no-VO session just like RETR."""
    ftp = _connect(gateway)
    try:
        with pytest.raises(ftplib.error_perm) as e:
            ftp.retrlines("LIST vodata", lambda _l: None)
        assert str(e.value).startswith("550")
    finally:
        ftp.quit()
