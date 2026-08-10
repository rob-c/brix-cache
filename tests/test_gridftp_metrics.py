"""GridFTP gateway → the shared unified metrics zone (``{proto="gridftp"}``).

The gateway is a stream module and the exporter is an HTTP location, but both
sit in one nginx process and the metrics zone is process-wide — so this suite
drives gsiftp verbs on the stream port and scrapes the resulting rows over HTTP.
Anything asserted here is therefore an end-to-end proof of the seam, not of a
unit.

The ownership split under test (see ``src/protocols/gridftp/ev/ftp_ev_metrics.c``
and Pattern 6 in ``docs/08-metrics-monitoring/metrics-bug-patterns.md``):

* the **protocol** owns the data plane — RETR books ``op="read"``, STOR/APPE book
  ``op="write"``, each exactly once per transfer, with bytes and latency;
* the **VFS** owns the namespace — LIST/SIZE/MKD/DELE are metered inside
  ``brix_vfs_*`` and must NOT be booked again by the gateway;
* both are stamped ``proto="gridftp"``.  That last point is a regression guard:
  the gateway's VFS contexts used to carry ``BRIX_PROTO_ROOT``, so every gsiftp
  namespace op was silently attributed to the native ``root://`` plane.

Each behaviour is covered on a success path, an error path and a
security-negative path (read-only export, path traversal).

Run:
    PYTHONPATH=tests python3 -m pytest tests/test_gridftp_metrics.py -v -p no:xdist
"""

from __future__ import annotations

import ftplib
import io
import os
import urllib.request

import pytest

from metrics_helpers import value as metric_value
from settings import BIND_HOST, NGINX_BIN, SERVER_HOST
from server_launcher import LifecycleHarness
from server_registry import NginxInstanceSpec

pytestmark = [pytest.mark.serial, pytest.mark.timeout(180),
              pytest.mark.uses_lifecycle_harness,
              pytest.mark.xdist_group("lc-gridftp-metrics")]


# --------------------------------------------------------------------------- #
# Fixture                                                                      #
# --------------------------------------------------------------------------- #
class _Gateway:
    """One nginx: a writable gsiftp gateway, a read-only one, and /metrics."""

    def __init__(self, harness, ro_root):
        endpoint = harness.start(NginxInstanceSpec(
            name="lc-gridftp-metrics",
            template="nginx_gridftp_metrics.conf",
            protocol="root",
            readiness="tcp",
            template_values={"BIND_HOST": BIND_HOST, "RO_ROOT": str(ro_root)},
            reason="gridftp unified-metrics seam ({proto=\"gridftp\"})"))
        self.harness = harness
        self.port = endpoint.port
        self.ro_port = endpoint.extra_ports["RO_PORT"]
        self.metrics_url = (f"http://{SERVER_HOST}:"
                            f"{endpoint.extra_ports['HTTP_PORT']}/metrics")
        self.export = endpoint.data_root
        self.ro_export = str(ro_root)

    def scrape(self) -> str:
        """Raw /metrics text.

        ``metrics_helpers.fetch()`` is pinned to the session fleet's
        ``NGINX_METRICS_PORT``; this instance owns its own endpoint, so only the
        GET is local — the parsing below is the shared ``metrics_helpers.value``.
        """
        with urllib.request.urlopen(self.metrics_url, timeout=30) as resp:
            return resp.read().decode()

    def close(self):
        self.harness.close()


@pytest.fixture(scope="module")
def gw(tmp_path_factory):
    if not os.access(NGINX_BIN, os.X_OK):
        pytest.skip(f"nginx not executable: {NGINX_BIN}")
    ro_root = tmp_path_factory.mktemp("gridftp-metrics-ro")
    (ro_root / "readonly.bin").write_bytes(b"R" * 512)
    gateway = _Gateway(LifecycleHarness(), ro_root)
    yield gateway
    gateway.close()


# --------------------------------------------------------------------------- #
# Scrape helpers                                                               #
# --------------------------------------------------------------------------- #
def _series(text, name, **labels):
    """One labelled sample, with an absent series read as 0.

    Absence is not a failure here: every assertion is a *delta*, and a family
    that never appears at all fails the ``after`` side just as loudly.
    """
    found = metric_value(text, name, labels)
    return 0 if found == -1 else found


def _ops(text, proto, op, status):
    return _series(text, "brix_io_ops_total", proto=proto, op=op, status=status)


def _bytes(text, direction, proto="gridftp"):
    return _series(text, f"brix_io_bytes_{direction}", proto=proto)


def _latency_count(text, proto, op):
    return _series(text, "brix_io_latency_usec_count", proto=proto, op=op)


def _auth(text, method, status, proto="gridftp"):
    return _series(text, "brix_auth_total", proto=proto, method=method,
                   status=status)


def _connect(gw, port=None):
    ftp = ftplib.FTP()
    ftp.connect(SERVER_HOST, port or gw.port, timeout=30)
    ftp.login()
    return ftp


def _seed(gw, name, data):
    path = os.path.join(gw.export, name)
    with open(path, "wb") as fh:
        fh.write(data)
    return path


# --------------------------------------------------------------------------- #
# Success — the data plane books one row, with bytes and latency               #
# --------------------------------------------------------------------------- #
def test_retr_books_one_read_row_with_bytes(gw):
    payload = b"A" * 4096
    _seed(gw, "retr-metrics.bin", payload)
    before = gw.scrape()

    ftp = _connect(gw)
    try:
        sink = io.BytesIO()
        ftp.retrbinary("RETR retr-metrics.bin", sink.write)
        assert sink.getvalue() == payload
    finally:
        ftp.quit()

    after = gw.scrape()
    assert (_ops(after, "gridftp", "read", "ok")
            - _ops(before, "gridftp", "read", "ok")) == 1, "one ok read row"
    assert (_bytes(after, "read") - _bytes(before, "read")) == len(payload)
    # A completed transfer carries an honest duration, so it is a latency
    # observation and not a bare count (brix_metric_op_done, not _op_count).
    assert (_latency_count(after, "gridftp", "read")
            - _latency_count(before, "gridftp", "read")) == 1
    # The gateway is its own protocol: a gsiftp RETR must not land on root://.
    assert (_ops(after, "stream", "read", "ok")
            - _ops(before, "stream", "read", "ok")) == 0


def test_stor_books_one_write_row_with_bytes(gw):
    payload = b"B" * 8192
    before = gw.scrape()

    ftp = _connect(gw)
    try:
        ftp.storbinary("STOR stor-metrics.bin", io.BytesIO(payload))
    finally:
        ftp.quit()

    after = gw.scrape()
    assert (_ops(after, "gridftp", "write", "ok")
            - _ops(before, "gridftp", "write", "ok")) == 1, "one ok write row"
    assert (_bytes(after, "written") - _bytes(before, "written")) == len(payload)
    assert (_latency_count(after, "gridftp", "write")
            - _latency_count(before, "gridftp", "write")) == 1


def test_namespace_ops_are_booked_by_the_vfs_under_gridftp(gw):
    """LIST is a VFS-owned dirlist row — stamped gridftp, booked exactly once.

    This is the regression guard for the old ``BRIX_PROTO_ROOT`` context: the
    row must move to ``proto="gridftp"`` and must NOT be double-booked by the
    protocol seam on top of the VFS observer.
    """
    _seed(gw, "listed.bin", b"L" * 16)
    before = gw.scrape()

    ftp = _connect(gw)
    try:
        ftp.retrlines("LIST", lambda _line: None)
    finally:
        ftp.quit()

    after = gw.scrape()
    delta = (_ops(after, "gridftp", "dirlist", "ok")
             - _ops(before, "gridftp", "dirlist", "ok"))
    assert delta == 1, f"expected exactly one dirlist row, got {delta}"
    assert (_ops(after, "stream", "dirlist", "ok")
            - _ops(before, "stream", "dirlist", "ok")) == 0, \
        "gsiftp namespace ops must not be attributed to root://"


def test_cleartext_login_books_an_auth_row(gw):
    before = gw.scrape()
    _connect(gw).quit()
    after = gw.scrape()
    assert (_auth(after, "none", "ok") - _auth(before, "none", "ok")) == 1
    assert (_auth(after, "gsi", "ok") - _auth(before, "gsi", "ok")) == 0


# --------------------------------------------------------------------------- #
# Error — a refused transfer is a row, not silence                             #
# --------------------------------------------------------------------------- #
def test_retr_of_absent_file_books_not_found_and_no_bytes(gw):
    before = gw.scrape()

    ftp = _connect(gw)
    try:
        with pytest.raises(ftplib.error_perm):
            ftp.retrbinary("RETR nowhere-at-all.bin", lambda _b: None)
    finally:
        ftp.quit()

    after = gw.scrape()
    assert (_ops(after, "gridftp", "read", "not_found")
            - _ops(before, "gridftp", "read", "not_found")) == 1
    assert (_ops(after, "gridftp", "read", "ok")
            - _ops(before, "gridftp", "read", "ok")) == 0
    assert (_bytes(after, "read") - _bytes(before, "read")) == 0
    # Refused before a data channel existed: no duration to report, so the
    # refusal is counted (brix_metric_op_count) without falsifying the lowest
    # latency bucket.
    assert (_latency_count(after, "gridftp", "read")
            - _latency_count(before, "gridftp", "read")) == 0


# --------------------------------------------------------------------------- #
# Security-negative — denials are visible in /metrics                          #
# --------------------------------------------------------------------------- #
def test_read_only_export_refuses_stor_as_forbidden(gw):
    before = gw.scrape()

    ftp = _connect(gw, gw.ro_port)
    try:
        with pytest.raises(ftplib.error_perm):
            ftp.storbinary("STOR denied.bin", io.BytesIO(b"nope"))
    finally:
        ftp.quit()

    after = gw.scrape()
    assert (_ops(after, "gridftp", "write", "forbidden")
            - _ops(before, "gridftp", "write", "forbidden")) == 1
    assert (_ops(after, "gridftp", "write", "ok")
            - _ops(before, "gridftp", "write", "ok")) == 0
    assert (_bytes(after, "written") - _bytes(before, "written")) == 0
    assert not os.path.exists(os.path.join(gw.ro_export, "denied.bin"))


def test_path_traversal_retr_books_forbidden(gw):
    before = gw.scrape()

    ftp = _connect(gw)
    try:
        with pytest.raises(ftplib.error_perm):
            ftp.retrbinary("RETR ../../etc/passwd", lambda _b: None)
    finally:
        ftp.quit()

    after = gw.scrape()
    assert (_ops(after, "gridftp", "read", "forbidden")
            - _ops(before, "gridftp", "read", "forbidden")) == 1
    assert (_bytes(after, "read") - _bytes(before, "read")) == 0
