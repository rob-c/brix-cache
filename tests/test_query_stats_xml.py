"""kXR_QStats stock XML shape (parity-audit §1.13).

Stock emits an XML ``<statistics>`` document whose root attributes
(tod/ver/src/tos/pgm/ins/pid/site) and per-section ``<stats id=...>`` blocks
monitoring consumers parse; BriX used to emit a divergent wrapper (spurious
``id=`` root attribute, missing tod/src/pid) with only two sections and
ignored the selector argument entirely.  Shapes and selector letters below
were verified live against stock 5.6.9 (a=all b=buff d=poll i=info l=link
p=protocol s=sched u=proc; unknown letters contribute nothing).

  * success   — full doc is well-formed XML with the stock root attributes,
                the BriX-fillable sections, and live counters (a read bumps
                the ops.rd counter)
  * error     — selector subsets honored: 'i' → info only, unknown letter →
                wrapper only (stock's empty-contribution behavior, NOT an
                error)
  * security  — a hostile oversized selector string stays a clean bounded
                well-formed document

Run:
    PYTHONPATH=tests pytest tests/test_query_stats_xml.py -v
"""

import os
import xml.etree.ElementTree as ET

import pytest

from settings import DATA_ROOT, NGINX_ANON_PORT
from _test_conf_pgio_helpers import (
    _handshake, _login, _open, _read_response, _read_drain, kXR_ok,
)
import struct

kXR_query = 3001
kXR_QStats = 1

pytestmark = [
    pytest.mark.requires_local_server,
    pytest.mark.timeout(60),
]


def _session():
    sock = _handshake("localhost", NGINX_ANON_PORT)
    _login(sock)
    return sock


def _stats(arg=b"a"):
    sock = _session()
    try:
        req = struct.pack("!2sHH2s4s8sI", b"\x00\x0a", kXR_query, kXR_QStats,
                          b"\x00\x00", b"\x00" * 4, b"\x00" * 8, len(arg))
        sock.sendall(req + arg)
        _sid, status, body = _read_response(sock)
        assert status == kXR_ok, f"QStats failed: {status}"
        return body.rstrip(b"\x00").decode("ascii")
    finally:
        sock.close()


def _section_ids(doc):
    return [s.get("id") for s in ET.fromstring(doc).findall("stats")]


class TestQStatsXml:

    def test_full_doc_stock_shape(self):
        """(success) well-formed XML, stock root attributes, expected
        sections, and numeric identity fields."""
        doc = _stats(b"a")
        root = ET.fromstring(doc)
        assert root.tag == "statistics"
        for attr in ("tod", "ver", "src", "tos", "pgm", "ins", "pid", "site"):
            assert attr in root.attrib, f"missing root attr {attr}: {doc[:120]}"
        assert "id" not in root.attrib, "spurious id= root attribute is back"
        assert int(root.get("tod")) >= int(root.get("tos"))
        assert int(root.get("pid")) > 0
        assert ":" in root.get("src")
        ids = _section_ids(doc)
        for want in ("info", "link", "xrootd", "sgen"):
            assert want in ids, f"section {want} missing: {ids}"

    def test_read_bumps_ops_counter(self):
        """(success, live counters) a served kXR_read increments ops/rd in the
        'p' (protocol) section."""
        name = "qstats-read.bin"
        os.makedirs(DATA_ROOT, exist_ok=True)
        with open(os.path.join(DATA_ROOT, name), "wb") as f:
            f.write(b"x" * 4096)
        try:
            def rd_counter():
                doc = _stats(b"p")
                return int(ET.fromstring(doc).find(
                    "stats[@id='xrootd']/ops/rd").text)
            before = rd_counter()
            sock = _session()
            _sid, st, body = _open(sock, "/" + name)
            assert st == kXR_ok
            _read_drain(sock, body[:4], 0, 4096)
            sock.close()
            assert rd_counter() >= before + 1, "ops/rd did not move"
        finally:
            os.remove(os.path.join(DATA_ROOT, name))

    def test_selector_subsets(self):
        """(error-shape) 'i' yields ONLY info; an unknown letter yields the
        bare wrapper — stock's empty contribution, not an error."""
        assert _section_ids(_stats(b"i")) == ["info"]
        assert _section_ids(_stats(b"l")) == ["link"]
        assert _section_ids(_stats(b"z")) == []
        both = _section_ids(_stats(b"il"))
        assert set(both) == {"info", "link"}, both

    def test_hostile_selector_bounded(self):
        """(security-neg) 400 junk selector bytes: still one clean bounded
        well-formed document."""
        doc = _stats(b"q" * 400)
        root = ET.fromstring(doc)
        assert root.tag == "statistics"
        assert len(doc) < 4096
        assert _section_ids(doc) == []
