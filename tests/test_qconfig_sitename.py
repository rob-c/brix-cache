"""kXR_Qconfig `sitename` key + the brix_sitename directive — parity audit §2.18.

Stock `xrdfs query config sitename` returns all.sitename — the human-readable
site/node identity monitoring and federation tooling use to label a server.
BriX previously had no way to set a sitename at all (the advertise.sitename
field existed but no directive wired it — the whole brix_cache_advertise family
is unreachable), and Qconfig fell through to echoing the literal key. This adds:

  * the `brix_sitename <name>` directive (populates the advertise.sitename slot,
    which the Pelican advertiser already reads once that feature is wired), and
  * a Qconfig `sitename` emitter that reports it — or echoes the key when unset,
    byte-identical to the pre-existing default branch (zero regression).

Coverage: configured ⇒ the name; unset ⇒ the key echo; the directive is accepted
by `nginx -t`. Self-contained (no shared fleet).
"""

import struct

import pytest

from settings import BIND_HOST
from server_registry import NginxInstanceSpec

import _test_session_bind_helpers as H

pytestmark = [pytest.mark.uses_lifecycle_harness,
              pytest.mark.xdist_group("lc-qconfig-sitename")]

_SERVER = "lc-qconfig-sitename"

kXR_query = 3001
kXR_Qconfig = 7
kXR_QStats = 1


def _spec(extra):
    return NginxInstanceSpec(
        name=_SERVER,
        template="nginx_lc_qconfig_sitename.conf",
        template_values={"BIND_HOST": BIND_HOST, "SITENAME_DIRECTIVE": extra},
        reason="Qconfig sitename wire and config coverage")


def _launch(lifecycle, extra):
    return lifecycle.start(_spec(extra)).port


def _qconfig(port, key):
    """Send kXR_query(kXR_Qconfig, key); return the value bytes (NUL/newline
    stripped). ClientQueryRequest body: infotype[2] then reserved; payload=key."""
    H.ANON_HOST = BIND_HOST
    sock, sessid, stream = H._establish_primary(port)
    try:
        body = struct.pack(">H", kXR_Qconfig) + b"\x00" * 14
        status, resp = H._send_req(sock, stream, kXR_query, body=body,
                                   payload=key)
        assert status == H.kXR_ok, f"Qconfig failed: {status}"
        return resp.split(b"\x00", 1)[0].rstrip(b"\n")
    finally:
        sock.close()


def test_sitename_reported_when_configured(lifecycle):
    """(success) brix_sitename set ⇒ Qconfig sitename returns that exact name."""
    port = _launch(lifecycle, "brix_sitename BriX-Test-Site;")
    assert _qconfig(port, b"sitename") == b"BriX-Test-Site"
    assert _qconfig(port, b"version").startswith(b"v")


def test_sitename_echoes_key_when_unset(lifecycle):
    """(regression) no brix_sitename ⇒ the key echo, byte-identical to before."""
    port = _launch(lifecycle, "")
    assert _qconfig(port, b"sitename") == b"sitename"


def _qstats_site(port):
    """kXR_query(kXR_QStats) → the site="…" attribute of the <statistics> XML."""
    import re
    H.ANON_HOST = BIND_HOST
    sock, sessid, stream = H._establish_primary(port)
    try:
        body = struct.pack(">H", kXR_QStats) + b"\x00" * 14
        status, resp = H._send_req(sock, stream, kXR_query, body=body,
                                   payload=b"a")
        assert status == H.kXR_ok, f"QStats failed: {status}"
        m = re.search(rb'site="([^"]*)"', resp)
        assert m is not None, f"no site= attribute in {resp[:120]!r}"
        return m.group(1)
    finally:
        sock.close()


def test_qstats_site_attribute_reports_sitename(lifecycle):
    """(success) the summary-monitoring <statistics site="…"> attribute — read by
    federation dashboards — now carries brix_sitename instead of empty."""
    port = _launch(lifecycle, "brix_sitename Mon-Site-7;")
    assert _qstats_site(port) == b"Mon-Site-7"


def test_qstats_site_empty_when_unset(lifecycle):
    """(regression) unset ⇒ site="" (empty), byte-identical to before."""
    port = _launch(lifecycle, "")
    assert _qstats_site(port) == b""


def test_directive_accepted_by_config_test(lifecycle):
    """(config) brix_sitename passes `nginx -t` (the directive is registered)."""
    lifecycle.register(_spec("brix_sitename Some-Site;"))
    lifecycle.reconfigure(_SERVER)
    r = lifecycle.nginx_test(_SERVER, check=False)
    assert r.returncode == 0, f"brix_sitename rejected by -t: {r.stderr}"
    assert "unknown directive" not in r.stderr
