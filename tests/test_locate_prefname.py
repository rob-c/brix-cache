"""kXR_locate `kXR_prefname` option — parity audit §2.18.

A data server answers kXR_locate with a location token `S<access><host>:<port>`.
Stock lets the client ask (option bit `kXR_prefname`, 0x0100) for the server's
DNS *hostname* in that token rather than its IP literal — the form a client
needs when a GSI host-cert CN must match, or when the name should re-resolve
through a different route. BriX previously hard-coded the IP (the option was
decoded-and-ignored, with a comment that wrongly claimed the hostname was the
default); it now honors the bit at the `locate_format_local` choke point.

Coverage:
  * default (option clear) ⇒ the IP literal, byte-identical to before;
  * prefname (option set)  ⇒ the server's advertised identity — XRDNET_IDENTITY
    when set (the stock XRootD short-circuit, honoured for parity), else
    gethostname(2) — never a dotted IP;
  * an empty or malformed XRDNET_IDENTITY is ignored (gethostname again).
  * the access char and port are preserved across both forms.
Self-contained (no shared fleet).
"""

import os
import re
import socket
import struct
from pathlib import Path

import pytest

from settings import BIND_HOST
from server_registry import NginxInstanceSpec

import _test_session_bind_helpers as H

pytestmark = [pytest.mark.uses_lifecycle_harness,
              pytest.mark.xdist_group("lc-locate-prefname")]

_SERVER = "lc-locate-prefname"

kXR_locate = 3027
kXR_prefname = 0x0100
_IPV4 = re.compile(rb"^\d{1,3}(\.\d{1,3}){3}$")


def _launch(lifecycle, env=None):
    endpoint = lifecycle.start(NginxInstanceSpec(
        name=_SERVER,
        template="nginx_lc_locate_prefname.conf",
        template_values={"BIND_HOST": BIND_HOST},
        env=env,
        reason="locate prefname wire coverage"))
    Path(endpoint.data_root, "f.bin").write_bytes(b"L" * 4096)
    return endpoint.port


def _expected_prefname():
    """What the server advertises: the harness's own XRDNET_IDENTITY (set on
    hosts whose gethostname has no DNS entry) or gethostname(2)."""
    return (os.environ.get("XRDNET_IDENTITY") or socket.gethostname()).encode()


def _relaunch_with(lifecycle, env):
    """Restart the ONE ledgered instance under a different environment (the
    lifecycle ledger has a fixed port per name, so identity variants reuse it
    serially rather than minting names)."""
    try:
        lifecycle.stop(_SERVER)
    except KeyError:
        pass
    return _launch(lifecycle, env=env)


def _prefname_host(port):
    sock = None
    try:
        H.ANON_HOST = BIND_HOST
        sock, sessid, stream = H._establish_primary(port)
        status, body = _locate(sock, stream, "/f.bin", kXR_prefname)
        assert status == H.kXR_ok, f"locate failed: {status} {body!r}"
        return _split_token(body.split(b"\x00", 1)[0])[1]
    finally:
        if sock is not None:
            sock.close()


def _locate(sock, stream, path, options):
    """Send kXR_locate. Body: options[2] reserved[14]; payload = path+NUL."""
    body = struct.pack(">H", options) + b"\x00" * 14
    return H._send_req(sock, stream, kXR_locate, body=body,
                       payload=path.encode() + b"\x00")


def _split_token(tok):
    """'S' + access + host:port  →  (access, host, port). Handles [v6]:port."""
    assert tok[:1] == b"S", f"not a server token: {tok!r}"
    access = tok[1:2]
    rest = tok[2:]
    hostport = rest.rsplit(b":", 1)
    return access, hostport[0], hostport[1]


def test_default_locate_returns_ip(lifecycle):
    """(regression) option clear ⇒ the IP literal, exactly as before."""
    port = _launch(lifecycle)
    sock = None
    try:
        H.ANON_HOST = BIND_HOST
        sock, sessid, stream = H._establish_primary(port)
        status, body = _locate(sock, stream, "/f.bin", 0)
        assert status == H.kXR_ok, f"locate failed: {status} {body!r}"
        tok = body.split(b"\x00", 1)[0]
        access, host, tport = _split_token(tok)
        assert access in (b"r", b"w"), f"bad access char: {access!r}"
        assert _IPV4.match(host), f"default locate host not an IP: {host!r}"
        assert host == BIND_HOST.encode()
        assert int(tport) == port
    finally:
        if sock is not None:
            sock.close()


def test_prefname_returns_hostname(lifecycle):
    """(success) kXR_prefname set ⇒ the node identity, not a dotted IP; access +
    port preserved."""
    port = _launch(lifecycle)
    sock = None
    try:
        H.ANON_HOST = BIND_HOST
        sock, sessid, stream = H._establish_primary(port)
        status, body = _locate(sock, stream, "/f.bin", kXR_prefname)
        assert status == H.kXR_ok, f"locate failed: {status} {body!r}"
        tok = body.split(b"\x00", 1)[0]
        access, host, tport = _split_token(tok)
        assert access in (b"r", b"w"), f"bad access char: {access!r}"
        assert not _IPV4.match(host), \
            f"prefname host is still an IP literal: {host!r}"
        assert host == _expected_prefname(), \
            f"prefname host {host!r} != identity {_expected_prefname()!r}"
        assert int(tport) == port, "port not preserved under prefname"
    finally:
        if sock is not None:
            sock.close()


def test_prefname_and_default_differ(lifecycle):
    """(discriminator) the two forms genuinely diverge — same server, one call
    each, host field IP vs name."""
    port = _launch(lifecycle)
    sock = None
    try:
        H.ANON_HOST = BIND_HOST
        sock, sessid, stream = H._establish_primary(port)
        _, ip_body = _locate(sock, stream, "/f.bin", 0)
        _, nm_body = _locate(sock, stream, "/f.bin", kXR_prefname)
        _, ip_host, _ = _split_token(ip_body.split(b"\x00", 1)[0])
        _, nm_host, _ = _split_token(nm_body.split(b"\x00", 1)[0])
        assert ip_host != nm_host, (
            "prefname produced the same host as the default "
            f"({ip_host!r}) — the option had no effect")
    finally:
        if sock is not None:
            sock.close()


def test_identity_override_is_advertised(lifecycle):
    """(success) XRDNET_IDENTITY names what prefname advertises — the same
    knob stock XRootD honours, so a host without a DNS name can still hand
    out one clients resolve."""
    try:
        port = _relaunch_with(lifecycle, {"XRDNET_IDENTITY": "locate-ident.test.local"})
        assert _prefname_host(port) == b"locate-ident.test.local"
    finally:
        lifecycle.stop(_SERVER)


def test_empty_identity_falls_back_to_gethostname(lifecycle):
    """(error) an empty override is no override: gethostname(2) again."""
    try:
        port = _relaunch_with(lifecycle, {"XRDNET_IDENTITY": ""})
        assert _prefname_host(port) == socket.gethostname().encode()
    finally:
        lifecycle.stop(_SERVER)


def test_malformed_identity_is_refused(lifecycle):
    """(security-negative) an override that is not a host name (spaces, a
    scheme, a path — anything a client would parse differently) is ignored
    rather than injected into the location token."""
    try:
        port = _relaunch_with(lifecycle, {"XRDNET_IDENTITY": "evil.test/redirect?x=1 y"})
        host = _prefname_host(port)
        assert host == socket.gethostname().encode(), host
        assert b"/" not in host and b" " not in host
    finally:
        lifecycle.stop(_SERVER)
