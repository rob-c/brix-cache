"""
Phase 1 capability-flags tests.

Verifies that the kXR_protocol response advertises the correct ServerProtocolBody.flags
bitmask for each server role.  Uses raw sockets — no PyXRootD dependency.

Servers under test:
  plain data server  — NGINX_ANON_PORT (11094)  brix_export only
  cache server       — CACHE_ONLY_PORT  (11200)  brix_cache_export configured
  proxy server       — PROXY_NGINX_PORT (11193)  brix_proxy on

Flag bit layout (XProtocol.hh, ServerProtocolBody.flags uint32 big-endian):
  kXR_isServer   0x00000001
  kXR_isManager  0x00000002
  kXR_attrCache  0x00000080  — server is a read-through cache node
  kXR_supposc    0x00100000  — POSC (persist-on-successful-close) supported
  kXR_suppgrw    0x00200000  — pgread/pgwrite with CRC32c supported
  kXR_attrProxy  0x00000200  — server is a transparent proxy
"""

import socket
import struct

import pytest

from settings import (
    CACHE_ONLY_PORT,
    COLLAPSE_REDIR_PORT,
    META_ONLY_PORT,
    NGINX_ANON_PORT,
    NGINX_GSI_PORT,
    PROXY_NGINX_PORT,
    SERVER_HOST,
    SUPERVISOR_PORT,
    VIRTUAL_REDIR_PORT,
)

# -- flag constants (mirror src/protocols/root/protocol/flags.h) --
_kXR_isServer    = 0x00000001
_kXR_isManager   = 0x00000002
_kXR_attrCache   = 0x00000080
_kXR_attrMeta    = 0x00000100
_kXR_attrProxy   = 0x00000200
_kXR_attrSuper   = 0x00000400
_kXR_attrVirtRdr = 0x00000800
_kXR_recoverWrts  = 0x00001000
_kXR_collapseRedir = 0x00002000
_kXR_supgpf       = 0x00400000
_kXR_anongpf      = 0x00800000
_kXR_supposc     = 0x00100000
_kXR_suppgrw     = 0x00200000

# XRootD response status for errors (kXR_error)
_kXR_status_ok    = 0
_kXR_status_error = 4003


# ---------------------------------------------------------------------------
# Wire helpers
# ---------------------------------------------------------------------------

def _recv_exact(sock: socket.socket, n: int) -> bytes:
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise RuntimeError(f"connection closed after {len(buf)}/{n} bytes")
        buf += chunk
    return buf


def _read_response(sock: socket.socket):
    hdr    = _recv_exact(sock, 8)
    status = struct.unpack(">H", hdr[2:4])[0]
    dlen   = struct.unpack(">I", hdr[4:8])[0]
    body   = _recv_exact(sock, dlen) if dlen else b""
    return status, body


def _get_protocol_flags(host: str, port: int) -> int:
    """Return the ServerProtocolBody.flags word from a kXR_protocol exchange."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(5)
    try:
        sock.connect((host, port))
        # XRootD initial handshake (20 bytes)
        sock.sendall(struct.pack(">IIIII", 0, 0, 0, 4, 2012))
        # kXR_protocol request — advertise kXR_ableTLS (0x02) so TLS-capable
        # servers still respond with the full flags word rather than aborting
        sock.sendall(struct.pack(">BB H I BB 10x I",
                                 0, 1, 3006, 0x00000520, 0x02, 0x03, 0))
        # Server handshake response is always 16 bytes
        _recv_exact(sock, 16)
        # kXR_protocol response: 8-byte header + body
        # body[0:4] = pval (protocol version), body[4:8] = flags
        status, body = _read_response(sock)
        assert status == 0, f"kXR_protocol returned status {status:#06x}"
        assert len(body) >= 8, f"protocol body too short: {len(body)} bytes"
        return struct.unpack(">I", body[4:8])[0]
    finally:
        sock.close()


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

@pytest.mark.requires_local_server
class TestAlwaysOnFlags:
    """kXR_suppgrw and kXR_supposc must be set by every server instance."""

    def test_suppgrw_set_on_plain_server(self):
        flags = _get_protocol_flags(SERVER_HOST, NGINX_ANON_PORT)
        assert flags & _kXR_suppgrw, (
            f"kXR_suppgrw (0x{_kXR_suppgrw:08x}) not set; flags={flags:#010x}"
        )

    def test_supposc_set_on_plain_server(self):
        flags = _get_protocol_flags(SERVER_HOST, NGINX_ANON_PORT)
        assert flags & _kXR_supposc, (
            f"kXR_supposc (0x{_kXR_supposc:08x}) not set; flags={flags:#010x}"
        )

    def test_is_server_set_on_plain_server(self):
        flags = _get_protocol_flags(SERVER_HOST, NGINX_ANON_PORT)
        assert flags & _kXR_isServer, (
            f"kXR_isServer (0x{_kXR_isServer:08x}) not set; flags={flags:#010x}"
        )

    @pytest.mark.registry_server("cache-only")
    def test_suppgrw_set_on_cache_server(self):
        flags = _get_protocol_flags(SERVER_HOST, CACHE_ONLY_PORT)
        assert flags & _kXR_suppgrw, (
            f"kXR_suppgrw not set on cache server; flags={flags:#010x}"
        )

    @pytest.mark.registry_server("proxy-nginx")
    def test_suppgrw_set_on_proxy_server(self):
        flags = _get_protocol_flags(SERVER_HOST, PROXY_NGINX_PORT)
        assert flags & _kXR_suppgrw, (
            f"kXR_suppgrw not set on proxy server; flags={flags:#010x}"
        )


@pytest.mark.requires_local_server
class TestCacheFlag:
    """kXR_attrCache (0x80) is set only when brix_cache_export is configured."""

    @pytest.mark.registry_server("cache-only")
    def test_cache_flag_set_for_cache_server(self):
        flags = _get_protocol_flags(SERVER_HOST, CACHE_ONLY_PORT)
        assert flags & _kXR_attrCache, (
            f"kXR_attrCache (0x{_kXR_attrCache:08x}) not set on cache server; "
            f"flags={flags:#010x}"
        )

    def test_cache_flag_absent_for_plain_server(self):
        flags = _get_protocol_flags(SERVER_HOST, NGINX_ANON_PORT)
        assert not (flags & _kXR_attrCache), (
            f"kXR_attrCache must not be set on a plain data server; "
            f"flags={flags:#010x}"
        )

    @pytest.mark.registry_server("proxy-nginx")
    def test_cache_flag_absent_for_proxy_server(self):
        flags = _get_protocol_flags(SERVER_HOST, PROXY_NGINX_PORT)
        assert not (flags & _kXR_attrCache), (
            f"kXR_attrCache must not be set on a proxy-only server; "
            f"flags={flags:#010x}"
        )


@pytest.mark.requires_local_server
class TestProxyFlag:
    """kXR_attrProxy (0x200) is set only when brix_proxy is on."""

    @pytest.mark.registry_server("proxy-nginx")
    def test_proxy_flag_set_for_proxy_server(self):
        flags = _get_protocol_flags(SERVER_HOST, PROXY_NGINX_PORT)
        assert flags & _kXR_attrProxy, (
            f"kXR_attrProxy (0x{_kXR_attrProxy:08x}) not set on proxy server; "
            f"flags={flags:#010x}"
        )

    def test_proxy_flag_absent_for_plain_server(self):
        flags = _get_protocol_flags(SERVER_HOST, NGINX_ANON_PORT)
        assert not (flags & _kXR_attrProxy), (
            f"kXR_attrProxy must not be set on a plain data server; "
            f"flags={flags:#010x}"
        )

    @pytest.mark.registry_server("cache-only")
    def test_proxy_flag_absent_for_cache_server(self):
        flags = _get_protocol_flags(SERVER_HOST, CACHE_ONLY_PORT)
        assert not (flags & _kXR_attrProxy), (
            f"kXR_attrProxy must not be set on a cache-only server; "
            f"flags={flags:#010x}"
        )


# ---------------------------------------------------------------------------
# Phase 2 helpers
# ---------------------------------------------------------------------------

def _do_open(host: str, port: int, path: str) -> int:
    """
    Perform a minimal XRootD open sequence and return the response status.

    Sequence: initial handshake → kXR_protocol → kXR_login (anon) → kXR_open.
    Returns the 2-byte status from the kXR_open response header.
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(5)
    try:
        sock.connect((host, port))
        # Initial handshake (20 bytes)
        sock.sendall(struct.pack(">IIIII", 0, 0, 0, 4, 2012))
        _recv_exact(sock, 16)  # server handshake reply

        # kXR_protocol
        sock.sendall(struct.pack(">BB H I BB 10x I",
                                 0, 1, 3006, 0x00000520, 0x02, 0x03, 0))
        status, _ = _read_response(sock)
        if status != 0:
            return status

        # kXR_login — anonymous, username "nobody"
        username = b"nobody"
        sock.sendall(struct.pack(">BB H I I 8s H 6x",
                                 0, 2, 3007, 20, 0, username, 0))
        status, _ = _read_response(sock)
        if status != 0:
            return status

        # kXR_open — read-only open of path
        payload = path.encode() + b"\x00"
        # header: streamid=0,3 | reqid=3010 | mode=0o400 | options=0x0010(read) | dlen
        sock.sendall(struct.pack(">BB H HH 12x I",
                                 0, 3, 3010, 0o400, 0x0010, len(payload)))
        sock.sendall(payload)
        status, _ = _read_response(sock)
        return status
    finally:
        sock.close()


# ---------------------------------------------------------------------------
# Phase 2 tests
# ---------------------------------------------------------------------------

@pytest.mark.requires_local_server
class TestMetadataOnlyFlag:
    """kXR_attrMeta (0x100) advertised by metadata-only nodes; open is rejected."""

    @pytest.mark.registry_server("meta-only")
    def test_meta_flag_set_for_meta_only_server(self):
        flags = _get_protocol_flags(SERVER_HOST, META_ONLY_PORT)
        assert flags & _kXR_attrMeta, (
            f"kXR_attrMeta (0x{_kXR_attrMeta:08x}) not set on meta-only server; "
            f"flags={flags:#010x}"
        )

    def test_meta_flag_absent_for_plain_server(self):
        flags = _get_protocol_flags(SERVER_HOST, NGINX_ANON_PORT)
        assert not (flags & _kXR_attrMeta), (
            f"kXR_attrMeta must not be set on a plain data server; "
            f"flags={flags:#010x}"
        )

    @pytest.mark.registry_server("meta-only")
    def test_metadata_server_rejects_open(self):
        status = _do_open(SERVER_HOST, META_ONLY_PORT, "/no-such-file")
        assert status == _kXR_status_error, (
            f"metadata-only server should return kXR_error ({_kXR_status_error}) "
            f"on open; got status={status}"
        )


@pytest.mark.requires_local_server
class TestSupervisorFlag:
    """kXR_attrSuper (0x400) set only when brix_supervisor is on."""

    @pytest.mark.registry_server("supervisor")
    def test_supervisor_flag_set(self):
        flags = _get_protocol_flags(SERVER_HOST, SUPERVISOR_PORT)
        assert flags & _kXR_attrSuper, (
            f"kXR_attrSuper (0x{_kXR_attrSuper:08x}) not set on supervisor; "
            f"flags={flags:#010x}"
        )

    @pytest.mark.registry_server("supervisor")
    def test_supervisor_implies_manager(self):
        flags = _get_protocol_flags(SERVER_HOST, SUPERVISOR_PORT)
        assert flags & _kXR_isManager, (
            f"kXR_isManager must be set alongside kXR_attrSuper; "
            f"flags={flags:#010x}"
        )

    def test_supervisor_flag_absent_for_plain_server(self):
        flags = _get_protocol_flags(SERVER_HOST, NGINX_ANON_PORT)
        assert not (flags & _kXR_attrSuper), (
            f"kXR_attrSuper must not be set on a plain data server; "
            f"flags={flags:#010x}"
        )


@pytest.mark.requires_local_server
class TestVirtualRedirFlag:
    """kXR_attrVirtRdr (0x800) auto-detected when manager_map set and cms_addr absent."""

    @pytest.mark.registry_server("virtual-redir")
    def test_virtual_redir_flag_set(self):
        flags = _get_protocol_flags(SERVER_HOST, VIRTUAL_REDIR_PORT)
        assert flags & _kXR_attrVirtRdr, (
            f"kXR_attrVirtRdr (0x{_kXR_attrVirtRdr:08x}) not set on virtual-redir "
            f"server; flags={flags:#010x}"
        )

    @pytest.mark.registry_server("virtual-redir")
    def test_virtual_redir_implies_manager(self):
        flags = _get_protocol_flags(SERVER_HOST, VIRTUAL_REDIR_PORT)
        assert flags & _kXR_isManager, (
            f"kXR_isManager must be set alongside kXR_attrVirtRdr; "
            f"flags={flags:#010x}"
        )

    def test_virtual_redir_flag_absent_for_plain_server(self):
        flags = _get_protocol_flags(SERVER_HOST, NGINX_ANON_PORT)
        assert not (flags & _kXR_attrVirtRdr), (
            f"kXR_attrVirtRdr must not be set on a plain data server; "
            f"flags={flags:#010x}"
        )


@pytest.mark.requires_local_server
class TestCollapseRedirFlag:
    """kXR_collapseRedir (0x2000) set only when brix_collapse_redir is on."""

    @pytest.mark.registry_server("collapse-redir")
    def test_collapse_redir_flag_set(self):
        flags = _get_protocol_flags(SERVER_HOST, COLLAPSE_REDIR_PORT)
        assert flags & _kXR_collapseRedir, (
            f"kXR_collapseRedir (0x{_kXR_collapseRedir:08x}) not set on "
            f"collapse-redir server; flags={flags:#010x}"
        )

    def test_collapse_redir_flag_absent_for_plain_server(self):
        flags = _get_protocol_flags(SERVER_HOST, NGINX_ANON_PORT)
        assert not (flags & _kXR_collapseRedir), (
            f"kXR_collapseRedir must not be set on a plain data server; "
            f"flags={flags:#010x}"
        )

    @pytest.mark.registry_server("cache-only")
    def test_collapse_redir_flag_absent_for_cache_server(self):
        flags = _get_protocol_flags(SERVER_HOST, CACHE_ONLY_PORT)
        assert not (flags & _kXR_collapseRedir), (
            f"kXR_collapseRedir must not be set on a cache-only server; "
            f"flags={flags:#010x}"
        )


@pytest.mark.requires_local_server
class TestRecoverWritesFlag:
    """kXR_recoverWrts (0x1000) is set when brix_recover_writes is on."""

    def test_recover_writes_set_on_anon_server(self):
        # nginx_shared.conf enables this for ANON_PORT
        flags = _get_protocol_flags(SERVER_HOST, NGINX_ANON_PORT)
        assert flags & _kXR_recoverWrts, (
            f"kXR_recoverWrts (0x{_kXR_recoverWrts:08x}) not set on anon server; "
            f"flags={flags:#010x}"
        )

    def test_recover_writes_absent_on_gsi_server(self):
        # nginx_shared.conf leaves this off for GSI_PORT
        flags = _get_protocol_flags(SERVER_HOST, NGINX_GSI_PORT)
        assert not (flags & _kXR_recoverWrts), (
            f"kXR_recoverWrts must not be set when disabled; "
            f"flags={flags:#010x}"
        )

    @pytest.mark.registry_server("supervisor")
    def test_recover_writes_absent_on_manager(self):
        flags = _get_protocol_flags(SERVER_HOST, SUPERVISOR_PORT)
        assert not (flags & _kXR_recoverWrts), (
            f"kXR_recoverWrts must not be set on a supervisor; "
            f"flags={flags:#010x}"
        )


@pytest.mark.requires_local_server
class TestGpfFlags:
    """kXR_supgpf (0x400000) and kXR_anongpf (0x800000) must never be advertised.

    GPF (Grouped Parallel Fetch) uses kXR_gpfile opcode 3005, which is retired in
    XRootD v5.  Neither flag may be set until src/protocols/root/query/gpfile.c is implemented and
    the opcode is re-activated in the dispatch table.  Modern clients use kXR_readv
    for the same batching behaviour.
    """

    def test_supgpf_never_set_on_plain_server(self):
        flags = _get_protocol_flags(SERVER_HOST, NGINX_ANON_PORT)
        assert not (flags & _kXR_supgpf), (
            f"kXR_supgpf must not be set until kXR_gpfile dispatch is "
            f"implemented; flags={flags:#010x}"
        )

    @pytest.mark.registry_server("proxy-nginx")
    def test_supgpf_never_set_on_proxy_server(self):
        flags = _get_protocol_flags(SERVER_HOST, PROXY_NGINX_PORT)
        assert not (flags & _kXR_supgpf), (
            f"kXR_supgpf must not be set on a proxy server; "
            f"flags={flags:#010x}"
        )

    @pytest.mark.registry_server("cache-only")
    def test_supgpf_never_set_on_cache_server(self):
        flags = _get_protocol_flags(SERVER_HOST, CACHE_ONLY_PORT)
        assert not (flags & _kXR_supgpf), (
            f"kXR_supgpf must not be set on a cache server; "
            f"flags={flags:#010x}"
        )

    def test_anongpf_never_set_on_plain_server(self):
        flags = _get_protocol_flags(SERVER_HOST, NGINX_ANON_PORT)
        assert not (flags & _kXR_anongpf), (
            f"kXR_anongpf must not be set until kXR_supgpf is implemented; "
            f"flags={flags:#010x}"
        )

    @pytest.mark.registry_server("proxy-nginx")
    def test_anongpf_never_set_on_proxy_server(self):
        flags = _get_protocol_flags(SERVER_HOST, PROXY_NGINX_PORT)
        assert not (flags & _kXR_anongpf), (
            f"kXR_anongpf must not be set on a proxy server; "
            f"flags={flags:#010x}"
        )
