"""XRootD ``unix`` auth over the wire — the client-asserted-identity mechanism.

`unix` is the one auth scheme where the client merely *declares* who it is: the
credential is the literal text ``"unix\\0<user>[ <group>]"`` with no proof of any
kind (src/auth/unix/auth.c).  Two things therefore carry the entire security
weight of the mechanism, and neither had live coverage before this module
(docs/refactor/testsuite-combinatorial-coverage-audit-2026-08-04.md §7 P1-3):

  * the **peer trust gate** — the assertion is honoured only for loopback peers
    unless ``brix_unix_trust_remote on`` deliberately widens it, and
  * the **name allow-list** — the unverified user/group bytes are confined to
    ``[A-Za-z0-9_.@+-]`` before they reach identity fields, log lines and metric
    labels.

Coverage (success · error · security-negative):
  success       loopback peer asserts a name -> kXR_ok, and the identity is
                usable (a read of a seeded file succeeds afterwards)
  error         malformed credentials (bad tag, empty user, over-long name)
                -> kXR_NotAuthorized, one per parse rejection
  security-neg  a NON-loopback peer is refused with trust off, and accepted only
                once trust is explicitly turned on (the whole point of the flag);
                name bytes outside the allow-list are refused; ops attempted
                before kXR_auth are refused; a credtype the server is not
                configured for is refused.

The non-loopback leg needs a second local address to dial, read off this host's
own interfaces; it skips when the host has only 127.0.0.0/8.  All instances are
throwaway registry-lifecycle nginx servers.
"""

import ipaddress
import os
import socket
import struct

import pytest
import psutil

from settings import BIND_HOST, HOST, NGINX_BIN
from server_launcher import LifecycleHarness
from server_registry import NginxInstanceSpec

from test_pgwrite_cse import (
    _handshake_login,
    _read_response,
    kXR_ok,
    kXR_error,
)

pytestmark = [pytest.mark.serial, pytest.mark.timeout(120),
              pytest.mark.uses_lifecycle_harness,
              pytest.mark.xdist_group("lc-unix-auth")]

kXR_auth, kXR_open, kXR_read = 3000, 3010, 3013
kXR_open_read = 0x0010
kXR_NotAuthorized = 3010          # errno EPERM -> kXR (error_mapping.c)

SEED = b"unix-auth wire payload\n"


# --------------------------------------------------------------------------- #
# Wire helpers
# --------------------------------------------------------------------------- #

def _auth(sock, cred: bytes, credtype: bytes = b"unix"):
    """Send one kXR_auth with `cred` as the credential blob; return the reply.

    Returns (status, errcode, body); errcode is the 4-byte kXR error code that
    prefixes an error body, or None on success.
    """
    sock.sendall(struct.pack("!2sH12s4sI", b"\x00\x03", kXR_auth,
                             b"\x00" * 12, credtype.ljust(4, b"\x00"),
                             len(cred)) + cred)
    status, body = _read_response(sock)
    errcode = (struct.unpack("!I", body[:4])[0]
               if (status == kXR_error and len(body) >= 4) else None)
    return status, errcode, body


def _open_read(sock, path: bytes):
    sock.sendall(struct.pack("!2sHHH2s6s4sI", b"\x00\x04", kXR_open,
                             0, kXR_open_read, b"\x00\x00", b"\x00" * 6,
                             b"\x00" * 4, len(path)) + path)
    return _read_response(sock)


def _read(sock, fhandle, length):
    sock.sendall(struct.pack("!2sH4sqiI", b"\x00\x05", kXR_read,
                             fhandle, 0, length, 0))
    status, body = _read_response(sock)
    return status, body


def _non_loopback_addr():
    """A local non-loopback IPv4 address, or None when the host has none.

    Dialling such an address from this same host gives the server a non-loopback
    PEER — the only unprivileged way to put the trust gate under test.  Read off
    the interfaces themselves through psutil's native adapter rather than a
    Linux-only ioctl or a hostname that commonly resolves into 127.0.0.0/8.
    """
    for addresses in psutil.net_if_addrs().values():
        for record in addresses:
            address = _unicast_ipv4(record)
            if address is not None:
                return address
    return None


def _unicast_ipv4(record):
    if record.family != socket.AF_INET:
        return None
    address = ipaddress.IPv4Address(record.address)
    if any((address.is_loopback, address.is_unspecified, address.is_multicast)):
        return None
    return str(address)


def test_non_loopback_probe_uses_native_interface_addresses(monkeypatch):
    from types import SimpleNamespace

    rows = [SimpleNamespace(family=socket.AF_INET6, address='::1'),  # net-literal-allow: interface-selection vector, never dialed
            SimpleNamespace(family=socket.AF_INET, address='127.0.0.7'),  # net-literal-allow: trusted-peer rejection vector, never dialed
            SimpleNamespace(family=socket.AF_INET, address='192.0.2.7')]
    monkeypatch.setattr(psutil, 'net_if_addrs', lambda: {'native0': rows})
    assert _non_loopback_addr() == '192.0.2.7'


@pytest.mark.parametrize('address', ['127.0.0.1', '127.64.7.1', '0.0.0.0', '224.0.0.1'])  # net-literal-allow: unusable interface-selection vectors, never dialed
def test_non_loopback_probe_cannot_mistake_a_trusted_or_nonunicast_peer(monkeypatch, address):
    from types import SimpleNamespace

    rows = [SimpleNamespace(family=socket.AF_INET, address=address)]
    monkeypatch.setattr(psutil, 'net_if_addrs', lambda: {'native0': rows})
    assert _non_loopback_addr() is None


def test_non_loopback_probe_cannot_turn_failed_inspection_into_a_skip(monkeypatch):
    def denied():
        raise PermissionError('cannot inspect native interfaces')

    monkeypatch.setattr(psutil, 'net_if_addrs', denied)
    with pytest.raises(PermissionError, match='cannot inspect native interfaces'):
        _non_loopback_addr()


def test_non_loopback_probe_refuses_malformed_native_address(monkeypatch):
    from types import SimpleNamespace

    rows = [SimpleNamespace(family=socket.AF_INET, address='not-an-ipv4-address')]
    monkeypatch.setattr(psutil, 'net_if_addrs', lambda: {'native0': rows})
    with pytest.raises(ValueError):
        _non_loopback_addr()


# --------------------------------------------------------------------------- #
# Fixtures
# --------------------------------------------------------------------------- #

@pytest.fixture(scope="module")
def harness():
    if not os.access(NGINX_BIN, os.X_OK):
        pytest.skip(f"nginx not executable: {NGINX_BIN}")
    h = LifecycleHarness()
    try:
        yield h
    finally:
        h.close()


def _start(lifecycle, name, bind_host, trust_remote):
    endpoint = lifecycle.start(NginxInstanceSpec(
        name=name,
        template="nginx_unix_auth.conf",
        protocol="root",
        host=bind_host,
        template_values={"BIND_HOST": bind_host,
                         "TRUST_REMOTE": trust_remote},
        reason="unix auth: peer trust gate + asserted-name validation"))
    with open(f"{endpoint.data_root}/u.txt", "wb") as fh:
        fh.write(SEED)
    return endpoint


@pytest.fixture(scope="module")
def loopback_srv(harness):
    return _start(harness, "lc-unix-loopback", BIND_HOST, "off")


@pytest.fixture(scope="module")
def remote_addr():
    addr = _non_loopback_addr()
    if addr is None:
        pytest.skip("host has no non-loopback IPv4 address to dial")
    return addr


@pytest.fixture(scope="module")
def remote_deny_srv(harness, remote_addr):
    return _start(harness, "lc-unix-remote-deny", remote_addr, "off")


@pytest.fixture(scope="module")
def remote_trust_srv(harness, remote_addr):
    return _start(harness, "lc-unix-remote-trust", remote_addr, "on")


def _login(endpoint, host=None):
    return _handshake_login(host=host or HOST, port=endpoint.port)


# --------------------------------------------------------------------------- #
# success
# --------------------------------------------------------------------------- #

def test_loopback_peer_asserted_name_accepted(loopback_srv):
    # The mechanism's happy path: a loopback peer names itself and is believed.
    # The group token is optional and separately validated, so assert both.
    sock = _login(loopback_srv)
    try:
        status, errcode, _ = _auth(sock, b"unix\x00brixuser atlas")
        assert status == kXR_ok, f"unix auth refused: st={status} err={errcode}"
    finally:
        sock.close()


def test_authenticated_identity_can_read(loopback_srv):
    # Auth that does not actually unlock the session would be a false positive:
    # prove the post-auth session serves data, byte-exact.
    sock = _login(loopback_srv)
    try:
        status, _, _ = _auth(sock, b"unix\x00brixuser")
        assert status == kXR_ok
        status, body = _open_read(sock, b"/u.txt")
        assert status == kXR_ok, f"open after unix auth failed: {status}"
        status, data = _read(sock, body[:4], len(SEED))
        assert status == kXR_ok and data == SEED, (status, data)
    finally:
        sock.close()


# --------------------------------------------------------------------------- #
# error — credential parse rejections
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize("cred, why", [
    (b"unix", "payload shorter than the 'unix\\0' tag plus one name byte"),
    (b"unixX\x00user", "tag not NUL-terminated at offset 4"),
    (b"gsi\x00\x00user", "wrong protocol tag inside a unix credential"),
    (b"unix\x00", "no user token at all"),
    (b"unix\x00 ", "user token is whitespace only"),
    (b"unix\x00" + b"u" * 512, "user longer than the identity buffer"),
])
def test_malformed_credential_denied(loopback_srv, cred, why):
    # Every parse failure must land on the same fail-closed answer; a credential
    # the server cannot fully parse must never authenticate a partial identity.
    sock = _login(loopback_srv)
    try:
        status, errcode, _ = _auth(sock, cred)
        assert status == kXR_error and errcode == kXR_NotAuthorized, \
            f"{why}: expected NotAuthorized, got st={status} err={errcode}"
    finally:
        sock.close()


# --------------------------------------------------------------------------- #
# security-negative
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize("cred, why", [
    (b"unix\x00us er/name", "path separator in the asserted user"),
    (b"unix\x00user\nmore", "newline would forge an extra audit-log line"),
    (b"unix\x00user;drop", "punctuation outside the identity-safe allow-list"),
    (b"unix\x00user grp/../x", "traversal bytes in the asserted group"),
    (b"unix\x00user grp\x1b[31m", "escape sequence in the asserted group"),
])
def test_unsafe_name_bytes_denied(loopback_srv, cred, why):
    # The asserted name is attacker-controlled text that ends up in log lines,
    # metric labels and ACL comparisons, so the byte allow-list is a security
    # control, not cosmetics: reject rather than sanitise-and-accept.
    sock = _login(loopback_srv)
    try:
        status, errcode, _ = _auth(sock, cred)
        assert status == kXR_error and errcode == kXR_NotAuthorized, \
            f"{why}: expected NotAuthorized, got st={status} err={errcode}"
    finally:
        sock.close()


def test_operations_before_auth_denied(loopback_srv):
    # Login alone must not unlock the session: auth_done, not logged_in, is the
    # gate (handshake/policy.c brix_dispatch_require_auth).
    sock = _login(loopback_srv)
    try:
        status, body = _open_read(sock, b"/u.txt")
        errcode = struct.unpack("!I", body[:4])[0] if len(body) >= 4 else None
        assert status == kXR_error and errcode == kXR_NotAuthorized, \
            f"open before kXR_auth must be refused, got st={status}"
    finally:
        sock.close()


@pytest.mark.parametrize("credtype", [b"sss", b"ztn", b"krb5", b"host"])
def test_other_credtype_denied_when_unix_configured(loopback_srv, credtype):
    # brix_auth selects exactly one mechanism; a client cannot talk the server
    # into a different one by changing the credtype tag.
    sock = _login(loopback_srv)
    try:
        status, errcode, _ = _auth(sock, b"unix\x00brixuser", credtype=credtype)
        assert status == kXR_error and errcode == kXR_NotAuthorized, \
            f"credtype {credtype!r} must be refused, got st={status}"
    finally:
        sock.close()


def test_remote_peer_denied_by_default(remote_deny_srv, remote_addr):
    # THE trust gate: an identical credential that succeeds over loopback must
    # be refused from a non-loopback peer while brix_unix_trust_remote is off —
    # otherwise anyone routable could assert any user name.
    sock = _login(remote_deny_srv, host=remote_addr)
    try:
        status, errcode, _ = _auth(sock, b"unix\x00brixuser atlas")
        assert status == kXR_error and errcode == kXR_NotAuthorized, \
            f"non-loopback peer must be refused, got st={status} err={errcode}"
    finally:
        sock.close()


def test_remote_peer_accepted_when_trust_enabled(remote_trust_srv, remote_addr):
    # The other side of the same boundary: the flag is what changes the verdict,
    # so an operator who opts in gets exactly what they asked for and the deny
    # above is proven to come from the gate rather than from the topology.
    sock = _login(remote_trust_srv, host=remote_addr)
    try:
        status, errcode, _ = _auth(sock, b"unix\x00brixuser atlas")
        assert status == kXR_ok, \
            f"trust_remote on must admit a remote peer, got st={status} err={errcode}"
    finally:
        sock.close()


def test_remote_trust_does_not_relax_name_validation(remote_trust_srv,
                                                     remote_addr):
    # Widening the peer gate must not widen the name allow-list with it: the two
    # controls are independent and the second still holds.
    sock = _login(remote_trust_srv, host=remote_addr)
    try:
        status, errcode, _ = _auth(sock, b"unix\x00user;drop")
        assert status == kXR_error and errcode == kXR_NotAuthorized, \
            f"unsafe name must still be refused, got st={status} err={errcode}"
    finally:
        sock.close()
