"""A CMS data node and the §6.1 signing canon, both host-parameterised.

`test_webdav_redirect_ds.py` already carries a `FakeNode` and a `_signed_cgi`,
but both are bolted to that file's module-level host and to its own secret, and
the manager it registers with is a second nginx instance.  The arm census needs
the registry populated on ONE instance whose five locations differ by a single
directive, so the node has to take the host it dials and the signer has to take
the key it signs with.

The canon itself is worth stating once, because every assertion about a
Location's CGI is an assertion about this string:

    HMAC-SHA256(key, "<METHOD>\\n<path>\\n<exp>\\n<usr>\\n<vo>")

`rdr_mac_hex` (src/protocols/webdav/redirect.c) binds the method and the path
into the signature, which is why a handoff minted for one path cannot be
replayed against another.
"""

import hashlib
import hmac
import socket
import struct
import threading
import time

# ── CMS wire constants (src/net/cms/cms_internal.h) ───────────────────────
CMS_RR_LOGIN, CMS_RR_PING, CMS_RR_PONG = 0, 17, 18
CMS_PT_SHORT, CMS_PT_INT = 0x80, 0xA0
CMS_LOGIN_VERSION = 3


def _recv_exact(sock, count):
    buf = b""
    while len(buf) < count:
        chunk = sock.recv(count - len(buf))
        if not chunk:
            raise ConnectionResetError(f"closed after {len(buf)}/{count} bytes")
        buf += chunk
    return buf


def _cms_frame(streamid, code, modifier=0, payload=b""):
    return struct.pack(">IBBH", streamid, code, modifier,
                       len(payload)) + payload


def _login_payload(dport, name=b"arm-node", paths=b"r /"):
    p = b""
    p += bytes([CMS_PT_SHORT]) + struct.pack(">H", CMS_LOGIN_VERSION)
    p += bytes([CMS_PT_INT]) + struct.pack(">I", 0x08)   # mode: server
    p += bytes([CMS_PT_INT]) + struct.pack(">I", 0)
    p += bytes([CMS_PT_INT]) + struct.pack(">I", 100)
    p += bytes([CMS_PT_INT]) + struct.pack(">I", 5000)
    p += bytes([CMS_PT_INT]) + struct.pack(">I", 100)
    p += bytes([CMS_PT_SHORT]) + struct.pack(">H", 1)
    p += bytes([CMS_PT_SHORT]) + struct.pack(">H", 7)
    p += bytes([CMS_PT_SHORT]) + struct.pack(">H", dport)
    p += bytes([CMS_PT_SHORT]) + struct.pack(">H", 0)
    for field in (name, paths, b"", b""):
        if not field:
            p += struct.pack(">H", 0)
        else:
            p += struct.pack(">H", len(field) + 1) + field + b"\x00"
    return p


class CmsNode:
    """A data node that logs in and answers pings so it stays selectable.

    The registry is what makes the `on` arm differ from the `off` arm at all:
    `brix_srv_select` returning nothing is DECLINED, which is indistinguishable
    on the wire from the flag being off.  A test that wants to attribute a
    served-locally answer to the directive has to know this node is up first.
    """

    def __init__(self, host, cms_port, dport):
        self.sock = socket.create_connection((host, cms_port), timeout=8)
        self.sock.settimeout(0.2)
        self.sock.sendall(_cms_frame(0, CMS_RR_LOGIN, 0,
                                     _login_payload(dport)))
        self._stop = False
        self._registered = threading.Event()
        threading.Thread(target=self._reader, daemon=True).start()

    def _reader(self):
        try:
            while not self._stop:
                try:
                    header = _recv_exact(self.sock, 8)
                except socket.timeout:
                    continue
                streamid, code, _mod, dlen = struct.unpack(">IBBH", header)
                if dlen:
                    _recv_exact(self.sock, dlen)
                if code == CMS_RR_PING:
                    self._registered.set()
                    self.sock.sendall(_cms_frame(streamid, CMS_RR_PONG))
        except (ConnectionResetError, OSError):
            pass

    def wait_registered(self, timeout=8.0):
        """True once the manager has pinged us — i.e. once we are in the
        registry it will select from."""
        return self._registered.wait(timeout)

    def close(self):
        self._stop = True
        try:
            self.sock.close()
        except OSError:
            pass


def mac_hex(secret, method, path, exp, usr="", vo=""):
    canon = f"{method}\n{path}\n{exp}\n{usr}\n{vo}".encode()
    return hmac.new(secret.encode(), canon, hashlib.sha256).hexdigest()


def signed_cgi(secret, method, path, usr="", vo="", ttl=120, exp=None):
    """The handoff CGI a manager would have appended, for use as the client."""
    exp = str(int(time.time()) + ttl) if exp is None else str(exp)
    return (f"brixrdr.exp={exp}&brixrdr.usr={usr}&brixrdr.vo={vo}"
            f"&brixrdr.mac={mac_hex(secret, method, path, exp, usr, vo)}")
