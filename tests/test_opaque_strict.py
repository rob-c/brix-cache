"""D-2 opaque-schema half — brix_opaque_strict opt-in CGI schema enforcement.

The always-on byte-hygiene gate (§L2, test_conf_openflags) already rejects a
control / shell-metacharacter / non-ASCII byte in the opaque.  brix_opaque_strict
adds the *schema* tier on top, and only when the operator opts in:

  success  — with strict on, a well-formed opaque (a typed oss.asize carrying an
             integer plus keys in recognized namespaces) opens normally;
  error    — with strict on, a typed key with a non-integer value (oss.asize=abc)
             is refused pre-handler with kXR_error/kXR_ArgInvalid;
  security — with strict on, a key in no recognized namespace (a junk / typo'd
             parameter) is refused with kXR_error/kXR_ArgInvalid;
  parity   — with strict OFF (the default), the SAME unknown-key open succeeds —
             proving the tier is a deliberate posture opt-in and never regresses
             stock parity for a deployment that leaves it off.

Drives the real XRootD wire path with the raw client from test_phase25_ratelimit
(login / open / status parsing); the opaque rides on the open path after '?',
exactly as xrdcp appends it.
"""

import os
import socket
import struct

import pytest

from server_registry import NginxInstanceSpec
from settings import NGINX_BIN, HOST, BIND_HOST
from test_phase25_ratelimit import _xrd_open, KXR_OK

pytestmark = [pytest.mark.uses_lifecycle_harness,
              pytest.mark.xdist_group("lc-opq")]

KXR_ERROR = 4003
kXR_ArgInvalid = 3000


@pytest.fixture(autouse=True)
def _require_binary():
    if not os.path.exists(NGINX_BIN):
        pytest.skip(f"nginx binary not found at {NGINX_BIN}")


def _login(port):
    """Anonymous login on a fresh connection, reusing the phase-25 wire steps."""
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(5)
    s.connect((HOST, port))
    s.sendall(struct.pack(">IIIII", 0, 0, 0, 4, 2012))
    s.recv(16)                                             # initial handshake
    s.sendall(struct.pack(">BB H I BB 10x I", 0, 1, 3006, 0, 0, 0x03, 0))
    hdr = s.recv(8)                                        # kXR_protocol reply
    dlen = struct.unpack(">I", hdr[4:8])[0]
    if dlen:
        s.recv(dlen)
    s.sendall(struct.pack(">BB H I 8s BB B B I", 0, 1, 3007, 0,
                          b"test\x00\x00\x00\x00", 0, 0, 5, 0, 0))
    hdr = s.recv(8)                                        # kXR_login reply
    dlen = struct.unpack(">I", hdr[4:8])[0]
    if dlen:
        s.recv(dlen)
    return s


def _errcode(body):
    return struct.unpack(">I", body[:4])[0] if len(body) >= 4 else None


def _start(lifecycle, data, name, *, strict):
    ep = lifecycle.start(NginxInstanceSpec(
        name=name, template="nginx_opaque_strict.conf", data_root=str(data),
        template_values={"BIND_HOST": BIND_HOST, "STRICT": strict},
        reason="D-2 brix_opaque_strict schema coverage"))
    return ep.port


def _open(port, path):
    s = _login(port)
    st, body = _xrd_open(s, path)
    s.close()
    return st, body


# --------------------------------------------------------------------------- #
# success: a well-formed opaque under strict mode opens normally.
# --------------------------------------------------------------------------- #
def test_strict_valid_opaque_opens(lifecycle, tmp_path):
    data = tmp_path / "data"; data.mkdir()
    (data / "real.dat").write_text("present\n")
    port = _start(lifecycle, data, "lc-opq-valid", strict="on")

    st, _ = _open(port, "/real.dat?oss.asize=1048576&tpc.src=root://h//p&authz=t")
    assert st == KXR_OK, ("well-formed opaque must open under strict", st)


# --------------------------------------------------------------------------- #
# error: a typed key with a non-integer value is refused pre-handler.
# --------------------------------------------------------------------------- #
def test_strict_typed_wrong_rejected(lifecycle, tmp_path):
    data = tmp_path / "data"; data.mkdir()
    (data / "real.dat").write_text("present\n")
    port = _start(lifecycle, data, "lc-opq-type", strict="on")

    st, body = _open(port, "/real.dat?oss.asize=abc")
    assert st == KXR_ERROR, ("typed-wrong opaque must error", st)
    assert _errcode(body) == kXR_ArgInvalid, _errcode(body)


# --------------------------------------------------------------------------- #
# security-negative: a key in no recognized namespace is refused.
# --------------------------------------------------------------------------- #
def test_strict_unknown_key_rejected(lifecycle, tmp_path):
    data = tmp_path / "data"; data.mkdir()
    (data / "real.dat").write_text("present\n")
    port = _start(lifecycle, data, "lc-opq-unknown", strict="on")

    st, body = _open(port, "/real.dat?evilparam=1")
    assert st == KXR_ERROR, ("unknown-key opaque must error", st)
    assert _errcode(body) == kXR_ArgInvalid, _errcode(body)


# --------------------------------------------------------------------------- #
# parity: with strict OFF (default), the same unknown key opens unchanged.
# --------------------------------------------------------------------------- #
def test_default_off_preserves_parity(lifecycle, tmp_path):
    data = tmp_path / "data"; data.mkdir()
    (data / "real.dat").write_text("present\n")
    port = _start(lifecycle, data, "lc-opq-off", strict="off")

    # The unknown key that strict refuses is accepted (byte-hygiene passes it) —
    # stock XRootD strips it; enabling strict is the only thing that rejects it.
    st, _ = _open(port, "/real.dat?evilparam=1")
    assert st == KXR_OK, ("unknown key must open when strict is off", st)
