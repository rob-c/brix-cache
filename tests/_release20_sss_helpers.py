"""Shared driver for the 2.0 F9 SSS entity suites.

`test_release20_sss_entity.py` and `test_release20_sss_proxied.py` both need
the same three things: a set of keytabs cut from one secret whose *policy*
differs, a raw kXR_auth round trip that returns the refusal instead of
tripping over it, and a parse of the one INFO line the server writes per
accepted credential.  They live here so neither suite grows a private copy.

The accept line is the witness for everything F9 added, because it is the
only place the server states what it kept:

    brix: SSS auth OK user=".." group=".." vorg=".." role=".." endo=N creds=M

`user`/`group` are byte-identical to what 1.x wrote (phase-115 pins that
prefix by regex); the entity suffix is append-only.  Endorsements and the
proxied credential are logged as lengths — neither is log material.
"""

import collections
import re

from _release20_tpc_helpers import err_text, log_since, log_size, start_lab
from _test_sss_helpers import sss_auth_frame, sss_credential, sss_write_keytab
from settings import HOST
from test_phase25_ratelimit import _xrd_login, _xrd_recv_status

__all__ = ["SssOk", "cut_keytabs", "err_text", "log_since", "log_size",
           "ok_lines", "sss_login", "sss_round", "start_lab"]

# The keytab policies the two labs load, all from ONE secret so that no
# difference below can be read as "they just had different keys".
#   any      u:anybody g:anygroup    the credential's own name and groups win
#   pinned   u:brixpinned g:...      the keytab pins the identity
#   origin   u:anybody g:origingrp   ANYUSR, but a fixed group that marks the
#                                    origin's own accept lines in a shared log
KEYTAB_POLICY = {
    "any": ("anybody", "anygroup"),
    "pinned": ("brixpinned", "brixpinned"),
    "origin": ("anybody", "origingrp"),
}

SssOk = collections.namedtuple("SssOk", "user group vorg role endo creds")

_OK_RE = re.compile(r'SSS auth OK user="([^"]*)" group="([^"]*)" '
                    r'vorg="([^"]*)" role="([^"]*)" endo=(\d+) creds=(\d+)')


def cut_keytabs(base, key, policies=("any", "pinned", "origin")):
    """One keytab file per policy, all carrying key id 1 and `key`."""
    out = {}
    for policy in policies:
        user, group = KEYTAB_POLICY[policy]
        out[policy] = sss_write_keytab(str(base / f"{policy}.keytab"), key,
                                       user=user, group=group)
    return out


def ok_lines(text):
    """Every `SSS auth OK` line in `text`, parsed, oldest first."""
    return [SssOk(user, group, vorg, role, int(endo), int(creds))
            for user, group, vorg, role, endo, creds in _OK_RE.findall(text)]


def sss_round(sock, key, **cred):
    """Send one kXR_auth SSS credential on an open session; return (status, body)."""
    sock.sendall(sss_auth_frame(sss_credential(key, **cred)))
    return _xrd_recv_status(sock)


def sss_login(port, key, **cred):
    """A logged-in session plus the result of its first SSS credential.

    Returns (socket, status, body) rather than asserting, so a negative can
    inspect the refusal and a challenge test can keep driving the session.
    The caller owns the socket.
    """
    sock = _xrd_login(HOST, port)
    status, body = sss_round(sock, key, **cred)
    return sock, status, body
