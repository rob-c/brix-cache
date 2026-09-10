"""Static guards for the three things that made outbound PROT P fail closed.

The protected GridFTP data channel worked on nobody's machine, and each of the
three reasons produced a log line that named something other than its cause.
The behavioural proof lives in test_phase115_gridftp_prot_p.py; what is pinned
here is the SHAPE that made each one possible, because all three are invisible
to a test that only asks whether the bytes arrived:

1. **The handshake ran at dial time.**  `gftp_dc_open_at()` connected the data
   socket and immediately ran `SSL_connect` on it.  A passive FTP server has no
   reason to touch the data connection until it has a transfer to run — it
   accepts and starts its side when RETR/STOR arrives (ftp_ev_data.c) — so the
   client was waiting for a ServerHello the server would not send until it read
   a command the client had not sent.  Both ends then sat there: the origin
   logged `control channel idle timeout (110)` and the client an SSL_connect
   with an EMPTY error queue.  Neither line names an ordering bug.

2. **OpenSSL was asked whether a delegated proxy is a TLS server certificate.**
   It is not, and it does not claim to be.  The in-handshake purpose check
   rejected the origin's chain with X509_V_ERR_INVALID_PURPOSE (26) before a
   byte moved, and reported "certificate verify failed" — which reads as a
   misconfigured origin.  The inbound half of the same feature has always
   accepted at the TLS layer and applied BriX's proxy policy afterwards; the
   connect half was the one still asking.

3. **The DN pin compared the wrong two identities.**  A GridFTP server runs its
   data channel on the credential the CLIENT delegated to it, so the DN that
   comes back is ours plus a `/CN=` per delegation step — never the origin's
   host DN.  Pinning to the origin's control DN could not match on a correct
   transfer, and its refusal message accused the origin of presenting the wrong
   identity.

Each of (2) and (3) also has a way of being "fixed" that is worse than the bug —
drop the post-handshake gate, or drop the pin — so those are guarded as pairs:
the TLS-layer accept may not exist without the verify that replaces it.
"""

from pathlib import Path

from csource_scan import calls_in_order, function_body, strip_comments

REPO_ROOT = Path(__file__).resolve().parents[1]
GSIFTP = REPO_ROOT / "src/fs/backend/gsiftp"
DC_C = GSIFTP / "gftp_dc.c"
DC_TLS_C = GSIFTP / "gftp_dc_tls.c"
DATA_C = GSIFTP / "gftp_data.c"
SPAS_C = GSIFTP / "gftp_spas.c"
EV_DIR = REPO_ROOT / "src/protocols/gridftp/ev"
EV_DATA_C = EV_DIR / "ftp_ev_data.c"
EV_XFER_C = EV_DIR / "ftp_ev_xfer.c"

# The three outbound transfer functions that open a data channel and issue the
# command that arms the origin's side of it.
TRANSFER_SITES = (
    ("gftp_transfer_begin", "gftp_transfer_command", "gftp_dc_secure"),
    ("gftp_retrieve_eret", "gftp_command", "gftp_dc_group_secure"),
    ("gftp_retrieve_positioned", "gftp_transfer_command",
     "gftp_dc_group_secure"),
)


def _text(path: Path) -> str:
    return path.read_text(encoding="utf-8", errors="replace")


# ---- 1. the handshake follows the transfer command --------------------------

def test_the_dial_does_not_handshake():
    """`gftp_dc_open_at` connects and returns; it must not start TLS.

    This is the whole of finding (1) in one assertion.  The dial has no way of
    knowing whether a transfer command has been sent, so it is the one place
    that can never be allowed to handshake.
    """
    body = function_body(_text(DC_C), "gftp_dc_open_at")
    assert "gftp_dc_tls_start" not in body, body
    assert "SSL_connect" not in body, body


def test_every_transfer_site_secures_after_it_commands():
    """Dial, command, THEN handshake — at all three sites, in that order.

    The ordering is asserted against the command WRITE, not merely against the
    dial: a handshake placed between the two would deadlock exactly as the
    original did, and would still look like "secure() comes last" to a reader
    checking only the end of the function.
    """
    source = _text(DATA_C)
    for function, command, secure in TRANSFER_SITES:
        body = function_body(source, function)
        assert calls_in_order(body, command, secure), (
            f"{function} must send its transfer command ({command}) before "
            f"{secure}(): {body}"
        )


def test_the_origin_only_starts_its_side_on_the_transfer_command():
    """The other half of the interlock, in the inbound tree.

    The client's ordering is only load-bearing because the server behaves this
    way, so the server's behaviour is pinned here too — three links:

      * the origin handshakes on the ACCEPT, not when the socket appears;
      * the accept handler is armed by opening the data channel;
      * and opening the data channel has exactly ONE caller, in the transfer
        verb's file — not in PASV, which merely nominates the port.

    If any link moved, the client's "command first" rule would be describing a
    server that no longer exists, and this test says which link changed.
    """
    source = _text(EV_DATA_C)
    accept = function_body(source, "ev_accept_handler")
    assert "brix_ftp_ev_dc_start_tls" in accept, accept

    opener = function_body(source, "ev_data_open_passive")
    assert "ev_accept_handler" in opener, opener

    callers = [path for path in sorted(EV_DIR.glob("*.c"))
               if "brix_ftp_ev_data_open(" in strip_comments(_text(path))
               and path != EV_DATA_C]
    assert callers == [EV_XFER_C], callers


# ---- 2. and 3. the verdict is BriX's, and it is made after the handshake -----

def test_the_tls_layer_accepts_and_the_post_handshake_gate_decides():
    """The accept callback and the gate that justifies it, as one unit.

    Deleting `gftp_dc_tls_pin` would leave a data channel that accepts any
    certificate from anyone — a strictly worse outcome than the bug it fixed —
    so the accept is pinned to the existence of its replacement rather than on
    its own.
    """
    source = _text(DC_TLS_C)
    start = function_body(source, "gftp_dc_tls_start")
    assert "SSL_set_verify" in start, start
    assert "gftp_dc_tls_accept_cb" in start, start
    assert calls_in_order(start, "SSL_connect", "gftp_dc_tls_pin"), start

    pin = function_body(source, "gftp_dc_tls_pin")
    assert "brix_gsi_verify_chain" in pin, pin
    assert "brix_ftp_dc_dn_matches" in pin, pin


def test_the_pin_is_against_our_own_delegated_identity():
    """Finding (3): the base of the pin is our subject, not the peer's DN.

    `session->peer_dn` must still be READ — an unauthenticated control channel
    delegates nothing and PROT P must refuse it — but it may not be the base of
    the comparison.
    """
    source = _text(DC_TLS_C)
    pin = function_body(source, "gftp_dc_tls_pin")
    assert "gftp_dc_tls_self_dn" in pin, pin
    assert "peer_dn[0] == '\\0'" in pin, pin
    assert "dn_matches(res.dn_buf, (const u_char *) session->peer_dn" not in pin

    self_dn = function_body(source, "gftp_dc_tls_self_dn")
    assert "SSL_get_certificate" in self_dn, self_dn
    assert "X509_NAME_oneline" in self_dn, self_dn


def test_the_two_roles_share_one_pin_predicate():
    """Security-negative: no second copy of the DN comparison.

    A predicate that exists twice gets fixed once.  Both roles must reach
    ftp_dc_dn.h, and neither may grow its own prefix/`/CN=` walk — the shape
    that would silently diverge from the other end of the same feature.
    """
    for source in (_text(DC_TLS_C), _text(REPO_ROOT
                   / "src/protocols/gridftp/ftp_dc_sec.c")):
        assert "brix_ftp_dc_dn_matches" in source
        assert 'ngx_strncmp(p, "CN="' not in source, source


def test_a_failed_handshake_reports_the_verify_verdict():
    """The diagnostic that would have named finding (2) on the first attempt.

    "certificate verify failed" is what OpenSSL's queue says for every rejected
    chain; the verify RESULT is the part that says which rule rejected it, and
    it is the only part an operator can act on.
    """
    body = function_body(_text(DC_TLS_C), "gftp_dc_tls_connect_error")
    assert "SSL_get_verify_result" in body, body
    assert "X509_verify_cert_error_string" in body, body


def test_a_protected_channel_that_cannot_be_secured_is_closed():
    """Fail-closed, at the source level.

    `gftp_dc_secure` has one failure exit and it must close the connection: a
    demotion to cleartext here would be invisible to every caller, since a
    clear channel and a secured one are the same `gftp_dc_t` afterwards.
    """
    body = function_body(_text(DC_C), "gftp_dc_secure")
    assert calls_in_order(body, "gftp_dc_tls_start", "gftp_dc_close"), body
    assert "return -1;" in body, body


def test_the_striped_group_secures_every_connection_or_none():
    """The SPAS half: one unsecured stripe would leak that stripe's bytes."""
    body = function_body(_text(SPAS_C), "gftp_dc_group_secure")
    assert "gftp_dc_secure" in body, body
    assert "gftp_dc_group_close" in body, body
