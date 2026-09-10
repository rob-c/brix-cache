"""2.0 F9 — SSS identity forwarding through the tap proxy.

Through 1.x a tap proxy authenticating upstream with SSS always presented the
keytab key's own user: every client behind the proxy arrived at the origin as
the same principal, so the origin could authorize the proxy but never the
person.  F9 adds `brix_tap_proxy_sss_identity`:

    keytab   the 1.x wire, byte for byte, and still the default
    client   the upstream credential carries the authenticated front-side
             client's entity — name, VO, role, groups, endorsements and the
             proxied credential the front's own keytab policy kept

The dangerous shape is the third one nobody asks for: an *unauthenticated*
front session in `client` mode.  There is no identity to forward, and quietly
falling back to the keytab user would launder an anonymous client into a named
one at the origin.  That case must be refused, and the origin must never see a
session at all.

Reading the evidence: the front and the origin share one error log, and both
write the same accept line.  The origin's keytab pins `g:origingrp` (it is the
only one of the three without `g:anygroup`), so `group="origingrp"` marks its
lines and nothing else can be mistaken for them.  A forwarded session is
therefore two lines in a known order — the client's arrival at the front, then
the proxy's arrival at the origin.
"""

import os
import subprocess

import pytest

from _release20_sss_helpers import (SssOk, cut_keytabs, err_text, log_since,
                                    log_size, ok_lines, sss_login, start_lab)
from _test_sss_helpers import (SSS_TYPE_CRED, SSS_TYPE_ENDO, SSS_TYPE_GRPS,
                               SSS_TYPE_ROLE, SSS_TYPE_VORG, sss_packed)
from fleet_lifecycle_ports import SHARED_PARSE_PLACEHOLDER_PORT
from server_registry import NginxInstanceSpec
from settings import BIND_HOST, HOST, NGINX_BIN
from test_phase25_ratelimit import KXR_OK, _xrd_login, _xrd_open, _xrd_read

pytestmark = [
    pytest.mark.serial,
    pytest.mark.timeout(300),
    pytest.mark.uses_lifecycle_harness,
    pytest.mark.xdist_group("lc-r20-sss-proxied"),
]

NAME = "lc-r20-sss-proxied"
SEED = b"sss-proxied-payload\n"
LFN = "/src.bin"

KXR_ERROR = 4003
XERR_IO_ERROR = 3007
XERR_NOT_AUTHORIZED = 3010
REFUSAL = "proxy: SSS identity forwarding refused: client is not authenticated"

ENDORSEMENT = "wlcg.groups:/cms/production"
CRED_BLOB = b"proxied-credential-bytes"
ENTITY = (
    (SSS_TYPE_VORG, sss_packed("cms")),
    (SSS_TYPE_ROLE, sss_packed("production")),
    (SSS_TYPE_GRPS, sss_packed("cms,atlas")),
    (SSS_TYPE_ENDO, sss_packed(ENDORSEMENT)),
    (SSS_TYPE_CRED, CRED_BLOB),
)

# What each hop logs for the entity above.  The front lets the credential name
# itself (its keytab is u:anybody g:anygroup); the origin's keytab is ANYUSR
# too, so the forwarded name stands, but its fixed group is what marks the line.
FRONT = SssOk("px-client", "cms,atlas", "cms", "production",
              len(ENDORSEMENT), len(CRED_BLOB))
ORIGIN = FRONT._replace(group="origingrp")
# keytab mode says nothing about the client: the key's own user, v1 wire.
ORIGIN_KEYTAB_MODE = SssOk("anybody", "origingrp", "-", "-", 0, 0)


@pytest.fixture(scope="module")
def lab(tmp_path_factory):
    key = os.urandom(32)
    tabs = cut_keytabs(tmp_path_factory.mktemp("r20_sss_proxied_keys"), key,
                       ("any", "origin"))
    node = start_lab(
        tmp_path_factory, name=NAME, template="nginx_release20_sss_proxied.conf",
        roots=("src",), seed_roots=("src",), seed=SEED,
        extra_ports=("KEYTAB_PORT", "ANON_PORT", "ORIGIN_PORT"),
        extra_values={"ANY_KEYTAB": tabs["any"], "ORIGIN_KEYTAB": tabs["origin"]},
        reason="2.0 F9: SSS identity forwarding")
    node["key"] = key
    yield node
    node["harness"].close()


def _read_through(lab, port_key, **cred):
    """Authenticate at a front, read LFN through it; (bytes, fresh log)."""
    mark = log_size(lab["endpoint"])
    sock, status, body = sss_login(lab["ports"][port_key], lab["key"], **cred)
    try:
        assert status == KXR_OK, err_text(body)
        status, body = _xrd_open(sock, LFN)
        assert status == KXR_OK, err_text(body)
        status, data = _xrd_read(sock, body[:4], 0, len(SEED))
        assert status == KXR_OK, err_text(data)
    finally:
        sock.close()
    return data, log_since(lab["endpoint"], mark)


# -- success ----------------------------------------------------------------


def test_client_mode_forwards_the_authenticated_client(lab):
    """Two hops, two accept lines: the same entity arrives at the origin as
    the client presented it at the front, and the data comes back."""
    data, fresh = _read_through(lab, "PORT", username="px-client", tlvs=ENTITY)

    assert data == SEED
    assert ok_lines(fresh) == [FRONT, ORIGIN]


def test_keytab_mode_forwards_the_keytab_user_not_the_client(lab):
    """The 1.x behaviour is still reachable and still identity-blind: the
    client's VO, role, endorsement and credential stop at the front.

    The client-mode read first is deliberate: it leaves an upstream connection
    in the pool that is logged in at the origin AS px-client.  This front must
    not inherit it -- that it opens (and is seen opening) its own keytab-mode
    session is the witness that pooled connections do not cross a forwarding
    mode.  Before the pool was keyed on identity, this test saw no origin line
    at all, because the client-mode connection had been handed straight to it.
    """
    _read_through(lab, "PORT", username="px-client", tlvs=ENTITY)
    data, fresh = _read_through(lab, "KEYTAB_PORT", username="px-client",
                                tlvs=ENTITY)

    assert data == SEED
    assert ok_lines(fresh) == [FRONT, ORIGIN_KEYTAB_MODE]


def test_a_name_only_client_forwards_a_name_only_entity(lab):
    """Forwarding carries what the client had, and invents nothing: a v1
    credential in must be a v1-shaped identity out."""
    data, fresh = _read_through(lab, "PORT", username="v1-px")

    assert data == SEED
    assert ok_lines(fresh) == [SssOk("v1-px", "nogroup", "-", "-", 0, 0),
                               SssOk("v1-px", "origingrp", "-", "-", 0, 0)]


# -- error ------------------------------------------------------------------


def _anon_open(lab):
    """An anonymous session at the client-mode front, one open; (status, body,
    fresh log).  The socket is closed before the log is read."""
    mark = log_size(lab["endpoint"])
    sock = _xrd_login(HOST, lab["ports"]["ANON_PORT"])
    try:
        status, body = _xrd_open(sock, LFN)
    finally:
        sock.close()
    return status, body, log_since(lab["endpoint"], mark)


def test_an_unauthenticated_front_session_is_refused(lab):
    """`brix_auth none` marks a session authenticated-as-nobody; client mode
    has nothing to forward and must say so instead of guessing."""
    status, body, _fresh = _anon_open(lab)

    assert status == KXR_ERROR, (status, body)
    assert err_text(body) == (XERR_IO_ERROR, REFUSAL)


def test_the_refusal_is_not_a_one_shot(lab):
    """A refused session stays usable and keeps refusing: the front does not
    fall back to the keytab user on a retry, and does not wedge either."""
    mark = log_size(lab["endpoint"])
    sock = _xrd_login(HOST, lab["ports"]["ANON_PORT"])
    try:
        first = _xrd_open(sock, LFN)
        second = _xrd_open(sock, LFN)
    finally:
        sock.close()

    assert [first[0], second[0]] == [KXR_ERROR, KXR_ERROR]
    assert err_text(second[1]) == (XERR_IO_ERROR, REFUSAL)
    assert ok_lines(log_since(lab["endpoint"], mark)) == []


# -- the upstream connection pool -------------------------------------------
#
# The proxy keeps authenticated upstream connections in a worker-local pool and
# hands them to later sessions.  Under `client` mode that pooled connection IS
# an identity: it is logged in at the origin as whoever opened it.  The three
# tests below pin the three halves of that -- reuse still happens, it never
# crosses an identity, and a refusal costs the origin nothing.


def test_a_second_read_by_the_same_client_reuses_the_upstream(lab):
    """The pool still pools: the same entity twice logs in at the origin once.
    A second origin accept line here would mean the fix below (keying reuse on
    the forwarded identity) had simply turned pooling off."""
    _read_through(lab, "PORT", username="px-client", tlvs=ENTITY)
    data, fresh = _read_through(lab, "PORT", username="px-client", tlvs=ENTITY)

    assert data == SEED
    assert ok_lines(fresh) == [FRONT]


def test_a_different_client_never_inherits_another_clients_upstream(lab):
    """The security half.  A pooled connection carries the entity it was minted
    with, so handing it to the next client would authorize that client's reads
    as somebody else at the origin.  The second client must open (and be seen
    opening) its own upstream session under its own name."""
    _read_through(lab, "PORT", username="px-client", tlvs=ENTITY)
    data, fresh = _read_through(lab, "PORT", username="px-other", tlvs=ENTITY)

    assert data == SEED
    assert ok_lines(fresh) == [FRONT._replace(user="px-other"),
                               ORIGIN._replace(user="px-other")]


def test_a_refused_session_does_not_mark_the_origin_down(lab):
    """A forwarding refusal is OUR decision -- the origin never saw the session
    and said nothing about itself.  Charging it against the upstream's health
    would let an anonymous client mark a healthy origin DOWN after
    BRIX_PROXY_MAX_FAILS refusals and blackhole every other session on the
    worker: an unauthenticated remote denial of service."""
    for _ in range(6):          # BRIX_PROXY_MAX_FAILS is 3
        status, _body, _fresh = _anon_open(lab)
        assert status == KXR_ERROR

    mark = log_size(lab["endpoint"])
    data, fresh = _read_through(lab, "PORT", username="px-healthy", tlvs=ENTITY)

    assert data == SEED
    assert ok_lines(fresh)[-1] == ORIGIN._replace(user="px-healthy")
    assert "upstream(s) down" not in log_since(lab["endpoint"], mark)


# -- security negatives -----------------------------------------------------


def test_the_refusal_never_reaches_the_origin(lab):
    """The whole point: no upstream credential is minted, so the origin logs
    no session at all.  A fallback to the keytab user would show up here as an
    `anybody`/`origingrp` accept line."""
    _status, _body, fresh = _anon_open(lab)

    assert ok_lines(fresh) == []
    assert REFUSAL in fresh


def test_the_origin_is_closed_to_an_unauthenticated_client(lab):
    """And the origin is not merely unused — it refuses a direct anonymous
    connection too, so the front is not the only thing standing in the way."""
    sock = _xrd_login(HOST, lab["ports"]["ORIGIN_PORT"])
    try:
        status, body = _xrd_open(sock, LFN)
    finally:
        sock.close()

    assert status == KXR_ERROR, (status, body)
    assert err_text(body) == (XERR_NOT_AUTHORIZED, "authentication required")


# -- grammar ----------------------------------------------------------------


def _render_and_test(lifecycle, tmp_path, line):
    reg = lifecycle.register(NginxInstanceSpec(
        name="lc-r20-sss-validate", template="nginx_release20_sss_validate.conf",
        protocol="none", readiness="none", port=SHARED_PARSE_PLACEHOLDER_PORT,
        data_root=str(tmp_path),
        template_values={"BIND_HOST": BIND_HOST, "SSS_LINES": f"        {line}\n"},
        reason="2.0 F9: brix_tap_proxy_sss_identity grammar"))
    endpoint = lifecycle.launcher.render_nginx(reg)
    return subprocess.run([NGINX_BIN, "-t", "-p", endpoint.prefix, "-c", "conf/nginx.conf"],
                          capture_output=True, text=True, timeout=30)


class TestGrammar:
    @pytest.mark.parametrize("line", ["brix_tap_proxy_sss_identity keytab;",
                                      "brix_tap_proxy_sss_identity client;"])
    def test_both_modes_parse(self, lifecycle, tmp_path, line):
        result = _render_and_test(lifecycle, tmp_path, line)
        assert result.returncode == 0, result.stderr

    @pytest.mark.parametrize("line,needle", [
        ("brix_tap_proxy_sss_identity both;",
         'invalid value "both"; use keytab or client'),
        ("brix_tap_proxy_sss_identity;", "invalid number of arguments"),
        ("brix_tap_proxy_sss_identity keytab client;",
         "invalid number of arguments"),
    ])
    def test_anything_else_is_refused(self, lifecycle, tmp_path, line, needle):
        result = _render_and_test(lifecycle, tmp_path, line)
        assert result.returncode != 0, result.stdout
        assert needle in result.stderr, result.stderr
