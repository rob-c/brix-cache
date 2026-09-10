"""2.0 F9 — the SSS v2 entity fields on the wire.

XRootD's XrdSecsss carries a whole XrdSecEntity inside the credential, not
just a user name: VO, role, groups, endorsements and, when the server opts in,
a proxied credential.  Through 1.x this module parsed NAME, GRPS and HOST and
silently ignored everything else, so a client that presented a VO got the same
identity as one that presented none.  F9 parses the full entity, and decides
per keytab how much of it is trusted:

  * a key mapped to `anybody`/`allusers` lets the credential name itself, so
    its VO/role/endorsements stand;
  * a key that pins the identity to one local user drops every asserted
    attribute — a holder of a pinned key must not be able to decorate itself
    with a VO the operator never granted;
  * a proxied credential is kept only where `brix_sss_getcreds on` says so.

The witness for all of it is the one INFO line the server writes per accepted
credential, whose `user`/`group` prefix is byte-identical to 1.x:

    brix: SSS auth OK user=".." group=".." vorg=".." role=".." endo=N creds=M

Every field cap is a hard refusal rather than a truncation: a NAME cut at 255
bytes is a *different* principal, and a cut credential is garbage that still
looks like one.  The negatives below drive each cap and each malformed TLV
shape from Python, so none of this depends on the native client being built.
"""

import os
import shutil
import subprocess

import pytest

from brix_suite.client_build import client_make
from _release20_sss_helpers import (SssOk, cut_keytabs, err_text, log_since,
                                    log_size, ok_lines, sss_login, sss_round,
                                    start_lab)
from _test_sss_helpers import (KXR_AUTHMORE, SSS_OPT_SNDLID, SSS_TYPE_CRED,
                               SSS_TYPE_ENDO, SSS_TYPE_GRPS, SSS_TYPE_LGID,
                               SSS_TYPE_ROLE, SSS_TYPE_VORG, sss_decrypt,
                               sss_identity_tlvs, sss_packed, sss_tlv)
from fleet_lifecycle_ports import SHARED_PARSE_PLACEHOLDER_PORT
from server_registry import NginxInstanceSpec
from settings import BIND_HOST, HOST, NGINX_BIN
from test_phase25_ratelimit import KXR_OK

pytestmark = [
    pytest.mark.serial,
    pytest.mark.timeout(240),
    pytest.mark.uses_lifecycle_harness,
    pytest.mark.xdist_group("lc-r20-sss-entity"),
]

NAME = "lc-r20-sss-entity"
SEED = b"sss-entity-payload\n"
KXR_ERROR = 4003
XERR_NOT_AUTHORIZED = 3010
REFUSAL = "SSS auth failed"

ENDORSEMENT = "wlcg.groups:/cms/production"
CRED_BLOB = b"proxied-credential-bytes"
ENTITY = (
    (SSS_TYPE_VORG, sss_packed("cms")),
    (SSS_TYPE_ROLE, sss_packed("production")),
    (SSS_TYPE_GRPS, sss_packed("cms,atlas")),
    (SSS_TYPE_ENDO, sss_packed(ENDORSEMENT)),
    (SSS_TYPE_CRED, CRED_BLOB),
)
# The entity as the ANY keytab accepts it, for the two faces that keep it all.
FULL = SssOk("ent-user", "cms,atlas", "cms", "production",
             len(ENDORSEMENT), len(CRED_BLOB))

# A key the server does not hold, presented under the key id it does: the id
# lookup succeeds and the CRC is what refuses, which is the wrong-key path.
WRONG_KEY = os.urandom(32)


@pytest.fixture(scope="module")
def lab(tmp_path_factory):
    key = os.urandom(32)
    tabs = cut_keytabs(tmp_path_factory.mktemp("r20_sss_entity_keys"), key,
                       ("any", "pinned"))
    node = start_lab(
        tmp_path_factory, name=NAME, template="nginx_release20_sss_entity.conf",
        roots=("src", "pinned", "nocreds"), seed_roots=("src",), seed=SEED,
        extra_ports=("PINNED_PORT", "NOCREDS_PORT"),
        extra_values={"ANY_KEYTAB": tabs["any"], "PINNED_KEYTAB": tabs["pinned"]},
        reason="2.0 F9: SSS v2 entity fields")
    node["key"] = key
    node["keytabs"] = tabs
    yield node
    node["harness"].close()


def _auth(lab, port_key="PORT", **cred):
    """One fresh session, one credential; returns (status, body, fresh log)."""
    mark = log_size(lab["endpoint"])
    sock, status, body = sss_login(lab["ports"][port_key], lab["key"], **cred)
    sock.close()
    return status, body, log_since(lab["endpoint"], mark)


# -- success ----------------------------------------------------------------


def test_the_full_entity_reaches_the_server(lab):
    status, body, fresh = _auth(lab, username="ent-user", tlvs=ENTITY)

    assert status == KXR_OK, err_text(body)
    assert ok_lines(fresh)[-1] == FULL


def test_a_v1_name_only_credential_is_unchanged(lab):
    """The 1.x wire still means exactly what it meant: a name, nothing else."""
    status, body, fresh = _auth(lab, username="v1-user")

    assert status == KXR_OK, err_text(body)
    assert ok_lines(fresh)[-1] == SssOk("v1-user", "nogroup", "-", "-", 0, 0)


def test_an_entity_field_one_short_of_its_cap_is_accepted(lab):
    """The cap is exclusive of the NUL, so cap-1 characters must still pass."""
    vorg = "v" * 255
    status, body, fresh = _auth(lab, username="cap-user",
                                tlvs=[(SSS_TYPE_VORG, sss_packed(vorg))])

    assert status == KXR_OK, err_text(body)
    assert ok_lines(fresh)[-1].vorg == vorg


def test_an_unknown_tlv_tag_is_ignored_not_refused(lab):
    """Forward compatibility: a tag this build does not know is skipped."""
    status, body, fresh = _auth(lab, username="fwd-user",
                                tlvs=[(0x7E, sss_packed("from-a-later-build")),
                                      (SSS_TYPE_VORG, sss_packed("cms"))])

    assert status == KXR_OK, err_text(body)
    assert ok_lines(fresh)[-1].vorg == "cms"


# -- error ------------------------------------------------------------------


def _refused(lab, port_key="PORT", **cred):
    status, body, fresh = _auth(lab, port_key, **cred)
    assert status == KXR_ERROR, (status, body)
    code, message = err_text(body)
    assert (code, message) == (XERR_NOT_AUTHORIZED, REFUSAL)
    assert ok_lines(fresh) == [], "a refused credential still logged an accept"


def test_a_name_at_its_cap_is_refused_not_truncated(lab):
    """255 characters + NUL is the last name that fits; 256 is a DIFFERENT
    principal, so it must fail the parse rather than land truncated."""
    _refused(lab, username="n" * 256)


def test_a_credential_blob_over_its_cap_is_refused(lab):
    _refused(lab, username="big-cred", tlvs=[(SSS_TYPE_CRED, b"c" * 4097)])


def test_a_tlv_header_cut_short_is_refused(lab):
    """A type byte with only one of its two length bytes behind it."""
    _refused(lab, username="short-hdr", trailer=bytes([SSS_TYPE_VORG, 0x00]))


def test_a_tlv_length_past_the_end_is_refused(lab):
    """The declared length overruns the block — the check that keeps a
    malformed credential from becoming an out-of-bounds read."""
    _refused(lab, username="overrun",
             trailer=sss_tlv(SSS_TYPE_VORG, b"x" * 4)[:-1])


# -- security negatives -----------------------------------------------------


def test_a_pinned_keytab_drops_every_client_asserted_attribute(lab):
    """The holder of a pinned key cannot name itself, nor decorate itself with
    a VO, role or endorsement.  The proxied credential is NOT part of this
    decision: it has its own explicit switch (brix_sss_getcreds), which this
    face has on, so it survives while the asserted attributes do not."""
    status, body, fresh = _auth(lab, "PINNED_PORT", username="impostor",
                                tlvs=ENTITY)

    assert status == KXR_OK, err_text(body)
    assert ok_lines(fresh)[-1] == SssOk("brixpinned", "brixpinned", "-", "-",
                                        0, len(CRED_BLOB))
    assert "SSS entity fields dropped: keytab pins the identity" in fresh


def test_getcreds_off_drops_the_proxied_credential(lab):
    """The default: a peer may present a credential, the server does not keep
    it.  Everything else about the same entity still stands, so the drop is
    attributable to brix_sss_getcreds and to nothing else."""
    status, body, fresh = _auth(lab, "NOCREDS_PORT", username="cred-user",
                                tlvs=ENTITY)

    assert status == KXR_OK, err_text(body)
    assert ok_lines(fresh)[-1] == FULL._replace(user="cred-user", creds=0)
    assert "SSS proxied credential dropped: brix_sss_getcreds is off" in fresh


def test_the_sndlid_challenge_completes_a_second_round(lab):
    """SNDLID asks the server for a login id instead of asserting one.  The
    reply is a BF32 block under the same key carrying an LGID field; the
    client then presents a self-contained credential."""
    mark = log_size(lab["endpoint"])
    sock, status, body = sss_login(lab["ports"]["PORT"], lab["key"],
                                   username="lid-user", opt=SSS_OPT_SNDLID)
    try:
        assert status == KXR_AUTHMORE, err_text(body)
        assert (SSS_TYPE_LGID, b"nobody\x00") in \
            sss_identity_tlvs(sss_decrypt(lab["key"], body))
        status, body = sss_round(sock, lab["key"], username="lid-user",
                                 tlvs=ENTITY)
    finally:
        sock.close()

    assert status == KXR_OK, err_text(body)
    assert ok_lines(log_since(lab["endpoint"], mark))[-1] == \
        FULL._replace(user="lid-user")


def test_a_wrong_key_in_the_second_round_is_denied(lab):
    """The challenge does not authenticate anybody: the round that follows it
    is verified against the keytab exactly like a first round would be."""
    sock, status, body = sss_login(lab["ports"]["PORT"], lab["key"],
                                   username="lid-user", opt=SSS_OPT_SNDLID)
    try:
        assert status == KXR_AUTHMORE, err_text(body)
        status, body = sss_round(sock, WRONG_KEY, username="lid-user")
    finally:
        sock.close()

    assert status == KXR_ERROR, (status, body)
    assert err_text(body) == (XERR_NOT_AUTHORIZED, REFUSAL)


# -- grammar ----------------------------------------------------------------


def _render_and_test(lifecycle, tmp_path, line):
    reg = lifecycle.register(NginxInstanceSpec(
        name="lc-r20-sss-validate", template="nginx_release20_sss_validate.conf",
        protocol="none", readiness="none", port=SHARED_PARSE_PLACEHOLDER_PORT,
        data_root=str(tmp_path),
        template_values={"BIND_HOST": BIND_HOST, "SSS_LINES": f"        {line}\n"},
        reason="2.0 F9: brix_sss_getcreds grammar"))
    endpoint = lifecycle.launcher.render_nginx(reg)
    return subprocess.run([NGINX_BIN, "-t", "-p", endpoint.prefix, "-c", "conf/nginx.conf"],
                          capture_output=True, text=True, timeout=30)


class TestGrammar:
    @pytest.mark.parametrize("line", ["brix_sss_getcreds on;", "brix_sss_getcreds off;"])
    def test_both_flag_values_parse(self, lifecycle, tmp_path, line):
        result = _render_and_test(lifecycle, tmp_path, line)
        assert result.returncode == 0, result.stderr

    @pytest.mark.parametrize("line,needle", [
        ("brix_sss_getcreds maybe;", 'invalid value "maybe"'),
        ("brix_sss_getcreds;", "invalid number of arguments"),
        ("brix_sss_getcreds on off;", "invalid number of arguments"),
    ])
    def test_anything_but_a_flag_is_refused(self, lifecycle, tmp_path, line, needle):
        result = _render_and_test(lifecycle, tmp_path, line)
        assert result.returncode != 0, result.stdout
        assert needle in result.stderr, result.stderr


# -- the native client ------------------------------------------------------

CLIENT_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                          "client")
XRDFS = os.path.join(CLIENT_DIR, "bin", "xrdfs")
# Anything that would authenticate the client some other way, so an SSS failure
# cannot be papered over by a stray proxy or token in the environment.
_STRAY_CREDS = ("X509_USER_PROXY", "X509_CERT_DIR", "BEARER_TOKEN",
                "BEARER_TOKEN_FILE", "XrdSecsssKT")


@pytest.fixture(scope="module")
def client_built():
    if shutil.which("cc") is None and shutil.which("gcc") is None:
        pytest.skip("no C compiler to build the native client")
    proc = client_make(CLIENT_DIR, "xrdfs", capture_output=True, text=True,
                       timeout=300)
    if proc.returncode != 0 or not os.access(XRDFS, os.X_OK):
        pytest.skip(f"native build failed:\n{proc.stdout}\n{proc.stderr}")


def _xrdfs(lab, *args, timeout=60):
    """One xrdfs run against the any-keytab face, with the lab's keytab."""
    env = dict(os.environ)
    for name in _STRAY_CREDS:
        env.pop(name, None)
    env["XrdSecSSSKT"] = lab["keytabs"]["any"]
    url = f"root://{HOST}:{lab['ports']['PORT']}"
    return subprocess.run([XRDFS, "--auth", "sss", *args, url, "stat", "/src.bin"],
                          capture_output=True, text=True, env=env, timeout=timeout)


class TestNativeClient:
    """The client half of F9: the flags that put an entity on the wire.  The
    server's own accept line is the witness, so these prove the two halves
    agree about the layout rather than just that the client ran."""

    def test_the_entity_flags_reach_the_server(self, lab, client_built, tmp_path):
        creds = tmp_path / "proxied.creds"
        creds.write_bytes(CRED_BLOB)
        mark = log_size(lab["endpoint"])

        proc = _xrdfs(lab, "--sss-vorg", "cms", "--sss-role", "production",
                      "--sss-endorse", ENDORSEMENT,
                      "--sss-creds-file", str(creds))

        assert proc.returncode == 0, proc.stdout + proc.stderr
        line = ok_lines(log_since(lab["endpoint"], mark))[-1]
        assert (line.vorg, line.role, line.endo, line.creds) == \
            ("cms", "production", len(ENDORSEMENT), len(CRED_BLOB))

    def test_no_entity_flags_still_sends_the_v1_wire(self, lab, client_built):
        """The flags are opt-in: without them the client is a 1.x client."""
        mark = log_size(lab["endpoint"])

        proc = _xrdfs(lab)

        assert proc.returncode == 0, proc.stdout + proc.stderr
        line = ok_lines(log_since(lab["endpoint"], mark))[-1]
        assert (line.vorg, line.role, line.endo, line.creds) == ("-", "-", 0, 0)

    def test_sndlid_lets_the_server_name_the_session(self, lab, client_built):
        """--sss-sndlid asks for a login id first, then authenticates with it —
        two rounds where the v1 wire needs one, ending in the same accept."""
        mark = log_size(lab["endpoint"])

        proc = _xrdfs(lab, "--sss-sndlid", "--sss-vorg", "cms")

        assert proc.returncode == 0, proc.stdout + proc.stderr
        assert ok_lines(log_since(lab["endpoint"], mark))[-1].vorg == "cms"

    def test_an_over_cap_field_never_authenticates(self, lab, client_built):
        """The client does not validate the flag values, the mint does — so an
        over-cap VO must fail closed end to end, never arrive truncated."""
        mark = log_size(lab["endpoint"])

        proc = _xrdfs(lab, "--sss-vorg", "v" * 512)

        assert proc.returncode != 0, proc.stdout
        assert ok_lines(log_since(lab["endpoint"], mark)) == []
