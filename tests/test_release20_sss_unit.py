"""2.0 F9 — the C unit suites behind the SSS v2 entity, and its seams.

Two pure-C kernels carry what the live suites cannot reach corner by corner:
`sss_entity.c` (the shared credential builder — TLV packing, caps, the SNDLID
first round and the challenge decode) and the client's `sss_id.c` (the
per-connection identity registry `--sss-identity` selects from).  Each ships a
`*_unittest.c`; this wrapper compiles and runs both, so a change to either
kernel fails the Python tier.

The static pins below cover the seams a unit test cannot see: that the parser
keeps ONE field table rather than a per-tag if-chain, that client and server
mint credentials through the same kernel, and that the proxy's forwarding
decision is read from the directive rather than assumed.
"""

import os
import re
import shutil
import subprocess

import pytest

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SRC = os.path.join(REPO, "src")
CLIENT = os.path.join(REPO, "client")
COMPAT = os.path.join(SRC, "core", "compat")
CLIENT_SSS = os.path.join(CLIENT, "lib", "auth", "sss")

# The shared kernel and its two dependencies: every suite below links them.
KERNEL = [os.path.join(COMPAT, name)
          for name in ("sss_entity.c", "sss_bf.c", "crc32_ieee.c")]

# name -> (extra include dirs, sources, link flags)
SUITES = {
    "sss_entity": (["-I", SRC],
                   [os.path.join(COMPAT, "sss_entity_unittest.c"), *KERNEL],
                   ["-lcrypto"]),
    "sss_id": (["-I", SRC],
               [os.path.join(CLIENT_SSS, "sss_id_unittest.c"),
                os.path.join(CLIENT_SSS, "sss_id.c"), *KERNEL],
               ["-lcrypto", "-pthread"]),
}


def _guard_compiler():
    cc = shutil.which("cc") or shutil.which("gcc")
    if cc is None:
        pytest.skip("no C compiler on PATH")
    return cc


@pytest.fixture(scope="module", params=sorted(SUITES))
def unit_binary(request, tmp_path_factory):
    cc = _guard_compiler()
    includes, sources, link = SUITES[request.param]
    missing = [path for path in sources if not os.path.exists(path)]
    if missing:
        pytest.skip(f"unit sources missing: {missing}")
    out = str(tmp_path_factory.mktemp("f9unit") / request.param)
    build = subprocess.run([cc, "-std=c11", "-D_GNU_SOURCE", "-Wall", "-Wextra",
                            "-Werror", *includes, *sources, "-o", out, *link],
                           capture_output=True, text=True, timeout=180)
    if build.returncode != 0:
        pytest.fail(f"{request.param} failed to compile:\n{build.stderr}")
    return out


def test_unit_suite_passes(unit_binary):
    run = subprocess.run([unit_binary], capture_output=True, text=True, timeout=60)
    assert run.returncode == 0, run.stdout + run.stderr
    assert "all checks passed" in run.stdout


# -- seams ------------------------------------------------------------------


def _read(*parts):
    with open(os.path.join(*parts), encoding="utf-8") as fh:
        return fh.read()


def _source(*parts):
    return _read(SRC, *parts)


def test_the_parser_keeps_one_field_table():
    """Each packed-string field is declared once, in the table `sss_store_field`
    walks.  A second mention would be an if-chain growing back."""
    parser = _source("auth", "sss", "auth_identity_challenge.c")

    assert parser.count("static const sss_string_field_t") == 1
    for tag in ("NAME", "VORG", "ROLE", "GRPS", "ENDO"):
        assert parser.count(f"{{ BRIX_SSS_TYPE_{tag},") == 1, tag


def test_every_wire_tag_is_distinct():
    """Two fields sharing a tag would silently overwrite each other."""
    header = _source("protocols", "root", "protocol", "sss.h")
    tags = re.findall(r"#define\s+BRIX_SSS_TYPE_(\w+)\s+(0x[0-9a-fA-F]+)", header)

    assert len(tags) >= 9
    values = [value for _name, value in tags]
    assert len(set(values)) == len(values), tags


def test_client_and_server_mint_through_one_kernel():
    """The credential the proxy sends upstream and the one the native client
    sends are built by the same function, so they cannot drift apart."""
    server = _source("auth", "sss", "auth_proxy_credential.c")
    client = _read(CLIENT, "lib", "auth", "sec", "sec_sss.c")

    assert "brix_sss_build_entity_credential(" in server
    assert "brix_sss_build_entity_credential(" in client
    assert "brix_sss_challenge_lgid(" in client


def test_the_proxy_reads_the_forwarding_mode_from_the_directive():
    """`client` mode is a decision, not a default: the mint path branches on
    the configured value and refuses when there is no identity to forward."""
    arm = _source("net", "proxy", "events_bootstrap_auth.c")

    assert "proxy->conf->proxy.sss_identity != BRIX_PROXY_SSS_IDENT_CLIENT" in arm
    assert "SSS identity forwarding refused" in arm


def test_the_forwarding_default_is_the_1x_wire():
    """An existing deployment that never heard of F9 keeps sending the keytab
    user, byte for byte."""
    merge = _source("core", "config", "server_conf_merge_proxy_net.c")

    assert re.search(r"merge_uint_value\(conf->proxy\.sss_identity,\s*"
                     r"prev->proxy\.sss_identity,\s*BRIX_PROXY_SSS_IDENT_KEYTAB\)",
                     merge), merge


def test_the_upstream_pool_is_keyed_on_the_forwarded_identity():
    """A pooled upstream connection is logged in at the origin as whoever
    minted it.  Reuse is therefore matched on the server block AND on a digest
    of the identity this session would present -- the bearer token, the
    forwarded SSS entity, the passthrough login name.  Matching on the auth
    type alone (what 1.x did) hands one client's authenticated session to the
    next one."""
    pool = _source("net", "proxy", "pool.c")

    assert "proxy_pool_ident(proxy, conf, ident);" in pool
    assert "proxy_pool_ident(proxy, conf, pc->ident_hash);" in pool
    assert "if (pc->conf == conf && pc->upstream_idx == idx) {" in pool
    assert "ngx_memcmp(pc->ident_hash, ident, 16) == 0" in pool
    # the entity, the token and the login name each fold in under their own tag
    for tag in ('"E", 1', '"T", 1', '"L", 1'):
        assert f"MD5_Update(&md5, {tag});" in pool, tag
    assert "brix_proxy_sss_client_entity(proxy, &ent) == NGX_OK" in pool
    # and the old key is gone for good
    assert "token_hash" not in pool
    assert "token_hash" not in _source("net", "proxy", "proxy_internal.h")


def test_a_forwarding_refusal_is_not_charged_to_the_origin():
    """The refusal is our own policy decision -- the origin never saw the
    session.  Counting it as an upstream failure lets an anonymous client mark
    a healthy origin DOWN after BRIX_PROXY_MAX_FAILS and blackhole every other
    session on the worker."""
    arm = _source("net", "proxy", "events_bootstrap_auth.c")
    lifecycle = _source("net", "proxy", "connect_lifecycle.c")

    assert "proxy->policy_refusal = 1;" in arm
    assert re.search(r"if \(!proxy->policy_refusal\) \{\s*"
                     r"brix_proxy_up_mark_failed\(proxy\);", lifecycle), lifecycle
    assert lifecycle.count("brix_proxy_up_mark_failed(proxy);") == 1


def test_only_an_asserted_vo_and_role_are_forwarded():
    """The attribute view the proxy reads is DERIVED from the group CSV when
    nobody asserted anything (a bare group "nogroup" reads as a VO named
    "nogroup"), so forwarding it unconditionally manufactures a VO membership
    the client never claimed.  A v1 NAME-only credential must arrive
    v1-shaped."""
    arm = _source("net", "proxy", "events_bootstrap_auth.c")
    identity = _source("core", "types", "identity.c")

    assert re.search(r"if \(id->acc_attrs_asserted\) \{\s*"
                     r"ent->vorg = brix_identity_acc_vorg_cstr\(id\);\s*"
                     r"ent->role = brix_identity_acc_role_cstr\(id\);", arm), arm
    # set only where a peer actually asserted the fields
    assert identity.count("acc_attrs_asserted = 1;") == 1
    assert "brix_identity_set_sss_entity(" in identity
