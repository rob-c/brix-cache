"""
test_audit15f_tpc_cred_forward.py — `brix_webdav_tpc_credential_forward`
(audit §A2, testsuite-combinatorial-coverage-audit 2026-08-15: zero occurrences
anywhere in the tree, while the WebDAV TPC directives around it were covered).

The toggle decides WHOSE identity a TPC pull uses against the source.  On (the
default) the destination acts as the END USER: the raw JWT the request
authenticated with is appended as `Authorization: Bearer <token>` to the
outbound leg (webdav_tpc_forward_user_bearer, tpc_copy.c:259).  Off, the leg is
anonymous / service-cert only — the caller's credential must not leave this
host.

That makes the off case a credential-containment boundary, so it is asserted
negatively on the SOURCE's wire log, not on the destination's status code: a
capturing TLS mock records the Authorization header of everything the puller
asks it for.

Every location authenticates for real (`brix_webdav_auth required` +
`brix_token_config`) because rctx->bearer_token — the only thing the
forwarder can forward — is set exclusively by webdav_verify_bearer_token
(auth_token.c:332).  Under `auth none` both settings look identical, which is
precisely the trap this file avoids.
"""

import os
import shutil
import ssl

import pytest
import requests

from _test_audit15f_helpers import (CapturingSource, gets, mint_localhost_cert,
                                    serve)
from fleet_lifecycle_ports import LIFECYCLE_SHARED_PORTS
from server_registry import NginxInstanceSpec
from settings import NGINX_BIN, HOST, BIND_HOST

def _guard_credfwd_1():
    if not os.path.exists(NGINX_BIN):
        pytest.skip(f"nginx binary not found at {NGINX_BIN}")

def _guard_credfwd_2():
    if shutil.which("openssl") is None:
        pytest.skip("openssl not found — cannot mint the mock source's cert")


try:
    from tokenforge import TokenForge, write_scitokens_cfg
    _HAVE_TOKENFORGE = True
except Exception:                       # noqa: BLE001 — cryptography optional
    _HAVE_TOKENFORGE = False

pytestmark = [
    pytest.mark.timeout(120),
    pytest.mark.uses_lifecycle_harness,
    pytest.mark.xdist_group("lc-audit15f-credfwd"),
    pytest.mark.skipif(not _HAVE_TOKENFORGE,
                       reason="tokenforge (cryptography) unavailable"),
]

MOCK_PORT = LIFECYCLE_SHARED_PORTS["lc-audit15f-credfwd"]["extra"]["MOCK_PORT"]
PAYLOAD = b"audit15f-credential-forwarding-payload-" * 64
PLANES = ("fwd", "nofwd")
# A COPY writes at the destination and reads at the source, so the caller's
# token has to carry both.
SCOPE = "storage.read:/ storage.create:/ storage.modify:/"


@pytest.fixture()
def credfwd(lifecycle, tmp_path):
    _guard_credfwd_1()
    _guard_credfwd_2()

    mint = tmp_path / "mint"
    forge = TokenForge(str(mint))
    forge.init_keys()
    token_cfg = mint / "scitokens.cfg"
    write_scitokens_cfg(str(token_cfg), [{
        "name": "credfwd", "issuer": forge.issuer,
        "audience": forge.audience, "base_paths": ["/"],
        "jwks_path": forge.jwks_path, "strategy": "capability",
    }])
    cadir = tmp_path / "cadir"
    cadir.mkdir()

    cert, key = mint_localhost_cert(tmp_path)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(str(cert), str(key))
    source = serve(CapturingSource, MOCK_PORT, tls=ctx, payload=PAYLOAD)

    export = tmp_path / "export"
    for plane in PLANES:
        _plane_dir(export, plane).mkdir(parents=True)
    for path in (tmp_path, export, *(export / p for p in PLANES),
                 *(_plane_dir(export, p) for p in PLANES)):
        os.chmod(path, 0o777)

    try:
        ep = lifecycle.start(NginxInstanceSpec(
            name="lc-audit15f-credfwd",
            template="nginx_audit15f_credfwd.conf",
            protocol="webdav",
            data_root=str(export),
            template_values={"BIND_HOST": BIND_HOST,
                             "EXPORT_ROOT": str(export),
                             "CA_PEM": str(cert),
                             "CADIR": str(cadir),
                             "TOKEN_CFG": str(token_cfg)},
            reason="audit-15f TPC credential forwarding"))
        yield ep, export, forge, source.recorded
    finally:
        source.shutdown()
        source.server_close()


def _plane_dir(export, plane):
    """Each location has its own export root and the wire path keeps the
    location prefix, so plane P's objects land under <root-of-P>/P/."""
    return export / plane / plane


def _landed(export, plane, name):
    path = _plane_dir(export, plane) / name
    return path.read_bytes() if path.exists() else None


def _copy(ep, plane, name, token=None, headers=None, obj="/obj.bin"):
    hdrs = {"Source": f"https://{HOST}:{MOCK_PORT}{obj}"}
    if token is not None:
        hdrs["Authorization"] = f"Bearer {token}"
    hdrs.update(headers or {})
    return requests.request("COPY", f"http://{HOST}:{ep.port}/{plane}/{name}",
                            headers=hdrs, timeout=60)


def _errlog(ep):
    """Instance logs are wiped at teardown, so failures quote them inline."""
    try:
        with open(os.path.join(ep.prefix, "logs", "error.log")) as fh:
            return fh.read()[-4000:]
    except FileNotFoundError:
        return ""


def test_forwarding_presents_the_callers_own_token_to_the_source(credfwd):
    """Default ON: the destination pulls AS THE USER — the source sees the very
    JWT the client authenticated with, not a service credential."""
    ep, export, forge, source = credfwd
    token = forge.generate(sub="alice", scope=SCOPE)
    r = _copy(ep, "fwd", "forwarded.bin", token=token)
    assert r.status_code == 201, (r.status_code, r.text[:400], _errlog(ep))
    assert _landed(export, "fwd", "forwarded.bin") == PAYLOAD
    auths = [row["auth"] for row in gets(source, "/obj.bin")]
    assert auths == [f"Bearer {token}"], \
        ("the pull leg did not carry the caller's own token", auths)


def test_forwarding_off_leaks_no_credential_to_the_source(credfwd):
    """Security-negative and the whole point of the toggle: with forwarding off
    the same authenticated COPY still succeeds, but the source leg carries NO
    credential at all — the caller's JWT stays on this host."""
    ep, export, forge, source = credfwd
    token = forge.generate(sub="alice", scope=SCOPE)
    r = _copy(ep, "nofwd", "contained.bin", token=token)
    assert r.status_code == 201, (r.status_code, r.text[:400], _errlog(ep))
    assert _landed(export, "nofwd", "contained.bin") == PAYLOAD, \
        "turning forwarding off broke the transfer instead of anonymising it"
    pulled = gets(source, "/obj.bin")
    assert len(pulled) == 1, pulled
    assert pulled[0]["auth"] is None, \
        ("the user's credential reached the source with forwarding off",
         pulled[0]["auth"])
    # Belt and braces: the token must not appear anywhere in the source's log
    # under another header spelling either.
    assert token not in repr(source), token[:24]


def test_explicit_transfer_header_is_never_overridden(credfwd):
    """Forwarding is OPPORTUNISTIC (tpc_copy.c:276): a client that spelled out
    its own TransferHeaderAuthorization keeps it — the default must not silently
    replace an explicitly delegated credential with the login token."""
    ep, export, forge, source = credfwd
    token = forge.generate(sub="alice", scope=SCOPE)
    delegated = "delegated-by-the-client-audit15f"
    r = _copy(ep, "fwd", "explicit.bin", token=token,
              headers={"TransferHeaderAuthorization": f"Bearer {delegated}"})
    assert r.status_code == 201, (r.status_code, r.text[:400], _errlog(ep))
    assert _landed(export, "fwd", "explicit.bin") == PAYLOAD
    auths = [row["auth"] for row in gets(source, "/obj.bin")]
    assert auths == [f"Bearer {delegated}"], \
        ("the caller's explicit transfer header was overridden", auths)


def test_unauthenticated_copy_never_reaches_the_source(credfwd):
    """Error case: no bearer under `brix_webdav_auth required`.  The COPY is
    refused, and — the part worth asserting — the source is never dialled, so
    an anonymous caller cannot use the destination as a pull proxy."""
    ep, export, _forge, source = credfwd
    r = _copy(ep, "fwd", "anon.bin")
    assert r.status_code in (401, 403), \
        f"anonymous COPY accepted under auth required: {r.status_code}"
    assert _landed(export, "fwd", "anon.bin") is None
    assert not source, ("the refused COPY still dialled the source", source)
