"""Native root:// third-party copy driven by a WLCG bearer token.

Every native-TPC config in the tree was `brix_auth none` or `brix_auth gsi`, so
the whole token column of the TPC matrix was empty
(docs/refactor/testsuite-combinatorial-coverage-audit-2026-08-04.md §7 item 7):
nothing proved a bearer-authenticated client can drive a third-party copy, and
the destination's OUTBOUND source-leg token paths — `tpc_outbound_ztn()` in
src/tpc/gsi/gsi_outbound_common.c, reached through gsi_outbound_finish.c once
the source advertises `&P=ztn` — had no live coverage at all.

The three ways a destination can credential its pull leg are each a separate
listener of one nginx (configs/nginx_tpc_token.conf), so a single fixture
covers the whole axis:

  passthrough  the client's own inbound bearer is snapshotted at kXR_open
               (src/tpc/engine/launch.c tpc_pull_capture_passthrough_token) and
               replayed to the source — the server default, `passthrough-opt`
  bearer file  passthrough off + `brix_tpc_outbound_bearer_file`: the source
               authenticates the GATEWAY, not the end user
  nothing      passthrough off and no bearer file: the destination holds no ztn
               credential, so an authenticating source must refuse the pull

Coverage (success · error · security-negative):
  success       a token-authenticated `xrdcp --tpc only` commits a byte-exact
                copy on the passthrough destination, and again on the
                bearer-file destination
  non-vacuity   the SOURCE access log names the *client's* subject for the
                passthrough copy and the *gateway's* subject for the
                bearer-file copy — proving which credential actually crossed
                the pull leg rather than merely that bytes arrived
  error         a destination with no outbound credential fails the copy closed
                and commits nothing
  security-neg  no token at all, an expired token, a wrong-audience token, and
                a read-only token are each refused, and none of them leaves a
                destination file behind
"""

import os
import re
import shutil
import subprocess
import sys
import time

import pytest

from settings import (BIND_HOST, CA_DIR, HOST, NGINX_BIN, SERVER_CERT,
                      SERVER_KEY, TOKENS_DIR, XRDCP_BIN, url_host)
from server_launcher import LifecycleHarness
from server_registry import NginxInstanceSpec

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from utils.make_token import TokenIssuer                       # noqa: E402

pytestmark = [pytest.mark.serial, pytest.mark.timeout(300),
              pytest.mark.uses_lifecycle_harness,
              pytest.mark.xdist_group("lc-tpc-token")]

# The client drives both legs, so its token needs read on the source and
# create/modify on the destination.  The gateway credential only ever reads.
CLIENT_SUB = "tpc-client"
CLIENT_SCOPE = "storage.read:/ storage.create:/ storage.modify:/"
GATEWAY_SUB = "tpc-gateway"
GATEWAY_SCOPE = "storage.read:/"

_AUTH_OK_RE = re.compile(r'AUTH ok method=\w+ user="([^"]*)"')

PAYLOAD = bytes(range(251)) * 61          # 15311 B: not a round buffer size


def _anon_env(token_file=None):
    """A client environment with every ambient credential removed.

    Without this an X509 proxy or `XrdSecPROTOCOL` left in the developer's
    shell would satisfy the login and the token leg would never run.

    `X509_CERT_DIR` is then put back to the harness CA so XrdCl can verify the
    servers' in-protocol TLS — which is mandatory here, because XrdCl refuses
    to send a ztn credential over a cleartext connection.  Verification stays
    ON: this module must fail if the TLS leg is broken, and the harness host
    cert carries an `IP:127.0.0.1` SAN so the loopback URLs match it.
    """
    env = os.environ.copy()
    for key in ("X509_CERT_DIR", "X509_USER_PROXY", "X509_USER_CERT",
                "X509_USER_KEY", "XrdSecPROTOCOL", "XRD_SECPROTOCOL",
                "BEARER_TOKEN", "BEARER_TOKEN_FILE", "XrdSecSSSKT"):
        env.pop(key, None)
    env["X509_CERT_DIR"] = CA_DIR
    if token_file is not None:
        env["BEARER_TOKEN_FILE"] = token_file
    return env


def _xrdcp_tpc(src, dst, token_file=None, timeout=60):
    return subprocess.run(
        [XRDCP_BIN, "-f", "-s", "--tpc", "only", src, dst],
        env=_anon_env(token_file), stdout=subprocess.PIPE,
        stderr=subprocess.PIPE, timeout=timeout)


def _name(prefix):
    return f"{prefix}_{os.getpid()}_{time.monotonic_ns()}.dat"


def _write_token(path, text):
    """Write a bearer token 0600.

    XrdSecProtocolztn refuses to read a token file that is group- or world-
    readable ("operation not permitted because of excessive permissions"), and
    it does so before ever touching the wire — a 0644 token therefore fails the
    login with a bare "No protocols left to try" that looks like a server bug.
    """
    with open(path, "w") as fh:
        fh.write(text)
    os.chmod(path, 0o600)
    return path


def _access_subjects(log_path):
    """Every authenticated subject the access log recorded, oldest first.

    brix_access_log interleaves two record shapes; the session line is the one
    that carries identity:

        [ts] SESS <id> AUTH ok method=token user="tpc-client" vo="-"

    Reading `user=` rather than the transfer lines is deliberate: bytes moving
    proves a copy happened, not WHOSE credential opened the source.
    """
    subjects = []
    try:
        with open(log_path, errors="replace") as fh:
            for line in fh:
                match = _AUTH_OK_RE.search(line)
                if match:
                    subjects.append(match.group(1))
    except FileNotFoundError:
        pass
    return subjects


@pytest.fixture(scope="module")
def node(tmp_path_factory):
    if not os.access(NGINX_BIN, os.X_OK):
        pytest.skip(f"nginx not executable: {NGINX_BIN}")
    if shutil.which(XRDCP_BIN) is None and not os.path.isabs(XRDCP_BIN):
        pytest.skip("xrdcp not found")
    if not (os.path.exists(SERVER_CERT) and os.path.isdir(CA_DIR)):
        pytest.skip("harness PKI missing; TLS is mandatory for a ztn client")

    issuer = TokenIssuer(TOKENS_DIR)
    if not (os.path.exists(issuer.key_path)
            and os.path.exists(issuer.jwks_path)):
        issuer.init_keys()

    creds = tmp_path_factory.mktemp("tpc_token_creds")
    client_token = _write_token(
        creds / "client.jwt",
        issuer.generate(sub=CLIENT_SUB, scope=CLIENT_SCOPE))
    gateway_token = _write_token(
        creds / "gateway.jwt",
        issuer.generate(sub=GATEWAY_SUB, scope=GATEWAY_SCOPE))
    expired_token = _write_token(
        creds / "expired.jwt",
        issuer.generate_expired(sub=CLIENT_SUB, scope=CLIENT_SCOPE))
    wrong_aud_token = _write_token(
        creds / "wrongaud.jwt",
        issuer.generate(sub=CLIENT_SUB, scope=CLIENT_SCOPE,
                        audience="some-other-service"))
    readonly_token = _write_token(
        creds / "readonly.jwt",
        issuer.generate(sub=CLIENT_SUB, scope="storage.read:/"))

    roots = {key: tmp_path_factory.mktemp(f"tpc_token_{key}")
             for key in ("src", "dst", "bfile", "nopass")}

    harness = LifecycleHarness()
    try:
        endpoint = harness.start(NginxInstanceSpec(
            name="lc-tpc-token",
            template="nginx_tpc_token.conf",
            protocol="root",
            readiness="tcp",
            host=BIND_HOST,
            template_values={
                "BIND_HOST": BIND_HOST,
                "JWKS": issuer.jwks_path,
                "TOKEN_ISSUER": issuer.issuer,
                "TOKEN_AUDIENCE": issuer.audience,
                "BEARER_FILE": str(gateway_token),
                "CERT_FILE": SERVER_CERT,
                "KEY_FILE": SERVER_KEY,
                "CA_DIR": CA_DIR,
                "SRC_ROOT": str(roots["src"]),
                "DST_ROOT": str(roots["dst"]),
                "BFILE_ROOT": str(roots["bfile"]),
                "NOPASS_ROOT": str(roots["nopass"]),
            },
            reason="native root:// TPC credentialed by a WLCG bearer token"))
        host = url_host(HOST)
        yield {
            "roots": roots,
            "log_dir": os.path.join(endpoint.prefix, "logs"),
            "src_url": f"root://{host}:{endpoint.extra_ports['PORT_SRC']}",
            "dst_url": f"root://{host}:{endpoint.port}",
            "bfile_url": f"root://{host}:{endpoint.extra_ports['PORT_BFILE']}",
            "nopass_url": f"root://{host}:{endpoint.extra_ports['PORT_NOPASS']}",
            "client_token": str(client_token),
            "expired_token": str(expired_token),
            "wrong_aud_token": str(wrong_aud_token),
            "readonly_token": str(readonly_token),
        }
    finally:
        harness.close()


def _seed(node, name=None):
    name = name or _name("tpc_tok_src")
    (node["roots"]["src"] / name).write_bytes(PAYLOAD)
    return name


def _copy(node, dest_key, src_name, dst_name, token_file):
    """`xrdcp --tpc only` from the one source plane to the named destination.

    `dest_key` indexes both the URL (`<key>_url`) and the on-disk export root,
    so a test names the credential shape it is exercising and nothing else.
    """
    return _xrdcp_tpc(f"{node['src_url']}//{src_name}",
                      f"{node[dest_key + '_url']}//{dst_name}",
                      token_file=token_file)


def _dest_path(node, dest_key, dst_name):
    return node["roots"][dest_key] / dst_name


# --------------------------------------------------------------------------- #
# success
# --------------------------------------------------------------------------- #

def test_passthrough_destination_copies_with_the_client_token(node):
    """The default outbound mode replays the client's own inbound bearer to the
    source, so a plain token-authenticated `--tpc only` transfers end to end."""
    src_name = _seed(node)
    dst_name = _name("tpc_tok_pass_dst")
    result = _copy(node, "dst", src_name, dst_name, node["client_token"])
    assert result.returncode == 0, (
        "a bearer-authenticated TPC copy must succeed on the passthrough "
        f"destination: {result.stderr.decode(errors='replace')}")
    assert _dest_path(node, "dst", dst_name).read_bytes() == PAYLOAD, \
        "the passthrough copy committed a file that is not byte-exact"


def test_bearer_file_destination_copies_with_the_service_token(node):
    """With passthrough off the pull leg authenticates from
    brix_tpc_outbound_bearer_file — the gateway's own credential — which is the
    shape a site uses when end-user tokens must not leave the gateway."""
    src_name = _seed(node)
    dst_name = _name("tpc_tok_bfile_dst")
    result = _copy(node, "bfile", src_name, dst_name, node["client_token"])
    assert result.returncode == 0, (
        "a static outbound bearer file must credential the pull leg: "
        f"{result.stderr.decode(errors='replace')}")
    assert _dest_path(node, "bfile", dst_name).read_bytes() == PAYLOAD, \
        "the bearer-file copy committed a file that is not byte-exact"


# --------------------------------------------------------------------------- #
# non-vacuity: which credential actually crossed the pull leg
# --------------------------------------------------------------------------- #

def test_source_sees_the_client_subject_for_a_passthrough_pull(node):
    """Bytes arriving proves a copy happened, not WHOSE credential carried it.

    The source's access log records the authenticated subject of every session,
    so a passthrough pull must appear there under the client's subject: if the
    destination silently fell back to anonymous or to a service credential the
    transfer would still succeed and this is the only assertion that notices.
    """
    src_name = _seed(node)
    dst_name = _name("tpc_tok_subj_pass")
    result = _copy(node, "dst", src_name, dst_name, node["client_token"])
    assert result.returncode == 0, result.stderr.decode(errors="replace")
    subjects = _access_subjects(
        os.path.join(node["log_dir"], "brix_access_src.log"))
    assert CLIENT_SUB in subjects, \
        f"source never saw the client subject on a passthrough pull: {subjects}"


def test_source_sees_the_gateway_subject_for_a_bearer_file_pull(node):
    """The bearer-file destination must present the GATEWAY identity, not the
    client's — otherwise `brix_tpc_outbound_passthrough off` is not actually
    suppressing the forwarded inbound token."""
    src_name = _seed(node)
    dst_name = _name("tpc_tok_subj_bfile")
    result = _copy(node, "bfile", src_name, dst_name, node["client_token"])
    assert result.returncode == 0, result.stderr.decode(errors="replace")
    subjects = _access_subjects(
        os.path.join(node["log_dir"], "brix_access_src.log"))
    assert GATEWAY_SUB in subjects, \
        f"source never saw the gateway subject on a bearer-file pull: {subjects}"


# --------------------------------------------------------------------------- #
# error
# --------------------------------------------------------------------------- #

def test_destination_without_an_outbound_credential_fails_closed(node):
    """passthrough off and no bearer file: the destination has nothing to offer
    a source that advertises &P=ztn, so the pull must fail rather than commit a
    partial or empty file."""
    src_name = _seed(node)
    dst_name = _name("tpc_tok_nopass_dst")
    result = _copy(node, "nopass", src_name, dst_name, node["client_token"])
    assert result.returncode != 0, \
        "a destination with no outbound credential must not complete the copy"
    assert not _dest_path(node, "nopass", dst_name).exists(), \
        "a refused pull left a file behind on the destination"


# --------------------------------------------------------------------------- #
# security-negative
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize("token_key, why", [
    (None, "no bearer token at all"),
    ("expired_token", "an expired token"),
    ("wrong_aud_token", "a token minted for another audience"),
])
def test_bad_client_credential_is_refused(node, token_key, why):
    """None of these may authenticate the client, so no copy may start and the
    destination directory must stay clean."""
    src_name = _seed(node)
    dst_name = _name("tpc_tok_neg_dst")
    result = _copy(node, "dst", src_name, dst_name,
                   None if token_key is None else node[token_key])
    assert result.returncode != 0, f"{why} must not authenticate a TPC copy"
    assert not _dest_path(node, "dst", dst_name).exists(), \
        f"{why} was refused but still left a destination file"


def test_read_only_token_cannot_write_at_the_destination(node):
    """Authentication is not authorization: a `storage.read` token opens the
    source fine but must be refused the destination's write-open."""
    src_name = _seed(node)
    dst_name = _name("tpc_tok_ro_dst")
    result = _copy(node, "dst", src_name, dst_name, node["readonly_token"])
    assert result.returncode != 0, \
        "a read-only token must not be allowed to create the destination file"
    assert not _dest_path(node, "dst", dst_name).exists(), \
        "a read-only token created a destination file"
