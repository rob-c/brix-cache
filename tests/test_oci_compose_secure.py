# tests/test_oci_compose_secure.py — the D14 compositions, pinned instead of
# theoretical (phase-104 D14).
#
# Every earlier lane in this phase proves ONE plane: the mirror pulls, the
# registry accepts a push, `brixcvmfs ingest image` flattens an image into a
# Stratum-0. D14 is the claim that those planes compose on a real box without
# any of them growing a mode — that a site can run
#
#   /v2/        pull-through mirror of an upstream registry
#   /local/v2/  its own registry
#   /cvmfs/     the Stratum-0 the ingested images live in
#
# in one server block, put the private half of that image space behind a
# credential, and let a consuming site union the images repo behind its main
# software repo under one client-visible name — all of it configuration.
#
# Ports 14200-14203: 14200 mock registry, 14201 the public full-stack front,
# 14202 the consuming site's union front, 14203 the scvmfs-gated twin of 14201
# (same template, gate lines filled in — which is itself the D14 claim).
#
# Three legs, per the standing rule:
#   success  — the three surfaces answer on one box; an authorized client
#              pulls a private ingested image byte-for-byte; the union serves
#              the image repo from behind the main one;
#   error    — an anonymous read of the gated tree fails closed on EVERY
#              class, manifest included;
#   security — a verified-but-unlisted client is refused (401/403 matrix), a
#              wrong token on a gated union member is TERMINAL, and the write
#              methods the composition does not offer stay refused and audited.
import hashlib
import os
import shutil
import ssl
import subprocess
import sys
import urllib.error
import urllib.request
import zlib
from pathlib import Path

import pytest

from brix_suite.registry import NginxInstanceSpec
from cmdscripts.cvmfs_publish_txn import (cas_path, lookup, open_catalog,
                                          parse_manifest)
from oci.mirror_lane import error_log, get, spawn_mock, stop_mocks
from server_launcher import LifecycleHarness
from settings import BIND_HOST, HOST

# conftest chdir()s into a scratch dir — anchor imports on this file's dir.
def _check_instantiate_1(text):
    assert "@" not in "".join(
        line for line in text.splitlines() if not line.lstrip().startswith("#")
    ), "an example config still has an unsubstituted placeholder"


sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                "cvmfs"))

from conformance_common import NGINX_BIN                        # noqa: E402
from test_cvmfs_scvmfs_x509 import _leaf, _self_signed          # noqa: E402

try:                                     # cryptography is an optional test dep
    from tokenforge import TokenForge, write_scitokens_cfg
    _HAVE_TOKENFORGE = True
except Exception:                        # noqa: BLE001
    _HAVE_TOKENFORGE = False

REPO_ROOT = Path(__file__).resolve().parent.parent
BRIX = REPO_ROOT / "client" / "bin" / "brixcvmfs"
DEPLOY = REPO_ROOT / "deploy" / "oci-mirror"

MOCK_PORT = 14200
PUBLIC_PORT = 14201
SITE_PORT = 14202
GATED_PORT = 14203

FQRN_MAIN = "sw.brix.io"
FQRN_IMG = "img.brix.io"
VIRT = "site.brix.io"

#: The one image the private tree holds, and where `ingest image` puts it.
IMAGE = "lab/app:v1"
IMAGE_PREFIX = "images"

#: The DN the gated front admits — the glob is the one
#: deploy/oci-mirror/full-stack.conf.example ships.
DN_ALLOWED = "release-bot"
DN_REFUSED = "intern"

pytestmark = [
    pytest.mark.uses_lifecycle_harness,
    pytest.mark.xdist_group("lc-oci-compose"),
    # Two repo mkfs (an RSA key pair each), an image ingest and three nginx
    # instances: the 30 s default cannot fit this lane even all-green.
    pytest.mark.timeout(300),
    pytest.mark.skipif(not BRIX.exists(),
                       reason="client/bin/brixcvmfs not built (make -C client)"),
    pytest.mark.skipif(shutil.which("openssl") is None,
                       reason="openssl not installed"),
]


# ---- the published trees ---------------------------------------------------

def _brix(*args, home):
    # HOME always points at a scratch dir so a developer's real registry
    # credentials can never leak into a lane.
    env = dict(os.environ, HOME=str(home))
    proc = subprocess.run([str(BRIX), *map(str, args)], capture_output=True,
                          text=True, timeout=180, env=env)
    assert proc.returncode == 0, f"brixcvmfs {args[0]} {args[1]}: {proc.stderr}"
    return proc


class Trees:
    """The published web root plus the handles the assertions need."""

    def __init__(self, web, main, img, base):
        self.web = web
        self.main = main
        self.img = img
        self._base = base

    def _object(self, repo, path):
        """(url-relative CAS path, stored bytes) of one published file."""
        cat = open_catalog(repo, parse_manifest(repo)["C"], self._base)
        row = lookup(cat, path)
        cat.close()
        assert row is not None, f"{path} is not in the published catalog"
        digest = row[3].hex()
        return f"data/{digest[:2]}/{digest[2:]}", cas_path(repo, digest).read_bytes()

    @property
    def image_digest(self):
        """The sha256 the registry named this image by, read back from the
        ingest memo — the same string the flat .images/ root is named with."""
        memo = self.img / ".brix-ingest" / "memo" / IMAGE_PREFIX / HOST / IMAGE
        return memo.read_text().split()[1]

    def image_manifest_object(self):
        digest = self.image_digest
        root = f"/{IMAGE_PREFIX}/.images/sha256/{digest[7:]}"
        return self._object(self.img, f"{root}/.manifest.json")

    def software_object(self):
        return self._object(self.main, "/sw/hello.txt")


@pytest.fixture(scope="module")
def upstream():
    proc, base = spawn_mock(MOCK_PORT)
    yield base
    stop_mocks(proc)


@pytest.fixture(scope="module")
def trees(upstream, tmp_path_factory):
    """One web root, two Stratum-0 repos: the public software area (published
    from a folder) and the private image area (published from the registry).

    Both are ordinary published content — which is the point of the D14
    re-export claim: nothing downstream can tell which verb produced which
    subtree."""
    root = tmp_path_factory.mktemp("compose")
    (root / "web" / "cvmfs").mkdir(parents=True)
    main = root / "web" / "cvmfs" / FQRN_MAIN
    img = root / "web" / "cvmfs" / FQRN_IMG

    _brix("repo", "mkfs", FQRN_MAIN, main, home=root)
    _brix("repo", "mkfs", FQRN_IMG, img, home=root)

    src = root / "sw"
    src.mkdir()
    (src / "hello.txt").write_bytes(b"the site's own software area\n")
    _brix("ingest", "dir", src, "--repo", main, "--prefix", "/sw", home=root)
    _brix("ingest", "image", f"{HOST}:{MOCK_PORT}/{IMAGE}", "--repo", img,
          "--insecure", home=root)

    return Trees(root / "web", main, img, root)


@pytest.fixture(scope="module")
def pki(tmp_path_factory):
    """A trust root that signs the allowed and the refused client, plus a
    throwaway server cert for the two TLS fronts."""
    d = tmp_path_factory.mktemp("compose_pki")
    ca_crt, ca_key = _self_signed(d, "BriX Test CA", "ca")
    srv = _self_signed(d, "localhost", "server")  # net-literal-allow: throwaway TLS cert subject
    return {
        "ca": ca_crt,
        "server": srv,
        DN_ALLOWED: _leaf(d, DN_ALLOWED, ca_crt, ca_key, "allowed"),
        DN_REFUSED: _leaf(d, DN_REFUSED, ca_crt, ca_key, "refused"),
    }


# ---- the three fronts ------------------------------------------------------

@pytest.fixture(scope="module")
def harness():
    """One lifecycle harness for the whole file.

    The stock `lifecycle` fixture is function-scoped, and these fronts are
    not: publishing two repos and ingesting an image costs more than every
    assertion in this file put together, so the trees — and therefore the
    servers over them — are built once. Teardown still stops and unregisters
    everything the harness created."""
    h = LifecycleHarness()
    try:
        yield h
    finally:
        h.close()


def _full_stack(harness, name, port, trees, tmp_path, *,
                listen_ssl="", ssl_lines="", s0_lines=""):
    cache = tmp_path / f"{name}-cache"
    registry_root = tmp_path / f"{name}-registry"
    for path in (cache, registry_root):
        path.mkdir(parents=True, exist_ok=True)
    return harness.start(NginxInstanceSpec(
        name=name,
        template="oci_compose.conf",
        port=port,
        protocol="https" if listen_ssl else "http",
        readiness="tcp",
        template_values={
            "BIND_HOST": BIND_HOST,
            "LISTEN_SSL": listen_ssl,
            "SSL_LINES": ssl_lines,
            "MOCK_HOST": HOST,
            "MOCK_PORT": MOCK_PORT,
            "CACHE_DIR": str(cache),
            "REGISTRY_ROOT": str(registry_root),
            "WEB_ROOT": str(trees.web),
            "S0_LINES": s0_lines,
        },
        reason="phase-104 D14 full-stack composition lane",
    ))


@pytest.fixture(scope="module")
def public(harness, trees, tmp_path_factory):
    """The public box: mirror + local registry + ungated Stratum-0."""
    return _full_stack(harness, "lc-oci-compose-public", PUBLIC_PORT, trees,
                       tmp_path_factory.mktemp("public"))


@pytest.fixture(scope="module")
def gated(harness, trees, pki, tmp_path_factory):
    """The same template with the scvmfs gate lines filled in — a private
    image tree is the public one plus four directives, and nothing else."""
    crt, key = pki["server"]
    return _full_stack(
        harness, "lc-oci-compose-gated", GATED_PORT, trees,
        tmp_path_factory.mktemp("gated"),
        listen_ssl=" ssl",
        ssl_lines=(f"ssl_certificate {crt}; ssl_certificate_key {key};"
                   f" ssl_client_certificate {pki['ca']};"
                   f" ssl_verify_client optional;"),
        s0_lines=("brix_scvmfs on;\n"
                  "            brix_scvmfs_authz x509;\n"
                  f'            brix_scvmfs_x509_dn "*CN={DN_ALLOWED}*";'))


@pytest.fixture(scope="module")
def issuers(tmp_path_factory):
    """A SciTokens issuer table plus the forge that mints against it."""
    if not _HAVE_TOKENFORGE:
        pytest.skip("tokenforge (cryptography) unavailable")
    d = tmp_path_factory.mktemp("compose_tokens")
    forge = TokenForge(str(d / "mint"))
    forge.init_keys()
    cfg = d / "scitokens.cfg"
    write_scitokens_cfg(str(cfg), [{
        "name": "compose-authz", "issuer": forge.issuer,
        "audience": forge.audience, "base_paths": ["/"],
        "jwks_path": forge.jwks_path, "strategy": "capability",
    }])
    return forge, cfg


@pytest.fixture(scope="module")
def site(harness, public, pki, issuers, tmp_path_factory):
    """The consuming site: one client-visible repo name over two members, the
    image member gated on this front."""
    forge, cfg = issuers
    crt, key = pki["server"]
    tmp = tmp_path_factory.mktemp("site")
    (tmp / "cache").mkdir()
    return harness.start(NginxInstanceSpec(
        name="lc-oci-compose-site",
        template="oci_compose_site.conf",
        port=SITE_PORT,
        protocol="https",
        readiness="tcp",
        template_values={
            "BIND_HOST": BIND_HOST,
            "SSL_CERT": str(crt),
            "SSL_KEY": str(key),
            "ORIGIN_HOST": HOST,
            "ORIGIN_PORT": PUBLIC_PORT,
            "CACHE_DIR": str(tmp / "cache"),
            "VIRT": VIRT,
            "MEMBER_MAIN": FQRN_MAIN,
            "MEMBER_IMG": FQRN_IMG,
            "ISSUERS": str(cfg),
        },
        reason="phase-104 D14 virtual-union composition lane",
    ))


# ---- fetch helpers ---------------------------------------------------------

def _fetch(port, path, *, client=None, token=None):
    """One https GET; returns (status, body). The server cert is throwaway, so
    verification is off — the credential under test is the CLIENT's."""
    ctx = ssl._create_unverified_context()
    if client is not None:
        ctx.load_cert_chain(str(client[0]), str(client[1]))
    req = urllib.request.Request(f"https://{HOST}:{port}{path}")
    if token is not None:
        req.add_header("Authorization", f"Bearer {token}")
    try:
        with urllib.request.urlopen(req, timeout=30, context=ctx) as resp:
            return resp.status, resp.read()
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read()


def _sha256(body):
    return hashlib.sha256(body).hexdigest()


# ---- success: the three surfaces on one box --------------------------------

def test_full_stack_serves_mirror_registry_and_stratum0(public, trees):
    """One server block, three planes. The mirror pulls a manifest from
    upstream, the site's own registry answers its API root, and the Stratum-0
    serves the published software area — none of them aware of the others."""
    base = f"http://{HOST}:{PUBLIC_PORT}"

    status, _, body = get(
        f"{base}/v2/{IMAGE.split(':')[0]}/manifests/{IMAGE.split(':')[1]}",
        {"Accept": "application/vnd.oci.image.manifest.v1+json"})
    assert status == 200, body
    assert b"layers" in body

    status, _, _ = get(f"{base}/local/v2/")
    assert status == 200, "the local registry's API root did not answer"

    rel, stored = trees.software_object()
    status, _, body = get(f"{base}/cvmfs/{FQRN_MAIN}/{rel}")
    assert (status, body) == (200, stored)




def test_scvmfs_gated_private_image_authorized_pull(gated, trees, pki):
    """An authorized client reads the private image tree end to end: the
    signed manifest, and the CAS object holding the image's own OCI manifest —
    whose bytes still hash to the digest the REGISTRY named the image by.

    That last equality is the whole D14 story in one assertion: the image the
    upstream holds, the tree `ingest image` published, and the bytes a gated
    Stratum-0 hands back are one object, and the gate changed none of it."""
    client = pki[DN_ALLOWED]

    status, body = _fetch(GATED_PORT, f"/cvmfs/{FQRN_IMG}/.cvmfspublished",
                          client=client)
    assert (status, body) == (200, (trees.img / ".cvmfspublished").read_bytes())

    rel, stored = trees.image_manifest_object()
    status, body = _fetch(GATED_PORT, f"/cvmfs/{FQRN_IMG}/{rel}", client=client)
    assert (status, body) == (200, stored)
    assert _sha256(zlib.decompress(body)) == trees.image_digest[len("sha256:"):]


# ---- error: the gated tree fails closed without a credential ---------------

_SURFACE = [".cvmfspublished", ".cvmfswhitelist", ".cvmfs_master_replica"]


def test_anonymous_denied_401_403_matrix(gated, trees, pki):
    """The S14 matrix applied to an image tree. Anonymous is 401 on EVERY
    class — the manifest included, so the private image space cannot even be
    enumerated around the preamble — and a client whose chain verifies but
    whose DN is outside the allow-glob is 403: authenticated is not
    authorized, and the image bytes are not the thing being protected here,
    the whole namespace is."""
    rel, _ = trees.image_manifest_object()
    paths = [f"/cvmfs/{FQRN_IMG}/{name}" for name in _SURFACE]
    paths.append(f"/cvmfs/{FQRN_IMG}/{rel}")

    for path in paths:
        status, _ = _fetch(GATED_PORT, path)
        assert status == 401, f"anonymous {path}: {status}"
    for path in paths:
        status, _ = _fetch(GATED_PORT, path, client=pki[DN_REFUSED])
        assert status == 403, f"unlisted DN {path}: {status}"


# ---- success: the union serves the image repo from behind the main one -----

def test_virtual_union_serves_image_repo_behind_main(site, trees, issuers):
    """One client-visible name over two repos. An object only the main repo
    holds serves anonymously; an object only the IMAGE repo holds serves to a
    valid bearer, reached by the walk advancing past the main member's 404 —
    and the signed metadata stays member[0]'s, so precedence is deterministic
    rather than "whichever answered first"."""
    forge, _ = issuers

    main_rel, main_bytes = trees.software_object()
    status, body = _fetch(SITE_PORT, f"/cvmfs/{VIRT}/{main_rel}")
    assert (status, body) == (200, main_bytes)

    img_rel, img_bytes = trees.image_manifest_object()
    status, body = _fetch(SITE_PORT, f"/cvmfs/{VIRT}/{img_rel}",
                          token=forge.generate())
    assert (status, body) == (200, img_bytes)

    status, body = _fetch(SITE_PORT, f"/cvmfs/{VIRT}/.cvmfspublished")
    assert (status, body) == (200, (trees.main / ".cvmfspublished").read_bytes())


# ---- security-negative: a refused member is terminal, never a fall-through -

def test_wrong_token_terminal_no_fallthrough(site, trees, issuers):
    """The G16 security property re-pinned on this composition.

    Only a 404 advances the member walk. A credential the gated member
    refuses ends it — with no second look at any sibling, and above all no
    quiet substitution of whatever an UNGATED member happens to hold at the
    same path. The object under test exists only in the image repo, so a
    fall-through would be visible as a 200; every refusal below has to be a
    refusal.

    DRIFT vs §D14, which spells this leg "wrong-token 403": an invalid,
    expired or out-of-scope bearer is answered 401 by
    brix_cvmfs_repo_authz_eval — 403 is the x509 shape (a chain that verifies
    behind a DN that is not allowed), which the gated-Stratum-0 leg above
    pins. The property under test is terminality, and it is unchanged."""
    forge, _ = issuers
    img_rel, img_bytes = trees.image_manifest_object()
    path = f"/cvmfs/{VIRT}/{img_rel}"

    refusals = {
        "anonymous": None,
        "expired": forge.generate_expired(),
        "forged signature": forge.generate_bad_signature(),
        "out of scope": forge.generate(scope="storage.read:/elsewhere"),
    }
    for label, token in refusals.items():
        status, body = _fetch(SITE_PORT, path, token=token)
        assert status == 401, f"{label}: {status}"
        assert body != img_bytes, f"{label} was served the gated object"

    # the composition is intact after the refusals: the ungated member still
    # serves, and a valid bearer still reaches the gated one
    main_rel, main_bytes = trees.software_object()
    assert _fetch(SITE_PORT, f"/cvmfs/{VIRT}/{main_rel}") == (200, main_bytes)
    assert _fetch(SITE_PORT, path, token=forge.generate()) == (200, img_bytes)


def test_mirror_stays_read_only_inside_the_composition(public):
    """Standing beside a registry that DOES accept writes changes nothing
    about the mirror: a write-class method at /v2/ is still a 405 and still
    earns the guard line fail2ban bans on. The two locations share a server,
    a worker and a module — they do not share a write policy."""
    status, _, _ = get(f"http://{HOST}:{PUBLIC_PORT}/v2/lab/app/blobs/uploads/",
                       method="POST")
    assert status == 405, status
    assert "signal=ocipush" in error_log(public)


# ---- the shipped recipes are the ones under test ---------------------------

def _instantiate(text, tmp_path, pki, issuers_cfg):
    """Fill a shipped example's @PLACEHOLDER@s with real paths on this box."""
    for sub in ("store", "web/cvmfs", "registry", "sw"):
        (tmp_path / sub).mkdir(parents=True, exist_ok=True)
    crt, key = pki["server"]
    values = {
        "@PORT@": str(PUBLIC_PORT + 10),
        "@TLSPORT@": str(PUBLIC_PORT + 11),
        "@DAVPORT@": str(PUBLIC_PORT + 12),
        "@CACHEDIR@": str(tmp_path),
        "@UPSTREAM@": "https://registry.example.org",
        "@REGISTRYROOT@": str(tmp_path / "registry"),
        "@WEBROOT@": str(tmp_path / "web"),
        "@SWROOT@": str(tmp_path / "sw"),
        "@CERT@": str(crt),
        "@KEY@": str(key),
        "@CLIENTCA@": str(pki["ca"]),
        "@ISSUERS@": str(issuers_cfg),
    }
    for key_, value in values.items():
        text = text.replace(key_, value)
    _check_instantiate_1(text)
    return text


@pytest.mark.parametrize("example", ["nginx.conf.example",
                                     "full-stack.conf.example"])
def test_shipped_example_configs_parse(example, tmp_path, pki, issuers):
    """The recipes in deploy/oci-mirror/ are documentation an operator PASTES,
    so they are held to the same standard as a template this suite renders:
    every directive spelled correctly, every one legal in the context it is
    written in, and the whole file accepted by the binary it is written for.

    A parse is not a deployment — but a recipe that does not parse has never
    been run by anyone, and that is the failure mode this catches."""
    _, cfg = issuers
    conf = tmp_path / example
    conf.write_text(_instantiate((DEPLOY / example).read_text(), tmp_path,
                                 pki, cfg))
    proc = subprocess.run([NGINX_BIN, "-t", "-p", str(tmp_path),
                           "-c", str(conf), "-e", str(tmp_path / "start.log")],
                          capture_output=True, text=True, timeout=60)
    assert proc.returncode == 0, proc.stderr
