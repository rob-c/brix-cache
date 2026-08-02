# brix-remote-ok
"""root://+GSI multi-user gateway over a LOCAL pblock:// store with per-UNIX-
GROUP read/write isolation (phase-80 P80.25), tested from the USER's side.

Topology under test (charts/pb-gsi, ``./xrd-lab test pbgsi``)::

    xrdcp/xrdfs as pa|pb (group phys), ea (group eng), stray (unmapped DN)
        │ root://+GSI (proxy certs; identity = the EEC DN, P80.11)
        ▼
    brix  (brix_auth gsi,
           brix_gridmap → EEC DN → local account (P80.21, no imp broker),
           brix_authdb g-rules over the account's UNIX groups:
             g phys /phys a     (phys: read/write on /phys)
             g eng  /phys rl    (eng:  read+lookup only on /phys)
             g eng  /eng  a     (eng:  read/write on /eng),
           brix_storage_backend pblock:///data/xrootd)

Unlike s3gsi/s3voms there is NO backend credential to select — the axis is
authorization + ownership.  The posture is **gate decides, catalog attests**:
the ``g``-rule gate makes every allow/deny decision from the mapped account's
unix-group membership, and the pblock catalog stamps each object's true
``{uid,gid}`` as attribution ground truth (P80.22).

Scope of THIS (k8s remote) suite vs. the local lab.  The catalog attestation
oracle — direct ``sqlite3`` queries joining ``objects.uid`` back to the EEC DN
— lives inside the server pod and is exercised by the local privileged suite
``tests/test_pblock_group_multiuser.py`` (P80.24).  Here we assert the
client-OBSERVABLE half: the exact grant/deny matrix a grid user sees over
``root://``, which is what proves the gate wiring end-to-end in-cluster.

Isolation contract, per-UNIX-GROUP (governed prefixes seeded world-writable so
the pblock POSIX layer is permissive and the g-rule gate is the sole
differentiator — charts/pb-gsi data-seed):

  * phys members (pa, pb) read/write ``/phys`` and share it;
  * eng member (ea) reads ``/phys`` (rl grant) but CANNOT write it, and
    read/writes its own ``/eng`` space;
  * cross-group writes are denied both directions;
  * an unmapped DN (stray) maps to no account, resolves no groups, and is
    denied on every governed prefix.

Remote-only: requires TEST_PBGSI_HOST (set by the pbgsi scenario); skipped
otherwise.
"""

import os
import shutil
import stat as statmod
import subprocess

import pytest

PBGSI_HOST = os.environ.get("TEST_PBGSI_HOST")
PBGSI_PORT = int(os.environ.get("TEST_PBGSI_PORT", "1096"))
TEST_ROOT = os.environ.get("TEST_ROOT", "/tmp/tr")
PKI_SRC = os.environ.get("PKI_SRC", "/auth/pki")

# logical user -> unix group (mapped in the gridmap).  stray is deliberately
# absent from the gridmap: a valid proxy that resolves to no local account.
GROUP = {"pa": "phys", "pb": "phys", "ea": "eng"}
USERS = ("pa", "pb", "ea", "stray")

pytestmark = pytest.mark.skipif(
    PBGSI_HOST is None,
    reason="pbgsi scenario env not set (TEST_PBGSI_HOST) — k8s remote-only suite")


# --------------------------------------------------------------------------
# GSI client plumbing — per-user proxies from the pbgsi-pki secret.
# --------------------------------------------------------------------------

@pytest.fixture(scope="module")
def gsi(tmp_path_factory):
    """Copy per-user proxies out of the (0644) secret mount with 0400 perms and
    return an env factory: gsi(user) -> subprocess env dict."""
    ca_dir = os.path.join(TEST_ROOT, "pki", "ca")
    assert os.path.isfile(os.path.join(ca_dir, "ca.pem")), \
        f"client-pki-init did not lay out {ca_dir} (clientPki mounts missing?)"
    pdir = tmp_path_factory.mktemp("proxies")
    proxies = {}
    for u in USERS:
        src = os.path.join(PKI_SRC, f"{u}_proxy.pem")
        assert os.path.isfile(src), f"missing {src} in pbgsi-pki secret"
        dst = str(pdir / f"{u}.pem")
        shutil.copyfile(src, dst)
        os.chmod(dst, statmod.S_IRUSR)
        proxies[u] = dst

    def env_for(user):
        env = dict(os.environ)
        for k in ("X509_USER_CERT", "X509_USER_KEY"):
            env.pop(k, None)
        env.update({
            "X509_USER_PROXY": proxies[user],
            "X509_CERT_DIR": ca_dir,
            "XrdSecPROTOCOL": "gsi",
            "XrdSecGSISRVNAMES": "*",
            "XRD_CONNECTIONRETRY": "1",
            "XRD_REQUESTTIMEOUT": "30",
        })
        return env

    return env_for


def _url(path):
    return f"root://{PBGSI_HOST}:{PBGSI_PORT}/{path}"


def _run(cmd, env, timeout=90):
    return subprocess.run(cmd, env=env, capture_output=True, text=True,
                          timeout=timeout)


def _xrdcp_up(env, local, path):
    return _run(["xrdcp", "-f", local, _url(path)], env)


def _xrdcp_down(env, path, local):
    return _run(["xrdcp", "-f", _url(path), local], env)


def _fail_blob(r):
    return f"rc={r.returncode} stdout={r.stdout!r} stderr={r.stderr!r}"


def _put(gsi, tmp_path, user, path, body):
    """Upload `body` as `user`; return the CompletedProcess (caller asserts)."""
    src = tmp_path / f"{user}-src-{path.replace('/', '_')}"
    src.write_bytes(body)
    return _xrdcp_up(gsi(user), str(src), path)


# ==========================================================================
# 1. phys group — read/write on /phys, and members share the space.
# ==========================================================================

class TestPhysGroup:
    def test_phys_member_write_read_roundtrip(self, gsi, tmp_path):
        body = b"from-pa-v1" * 512
        up = _put(gsi, tmp_path, "pa", "/phys/pa.dat", body)
        assert up.returncode == 0, f"phys member write on /phys must succeed: {_fail_blob(up)}"
        dst = tmp_path / "pa.dst"
        down = _xrdcp_down(gsi("pa"), "/phys/pa.dat", str(dst))
        assert down.returncode == 0 and dst.read_bytes() == body, \
            f"phys member must read its own /phys object back: {_fail_blob(down)}"

    def test_second_phys_member_writes_phys(self, gsi, tmp_path):
        up = _put(gsi, tmp_path, "pb", "/phys/pb.dat", b"from-pb")
        assert up.returncode == 0, f"second phys member write must succeed: {_fail_blob(up)}"

    def test_phys_members_share_the_group_space(self, gsi, tmp_path):
        """The g-rule grants the whole phys group `a` on /phys, and created
        objects are world-readable, so pa reads pb's object — group sharing,
        not per-user isolation (the pblock POSIX layer is intentionally
        neutralised; the gate is the sole differentiator)."""
        assert _put(gsi, tmp_path, "pb", "/phys/pb_shared.dat", b"pb-shared").returncode == 0
        dst = tmp_path / "shared.dst"
        r = _xrdcp_down(gsi("pa"), "/phys/pb_shared.dat", str(dst))
        assert r.returncode == 0 and dst.read_bytes() == b"pb-shared", \
            f"phys members must share /phys: {_fail_blob(r)}"


# ==========================================================================
# 2. eng group — read-only crossing onto /phys, read/write on /eng.
# ==========================================================================

class TestEngGroup:
    def test_eng_member_reads_phys_readonly(self, gsi, tmp_path):
        """The 'g eng /phys rl' grant lets an eng member READ a phys object..."""
        assert _put(gsi, tmp_path, "pa", "/phys/for_eng.dat", b"phys-data").returncode == 0
        dst = tmp_path / "for_eng.dst"
        r = _xrdcp_down(gsi("ea"), "/phys/for_eng.dat", str(dst))
        assert r.returncode == 0 and dst.read_bytes() == b"phys-data", \
            f"eng member must read /phys (rl grant): {_fail_blob(r)}"

    def test_eng_member_cannot_write_phys(self, gsi, tmp_path):
        """...but NOT write it — 'rl' has no write bit, so the gate denies."""
        r = _put(gsi, tmp_path, "ea", "/phys/eng_attempt.dat", b"nope")
        assert r.returncode != 0, \
            "SECURITY: an eng member wrote /phys despite only an 'rl' grant"

    def test_eng_member_write_read_own_space(self, gsi, tmp_path):
        body = b"from-ea"
        up = _put(gsi, tmp_path, "ea", "/eng/ea.dat", body)
        assert up.returncode == 0, f"eng member write on /eng must succeed: {_fail_blob(up)}"
        dst = tmp_path / "ea.dst"
        down = _xrdcp_down(gsi("ea"), "/eng/ea.dat", str(dst))
        assert down.returncode == 0 and dst.read_bytes() == body, \
            f"eng member must read its own /eng object: {_fail_blob(down)}"


# ==========================================================================
# 3. Cross-group isolation (symmetric) + fail-closed unmapped DN.
# ==========================================================================

class TestCrossGroupAndUnmapped:
    def test_phys_member_denied_on_eng(self, gsi, tmp_path):
        """The other crossing: phys has no rule granting /eng, so a phys write
        there is denied — cross-group isolation is symmetric."""
        r = _put(gsi, tmp_path, "pa", "/eng/phys_attempt.dat", b"nope")
        assert r.returncode != 0, \
            "SECURITY: a phys member wrote /eng with no rule granting it"

    def test_phys_member_cannot_read_eng(self, gsi, tmp_path):
        assert _put(gsi, tmp_path, "ea", "/eng/ea_secret.dat", b"eng-secret").returncode == 0
        r = _xrdcp_down(gsi("pa"), "/eng/ea_secret.dat", str(tmp_path / "loot"))
        assert r.returncode != 0, \
            "SECURITY: a phys member read an /eng object with no grant on /eng"

    def test_unmapped_dn_denied_everywhere(self, gsi, tmp_path):
        """stray authenticates with the same CA but has no gridmap line: it maps
        to no local account, resolves no groups, and matches no g-rule under a
        governed prefix — denied on both spaces, never a silent fall-through."""
        for space in ("/phys/x.dat", "/eng/x.dat"):
            r = _put(gsi, tmp_path, "stray", space, b"stray")
            assert r.returncode != 0, \
                f"SECURITY: an unmapped DN was served on {space}"
