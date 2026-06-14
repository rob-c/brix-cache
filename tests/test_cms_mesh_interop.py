"""
Real XRootD <-> nginx-xrootd CMS mesh interoperability tests.

The mesh topologies (real xrootd+cmsd and nginx-xrootd instances wired together
via the CMS protocol) are brought up by the test harness — manage_test_servers.sh
start-all -> cms_mesh_servers.py — on the fixed ports in cms_mesh_lib.PORTS.
These tests only *connect* to those ports and skip if a topology is not up; they
do not launch any daemons themselves.  All daemon lifecycle and config building
lives in cms_mesh_lib.

Each topology serves files seeded with deterministic content (cms_mesh_lib.content)
so assertions need no access to the data-node filesystem (except the write and
large-file cases, which check the node's fixed export dir via data_dir()).
"""

import os
import subprocess
import time

import pytest

import cms_mesh_lib as M
from cms_mesh_lib import (
    PORTS, HOST, content, data_dir, port_open, read_text, md5_file,
    located_port, stat_size, have_binaries, CURL_BIN,
    xrdfs_locate, xrdcp_get, xrdcp_put, xrdfs_stat, xrdfs_ls,
    https_get, https_put,
)

pytestmark = [
    pytest.mark.skipif(
        not have_binaries(),
        reason="CMS mesh interop needs xrootd, cmsd, xrdfs, xrdcp and nginx",
    ),
    pytest.mark.timeout(120),
]


def _require(*pairs):
    """Skip unless every (label, port) is listening — i.e. the harness brought
    that topology up (manage_test_servers.sh start-all)."""
    for label, port in pairs:
        if not port_open(port):
            pytest.skip(f"{label} (:{port}) not up — run "
                        "manage_test_servers.sh start-all")


def _kill_port(port):
    out = subprocess.run(["ss", "-tlnp"], capture_output=True, text=True).stdout
    for line in out.splitlines():
        if f":{port} " in line and "pid=" in line:
            pid = line.split("pid=")[1].split(",")[0]
            subprocess.run(["kill", "-9", pid], check=False)


# --------------------------------------------------------------------------- #
# A — nginx data node -> real xrootd+cmsd manager
# --------------------------------------------------------------------------- #


class TestNginxDataNodeToRealManager:
    def test_real_manager_redirects_to_nginx(self):
        _require(("real manager", PORTS["a_mgr"]), ("nginx node", PORTS["a_nds"]))
        rc, out, err = xrdfs_locate(PORTS["a_mgr"], "/fileA.txt")
        assert rc == 0, f"locate failed: {err or out}"
        assert PORTS["a_nds"] in located_port(out), out

    def test_xrdcp_through_real_manager_from_nginx(self, tmp_path):
        _require(("real manager", PORTS["a_mgr"]))
        dst = str(tmp_path / "a.txt")
        assert xrdcp_get(PORTS["a_mgr"], "fileA.txt", dst).returncode == 0
        assert read_text(dst) == content("a")


# --------------------------------------------------------------------------- #
# B — real xrootd+cmsd data node -> nginx manager
# --------------------------------------------------------------------------- #


class TestRealDataNodeToNginxManager:
    def test_nginx_registers_real_node_with_paths(self):
        _require(("nginx manager", PORTS["b_mgr"]), ("real node", PORTS["b_rds"]))
        log = os.path.join(M.MESH_DIR, "b", "logs", "b-mgr-error.log")
        body = read_text(log) if os.path.exists(log) else ""
        assert "registered" in body, "nginx never logged a CMS registration"
        assert "paths=[]" not in body.split("registered", 1)[1][:200], \
            "real node registered with empty paths (login parse bug)"

    def test_nginx_redirects_to_real_node(self):
        _require(("nginx manager", PORTS["b_mgr"]), ("real node", PORTS["b_rds"]))
        rc, out, err = xrdfs_locate(PORTS["b_mgr"], "/fileB.txt")
        assert rc == 0 and PORTS["b_rds"] in located_port(out), out

    def test_xrdcp_through_nginx_from_real_node(self, tmp_path):
        _require(("nginx manager", PORTS["b_mgr"]))
        dst = str(tmp_path / "b.txt")
        assert xrdcp_get(PORTS["b_mgr"], "fileB.txt", dst).returncode == 0
        assert read_text(dst) == content("b")


# --------------------------------------------------------------------------- #
# C — mixed pool (nginx mgr + nginx DS + real DS, by path)
# --------------------------------------------------------------------------- #


class TestMixedPool:
    def test_route_to_nginx_node_by_path(self, tmp_path):
        _require(("nginx manager", PORTS["c_mgr"]), ("nginx DS", PORTS["c_nds"]))
        rc, out, _ = xrdfs_locate(PORTS["c_mgr"], "/ngx/n.txt")
        assert rc == 0 and PORTS["c_nds"] in located_port(out), out
        dst = str(tmp_path / "c_ngx.txt")
        assert xrdcp_get(PORTS["c_mgr"], "ngx/n.txt", dst).returncode == 0
        assert read_text(dst) == content("c-ngx")

    def test_route_to_real_node_by_path(self, tmp_path):
        _require(("nginx manager", PORTS["c_mgr"]), ("real DS", PORTS["c_rds"]))
        rc, out, _ = xrdfs_locate(PORTS["c_mgr"], "/real/r.txt")
        assert rc == 0 and PORTS["c_rds"] in located_port(out), out
        dst = str(tmp_path / "c_real.txt")
        assert xrdcp_get(PORTS["c_mgr"], "real/r.txt", dst).returncode == 0
        assert read_text(dst) == content("c-real")


# --------------------------------------------------------------------------- #
# D — multi-tier: real meta -> nginx sub-manager -> nginx leaf
# --------------------------------------------------------------------------- #


class TestMultiTierMesh:
    def test_xrdcp_resolves_through_tiers(self, tmp_path):
        _require(("real meta", PORTS["d_meta"]), ("nginx sub", PORTS["d_sub"]),
                 ("nginx leaf", PORTS["d_leaf"]))
        dst = str(tmp_path / "d.txt")
        r = xrdcp_get(PORTS["d_meta"], "fileD.txt", dst)
        assert r.returncode == 0, f"multi-tier xrdcp failed: {r.stderr}"
        assert read_text(dst) == content("d")


# --------------------------------------------------------------------------- #
# Pools
# --------------------------------------------------------------------------- #


class TestRealManagerPoolOfNginx:
    def test_route_path_a_to_node1(self, tmp_path):
        _require(("real manager", PORTS["prm_mgr"]), ("node1", PORTS["prm_n1"]))
        dst = str(tmp_path / "a.txt")
        assert xrdcp_get(PORTS["prm_mgr"], "a/x.txt", dst).returncode == 0
        assert read_text(dst) == content("prm-a")

    def test_route_path_b_to_node2(self, tmp_path):
        _require(("real manager", PORTS["prm_mgr"]), ("node2", PORTS["prm_n2"]))
        dst = str(tmp_path / "b.txt")
        assert xrdcp_get(PORTS["prm_mgr"], "b/y.txt", dst).returncode == 0
        assert read_text(dst) == content("prm-b")


class TestNginxManagerPoolOfReal:
    def test_locate_ra_routes_to_real1(self):
        _require(("nginx manager", PORTS["pnm_mgr"]), ("real1", PORTS["pnm_r1"]))
        rc, out, _ = xrdfs_locate(PORTS["pnm_mgr"], "/ra/x.txt")
        assert rc == 0 and PORTS["pnm_r1"] in located_port(out), out

    def test_xrdcp_ra_and_rb(self, tmp_path):
        _require(("nginx manager", PORTS["pnm_mgr"]),
                 ("real1", PORTS["pnm_r1"]), ("real2", PORTS["pnm_r2"]))
        for path, tag in (("ra/x.txt", "pnm-ra"), ("rb/y.txt", "pnm-rb")):
            dst = str(tmp_path / path.replace("/", "_"))
            assert xrdcp_get(PORTS["pnm_mgr"], path, dst).returncode == 0
            assert read_text(dst) == content(tag)


# --------------------------------------------------------------------------- #
# Writes (both directions)
# --------------------------------------------------------------------------- #


class TestWriteThroughRealManagerToNginx:
    def test_upload_lands_on_nginx_node(self, tmp_path):
        _require(("real manager", PORTS["wrm_mgr"]), ("nginx node", PORTS["wrm_nds"]))
        local = str(tmp_path / "up.txt")
        body = "uploaded-via-real-manager\n" * 32
        with open(local, "w") as f:
            f.write(body)
        # root-level path: nginx does not auto-create parent dirs (unlike oss)
        r = xrdcp_put(PORTS["wrm_mgr"], local, "/up_real_mgr.txt")
        assert r.returncode == 0, f"upload failed: {r.stderr}"
        landed = os.path.join(data_dir("wrm", "wrm-nds"), "up_real_mgr.txt")
        assert os.path.exists(landed) and read_text(landed) == body


class TestWriteThroughNginxManagerToReal:
    def test_upload_lands_on_real_node(self, tmp_path):
        _require(("nginx manager", PORTS["wnm_mgr"]), ("real node", PORTS["wnm_rds"]))
        local = str(tmp_path / "up.txt")
        body = "uploaded-via-nginx-manager\n" * 32
        with open(local, "w") as f:
            f.write(body)
        r = xrdcp_put(PORTS["wnm_mgr"], local, "/up2.txt")
        assert r.returncode == 0, f"upload failed: {r.stderr}"
        landed = os.path.join(data_dir("wnm", "wnm-rds"), "up2.txt")
        assert os.path.exists(landed) and read_text(landed) == body


# --------------------------------------------------------------------------- #
# stat / ls, negative, failover, large file, baseline
# --------------------------------------------------------------------------- #


class TestStatLsThroughNginxManager:
    def test_stat_reports_size(self):
        _require(("nginx manager", PORTS["sl_mgr"]), ("real node", PORTS["sl_rds"]))
        rc, out, err = xrdfs_stat(PORTS["sl_mgr"], "/d/f.txt")
        assert rc == 0, f"stat failed: {err or out}"
        assert stat_size(out) == 4096, out

    def test_ls_lists_directory(self):
        _require(("nginx manager", PORTS["sl_mgr"]), ("real node", PORTS["sl_rds"]))
        rc, out, err = xrdfs_ls(PORTS["sl_mgr"], "/d")
        assert rc == 0 and "f.txt" in out, err or out


class TestNegativeNoSuchPath:
    def test_unserved_path_errors(self, tmp_path):
        _require(("nginx manager", PORTS["neg_mgr"]), ("real node", PORTS["neg_rds"]))
        dst = str(tmp_path / "none.txt")
        # Expect failure: don't retry, and a short timeout — an unserved path
        # makes the manager wait, so xrdcp_get returns a clean non-zero result.
        r = xrdcp_get(PORTS["neg_mgr"], "other/missing.txt", dst, timeout=12,
                      retries=1)
        assert r.returncode != 0, "expected failure for an unserved path"
        assert not os.path.exists(dst) or os.path.getsize(dst) == 0


class TestDataNodeFailover:
    def test_redirect_then_gone_after_kill(self):
        _require(("nginx manager", PORTS["fo_mgr"]), ("real node", PORTS["fo_rds"]))
        rc, out, _ = xrdfs_locate(PORTS["fo_mgr"], "/f.txt")
        assert rc == 0 and PORTS["fo_rds"] in located_port(out), \
            f"expected redirect to {PORTS['fo_rds']} before kill: {out}"
        # Kill the whole real node (cmsd + xrootd share this cfg). A server-role
        # cmsd may not bind its own port, so killing by port alone can miss it —
        # the cmsd is the connection the nginx manager blacklists on close.
        subprocess.run(["pkill", "-9", "-f", M.node_cfg("fo", "fo-rds")],
                       check=False)
        time.sleep(5)
        rc2, out2, _ = xrdfs_locate(PORTS["fo_mgr"], "/f.txt")
        assert not (rc2 == 0 and PORTS["fo_rds"] in located_port(out2)), \
            f"manager still redirects to a dead node: rc={rc2} {out2}"


class TestLargeFileThroughNginxManager:
    def test_16mib_round_trip(self, tmp_path):
        _require(("nginx manager", PORTS["lg_mgr"]), ("real node", PORTS["lg_rds"]))
        src = os.path.join(data_dir("lg", "lg-rds"), "big.bin")
        if not os.path.exists(src):
            pytest.skip("large file not seeded")
        dst = str(tmp_path / "big.out")
        r = xrdcp_get(PORTS["lg_mgr"], "big.bin", dst, timeout=120)
        assert r.returncode == 0, f"large xrdcp failed: {r.stderr}"
        assert md5_file(dst) == md5_file(src)


class TestBaselineRealCluster:
    def test_real_to_real_redirect_and_copy(self, tmp_path):
        _require(("real manager", PORTS["bl_mgr"]), ("real node", PORTS["bl_rds"]))
        rc, out, _ = xrdfs_locate(PORTS["bl_mgr"], "/base.txt")
        assert rc == 0 and PORTS["bl_rds"] in located_port(out), out
        dst = str(tmp_path / "base.txt")
        assert xrdcp_get(PORTS["bl_mgr"], "base.txt", dst).returncode == 0
        assert read_text(dst) == content("bl")


class TestMultiTierRealLeaf:
    def test_xrdcp_resolves_meta_to_real_leaf(self, tmp_path):
        _require(("real meta", PORTS["mrl_meta"]), ("nginx sub", PORTS["mrl_sub"]),
                 ("real leaf", PORTS["mrl_leaf"]))
        dst = str(tmp_path / "e.txt")
        r = xrdcp_get(PORTS["mrl_meta"], "fileE.txt", dst)
        assert r.returncode == 0, f"multi-tier(real leaf) xrdcp failed: {r.stderr}"
        assert read_text(dst) == content("mrl")


# --------------------------------------------------------------------------- #
# Multi-protocol meshes — cms:// + root:// + https:// in one cluster
# --------------------------------------------------------------------------- #


class TestTriProtocolMesh:
    """One CMS mesh, three protocols: cms:// (cluster), root:// (xrdcp via the
    nginx manager) and https:// (WebDAV direct to the dual-protocol nginx node)."""

    def test_root_via_cms_to_nginx_dual(self, tmp_path):
        _require(("nginx manager", PORTS["tri_mgr"]),
                 ("dual node", PORTS["tri_dual"]))
        rc, out, _ = xrdfs_locate(PORTS["tri_mgr"], "/dav/f.txt")
        assert rc == 0 and PORTS["tri_dual"] in located_port(out), out
        dst = str(tmp_path / "dav_root.txt")
        assert xrdcp_get(PORTS["tri_mgr"], "dav/f.txt", dst).returncode == 0
        assert read_text(dst) == content("tri-dav")

    def test_root_via_cms_to_real_node(self, tmp_path):
        _require(("nginx manager", PORTS["tri_mgr"]),
                 ("real node", PORTS["tri_real"]))
        dst = str(tmp_path / "real_root.txt")
        assert xrdcp_get(PORTS["tri_mgr"], "real/r.txt", dst).returncode == 0
        assert read_text(dst) == content("tri-real")

    def test_https_direct_to_dual_node(self, tmp_path):
        if not CURL_BIN:
            pytest.skip("curl not available")
        _require(("dual https", PORTS["tri_dual_https"]))
        dst = str(tmp_path / "dav_https.txt")
        r = https_get(PORTS["tri_dual_https"], "/dav/f.txt", dst)
        assert r.stdout.strip().endswith("200"), f"https GET: {r.stdout} {r.stderr}"
        assert read_text(dst) == content("tri-dav")

    def test_cross_protocol_https_write_root_read(self, tmp_path):
        if not CURL_BIN:
            pytest.skip("curl not available")
        _require(("dual https", PORTS["tri_dual_https"]),
                 ("nginx manager", PORTS["tri_mgr"]))
        local = str(tmp_path / "x.txt")
        body = "written-via-https-read-via-root\n" * 4
        with open(local, "w") as f:
            f.write(body)
        r = https_put(PORTS["tri_dual_https"], local, "/dav/x.txt")
        assert r.stdout.strip()[-3:] in ("200", "201", "204"), r.stdout
        time.sleep(1)
        dst = str(tmp_path / "x_root.txt")
        assert xrdcp_get(PORTS["tri_mgr"], "dav/x.txt", dst).returncode == 0
        assert read_text(dst) == body


class TestWideHeterogeneousPool:
    """One nginx manager fronting FOUR data nodes — two nginx, two real
    xrootd — each exporting a distinct path."""

    _NODE = {"na": "w_n1", "nb": "w_n2", "ra": "w_r1", "rb": "w_r2"}

    @pytest.mark.parametrize("key", ["na", "nb", "ra", "rb"])
    def test_each_path_routes_and_copies(self, tmp_path, key):
        port = PORTS[self._NODE[key]]
        _require(("nginx manager", PORTS["w_mgr"]), (f"node {key}", port))
        rc, out, _ = xrdfs_locate(PORTS["w_mgr"], f"/{key}/f.txt")
        assert rc == 0 and port in located_port(out), out
        dst = str(tmp_path / f"{key}.txt")
        assert xrdcp_get(PORTS["w_mgr"], f"{key}/f.txt", dst).returncode == 0
        assert read_text(dst) == content(f"w-{key}")


class TestRealXrootdHttpInMesh:
    """A real xrootd node serving BOTH root:// (in the nginx CMS cluster) and
    https:// (XrdHttp) — read the same file via each protocol."""

    def test_root_via_cms(self, tmp_path):
        _require(("nginx manager", PORTS["rh_mgr"]), ("real node", PORTS["rh_real"]))
        dst = str(tmp_path / "h_root.txt")
        assert xrdcp_get(PORTS["rh_mgr"], "h.txt", dst).returncode == 0
        assert read_text(dst) == content("rh")

    def test_https_direct_to_xrootd(self, tmp_path):
        if not CURL_BIN:
            pytest.skip("curl not available")
        if not port_open(PORTS["rh_real_http"]):
            pytest.skip("XrdHttp endpoint not up")
        dst = str(tmp_path / "h_https.txt")
        r = https_get(PORTS["rh_real_http"], "/h.txt", dst)
        assert r.stdout.strip().endswith("200"), f"XrdHttp GET: {r.stdout}"
        assert read_text(dst) == content("rh")


# --------------------------------------------------------------------------- #
# SSS — nginx manager requiring the cmsd sss handshake (Phase 28 W1a)
# --------------------------------------------------------------------------- #


class TestCmsSssAuth:
    """The nginx manager's CMS port requires an sss credential
    (xrootd_cms_server_sss_keytab).  A data node that does not complete the
    kYR_xauth sss handshake must be refused registration — so the manager has
    no server for the node's path and a locate returns no redirect.

    This is the fail-closed security assertion for W1a.  (The complementary
    back-compat case — a manager WITHOUT sss admits the same kind of node — is
    covered by the B topology, TestNginxManager.)
    """

    def test_unauthenticated_node_is_refused(self):
        _require(("sss manager", PORTS["sss_mgr"]),
                 ("data node", PORTS["sss_rds"]))
        # The node process is up (port listening) but, lacking a working sss
        # credential, it must never be admitted to the registry.
        rc, out, err = xrdfs_locate(PORTS["sss_mgr"], "/fileS.txt")
        assert PORTS["sss_rds"] not in located_port(out), (
            "fail-closed violated: an sss-required manager admitted a node that "
            f"did not present a valid sss credential\nlocate rc={rc} out={out!r}")
