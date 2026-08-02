"""Offline guards for the local (no-cluster) GridFTP interop runner.

The runner (``cmdscripts/gridftp_interop_local.py``) replaces the k8s-cluster
half of the phase-82 interop matrix with a locally-booted combined gateway plus
the ``gridftp-client`` image under rootless podman. These tests pin the parts
that must stay correct without a container or a cluster:

  * the ``build_interop_run_plan`` command-plan wiring (success + the VOMS
    present/absent branch);
  * that the combined gateway config the runner boots actually validates under
    ``nginx -t`` (success), and self-skips when the build/PKI is absent;
  * that ``tools/ci/check_gridftp_interop_image.py`` is green on the tree and
    reddens on real drift (security/regression-negative).
"""
from __future__ import annotations

import importlib.util
import os
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

import pytest

from settings import BIND_HOST, NGINX_BIN, PKI_DIR

sys.path.insert(0, str(Path(__file__).resolve().parent))
from cmdscripts import gridftp_interop_local as gil  # noqa: E402

REPO = Path(__file__).resolve().parents[1]
GUARD = REPO / "tools/ci/check_gridftp_interop_image.py"


# --- command-plan wiring -----------------------------------------------------

def _plan(**over):
    base = dict(host="gw.local", gsiftp_port=2811, ftp_port=2810,
                repo_root=str(REPO), proxy="/pki/user/proxy_std.pem",
                ca_dir="/pki/ca")
    base.update(over)
    return gil.build_interop_run_plan(**base)


def test_plan_wires_host_ports_network_and_matrix_target():
    plan = _plan(image="img:test")
    argv = plan["argv"]
    assert argv[0] == "podman" and "--network=host" in argv
    assert "img:test" in argv
    # The matrix connection contract lands in the container env.
    assert plan["container_env"]["TEST_GRIDFTP_HOST"] == "gw.local"
    assert plan["container_env"]["TEST_GRIDFTP_GSIFTP_PORT"] == "2811"
    assert plan["container_env"]["TEST_GRIDFTP_FTP_PORT"] == "2810"
    assert plan["container_env"]["X509_USER_PROXY"] == "/creds/user_proxy.pem"
    # Drives exactly the phase-82 interop file (mounted alone into a clean dir),
    # with the repo pytest.ini deliberately not loaded.
    c_test = "/interop/test_gridftp_interop.py"
    assert c_test in plan["pytest_argv"]
    assert "/dev/null" in plan["pytest_argv"]      # -c /dev/null
    # The interop file + proxy + CA dir map to the fixed targets; the whole repo
    # is NOT mounted (avoids the repo config / conftest).
    dsts = {dst for _s, dst, _m in plan["mounts"]}
    assert {c_test, "/creds/user_proxy.pem",
            "/etc/grid-security/certificates"} <= dsts
    assert "/repo" not in dsts
    for _s, _d, mode in plan["mounts"]:
        assert mode == "ro"


def test_plan_omits_voms_proxy_when_absent():
    plan = _plan()
    assert "TEST_GRIDFTP_VOMS_PROXY" not in plan["container_env"]
    assert all(dst != "/creds/vuser_proxy.pem" for _s, dst, _m in plan["mounts"])


def test_plan_includes_voms_proxy_when_present():
    plan = _plan(voms_proxy="/pki/user/vuser_proxy.pem", bulk_n=8)
    assert plan["container_env"]["TEST_GRIDFTP_VOMS_PROXY"] == "/creds/vuser_proxy.pem"
    assert plan["container_env"]["TEST_GRIDFTP_BULK_N"] == "8"
    assert any(dst == "/creds/vuser_proxy.pem" for _s, dst, _m in plan["mounts"])


def test_plan_wires_pblock_backend_port_when_present():
    """The non-posix backend cell reads TEST_GRIDFTP_BACKEND_PBLOCK_PORT; the
    plan must thread the pblock listener port into the container env so the
    reference client drives a backend round-trip (P82.6)."""
    plan = _plan(pblock_port=2812)
    assert plan["container_env"]["TEST_GRIDFTP_BACKEND_PBLOCK_PORT"] == "2812"


def test_plan_omits_pblock_backend_port_when_absent():
    plan = _plan()
    assert "TEST_GRIDFTP_BACKEND_PBLOCK_PORT" not in plan["container_env"]


def test_plan_wires_s3_backend_port_when_present():
    """The object-store backend cell reads TEST_GRIDFTP_BACKEND_S3_PORT; the plan
    must thread the s3-backed gsiftp listener port into the container env so the
    reference client drives an s3:// backend round-trip (P82.6, s3 leg)."""
    plan = _plan(s3_port=2813)
    assert plan["container_env"]["TEST_GRIDFTP_BACKEND_S3_PORT"] == "2813"


def test_plan_omits_s3_backend_port_when_absent():
    plan = _plan()
    assert "TEST_GRIDFTP_BACKEND_S3_PORT" not in plan["container_env"]


def test_env_contract_constant_matches_plan_and_dockerfile_packages():
    # The declared env contract must include the connection keys the plan sets.
    for key in ("TEST_GRIDFTP_HOST", "TEST_GRIDFTP_GSIFTP_PORT",
                "TEST_GRIDFTP_FTP_PORT", "TEST_GRIDFTP_BACKEND_S3_PORT",
                "X509_USER_PROXY", "TEST_GRIDFTP_VOMS_PROXY"):
        assert key in gil.INTEROP_ENV_VARS
    # Three reference client stacks, three matrix-facing tools.
    assert len(gil.INTEROP_CLIENT_PACKAGES) == 3
    assert len(gil.INTEROP_CLIENT_TOOLS) == 3


# --- the combined gateway config validates under nginx -----------------------

def test_combined_gateway_config_validates(tmp_path):
    """The two-listener config the runner boots must parse under `nginx -t`."""
    if not os.access(NGINX_BIN, os.X_OK):
        pytest.skip(f"nginx not executable: {NGINX_BIN}")
    pki = {
        "cert": Path(PKI_DIR) / "server" / "hostcert.pem",
        "key": Path(PKI_DIR) / "server" / "hostkey.pem",
        "ca": Path(PKI_DIR) / "ca",
    }
    for p in pki.values():
        if not p.exists():
            pytest.skip(f"test PKI incomplete: missing {p}")
    log_dir = tmp_path / "logs"
    data_root = tmp_path / "export"
    pblock_root = tmp_path / "export-pblock"
    for d in (log_dir, data_root, pblock_root):
        d.mkdir()
    conf = gil._render_gateway_conf(
        template=REPO / "tests/configs/nginx_gridftp_interop.conf",
        out=tmp_path / "gateway.conf", log_dir=log_dir, data_root=data_root,
        bind_host=BIND_HOST, gsiftp_port=32811, ftp_port=32810, pki=pki,
        pblock_gsiftp_port=32812, pblock_root=pblock_root)
    r = subprocess.run([NGINX_BIN, "-t", "-c", str(conf), "-e",
                        str(log_dir / "error.log")],
                       capture_output=True, text=True)
    assert r.returncode == 0, f"nginx -t rejected combined gateway conf:\n{r.stderr}"
    rendered = (tmp_path / "gateway.conf").read_text()
    assert "brix_gridftp_storage_backend pblock" in rendered
    assert str(pblock_root) in rendered
    # The main gateway must NOT carry the s3 leg — it stays single-worker for
    # pblock coherence; the s3 leg lives in its own 2-worker instance.
    assert "worker_processes 1;" in rendered
    assert "brix_s3" not in rendered
    survivors = re.findall(r"\{[A-Z0-9_]+\}", rendered)
    assert not survivors, f"unrendered placeholders survived: {survivors}"


def test_s3_backend_leg_config_validates(tmp_path):
    """The separate 2-worker s3-backend instance (embedded brix_s3 origin + an
    s3://-backed gsiftp listener) must parse under `nginx -t`, carry the s3
    registration, and leave no placeholder unrendered."""
    if not os.access(NGINX_BIN, os.X_OK):
        pytest.skip(f"nginx not executable: {NGINX_BIN}")
    pki = {
        "cert": Path(PKI_DIR) / "server" / "hostcert.pem",
        "key": Path(PKI_DIR) / "server" / "hostkey.pem",
        "ca": Path(PKI_DIR) / "ca",
    }
    for p in pki.values():
        if not p.exists():
            pytest.skip(f"test PKI incomplete: missing {p}")
    log_dir = tmp_path / "logs-s3"
    s3_export = tmp_path / "export-s3"
    s3_dir = tmp_path / "s3-origin"
    http_tmp = tmp_path / "http-tmp"
    for d in (log_dir, s3_export, s3_dir, http_tmp):
        d.mkdir()
    conf = gil._render_s3_conf(
        template=REPO / "tests/configs/nginx_gridftp_interop_s3.conf",
        out=tmp_path / "gateway-s3.conf", log_dir=log_dir, bind_host=BIND_HOST,
        pki=pki, s3_gsiftp_port=32813, s3_origin_port=32814, s3_dir=s3_dir,
        s3_export=s3_export, tmp_dir=http_tmp)
    r = subprocess.run([NGINX_BIN, "-t", "-c", str(conf), "-e",
                        str(log_dir / "error.log")],
                       capture_output=True, text=True)
    assert r.returncode == 0, f"nginx -t rejected s3-backend conf:\n{r.stderr}"
    rendered = (tmp_path / "gateway-s3.conf").read_text()
    assert "brix_gridftp_storage_backend    s3://" in rendered
    assert "brix_s3 on;" in rendered
    assert str(s3_dir) in rendered
    # Two workers required for the co-hosted origin (self-deadlock otherwise).
    assert "worker_processes 2;" in rendered
    # No {PLACEHOLDER} token (all-caps + underscores) may survive substitution.
    survivors = re.findall(r"\{[A-Z0-9_]+\}", rendered)
    assert not survivors, f"unrendered placeholders survived: {survivors}"


# --- the CI guard: green on the tree, red on drift ---------------------------

def _run_guard() -> tuple[int, str]:
    p = subprocess.run([sys.executable, str(GUARD)], capture_output=True, text=True)
    return p.returncode, p.stdout + p.stderr


def test_interop_image_guard_green():
    rc, out = _run_guard()
    assert rc == 0, out


def test_guard_reddens_when_dockerfile_drops_a_client_stack():
    df = REPO / "k8s-tests/Dockerfiles/gridftp-client/Dockerfile"
    orig = df.read_text()
    dropped = gil.INTEROP_CLIENT_PACKAGES[1]  # gfal2 stack
    try:
        df.write_text(orig.replace(dropped, "some-other-pkg"))
        rc, out = _run_guard()
    finally:
        df.write_text(orig)
    assert rc != 0 and dropped in out, out


def test_guard_reddens_when_gateway_config_loses_a_listener():
    conf = REPO / "tests/configs/nginx_gridftp_interop.conf"
    orig = conf.read_text()
    try:
        conf.write_text(orig.replace("{FTP_PORT}", "2810"))
        rc, out = _run_guard()
    finally:
        conf.write_text(orig)
    assert rc != 0 and "FTP_PORT" in out, out


def test_guard_reddens_when_gateway_config_drops_pblock_backend():
    """Dropping the pblock backend registration would silently degrade the
    non-posix backend interop cell to a posix round-trip — the guard must fire."""
    conf = REPO / "tests/configs/nginx_gridftp_interop.conf"
    orig = conf.read_text()
    try:
        conf.write_text(orig.replace("brix_gridftp_storage_backend pblock;", ""))
        rc, out = _run_guard()
    finally:
        conf.write_text(orig)
    assert rc != 0 and "pblock" in out, out


def test_guard_reddens_when_s3_config_drops_s3_backend():
    """Dropping the s3:// backend registration from the separate s3-leg config
    would silently degrade the object-store backend interop cell to a posix
    round-trip — the guard fires."""
    conf = REPO / "tests/configs/nginx_gridftp_interop_s3.conf"
    orig = conf.read_text()
    try:
        conf.write_text(orig.replace(
            "brix_gridftp_storage_backend    s3://{BIND_HOST}:{S3_ORIGIN_PORT}/testbucket;",
            ""))
        rc, out = _run_guard()
    finally:
        conf.write_text(orig)
    assert rc != 0 and "s3" in out, out
