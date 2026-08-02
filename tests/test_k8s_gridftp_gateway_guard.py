"""Offline guards for the phase-82 k8s GridFTP-gateway wiring.

Live interop on minikube was blocked for a long time behind a set of stale
k8s-lab defects that are invisible until the gateway pod actually boots. These
guards pin the fixes so the path can't silently regress again — all static file
checks plus one optional ``helm template`` render assertion (skipped when helm
is absent). No cluster or container is required.

The defects these lock down (all fixed 2026-07-31):

  * ``Dockerfiles/server/entrypoint.sh`` had regressed to a bare ``exec "$@"``
    that ran ``nginx`` against the stock compiled conf-path and ignored the
    chart-mounted ``$NGINX_CONF`` at /etc/brix — the role config never loaded.
    It also mkdir'd the read-only /etc/grid-security secret mounts, faulting on
    the RO fs, and dropped the /var/log/brix dir the configs' error_log/pid need.
  * ``charts/topology-role/templates/configmap.yaml`` rendered a self-contained
    config (loaded via ``nginx -c``) that never loaded the dynamic modules, so
    every ``brix_*`` / ``stream`` directive was an "unknown directive" at parse.
  * ``labtools/lab.py`` did not route the ``gridftp`` scenario to
    ``lab_suite.run`` even though the driver existed.
"""
from __future__ import annotations

import re
import shutil
import subprocess
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
K8S = REPO / "k8s-tests"
ENTRYPOINT = K8S / "Dockerfiles/server/entrypoint.sh"
CONFIGMAP = K8S / "charts/topology-role/templates/configmap.yaml"
LAB_PY = K8S / "labtools/lab.py"
LAB_SUITE_PY = K8S / "labtools/lab_suite.py"
GRIDFTP_CHART = K8S / "charts/gridftp-interop"
CLIENT_DOCKERFILE = K8S / "Dockerfiles/gridftp-client/Dockerfile"
RUNNER_JOB = K8S / "charts/test-runner/templates/job.yaml"
PKI_BOOTSTRAP = GRIDFTP_CHART / "templates/pki-bootstrap-job.yaml"
INTEROP_TEST = K8S / "remote-suite/tests/test_gridftp_interop.py"


# --- entrypoint: must load the mounted config, not the stock conf-path -------

def test_entrypoint_launches_nginx_against_mounted_conf():
    body = ENTRYPOINT.read_text()
    # The default CMD is `nginx ...`; the entrypoint must run it with an explicit
    # -c "$NGINX_CONF" so the /etc/brix mount is honoured (a bare `exec "$@"`
    # would fall through to the compiled /etc/nginx/nginx.conf and ignore it).
    assert re.search(r'exec\s+nginx\s+-c\s+"\$NGINX_CONF"', body), (
        "entrypoint must exec `nginx -c \"$NGINX_CONF\"`; a bare exec \"$@\" "
        "ignores the chart-mounted role config at /etc/brix/nginx.conf")
    # Validate the config first so a bad render crashes with a clear message.
    assert 'nginx -t -c "$NGINX_CONF"' in body


def test_entrypoint_default_conf_is_the_brix_mount():
    body = ENTRYPOINT.read_text()
    assert 'NGINX_CONF="${NGINX_CONF:-/etc/brix/nginx.conf}"' in body


def test_entrypoint_creates_logdir_but_not_readonly_pki():
    body = ENTRYPOINT.read_text()
    # The configs put error_log / pid under /var/log/brix — that dir must exist.
    assert "/var/log/brix" in body and "mkdir -p" in body
    # /etc/grid-security/* are read-only secret/configMap mounts; mkdir'ing them
    # faults the RO fs and crash-loops the pod. Never create them.
    assert not re.search(r'mkdir[^\n]*\/etc\/grid-security', body), (
        "entrypoint must not mkdir the read-only /etc/grid-security PKI mounts")


# --- configmap: the rendered role config must load the dynamic modules -------

def test_configmap_template_loads_dynamic_modules():
    body = CONFIGMAP.read_text()
    assert "include /usr/share/nginx/modules/*.conf;" in body, (
        "role config is loaded via `nginx -c` and bypasses the stock "
        "nginx.conf, so it must load the stream + brix dynamic modules itself")


# --- lab CLI: the gridftp scenario must reach its driver ---------------------

def test_lab_cli_dispatches_gridftp_scenario():
    body = LAB_PY.read_text()
    # The lab_suite dispatch tuple in cmd_test must list "gridftp"; otherwise the
    # CLI rejects it with "unknown scenario" despite lab_suite.run handling it.
    m = re.search(r'scenario in \(([^)]*)\):\s*\n\s*from \. import lab_suite', body)
    assert m and '"gridftp"' in m.group(1), (
        "lab.py cmd_test must route the gridftp scenario to lab_suite.run")


# --- optional end-to-end render: modules load before the stream block --------

# `helm dependency build` vendors subcharts over the network — it can exceed the
# fast-lane 30s pytest-timeout, whose signal crashes the whole file (INTERNALERROR)
# and takes the offline guards down with it. Give this one render test its own
# budget so a slow vendor fetch degrades to a slow pass, not a suite crash.
@pytest.mark.timeout(180)
@pytest.mark.skipif(shutil.which("helm") is None, reason="helm not installed")
def test_helm_render_puts_module_include_before_stream_block():
    # Vendor deps then render; the include must appear before `stream {` so the
    # brix stream directives are known by the time nginx parses the block.
    subprocess.run(["helm", "dependency", "build", str(GRIDFTP_CHART)],
                   capture_output=True, check=False)
    out = subprocess.run(
        ["helm", "template", "gf", str(GRIDFTP_CHART)],
        capture_output=True, text=True)
    if out.returncode != 0:
        pytest.skip(f"helm template unavailable: {out.stderr.strip()[:200]}")
    rendered = out.stdout
    inc = rendered.find("include /usr/share/nginx/modules/*.conf;")
    stream = rendered.find("stream {")
    assert inc != -1, "rendered configmap is missing the module include"
    assert stream != -1 and inc < stream, (
        "module include must precede the stream block in the rendered config")


# --- reference-client test-runner wiring (P82.11 ship-the-interop-test) -------
#
# The gridftp lab drives the gateway with the REFERENCE Globus client stack, not
# brix-client, and runs remote-suite/tests/test_gridftp_interop.py inside it.
# These guards pin the four load-bearing pieces of that wiring so a refactor of
# the image layout, the runner Job, or the PKI bootstrap can't silently strand
# the interop lane (which needs a live cluster to catch otherwise).

def test_client_image_ships_the_interop_runner_layout():
    body = CLIENT_DOCKERFILE.read_text()
    # pytest runs from /opt/brix with the test tree + utils + the pki-init helper
    # copied in; the interop suite imports settings from tests/, so PYTHONPATH is
    # wired via the runner env (see lab_suite), but the tree must be present.
    assert "remote-suite/tests/" in body and "/opt/brix/tests/" in body, (
        "client image must copy the remote-suite test tree into /opt/brix/tests")
    assert "remote-suite/utils/" in body and "/opt/brix/utils/" in body, (
        "client image must ship utils/ (make_proxy.py) for client-pki-init.sh")
    assert "client-pki-init.sh" in body, (
        "client image must ship client-pki-init.sh so the runner can lay out PKI")
    assert re.search(r'WORKDIR\s+/opt/brix', body)


def test_runner_secret_mount_is_0600_for_globus():
    # globus/gfal reject a proxy or key whose file perms exceed 600 ("too
    # permissive"); a secret volume defaults to 0644, so the auth-pki mount must
    # pin defaultMode: 0600 or the whole GSI matrix fails before the handshake.
    body = RUNNER_JOB.read_text()
    m = re.search(r'name:\s*auth-pki\s*\n\s*secret:.*?(?=\n\s*-\s*name:|\Z)',
                  body, re.S)
    assert m, "job.yaml must define the auth-pki secret volume"
    assert re.search(r'defaultMode:\s*0?600', m.group(0)), (
        "the auth-pki secret volume must set defaultMode 0600 — globus refuses "
        "a proxy/key file with looser-than-600 permissions")


def test_runner_mounts_the_ca_bundle_when_configured():
    body = RUNNER_JOB.read_text()
    # The gsiftp handshake needs the issuer signing_policy, which the ca.pem+hash
    # rebuild in client-pki-init does NOT synthesize; the lab mounts the ready
    # ca-bundle configMap and client-pki-init dereferences it into real files.
    assert "caBundleConfigMap" in body and "/auth/cabundle" in body, (
        "job.yaml must optionally mount clientPki.caBundleConfigMap at "
        "/auth/cabundle for the GSI trust dir")


def test_pki_bootstrap_is_idempotent_and_rematches_the_host_cn():
    body = PKI_BOOTSTRAP.read_text()
    # pre-install,pre-upgrade hook re-fires on every helm upgrade; regenerating
    # the CA there desyncs the still-running gateway host cert from a runner that
    # mounts the fresh trust bundle. Guard: reuse existing material.
    assert "already provisioned" in body and "kubectl get secret gridftp-pki" in body, (
        "pki-bootstrap must be idempotent — reuse existing PKI on re-upgrade "
        "instead of regenerating the CA and desyncing the running gateway")
    # blitz_test_pki mints CN=localhost, but globus authorizes the gsiftp server
    # by the host it dialled ($HOSTCN); the host cert must be re-minted to match.
    assert "HOSTCN" in body and 'CN=$HOSTCN' in body, (
        "pki-bootstrap must re-mint the host cert with CN=$HOSTCN (+SAN) so "
        "globus does not deny authorization on a CN mismatch")


def test_interop_gates_unpinnable_data_channel_cells():
    # The gateway pins every data channel to the control peer, so passive PASV
    # and same-endpoint gsiftp→gsiftp TPC cannot pass behind a single Service.
    # They are gated on TEST_GRIDFTP_DATACHAN_PINNED (set by the lab), NOT
    # deleted — they still run on host-network / dual-endpoint deployments.
    body = INTEROP_TEST.read_text()
    assert "TEST_GRIDFTP_DATACHAN_PINNED" in body and "_skip_if_datachan_pinned" in body, (
        "interop suite must gate the passive + TPC cells on "
        "TEST_GRIDFTP_DATACHAN_PINNED, not hard-fail them on the k8s topology")
    # And the lab must actually set that flag for the container tier.
    lab = LAB_SUITE_PY.read_text()
    assert "TEST_GRIDFTP_DATACHAN_PINNED=1" in lab, (
        "lab_suite _gridftp must set TEST_GRIDFTP_DATACHAN_PINNED=1")
    assert "image.repository=gridftp-client" in lab, (
        "lab_suite _gridftp must drive with the reference gridftp-client image")
