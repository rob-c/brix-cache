"""lab_suite — the two in-cluster pytest scenarios (was xrd-lab's scenario_suite
+ scenario_remote_suite): deploy the authority plane + a mono/mega server, run
the real suite via the test-runner Job in REMOTE mode, then tear down.
"""
import os
import subprocess

from . import LAB

_CHARTS = LAB / "charts"

# (scenario) -> (namespace, server release config, client image, extra runner sets)
_MONO_PORTS = [("anon", 11094), ("gsi", 11095), ("tls", 11096), ("token", 11097), ("metrics", 9100)]
_MEGA_PORTS = [("anon", 11094), ("gsi", 11095), ("tls", 11096), ("token", 11097),
               ("webdav", 8443), ("webdavgtls", 8444), ("httpdav", 8080),
               ("crl", 11104), ("s3", 9001), ("metrics", 9100), ("readonly", 11102)]


def _dry():
    return os.environ.get("XRD_LAB_DRY_RUN", "0") == "1"


def _helm(*args):
    if _dry():
        return
    subprocess.run(["helm", *map(str, args)], check=True)


def _port_sets(ports):
    out = []
    for i, (name, port) in enumerate(ports):
        out += [f"role.ports[{i}].name={name}", f"role.ports[{i}].port={port}"]
    return out


def run(scenario, argv):
    if scenario == "s3fwd":
        return _s3fwd(argv[0] if argv else "tests/test_minio_s3_forward.py")
    if scenario == "s3gsi":
        return _s3gsi(argv[0] if argv else "tests/test_s3gsi_multiuser.py")
    sel = argv[0] if argv else ("tests/test_file_api.py" if scenario == "suite" else "tests/test_query.py")
    if scenario == "suite":
        return _suite(sel, argv[1] if len(argv) > 1 else "")
    return _remote_suite(sel)


def _suite(sel, extra):
    ns = "brix-suite"
    if _dry():
        return ["helm upgrade --install auth charts/auth-authority -n brix-suite (ca+token)",
                "helm upgrade --install srv charts/topology-role -n brix-suite role.configKey=fleet-mono (all auth ports)",
                f"kubectl -n brix-suite run suite --image=brix-test-runner:dev --env=TEST_SERVER_HOST=srv-mono -- pytest {sel}"]
    _deploy_auth(ns)
    srv = ["upgrade", "--install", "srv", str(_CHARTS / "topology-role"), "-n", ns,
           "--set", "role.name=mono,role.configKey=fleet-mono",
           "--set", "role.auth.caBundle=auth-ca-bundle",
           "--set", "role.auth.hostCertSecret=auth-pki",
           "--set", "role.auth.jwksUrl=http://auth-token-issuer:8080/certs/jwks.json",
           "--wait", "--timeout", "3m"]
    for kv in _port_sets(_MONO_PORTS):
        srv += ["--set", kv]
    _helm(*srv)
    _helm("upgrade", "--install", "run", str(_CHARTS / "test-runner"), "-n", ns,
          "--set", "image.repository=brix-test-runner,image.tag=dev",
          "--set", "testRunner.tier=custom", "--set", f"testRunner.selection={sel}",
          "--set", f"testRunner.extraArgs=-p no:xdist -q {extra}",
          "--set", "testRunner.env.TEST_SERVER_HOST=srv-mono",
          "--set", "testRunner.env.TEST_ROOT=/tmp/tr",
          "--set", "clientPki.enabled=true", "--set", "clientPki.pkiSecret=auth-pki",
          "--set", "clientPki.jwksConfigMap=auth-jwks")
    return _collect(ns, ["auth", "srv", "run"])


def _remote_suite(sel):
    ns = "brix-remote"
    if _dry():
        return ["helm upgrade --install auth charts/auth-authority -n brix-remote (ca+token)",
                "helm upgrade --install srv charts/topology-role -n brix-remote role.configKey=fleet-mega (all ports)",
                "helm upgrade --install brix-remote charts/client-rbac -n brix-remote",
                f"helm upgrade --install run charts/test-runner -n brix-remote image=brix-client TEST_SERVER_HOST=srv-mega BRIX_SUITE_NS=brix-remote -- pytest {sel}"]
    _deploy_auth(ns)
    _helm("upgrade", "--install", "brix-remote", str(_CHARTS / "client-rbac"), "-n", ns)
    srv = ["upgrade", "--install", "srv", str(_CHARTS / "topology-role"), "-n", ns,
           "--set", "role.name=mega,role.configKey=fleet-mega",
           "--set", "role.auth.caBundle=auth-ca-bundle",
           "--set", "role.auth.hostCertSecret=auth-pki",
           "--set", "role.auth.jwksUrl=http://auth-token-issuer:8080/certs/jwks.json",
           "--set", "role.auth.crlUrl=http://auth-grid-ca:8080/crl/test-user.crl.pem",
           "--wait", "--timeout", "3m"]
    for kv in _port_sets(_MEGA_PORTS):
        srv += ["--set", kv]
    _helm(*srv)
    _helm("upgrade", "--install", "run", str(_CHARTS / "test-runner"), "-n", ns,
          "--set", "image.repository=brix-client,image.tag=dev",
          "--set", "serviceAccount=brix-remote-client",
          "--set", "testRunner.tier=custom", "--set", f"testRunner.selection={sel}",
          "--set", "testRunner.extraArgs=-p no:xdist -q",
          "--set", "testRunner.env.TEST_SERVER_HOST=srv-mega",
          "--set", f"testRunner.env.BRIX_SUITE_NS={ns}",
          "--set", "testRunner.env.TEST_ROOT=/tmp/tr",
          "--set", "clientPki.enabled=true", "--set", "clientPki.pkiSecret=auth-pki",
          "--set", "clientPki.jwksConfigMap=auth-jwks")
    return _collect(ns, ["auth", "srv", "brix-remote", "run"])


def _s3fwd(sel):
    """MinIO backend + brix S3-credential-forwarding role, verified by the
    remote-mode test_minio_s3_forward.py (fault-attributing: [backend] vs
    [brix-machinery]).  Release "fwd" → Services fwd-minio / fwd-s3fwd."""
    ns = "brix-s3fwd"
    if _dry():
        return ["helm dependency build charts/s3-forward",
                "helm upgrade --install fwd charts/s3-forward -n brix-s3fwd",
                f"helm upgrade --install run charts/test-runner -n brix-s3fwd "
                f"TEST_MINIO_HOST=fwd-minio TEST_S3FWD_HOST=fwd-s3fwd -- pytest {sel}"]
    subprocess.run(["kubectl", "create", "namespace", ns], capture_output=True)
    _helm("dependency", "build", str(_CHARTS / "s3-forward"))
    _helm("upgrade", "--install", "fwd", str(_CHARTS / "s3-forward"), "-n", ns,
          "--wait", "--timeout", "3m")
    _helm("upgrade", "--install", "run", str(_CHARTS / "test-runner"), "-n", ns,
          # brix-client (sourced from k8s-tests/remote-suite/), not
          # brix-test-runner (sourced from top-level tests/) — this test
          # lives only in remote-suite now.
          "--set", "image.repository=brix-client,image.tag=dev",
          "--set", "testRunner.tier=custom", "--set", f"testRunner.selection={sel}",
          "--set", "testRunner.extraArgs=-p no:xdist -v",
          "--set", "testRunner.env.TEST_MINIO_HOST=fwd-minio",
          "--set", "testRunner.env.TEST_MINIO_PORT=9000",
          "--set", "testRunner.env.TEST_S3FWD_HOST=fwd-s3fwd",
          "--set", "testRunner.env.TEST_S3FWD_PORT=8446",
          "--set", "testRunner.env.TEST_MINIO_BUCKET=brixfwd")
    return _collect(ns, ["fwd", "run"])


def _s3gsi(sel):
    """root://+GSI multi-user gateway over MinIO S3: per-VO backend
    credentials (bob/alice=atlas, tom/jane=cms) + per-user authdb isolation,
    verified user-side by test_s3gsi_multiuser.py (xrdcp/xrdfs as each user;
    [backend]-vs-[brix-machinery] fault attribution).  Release "sg" →
    Services sg-minio / sg-s3gsi (ports 1094 allow-lane, 1095 deny-lane)."""
    ns = "brix-s3gsi"
    if _dry():
        return ["helm dependency build charts/s3-gsi",
                "helm upgrade --install sg charts/s3-gsi -n brix-s3gsi",
                f"helm upgrade --install run charts/test-runner -n brix-s3gsi "
                f"image=brix-client TEST_S3GSI_HOST=sg-s3gsi TEST_MINIO_HOST=sg-minio -- pytest {sel}"]
    subprocess.run(["kubectl", "create", "namespace", ns], capture_output=True)
    _helm("dependency", "build", str(_CHARTS / "s3-gsi"))
    _helm("upgrade", "--install", "sg", str(_CHARTS / "s3-gsi"), "-n", ns,
          "--wait", "--timeout", "5m")
    _helm("upgrade", "--install", "run", str(_CHARTS / "test-runner"), "-n", ns,
          "--set", "image.repository=brix-client,image.tag=dev",
          "--set", "testRunner.tier=custom", "--set", f"testRunner.selection={sel}",
          "--set", "testRunner.extraArgs=-p no:xdist -v",
          "--set", "testRunner.env.TEST_S3GSI_HOST=sg-s3gsi",
          "--set", "testRunner.env.TEST_S3GSI_PORT=1094",
          "--set", "testRunner.env.TEST_S3GSI_DENY_PORT=1095",
          "--set", "testRunner.env.TEST_MINIO_HOST=sg-minio",
          "--set", "testRunner.env.TEST_MINIO_PORT=9000",
          "--set", "testRunner.env.TEST_S3GSI_BUCKET=brixgsi",
          # brix-client image has no local nginx — never let conftest
          # start-all a local fleet; this suite only talks to the cluster.
          "--set", "testRunner.env.TEST_SKIP_SERVER_SETUP=1",
          "--set", "testRunner.env.TEST_ROOT=/tmp/tr",
          "--set", "clientPki.enabled=true", "--set", "clientPki.pkiSecret=s3gsi-pki",
          "--set", "clientPki.jwksConfigMap=s3gsi-jwks")
    return _collect(ns, ["sg", "run"])


def _deploy_auth(ns):
    subprocess.run(["kubectl", "get", "namespace", ns], capture_output=True) \
        .returncode or subprocess.run(["kubectl", "create", "namespace", ns])
    _helm("upgrade", "--install", "auth", str(_CHARTS / "auth-authority"), "-n", ns,
          "--set", "services.ca=true,services.token=true,services.voms=false,services.krb5=false",
          "--wait", "--timeout", "3m")


def _collect(ns, releases):
    subprocess.run(["kubectl", "-n", ns, "wait", "--for=condition=complete",
                    "--timeout=400s", "job/run-test-runner"], capture_output=True)
    logs = subprocess.run(["kubectl", "-n", ns, "logs", "job/run-test-runner"],
                          capture_output=True, text=True).stdout
    ok = subprocess.run(["kubectl", "-n", ns, "get", "job", "run-test-runner",
                         "-o", "jsonpath={.status.succeeded}"],
                        capture_output=True, text=True).stdout
    subprocess.run(["helm", "uninstall", *releases, "-n", ns], capture_output=True)
    lines = logs.strip().splitlines()[-20:]
    if ok != "1":
        from .lab import _fail
        _fail("\n".join(lines) + "\nsuite FAILED")
    return lines
