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
