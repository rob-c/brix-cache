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


def _selection(argv, default):
    if argv:
        return argv[0]
    return default


def _special_scenario(scenario):
    return {
        "s3fwd": (_s3fwd, "tests/test_minio_s3_forward.py"),
        "s3gsi": (_s3gsi, "tests/test_s3gsi_multiuser.py"),
        "s3voms": (_s3voms, "tests/test_s3voms_multiuser.py"),
        "pbgsi": (_pbgsi, "tests/test_pbgsi_multiuser.py"),
        "gridftp": (_gridftp, "tests/test_gridftp_interop.py"),
    }.get(scenario)


def run(scenario, argv):
    special = _special_scenario(scenario)
    if special is not None:
        handler, default = special
        return handler(_selection(argv, default))
    default = "tests/test_file_api.py" if scenario == "suite" \
        else "tests/test_query.py"
    sel = _selection(argv, default)
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


def _s3voms(sel):
    """root://+GSI ZERO-provisioning gateway over MinIO S3: authorization AND
    backend-credential selection are both driven by the client's VOMS AC
    (P80.14).  bob/alice carry a vo=atlas AC, tom/jane a vo=cms AC, mallory no
    AC at all; the server ships only two VO-tier credentials + a two-line org
    authdb — no gridmap, no per-user file.  Verified user-side by
    test_s3voms_multiuser.py.  Release "sv" → Services sv-minio / sv-s3voms
    (port 1097, fallback=deny only)."""
    ns = "brix-s3voms"
    if _dry():
        return ["helm dependency build charts/s3-voms",
                "helm upgrade --install sv charts/s3-voms -n brix-s3voms",
                f"helm upgrade --install run charts/test-runner -n brix-s3voms "
                f"image=brix-client TEST_S3VOMS_HOST=sv-s3voms TEST_MINIO_HOST=sv-minio -- pytest {sel}"]
    subprocess.run(["kubectl", "create", "namespace", ns], capture_output=True)
    _helm("dependency", "build", str(_CHARTS / "s3-voms"))
    _helm("upgrade", "--install", "sv", str(_CHARTS / "s3-voms"), "-n", ns,
          "--wait", "--timeout", "5m")
    _helm("upgrade", "--install", "run", str(_CHARTS / "test-runner"), "-n", ns,
          "--set", "image.repository=brix-client,image.tag=dev",
          "--set", "testRunner.tier=custom", "--set", f"testRunner.selection={sel}",
          "--set", "testRunner.extraArgs=-p no:xdist -v",
          "--set", "testRunner.env.TEST_S3VOMS_HOST=sv-s3voms",
          "--set", "testRunner.env.TEST_S3VOMS_PORT=1097",
          "--set", "testRunner.env.TEST_MINIO_HOST=sv-minio",
          "--set", "testRunner.env.TEST_MINIO_PORT=9000",
          "--set", "testRunner.env.TEST_S3VOMS_BUCKET=brixvoms",
          # brix-client image has no local nginx — never let conftest
          # start-all a local fleet; this suite only talks to the cluster.
          "--set", "testRunner.env.TEST_SKIP_SERVER_SETUP=1",
          "--set", "testRunner.env.TEST_ROOT=/tmp/tr",
          "--set", "clientPki.enabled=true", "--set", "clientPki.pkiSecret=s3voms-pki",
          "--set", "clientPki.jwksConfigMap=s3voms-jwks")
    return _collect(ns, ["sv", "run"])


def _pbgsi(sel):
    """root://+GSI multi-user gateway over a LOCAL pblock:// store with
    per-UNIX-GROUP r/w isolation (P80.25): pa/pb→phys (rw /phys), ea→eng (ro
    /phys, rw /eng), stray→unmapped-DN deny.  No backend credential — the axis
    is authorization + ownership (gate decides, catalog attests).  Verified
    user-side by test_pbgsi_multiuser.py.  Release "pb" → Service pb-pbgsi
    (port 1096)."""
    ns = "brix-pbgsi"
    if _dry():
        return ["helm dependency build charts/pb-gsi",
                "helm upgrade --install pb charts/pb-gsi -n brix-pbgsi",
                f"helm upgrade --install run charts/test-runner -n brix-pbgsi "
                f"image=brix-client TEST_PBGSI_HOST=pb-pbgsi -- pytest {sel}"]
    subprocess.run(["kubectl", "create", "namespace", ns], capture_output=True)
    _helm("dependency", "build", str(_CHARTS / "pb-gsi"))
    _helm("upgrade", "--install", "pb", str(_CHARTS / "pb-gsi"), "-n", ns,
          "--wait", "--timeout", "5m")
    _helm("upgrade", "--install", "run", str(_CHARTS / "test-runner"), "-n", ns,
          "--set", "image.repository=brix-client,image.tag=dev",
          "--set", "testRunner.tier=custom", "--set", f"testRunner.selection={sel}",
          "--set", "testRunner.extraArgs=-p no:xdist -v",
          "--set", "testRunner.env.TEST_PBGSI_HOST=pb-pbgsi",
          "--set", "testRunner.env.TEST_PBGSI_PORT=1096",
          # brix-client image has no local nginx — never let conftest
          # start-all a local fleet; this suite only talks to the cluster.
          "--set", "testRunner.env.TEST_SKIP_SERVER_SETUP=1",
          "--set", "testRunner.env.TEST_ROOT=/tmp/tr",
          "--set", "clientPki.enabled=true", "--set", "clientPki.pkiSecret=pbgsi-pki",
          "--set", "clientPki.jwksConfigMap=pbgsi-jwks")
    return _collect(ns, ["pb", "run"])


def _gridftp(sel):
    """brix GridFTP gateway (gsiftp:// + cleartext) fronting a posix export,
    driven by the REFERENCE grid client stack — globus-url-copy, gfal2, a VOMS-AC
    proxy, and an FTS-style transfer-list / third-party-copy bulk lane (phase-82
    P82.5/P82.10).  Self-contained (like pb-gsi): the chart's own pki-bootstrap
    publishes the CA/host material + two client proxies (user_proxy.pem plain,
    vuser_proxy.pem VOMS-AC vo=atlas) as the gridftp-pki Secret.  Release "gf" →
    Service gf-gridftp (gsiftp 2811, cleartext ftp 2810)."""
    ns = "brix-gridftp"
    if _dry():
        return ["helm dependency build charts/gridftp-interop",
                "helm upgrade --install gf charts/gridftp-interop -n brix-gridftp",
                f"helm upgrade --install run charts/test-runner -n brix-gridftp "
                f"image=gridftp-client TEST_GRIDFTP_HOST=gf-gridftp "
                f"TEST_GRIDFTP_VOMS_PROXY=/auth/pki/vuser_proxy.pem -- pytest {sel}"]
    subprocess.run(["kubectl", "create", "namespace", ns], capture_output=True)
    _helm("dependency", "build", str(_CHARTS / "gridftp-interop"))
    _helm("upgrade", "--install", "gf", str(_CHARTS / "gridftp-interop"), "-n", ns,
          "--wait", "--timeout", "5m")
    _helm("upgrade", "--install", "run", str(_CHARTS / "test-runner"), "-n", ns,
          # the REFERENCE grid client stack (globus-url-copy + gfal2 + voms),
          # NOT brix-client (plain xrootd tools) — cross-implementation interop
          # is the whole point; the image also ships the /opt/brix runner layout.
          "--set", "image.repository=gridftp-client,image.tag=dev",
          "--set", "testRunner.tier=custom", "--set", f"testRunner.selection={sel}",
          "--set", "testRunner.extraArgs=-p no:xdist -v",
          "--set", "testRunner.env.TEST_GRIDFTP_HOST=gf-gridftp",
          "--set", "testRunner.env.TEST_GRIDFTP_GSIFTP_PORT=2811",
          "--set", "testRunner.env.TEST_GRIDFTP_FTP_PORT=2810",
          # the two proxies the pki-bootstrap published into gridftp-pki, mounted
          # at /auth/pki by the runner's clientPki init.
          "--set", "testRunner.env.X509_USER_PROXY=/auth/pki/user_proxy.pem",
          "--set", "testRunner.env.TEST_GRIDFTP_VOMS_PROXY=/auth/pki/vuser_proxy.pem",
          # GSI trust: client-pki-init.sh dereferences the mounted CA bundle
          # (/auth/cabundle configMap → hash-linked ca .0 + .signing_policy) into
          # REAL files under $TEST_ROOT/pki/ca; point globus/gfal there. Same CA
          # that signed the gateway host cert (pki-bootstrap is now idempotent, so
          # gateway and runner stay on one CA generation), so gsiftp validates.
          "--set", "testRunner.env.X509_CERT_DIR=/tmp/tr/pki/ca",
          # pytest runs from workingDir /opt/brix; settings.py lives in tests/,
          # so put it on the import path for conftest's `from settings import`.
          "--set", "testRunner.env.PYTHONPATH=/opt/brix/tests",
          # the gateway pins every data channel to the control peer, so behind a
          # single k8s Service it exposes no passive data-port range and refuses
          # a same-endpoint gsiftp→gsiftp TPC (data addr ≠ control peer). Gate
          # the passive + TPC cells here; they stay live on host-network / dual-
          # endpoint deployments where the reference client can satisfy them.
          "--set", "testRunner.env.TEST_GRIDFTP_DATACHAN_PINNED=1",
          # the runner image has no local nginx — never let conftest start-all a
          # local fleet; this suite only talks to the cluster gateway.
          "--set", "testRunner.env.TEST_SKIP_SERVER_SETUP=1",
          "--set", "testRunner.env.TEST_ROOT=/tmp/tr",
          "--set", "clientPki.enabled=true", "--set", "clientPki.pkiSecret=gridftp-pki",
          "--set", "clientPki.jwksConfigMap=gridftp-jwks",
          "--set", "clientPki.caBundleConfigMap=gridftp-ca-bundle")
    return _collect(ns, ["gf", "run"])


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
