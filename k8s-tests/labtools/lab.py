"""lab — the k8s test-lab driver (was the xrd-lab bash script).

Design for Pythonic testing: the up/deploy/down/status/images actions are pure
``plan_*`` functions returning command lists (argv), so tests assert on them
directly and dry-run just prints them. Scenarios deploy + probe; each returns a
list of report lines (its dry description, or the live probe output). ./xrd-lab
is a thin wrapper over ``python3 -m labtools.lab``.
"""
import os
import subprocess
import sys

from . import LAB, REPO
from . import targets

CHART = LAB / "charts" / "brix-test-lab"


def _dry():
    return os.environ.get("XRD_LAB_DRY_RUN", "0") == "1"


def _cfg():
    return (os.environ.get("XRD_LAB_DRIVER", "docker"),
            os.environ.get("XRD_LAB_NODES", "1"),
            os.environ.get("XRD_LAB_K8S_VERSION", "v1.31.4"))


def _dockerfile(image):
    return str(LAB / "images" / image / "Dockerfile")


# ---------------------------------------------------------------------------
# Command plans — pure, testable. Each returns a list of argv lists.
# ---------------------------------------------------------------------------
def plan_up():
    driver, nodes, k8s = _cfg()
    return [
        ["minikube", "start", f"--driver={driver}", f"--nodes={nodes}",
         f"--kubernetes-version={k8s}"],
        ["minikube", "addons", "enable", "metrics-server"],
    ]


# (profiles that need it, image tag, image subdir | None=smoke builds in-cluster)
_IMAGES = [
    (("dev",),                         "brix-smoke",       None),
    (("gsi", "token", "fleet", "full"), "brix-authority",   "authority"),
    (("token", "full"),                "brix-krb5-kdc",    "krb5-kdc"),
    (("chaos", "cms", "fleet", "full"), "brix-server",      "server"),
    (("fleet", "full"),                "brix-test-runner", "test-runner"),
]


def plan_images(profile):
    target = targets.current()
    tag = targets.image_tag()
    cmds = []
    for profiles, repo, subdir in _IMAGES:
        if profile not in profiles:
            continue
        image = f"{repo}:{tag}"
        if subdir is None:
            cmds.append([
                "minikube", "image", "build",
                *targets.smoke_build_args(target),
                "-t", image, str(LAB / "images" / "smoke"),
            ])
        else:
            cmds += [[
                "docker", "build",
                *targets.build_args(target),
                "-t", image, "-f", _dockerfile(subdir), str(REPO),
            ], ["minikube", "image", "load", image]]
    return cmds


def plan_deploy(profile):
    ns = f"brix-{profile}"
    values = CHART / "values" / f"values.{profile}.yaml"
    return plan_images(profile) + [
        ["kubectl", "create", "namespace", ns],
        ["kubectl", "label", "namespace", ns,
         "pod-security.kubernetes.io/enforce=baseline", "--overwrite"],
        ["helm", "dependency", "build", str(CHART)],
        ["helm", "upgrade", "--install", f"brix-{profile}", str(CHART),
         "--namespace", ns, "--create-namespace", "--values", str(values),
         "--wait", "--timeout", "5m"],
    ]


def plan_down(profile):
    ns = f"brix-{profile}"
    return [["helm", "uninstall", f"brix-{profile}", "--namespace", ns],
            ["kubectl", "delete", "namespace", ns, "--ignore-not-found"]]


def plan_status():
    return [["kubectl", "get", "nodes", "-o", "wide"],
            ["kubectl", "get", "pods", "-A", "-l", "app.kubernetes.io/part-of=brix-test-lab"]]


# ---------------------------------------------------------------------------
# Executor.
# ---------------------------------------------------------------------------
def _sh(cmd, check=True, capture=False):
    if _dry():
        print(" ".join(cmd))
        return subprocess.CompletedProcess(cmd, 0, "", "")
    return subprocess.run(cmd, check=check, text=True,
                          stdout=subprocess.PIPE if capture else None,
                          stderr=subprocess.PIPE if capture else None)


def _run_plan(cmds, check=True):
    for c in cmds:
        if c[:3] == ["kubectl", "create", "namespace"] and not _dry():
            if subprocess.run(["kubectl", "get", "namespace", c[3]],
                              capture_output=True).returncode == 0:
                continue          # idempotent
        _sh(c, check=check)


def _probe(ns, name, image, script):
    """Run a throwaway pod, return its stdout (empty on failure)."""
    r = subprocess.run(
        ["kubectl", "-n", ns, "run", f"{name}-{os.getpid()}", "--rm", "-i",
         "--restart=Never", f"--image={image}", "--image-pull-policy=Never",
         "--quiet", "--command", "--", "bash", "-lc", script],
        capture_output=True, text=True)
    return r.stdout.strip()


def _http_probe(ns, name, url):
    return _probe(ns, name, "brix-authority:dev",
                  f"curl -fsS -o /dev/null -w '%{{http_code}}' '{url}' || true")


# ---------------------------------------------------------------------------
# Scenarios — return report lines (dry description, or live probe output).
# ---------------------------------------------------------------------------
def scenario_smoke():
    ns, svc = "brix-dev", "brix-dev-smoke"
    if _dry():
        return [f"kubectl -n {ns} port-forward svc/{svc} 18080:8080",
                "curl -sf http://127.0.0.1:18080/healthz"]
    code = _probe(ns, "smoke-probe", "brix-smoke:dev",
                  f"curl -s -o /dev/null -w '%{{http_code}}' "
                  f"http://{svc}.{ns}.svc.cluster.local:8080/healthz")
    return ["smoke OK (200 /healthz)"] if code == "200" else _fail(f"smoke FAILED ({code!r})")


def scenario_authorities(prof="gsi"):
    ns = rel = f"brix-{prof}"
    if _dry():
        return [f"kubectl -n {ns} run probe --image=brix-authority:dev -- curl http://{rel}-grid-ca:8080/crl/test-user.crl.pem",
                f"kubectl -n {ns} run probe --image=brix-authority:dev -- curl http://{rel}-token-issuer:8080/certs/jwks.json"]
    lines = []
    crl = _http_probe(ns, "crlprobe", f"http://{rel}-grid-ca:8080/crl/test-user.crl.pem")
    if crl != "200":
        return _fail(f"CRL FAILED ({crl})")
    lines.append("CRL OK")
    jwks = _http_probe(ns, "jwksprobe", f"http://{rel}-token-issuer:8080/certs/jwks.json")
    lines.append("JWKS OK" if jwks == "200" else "JWKS SKIP (token issuer not in this profile)")
    return lines


_CACHE_SH = r'''set -e
  f="rt-$(date +%s%N).dat"; head -c 2097152 /dev/urandom > /tmp/src
  xrdcp -f -N /tmp/src root://brix-chaos-chaos-tier3:1094//$f
  xrdcp -f -N root://brix-chaos-chaos-tier1:1094//$f /tmp/dst
  a=$(sha256sum /tmp/src|cut -d" " -f1); b=$(sha256sum /tmp/dst|cut -d" " -f1)
  [ "$a" = "$b" ] && echo CACHE_PATH_OK || { echo MISMATCH; exit 1; }'''
_CMS_LOCATE_SH = r'''set -e
  f="cms-$(date +%s%N).dat"; echo cms > /tmp/c
  xrdcp -f -N /tmp/c root://{ds}:1094//$f
  for i in $(seq 1 15); do
    if xrdfs root://{redir}:1094 locate /$f 2>/dev/null | grep -q .; then echo CMS_REGISTERED_OK; exit 0; fi
    sleep 3
  done
  echo CMS_LOCATE_FAILED; exit 1'''


def scenario_chaos():
    ns = "brix-chaos"
    if _dry():
        return ["kubectl -n brix-chaos run chaos-probe --image=brix-server:dev -- read-through via brix-chaos-chaos-tier1:1094",
                "kubectl -n brix-chaos run cms-probe --image=brix-server:dev -- xrdfs brix-chaos-chaos-discovery-redir:1094 locate"]
    lines = []
    if "CACHE_PATH_OK" not in _probe(ns, "chaos-probe", "brix-server:dev", _CACHE_SH):
        return _fail("chaos read-through FAILED")
    lines.append("CACHE_PATH_OK")
    cms = _CMS_LOCATE_SH.format(ds="brix-chaos-chaos-discovery-ds", redir="brix-chaos-chaos-discovery-redir")
    if "CMS_REGISTERED_OK" not in _probe(ns, "cms-probe", "brix-server:dev", cms):
        return _fail("chaos CMS registration FAILED")
    return lines + ["CMS_REGISTERED_OK", "chaos OK"]


_FLEET_ANON_SH = r'''set -e
  f="fl-$(date +%s%N).dat"; head -c 1048576 /dev/urandom > /tmp/src
  xrdcp -f -N /tmp/src root://brix-fleet-anon:11094//$f
  xrdcp -f -N root://brix-fleet-anon:11094//$f /tmp/dst
  a=$(sha256sum /tmp/src|cut -d" " -f1); b=$(sha256sum /tmp/dst|cut -d" " -f1)
  [ "$a" = "$b" ] && echo FLEET_ANON_OK || { echo MISMATCH; exit 1; }'''


def scenario_fleet():
    ns = "brix-fleet"
    if _dry():
        return ["kubectl -n brix-fleet run fleet-probe --image=brix-server:dev -- anon round-trip root://brix-fleet-anon:11094",
                "kubectl -n brix-fleet get pod gsi/token (Ready proves CRL/JWKS fetched over HTTP)"]
    if "FLEET_ANON_OK" not in _probe(ns, "fleet-probe", "brix-server:dev", _FLEET_ANON_SH):
        return _fail("fleet anon round-trip FAILED")
    lines = ["FLEET_ANON_OK"]
    for role in ("gsi", "token"):
        ready = subprocess.run(
            ["kubectl", "-n", ns, "get", "pod", "-l", f"app.kubernetes.io/component={role}",
             "-o", "jsonpath={.items[0].status.conditions[?(@.type=='Ready')].status}"],
            capture_output=True, text=True).stdout
        if "True" not in ready:
            return _fail(f"{role} role NOT Ready")
        lines.append(f"{role} role Ready (authority material consumed)")
    return lines + ["fleet OK"]


def scenario_cms():
    ns = "brix-cms"
    if _dry():
        return ["kubectl -n brix-cms run cms-probe --image=brix-server:dev -- xrdfs root://brix-cms-manager:1094 locate"]
    cms = _CMS_LOCATE_SH.format(ds="brix-cms-ds", redir="brix-cms-manager")
    if "CMS_REGISTERED_OK" not in _probe(ns, "cms-probe", "brix-server:dev", cms):
        return _fail("cms registration FAILED")
    return ["CMS_REGISTERED_OK", "cms OK"]


def scenario_dedicated(name):
    from . import catalog
    cat = LAB / "scenarios" / "catalog.yaml"
    scn = catalog.scenarios(cat)[name]
    ns = rel = "brix-dedicated"
    check = scn.get("check", "none")
    port = scn["ports"][0]["port"]
    svc = f"{rel}-{name}"
    sets = catalog.render(cat, name, rel)
    if _dry():
        return [f"helm upgrade --install {rel} charts/topology-role --namespace {ns} "
                + " ".join(f"--set {kv}" for kv in sets),
                f"check '{check}' against root://{svc}:{port}"]
    _ensure_server_image()
    _run_plan([["kubectl", "create", "namespace", ns]])
    helm = ["helm", "upgrade", "--install", rel, str(LAB / "charts" / "topology-role"),
            "--namespace", ns, "--wait", "--timeout", "3m"]
    for kv in sets:
        helm += ["--set", kv]
    _sh(helm)
    lines = []
    if check == "write-rejected":
        script = (f'echo x > /tmp/f; if xrdcp -f -N /tmp/f root://{svc}:{port}//ro-$(date +%s).dat '
                  '2>/dev/null; then echo WRITE_ALLOWED_UNEXPECTED; exit 1; else echo WRITE_REJECTED_OK; fi')
        out = _probe(ns, "ro-probe", "brix-server:dev", script)
        subprocess.run(["helm", "uninstall", rel, "-n", ns], capture_output=True)
        if "WRITE_REJECTED_OK" not in out:
            return _fail(f"{name}: write not rejected")
        return ["WRITE_REJECTED_OK", f"{name} OK"]
    subprocess.run(["helm", "uninstall", rel, "-n", ns], capture_output=True)
    return [f"scenario {name!r} deployed (no client-observable check)"]


def _ensure_server_image():
    have = subprocess.run(["minikube", "image", "ls"], capture_output=True, text=True).stdout
    if "brix-server:dev" not in have:
        _sh(["docker", "build", "-t", "brix-server:dev", "-f", _dockerfile("server"), str(REPO)])
        _sh(["minikube", "image", "load", "brix-server:dev"])


def _fail(msg):
    print(msg, file=sys.stderr)
    raise SystemExit(1)


SCENARIOS = {
    "smoke": scenario_smoke,
    "authorities": scenario_authorities,
    "chaos": scenario_chaos,
    "fleet": scenario_fleet,
    "cms": scenario_cms,
    "dedicated": scenario_dedicated,
}


def cmd_test(argv):
    from . import catalog
    scenario = argv[0] if argv else ""
    if not scenario:
        print("error: test requires a <scenario>", file=sys.stderr)
        return 2
    if scenario == "authorities":
        lines = scenario_authorities(argv[1] if len(argv) > 1 else "gsi")
    elif scenario in ("suite", "remote-suite"):
        from . import lab_suite
        lines = lab_suite.run(scenario, argv[1:])
    elif scenario in ("ceph-docker", "ceph-rpmbuild"):
        from . import ceph_docker
        lines = ceph_docker.run(scenario)
    elif scenario in SCENARIOS:
        lines = SCENARIOS[scenario]()
    elif catalog.scenarios(LAB / "scenarios" / "catalog.yaml").get(scenario) is not None:
        lines = scenario_dedicated(scenario)
    else:
        print(f"error: unknown scenario {scenario!r}", file=sys.stderr)
        return 2
    for line in lines:
        print(line)
    return 0


USAGE = """Usage: xrd-lab <command> [args]
  up                 Start minikube (pinned k8s version)
  deploy <profile>   Build images into the cluster and helm-install the profile
  test <scenario>    Run a scenario check against a deployed profile
  status             Show cluster nodes and lab resources
  down <profile>     Uninstall a profile release and delete its namespace
Env: XRD_LAB_K8S_VERSION XRD_LAB_NODES XRD_LAB_DRIVER XRD_LAB_OS_TARGET XRD_LAB_DRY_RUN"""


def main(argv):
    cmd, rest = (argv[0] if argv else "help"), argv[1:]
    if cmd == "up":
        _run_plan(plan_up())
    elif cmd == "deploy":
        if not rest:
            print("error: deploy requires a <profile> argument", file=sys.stderr)
            print(USAGE, file=sys.stderr)
            return 2
        _run_plan(plan_deploy(rest[0]))
    elif cmd == "down":
        if not rest:
            print("error: down requires a <profile> argument", file=sys.stderr)
            print(USAGE, file=sys.stderr)
            return 2
        _run_plan(plan_down(rest[0]), check=False)   # cleanup is idempotent
    elif cmd == "status":
        _run_plan(plan_status())
    elif cmd == "test":
        return cmd_test(rest)
    elif cmd in ("help", "-h", "--help"):
        print(USAGE, file=sys.stderr)
    else:
        print(f"error: unknown command {cmd!r}", file=sys.stderr)
        print(USAGE, file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
