# tests/oci/mirror_lane.py — the shared driver for the three D0–D3 mirror
# lanes (classify / authdance / cachepolicy).
#
# Every one of them needs the same two things: a mock registry on a fixed port
# and a REAL brix nginx in front of it rendered from tests/configs/oci_mirror.conf.
# The nginx half must go through the lifecycle harness — a bare
# subprocess.Popen([NGINX_BIN, …]) is what test_server_registry_lint.py's
# frozen LAUNCH_BACKLOG exists to stop — so this module wraps
# lifecycle.start(NginxInstanceSpec(...)) rather than spawning anything itself,
# and the lanes carry pytest.mark.uses_lifecycle_harness.
#
# Ports: the `oci` neighbourhood claimed in docs/10-reference/test-fleet-ports.md.
# Mocks take base+0..9 and nginx fronts base+10..19, the same split
# cvmfs/conformance_common.py's PortBlock uses — but spelled as literals here
# because these blocks are anchored absolutely (like test_oci_brixoci_copy.py's
# 14140 quintet), not tiled off TEST_PORT_START.
import json
import subprocess
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import NamedTuple

from brix_suite.registry import NginxInstanceSpec
from settings import HOST

MOCK = str(Path(__file__).resolve().parent / "mock_registry.py")

#: The CDN twin binds a DIFFERENT host string so a redirect off the registry is
#: a genuine cross-host hop — the only shape in which the strip-Authorization
#: policy (D1.4) is observable. The evil realm needs a third address for the
#: same reason: a realm the mirror must refuse has to be REACHABLE, or the
#: refusal proves nothing but a failed connect.
CDN_HOST = "127.0.0.2"   # net-literal-allow: second loopback address IS the subject
EVIL_HOST = "127.0.0.3"  # net-literal-allow: third loopback address IS the subject


def spawn_mock(port, *extra, bind=None):
    """Start a mock registry and wait for its control plane to answer."""
    argv = [sys.executable, MOCK, "--port", str(port)]
    if bind is not None:
        argv += ["--bind", bind]
    proc = subprocess.Popen(argv + list(extra))
    base = "http://%s:%d" % (bind or HOST, port)
    if not wait_ready(base):
        proc.terminate()
        proc.wait()
        raise RuntimeError("mock registry on %d never came up" % port)
    return proc, base


def stop_mocks(*procs):
    for proc in procs:
        proc.terminate()
    for proc in procs:
        proc.wait()


def wait_ready(base, timeout=10.0):
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            urllib.request.urlopen(base + "/ctl/log", timeout=0.2).read()
            return True
        except Exception:                          # noqa: BLE001 — any failure = not up
            time.sleep(0.05)
    return False


def ctl(base, endpoint):
    with urllib.request.urlopen(base + "/ctl/" + endpoint, timeout=10) as resp:
        return json.load(resp)


def ctl_post(base, endpoint, payload=None):
    data = json.dumps(payload).encode() if payload is not None else b""
    req = urllib.request.Request(base + "/ctl/" + endpoint, method="POST",
                                 data=data)
    urllib.request.urlopen(req, timeout=10).read()


def reset(*bases):
    for base in bases:
        ctl_post(base, "reset")


def hits(base, method=None, path_prefix=None):
    """Upstream request log, optionally filtered by method / path prefix."""
    rows = ctl(base, "log")
    if method is not None:
        rows = [r for r in rows if r["method"] == method]
    if path_prefix is not None:
        rows = [r for r in rows if r["path"].startswith(path_prefix)]
    return rows


class Mirror(NamedTuple):
    """One running mirror front and the three handles every assertion needs."""

    base: str            #: http://host:port — what a client talks to
    endpoint: object     #: the registry ServerEndpoint (prefix, logs, ports)
    cache: Path          #: this instance's cache store, for on-disk assertions


def mirror_spec(name, port, mock_port, cache_dir, *, manifest_ttl="60s",
                verify="oci-digest", auth_lines="", extra_lines="",
                mock_host=None) -> NginxInstanceSpec:
    """The spec for one mirror front — rendered by a start, or by nginx -t.

    A lane that asserts a parse-time refusal needs the spec without the start,
    so the builder is separate from start_mirror below.
    """
    return NginxInstanceSpec(
        name=name,
        template="oci_mirror.conf",
        port=port,
        protocol="http",
        readiness="tcp",
        template_values={
            "BIND_HOST": HOST,
            "MOCK_HOST": mock_host or HOST,
            "MOCK_PORT": mock_port,
            "CACHE_DIR": str(cache_dir),
            "MANIFEST_TTL": manifest_ttl,
            "VERIFY_MODE": verify,
            "AUTH_LINES": auth_lines,
            "EXTRA_LINES": extra_lines,
        },
        reason="phase-104 OCI pull-through mirror lane",
    )


def start_mirror(lifecycle, name, port, mock_port, cache_dir,
                 **kwargs) -> Mirror:
    """Bring up one brix nginx mirror front.

    `cache_dir` is per-instance (a tmp_path subdir) so a lane's cold-pull leg
    is genuinely cold even when an earlier test in the same file already
    warmed the same object.
    """
    Path(cache_dir).mkdir(parents=True, exist_ok=True)
    endpoint = lifecycle.start(mirror_spec(name, port, mock_port, cache_dir,
                                           **kwargs))
    return Mirror("http://%s:%d" % (endpoint.host, endpoint.port), endpoint,
                  Path(cache_dir))


def error_log(endpoint):
    """The instance's error.log text ('' before nginx has written anything)."""
    path = Path(endpoint.prefix, "logs", "error.log")
    if not path.exists():
        return ""
    return path.read_text(encoding="utf-8", errors="replace")


def get(url, headers=None, method="GET"):
    """One request at the mirror; returns (status, headers, body).

    urllib raises on >=400 and a registry lane reads those statuses as data,
    so the HTTPError is unwrapped back into the same triple.
    """
    req = urllib.request.Request(url, method=method,
                                 headers=headers or {})
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            return resp.status, dict(resp.headers), resp.read()
    except urllib.error.HTTPError as exc:
        return exc.code, dict(exc.headers), exc.read()


def err_code(body):
    """The OCI error code out of an error envelope ('' if unparsable)."""
    try:
        return json.loads(body)["errors"][0]["code"]
    except Exception:                              # noqa: BLE001 — shape IS the assertion
        return ""


def manifest_layers(body):
    return json.loads(body)["layers"]


def cache_files(cache_dir):
    """Every regular file under the mirror's cache store, path-relative."""
    root = Path(cache_dir)
    if not root.exists():
        return []
    return sorted(str(p.relative_to(root)) for p in root.rglob("*")
                  if p.is_file())
