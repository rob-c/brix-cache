# tests/rpm/mirror_lane.py — the driver for the D15.9 native RPM mirror lane.
#
# Same shape as tests/oci/mirror_lane.py, and for the same reason: the nginx
# half must go through the lifecycle harness (a bare subprocess.Popen of the
# binary is what test_server_registry_lint.py's frozen LAUNCH_BACKLOG exists
# to stop), so this module wraps lifecycle.start(NginxInstanceSpec(...)) and
# the lanes carry pytest.mark.uses_lifecycle_harness.
#
# The origin half is tests/rpm/mock_repo.py serving a repository built once by
# `brixrpm createrepo` over the D12 fixture packages — real repodata, so the
# `<checksum>-<name>` grammar the mirror verifies against is the one createrepo
# actually writes rather than one this lane invented.
#
# Ports: the `rpm` neighbourhood claimed in docs/10-reference/test-fleet-ports.md.
import json
import re
import shutil
import subprocess
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import NamedTuple

from brix_suite.registry import NginxInstanceSpec
from settings import HOST

HERE = Path(__file__).resolve().parent
MOCK = str(HERE / "mock_repo.py")
REPO_ROOT = HERE.parents[1]
BRIXRPM = REPO_ROOT / "client" / "bin" / "brixrpm"

#: The repository lives under a prefix, because a mirror serving from "/" would
#: hide any bug in which the cache key and the upstream path disagree only in
#: their leading component.
PREFIX = "/el9/"


def missing_tools():
    """Why this lane cannot run here ('' when it can)."""
    if not BRIXRPM.exists():
        return "client/bin/brixrpm not built (make -C client brixrpm)"
    if shutil.which("rpmbuild") is None:
        return "rpmbuild not installed (fixture packages are BUILT)"
    return ""


def build_repo(docroot: Path) -> Path:
    """Populate `docroot` with a real repository under PREFIX.

    Returns the repository directory. Import is local so a lane that skips for
    a missing rpmbuild never pays make_fixtures' import cost.
    """
    sys.path.insert(0, str(HERE))
    import make_fixtures                                   # noqa: PLC0415

    repo = docroot / PREFIX.strip("/")
    (repo / "Packages").mkdir(parents=True, exist_ok=True)
    for src in make_fixtures.build():
        shutil.copy2(src, repo / "Packages" / src.name)
    done = subprocess.run([str(BRIXRPM), "createrepo", str(repo)],
                          capture_output=True, text=True)
    assert done.returncode == 0, done.stderr
    return repo


#: createrepo writes every file beside repomd.xml as "<checksum>-<name>".
#: Anything else in repodata/ (brixrpm's own incremental cache, a stray .asc)
#: is NOT self-addressing and must not be mistaken for the route under test.
_DIGEST_NAMED = re.compile(r"^[0-9a-f]{40,128}-")


def repodata_names(repo: Path):
    """(digest-named metadata files, repomd.xml) as PREFIX-relative URIs."""
    named = sorted(p.name for p in (repo / "repodata").iterdir()
                   if _DIGEST_NAMED.match(p.name))
    return ([PREFIX + "repodata/" + f for f in named],
            PREFIX + "repodata/repomd.xml")


def package_uris(repo: Path):
    return sorted(PREFIX + "Packages/" + p.name
                  for p in (repo / "Packages").iterdir())


def spawn_mock(port, root, bind=None):
    """Start the origin and wait for its control plane to answer."""
    argv = [sys.executable, MOCK, "--port", str(port), "--root", str(root)]
    if bind is not None:
        argv += ["--bind", bind]
    proc = subprocess.Popen(argv)
    base = "http://%s:%d" % (bind or HOST, port)
    if not wait_ready(base):
        proc.terminate()
        proc.wait()
        raise RuntimeError("mock repo on %d never came up" % port)
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
        except Exception:                      # noqa: BLE001 — any failure = not up
            time.sleep(0.05)
    return False


def _ctl_post(base, endpoint, payload=None):
    data = json.dumps(payload or {}).encode()
    req = urllib.request.Request(base + "/ctl/" + endpoint, method="POST",
                                 data=data,
                                 headers={"Content-Type": "application/json"})
    urllib.request.urlopen(req, timeout=10).read()


def reset(*bases):
    for base in bases:
        _ctl_post(base, "reset")


def fault(base, kind, path_re=None):
    """Arm (or with kind='none' disarm) a fault on the origin."""
    _ctl_post(base, "fault", {"kind": kind, "path_re": path_re})


def hits(base, method=None, path_suffix=None):
    """The origin's request journal, optionally filtered."""
    with urllib.request.urlopen(base + "/ctl/log", timeout=10) as resp:
        rows = json.load(resp)
    return _path_hits(_method_hits(rows, method), path_suffix)


def _method_hits(rows, method):
    if method is None:
        return rows
    return [row for row in rows if row["method"] == method]


def _path_hits(rows, suffix):
    if suffix is None:
        return rows
    return [row for row in rows if row["path"].endswith(suffix)]


class Mirror(NamedTuple):
    """One running mirror front and the handles every assertion needs."""

    base: str            #: http://host:port — what dnf talks to
    endpoint: object     #: the registry ServerEndpoint (prefix, logs, ports)
    cache: Path          #: this instance's cache store, for on-disk assertions


def mirror_spec(name, port, mock_port, cache_dir, *, metadata_ttl="60s",
                verify="rpm-repodata", extra_lines="",
                mock_host=None) -> NginxInstanceSpec:
    """The spec for one mirror front — rendered by a start, or by nginx -t.

    A lane that asserts a parse-time refusal needs the spec without the start,
    so the builder is separate from start_mirror below.
    """
    return NginxInstanceSpec(
        name=name,
        template="rpm_mirror.conf",
        port=port,
        protocol="http",
        readiness="tcp",
        template_values={
            "BIND_HOST": HOST,
            "MOCK_HOST": mock_host or HOST,
            "MOCK_PORT": mock_port,
            "PREFIX": PREFIX,
            "CACHE_DIR": str(cache_dir),
            "METADATA_TTL": metadata_ttl,
            "VERIFY_MODE": verify,
            "EXTRA_LINES": extra_lines,
        },
        reason="phase-104 D15.9 native RPM pull-through mirror lane",
    )


def start_mirror(lifecycle, name, port, mock_port, cache_dir,
                 **kwargs) -> Mirror:
    """Bring up one brix nginx mirror front.

    `cache_dir` is per-instance (a tmp_path subdir) so a lane's cold leg is
    genuinely cold even when an earlier test warmed the same object.
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

    urllib raises on >=400 and this lane reads those statuses as data, so the
    HTTPError is unwrapped back into the same triple.
    """
    req = urllib.request.Request(url, method=method, headers=headers or {})
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            return resp.status, dict(resp.headers), resp.read()
    except urllib.error.HTTPError as exc:
        return exc.code, dict(exc.headers), exc.read()


def cache_files(cache_dir):
    """Every regular file under the mirror's cache store, path-relative."""
    root = Path(cache_dir)
    if not root.exists():
        return []
    return sorted(str(p.relative_to(root)) for p in root.rglob("*")
                  if p.is_file())
