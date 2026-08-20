"""
xrddiag remote-doctor --config-audit (phase-93): remote config & performance
advisor.

`remote-doctor <url> --config-audit` scrapes an endpoint's *advertised*
configuration (kXR_Qconfig) and capacity (kXR_Qspace) over a live root://
connection, then classifies the scraped *values* — not error codes — into
actionable green/yellow/red findings (missing checksum algorithm, TPC not
advertised, sitename unset, low server-side parallelism, near-full export), and
promotes the existing perf/shedding signals into the same machine-readable
diagnosis records. `--all-servers` turns a manager URL into a fleet fan-out: it
locates every data server, scrapes each, and diffs the fleet for uniformity
(version skew, manager-role count, capacity balance).

Pure composition of the public libbrix API — no new wire. PII-free by
construction: only advertised scalars (version / role / booleans / byte counts),
never a path, token, or credential.

Deterministic against a stock anon export:
  * the server has no "sitename" Qconfig emitter → it echoes the key → the scrape
    reads "" → config-sitename WARN fires every run;
  * kXR_Qspace answers real statvfs totals → --cap-threshold 101 (free% < 101 is
    always true) forces a capacity-low WARN every run;
  * chksum advertises adler32,crc32c → config-chksum stays green (absent).

Self-contained: self-hosts its own anon nginx via the registry lifecycle harness
(the shared fleet churns under concurrent work). Runs serial.

Run:
    PYTHONPATH=tests pytest tests/test_config_audit.py -v -p no:xdist
"""

import json
import os
import shutil
import subprocess

import pytest

from server_registry import NginxInstanceSpec
from settings import HOST

pytestmark = [pytest.mark.timeout(120), pytest.mark.uses_lifecycle_harness,
              pytest.mark.xdist_group("lc-cfgaudit")]

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CLIENT_DIR = os.path.join(REPO, "client")
XRDDIAG = os.path.join(CLIENT_DIR, "bin", "xrddiag")
NGINX_BIN = os.environ.get("NGINX_BIN", "/tmp/nginx-1.28.3/objs/nginx")

# Clean env: no X509 / no token so anon stays anon and nothing is in credential scope.
_CLEAN_ENV = {k: v for k, v in os.environ.items()}
for _k in ("X509_USER_PROXY", "X509_CERT_DIR", "BEARER_TOKEN", "BEARER_TOKEN_FILE"):
    _CLEAN_ENV.pop(_k, None)


@pytest.fixture(scope="module")
def doctor():
    """Build xrddiag once; skip cleanly without a compiler / nginx."""
    if shutil.which("cc") is None and shutil.which("gcc") is None:
        pytest.skip("no C compiler to build the native client")
    proc = subprocess.run(["make", "-C", CLIENT_DIR, "xrddiag"],
                          capture_output=True, text=True, timeout=180)
    if proc.returncode != 0 or not os.path.exists(XRDDIAG):
        pytest.skip(f"xrddiag build failed:\n{proc.stdout}\n{proc.stderr}")
    if not os.access(NGINX_BIN, os.X_OK):
        pytest.skip(f"nginx binary not executable: {NGINX_BIN}")
    return XRDDIAG


@pytest.fixture
def anon(lifecycle, doctor, tmp_path_factory):
    """A read-only anon export with one small file to probe."""
    data = tmp_path_factory.mktemp("cfgaudit") / "data"
    data.mkdir()
    (data / "probe.bin").write_bytes(os.urandom(64 * 1024))
    ep = lifecycle.start(NginxInstanceSpec(
        name="lc-cfgaudit-anon",
        template="nginx_xrddiag_remote_doctor_stream.conf",
        protocol="root",
        readiness="tcp",
        data_root=str(data),
        template_values={"ALLOW_WRITE_LINE": ""},
        reason="Anon root:// export for the phase-93 config-audit battery.",
    ))
    yield {"port": ep.port, "data": data}


def _run(*args, timeout=60):
    return subprocess.run([XRDDIAG, *args], capture_output=True, text=True,
                          env=_CLEAN_ENV, timeout=timeout)


def _diagnosis(blob):
    """Pull the diagnosis array out of a --json run as {probe: finding}."""
    doc = json.loads(blob)["remote_doctor"]
    return {d["probe"]: d for d in doc["endpoints"][0]["diagnosis"]}


def _config(blob):
    return json.loads(blob)["remote_doctor"]["endpoints"][0]["config"]


# --------------------------------------------------------------------------
# (1) success — config block is scraped and rendered (text + JSON)
# --------------------------------------------------------------------------

def test_config_audit_json_block(anon):
    """--config-audit adds a populated config block: version + role scraped,
    checksum flags parsed, capacity byte-totals present."""
    port = anon["port"]
    p = _run("remote-doctor", f"root://{HOST}:{port}//probe.bin",
             "--config-audit", "--json", "--metrics-port", "0",
             "--probe-timeout", "8000")
    assert p.returncode == 0, f"{p.stdout}\n{p.stderr}"
    cfg = _config(p.stdout)
    assert cfg is not None, p.stdout
    assert cfg["version"], cfg                       # server advertises a version
    assert cfg["role"] == "server", cfg              # standalone data server
    assert cfg["have_adler32"] is True and cfg["have_crc32c"] is True, cfg
    assert cfg["space_total"] > 0 and cfg["space_free"] >= 0, cfg


def test_config_audit_text_block(anon):
    """Text mode prints the config: and capacity: lines."""
    port = anon["port"]
    p = _run("remote-doctor", f"root://{HOST}:{port}//probe.bin",
             "--config-audit", "--metrics-port", "0", "--probe-timeout", "8000")
    assert p.returncode == 0, f"{p.stdout}\n{p.stderr}"
    assert "config: version=" in p.stdout, p.stdout
    assert "role=server" in p.stdout, p.stdout
    assert "capacity:" in p.stdout, p.stdout


def test_config_audit_off_by_default(anon):
    """Without --config-audit there is no config block and no config-* finding."""
    port = anon["port"]
    p = _run("remote-doctor", f"root://{HOST}:{port}//probe.bin",
             "--json", "--metrics-port", "0", "--probe-timeout", "8000")
    assert p.returncode == 0, p.stderr
    doc = json.loads(p.stdout)["remote_doctor"]["endpoints"][0]
    assert doc.get("config") is None, doc
    assert not any(k.startswith("config-") for k in _diagnosis(p.stdout)), doc


# --------------------------------------------------------------------------
# (2) classification — a value-fault deterministically fires a finding
# --------------------------------------------------------------------------

def test_config_audit_sitename_warns(anon):
    """The stock server has no sitename emitter (echoes the key) → the scrape
    reads it as unset → config-sitename WARN fires, and a healthy checksum config
    keeps config-chksum green (absent)."""
    port = anon["port"]
    p = _run("remote-doctor", f"root://{HOST}:{port}//probe.bin",
             "--config-audit", "--json", "--metrics-port", "0",
             "--probe-timeout", "8000")
    dx = _diagnosis(p.stdout)
    assert dx.get("config-sitename", {}).get("verdict") == "warn", dx
    assert "sitename" in dx["config-sitename"]["cause"].lower(), dx
    assert "config-chksum" not in dx, dx     # adler32,crc32c advertised → green


def test_config_audit_capacity_threshold_warns(anon):
    """--cap-threshold 101 (any free% is < 101) forces the capacity-low WARN,
    proving the capacity classifier and its threshold knob end-to-end."""
    port = anon["port"]
    p = _run("remote-doctor", f"root://{HOST}:{port}//probe.bin",
             "--config-audit", "--cap-threshold", "101", "--json",
             "--metrics-port", "0", "--probe-timeout", "8000")
    dx = _diagnosis(p.stdout)
    assert dx.get("capacity-low", {}).get("verdict") == "warn", dx
    assert "full" in dx["capacity-low"]["cause"].lower(), dx
    # a sane default threshold does NOT flag a near-empty test filesystem
    p2 = _run("remote-doctor", f"root://{HOST}:{port}//probe.bin",
              "--config-audit", "--cap-threshold", "1", "--json",
              "--metrics-port", "0",
              "--probe-timeout", "8000")
    assert "capacity-low" not in _diagnosis(p2.stdout), p2.stdout


# --------------------------------------------------------------------------
# (3) fleet fan-out — --all-servers locates DSs and diffs the cluster
# --------------------------------------------------------------------------

def test_all_servers_fanout(anon):
    """--all-servers turns the URL into a manager + located-DS fan-out and runs
    the cross-cluster diff. A lone data server advertises zero managers, so the
    exactly-one-manager rule fires config-role FAIL deterministically."""
    port = anon["port"]
    p = _run("remote-doctor", f"root://{HOST}:{port}//probe.bin",
             "--all-servers", "--metrics-port", "0", "--probe-timeout", "8000")
    assert "Cluster analysis" in p.stdout, p.stdout
    assert "manager + " in p.stdout, p.stdout
    assert "manager" in p.stdout.lower() and "role" in p.stdout.lower(), p.stdout


def test_all_servers_json_cross_cluster(anon):
    """--all-servers --json records the cross-cluster findings onto the manager
    endpoint (config-role for a no-manager fleet)."""
    port = anon["port"]
    p = _run("remote-doctor", f"root://{HOST}:{port}//probe.bin",
             "--all-servers", "--json", "--metrics-port", "0",
             "--probe-timeout", "8000")
    doc = json.loads(p.stdout)["remote_doctor"]
    assert len(doc["endpoints"]) >= 2, doc     # manager + >=1 located DS
    mgr = {d["probe"]: d for d in doc["endpoints"][0]["diagnosis"]}
    assert mgr.get("config-role", {}).get("verdict") == "fail", mgr


# --------------------------------------------------------------------------
# (5) mesh diagram — --map draws the fan-out topology (ascii / dot / mermaid)
# --------------------------------------------------------------------------

def test_map_ascii_tree(anon):
    """--map draws the CMS-located mesh as an ASCII tree: a titled header, the
    redirector we connected to at the root, and one branch per node it located.
    Roles are read from the CMS locate answer — the root, having located other
    hosts, is typed 'redirector'; each holder is typed 'data server' with its
    read/write access, so the topology distinguishes node kinds, not a flat star."""
    port = anon["port"]
    p = _run("remote-doctor", f"root://{HOST}:{port}//probe.bin",
             "--map", "--metrics-port", "0", "--probe-timeout", "8000")
    assert p.returncode in (0, 1), f"{p.stdout}\n{p.stderr}"
    assert "Mesh topology" in p.stdout, p.stdout
    assert "CMS locate" in p.stdout, p.stdout
    assert f":{port}" in p.stdout, p.stdout            # an authority is drawn
    assert "redirector" in p.stdout, p.stdout          # root typed from CMS locate
    assert "data server" in p.stdout, p.stdout         # located holder typed
    assert ("data server rw" in p.stdout
            or "data server ro" in p.stdout), p.stdout  # access surfaced
    assert "GREEN" in p.stdout or "YELLOW" in p.stdout, p.stdout


def test_map_cms_roles_json(anon):
    """The CMS locate-plane classification is exposed structurally: every endpoint
    carries a `cms` object, the root is reported as a manager/redirector, and a
    located data server carries its ro/rw access — the same data the map renders,
    available to monitoring tools and present even for un-connectable holders."""
    import json
    port = anon["port"]
    p = _run("remote-doctor", f"root://{HOST}:{port}//probe.bin",
             "--all-servers", "--json", "--metrics-port", "0",
             "--probe-timeout", "8000")
    assert p.returncode in (0, 1), f"{p.stdout}\n{p.stderr}"
    doc = json.loads(p.stdout)
    eps = doc["remote_doctor"]["endpoints"]
    assert len(eps) >= 2, eps                          # root + >=1 located node
    root = eps[0]["cms"]
    assert root["reported"] is True and root["role"] == "manager", eps[0]
    holder = eps[1]["cms"]
    assert holder["reported"] is True and holder["role"] == "server", eps[1]
    assert holder["access"] in ("ro", "rw"), eps[1]


def test_map_dot_graph_only(anon):
    """--map-format dot emits a standalone Graphviz digraph (pipeable to
    `dot -Tpng`) with no per-node health-report noise around it."""
    port = anon["port"]
    p = _run("remote-doctor", f"root://{HOST}:{port}//probe.bin",
             "--map", "--map-format", "dot", "--metrics-port", "0",
             "--probe-timeout", "8000")
    assert p.returncode in (0, 1), f"{p.stdout}\n{p.stderr}"
    out = p.stdout.strip()
    assert out.startswith("digraph mesh {"), out
    assert out.endswith("}"), out
    assert "n0 [label=" in out and "shape=box3d" in out, out   # manager root
    assert "n0 -> n1;" in out, out                             # >=1 edge
    assert "Mesh topology" not in out, out                     # graph-only
    assert "Cluster analysis" not in out, out


def test_map_mermaid_graph_only(anon):
    """--map-format mermaid emits a standalone Mermaid graph with health classes."""
    port = anon["port"]
    p = _run("remote-doctor", f"root://{HOST}:{port}//probe.bin",
             "--map", "--map-format", "mermaid", "--metrics-port", "0",
             "--probe-timeout", "8000")
    assert p.returncode in (0, 1), f"{p.stdout}\n{p.stderr}"
    out = p.stdout.strip()
    assert out.startswith("graph TD"), out
    assert "n0 --> n1" in out, out
    assert "classDef green" in out and "class n0 " in out, out
    assert "Mesh topology" not in out, out


def test_map_pii_free(anon):
    """The diagram carries only cluster-member authorities + advertised scalars —
    never the probed path, a credential, or a filesystem internal."""
    port = anon["port"]
    for fmt in ("ascii", "dot", "mermaid"):
        p = _run("remote-doctor", f"root://{HOST}:{port}//probe.bin",
                 "--map", "--map-format", fmt, "--metrics-port", "0",
                 "--probe-timeout", "8000")
        blob = p.stdout
        for leak in ("probe.bin", "BEARER", "x509", "/tmp/", "PRIVATE",
                     "subject=", str(anon["data"])):
            assert leak not in blob, f"PII/secret leaked: {leak!r} in:\n{blob}"


def test_map_non_eos_untouched(anon):
    """The EOS dialect (--map speaks EOS's /proc channel to enumerate the FST farm
    behind an MGM) must be a no-op against a stock XRootD server: the /proc/user/
    version probe is not an EOS MGM, so no `EOS`/`FST` tokens appear, no `eos`
    object is emitted, and the ordinary CMS-locate map still renders cleanly. This
    guards the enrichment from ever mislabelling a non-EOS mesh."""
    import json
    port = anon["port"]
    # ascii map: renders, but carries none of the EOS-only vocabulary
    p = _run("remote-doctor", f"root://{HOST}:{port}//probe.bin",
             "--map", "--metrics-port", "0", "--probe-timeout", "8000")
    assert p.returncode in (0, 1), f"{p.stdout}\n{p.stderr}"
    assert "Mesh topology" in p.stdout, p.stdout
    # the EOS-only node/report lines (distinct from the generic legend blurb):
    assert "eos: EOS MGM" not in p.stdout, p.stdout      # per-node MGM banner
    assert "] EOS FST " not in p.stdout, p.stdout         # FST report row
    assert "admin-gated" not in p.stdout, p.stdout
    assert "fileinfo replica sampling" not in p.stdout, p.stdout  # no fallback fired
    # json: no per-endpoint `eos` object for a non-EOS server
    j = _run("remote-doctor", f"root://{HOST}:{port}//probe.bin",
             "--all-servers", "--json", "--metrics-port", "0",
             "--probe-timeout", "8000")
    assert j.returncode in (0, 1), f"{j.stdout}\n{j.stderr}"
    doc = json.loads(j.stdout)
    for ep in doc["remote_doctor"]["endpoints"]:
        assert "eos" not in ep, ep


# --------------------------------------------------------------------------
# (6) mesh latency — --latency times a bi-directional round-trip per node
# --------------------------------------------------------------------------

def test_latency_table(anon):
    """--latency probes every mesh node over both control planes and prints a
    min/avg/max table. The XRootD data plane (kXR_stat) is always measurable
    against a reachable server; the CMS plane (kXR_locate) is best-effort."""
    import re
    port = anon["port"]
    p = _run("remote-doctor", f"root://{HOST}:{port}//probe.bin",
             "--latency", "--latency-count", "3", "--metrics-port", "0",
             "--probe-timeout", "8000")
    assert p.returncode in (0, 1), f"{p.stdout}\n{p.stderr}"
    assert "Mesh latency" in p.stdout and "bi-directional" in p.stdout, p.stdout
    assert "xrootd (data plane)" in p.stdout, p.stdout
    assert "cms (redirect plane)" in p.stdout, p.stdout
    assert "kXR_stat" in p.stdout and "kXR_locate" in p.stdout, p.stdout   # legend
    # at least one node reports a real min/avg/max triple (float/float/float)
    assert re.search(r"\d+\.\d+/\d+\.\d+/\d+\.\d+", p.stdout), p.stdout


def test_latency_json(anon):
    """--latency --json records a per-endpoint latency object with a sample count
    and per-plane ok/min/avg/max, plus the skipped boolean on every endpoint."""
    port = anon["port"]
    p = _run("remote-doctor", f"root://{HOST}:{port}//probe.bin",
             "--latency", "--latency-count", "3", "--json",
             "--metrics-port", "0", "--probe-timeout", "8000")
    assert p.returncode in (0, 1), p.stderr
    ep0 = json.loads(p.stdout)["remote_doctor"]["endpoints"][0]
    assert ep0.get("skipped") is False, ep0
    lat = ep0.get("latency")
    assert lat is not None, ep0
    assert lat["samples"] == 3, lat
    assert lat["xrootd"]["ok"] >= 1, lat            # data plane measured
    assert lat["xrootd"]["avg_ms"] >= 0.0, lat
    assert "cms" in lat and "ok" in lat["cms"], lat  # cms plane present (best-effort)


def test_latency_off_by_default(anon):
    """Without --latency there is no latency block and no probe overhead."""
    port = anon["port"]
    p = _run("remote-doctor", f"root://{HOST}:{port}//probe.bin",
             "--json", "--metrics-port", "0", "--probe-timeout", "8000")
    assert p.returncode == 0, p.stderr
    ep0 = json.loads(p.stdout)["remote_doctor"]["endpoints"][0]
    assert "latency" not in ep0, ep0
    assert "Mesh latency" not in p.stdout, p.stdout


def test_latency_pii_free(anon):
    """The latency table/JSON carries only authorities + timing scalars."""
    port = anon["port"]
    for extra in (["--json"], []):
        p = _run("remote-doctor", f"root://{HOST}:{port}//probe.bin",
                 "--latency", "--metrics-port", "0", "--probe-timeout", "8000",
                 *extra)
        for leak in ("probe.bin", "BEARER", "x509", "/tmp/", "PRIVATE",
                     "subject=", str(anon["data"])):
            assert leak not in p.stdout, f"PII/secret leaked: {leak!r}"


# --------------------------------------------------------------------------
# (4) security-neg / PII — the config block leaks no path, token, or secret
# --------------------------------------------------------------------------

def test_config_audit_pii_free(anon):
    """The scraped config/capacity rendering carries only advertised scalars —
    never the probed path, a credential, or filesystem internals."""
    port = anon["port"]
    for extra in (["--json"], []):
        p = _run("remote-doctor", f"root://{HOST}:{port}//probe.bin",
                 "--config-audit", "--cap-threshold", "101",
                 "--metrics-port", "0", "--probe-timeout", "8000", *extra)
        blob = p.stdout
        for leak in ("probe.bin", "BEARER", "x509", "/tmp/", "PRIVATE",
                     "subject=", str(anon["data"])):
            assert leak not in blob, f"PII/secret leaked: {leak!r} in:\n{blob}"


def test_config_audit_read_only(anon):
    """--config-audit performs no mutation — the export is byte-for-byte unchanged
    and no diagnostic artifact is left behind."""
    data = anon["data"]
    # ignore server-managed dotfiles (e.g. .nginx-xrootd-ckp-recovery.lock) — the
    # claim under test is that the *client* writes nothing to the namespace.
    def snap():
        return {n: (data / n).stat().st_size
                for n in os.listdir(data) if not n.startswith(".")}
    before = snap()
    port = anon["port"]
    _run("remote-doctor", f"root://{HOST}:{port}//probe.bin",
         "--config-audit", "--all-servers", "--cap-threshold", "101",
         "--metrics-port", "0", "--probe-timeout", "8000")
    after = snap()
    assert before == after, f"config-audit mutated the export: {before} -> {after}"
    assert not any("xrddiag" in n for n in after), f"artifact left behind: {after}"
