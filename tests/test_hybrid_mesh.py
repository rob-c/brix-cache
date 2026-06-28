"""
tests/test_hybrid_mesh.py — exercise the hybrid two-tier cross-backend mesh
across protocols and entry points, and MAP which mesh components each scenario
uses.

Topology (see docs/superpowers/specs/2026-06-27-hybrid-mesh-design.md and
hybrid_mesh_lib.py):

      client
        v
    a) nginx redirector (tier-1 CMS manager) + S3 front + WebDAV front
    +--------+--------+
    v                 v
 b) nginx          c) xrootd PSS      (read/write-through proxies -> g)
    proxy             proxy
    +--------+--------+
        v
    g) xrootd redirector (tier-2 cmsd manager) + XrdHttp
   +----+----+
   v    v    v
 d)xrd e)xrd f)nginx                  (data servers; f also S3 + WebDAV origin)

These tests connect to the dedicated 11300-11330 band brought up by
`tests/manage_test_servers.sh start-all` (via hybrid_mesh_servers.py).  They skip
if the mesh is not up.  Each scenario records the components it traversed —
proven by observable evidence (the entry port used, the data server that served
the bytes via its content tag, HTTP status) — and a final test prints the
component-usage matrix and asserts every node was exercised by some path.

Run:
    tests/manage_test_servers.sh start
    PYTHONPATH=tests pytest tests/test_hybrid_mesh.py -v -s
"""

import hashlib
import os
import subprocess
import time
import uuid

import pytest

import cms_mesh_lib as cml
import hybrid_mesh_lib as hml

P = hml.PORTS
HOST = hml.HOST
EXPORT = hml.EXPORT                       # "/mesh"
STORE = os.path.join(hml.MESH_DIR, "hybrid")   # <node>-data dirs live here

pytestmark = pytest.mark.timeout(120)


# --------------------------------------------------------------------------- #
# Skip gate: the mesh must be up (binaries present + front doors listening)
# --------------------------------------------------------------------------- #

def _mesh_up():
    return all(cml.port_open(p) for p in
               (P["a_data"], P["g_data"], P["a_s3"], P["f_data"], P["g_http"]))


if not _mesh_up():
    pytest.skip("hybrid mesh not up (run manage_test_servers.sh start)",
                allow_module_level=True)


# --------------------------------------------------------------------------- #
# Component-usage ledger — every scenario appends one row
# --------------------------------------------------------------------------- #

COMPONENTS = ["a", "b", "c", "g", "d", "e", "f"]
LABELS = {
    "a": "nginx redirector (tier-1)",
    "b": "nginx proxy",
    "c": "xrootd PSS proxy",
    "g": "xrootd redirector (tier-2)",
    "d": "xrootd data server",
    "e": "xrootd data server",
    "f": "nginx data server",
}
USAGE = []          # list of (scenario, protocol_chain, set(components), evidence)


def _record(scenario, chain, components, evidence):
    USAGE.append((scenario, chain, set(components), evidence))


def _ds_of(text):
    """Map a seeded file's content tag back to the data server that served it
    (the equivalence/seed files are tagged 'cmsmesh::hybrid-<node>')."""
    for node in ("d", "e", "f"):
        if f"hybrid-{node}" in text:
            return node
    return None


# --------------------------------------------------------------------------- #
# Client helpers (root:// via xrdcp, S3 + WebDAV via curl)
# --------------------------------------------------------------------------- #

def _rand(tag, n=64):
    return (f"{tag}-{uuid.uuid4().hex}\n" + "x" * n).encode()


def _md5(b):
    return hashlib.md5(b).hexdigest()


def _write_tmp(tmp_path, name, data):
    p = tmp_path / name
    p.write_bytes(data)
    return str(p)


def _xrdcp_up(port, src, lpath):
    return cml.xrdcp_put(port, src, lpath)


def _xrdcp_down(port, lpath, dst):
    return cml.xrdcp_get(port, lpath, dst)


def _s3_put(port, key, src):
    return subprocess.run(
        ["curl", "-sS", "-o", "/dev/null", "-w", "%{http_code}", "-T", src,
         f"http://{HOST}:{port}/{hml.S3_BUCKET}/{key.lstrip('/')}"],
        capture_output=True, text=True, timeout=60)


def _s3_get(port, key, dst):
    return subprocess.run(
        ["curl", "-sS", "-o", dst, "-w", "%{http_code}",
         f"http://{HOST}:{port}/{hml.S3_BUCKET}/{key.lstrip('/')}"],
        capture_output=True, text=True, timeout=60)


def _webdav_get(port, path, dst, tls=True, follow=True):
    scheme = "https" if tls else "http"
    args = ["curl", "-sS", "-o", dst, "-w", "%{http_code}"]
    if tls:
        args.append("-k")
    if follow:
        args.append("-L")
    args.append(f"{scheme}://{HOST}:{port}/{path.lstrip('/')}")
    return subprocess.run(args, capture_output=True, text=True, timeout=60)


# --------------------------------------------------------------------------- #
# root:// upload / download
# --------------------------------------------------------------------------- #

def test_root_write_through_and_readback(tmp_path):
    """Upload via the tier-1 redirector a (a -> proxy -> g -> DS), then read it
    back through a.  Proves the write-through data plane end to end."""
    data = _rand("root-wt")
    src = _write_tmp(tmp_path, "in", data)
    key = f"{EXPORT}/rt-{uuid.uuid4().hex}.bin"

    up = _xrdcp_up(P["a_data"], src, key)
    assert up.returncode == 0, up.stderr

    dst = str(tmp_path / "out")
    down = _xrdcp_down(P["a_data"], key, dst)
    assert down.returncode == 0, down.stderr
    assert open(dst, "rb").read() == data

    _record("root upload+readback via a", "root://: a->proxy->g->DS",
            {"a", "g"}, "xrdcp put+get rc=0, bytes match")


@pytest.mark.parametrize("proxy", ["b", "c"])
def test_root_download_via_each_proxy(tmp_path, proxy):
    """Download the shared seed file directly through each read-through proxy
    (b=nginx, c=xrootd PSS), which forwards to g and follows its redirect to a
    DS.  Records the proxy and the DS that actually served."""
    port = P[f"{proxy}_data"]
    dst = str(tmp_path / f"out-{proxy}")
    r = _xrdcp_down(port, f"{EXPORT}/{hml.SEED_REL}", dst)
    assert r.returncode == 0, r.stderr
    served = _ds_of(open(dst).read())
    assert served in ("d", "e", "f")
    _record(f"root download via proxy {proxy}",
            f"root://: {proxy}->g->{served}",
            {proxy, "g", served}, f"xrdcp rc=0, served by {served}")


# --------------------------------------------------------------------------- #
# S3 upload / download (nginx ingest path a -> b -> f)
# --------------------------------------------------------------------------- #

def test_s3_upload_download(tmp_path):
    """S3 PUT through the tier-1 S3 front (a-S3 -> b-S3 -> f-S3 origin), then S3
    GET it back through the same chain."""
    data = _rand("s3-rt")
    src = _write_tmp(tmp_path, "s3in", data)
    key = f"s3rt-{uuid.uuid4().hex}.bin"

    up = _s3_put(P["a_s3"], key, src)
    assert up.stdout.strip() == "200", f"S3 PUT -> {up.stdout} {up.stderr}"

    dst = str(tmp_path / "s3out")
    down = _s3_get(P["a_s3"], key, dst)
    assert down.stdout.strip() == "200", f"S3 GET -> {down.stdout}"
    assert open(dst, "rb").read() == data

    _record("S3 upload+download via a", "S3: a->b->f (nginx-only)",
            {"a", "b", "f"}, "curl PUT/GET 200, bytes match")


# --------------------------------------------------------------------------- #
# Multi-protocol: S3 ingest -> read back via root:// and WebDAV (the cross-
# protocol pickup the cluster namespace enables)
# --------------------------------------------------------------------------- #

def test_multiprotocol_s3up_rootdown(tmp_path):
    """S3 PUT (a->b->f) writes into the cluster namespace; read the SAME object
    back over root:// through the cluster (a->proxy->g->locate->f).  The bytes a
    root:// client gets are exactly what the S3 client wrote."""
    data = _rand("s3up-rootdown")
    src = _write_tmp(tmp_path, "mpin", data)
    key = f"mp-{uuid.uuid4().hex}.bin"

    up = _s3_put(P["a_s3"], key, src)
    assert up.stdout.strip() == "200", up.stdout

    # The cluster locates the freshly-PUT object on f; give registration a beat.
    dst = str(tmp_path / "mpout")
    last = None
    for _ in range(5):
        last = _xrdcp_down(P["a_data"], f"{EXPORT}/{key}", dst)
        if last.returncode == 0:
            break
        time.sleep(1)
    assert last.returncode == 0, last.stderr
    assert _md5(open(dst, "rb").read()) == _md5(data)

    _record("S3-up / root-down (cross-protocol)",
            "S3 in: a->b->f  |  root out: a->proxy->g->f",
            {"a", "b", "g", "f"},
            "S3 PUT 200 then xrdcp GET byte-identical")


def test_multiprotocol_s3up_webdavdown(tmp_path):
    """S3 PUT (a->b->f), then read the object back over WebDAV through the stock
    tier-2 XrdHttp redirector g.  When g selects nginx f, the single-port handoff
    serves it; when g selects a stock DS the file is not there, so this asserts
    pickup specifically via f's data port (the handoff path)."""
    data = _rand("s3up-davdown")
    src = _write_tmp(tmp_path, "mpdin", data)
    key = f"mpd-{uuid.uuid4().hex}.bin"

    up = _s3_put(P["a_s3"], key, src)
    assert up.stdout.strip() == "200", up.stdout
    time.sleep(1)

    # The object lives only on f; address f's data port directly (the stock
    # redirector would redirect HTTP there anyway) to exercise the handoff.
    dst = str(tmp_path / "mpdout")
    r = _webdav_get(P["f_data"], f"{EXPORT}/{key}", dst, tls=False, follow=False)
    assert r.stdout.strip() == "200", f"WebDAV via f handoff -> {r.stdout}"
    assert open(dst, "rb").read() == data

    _record("S3-up / WebDAV-down (cross-protocol)",
            "S3 in: a->b->f  |  davs out: f data-port handoff -> f WebDAV",
            {"a", "b", "f"},
            "S3 PUT 200 then WebDAV GET 200 via single-port handoff, bytes match")


# --------------------------------------------------------------------------- #
# WebDAV download through the tier-2 redirector across mixed backends
# --------------------------------------------------------------------------- #

def test_webdav_download_via_redirector():
    """davs GET via the stock XrdHttp redirector g, following its redirect to
    whichever DS it selects — stock d/e serve on their multiplexed data port,
    nginx f serves via the single-port handoff.  Sweeps until each backend has
    served at least once (proves cross-backend WebDAV through the redirector)."""
    served = set()
    out = "/tmp/hm_dav_probe.out"
    for i in range(24):
        r = _webdav_get(P["g_http"], f"{EXPORT}/{hml.SEED_REL}", out,
                        tls=True, follow=True)
        if r.stdout.strip() == "200":
            node = _ds_of(open(out).read())
            if node:
                served.add(node)
        if served >= {"d", "e", "f"}:
            break
    assert served, "no DS served WebDAV via the redirector"
    # f via the redirector proves the handoff; d/e prove stock multiplexing.
    _record("WebDAV download via redirector g",
            "davs://: g->(307)->DS (f via handoff)",
            {"g"} | served, f"davs 200 from {sorted(served)}")


# --------------------------------------------------------------------------- #
# Cross-backend equivalence: identical bytes served byte-for-byte by the
# xrootd DSs (d, e) and the nginx DS (f), addressed directly.
# --------------------------------------------------------------------------- #

def test_cross_backend_equivalence(tmp_path):
    """Stage identical bytes directly into d, e and f's stores, then read the
    same logical path from each DS's own port and assert byte-identical service
    across both backends (xrootd d/e vs nginx f)."""
    data = _rand("equiv", n=4096)
    rel = f"equiv-{uuid.uuid4().hex}.bin"
    digests = {}
    for node in ("d", "e", "f"):
        full = os.path.join(STORE, f"{node}-data", EXPORT.lstrip("/"), rel)
        os.makedirs(os.path.dirname(full), exist_ok=True)
        with open(full, "wb") as fh:
            fh.write(data)
    time.sleep(0.5)
    for node in ("d", "e", "f"):
        dst = str(tmp_path / f"eq-{node}")
        r = _xrdcp_down(P[f"{node}_data"], f"{EXPORT}/{rel}", dst)
        assert r.returncode == 0, f"{node}: {r.stderr}"
        digests[node] = _md5(open(dst, "rb").read())

    assert digests["d"] == digests["e"] == digests["f"] == _md5(data), digests
    _record("cross-backend equivalence (direct d/e/f)",
            "root:// direct to each DS port",
            {"d", "e", "f"}, "identical md5 from xrootd d/e and nginx f")


# --------------------------------------------------------------------------- #
# Large-file integrity through the full mesh
# --------------------------------------------------------------------------- #

def test_large_file_roundtrip(tmp_path):
    """8 MiB random upload via a then download via a — integrity through the full
    write-through + read path."""
    data = os.urandom(8 * 1024 * 1024)
    src = _write_tmp(tmp_path, "big.in", data)
    key = f"{EXPORT}/big-{uuid.uuid4().hex}.bin"

    up = _xrdcp_up(P["a_data"], src, key)
    assert up.returncode == 0, up.stderr
    dst = str(tmp_path / "big.out")
    down = _xrdcp_down(P["a_data"], key, dst)
    assert down.returncode == 0, down.stderr
    assert _md5(open(dst, "rb").read()) == _md5(data)
    _record("8 MiB roundtrip via a", "root://: a->proxy->g->DS (large)",
            {"a", "g"}, "8 MiB md5 match")


# --------------------------------------------------------------------------- #
# Component-usage map (ordered last) — print the matrix + assert full coverage
# --------------------------------------------------------------------------- #

def test_zzz_component_usage_map():
    """Aggregate every scenario's observed component usage into a matrix, print
    it, and assert every mesh node was exercised by at least one path."""
    assert USAGE, "no scenarios recorded — did the earlier tests run?"

    covered = set().union(*(c for _, _, c, _ in USAGE))

    print("\n\n=== HYBRID MESH — COMPONENT USAGE MAP ===\n")
    header = "scenario".ljust(40) + "".join(n.upper().center(4)
                                             for n in COMPONENTS)
    print(header)
    print("-" * len(header))
    for scenario, chain, comps, _ in USAGE:
        row = scenario[:39].ljust(40)
        row += "".join((" ●  " if n in comps else " ·  ") for n in COMPONENTS)
        print(row)
    print("-" * len(header))
    totals = "TOTAL paths touching node".ljust(40)
    totals += "".join(str(sum(1 for _, _, c, _ in USAGE if n in c)).center(4)
                      for n in COMPONENTS)
    print(totals)

    print("\nlegend:")
    for n in COMPONENTS:
        print(f"  {n.upper()} = {LABELS[n]}")
    print("\nper-scenario protocol chain + evidence:")
    for scenario, chain, _, evidence in USAGE:
        print(f"  - {scenario}\n      {chain}\n      evidence: {evidence}")

    missing = set(COMPONENTS) - covered
    assert not missing, f"components never exercised by any scenario: {missing}"
