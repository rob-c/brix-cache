"""Shared helpers for the per-family cachemx grid suites.

Exposition parsing utilities (sample extraction, series maps, label pairs)
plus the mixed-traffic burst that materializes rows across every protocol
plane before a scrape.  Kept out of the test modules so the two grid files
and the semantics file share one parser.
"""

import os
import re
import tempfile

import _cachemx as cx

# One sample line: name, optional {labels}, value.  brix emits no timestamps.
SAMPLE = re.compile(r"^([a-zA-Z_:][a-zA-Z0-9_:]*)(\{[^}]*\})? (\S+)$")
PAIR = re.compile(r'([a-zA-Z_][a-zA-Z0-9_]*)="((?:[^"\\]|\\.)*)"')


def components(family: str, typ: str) -> tuple:
    """The sample-line name prefixes a family owns in the exposition."""
    if typ == "histogram":
        return (family + "_bucket", family + "_sum", family + "_count")
    return (family,)


def sample_lines(lines, family: str, typ: str) -> list:
    """Every sample line of `family` (exact-name match, no prefix bleed)."""
    out = []
    for comp in components(family, typ):
        pb, ps = comp + "{", comp + " "
        out.extend(l for l in lines if l.startswith(pb) or l.startswith(ps))
    return out


def series(lines, family: str, typ: str) -> dict:
    """{'name{labels}': [values...]} — one entry per exposed series string.
    A list longer than 1 means the series was emitted twice (illegal)."""
    m = {}
    for line in sample_lines(lines, family, typ):
        mt = SAMPLE.match(line)
        assert mt, f"unparseable sample line: {line!r}"
        m.setdefault(mt.group(1) + (mt.group(2) or ""), []).append(mt.group(3))
    return m


def label_pairs(labelblock: str) -> list:
    """[(key, value)] pairs from a '{k="v",...}' block ('' -> [])."""
    return PAIR.findall(labelblock or "")


def first_index(lines, prefix: str) -> int:
    """Index of the first line starting with `prefix`, or -1."""
    for i, l in enumerate(lines):
        if l.startswith(prefix):
            return i
    return -1


def burst(mx):
    """One mixed-traffic pass over every plane family: WebDAV (anon, bearer,
    cert, bad-auth, namespace methods, ranges, 404), S3 (anon + SigV4),
    root:// (anon + GSI, data + namespace), so a following scrape carries
    live rows for as many families as one unprivileged client can reach."""
    n = cx.unique_name("gridd")
    mx.seed_local(n, 512)
    assert mx.dav_request("dav", f"/{n}")[0] == 200
    mx.dav_request("dav", f"/{n}", headers={"Range": "bytes=0-99"})
    mx.dav_request("dav", f"/{n}", headers={"Range": "bytes=9000-9999"})
    mx.dav_request("dav", f"/absent_{n}")
    mx.dav_request("dav", f"/{n}", method="HEAD")
    mx.dav_request("dav", f"/col_{n}", method="MKCOL")
    mx.dav_request("dav", f"/col_{n}", method="PROPFIND",
                   headers={"Depth": "0"})
    mx.dav_request("dav", f"/col_{n}", method="DELETE")
    mx.dav_request("dav", "/", method="OPTIONS")
    mx.dav_request("dav", f"/put_{n}", method="PUT", data=b"x" * 256)
    mx.dav_request("dav", f"/put_{n}", method="MOVE",
                   headers={"Destination": mx.http_url("dav", f"/mv_{n}")})
    mx.dav_request("dav", f"/mv_{n}", method="DELETE")

    m = cx.unique_name("grids")
    mx.seed_local(m, 300)
    if os.path.exists(cx.TOKEN_FILE):
        tok = open(cx.TOKEN_FILE).read().strip()
        mx.dav_request("davs", f"/{m}",
                       headers={"Authorization": f"Bearer {tok}"})
    mx.dav_request("davs", f"/{m}", headers={"Authorization": "Bearer bad"})
    mx.dav_request("davsg", f"/{m}")
    assert mx.s3_request("s3", m)[0] == 200
    mx.s3_request("s3sig", m)
    mx.s3_request("s3", f"absent_{m}")
    mx.s3_request("s3", m, method="DELETE")

    o = cx.unique_name("gridr")
    mx.seed_origin(o, 700)
    mx.xrdfs("none", "stat", f"/{o}")
    mx.xrdfs("gsi", "stat", f"/{o}")
    mx.xrdfs("none", "stat", f"/absent_{o}")
    with tempfile.TemporaryDirectory() as td:
        dst = os.path.join(td, "g.bin")
        mx.xrdcp_get("none", f"/{o}", dst)
        src = os.path.join(td, "p.bin")
        with open(src, "wb") as f:
            f.write(b"y" * 400)
        mx.xrdcp_put("none", src, f"/up_{o}")
    mx.xrdfs("none", "rm", f"/{o}")
    cx.settle()
