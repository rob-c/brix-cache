"""Phase-115 W3.3 — space groups: ``brix_oss_space <group> <prefix> [quota=]``.

Stock xrootd accounts and caps storage per space group (``oss.space`` /
``oss.cgroup``: one per VO or activity); a client selects a group at create
time with ``oss.cgroup=`` and reads its report with kXR_Qspace. Before W3.3
BriX had one name (brix_oss_cgroup) and one export-wide quota (brix_oss_quota):
the report could name a group but never distinguish two, and no per-VO cap
existed.

Pinned here (posix export, one worker, fleet-free lane):

* the report is the group's — kXR_Qspace on a path answers with the name,
  quota, bytes under the prefix and a maxf capped by the quota headroom of
  the group whose LONGEST prefix owns it, at a component boundary only
  ("/atlasdata" is not "/atlas"); ``?oss.cgroup=<name>`` selects by name;
  everything else is the export-wide default group;
* the cap is real — with brix_oss_quota_enforce on, a write that would push a
  group past its quota is refused kXR_overQuota, also inside the 5 s usage
  cache TTL (every admitted write is charged), and the group's quota ALONE
  governs its prefix (brix_oss_quota covers only paths outside every group);
* isolation — group A over quota never refuses group B or the default group;
* a create-open naming a group whose prefix does not own the path, or an
  unknown group, is refused kXR_ArgInvalid and creates nothing; read opens
  ignore the key;
* nginx -t refuses every malformed declaration (name, prefix, quota,
  duplicate name or prefix) and accepts the documented forms.
"""

import os
import struct
import subprocess
import time

import pytest

from settings import BIND_HOST
from server_registry import NginxInstanceSpec

import _test_session_bind_helpers as H

pytestmark = [pytest.mark.uses_lifecycle_harness,
              pytest.mark.xdist_group("lc-p115-space")]

_SERVER = "lc-p115-space"
_REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_XRDCP = os.path.join(_REPO, "client", "bin", "xrdcp")

kXR_query = 3001
kXR_Qspace = 5
kXR_open_updt = 0x0020
kXR_mkpath = 0x0100
kXR_ArgInvalid = 3000
kXR_overQuota = 3021

_GROUPS = ("brix_oss_space atlas /atlas quota=65536;\n"
           "        brix_oss_space deep /atlas/deep quota=1024;\n"
           "        brix_oss_space cms /cms;")
_DIRS = ("atlas", "atlas/deep", "cms", "other", "atlasdata")


# --------------------------------------------------------------------------
# helpers
# --------------------------------------------------------------------------

def _spec(tmp_path, space_lines, extra_lines=""):
    export = tmp_path / "export"
    for d in _DIRS:
        (export / d).mkdir(parents=True, exist_ok=True)
    return NginxInstanceSpec(
        name=_SERVER,
        template="nginx_p115_space_groups.conf",
        data_root=str(export),
        template_values={"BIND_HOST": BIND_HOST,
                         "SPACE_LINES": space_lines,
                         "EXTRA_LINES": extra_lines},
        reason="phase-115 W3.3 space groups")


def _launch(lifecycle, tmp_path, space_lines, extra_lines=""):
    return lifecycle.start(_spec(tmp_path, space_lines, extra_lines)).port


def _session(port):
    H.ANON_HOST = BIND_HOST
    return H._establish_primary(port)


def _err(body):
    return struct.unpack(">i", body[:4])[0], body[4:].rstrip(b"\x00").decode(errors="replace")


def _qspace(port, arg):
    """(status, body) of one raw kXR_Qspace on ``arg`` ("<path>[?cgi]")."""
    sock, _sessid, stream = _session(port)
    try:
        return H._send_req(sock, stream, kXR_query,
                           body=struct.pack(">H", kXR_Qspace) + b"\x00" * 14,
                           payload=arg.encode())
    finally:
        sock.close()


def _report(port, arg):
    status, body = _qspace(port, arg)
    assert status == H.kXR_ok, f"Qspace {arg!r}: status {status} {body!r}"
    return dict(kv.split("=", 1) for kv in body.rstrip(b"\x00").decode().split("&"))


def _open_new(sock, stream, path):
    body = struct.pack(">HH", 0o644, H.kXR_new | kXR_open_updt | kXR_mkpath) + b"\x00" * 12
    return H._send_req(sock, stream, H.kXR_open, body=body, payload=path.encode() + b"\x00")


def _close(sock, stream, fhandle):
    status, _body = H._send_req(sock, stream, H.kXR_close, body=fhandle + b"\x00" * 12)
    assert status == H.kXR_ok


def _upload(tmp_path, port, path, nbytes):
    """Upload ``nbytes`` to ``path`` with the native client (the write gate
    under test sits at the shared admission chokepoint, upstream of the
    pwrite, so the client's chunking is irrelevant)."""
    if not os.access(_XRDCP, os.X_OK):
        pytest.skip("native xrdcp not built")
    src = tmp_path / ("src-" + path.strip("/").replace("/", "_"))
    src.write_bytes(b"Q" * nbytes)
    return subprocess.run(
        ["env", "-u", "LD_LIBRARY_PATH", _XRDCP, "-f", str(src),
         f"root://{BIND_HOST}:{port}/{path}"],
        capture_output=True, text=True, timeout=60)


def _refused_over_quota(proc):
    return proc.returncode != 0 and "quota" in (proc.stderr + proc.stdout).lower()


def _assert_group(r, name, used, quota):
    """One group's report: name, bytes under the prefix, quota, and maxf =
    min(free, headroom) for a capped group / free for an unlimited one."""
    assert r["oss.cgroup"] == name, r
    assert int(r["oss.used"]) == used and int(r["oss.quota"]) == quota, r
    if quota < 0:
        assert r["oss.maxf"] == r["oss.free"], r
    else:
        assert int(r["oss.maxf"]) == min(int(r["oss.free"]), quota - used), r


# --------------------------------------------------------------------------
# kXR_Qspace: the report is the group's
# --------------------------------------------------------------------------

def test_qspace_reports_the_group_whose_longest_prefix_owns_the_path(lifecycle, tmp_path):
    """(success) name, quota, bytes under the prefix, maxf = min(free, quota
    headroom); a nested group's bytes count toward both it and its parent;
    the boundary is a path component; anything else is the default group."""
    port = _launch(lifecycle, tmp_path, _GROUPS)
    export = tmp_path / "export"
    (export / "atlas/a.bin").write_bytes(b"A" * 4096)
    (export / "atlas/deep/d.bin").write_bytes(b"D" * 100)
    (export / "cms/b.bin").write_bytes(b"B" * 1024)
    (export / "atlasdata/z.bin").write_bytes(b"Z" * 10)

    _assert_group(_report(port, "/atlas/anything"), "atlas", 4196, 65536)
    _assert_group(_report(port, "/atlas/deep/x"), "deep", 100, 1024)
    _assert_group(_report(port, "/cms"), "cms", 1024, -1)
    for arg in ("/", "/other/x", "/atlasdata/z.bin"):
        r = _report(port, arg)
        assert r["oss.cgroup"] == "site" and r["oss.quota"] == "-1", (arg, r)


def test_qspace_selects_a_group_by_name(lifecycle, tmp_path):
    """(success) ``?oss.cgroup=<name>`` wins over the path; the default
    group is selectable by its brix_oss_cgroup name."""
    port = _launch(lifecycle, tmp_path, _GROUPS)
    (tmp_path / "export/cms/b.bin").write_bytes(b"B" * 512)
    assert _report(port, "/?oss.cgroup=cms")["oss.cgroup"] == "cms"
    assert int(_report(port, "/atlas/x?oss.cgroup=cms")["oss.used"]) == 512
    assert _report(port, "/cms/b.bin?oss.cgroup=site")["oss.cgroup"] == "site"


def test_qspace_unknown_group_selector_is_arginvalid(lifecycle, tmp_path):
    """(error) a selector naming no group is the caller's error."""
    port = _launch(lifecycle, tmp_path, _GROUPS)
    status, body = _qspace(port, "/atlas/x?oss.cgroup=nope")
    assert status == H.kXR_error, (status, body)
    code, text = _err(body)
    assert code == kXR_ArgInvalid and "unknown space group" in text, (code, text)


# --------------------------------------------------------------------------
# the write gate
# --------------------------------------------------------------------------

def test_group_quota_governs_its_prefix_and_the_export_quota_the_rest(lifecycle, tmp_path):
    """(success + error) inside a group only ITS quota applies — an export-wide
    1-byte quota does not refuse a 48 KiB write under /atlas — while a path in
    no group is still governed by brix_oss_quota."""
    port = _launch(lifecycle, tmp_path,
                   "brix_oss_space atlas /atlas quota=65536;",
                   "brix_oss_quota 1;\n        brix_oss_quota_enforce on;")
    r = _upload(tmp_path, port, "/atlas/a.bin", 49152)
    assert r.returncode == 0, f"group write refused by the export quota: {r.stderr}"
    r = _upload(tmp_path, port, "/other/o.bin", 4096)
    assert _refused_over_quota(r), f"export quota no longer governs outside groups: {r.stderr}"


def test_over_quota_write_is_refused_even_inside_the_usage_cache_ttl(lifecycle, tmp_path):
    """(error) 48 KiB lands; a second 48 KiB straight after (inside the 5 s
    TTL) is refused because admitted bytes are charged to the group; after the
    TTL an 8 KiB write that fits is admitted (the refusal is exact, not
    sticky) and the report shows the bytes that landed."""
    port = _launch(lifecycle, tmp_path,
                   "brix_oss_space atlas /atlas quota=65536;",
                   "brix_oss_quota_enforce on;")
    r = _upload(tmp_path, port, "/atlas/a.bin", 49152)
    assert r.returncode == 0, r.stderr
    r = _upload(tmp_path, port, "/atlas/b.bin", 49152)
    assert _refused_over_quota(r), f"burst inside the TTL overran the quota: {r.stderr}"
    time.sleep(5.2)
    r = _upload(tmp_path, port, "/atlas/c.bin", 8192)
    assert r.returncode == 0, f"a fitting write was refused after the TTL: {r.stderr}"
    time.sleep(5.2)
    assert int(_report(port, "/atlas")["oss.used"]) == 49152 + 8192


def test_group_over_quota_never_refuses_another_group(lifecycle, tmp_path):
    """(security-negative) atlas full: cms, the default group and the
    look-alike "/atlasdata" all still admit writes."""
    port = _launch(lifecycle, tmp_path,
                   "brix_oss_space atlas /atlas quota=4096;\n"
                   "        brix_oss_space cms /cms quota=65536;",
                   "brix_oss_quota_enforce on;")
    r = _upload(tmp_path, port, "/atlas/big.bin", 8192)
    assert _refused_over_quota(r), f"8 KiB into a 4 KiB group landed: {r.stderr}"
    for path in ("/cms/ok.bin", "/other/ok.bin", "/atlasdata/ok.bin"):
        r = _upload(tmp_path, port, path, 8192)
        assert r.returncode == 0, f"{path} refused by another group's quota: {r.stderr}"


# --------------------------------------------------------------------------
# kXR_open ?oss.cgroup=
# --------------------------------------------------------------------------

def test_create_open_must_name_the_group_that_owns_the_path(lifecycle, tmp_path):
    """(security-negative) a create naming a foreign or unknown group is
    refused kXR_ArgInvalid and creates nothing; naming the owner, the default
    group by name, or nothing at all is accepted; read opens ignore the key."""
    port = _launch(lifecycle, tmp_path, _GROUPS)
    export = tmp_path / "export"
    sock, _sessid, stream = _session(port)
    try:
        refused = (("/atlas/f.bin?oss.cgroup=cms", "path is not in space group"),
                   ("/atlas/g.bin?oss.cgroup=nope", "unknown space group"),
                   ("/other/h.bin?oss.cgroup=atlas", "path is not in space group"),
                   ("/atlas/i.bin?oss.cgroup=site", "path is not in space group"))
        for path, needle in refused:
            status, body = _open_new(sock, stream, path)
            assert status == H.kXR_error, (path, status, body)
            code, text = _err(body)
            assert code == kXR_ArgInvalid and needle in text, (path, code, text)
            assert not (export / path.split("?")[0].lstrip("/")).exists(), path

        for path in ("/atlas/j.bin?oss.cgroup=atlas", "/other/k.bin?oss.cgroup=site",
                     "/atlas/deep/l.bin?oss.cgroup=deep", "/cms/m.bin"):
            status, body = _open_new(sock, stream, path)
            assert status == H.kXR_ok, (path, status, body)
            _close(sock, stream, body[:4])

        (export / "cms/r.bin").write_bytes(b"R" * 16)
        status, body = H._open_waiting(sock, stream, "/cms/r.bin?oss.cgroup=nope",
                                       H.kXR_open_read)
        assert status == H.kXR_ok, ("read opens ignore oss.cgroup", status, body)
        _close(sock, stream, body[:4])
    finally:
        sock.close()


# --------------------------------------------------------------------------
# nginx -t
# --------------------------------------------------------------------------

@pytest.mark.parametrize("lines, needle", [
    ("brix_oss_space a&b /x;", "CGI report grammar"),
    ('brix_oss_space "" /x;', "is empty or carries"),
    ("brix_oss_space a atlas;", "absolute export-relative"),
    ("brix_oss_space a /a/../b;", "absolute export-relative"),
    ("brix_oss_space a /atlas/;", "absolute export-relative"),
    ("brix_oss_space a /;", "absolute export-relative"),
    ("brix_oss_space a /x quota=lots;", "not a non-negative size"),
    ("brix_oss_space a /x size=1;", "expected quota="),
    ("brix_oss_space a /x;\n        brix_oss_space a /y;", "declared twice"),
    ("brix_oss_space a /x;\n        brix_oss_space b /x;", "already belongs to group"),
])
def test_nginx_t_refuses_malformed_declarations(lifecycle, tmp_path, lines, needle):
    """(error) every malformed form fails the parse with a named reason."""
    lifecycle.register(_spec(tmp_path, lines))
    lifecycle.reconfigure(_SERVER)
    r = lifecycle.nginx_test(_SERVER, check=False)
    assert r.returncode != 0, f"accepted: {lines!r}"
    assert "brix_oss_space" in r.stderr and needle in r.stderr, r.stderr


def test_nginx_t_accepts_the_documented_forms(lifecycle, tmp_path):
    """(success) sized, unlimited, nested and quota-less declarations parse."""
    lifecycle.register(_spec(tmp_path,
                             "brix_oss_space a /x quota=1m;\n"
                             "        brix_oss_space b /x/y;\n"
                             "        brix_oss_space c /z quota=-1;"))
    lifecycle.reconfigure(_SERVER)
    r = lifecycle.nginx_test(_SERVER, check=False)
    assert r.returncode == 0, r.stderr
