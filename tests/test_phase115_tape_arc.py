"""Phase-115 W3.1 — the tape dataset archiver behind ``tape://<adapter>/<base>?arc=<depth>``.

A tape MSS is happiest with a few large objects, not a million small files;
XRootD's OssArc answers that by sealing a *dataset* into one archive. Until
this phase every key behind a ``tape://`` tier became its own tape object.
``?arc=<depth>`` (1..8) now wraps whichever MSS adapter the URL selects (stub /
exec / lib) in the archiver decorator ``src/fs/backend/frm/sd_frm_arc.c``:

  * a dataset is the first ``depth`` path components (``/ds1`` at depth 1);
  * members written into it stay in the online buffer (their per-key migrate
    is deferred); writing the completion marker ``.brix-dataset-complete``
    seals the dataset: every regular file below it is packed into one *stored*
    ZIP ``<ds>.brixarc.zip`` (readable by ``unzip`` / ``zipfile`` — an operator
    never needs this software to open an archive), which the inner adapter
    migrates, plus a sidecar index ``<base>/.arcidx/<ds>.idx``;
  * a read of a member whose online copy is gone recalls the archive and
    extracts that one member; the sidecar answers stat/dirlist without a recall;
  * a sealed dataset is immutable — new members are refused (EPERM →
    kXR_NotAuthorized), the marker cannot be republished (EEXIST →
    kXR_ItExists) and ``*.brixarc.zip`` is a reserved key (EINVAL →
    kXR_ArgInvalid);
  * member names are validated on the way out of an archive: nothing outside
    the dataset directory is ever created, whatever the archive claims.

Coverage (each subject is its own nginx; no shared fleet):
  success      — seal → one archive + sidecar and no per-file tape objects, a
                 plain key at ≤ depth still migrates per file, dirlist from the
                 sidecar, byte-exact recall of members out of the archive;
  error        — a member missing from its (stale-indexed) archive is
                 kXR_NotFound while its neighbours serve; the query grammar is
                 refused by ``nginx -t`` on both store-URL parsers;
  security-neg — crafted archives with escaping names extract only the safe
                 member; a sealed dataset refuses writes and its tape objects
                 stay byte-identical; the purge engine never releases an
                 unsealed member (the only copy there is) and does once sealed;
  unit         — the ZIP container's C unit checks (round trip, patched central
                 directory, corrupt payload, ZIP32 limits) compile and pass.
"""

import os
import re
import shutil
import struct
import subprocess
import time
import zipfile
from pathlib import Path

import pytest

from settings import BIND_HOST, NGINX_BIN
from server_registry import NginxInstanceSpec
from cmdscripts.live_common import inject_nginx_load_modules, inject_nginx_runtime_paths

import _test_session_bind_helpers as H

pytestmark = [pytest.mark.uses_lifecycle_harness,
              pytest.mark.xdist_group("lc-p115-tape-arc")]

SRC = Path(__file__).resolve().parents[1] / "src"
ZIP_UNIT_SRCS = ("fs/backend/frm/frm_zip_unittest.c", "fs/backend/frm/frm_zip.c",
                 "core/compat/crc32_ieee.c")

kXR_dirlist = 3004
kXR_open_updt = 0x0020
kXR_mkpath = 0x0100
kXR_ArgInvalid = 3000
kXR_NotAuthorized = 3010
kXR_NotFound = 3011
kXR_ItExists = 3018

MARKER = ".brix-dataset-complete"
MEMBERS = {"f1": b"one " * 300, "f2": b"two " * 500, "sub/f4": b"four" * 100}
UNSAFE = ["../../escape.bin", "/abs.bin", "sub/../x.bin"]
PURGE = "brix_frm_purge_max_bytes 100; brix_frm_purge_interval 1s;"
SUMMARY_KEYS = ("released", "bytes", "owned_before", "owned_after", "young",
                "pinned", "unmigrated", "symlink", "failed")
SUMMARY_RX = re.compile(
    r'tape purge "[^"]+/\.online": released (\d+) file\(s\), (\d+) bytes '
    r'\(occupancy \d+ -> \d+ ppm, owned (\d+) -> (\d+) bytes; skipped '
    r'young=(\d+) pinned=(\d+) unmigrated=(\d+) symlink=(\d+) failed=(\d+)\)')


# --------------------------------------------------------------------------
# harness
# --------------------------------------------------------------------------

def _launch(lifecycle, tmp_path, name, backend, purge_lines="", first_ms=500):
    """The W3.2 template fits: a tape:// backend needs the cache store and the
    stage-request registry it declares, and PURGE_LINES may stay empty."""
    export = tmp_path / "export"
    export.mkdir(exist_ok=True)
    for sub in ("cache", "control"):
        (tmp_path / sub).mkdir(exist_ok=True)
    return lifecycle.start(NginxInstanceSpec(
        name=name,
        template="nginx_p115_tape_purge.conf",
        data_root=str(export),
        env={"BRIX_CACHE_REAP_FIRST_MS": str(first_ms)},
        template_values={
            "BIND_HOST": BIND_HOST,
            "BACKEND": backend,
            "CACHE_DIR": str(tmp_path / "cache"),
            "QUEUE_PATH": str(tmp_path / "frm.queue"),
            "CONTROL_DIR": str(tmp_path / "control"),
            "PURGE_LINES": purge_lines,
            "ALLOW_WRITE": "on",
        },
        reason="phase-115 W3.1 tape dataset archiver"))


def _elog(endpoint):
    return os.path.join(endpoint.prefix, "logs", "error.log")


def _wait_log(elog, pattern, timeout=20.0):
    """Block until ``pattern`` appears in the error log; the match or None."""
    rx = re.compile(pattern)
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            with open(elog) as fh:
                for line in fh:
                    m = rx.search(line)
                    if m:
                        return m
        except FileNotFoundError:
            pass
        time.sleep(0.1)
    return None


def _summaries(elog):
    out = []
    try:
        with open(elog) as fh:
            for line in fh:
                m = SUMMARY_RX.search(line)
                if m:
                    out.append(dict(zip(SUMMARY_KEYS, map(int, m.groups()))))
    except FileNotFoundError:
        pass
    return out


def _wait_summary(elog, pred, timeout=30.0):
    """The first purge summary satisfying ``pred`` within ``timeout``."""
    deadline = time.time() + timeout
    while time.time() < deadline:
        for s in _summaries(elog):
            if pred(s):
                return s
        time.sleep(0.2)
    raise AssertionError(f"no purge summary matched within {timeout}s: {_summaries(elog)}")


def _session(port):
    H.ANON_HOST = BIND_HOST
    return H._establish_primary(port)


def _err(body):
    """(kXR error code, message) of a kXR_error body."""
    code = struct.unpack(">i", body[:4])[0] if len(body) >= 4 else -1
    return code, body[4:].rstrip(b"\x00").decode(errors="replace")


def _open(sock, stream, path, flags, mode=0o644):
    return H._open_waiting(sock, stream, path, flags, mode)


def _put(port, path, data):
    """Create ``path`` holding ``data`` over root://: (status, body) of the
    first step that failed, else the kXR_close reply."""
    sock, _sessid, stream = _session(port)
    try:
        status, body = _open(sock, stream, path,
                             H.kXR_new | kXR_open_updt | kXR_mkpath)
        if status != H.kXR_ok:
            return status, body
        fhandle = body[:4]
        wbody = fhandle + struct.pack(">q", 0) + b"\x00" * 4   # offset, pathid, pad
        status, body = H._send_req(sock, stream, H.kXR_write, body=wbody, payload=data)
        if status != H.kXR_ok:
            return status, body
        return H._send_req(sock, stream, H.kXR_close, body=fhandle + b"\x00" * 12)
    finally:
        sock.close()


def _read(port, path, length):
    """(status, data-or-error-body) of an open + read of ``length`` bytes."""
    sock, _sessid, stream = _session(port)
    try:
        status, body = _open(sock, stream, path, H.kXR_open_read)
        if status != H.kXR_ok:
            return status, body
        return H._read_handle(sock, stream, body[:4], length)
    finally:
        sock.close()


def _read_ok(port, path, length):
    status, data = _read(port, path, length)
    assert status == H.kXR_ok, f"read {path}: status {status} {_err(data)}"
    return data


def _dirlist(port, path):
    sock, _sessid, stream = _session(port)
    try:
        status, body = H._send_req(sock, stream, kXR_dirlist, body=b"\x00" * 16,
                                   payload=path.encode() + b"\x00")
    finally:
        sock.close()
    assert status == H.kXR_ok, f"dirlist {path}: status {status} {_err(body)}"
    return sorted(n for n in body.rstrip(b"\x00").decode().split("\n") if n)


# --------------------------------------------------------------------------
# tape-side fixtures: what a previous life of the server (or any zip tool) left
# --------------------------------------------------------------------------

def _tape_zip(base, ds):
    return base / f"{ds}.brixarc.zip"


def _sidecar(base, ds):
    return base / ".arcidx" / f"{ds}.idx"


def _sidecar_names(base, ds):
    return [line.split("\t")[0] for line in _sidecar(base, ds).read_text().splitlines()]


def _write_archive(path, members):
    """A stored ZIP as any tool writes it; ``members`` maps name -> bytes.
    ``ZipInfo`` keeps a crafted name verbatim (``ZipFile.write`` would sanitise
    it), and the read-back asserts the archive really carries those names."""
    path.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_STORED) as zf:
        for name, data in members.items():
            zf.writestr(zipfile.ZipInfo(name), data)
    with zipfile.ZipFile(path) as zf:
        assert zf.namelist() == list(members), "zipfile rewrote a crafted member name"
        return zf.infolist()


def _plant_sealed(base, ds, members, stale=()):
    """A dataset sealed earlier: the archive on tape plus its sidecar index
    (one ``name\\tsize\\tlfh_off\\tcrc`` line per member, name-sorted). ``stale``
    adds index lines for members the archive no longer holds."""
    infos = _write_archive(_tape_zip(base, ds), members)
    lines = [f"{i.filename}\t{i.file_size}\t{i.header_offset}\t{i.CRC:08x}\n"
             for i in infos]
    lines += [f"{name}\t1\t0\t00000000\n" for name in stale]
    _sidecar(base, ds).parent.mkdir(parents=True, exist_ok=True)
    _sidecar(base, ds).write_text("".join(sorted(lines)))


def _assert_tape_archive(base, ds, members):
    """One stored ZIP holding exactly ``members`` byte-exact, a name-sorted
    sidecar, and the marker migrated — nothing else of the dataset on tape."""
    with zipfile.ZipFile(_tape_zip(base, ds)) as zf:
        assert zf.testzip() is None
        assert sorted(zf.namelist()) == sorted(members)
        assert {i.compress_type for i in zf.infolist()} == {zipfile.ZIP_STORED}
        assert {n: zf.read(n) for n in members} == members
    assert _sidecar_names(base, ds) == sorted(members)
    assert (base / ds / MARKER).exists(), "the marker itself must migrate"
    per_file = sorted(str(p.relative_to(base)) for p in (base / ds).rglob("*")
                      if p.name != MARKER)
    assert per_file == [], f"members leaked onto tape per file: {per_file}"


def _assert_recall_from_archive(port, base, ds, members):
    """With the online dataset and the online archive gone, every member reads
    byte-exact and lands back in the online buffer."""
    shutil.rmtree(base / ".online" / ds)
    (base / ".online" / f"{ds}.brixarc.zip").unlink(missing_ok=True)
    for name, data in members.items():
        assert _read_ok(port, f"/{ds}/{name}", len(data)) == data, name
        assert (base / ".online" / ds / name).read_bytes() == data, \
            f"the recall did not land {name} back in the online buffer"


def _put_ok(port, path, data):
    status, body = _put(port, path, data)
    assert status == H.kXR_ok, f"put {path}: status {status} {_err(body)}"


def _put_refused(port, path, want):
    status, body = _put(port, path, b"late")
    assert status == H.kXR_error, f"{path} was accepted"
    assert _err(body)[0] == want, (path, _err(body))


def _names_under(root, wanted):
    return sorted(str(p) for p in root.rglob("*") if p.name in wanted)


def _chill(online, names, when):
    """Make ``names`` look untouched since ``when`` (atime and mtime)."""
    for name in names:
        os.utime(online / name, (when, when))


# --------------------------------------------------------------------------
# success
# --------------------------------------------------------------------------

def test_marker_seals_the_dataset_into_one_archive_object(lifecycle, tmp_path):
    """(success) three members (one nested) stay online-only until the marker
    lands; then exactly one stored ZIP + its sidecar reach tape, the marker
    migrates, a plain key at depth 1 still migrates per file, dirlist comes
    from the sidecar, and members recall byte-exact after their online copies
    (and the online archive) are gone."""
    base = tmp_path / "tape"
    base.mkdir()
    ep = _launch(lifecycle, tmp_path, "lc-p115-arc", f"tape://{base}?arc=1")
    elog = _elog(ep)
    assert _wait_log(elog, r"dataset archiver armed over the stub adapter \(depth=1, "
                     rf"base={re.escape(str(base))}\)"), "decorator did not report itself"

    for name, data in MEMBERS.items():
        _put_ok(ep.port, f"/ds1/{name}", data)
    _put_ok(ep.port, "/top.bin", b"T" * 64)
    assert (base / "top.bin").read_bytes() == b"T" * 64, "a plain key must migrate per file"
    assert not (base / "ds1").exists(), "a member became its own tape object"
    assert not _tape_zip(base, "ds1").exists(), "sealed before the marker"

    _put_ok(ep.port, f"/ds1/{MARKER}", b"done\n")
    m = _wait_log(elog, r'tape archive "/ds1": sealed (\d+) member\(s\), (\d+) bytes')
    assert m is not None, "no seal notice"
    assert (int(m.group(1)), int(m.group(2))) == (3, sum(map(len, MEMBERS.values())))
    _assert_tape_archive(base, "ds1", MEMBERS)
    assert _dirlist(ep.port, "/ds1") == ["f1", "f2", "sub"]
    _assert_recall_from_archive(ep.port, base, "ds1", MEMBERS)


def test_python_written_archive_recalls_and_lists(lifecycle, tmp_path):
    """(success, interop) an archive + index written by ``zipfile`` (any zip
    tool) is served: the C reader trusts the stored container, not its writer."""
    base = tmp_path / "tape"
    _plant_sealed(base, "ds1", MEMBERS)
    ep = _launch(lifecycle, tmp_path, "lc-p115-arc", f"tape://{base}?arc=1")
    assert _dirlist(ep.port, "/ds1") == ["f1", "f2", "sub"]
    assert _read_ok(ep.port, "/ds1/sub/f4", len(MEMBERS["sub/f4"])) == MEMBERS["sub/f4"]
    assert _read_ok(ep.port, "/ds1/f1", len(MEMBERS["f1"])) == MEMBERS["f1"]


# --------------------------------------------------------------------------
# error
# --------------------------------------------------------------------------

def test_member_missing_from_its_archive_is_not_found(lifecycle, tmp_path):
    """(error) the index still lists ``f2`` but the archive lost it: the recall
    ends in kXR_NotFound (never a generic I/O error), and ``f1`` / ``sub/f4``
    extract from the same archive afterwards."""
    base = tmp_path / "tape"
    kept = {k: v for k, v in MEMBERS.items() if k != "f2"}
    _plant_sealed(base, "ds1", kept, stale=("f2",))
    ep = _launch(lifecycle, tmp_path, "lc-p115-arc", f"tape://{base}?arc=1")

    status, body = _read(ep.port, "/ds1/f2", len(MEMBERS["f2"]))
    assert status == H.kXR_error, "a missing member was served"
    assert _err(body)[0] == kXR_NotFound, _err(body)
    for name, data in kept.items():
        assert _read_ok(ep.port, f"/ds1/{name}", len(data)) == data, name


def _nginx_t(root, body, cache_store=None):
    for d in ("logs", "data", "cache", "tape"):
        (root / d).mkdir(exist_ok=True)
    cache = f"posix:{root}/cache" if cache_store is None else cache_store
    conf = root / "arc.conf"
    conf.write_text(f"""daemon off; error_log {root}/logs/e.log info;
pid {root}/n.pid; thread_pool default threads=2;
events {{ worker_connections 64; }}
stream {{ server {{ listen unix:s.sock;
    brix_root on; brix_auth none; brix_export {root}/data;
    brix_cache_store {cache};
    {body}
}} }}
""")
    inject_nginx_load_modules(conf)
    inject_nginx_runtime_paths(conf, root)
    p = subprocess.run([str(NGINX_BIN), "-t", "-p", str(root), "-c", str(conf)],
                       capture_output=True, text=True, timeout=30)
    return p.returncode, p.stderr + p.stdout


@pytest.mark.parametrize("query", ["arc=0", "arc=9", "arc=abc", "arc=", "arc=1x", "bogus=1"])
def test_storage_backend_query_refused_by_nginx_t(tmp_path, query):
    rc, out = _nginx_t(tmp_path, f"brix_storage_backend tape://{tmp_path}/tape?{query};")
    assert rc != 0, f"{query!r} accepted:\n{out}"
    assert f'tape:// query "{query}" is not "arc=<1..8>"' in out, out


def test_storage_backend_query_accepted_by_nginx_t(tmp_path):
    rc, out = _nginx_t(tmp_path, f"brix_storage_backend tape://{tmp_path}/tape?arc=3;")
    assert rc == 0, out


# The tier grammar (brix_stage_store / brix_cache_store) spells a tape store
# with an authority — tape://<adapter>/<base> — where the backend grammar takes
# the bare base (tape://<base>); and a brix_stage_store URL is never parsed at
# all unless `brix_stage on` enables the stage engine that owns it.  Both are
# compat facts an operator trips over, pinned below beside the query check.

def _tier_stage(tmp_path, url):
    return _nginx_t(tmp_path, f"brix_storage_backend posix:{tmp_path}/data; "
                              f"brix_stage on; brix_stage_store {url};")


@pytest.mark.parametrize("query", ["arc=0", "arc=9", "arc=abc", "arc=", "bogus=1"])
def test_tier_store_query_refused_by_nginx_t(tmp_path, query):
    """(error, grammar) the tier grammar behind brix_stage_store carries the
    same query and refuses a bad one before any role validation runs."""
    rc, out = _tier_stage(tmp_path, f"tape://stub{tmp_path}/tape?{query}")
    assert rc != 0, f"{query!r} accepted:\n{out}"
    assert f'tape store opts "?{query}": expected "arc=<1..8>"' in out, out


def test_tier_store_query_accepted_by_nginx_t(tmp_path):
    rc, out = _tier_stage(tmp_path, f"tape://stub{tmp_path}/tape?arc=2")
    assert rc == 0, out


def test_tier_cache_store_query_refused_by_nginx_t(tmp_path):
    """(error, grammar) the cache-store spelling of the same URL is checked too."""
    rc, out = _nginx_t(tmp_path, f"brix_storage_backend posix:{tmp_path}/data;",
                       cache_store=f"tape://stub{tmp_path}/tape?arc=9")
    assert rc != 0 and 'tape store opts "?arc=9": expected "arc=<1..8>"' in out, out


def test_tier_stage_store_is_inert_without_brix_stage_on(tmp_path):
    """(compat) without `brix_stage on` the stage-store URL is never parsed:
    a bad query passes nginx -t.  Operators must enable the engine to have the
    store validated at all."""
    rc, out = _nginx_t(tmp_path, f"brix_storage_backend posix:{tmp_path}/data; "
                                 f"brix_stage_store tape://stub{tmp_path}/tape?arc=9;")
    assert rc == 0, out


def test_tier_tape_store_needs_an_adapter_authority(tmp_path):
    """(compat) the tier grammar wants tape://<adapter>/<base>; the backend
    grammar's bare tape://<base> is refused as a missing host."""
    rc, out = _tier_stage(tmp_path, f"tape://{tmp_path}/tape?arc=2")
    assert rc != 0 and "invalid store host" in out, out


# --------------------------------------------------------------------------
# security-negative
# --------------------------------------------------------------------------

def test_unsafe_member_names_are_skipped_never_extracted(lifecycle, tmp_path):
    """(security-neg) a tape archive claiming ``../../escape.bin``, ``/abs.bin``
    and ``sub/../x.bin`` (no sidecar, so the server rebuilds the index from the
    archive) serves only ``ok.bin``: the three names are skipped and logged,
    the rebuilt sidecar and dirlist show one member, and no file by those
    names appears anywhere."""
    base = tmp_path / "tape"
    members = {"ok.bin": b"OK" * 100}
    members.update({name: b"EVIL" * 50 for name in UNSAFE})
    _write_archive(_tape_zip(base, "ds2"), members)
    ep = _launch(lifecycle, tmp_path, "lc-p115-arc", f"tape://{base}?arc=1")

    assert _read_ok(ep.port, "/ds2/ok.bin", 200) == b"OK" * 100
    # every arc log line names the DATASET ("/ds2"), never the archive object
    # ("/ds2.brixarc.zip"): the extract-side lines used to name the object
    # while the seal line named the dataset, so one grep could not follow one
    # dataset through its life (phase-115 W3.1).
    assert _wait_log(_elog(ep), r'tape archive "/ds2": skipped 3 unsafe member name\(s\)')
    assert (_sidecar_names(base, "ds2"), _dirlist(ep.port, "/ds2")) == (["ok.bin"], ["ok.bin"])
    assert _names_under(tmp_path, ("escape.bin", "abs.bin", "x.bin")) == []
    assert not Path("/abs.bin").exists()


def test_sealed_dataset_refuses_writes_and_keeps_tape_objects_intact(lifecycle, tmp_path):
    """(security-neg) after the seal: a new member is kXR_NotAuthorized, the
    marker cannot be republished (kXR_ItExists), the archive name itself is a
    reserved key (kXR_ArgInvalid); the archive and index bytes never change and
    nothing by the refused names lands on tape or in the buffer."""
    base = tmp_path / "tape"
    _plant_sealed(base, "ds1", MEMBERS)
    zip_before = _tape_zip(base, "ds1").read_bytes()
    idx_before = _sidecar(base, "ds1").read_text()
    ep = _launch(lifecycle, tmp_path, "lc-p115-arc", f"tape://{base}?arc=1")

    _put_refused(ep.port, "/ds1/f9", kXR_NotAuthorized)
    _put_refused(ep.port, f"/ds1/{MARKER}", kXR_ItExists)
    _put_refused(ep.port, "/x.brixarc.zip", kXR_ArgInvalid)

    assert (_tape_zip(base, "ds1").read_bytes(), _sidecar(base, "ds1").read_text()) \
        == (zip_before, idx_before), "a refused write changed a tape object"
    assert _names_under(base, ("f9", "x.brixarc.zip")) == []
    assert _read_ok(ep.port, "/ds1/f1", len(MEMBERS["f1"])) == MEMBERS["f1"]


def test_purge_spares_unsealed_members_and_releases_them_once_sealed(lifecycle, tmp_path):
    """(security-neg, W3.2 interplay) two cold members of an unsealed dataset
    are the only copies there are: the cap arm reports them ``unmigrated`` and
    keeps them. Sealing the dataset makes the archive their durable copy, and
    the next pass releases them; a read then recalls from the archive."""
    base = tmp_path / "tape"
    online = base / ".online" / "ds1"
    online.mkdir(parents=True)
    old = time.time() - 600
    for name in ("f1", "f2"):
        (online / name).write_bytes(MEMBERS[name])
    _chill(online, ("f1", "f2"), old)
    ep = _launch(lifecycle, tmp_path, "lc-p115-arc-purge", f"tape://{base}?arc=1",
                 PURGE, first_ms=500)
    elog = _elog(ep)

    first = _wait_summary(elog, lambda s: s["unmigrated"] == 2)
    assert (first["released"], sorted(p.name for p in online.iterdir())) == (0, ["f1", "f2"])

    _put_ok(ep.port, f"/ds1/{MARKER}", b"done\n")
    assert _wait_log(elog, r'tape archive "/ds1": sealed 2 member\(s\)')
    _chill(online, ("f1", "f2"), old)       # packing read them; cold again
    final = _wait_summary(elog, lambda s: s["released"] >= 2)
    assert (final["unmigrated"], _names_under(online, ("f1", "f2"))) == (0, [])
    assert _read_ok(ep.port, "/ds1/f1", len(MEMBERS["f1"])) == MEMBERS["f1"]


# --------------------------------------------------------------------------
# unit — the ZIP container
# --------------------------------------------------------------------------

CC = shutil.which("gcc") or shutil.which("cc")
ZIP_UNIT_PATHS = [str(SRC / s) for s in ZIP_UNIT_SRCS]


def _build_zip_unit(tmp_path):
    if CC is None:
        pytest.skip("no C compiler on PATH")
    out = tmp_path / "frm_zip_ut"
    r = subprocess.run([CC, "-Wall", "-Wextra", "-Werror", "-I", str(SRC), "-o", str(out),
                        *ZIP_UNIT_PATHS], capture_output=True, text=True, timeout=180)
    assert r.returncode == 0, r.stderr
    return out


def test_zip_container_unit_checks_pass(tmp_path):
    out = _build_zip_unit(tmp_path)
    r = subprocess.run([str(out)], capture_output=True, text=True, timeout=60,
                       env={**os.environ, "TMPDIR": str(tmp_path)})
    assert r.returncode == 0, r.stdout + r.stderr
    assert "all checks passed" in r.stdout, r.stdout
