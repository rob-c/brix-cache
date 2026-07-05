"""Differential conformance for `xrdcp` OPTION breadth, RECURSIVE copies,
multi-stream transfers, and round-trips — against BOTH our nginx-xrootd server
and the stock xrootd server (and exercising our own native xrdcp client).

Sibling files own the neighbouring ground; this file does not duplicate them:
  * test_official_interop.py  — broad xrdfs op matrix + a couple of xrdcp probes
  * test_conf_io_read.py      — the raw read data-plane (read/readv/pgread bytes)
  * test_conf_client.py       — Q2 client parity + a first slice of -f/-N/-s/-r

Here the focus is the `xrdcp` TRANSFER-OPTION surface itself, end to end:
  -f/--force, -N/--nopbar, -s/--silent, default(progress), -p/--path(MakeDir),
  --posc, --cksum (adler32:source / adler32:print), -r/--recursive (download,
  upload, whole-tree), -S/--streams (multi-stream), --retry, stdout("-") sink,
  stdin("-") source, the empty file, and large round-trips.

Philosophy (per the maintainer): a divergence is a BUG IN THIS IMPLEMENTATION
(our server, or our client) unless there is positive evidence otherwise. The
oracle is the stock toolchain on the stock server. Every assertion either:
  * pins stock-correct behaviour (the stock client/server is the reference), or
  * is DIFFERENTIAL (same op, our vs stock server, byte-compared), or
  * is a Q2 check of OUR client against the stock server.

When an xrdcp option is genuinely unsupported by the installed build, the test
asserts the only thing that is non-negotiable — that it does NOT corrupt data —
and REPORTS the option as unsupported via the captured output, rather than
silently passing as if the option worked.

Self-provisioning on dedicated high ports; skips entirely without the stock
toolchain (xrootd/xrdfs/xrdcp on PATH).

xrdcp option reference consulted (not modified):
  /tmp/brix-src/src/XrdApps/XrdCpConfig.cc   opLetters / opVec / defCks
  /tmp/brix-src/src/XrdClient .../XrdClClassicCopyJob.cc
"""

import hashlib
import os
import subprocess
import zlib

import pytest

import official_interop_lib as L

pytestmark = [pytest.mark.timeout(240),
              pytest.mark.skipif(not L.have_official(),
                                 reason="stock xrootd/xrdfs/xrdcp not installed")]


# --------------------------------------------------------------------------- #
# Module fixture: our server + the stock server on identical rich data trees.  #
# Dedicated ports so this file never collides with the sibling suites.         #
# --------------------------------------------------------------------------- #
@pytest.fixture(scope="module")
def srv(tmp_path_factory):
    base = str(tmp_path_factory.mktemp("conf_xrdcp"))
    try:
        procs, ctx = L.start_pair(base, our_port=L.worker_port(14036), off_port=L.worker_port(14037))
    except Exception as e:  # noqa: BLE001 - any launch failure -> skip cleanly
        pytest.skip(f"server pair did not start: {e}")
    yield ctx
    L.stop_pair(procs)


# --------------------------------------------------------------------------- #
# Helpers                                                                      #
# --------------------------------------------------------------------------- #
def _read(p):
    with open(p, "rb") as f:
        return f.read()


def _src_bytes(ctx, name):
    """Authoritative source bytes for `name` (identical on both data dirs)."""
    return _read(os.path.join(ctx["our_data"], name))


def _md5(b):
    return hashlib.md5(b).hexdigest()


def _adler_hex(b):
    return f"{zlib.adler32(b) & 0xffffffff:08x}"


def _timeout_for(name):
    return 180 if ("big1m" in name or name == "/") else 90


def _cp(xrdcp, *args, timeout=90):
    return L.run([xrdcp, *args], timeout=timeout)


def _download(xrdcp, url, name, dst, *opts, timeout=90):
    return _cp(xrdcp, *opts, f"{url}//{name}", dst, timeout=timeout)


def _unsupported(out, err):
    """True when xrdcp signalled the OPTION (not the data) is unavailable."""
    blob = (out + err).lower()
    return any(k in blob for k in ("unsupported", "not supported",
                                   "invalid option", "unknown option",
                                   "unrecognized"))


def _make_local_tree(root):
    """A small deterministic local tree for recursive UPLOAD tests."""
    j = os.path.join
    os.makedirs(j(root, "x", "y"), exist_ok=True)
    files = {
        "top.txt": b"top\n",
        os.path.join("x", "mid.bin"): bytes((i * 13 + 1) & 0xff for i in range(777)),
        os.path.join("x", "y", "leaf.bin"): bytes((i * 29 + 5) & 0xff for i in range(2050)),
    }
    for rel, data in files.items():
        with open(j(root, rel), "wb") as f:
            f.write(data)
    return files


# =========================================================================== #
# OPTION: -f / --force — overwrite an existing local target, byte-exact, and   #
# do it twice to prove the overwrite path itself is correct (not a no-op).     #
# =========================================================================== #
@pytest.mark.parametrize("name", ["data.bin", "sz_4096.bin", "hello.txt"])
def test_force_overwrite_download(srv, tmp_path, name):
    dst = str(tmp_path / f"force_{name}")
    with open(dst, "wb") as f:
        f.write(b"STALE pre-existing junk that must be replaced")
    want = _src_bytes(srv, name)
    for attempt in (1, 2):  # second pass overwrites the freshly-correct file
        rc, out, err = _download(L.OFF_XRDCP, srv["our"], name, dst, "-f")
        assert rc == 0, (f"xrdcp -f (pass {attempt}) {name} <- OUR server "
                         f"failed: {out}{err}")
        assert _read(dst) == want, (
            f"xrdcp -f (pass {attempt}) {name}: overwritten bytes != source")


def test_force_required_for_existing_target(srv, tmp_path):
    """Without -f to an existing local target, xrdcp must refuse (it does not
    silently clobber). Pin that our server's download obeys the same rule the
    stock server does — same rc class for both."""
    dst = str(tmp_path / "noforce.bin")
    open(dst, "wb").write(b"already here")
    rc_our, o1, e1 = _download(L.OFF_XRDCP, srv["our"], "data.bin", dst)
    rc_off, o2, e2 = _download(L.OFF_XRDCP, srv["off"], "data.bin", dst)
    assert (rc_our == 0) == (rc_off == 0), (
        f"no-force-to-existing diverges: OUR rc={rc_our} STOCK rc={rc_off} "
        f"(our={o1}{e1} stock={o2}{e2})")
    # whatever the rc, the original local file must be intact (no partial clobber)
    assert _read(dst) == b"already here", "no-force download clobbered the target"


# =========================================================================== #
# OPTION: -N / -s / default(progress) — output-mode flags must never affect    #
# the bytes delivered. Parametrize across files and modes; integrity is exact. #
# =========================================================================== #
@pytest.mark.parametrize("mode", ["-N", "-s", "--nopbar", "--silent", "default"])
@pytest.mark.parametrize("name", ["data.bin", "sz_65536.bin", "hello.txt"])
def test_output_mode_integrity(srv, tmp_path, mode, name):
    dst = str(tmp_path / f"mode_{mode.strip('-')}_{name}")
    opts = ["-f"] if mode == "default" else [mode, "-f"]
    rc, out, err = _download(L.OFF_XRDCP, srv["our"], name, dst, *opts,
                             timeout=_timeout_for(name))
    assert rc == 0, f"xrdcp {mode} {name} <- OUR server failed: {out}{err}"
    assert _read(dst) == _src_bytes(srv, name), (
        f"xrdcp {mode} {name}: output-mode flag altered the bytes")


# =========================================================================== #
# OPTION: -f upload — local -> server, byte-exact on disk; and no-force        #
# upload-to-existing parity vs stock.                                          #
# =========================================================================== #
def test_force_overwrite_upload(srv, tmp_path):
    src = str(tmp_path / "up_force.src")
    payload = bytes((i * 53 + 3) & 0xff for i in range(4321))
    open(src, "wb").write(payload)
    remote = "/up_force.bin"
    on_disk = os.path.join(srv["our_data"], "up_force.bin")
    # seed a different prior object so -f must truly overwrite
    open(on_disk, "wb").write(b"prior server-side contents")
    rc, out, err = _cp(L.OFF_XRDCP, "-f", src, f"{srv['our']}/{remote}")
    assert rc == 0, f"xrdcp -f upload to OUR server failed: {out}{err}"
    assert _read(on_disk) == payload, "xrdcp -f upload: server bytes != source"


def test_noforce_upload_to_existing_parity(srv, tmp_path):
    """Upload (no -f) onto a pre-existing remote object: our server and the
    stock server must give the same rc class; neither silently corrupts."""
    src = str(tmp_path / "up_noforce.src")
    payload = bytes((i * 7 + 9) & 0xff for i in range(1500))
    open(src, "wb").write(payload)
    # pre-create the destination on BOTH servers
    for data_dir, ext in ((srv["our_data"], "our"), (srv["off_data"], "off")):
        open(os.path.join(data_dir, "noforce_up.bin"), "wb").write(b"existing\n")
    rc_our, o1, e1 = _cp(L.OFF_XRDCP, src, f"{srv['our']}//noforce_up.bin")
    rc_off, o2, e2 = _cp(L.OFF_XRDCP, src, f"{srv['off']}//noforce_up.bin")
    assert (rc_our == 0) == (rc_off == 0), (
        f"no-force upload-to-existing diverges: OUR rc={rc_our} "
        f"STOCK rc={rc_off} (our={o1}{e1} stock={o2}{e2})")


# =========================================================================== #
# OPTION: missing-parent creation — uploading to a path whose parent dir does  #
# not exist. The reference server auto-creates the path (verified in sibling   #
# tests); ours must too, with and without an explicit -p/--path (MakeDir).     #
# =========================================================================== #
@pytest.mark.parametrize("flag", ["none", "-p", "--path"])
def test_upload_missing_parent_creates_path(srv, tmp_path, flag):
    src = str(tmp_path / f"mkpath_{flag.strip('-') or 'none'}.src")
    payload = bytes((i * 11 + 2) & 0xff for i in range(900))
    open(src, "wb").write(payload)
    sub = f"mkparent_{flag.strip('-') or 'none'}"
    remote = f"/{sub}/a/b/file.bin"
    opts = [] if flag == "none" else [flag]
    rc, out, err = _cp(L.OFF_XRDCP, "-f", *opts, src, f"{srv['our']}/{remote}",
                       timeout=90)
    assert rc == 0, (f"xrdcp upload (flag={flag}) to a missing parent on OUR "
                     f"server failed: {out}{err}")
    on_disk = os.path.join(srv["our_data"], sub, "a", "b", "file.bin")
    assert os.path.exists(on_disk), (
        f"xrdcp upload (flag={flag}): missing-parent path was not created")
    assert _read(on_disk) == payload, (
        f"xrdcp upload (flag={flag}): bytes under created path != source")


def test_upload_missing_parent_parity_stock(srv, tmp_path):
    """Differential: the SAME missing-parent upload must land on both servers
    (the stock server is the oracle for auto-mkpath)."""
    src = str(tmp_path / "mkpath_diff.src")
    payload = bytes((i * 19 + 4) & 0xff for i in range(640))
    open(src, "wb").write(payload)
    results = {}
    for url, ext, data_dir in ((srv["our"], "our", srv["our_data"]),
                               (srv["off"], "off", srv["off_data"])):
        rc, out, err = _cp(L.OFF_XRDCP, "-f", src,
                           f"{url}//mkdiff/deep/here.bin")
        landed = os.path.join(data_dir, "mkdiff", "deep", "here.bin")
        results[ext] = (rc, os.path.exists(landed) and _read(landed) == payload)
    assert results["our"] == results["off"], (
        f"missing-parent upload diverges OUR={results['our']} "
        f"STOCK={results['off']}")


# =========================================================================== #
# OPTION: --posc (Persist-On-Successful-Close) — a successful upload must       #
# persist the object exactly.                                                  #
# =========================================================================== #
def test_posc_upload_persists(srv, tmp_path):
    src = str(tmp_path / "posc.src")
    payload = bytes((i * 7 + 1) & 0xff for i in range(5000))
    open(src, "wb").write(payload)
    rc, out, err = _cp(L.OFF_XRDCP, "--posc", "-f", src,
                       f"{srv['our']}//posc_ok.bin")
    assert rc == 0, f"xrdcp --posc upload to OUR server failed: {out}{err}"
    on_disk = os.path.join(srv["our_data"], "posc_ok.bin")
    assert os.path.exists(on_disk), "xrdcp --posc: object not persisted"
    assert _read(on_disk) == payload, "xrdcp --posc: persisted bytes != source"


def test_posc_upload_parity_stock(srv, tmp_path):
    """--posc on a clean transfer must succeed on our server exactly as on the
    stock server (differential rc + landed bytes)."""
    src = str(tmp_path / "posc_diff.src")
    payload = bytes((i * 23 + 6) & 0xff for i in range(3333))
    open(src, "wb").write(payload)
    out = {}
    for url, ext, data_dir in ((srv["our"], "our", srv["our_data"]),
                               (srv["off"], "off", srv["off_data"])):
        rc, o, e = _cp(L.OFF_XRDCP, "--posc", "-f", src,
                       f"{url}//posc_diff.bin")
        landed = os.path.join(data_dir, "posc_diff.bin")
        out[ext] = (rc, os.path.exists(landed) and _read(landed) == payload)
    assert out["our"] == out["off"], (
        f"--posc upload diverges OUR={out['our']} STOCK={out['off']}")


# =========================================================================== #
# OPTION: --cksum adler32:source — the client re-checksums received bytes and  #
# compares to the server's advertised checksum. SUCCESS or a clean unsupported #
# build is fine; a checksum MISMATCH is never tolerated (it means corruption). #
# =========================================================================== #
@pytest.mark.parametrize("name", ["data.bin", "cksum.bin", "sz_4096.bin",
                                  "hello.txt"])
def test_cksum_source_verify(srv, tmp_path, name):
    dst = str(tmp_path / f"cksum_src_{name}")
    rc, out, err = _download(L.OFF_XRDCP, srv["our"], name, dst,
                             "-f", "--cksum", "adler32:source")
    blob = (out + err).lower()
    assert "mismatch" not in blob, (
        f"xrdcp --cksum adler32:source {name} <- OUR server reported a "
        f"checksum MISMATCH (read corruption): {out}{err}")
    if rc == 0:
        assert _read(dst) == _src_bytes(srv, name), (
            f"--cksum transfer of {name} reported rc=0 but bytes differ")
    else:
        # Not a mismatch, so this is an unsupported-checksum build: surface it.
        assert _unsupported(out, err) or "checksum" in blob, (
            f"--cksum {name} failed for a non-checksum reason: {out}{err}")


@pytest.mark.parametrize("name", ["data.bin", "cksum.bin"])
def test_cksum_source_diff_our_vs_stock(srv, tmp_path, name):
    """The same --cksum-verified download from OUR vs the STOCK server must
    yield identical bytes (when both succeed)."""
    a = str(tmp_path / f"cks_our_{name}")
    b = str(tmp_path / f"cks_off_{name}")
    rc_a, oa, ea = _download(L.OFF_XRDCP, srv["our"], name, a, "-f",
                             "--cksum", "adler32:source")
    rc_b, ob, eb = _download(L.OFF_XRDCP, srv["off"], name, b, "-f",
                             "--cksum", "adler32:source")
    assert "mismatch" not in (oa + ea).lower(), (
        f"--cksum {name} mismatch from OUR server: {oa}{ea}")
    if rc_a == 0 and rc_b == 0:
        assert _read(a) == _read(b), (
            f"--cksum {name}: OUR and STOCK downloads differ in bytes")


# =========================================================================== #
# OPTION: --cksum adler32:print — print a locally-computed checksum. The value #
# must equal zlib.adler32 over the source bytes.                               #
# =========================================================================== #
@pytest.mark.parametrize("name", ["data.bin", "cksum.bin", "hello.txt"])
def test_cksum_print_value(srv, tmp_path, name):
    dst = str(tmp_path / f"cksum_print_{name}")
    rc, out, err = _download(L.OFF_XRDCP, srv["our"], name, dst,
                             "-f", "--cksum", "adler32:print")
    blob = (out + err)
    if rc != 0:
        assert "mismatch" not in blob.lower(), (
            f"--cksum print {name}: checksum mismatch reported: {blob}")
        assert _unsupported(out, err) or "checksum" in blob.lower(), (
            f"--cksum adler32:print {name} failed unexpectedly: {blob}")
        return
    want = _adler_hex(_src_bytes(srv, name))
    assert want in blob.lower(), (
        f"--cksum adler32:print {name}: expected adler32 {want} not in "
        f"output: {blob!r}")
    # the downloaded bytes must still be exact
    assert _read(dst) == _src_bytes(srv, name), (
        f"--cksum print {name}: downloaded bytes != source")


# =========================================================================== #
# OPTION: -r / --recursive — DOWNLOAD a directory tree, all leaves byte-exact. #
# =========================================================================== #
def test_recursive_download_many(srv, tmp_path):
    dst = str(tmp_path / "rec_many")
    os.makedirs(dst)
    rc, out, err = _download(L.OFF_XRDCP, srv["our"], "many", dst, "-r", "-f",
                             timeout=120)
    assert rc == 0, f"xrdcp -r /many <- OUR server failed: {out}{err}"
    landed = os.path.join(dst, "many")
    for i in range(12):
        fp = os.path.join(landed, f"f{i:02d}.txt")
        assert os.path.exists(fp), f"recursive /many missing f{i:02d}.txt"
        assert _read(fp) == _src_bytes(srv, os.path.join("many", f"f{i:02d}.txt")), (
            f"recursive /many: f{i:02d}.txt content mismatch")


def test_recursive_download_deep_relpath(srv, tmp_path):
    dst = str(tmp_path / "rec_deep")
    os.makedirs(dst)
    rc, out, err = _download(L.OFF_XRDCP, srv["our"], "deep", dst, "-r", "-f",
                             timeout=120)
    assert rc == 0, f"xrdcp -r /deep <- OUR server failed: {out}{err}"
    leaf = os.path.join(dst, "deep", "a", "b", "c", "leaf.txt")
    assert os.path.exists(leaf), (
        f"recursive /deep: leaf not at the right relative path: {out}{err}")
    assert _read(leaf) == _src_bytes(
        srv, os.path.join("deep", "a", "b", "c", "leaf.txt")), (
        "recursive /deep: leaf content mismatch")


def test_recursive_download_whole_tree(srv, tmp_path):
    """`-r` of the whole namespace: every known leaf must land byte-exact.

    The reference selects the export root with a "." path component
    (root://host//.); the bare root://host// form is rejected by xrdcp itself
    on BOTH servers (confirmed: same "Invalid arguments"), so we use the form
    the stock toolchain accepts.
    """
    dst = str(tmp_path / "rec_root")
    os.makedirs(dst)
    rc, out, err = _download(L.OFF_XRDCP, srv["our"], ".", dst, "-r", "-f",
                             timeout=180)
    assert rc == 0, f"xrdcp -r / (whole tree) <- OUR server failed: {out}{err}"
    # locate the copied root (xrdcp may nest under a host/dir component)
    expect_leaves = ["hello.txt", "data.bin", "cksum.bin", "empty.txt",
                     os.path.join("sub", "nested.txt"),
                     os.path.join("deep", "a", "b", "c", "leaf.txt")]
    expect_leaves += [os.path.join("many", f"f{i:02d}.txt") for i in range(12)]
    # build a set of downloaded basenames+sizes for membership + a few md5 checks
    found = {}
    for root_dir, _dirs, files in os.walk(dst):
        for fn in files:
            fp = os.path.join(root_dir, fn)
            found.setdefault(fn, []).append(fp)
    for rel in expect_leaves:
        base = os.path.basename(rel)
        assert base in found, f"whole-tree recursive copy missing {rel}"
    # md5-verify a representative subset against the source
    for rel in ["data.bin", "cksum.bin",
                os.path.join("deep", "a", "b", "c", "leaf.txt")]:
        base = os.path.basename(rel)
        want = _md5(_src_bytes(srv, rel))
        got = {_md5(_read(fp)) for fp in found[base]}
        assert want in got, (
            f"whole-tree recursive copy: {rel} md5 {want} not among {got}")


# =========================================================================== #
# OPTION: -r recursive UPLOAD of a local tree to the server, byte-exact.       #
# =========================================================================== #
def test_recursive_upload_tree(srv, tmp_path):
    local = str(tmp_path / "uptree")
    os.makedirs(local)
    files = _make_local_tree(local)
    remote_dir = "rec_up"
    # Recursive upload requires a directory target; a trailing slash tells xrdcp
    # the destination is a directory (same requirement against the stock server).
    rc, out, err = _cp(L.OFF_XRDCP, "-r", "-f", local,
                       f"{srv['our']}//{remote_dir}/", timeout=120)
    assert rc == 0, f"xrdcp -r upload to OUR server failed: {out}{err}"
    # xrdcp places the source dir's basename under the destination
    landed_root = os.path.join(srv["our_data"], remote_dir, os.path.basename(local))
    for rel, data in files.items():
        fp = os.path.join(landed_root, rel)
        assert os.path.exists(fp), f"recursive upload missing {rel} (at {fp})"
        assert _read(fp) == data, f"recursive upload {rel}: bytes != source"


# =========================================================================== #
# OPTION: -S / --streams N — multi-stream download. The byte payload must be   #
# exact regardless of stream count. If the build rejects the option, assert it #
# did NOT corrupt data (any bytes produced are exact) and report it.           #
# =========================================================================== #
@pytest.mark.parametrize("flag", ["-S", "--streams"])
@pytest.mark.parametrize("n", [2, 4])
def test_multistream_download(srv, tmp_path, flag, n):
    name = "big1m.bin"
    dst = str(tmp_path / f"ms_{flag.strip('-')}_{n}.bin")
    rc, out, err = _download(L.OFF_XRDCP, srv["our"], name, dst, "-f",
                             flag, str(n), timeout=180)
    want = _src_bytes(srv, name)
    if rc == 0:
        assert _read(dst) == want, (
            f"multi-stream {flag} {n} {name}: byte mismatch (corruption)")
    else:
        # Option not honoured by this build: never tolerate corruption.
        if os.path.exists(dst) and os.path.getsize(dst) > 0:
            assert _read(dst) == want, (
                f"multi-stream {flag} {n}: nonzero rc AND wrong bytes "
                f"= data corruption: {out}{err}")
        assert _unsupported(out, err) or "stream" in (out + err).lower(), (
            f"multi-stream {flag} {n} failed for a non-stream reason: {out}{err}")


def test_multistream_diff_our_vs_stock(srv, tmp_path):
    """Same -S 4 download from OUR vs STOCK server: when both succeed, bytes
    must be identical."""
    a = str(tmp_path / "ms_our.bin")
    b = str(tmp_path / "ms_off.bin")
    rc_a, oa, ea = _download(L.OFF_XRDCP, srv["our"], "big1m.bin", a, "-f",
                             "-S", "4", timeout=180)
    rc_b, ob, eb = _download(L.OFF_XRDCP, srv["off"], "big1m.bin", b, "-f",
                             "-S", "4", timeout=180)
    if rc_a == 0 and rc_b == 0:
        assert _read(a) == _read(b), (
            "multi-stream -S 4: OUR and STOCK downloads differ in bytes")


# =========================================================================== #
# OPTION: download to stdout ("-").                                            #
# =========================================================================== #
def test_download_to_stdout(srv):
    rc, out, err = _cp(L.OFF_XRDCP, "-f", f"{srv['our']}//hello.txt", "-")
    assert rc == 0, f"xrdcp -> stdout from OUR server failed: {err}"
    assert "hello world" in out, f"stdout payload wrong: {out!r}"


def test_download_to_stdout_binary_exact(srv):
    """A binary file delivered to stdout must be byte-exact (capture raw)."""
    r = subprocess.run([L.OFF_XRDCP, "-f", f"{srv['our']}//sz_4096.bin", "-"],
                       capture_output=True, timeout=90)
    assert r.returncode == 0, f"xrdcp binary -> stdout failed: {r.stderr!r}"
    assert r.stdout == _src_bytes(srv, "sz_4096.bin"), (
        "xrdcp binary -> stdout: byte mismatch vs source")


# =========================================================================== #
# OPTION: upload from stdin ("-" source). xrdcp DISALLOWS stdin as a source    #
# (XrdCpConfig.cc: "Using stdin as a source is disallowed."). Pin that our     #
# server's behaviour matches the stock server's for this input.               #
# =========================================================================== #
def test_upload_from_stdin_parity(srv):
    payload = b"piped-in-content\n"
    res = {}
    for url, ext in ((srv["our"], "our"), (srv["off"], "off")):
        r = subprocess.run([L.OFF_XRDCP, "-f", "-", f"{url}//stdin_up.bin"],
                           input=payload, capture_output=True, timeout=90)
        res[ext] = r.returncode
    # xrdcp rejects stdin sources outright; both servers see the same outcome.
    assert (res["our"] == 0) == (res["off"] == 0), (
        f"stdin-source upload diverges: OUR rc={res['our']} STOCK rc={res['off']}")


# =========================================================================== #
# Empty file — 0-byte up/download must succeed and produce a 0-byte object.    #
# =========================================================================== #
def test_empty_file_download(srv, tmp_path):
    dst = str(tmp_path / "empty_dl.txt")
    rc, out, err = _download(L.OFF_XRDCP, srv["our"], "empty.txt", dst, "-f")
    assert rc == 0, f"xrdcp empty.txt download <- OUR server failed: {out}{err}"
    assert os.path.getsize(dst) == 0, (
        f"empty download produced {os.path.getsize(dst)} bytes, want 0")


def test_empty_file_upload(srv, tmp_path):
    src = str(tmp_path / "empty_up.src")
    open(src, "wb").close()
    rc, out, err = _cp(L.OFF_XRDCP, "-f", src, f"{srv['our']}//empty_up.bin")
    assert rc == 0, f"xrdcp empty upload to OUR server failed: {out}{err}"
    on_disk = os.path.join(srv["our_data"], "empty_up.bin")
    assert os.path.exists(on_disk) and os.path.getsize(on_disk) == 0, (
        "empty upload did not land as a 0-byte object")


# =========================================================================== #
# Round-trip — 1 MiB upload then download; md5 stable across the round trip.   #
# =========================================================================== #
def test_big_roundtrip_md5_stable(srv, tmp_path):
    big = bytes((i * 2654435761) & 0xff for i in range(1024 * 1024))
    src = str(tmp_path / "rt_big.src")
    open(src, "wb").write(big)
    up_md5 = _md5(big)
    rc, o, e = _cp(L.OFF_XRDCP, "-f", src, f"{srv['our']}//rt_big.bin",
                   timeout=180)
    assert rc == 0, f"round-trip upload to OUR server failed: {o}{e}"
    dl = str(tmp_path / "rt_big.dl")
    rc, o, e = _download(L.OFF_XRDCP, srv["our"], "rt_big.bin", dl, "-f",
                         timeout=180)
    assert rc == 0, f"round-trip download from OUR server failed: {o}{e}"
    assert _md5(_read(dl)) == up_md5, (
        "1 MiB round-trip md5 changed across upload+download")


# =========================================================================== #
# OPTION: --retry N on a healthy transfer — still rc==0 and byte-exact.        #
# =========================================================================== #
@pytest.mark.parametrize("n", ["1", "3"])
def test_retry_on_good_transfer(srv, tmp_path, n):
    dst = str(tmp_path / f"retry_{n}.bin")
    rc, out, err = _download(L.OFF_XRDCP, srv["our"], "data.bin", dst, "-f",
                             "--retry", n)
    if rc != 0 and _unsupported(out, err):
        pytest.skip(f"--retry unsupported by this xrdcp build: {err.strip()}")
    assert rc == 0, f"xrdcp --retry {n} <- OUR server failed: {out}{err}"
    assert _read(dst) == _src_bytes(srv, "data.bin"), (
        f"xrdcp --retry {n}: byte mismatch")


# =========================================================================== #
# DIFFERENTIAL — same flags, same file, OUR vs STOCK server -> identical bytes.#
# =========================================================================== #
@pytest.mark.parametrize("name,flags", [
    ("data.bin", ["-f"]),
    ("sz_65536.bin", ["-f", "-N"]),
    ("cksum.bin", ["-f", "-s"]),
    ("hello.txt", ["-f"]),
    ("big1m.bin", ["-f"]),
    ("empty.txt", ["-f"]),
    ("sz_4097.bin", ["-f", "--nopbar"]),
])
def test_diff_download_same_bytes(srv, tmp_path, name, flags):
    a = str(tmp_path / f"diff_our_{name}")
    b = str(tmp_path / f"diff_off_{name}")
    t = _timeout_for(name)
    rc_a, oa, ea = _download(L.OFF_XRDCP, srv["our"], name, a, *flags, timeout=t)
    rc_b, ob, eb = _download(L.OFF_XRDCP, srv["off"], name, b, *flags, timeout=t)
    assert rc_a == 0, f"download {name} {flags} from OUR server failed: {oa}{ea}"
    assert rc_b == 0, f"download {name} {flags} from STOCK server failed: {ob}{eb}"
    assert _read(a) == _read(b), (
        f"xrdcp {flags} got different bytes for {name} from the two servers")


# =========================================================================== #
# Q2 — OUR xrdcp client against the STOCK server: option breadth + integrity.  #
# A divergence here is a BUG IN OUR CLIENT; the stock server is the oracle.    #
# =========================================================================== #
@pytest.mark.parametrize("name", ["data.bin", "sz_65536.bin", "hello.txt",
                                  "big1m.bin"])
def test_q2_our_client_download(srv, tmp_path, name):
    if not os.path.exists(L.OUR_XRDCP):
        pytest.skip("our xrdcp not built")
    dst = str(tmp_path / f"q2dl_{name}")
    rc, out, err = _download(L.OUR_XRDCP, srv["off"], name, dst, "-f",
                             timeout=_timeout_for(name))
    assert rc == 0, f"OUR xrdcp {name} <- stock server failed: {out}{err}"
    assert _read(dst) == _src_bytes(srv, name), (
        f"OUR xrdcp download {name}: byte mismatch vs stock source")


@pytest.mark.parametrize("mode", ["-N", "-s"])
def test_q2_our_client_output_modes(srv, tmp_path, mode):
    if not os.path.exists(L.OUR_XRDCP):
        pytest.skip("our xrdcp not built")
    dst = str(tmp_path / f"q2mode_{mode.strip('-')}.bin")
    rc, out, err = _download(L.OUR_XRDCP, srv["off"], "data.bin", dst, mode, "-f")
    if rc != 0 and _unsupported(out, err):
        pytest.skip(f"OUR xrdcp lacks {mode}: {err.strip()}")
    assert rc == 0, f"OUR xrdcp {mode} <- stock server failed: {out}{err}"
    assert _read(dst) == _src_bytes(srv, "data.bin"), (
        f"OUR xrdcp {mode}: output-mode flag altered the bytes")


@pytest.mark.parametrize("size", [0, 1, 4096, 65537])
def test_q2_our_client_upload(srv, tmp_path, size):
    if not os.path.exists(L.OUR_XRDCP):
        pytest.skip("our xrdcp not built")
    payload = bytes((i * 31 + size) & 0xff for i in range(size))
    src = str(tmp_path / f"q2up_{size}.src")
    open(src, "wb").write(payload)
    remote = f"/q2up_{size}.bin"
    rc, out, err = _cp(L.OUR_XRDCP, "-f", src, f"{srv['off']}/{remote}",
                       timeout=120)
    assert rc == 0, f"OUR xrdcp upload size={size} -> stock failed: {out}{err}"
    on_disk = os.path.join(srv["off_data"], remote.lstrip("/"))
    assert os.path.exists(on_disk), f"OUR upload size={size} did not land on stock"
    assert _read(on_disk) == payload, (
        f"OUR xrdcp upload size={size}: byte mismatch on stock disk")


def test_q2_our_client_recursive_download(srv, tmp_path):
    if not os.path.exists(L.OUR_XRDCP):
        pytest.skip("our xrdcp not built")
    dst = str(tmp_path / "q2_rec_many")
    os.makedirs(dst)
    rc, out, err = _download(L.OUR_XRDCP, srv["off"], "many", dst, "-r", "-f",
                             timeout=120)
    if rc != 0 and _unsupported(out, err):
        pytest.skip(f"OUR xrdcp lacks recursive copy: {err.strip()}")
    assert rc == 0, f"OUR xrdcp -r /many <- stock server failed: {out}{err}"
    # find every f??.txt that landed, anywhere under dst, and verify it
    found = {}
    for root_dir, _d, files in os.walk(dst):
        for fn in files:
            found[fn] = os.path.join(root_dir, fn)
    for i in range(12):
        fn = f"f{i:02d}.txt"
        assert fn in found, f"OUR recursive /many missing {fn}: {out}{err}"
        assert _read(found[fn]) == _src_bytes(
            srv, os.path.join("many", fn)), (
            f"OUR recursive /many: {fn} content mismatch")


def test_q2_our_client_stdout(srv):
    if not os.path.exists(L.OUR_XRDCP):
        pytest.skip("our xrdcp not built")
    rc, out, err = _cp(L.OUR_XRDCP, "-f", f"{srv['off']}//hello.txt", "-")
    if rc != 0 and _unsupported(out, err):
        pytest.skip(f"OUR xrdcp lacks stdout sink: {err.strip()}")
    assert rc == 0, f"OUR xrdcp -> stdout from stock server failed: {err}"
    assert "hello world" in out, f"OUR stdout payload wrong: {out!r}"


# =========================================================================== #
# Oracle — stock client against stock server (proves the tooling is sound; a   #
# failure here is environmental, not ours).                                    #
# =========================================================================== #
def test_oracle_stock_to_stock(srv, tmp_path):
    dst = str(tmp_path / "oracle.bin")
    rc, out, err = _download(L.OFF_XRDCP, srv["off"], "data.bin", dst, "-f")
    assert rc == 0, f"oracle stock->stock failed (tooling broken): {out}{err}"
    assert _read(dst) == _src_bytes(srv, "data.bin")


def test_oracle_stock_recursive(srv, tmp_path):
    dst = str(tmp_path / "oracle_rec")
    os.makedirs(dst)
    rc, out, err = _download(L.OFF_XRDCP, srv["off"], "many", dst, "-r", "-f",
                             timeout=120)
    assert rc == 0, f"oracle stock recursive failed (tooling broken): {out}{err}"
    assert os.path.exists(os.path.join(dst, "many", "f00.txt"))
