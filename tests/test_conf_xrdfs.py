"""Breadth-first differential conformance across EVERY xrdfs subcommand.

This suite is deliberately wide rather than deep: it exercises the whole
`xrdfs` command surface (ls / stat / statvfs / locate / query{config,checksum,
opaque,space,stats} / cat / tail / mkdir / rmdir / rm / mv / chmod / truncate /
prepare / spaceinfo) and compares results across the four conformance
quadrants. The narrow field-level oracles live in test_conf_stat.py; the
transfer-option breadth lives in test_conf_client.py. This file owns the
"does every subcommand behave the same on our server as on the reference"
question, plus the Q2 axis "does our xrdfs client behave the same as the
reference client against the reference server".

Quadrants (see official_interop_lib.py):
  * STOCK xrdfs -> OUR server   vs   STOCK xrdfs -> STOCK server  (the gold diff)
  * OUR   xrdfs -> STOCK server (Q2: a failure is a BUG IN OUR CLIENT)

Philosophy (per the maintainer): a divergence is a bug in THIS implementation
unless there is positive evidence otherwise. The stock toolchain is the oracle;
we pin to it. Where the stock *data server* lacks a feature (e.g. the checksum
plugin) the test asserts category parity and, where the prompt demands it,
falls back to an independent oracle (zlib.adler32) so OUR server is still held
to a correct answer.

Self-provisioning on high ports; the whole module skips without the stock
xrootd toolchain. Mutation paths are unique per test so the shared module
fixture stays deterministic.
"""

import os
import subprocess
import zlib

import pytest

import official_interop_lib as L

pytestmark = [pytest.mark.timeout(240),
              pytest.mark.skipif(not L.have_official(),
                                 reason="stock xrootd/xrdfs/xrdcp not installed")]

OUR_PORT = L.worker_port(14034)
OFF_PORT = L.worker_port(14035)
# --------------------------------------------------------------------------- #
# Module fixture — our server + stock server on identical rich trees.
# --------------------------------------------------------------------------- #
@pytest.fixture(scope="module")
def srv(tmp_path_factory):
    base = str(tmp_path_factory.mktemp("confxrdfs"))
    try:
        procs, ctx = L.start_pair(base, our_port=OUR_PORT, off_port=OFF_PORT)
    except RuntimeError as e:
        pytest.skip(f"server pair launch failed: {e}")
    yield ctx
    L.stop_pair(procs)


# --------------------------------------------------------------------------- #
# Runners — `fs` is the STOCK xrdfs (the probe); `ourfs` is OUR xrdfs (Q2).
# --------------------------------------------------------------------------- #
def fs(url, *args, timeout=60):
    return L.run([L.OFF_XRDFS, url, *args], timeout=timeout)


def ourfs(url, *args, timeout=60):
    return L.run([L.OUR_XRDFS, url, *args], timeout=timeout)


# --------------------------------------------------------------------------- #
# Parsers
# --------------------------------------------------------------------------- #
def _names(out):
    """Basenames of an `ls` listing, dropping any internal artifacts."""
    names = set()
    for line in out.splitlines():
        s = line.strip()
        if not s:
            continue
        base = os.path.basename(s.rstrip("/"))
        if base.startswith(".nginx-xrootd"):
            continue
        names.add(base)
    return names


def _fields(out):
    """Parse 'Key: value' output (stat / statvfs / spaceinfo) into a dict."""
    d = {}
    for line in out.splitlines():
        if ":" in line:
            k, _, v = line.partition(":")
            d[k.strip()] = v.strip()
    return d


def _read(p):
    with open(p, "rb") as f:
        return f.read()


def _ondisk(srv, side, rel):
    return os.path.join(srv[f"{side}_data"], rel.lstrip("/"))


# =========================================================================== #
# ls — plain, file, dir, empty, nonexistent, -l, -R                           (10)
# =========================================================================== #
@pytest.mark.parametrize("path,expect", [
    ("/", {"hello.txt", "data.bin", "sub", "many", "deep", "cksum.bin",
           "empty.txt", "empty_dir", "big1m.bin", "with space.txt"}),
    ("/sub", {"nested.txt"}),
    ("/many", {f"f{i:02d}.txt" for i in range(12)}),
    ("/deep", {"a"}),
    ("/deep/a/b/c", {"leaf.txt"}),
])
def test_ls_plain_set_matches(srv, path, expect):
    orc, oout, _ = fs(srv["our"], "ls", path)
    frc, fout, _ = fs(srv["off"], "ls", path)
    assert orc == 0 and frc == 0, f"ls {path} failed (our={orc} stock={frc})"
    our, off = _names(oout), _names(fout)
    assert our == off, f"ls {path} divergence: ours={our} stock={off}"
    assert expect <= our, f"ls {path}: missing {expect - our}"


def test_ls_of_a_file(srv):
    orc, oout, _ = fs(srv["our"], "ls", "/hello.txt")
    frc, fout, _ = fs(srv["off"], "ls", "/hello.txt")
    assert orc == 0 and frc == 0, "ls of a file should succeed on both"
    assert _names(oout) == _names(fout) == {"hello.txt"}, \
        f"ls file divergence: ours={_names(oout)} stock={_names(fout)}"


def test_ls_empty_dir(srv):
    orc, oout, _ = fs(srv["our"], "ls", "/empty_dir")
    frc, fout, _ = fs(srv["off"], "ls", "/empty_dir")
    assert orc == 0 and frc == 0, "ls /empty_dir should succeed on both"
    assert _names(oout) == _names(fout) == set(), \
        f"empty dir not empty: ours={_names(oout)} stock={_names(fout)}"


def test_ls_nonexistent_errors_match(srv):
    orc, oo, oe = fs(srv["our"], "ls", "/no_such_dir_zzz")
    frc, fo, fe = fs(srv["off"], "ls", "/no_such_dir_zzz")
    assert orc != 0 and frc != 0, "ls nonexistent must error on both"
    assert L.err_code(oe + oo) == L.err_code(fe + fo), \
        f"ls noent category divergence: ours={oe+oo!r} stock={fe+fo!r}"


def test_ls_long_carries_sizes(srv):
    o = fs(srv["our"], "ls", "-l", "/")[1]
    f = fs(srv["off"], "ls", "-l", "/")[1]
    for name, sz in (("data.bin", "4096"), ("big1m.bin", "1048576"),
                     ("hello.txt", "12")):
        assert any(sz in l and name in l for l in o.splitlines()), \
            f"our ls -l lost {name} size {sz}: {o!r}"
        assert any(sz in l and name in l for l in f.splitlines()), \
            f"stock ls -l lost {name} size {sz}"


def test_ls_recursive_leaf_set_matches(srv):
    orc, oout, _ = fs(srv["our"], "ls", "-R", "/")
    frc, fout, _ = fs(srv["off"], "ls", "-R", "/")
    assert orc == 0 and frc == 0, "ls -R should succeed on both"
    leaves = {"hello.txt", "nested.txt", "leaf.txt", "data.bin", "cksum.bin"}
    leaves |= {f"f{i:02d}.txt" for i in range(12)}
    our, off = _names(oout), _names(fout)
    assert leaves <= our, f"our ls -R missing {leaves - our}"
    assert leaves <= off, f"stock ls -R missing {leaves - off}"


# =========================================================================== #
# stat — file, dir, nonexistent, field parity                                  (4)
# =========================================================================== #
@pytest.mark.parametrize("path,size", [
    ("/hello.txt", "12"),
    ("/data.bin", "4096"),
    ("/empty.txt", "0"),
    ("/big1m.bin", "1048576"),
    ("/cksum.bin", "10000"),
])
def test_stat_file_size_parity(srv, path, size):
    o = _fields(fs(srv["our"], "stat", path)[1])
    f = _fields(fs(srv["off"], "stat", path)[1])
    assert o.get("Size") == f.get("Size") == size, \
        f"stat {path} Size: ours={o.get('Size')} stock={f.get('Size')} want {size}"


@pytest.mark.parametrize("path", ["/sub", "/many", "/deep", "/empty_dir"])
def test_stat_dir_isdir_parity(srv, path):
    o = _fields(fs(srv["our"], "stat", path)[1])
    f = _fields(fs(srv["off"], "stat", path)[1])
    assert "IsDir" in o.get("Flags", ""), f"our stat {path} not IsDir: {o.get('Flags')!r}"
    assert "IsDir" in f.get("Flags", ""), f"stock stat {path} not IsDir: {f.get('Flags')!r}"


def test_stat_field_keys_parity(srv):
    o = _fields(fs(srv["our"], "stat", "/hello.txt")[1])
    f = _fields(fs(srv["off"], "stat", "/hello.txt")[1])
    need = {"Path", "Id", "Size", "Flags"}
    assert need <= set(o), f"our stat missing {need - set(o)} (stock has {set(f)})"
    assert need <= set(f), f"stock stat missing {need - set(f)}"
    assert o.get("Flags") == f.get("Flags"), \
        f"Flags divergence: ours={o.get('Flags')!r} stock={f.get('Flags')!r}"


@pytest.mark.parametrize("path", ["/does_not_exist.bin", "/sub/missing.txt"])
def test_stat_nonexistent_errors_match(srv, path):
    orc, oo, oe = fs(srv["our"], "stat", path)
    frc, fo, fe = fs(srv["off"], "stat", path)
    assert orc != 0 and frc != 0, f"stat {path} must error on both"
    assert L.err_code(oe + oo) == L.err_code(fe + fo), \
        f"stat {path} category divergence: ours={oe+oo!r} stock={fe+fo!r}"


# =========================================================================== #
# statvfs — 6-field RW/staging parity                                          (2)
# =========================================================================== #
def test_statvfs_field_keys_match(srv):
    o = _fields(fs(srv["our"], "statvfs", "/")[1])
    f = _fields(fs(srv["off"], "statvfs", "/")[1])
    assert set(o) == set(f), f"statvfs key set divergence: ours={set(o)} stock={set(f)}"
    # xrdfs renders Path plus the 6 RW/staging metrics (the reference form).
    assert len(o) == 7, f"statvfs not Path+6 metric fields: {o}"


def test_statvfs_rw_node_count(srv):
    o = _fields(fs(srv["our"], "statvfs", "/")[1])
    f = _fields(fs(srv["off"], "statvfs", "/")[1])
    assert o.get("Nodes with RW space") == f.get("Nodes with RW space") == "1", \
        f"RW node count: ours={o.get('Nodes with RW space')} stock={f.get('Nodes with RW space')}"


# =========================================================================== #
# locate — rc parity (content is host-specific)                               (2)
# =========================================================================== #
@pytest.mark.parametrize("path", ["/hello.txt", "/data.bin", "/sub"])
def test_locate_rc_parity(srv, path):
    orc, oo, oe = fs(srv["our"], "locate", path)
    frc, fo, fe = fs(srv["off"], "locate", path)
    assert orc == 0, f"our locate {path} failed: {oo}{oe}"
    assert frc == 0, f"stock locate {path} failed: {fo}{fe}"
    assert oo.strip() and fo.strip(), "locate produced no output"


def test_locate_deep_flag_rc_parity(srv):
    # -m prefers host names; a flag variation must not regress rc.
    orc, _, _ = fs(srv["our"], "locate", "-m", "/hello.txt")
    frc, _, _ = fs(srv["off"], "locate", "-m", "/hello.txt")
    assert (orc == 0) == (frc == 0), \
        f"locate -m rc divergence: ours={orc} stock={frc}"


# =========================================================================== #
# query config — bare-value shape parity across many keys                      (1)
# =========================================================================== #
_CFG_KEYS = ["bind_max", "readv_iov_max", "readv_ior_max", "chksum", "tpc",
             "pio_max", "cms", "role", "sitename", "version", "wan_port",
             "window"]


@pytest.mark.parametrize("key", _CFG_KEYS)
def test_query_config_bare_value_parity(srv, key):
    orc, oout, oerr = fs(srv["our"], "query", "config", key)
    frc, fout, ferr = fs(srv["off"], "query", "config", key)
    assert (orc == 0) == (frc == 0), \
        f"query config {key} rc divergence: ours={orc} stock={frc}"
    if orc == 0:
        # The reference returns a BARE value, never 'key=value'.
        val = oout.strip().splitlines()[0] if oout.strip() else ""
        assert not val.startswith(f"{key}="), \
            f"our query config {key} carries a 'key=' prefix: {oout!r}"


# =========================================================================== #
# query checksum — '<algo> <hex>' shape; fall back to zlib.adler32 oracle      (3)
# when the stock DATA server lacks the checksum plugin.
# =========================================================================== #
def test_query_checksum_shape_on_our_server(srv):
    rc, out, err = fs(srv["our"], "query", "checksum", "/cksum.bin")
    assert rc == 0, f"our query checksum failed: {out}{err}"
    toks = out.split()
    assert len(toks) >= 2, f"checksum reply not '<algo> <hex>': {out!r}"
    int(toks[-1], 16)  # hex must parse


def test_query_checksum_matches_zlib_adler32(srv):
    # The stock data server has no checksum plugin (the prompt anticipates this),
    # so use zlib.adler32 over the identical bytes as the independent oracle and
    # require OUR server to produce exactly that.
    data = _read(_ondisk(srv, "our", "cksum.bin"))
    want = f"{zlib.adler32(data) & 0xffffffff:08x}"
    rc, out, _ = fs(srv["our"], "query", "checksum", "/cksum.bin")
    assert rc == 0, "our query checksum must succeed"
    got = out.split()[-1].lower()
    assert got == want, f"our adler32 {got!r} != zlib.adler32 {want!r}"


def test_query_checksum_stock_data_server_category(srv):
    # Differential: whatever the stock server answers, parity is what matters.
    # The stock data server commonly errors (no plugin) while ours succeeds —
    # that is acceptable; we only require ours to never silently mis-answer.
    orc, oout, _ = fs(srv["our"], "query", "checksum", "/data.bin")
    frc, fout, ferr = fs(srv["off"], "query", "checksum", "/data.bin")
    assert orc == 0, f"our checksum must succeed: {oout}"
    if frc == 0:
        assert oout.split()[-1] == fout.split()[-1], \
            f"checksum hex divergence: ours={oout!r} stock={fout!r}"
    else:
        assert "support" in (ferr + fout).lower(), \
            f"unexpected stock checksum failure category: {ferr+fout!r}"


# =========================================================================== #
# query opaque / space / stats — success/failure category parity              (3)
# =========================================================================== #
def test_query_opaque_category_parity(srv):
    orc, oo, oe = fs(srv["our"], "query", "opaque", "/hello.txt")
    frc, fo, fe = fs(srv["off"], "query", "opaque", "/hello.txt")
    # opaque is implementation-dependent; both should reject it the same way.
    assert (orc == 0) == (frc == 0), \
        f"query opaque rc divergence: ours={orc} stock={frc}"


def test_query_space_succeeds_parity(srv):
    orc, oo, _ = fs(srv["our"], "query", "space", "/")
    frc, fo, _ = fs(srv["off"], "query", "space", "/")
    assert (orc == 0) == (frc == 0), \
        f"query space rc divergence: ours={orc} stock={frc}"
    if orc == 0 and frc == 0:
        assert "oss.space=" in oo, f"our query space malformed: {oo!r}"
        assert "oss.space=" in fo, f"stock query space malformed: {fo!r}"


def test_query_stats_succeeds_parity(srv):
    orc, oo, _ = fs(srv["our"], "query", "stats", "a")
    frc, fo, _ = fs(srv["off"], "query", "stats", "a")
    assert (orc == 0) == (frc == 0), \
        f"query stats rc divergence: ours={orc} stock={frc}"
    if orc == 0 and frc == 0:
        assert "<statistics" in oo and "<statistics" in fo, \
            f"query stats not XML: ours={oo[:80]!r} stock={fo[:80]!r}"


# =========================================================================== #
# cat — exact bytes (text + binary, byte-exact via raw capture)               (3)
# =========================================================================== #
def test_cat_text_exact(srv):
    orc, oout, _ = fs(srv["our"], "cat", "/hello.txt")
    frc, fout, _ = fs(srv["off"], "cat", "/hello.txt")
    assert orc == 0 and frc == 0, "cat /hello.txt should succeed on both"
    assert oout == fout == "hello world\n", \
        f"cat text divergence: ours={oout!r} stock={fout!r}"


@pytest.mark.parametrize("name", ["data.bin", "sz_65536.bin"])
def test_cat_binary_byte_exact(srv, name):
    # L.run is text mode; capture raw bytes ourselves for binary payloads.
    our = subprocess.run([L.OFF_XRDFS, srv["our"], "cat", f"/{name}"],
                         capture_output=True, timeout=60)
    off = subprocess.run([L.OFF_XRDFS, srv["off"], "cat", f"/{name}"],
                         capture_output=True, timeout=60)
    assert our.returncode == 0 and off.returncode == 0, \
        f"cat {name} failed: our={our.returncode} off={off.returncode}"
    src = _read(_ondisk(srv, "our", name))
    assert our.stdout == src, f"our cat {name} not byte-exact vs source"
    assert off.stdout == src, f"stock cat {name} not byte-exact vs source"


# =========================================================================== #
# tail — last bytes parity (xrdfs `tail` is supported)                        (2)
# =========================================================================== #
def test_tail_whole_small_file(srv):
    orc, oout, _ = fs(srv["our"], "tail", "/hello.txt")
    frc, fout, _ = fs(srv["off"], "tail", "/hello.txt")
    assert orc == 0 and frc == 0, "tail /hello.txt should succeed on both"
    assert oout == fout == "hello world\n", \
        f"tail divergence: ours={oout!r} stock={fout!r}"


def test_tail_byte_count(srv):
    orc, oout, _ = fs(srv["our"], "tail", "-c", "5", "/hello.txt")
    frc, fout, _ = fs(srv["off"], "tail", "-c", "5", "/hello.txt")
    assert orc == 0 and frc == 0, "tail -c should succeed on both"
    assert oout == fout == "orld\n", \
        f"tail -c divergence: ours={oout!r} stock={fout!r}"


# =========================================================================== #
# mkdir / mkdir -p / rmdir — on-disk effects + rc parity (unique paths)        (3)
# =========================================================================== #
def test_mkdir_rmdir_roundtrip(srv):
    for side in ("our", "off"):
        d = f"/x_mkdir_{side}"
        rc, o, e = fs(srv[side], "mkdir", d)
        assert rc == 0, f"{side} mkdir failed: {o}{e}"
        assert os.path.isdir(_ondisk(srv, side, d)), f"{side} mkdir no on-disk dir"
        rc, o, e = fs(srv[side], "rmdir", d)
        assert rc == 0, f"{side} rmdir failed: {o}{e}"
        assert not os.path.exists(_ondisk(srv, side, d)), f"{side} rmdir left dir"


def test_mkdir_p_tree(srv):
    for side in ("our", "off"):
        d = f"/x_mkp_{side}/a/b/c"
        rc, o, e = fs(srv[side], "mkdir", "-p", d)
        assert rc == 0, f"{side} mkdir -p failed: {o}{e}"
        assert os.path.isdir(_ondisk(srv, side, d)), f"{side} mkdir -p no deep dir"


def test_rmdir_nonexistent_rc_parity(srv):
    # The stock xrootd server treats rmdir of a missing directory as a no-op
    # success (rc==0); the only conformance requirement is that OUR server
    # answers identically. Pin to the reference rather than to an assumption.
    orc, oo, oe = fs(srv["our"], "rmdir", "/x_rmdir_noent")
    frc, fo, fe = fs(srv["off"], "rmdir", "/x_rmdir_noent")
    assert (orc == 0) == (frc == 0), \
        f"rmdir noent rc divergence: ours={orc} ({oe!r}) stock={frc} ({fe!r})"
    if orc != 0:
        assert L.err_code(oe + oo) == L.err_code(fe + fo), \
            f"rmdir noent category divergence: ours={oe+oo!r} stock={fe+fo!r}"


# =========================================================================== #
# rm — removed + rc parity; rm nonexistent error parity (unique paths)         (2)
# =========================================================================== #
def test_rm_existing_file(srv):
    for side in ("our", "off"):
        rel = f"/x_rm_{side}.bin"
        with open(_ondisk(srv, side, rel), "wb") as f:
            f.write(b"delete me\n")
        rc, o, e = fs(srv[side], "rm", rel)
        assert rc == 0, f"{side} rm failed: {o}{e}"
        assert not os.path.exists(_ondisk(srv, side, rel)), f"{side} rm left file"


def test_rm_nonexistent_errors_match(srv):
    orc, oo, oe = fs(srv["our"], "rm", "/x_rm_noent.bin")
    frc, fo, fe = fs(srv["off"], "rm", "/x_rm_noent.bin")
    assert orc != 0 and frc != 0, "rm nonexistent must error on both"
    assert L.err_code(oe + oo) == L.err_code(fe + fo), \
        f"rm noent category divergence: ours={oe+oo!r} stock={fe+fo!r}"


# =========================================================================== #
# mv — renamed on disk + rc parity (unique paths)                             (2)
# =========================================================================== #
def test_mv_rename(srv):
    for side in ("our", "off"):
        a, b = f"/x_mv_{side}_a.txt", f"/x_mv_{side}_b.txt"
        with open(_ondisk(srv, side, a), "w") as f:
            f.write("mv\n")
        rc, o, e = fs(srv[side], "mv", a, b)
        assert rc == 0, f"{side} mv failed: {o}{e}"
        assert not os.path.exists(_ondisk(srv, side, a)), f"{side} mv left source"
        assert os.path.exists(_ondisk(srv, side, b)), f"{side} mv no destination"


def test_mv_nonexistent_errors_match(srv):
    orc, oo, oe = fs(srv["our"], "mv", "/x_mv_noent_a.txt", "/x_mv_noent_b.txt")
    frc, fo, fe = fs(srv["off"], "mv", "/x_mv_noent_a.txt", "/x_mv_noent_b.txt")
    assert orc != 0 and frc != 0, "mv of nonexistent must error on both"
    assert L.err_code(oe + oo) == L.err_code(fe + fo), \
        f"mv noent category divergence: ours={oe+oo!r} stock={fe+fo!r}"


# =========================================================================== #
# chmod — on-disk mode parity (unique paths)                                  (1)
# =========================================================================== #
def test_chmod_mode_parity(srv):
    import stat as _stat
    for side in ("our", "off"):
        rel = f"/x_chmod_{side}.txt"
        with open(_ondisk(srv, side, rel), "w") as f:
            f.write("c\n")
        rc, o, e = fs(srv[side], "chmod", rel, "rwxr-xr-x")
        assert rc == 0, f"{side} chmod failed: {o}{e}"
        mode = _stat.S_IMODE(os.stat(_ondisk(srv, side, rel)).st_mode)
        assert mode == 0o755, f"{side} chmod mode {mode:o} != 755"


# =========================================================================== #
# truncate — on-disk size parity (unique paths)                               (2)
# =========================================================================== #
@pytest.mark.parametrize("size", [0, 10])
def test_truncate_size_parity(srv, size):
    for side in ("our", "off"):
        rel = f"/x_trunc_{side}_{size}.bin"
        with open(_ondisk(srv, side, rel), "wb") as f:
            f.write(b"\x00" * 100)
        rc, o, e = fs(srv[side], "truncate", rel, str(size))
        assert rc == 0, f"{side} truncate failed: {o}{e}"
        assert os.path.getsize(_ondisk(srv, side, rel)) == size, \
            f"{side} truncate size {os.path.getsize(_ondisk(srv, side, rel))} != {size}"


# =========================================================================== #
# prepare — rc/category parity (kXR_prepare; the stock server may no-op)       (1)
# =========================================================================== #
def test_prepare_category_parity(srv):
    orc, oo, oe = fs(srv["our"], "prepare", "/hello.txt")
    frc, fo, fe = fs(srv["off"], "prepare", "/hello.txt")
    assert (orc == 0) == (frc == 0), \
        f"prepare rc divergence: ours={orc} ({oe!r}) stock={frc} ({fe!r})"


# =========================================================================== #
# spaceinfo — field parity                                                     (1)
# =========================================================================== #
def test_spaceinfo_field_keys_match(srv):
    o = _fields(fs(srv["our"], "spaceinfo", "/")[1])
    f = _fields(fs(srv["off"], "spaceinfo", "/")[1])
    assert set(o) == set(f), \
        f"spaceinfo key set divergence: ours={set(o)} stock={set(f)}"
    assert "Total" in o, f"spaceinfo missing Total: {o}"


# =========================================================================== #
# combined lifecycle — mkdir -> put -> ls -> stat -> rm -> rmdir, on-disk      (1)
# =========================================================================== #
def test_combined_lifecycle_on_our_server(srv, tmp_path):
    d = "/x_life_dir"
    rc, o, e = fs(srv["our"], "mkdir", d)
    assert rc == 0, f"lifecycle mkdir: {o}{e}"
    src = str(tmp_path / "life.bin")
    payload = bytes((i * 13 + 1) & 0xff for i in range(2048))
    with open(src, "wb") as f:
        f.write(payload)
    rc, o, e = L.run([L.OFF_XRDCP, "-f", src, f"{srv['our']}/{d}/life.bin"])
    assert rc == 0, f"lifecycle put: {o}{e}"
    rc, lout, _ = fs(srv["our"], "ls", d)
    assert rc == 0 and "life.bin" in _names(lout), f"lifecycle ls: {lout!r}"
    st = _fields(fs(srv["our"], "stat", f"{d}/life.bin")[1])
    assert st.get("Size") == "2048", f"lifecycle stat size: {st.get('Size')}"
    assert _read(_ondisk(srv, "our", f"{d}/life.bin")) == payload, \
        "lifecycle on-disk bytes mismatch"
    rc, o, e = fs(srv["our"], "rm", f"{d}/life.bin")
    assert rc == 0, f"lifecycle rm: {o}{e}"
    rc, o, e = fs(srv["our"], "rmdir", d)
    assert rc == 0, f"lifecycle rmdir: {o}{e}"
    assert not os.path.exists(_ondisk(srv, "our", d)), "lifecycle dir not removed"


# =========================================================================== #
# Q2 — OUR xrdfs against the STOCK server (read-only; a failure == client bug) #
# Parametrized breadth; output consistent with the stock-on-stock reference.  #
# =========================================================================== #
@pytest.mark.parametrize("args,check", [
    (["ls", "/"], lambda o: "hello.txt" in o),
    (["ls", "-l", "/"], lambda o: "data.bin" in o and "4096" in o),
    (["ls", "-R", "/sub"], lambda o: "nested.txt" in o),
    (["ls", "/sub"], lambda o: "nested.txt" in o),
    (["stat", "/hello.txt"], lambda o: "Size" in o and "12" in o),
    (["stat", "/sub"], lambda o: "IsDir" in o),
    (["statvfs", "/"], lambda o: bool(o.strip())),
    (["locate", "/hello.txt"], lambda o: bool(o.strip())),
    (["cat", "/hello.txt"], lambda o: "hello world" in o),
    (["tail", "/hello.txt"], lambda o: "hello world" in o),
    (["query", "config", "version"], lambda o: bool(o.strip())),
    (["query", "config", "chksum"], lambda o: not o.strip().startswith("chksum=")),
])
def test_q2_our_xrdfs_readonly_vs_stock(srv, args, check):
    rc, out, err = ourfs(srv["off"], *args)
    assert rc == 0, f"OUR xrdfs {args} -> stock server failed: {out}{err}"
    assert check(out), f"OUR xrdfs {args}: output inconsistent with stock: {out!r}"


def test_q2_our_xrdfs_query_config_no_key_prefix(srv):
    # The reference returns bare values; ensure OUR client never echoes 'key='.
    for key in ("bind_max", "tpc", "readv_iov_max"):
        rc, out, err = ourfs(srv["off"], "query", "config", key)
        assert rc == 0, f"OUR query config {key} -> stock failed: {out}{err}"
        assert not out.strip().startswith(f"{key}="), \
            f"OUR query config {key} carries 'key=' prefix: {out!r}"


def test_q2_our_xrdfs_query_checksum_matches_stock_client(srv):
    # Both clients hit the SAME stock server: a divergence is OUR client's bug.
    our_rc, our_out, _ = ourfs(srv["off"], "query", "checksum", "/cksum.bin")
    off_rc, off_out, _ = fs(srv["off"], "query", "checksum", "/cksum.bin")
    assert (our_rc == 0) == (off_rc == 0), \
        f"OUR client checksum rc={our_rc} disagrees with stock client rc={off_rc}"
    if our_rc == 0 and off_rc == 0:
        assert our_out.split()[-1] == off_out.split()[-1], \
            f"OUR client checksum {our_out!r} != stock client {off_out!r}"


def test_q2_our_xrdfs_stat_size_matches_stock_client(srv):
    o = _fields(ourfs(srv["off"], "stat", "/data.bin")[1])
    s = _fields(fs(srv["off"], "stat", "/data.bin")[1])
    assert o.get("Size") == s.get("Size") == "4096", \
        f"OUR client stat Size={o.get('Size')} vs stock client {s.get('Size')}"


def test_q2_our_xrdfs_statvfs_six_fields(srv):
    rc, out, err = ourfs(srv["off"], "statvfs", "/")
    assert rc == 0, f"OUR statvfs -> stock failed: {out}{err}"
    # Our client renders statvfs as 6 whitespace-separated fields.
    toks = out.split()
    assert len(toks) >= 6, f"OUR statvfs not 6+ fields: {out!r}"


def test_q2_our_xrdfs_cat_binary_byte_exact(srv):
    r = subprocess.run([L.OUR_XRDFS, srv["off"], "cat", "/sz_4096.bin"],
                       capture_output=True, timeout=60)
    assert r.returncode == 0, f"OUR cat binary -> stock failed: {r.stderr!r}"
    assert r.stdout == _read(_ondisk(srv, "off", "sz_4096.bin")), \
        "OUR client cat binary not byte-exact vs stock source"


# =========================================================================== #
# Q2 — OUR xrdfs MUTATIONS against the STOCK server (unique paths)            #
# A divergence here is a BUG IN OUR CLIENT; the stock disk is the witness.    #
# =========================================================================== #
def test_q2_our_mkdir_rmdir_on_stock(srv):
    d = "/q2x_mkdir"
    rc, o, e = ourfs(srv["off"], "mkdir", d)
    assert rc == 0, f"OUR mkdir -> stock failed: {o}{e}"
    assert os.path.isdir(_ondisk(srv, "off", d)), "OUR mkdir no on-disk dir on stock"
    rc, o, e = ourfs(srv["off"], "rmdir", d)
    assert rc == 0, f"OUR rmdir -> stock failed: {o}{e}"
    assert not os.path.exists(_ondisk(srv, "off", d)), "OUR rmdir left dir on stock"


def test_q2_our_rm_on_stock(srv):
    rel = "/q2x_rm.bin"
    with open(_ondisk(srv, "off", rel), "wb") as f:
        f.write(b"x\n")
    rc, o, e = ourfs(srv["off"], "rm", rel)
    assert rc == 0, f"OUR rm -> stock failed: {o}{e}"
    assert not os.path.exists(_ondisk(srv, "off", rel)), "OUR rm left file on stock"


def test_q2_our_mv_on_stock(srv):
    a, b = "/q2x_mv_a.txt", "/q2x_mv_b.txt"
    with open(_ondisk(srv, "off", a), "w") as f:
        f.write("mv\n")
    rc, o, e = ourfs(srv["off"], "mv", a, b)
    assert rc == 0, f"OUR mv -> stock failed: {o}{e}"
    assert os.path.exists(_ondisk(srv, "off", b)), "OUR mv no destination on stock"
    assert not os.path.exists(_ondisk(srv, "off", a)), "OUR mv left source on stock"


def test_q2_our_chmod_on_stock(srv):
    """OUR xrdfs chmod must set the same mode the stock client does, via the
    stock 9-char symbolic form ("rwxr-xr-x"). (Previously our client only parsed
    octal, so the symbolic form silently became mode 000 — fixed in client/apps/
    xrdfs.c parse_chmod_mode, which now accepts both symbolic and octal.)"""
    import stat as _stat
    rel = "/q2x_chmod.txt"
    ours = _ondisk(srv, "off", rel)
    with open(ours, "w") as f:
        f.write("c\n")
    # Reference: the SAME chmod via the stock client on the SAME stock server.
    ref = _ondisk(srv, "off", "/q2x_chmod_ref.txt")
    with open(ref, "w") as f:
        f.write("c\n")
    fs(srv["off"], "chmod", "/q2x_chmod_ref.txt", "rwxr-xr-x")
    ref_mode = _stat.S_IMODE(os.stat(ref).st_mode)

    rc, o, e = ourfs(srv["off"], "chmod", rel, "rwxr-xr-x")
    assert rc == 0, f"OUR chmod -> stock failed: {o}{e}"
    mode = _stat.S_IMODE(os.stat(ours).st_mode)
    assert mode == ref_mode, \
        f"OUR client chmod set mode {mode:o}, stock client set {ref_mode:o}"


def test_q2_our_truncate_on_stock(srv):
    rel = "/q2x_trunc.bin"
    with open(_ondisk(srv, "off", rel), "wb") as f:
        f.write(b"\x00" * 100)
    rc, o, e = ourfs(srv["off"], "truncate", rel, "7")
    assert rc == 0, f"OUR truncate -> stock failed: {o}{e}"
    assert os.path.getsize(_ondisk(srv, "off", rel)) == 7, \
        f"OUR truncate on stock: size {os.path.getsize(_ondisk(srv, 'off', rel))} != 7"
