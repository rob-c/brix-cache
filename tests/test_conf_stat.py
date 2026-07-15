"""Differential conformance for stat / ls / statvfs / locate.

Every probe is run with the STOCK XRootD client (xrdfs) against BOTH our
nginx-xrootd server and the stock xrootd data server, on byte-identical data
trees. The assertion pins OUR behavior to the STOCK reference: a divergence is
assumed to be a bug in our implementation.

Field semantics follow XrdXrootdXeq.cc (StatGen / do_Stat / do_Dirlist):
  StatGen emits "id size flags mtime" -> xrdfs renders
    Path:  <path>
    Id:    <dev>:<ino>
    Size:  <bytes>
    MTime: <unix or rendered>
    Flags: <n> (<Name|Name|...>)   e.g. IsReadable, IsWritable, IsDir, ...

Harness: official_interop_lib (PYTHONPATH=tests). Self-provisioning; the whole
module skips without the stock xrootd toolchain.
"""

import os

import pytest

import official_interop_lib as L

pytestmark = [pytest.mark.timeout(180),
              pytest.mark.skipif(not L.have_official(),
                                 reason="stock xrootd/xrdfs not installed")]

OUR_PORT = L.worker_port(14002)
OFF_PORT = L.worker_port(14003)
# --------------------------------------------------------------------------- #
# Fixture — launch our + stock server on identical rich trees (skip on launch
# failure), mirroring the test_official_interop.py module-scoped style.
# --------------------------------------------------------------------------- #
@pytest.fixture(scope="module")
def srv(tmp_path_factory):
    base = str(tmp_path_factory.mktemp("confstat"))
    try:
        procs, ctx = L.start_pair(base, our_port=OUR_PORT, off_port=OFF_PORT)
    except RuntimeError as e:
        pytest.skip(f"server pair launch failed: {e}")
    yield ctx
    L.stop_pair(procs)


# --------------------------------------------------------------------------- #
# Runners (stock xrdfs is the probe; our client only for symmetry helpers)
# --------------------------------------------------------------------------- #
def fs(url, *args, timeout=60):
    return L.run([L.OFF_XRDFS, url, *args], timeout=timeout)


def ourfs(url, *args, timeout=60):
    return L.run([L.OUR_XRDFS, url, *args], timeout=timeout)


# --------------------------------------------------------------------------- #
# Parsers
# --------------------------------------------------------------------------- #
def _statf(out):
    """Parse stat / statvfs 'Key: value' output into a dict."""
    d = {}
    for line in out.splitlines():
        if ":" in line:
            k, _, v = line.partition(":")
            d[k.strip()] = v.strip()
    return d


def _ls_set(out):
    """Basenames of an `ls` listing, dropping our internal artifacts."""
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


def _ls_l_sizes(out):
    """Map basename -> size column from `ls -l` output.

    xrdfs -l column layout differs between builds/servers, e.g.
      stock: -rw-r--r-- owner group   4096 2026-06-23 21:58:49 /data.bin
      ours:  -r-- 2026-06-23 21:58:49         4096 /data.bin
    The size is the last bare all-digit token (date tokens carry '-'/':'),
    and the path is the final token. Parse robustly across both layouts.
    """
    sizes = {}
    for line in out.splitlines():
        toks = line.split()
        if len(toks) < 2:
            continue
        path = toks[-1]
        size = None
        for t in toks[:-1]:
            if t.isdigit():
                size = int(t)
        if size is None:
            continue
        sizes[os.path.basename(path.rstrip("/"))] = size
    return sizes


def _stat_both(srv, path):
    o = _statf(fs(srv["our"], "stat", path)[1])
    f = _statf(fs(srv["off"], "stat", path)[1])
    return o, f


# =========================================================================== #
# stat size — exact byte count, our == stock == expected (heavily parametrized)
# =========================================================================== #
@pytest.mark.parametrize("path,size", [
    ("/sz_1.bin", 1),
    ("/sz_255.bin", 255),
    ("/sz_4095.bin", 4095),
    ("/sz_4096.bin", 4096),
    ("/sz_4097.bin", 4097),
    ("/sz_8192.bin", 8192),
    ("/sz_65536.bin", 65536),
    ("/empty.txt", 0),
    ("/data.bin", 4096),
    ("/big1m.bin", 1048576),
    ("/cksum.bin", 10000),
    ("/hello.txt", 12),
])
def test_stat_size_matches(srv, path, size):
    o, f = _stat_both(srv, path)
    assert o.get("Size") == str(size), \
        f"our stat {path} Size={o.get('Size')!r}, expected {size}"
    assert f.get("Size") == str(size), \
        f"stock stat {path} Size={f.get('Size')!r}, expected {size}"
    assert o.get("Size") == f.get("Size"), \
        f"Size divergence {path}: ours={o.get('Size')!r} stock={f.get('Size')!r}"


# =========================================================================== #
# stat IsDir — directories carry the IsDir flag on both servers
# =========================================================================== #
@pytest.mark.parametrize("path", ["/sub", "/empty_dir", "/deep/a/b/c",
                                  "/deep", "/many"])
def test_stat_isdir_flag(srv, path):
    o, f = _stat_both(srv, path)
    assert "IsDir" in o.get("Flags", ""), \
        f"our stat {path} missing IsDir: Flags={o.get('Flags')!r}"
    assert "IsDir" in f.get("Flags", ""), \
        f"stock stat {path} missing IsDir: Flags={f.get('Flags')!r}"


# =========================================================================== #
# stat regular file — NOT a directory on either server
# =========================================================================== #
@pytest.mark.parametrize("path", ["/hello.txt", "/data.bin", "/sz_4096.bin"])
def test_stat_regular_not_isdir(srv, path):
    o, f = _stat_both(srv, path)
    assert "IsDir" not in o.get("Flags", ""), \
        f"our stat {path} wrongly flags IsDir: {o.get('Flags')!r}"
    assert "IsDir" not in f.get("Flags", ""), \
        f"stock stat {path} wrongly flags IsDir: {f.get('Flags')!r}"


# =========================================================================== #
# stat IsReadable — readable file carries IsReadable on both
# =========================================================================== #
def test_stat_isreadable(srv):
    o, f = _stat_both(srv, "/hello.txt")
    assert "IsReadable" in o.get("Flags", ""), \
        f"our stat missing IsReadable: {o.get('Flags')!r}"
    assert "IsReadable" in f.get("Flags", ""), \
        f"stock stat missing IsReadable: {f.get('Flags')!r}"


# =========================================================================== #
# stat Flags string — full rendered Flags field matches stock exactly
# =========================================================================== #
@pytest.mark.parametrize("path", ["/hello.txt", "/data.bin", "/sub"])
def test_stat_flags_string_matches(srv, path):
    o, f = _stat_both(srv, path)
    assert o.get("Flags") == f.get("Flags"), \
        f"Flags divergence {path}: ours={o.get('Flags')!r} stock={f.get('Flags')!r}"


# =========================================================================== #
# stat field set — our stat emits the same key set as the stock reference
# =========================================================================== #
def test_stat_field_keys_match(srv):
    o, f = _stat_both(srv, "/hello.txt")
    need = {"Path", "Id", "Size", "Flags"}
    assert need <= set(o), f"our stat missing keys {need - set(o)} (stock has {set(f)})"
    assert need <= set(f), f"stock stat missing keys {need - set(f)}"


# =========================================================================== #
# stat MTime — present and numeric-ish on both servers
# =========================================================================== #
@pytest.mark.parametrize("path", ["/hello.txt", "/data.bin", "/sub"])
def test_stat_mtime_present(srv, path):
    o, f = _stat_both(srv, path)
    om = o.get("MTime", "")
    fm = f.get("MTime", "")
    assert om, f"our stat {path} missing MTime: {o}"
    assert fm, f"stock stat {path} missing MTime: {f}"
    # MTime renders as a date/time string or unix seconds; require it to contain
    # at least one digit on both (xrdfs always renders a timestamp).
    assert any(c.isdigit() for c in om), f"our MTime not numeric-ish: {om!r}"
    assert any(c.isdigit() for c in fm), f"stock MTime not numeric-ish: {fm!r}"


# =========================================================================== #
# stat nonexistent — both error (rc != 0), same coarse error category
# =========================================================================== #
@pytest.mark.parametrize("path", ["/does_not_exist.bin",
                                  "/sub/missing.txt",
                                  "/no_such_dir/x"])
def test_stat_nonexistent_errors_match(srv, path):
    orc, oout, oerr = fs(srv["our"], "stat", path)
    frc, fout, ferr = fs(srv["off"], "stat", path)
    assert orc != 0, f"our stat {path} unexpectedly succeeded: {oout}"
    assert frc != 0, f"stock stat {path} unexpectedly succeeded: {fout}"
    oc = L.err_code(oerr + oout)
    fc = L.err_code(ferr + fout)
    assert oc == fc, f"error category divergence {path}: ours={oc!r} stock={fc!r}"


# =========================================================================== #
# ls — basename set matches the stock reference exactly (filter our artifacts)
# =========================================================================== #
@pytest.mark.parametrize("path", ["/sub", "/empty_dir", "/many", "/deep",
                                  "/deep/a/b/c"])
def test_ls_basename_set_matches(srv, path):
    orc, oout, _ = fs(srv["our"], "ls", path)
    frc, fout, _ = fs(srv["off"], "ls", path)
    assert orc == 0, f"our ls {path} failed"
    assert frc == 0, f"stock ls {path} failed"
    assert _ls_set(oout) == _ls_set(fout), \
        f"ls {path} divergence: ours={_ls_set(oout)} stock={_ls_set(fout)}"


# =========================================================================== #
# ls root — the stable baseline tree is a subset on both, no leaked artifacts
# =========================================================================== #
def test_ls_root_matches(srv):
    # Full our-vs-stock set equality runs against a per-worker isolated dir: the
    # shared export '/' is polluted by concurrent xdist workers under -n8.
    lroot = L.ensure_listing_root(srv)
    our_l = _ls_set(fs(srv["our"], "ls", lroot)[1])
    off_l = _ls_set(fs(srv["off"], "ls", lroot)[1])
    assert our_l == off_l, f"ls {lroot} divergence: ours={our_l} stock={off_l}"
    assert L.LISTING_ROOT_ENTRIES <= our_l, \
        f"ls {lroot}: missing {L.LISTING_ROOT_ENTRIES - our_l}"
    # The artifact-leak check stays on the REAL root — pollution-immune, since
    # only our server could ever surface a .nginx-xrootd name (no worker seeds
    # one), and it is the real namespace we must prove clean.
    our_root = _ls_set(fs(srv["our"], "ls", "/")[1])
    assert not any(n.startswith(".nginx-xrootd") for n in our_root), \
        f"our server leaks an internal artifact into the namespace: {our_root}"


# =========================================================================== #
# ls /many — exactly 12 entries, identical set on both
# =========================================================================== #
def test_ls_many_twelve_entries(srv):
    our = _ls_set(fs(srv["our"], "ls", "/many")[1])
    off = _ls_set(fs(srv["off"], "ls", "/many")[1])
    expected = {f"f{i:02d}.txt" for i in range(12)}
    assert our == expected, f"our /many = {our}, expected {expected}"
    assert off == expected, f"stock /many = {off}, expected {expected}"


# =========================================================================== #
# ls /empty_dir — empty listing on both servers
# =========================================================================== #
def test_ls_empty_dir(srv):
    orc, oout, _ = fs(srv["our"], "ls", "/empty_dir")
    frc, fout, _ = fs(srv["off"], "ls", "/empty_dir")
    assert orc == 0 and frc == 0, "ls /empty_dir should succeed on both"
    assert _ls_set(oout) == set(), f"our /empty_dir not empty: {_ls_set(oout)}"
    assert _ls_set(fout) == set(), f"stock /empty_dir not empty: {_ls_set(fout)}"


# =========================================================================== #
# ls -l — size column per known file matches stock
# =========================================================================== #
@pytest.mark.parametrize("name,size", [
    ("data.bin", 4096),
    ("hello.txt", 12),
    ("empty.txt", 0),
    ("cksum.bin", 10000),
    ("big1m.bin", 1048576),
])
def test_ls_l_size_column_matches(srv, name, size):
    o = _ls_l_sizes(fs(srv["our"], "ls", "-l", "/")[1])
    f = _ls_l_sizes(fs(srv["off"], "ls", "-l", "/")[1])
    assert o.get(name) == size, f"our ls -l size for {name}={o.get(name)}, want {size}"
    assert f.get(name) == size, f"stock ls -l size for {name}={f.get(name)}, want {size}"
    assert o.get(name) == f.get(name), \
        f"ls -l size divergence for {name}: ours={o.get(name)} stock={f.get(name)}"


# =========================================================================== #
# ls -R — full leaf set appears on both servers
# =========================================================================== #
def test_ls_recursive_full_leaf_set(srv):
    orc, oout, _ = fs(srv["our"], "ls", "-R", "/")
    frc, fout, _ = fs(srv["off"], "ls", "-R", "/")
    assert orc == 0 and frc == 0, "ls -R should succeed on both"
    leaves = {"hello.txt", "nested.txt", "leaf.txt", "empty.txt", "data.bin",
              "cksum.bin", "big1m.bin", "with space.txt"}
    leaves |= {f"f{i:02d}.txt" for i in range(12)}
    leaves |= {f"sz_{n}.bin" for n in (1, 255, 4095, 4096, 4097, 8192, 65536)}
    our = _ls_set(oout)
    off = _ls_set(fout)
    assert leaves <= our, f"our ls -R missing leaves: {leaves - our}"
    assert leaves <= off, f"stock ls -R missing leaves: {leaves - off}"


# =========================================================================== #
# ls — spaced filename appears intact in its parent listing on both
# =========================================================================== #
def test_ls_spaced_filename(srv):
    our = _ls_set(fs(srv["our"], "ls", "/")[1])
    off = _ls_set(fs(srv["off"], "ls", "/")[1])
    assert "with space.txt" in our, f"our ls / lost the spaced name: {our}"
    assert "with space.txt" in off, f"stock ls / lost the spaced name: {off}"


# =========================================================================== #
# ls nonexistent dir — both error, same coarse category
# =========================================================================== #
def test_ls_nonexistent_dir_errors_match(srv):
    orc, oout, oerr = fs(srv["our"], "ls", "/no_such_dir")
    frc, fout, ferr = fs(srv["off"], "ls", "/no_such_dir")
    assert orc != 0, f"our ls /no_such_dir unexpectedly succeeded: {oout}"
    assert frc != 0, f"stock ls /no_such_dir unexpectedly succeeded: {fout}"
    oc = L.err_code(oerr + oout)
    fc = L.err_code(ferr + fout)
    assert oc == fc, f"ls error category divergence: ours={oc!r} stock={fc!r}"


# =========================================================================== #
# statvfs — both yield the reference 6-field RW/staging output
# =========================================================================== #
def test_statvfs_rw_field_present(srv):
    orc, oout, _ = fs(srv["our"], "statvfs", "/")
    frc, fout, _ = fs(srv["off"], "statvfs", "/")
    assert orc == 0, f"our statvfs / failed: {oout}"
    assert frc == 0, f"stock statvfs / failed: {fout}"
    assert "Nodes with RW space" in oout, f"our statvfs not parsed: {oout!r}"
    assert "Nodes with RW space" in fout, f"stock statvfs not parsed: {fout!r}"


def test_statvfs_field_keys_match(srv):
    o = _statf(fs(srv["our"], "statvfs", "/")[1])
    f = _statf(fs(srv["off"], "statvfs", "/")[1])
    assert set(o) == set(f), \
        f"statvfs key set divergence: ours={set(o)} stock={set(f)}"


# =========================================================================== #
# locate — succeeds on both (content is host-specific, only assert success)
# =========================================================================== #
@pytest.mark.parametrize("path", ["/hello.txt", "/data.bin", "/sub"])
def test_locate_succeeds(srv, path):
    orc, oout, oerr = fs(srv["our"], "locate", path)
    frc, fout, ferr = fs(srv["off"], "locate", path)
    assert orc == 0, f"our locate {path} failed: {oout}{oerr}"
    assert frc == 0, f"stock locate {path} failed: {fout}{ferr}"
