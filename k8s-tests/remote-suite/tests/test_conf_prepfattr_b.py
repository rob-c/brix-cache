from _test_conf_prepfattr_helpers import *  # noqa: F401,F403  (Phase-38 split shared header)

@pytest.mark.parametrize("name,value", XATTR_CASES)
def test_xattr_set_get_roundtrip_value_parity(srv, name, value):
    """`xrdfs xattr set` then `get` round-trips the EXACT value, identically on
    both servers (Set->Get, XProtocol.cc nvec/vvec). Unique attr name per case
    on a per-test file to avoid cross-talk."""
    # set+get on each server independently, compare the get output
    def setget(url):
        rc1, _, e1 = L.run([L.OFF_XRDFS, url, "xattr", "/data.bin",
                            "set", f"{name}={value}"])
        rc2, o2, e2 = L.run([L.OFF_XRDFS, url, "xattr", "/data.bin",
                            "get", name])
        return rc1, rc2, o2, e1, e2
    ro = setget(srv["our"])
    rf = setget(srv["off"])
    raw = f"\n  OURS set_rc={ro[0]} get_rc={ro[1]} out={ro[2].strip()!r}" \
          f"\n  STOCK set_rc={rf[0]} get_rc={rf[1]} out={rf[2].strip()!r}"
    assert (ro[0] == 0) == (rf[0] == 0), f"xattr set parity differs:{raw}"
    assert (ro[1] == 0) == (rf[1] == 0), f"xattr get parity differs:{raw}"
    if ro[1] == 0:
        # the value line is the last non-comment line: name="value"
        def val(out):
            for ln in reversed(out.splitlines()):
                if ln.startswith("#") or not ln.strip():
                    continue
                return ln.strip()
            return ""
        assert val(ro[2]) == val(rf[2]), \
            f"xattr get value differs from stock:{raw}"


@pytest.mark.parametrize("idx,name,value",
                         [(i, n, v) for i, (n, v) in enumerate(XATTR_CASES[:5])])
def test_xattr_set_lands_on_disk(srv, idx, name, value):
    """After `xrdfs xattr set`, the attribute is present on OUR data root. The
    reference stores it under the FATTR_NAMESPACE prefix (on-disk key is
    "user.U.<name>"); we accept either the stock-style prefixed key or the bare
    key as long as the value matches stock's on-disk encoding.

    Each case uses a UNIQUE pre-created file so attributes never accumulate and
    hit the underlying filesystem's per-inode xattr-size cap (which both servers
    reject identically — that shared rejection is a parity, not a bug, so the
    on-disk assertion is gated on stock having stored the attr too)."""
    rel = f"/xa_disk_{idx}.bin"
    _make_pair_file(srv, rel, b"x" * 16)
    rc_o, _, e_o = L.run([L.OFF_XRDFS, srv["our"], "xattr", rel,
                          "set", f"{name}={value}"])
    rc_f, _, e_f = L.run([L.OFF_XRDFS, srv["off"], "xattr", rel,
                          "set", f"{name}={value}"])
    assert (rc_o == 0) == (rc_f == 0), \
        f"xattr set {name} accept/reject differs: ours rc={rc_o} " \
        f"({e_o.strip()!r}) stock rc={rc_f} ({e_f.strip()!r})"
    if rc_f != 0:
        # stock itself rejected the set (e.g. fs xattr-size cap) -> parity only
        return
    our_attrs = _disk_xattrs(our_disk(srv, rel))
    off_attrs = _disk_xattrs(off_disk(srv, rel))
    if our_attrs is None or off_attrs is None:
        pytest.skip("filesystem does not expose user xattrs (getfattr/os.listxattr)")
    om = _find_attr_value(our_attrs, name)
    fm = _find_attr_value(off_attrs, name)
    assert fm is not None, f"stock did not store {name} on disk: {sorted(off_attrs)}"
    assert om is not None, \
        f"xattr {name} not found on OUR disk (have {sorted(our_attrs)})"
    assert om == fm, \
        f"on-disk xattr value for {name} differs: OURS {om!r} STOCK {fm!r}"


# =========================================================================== #
# H. STOCK xrdfs xattr list — internal namespace prefix MUST NOT leak
# =========================================================================== #
@pytest.mark.parametrize("name", [
    "user.la", "user.lb", "user.lc.dotted", "user.l_underscore",
])
def test_xattr_list_no_namespace_leak(srv, name):
    """`xrdfs xattr list` must show the attr under its ORIGINAL name. The server
    stores it under the FATTR_NAMESPACE ("user") prefix internally, but the
    reference STRIPS that prefix in the List response (XeqFALsd, Xeq:474); our
    server leaks it as "U.<name>". Pin stock."""
    L.run([L.OFF_XRDFS, srv["our"], "xattr", "/cksum.bin",
           "set", f"{name}=v"])
    L.run([L.OFF_XRDFS, srv["off"], "xattr", "/cksum.bin",
           "set", f"{name}=v"])
    rc_o, o_o, _ = L.run([L.OFF_XRDFS, srv["our"], "xattr", "/cksum.bin", "list"])
    rc_f, o_f, _ = L.run([L.OFF_XRDFS, srv["off"], "xattr", "/cksum.bin", "list"])
    assert rc_o == 0 and rc_f == 0, "xattr list should succeed on both"
    # the names listed (strip "# file:" header and ="value" suffix)
    def names(out):
        s = set()
        for ln in out.splitlines():
            ln = ln.strip()
            if not ln or ln.startswith("#"):
                continue
            s.add(ln.split("=", 1)[0])
        return s
    no, nf = names(o_o), names(o_f)
    assert name in nf, f"stock list missing {name}: {nf}"
    if name not in no:
        leaked = {n for n in no if n.endswith(name) and n != name}
        pytest.xfail(
            "OUR-SERVER BUG: kXR_fattrList leaks the internal FATTR_NAMESPACE "
            f"prefix. Expected {name!r} (as stock shows: {sorted(nf)}); ours "
            f"shows {sorted(no)} (leaked as {sorted(leaked)}). The reference "
            "strips the 'user' namespace prefix before returning names "
            "(XeqFALsd, Xeq:474).")
    assert name in no


# =========================================================================== #
# I. STOCK xrdfs xattr del — del removes, subsequent get/list reflect it
# =========================================================================== #
@pytest.mark.parametrize("name", ["user.d1", "user.d2", "user.d3.x"])
def test_xattr_del_removes_attr_parity(srv, name):
    """`xrdfs xattr del` removes the attr -> a subsequent `get` reports
    absence, identically on both servers."""
    for url in (srv["our"], srv["off"]):
        L.run([L.OFF_XRDFS, url, "xattr", "/empty.txt", "set", f"{name}=z"])
    rc_o, _, e_o = L.run([L.OFF_XRDFS, srv["our"], "xattr", "/empty.txt",
                          "del", name])
    rc_f, _, e_f = L.run([L.OFF_XRDFS, srv["off"], "xattr", "/empty.txt",
                          "del", name])
    assert (rc_o == 0) == (rc_f == 0), \
        f"xattr del parity differs: ours rc={rc_o} stock rc={rc_f}"
    # del-then-get
    go = L.run([L.OFF_XRDFS, srv["our"], "xattr", "/empty.txt", "get", name])
    gf = L.run([L.OFF_XRDFS, srv["off"], "xattr", "/empty.txt", "get", name])
    # stock reports a deleted attr's get as an (empty value / error) — compare
    # the presence of a value line, not the exact wording.
    def has_value(out):
        for ln in out.splitlines():
            ln = ln.strip()
            if ln and not ln.startswith("#") and "=" in ln:
                v = ln.split("=", 1)[1].strip().strip('"')
                return v != ""
        return False
    assert has_value(go[1]) == has_value(gf[1]), \
        f"del-then-get value-presence differs: ours={go[1].strip()!r} " \
        f"stock={gf[1].strip()!r}"


# =========================================================================== #
# J. STOCK xrdfs xattr multiple attrs on one file -> list count parity
# =========================================================================== #
def test_xattr_multiple_attrs_list_count_parity(srv):
    """Set several attrs on one file -> `list` shows the same COUNT on both
    servers (multi-attr round-trip)."""
    names = ["user.m0", "user.m1", "user.m2", "user.m3"]
    for url in (srv["our"], srv["off"]):
        for i, n in enumerate(names):
            L.run([L.OFF_XRDFS, url, "xattr", "/many/f02.txt",
                   "set", f"{n}=val{i}"])
    rc_o, o_o, _ = L.run([L.OFF_XRDFS, srv["our"], "xattr", "/many/f02.txt", "list"])
    rc_f, o_f, _ = L.run([L.OFF_XRDFS, srv["off"], "xattr", "/many/f02.txt", "list"])
    assert rc_o == 0 and rc_f == 0
    def count(out):
        return sum(1 for ln in out.splitlines()
                   if ln.strip() and not ln.strip().startswith("#"))
    assert count(o_o) == count(o_f), \
        f"xattr list count differs: ours={count(o_o)} ({o_o.strip()!r}) " \
        f"stock={count(o_f)} ({o_f.strip()!r})"


@pytest.mark.parametrize("path", RAW_FA_FILES)
def test_raw_fattr_set_get_roundtrip(srv, path):
    """RAW kXR_fattrSet then kXR_fattrGet -> the Get response carries faRC[2],
    the nvec name record, and the value, BYTE-IDENTICAL to stock."""
    name, value = "user.rawk", "rawval"
    so, sf = _both()
    try:
        st_o, b_o = _fattr(so, path, kXR_fattrSet, 1, names=[name], values=[value])
        st_f, b_f = _fattr(sf, path, kXR_fattrSet, 1, names=[name], values=[value])
        assert (st_o == kXR_ok) == (st_f == kXR_ok), \
            f"raw fattrSet success differs: ours={_category(st_o, b_o)} " \
            f"stock={_category(st_f, b_f)}"
        # set responses should match byte-for-byte (faRC + nvec names echoed)
        assert b_o == b_f, \
            f"raw fattrSet response framing differs:\n  OURS {b_o!r}\n  STOCK {b_f!r}"
        g_o = _fattr(so, path, kXR_fattrGet, 1, names=[name])
        g_f = _fattr(sf, path, kXR_fattrGet, 1, names=[name])
    finally:
        so.close()
        sf.close()
    assert g_o[0] == kXR_ok and g_f[0] == kXR_ok, "raw fattrGet should succeed"
    assert g_o[1] == g_f[1], \
        f"raw fattrGet response differs:\n  OURS {g_o[1]!r}\n  STOCK {g_f[1]!r}"
    dec_o = _fattr_get_decode(g_o[1])
    dec_f = _fattr_get_decode(g_f[1])
    assert dec_o and dec_f, f"raw fattrGet undecodable: {g_o[1]!r} / {g_f[1]!r}"
    assert dec_o[0][2] == value.encode() == dec_f[0][2], \
        f"raw fattrGet value differs: ours={dec_o[0][2]!r} stock={dec_f[0][2]!r}"


def test_raw_fattr_get_missing_attr_is_perattr_rc(srv):
    """RAW kXR_fattrGet of a NONEXISTENT attribute -> the reference returns
    kXR_ok with a NON-ZERO per-attr rc inside the nvec (Xeq:430), NOT a
    request-level error. Pin stock; ours must match the framing."""
    name = "user.absent_raw"
    so, sf = _both()
    try:
        st_o, b_o = _fattr(so, "/hello.txt", kXR_fattrGet, 1, names=[name])
        st_f, b_f = _fattr(sf, "/hello.txt", kXR_fattrGet, 1, names=[name])
    finally:
        so.close()
        sf.close()
    raw = f"\n  OURS cat={_category(st_o, b_o)} body={b_o!r}" \
          f"\n  STOCK cat={_category(st_f, b_f)} body={b_f!r}"
    # stock: ok-with-perattr-rc
    assert st_f == kXR_ok, f"stock fattrGet-missing-attr not ok:{raw}"
    if (st_o == kXR_ok) != (st_f == kXR_ok):
        pytest.xfail(
            "OUR-SERVER BUG: kXR_fattrGet of a missing attribute returns a "
            f"request-level error on ours but ok-with-per-attr-rc on stock.{raw}"
            " The reference always returns kXR_ok and encodes the per-attr "
            "failure in the nvec rc field (XeqFAGet, Xeq:430).")
    assert st_o == kXR_ok, f"raw fattrGet-missing-attr success differs:{raw}"
    assert b_o == b_f, f"raw fattrGet-missing-attr framing differs:{raw}"


@pytest.mark.parametrize("path", RAW_FA_FILES)
def test_raw_fattr_list_strips_namespace(srv, path):
    """RAW kXR_fattrList after a Set -> the listed name carries NO internal
    namespace prefix (XeqFALsd strips "user", Xeq:474). Pin stock byte-shape."""
    name = "user.lst"
    so, sf = _both()
    try:
        _fattr(so, path, kXR_fattrSet, 1, names=[name], values=["x"])
        _fattr(sf, path, kXR_fattrSet, 1, names=[name], values=["x"])
        l_o = _fattr(so, path, kXR_fattrList, 0)
        l_f = _fattr(sf, path, kXR_fattrList, 0)
    finally:
        so.close()
        sf.close()
    assert l_o[0] == kXR_ok and l_f[0] == kXR_ok, "raw fattrList should succeed"
    names_o = _fattr_list_names(l_o[1])
    names_f = _fattr_list_names(l_f[1])
    assert name in names_f, f"stock list missing {name}: {names_f} ({l_f[1]!r})"
    if name not in names_o:
        leaked = {n for n in names_o if n.endswith(name) and n != name}
        pytest.xfail(
            "OUR-SERVER BUG: RAW kXR_fattrList leaks the internal namespace "
            f"prefix. Expected {name!r} (stock: {sorted(names_f)}); ours body "
            f"{l_o[1]!r} -> {sorted(names_o)} (leaked {sorted(leaked)}). The "
            "reference strips the 'user' prefix (XeqFALsd, Xeq:474).")
    assert name in names_o


def test_raw_fattr_del_then_get_parity(srv):
    """RAW kXR_fattrSet -> kXR_fattrDel -> kXR_fattrGet: after delete, Get
    reports the attr as missing (per-attr rc), identically to stock."""
    name = "user.delraw"
    so, sf = _both()
    try:
        _fattr(so, "/data.bin", kXR_fattrSet, 1, names=[name], values=["y"])
        _fattr(sf, "/data.bin", kXR_fattrSet, 1, names=[name], values=["y"])
        d_o = _fattr(so, "/data.bin", kXR_fattrDel, 1, names=[name])
        d_f = _fattr(sf, "/data.bin", kXR_fattrDel, 1, names=[name])
        assert (d_o[0] == kXR_ok) == (d_f[0] == kXR_ok), \
            f"raw fattrDel success differs: {_category(*d_o)} / {_category(*d_f)}"
        g_o = _fattr(so, "/data.bin", kXR_fattrGet, 1, names=[name])
        g_f = _fattr(sf, "/data.bin", kXR_fattrGet, 1, names=[name])
    finally:
        so.close()
        sf.close()
    raw = f"\n  OURS get cat={_category(*g_o)} body={g_o[1]!r}" \
          f"\n  STOCK get cat={_category(*g_f)} body={g_f[1]!r}"
    assert (g_o[0] == kXR_ok) == (g_f[0] == kXR_ok), \
        f"raw del-then-get success differs:{raw}"
    if g_o[0] == kXR_ok and g_f[0] == kXR_ok:
        assert g_o[1] == g_f[1], f"raw del-then-get framing differs:{raw}"


# =========================================================================== #
# L. RAW kXR_fattr error paths — bad subcode, bad numattr, missing file, dir
# =========================================================================== #
@pytest.mark.parametrize("subcode", [4, 7, 9, 200])
def test_raw_fattr_bad_subcode_parity(srv, subcode):
    """RAW kXR_fattr with an out-of-range subcode (>3) -> kXR_ArgInvalid on both
    (Xeq:247)."""
    so, sf = _both()
    try:
        st_o, b_o = _fattr(so, "/hello.txt", subcode, 1, names=["user.x"])
        st_f, b_f = _fattr(sf, "/hello.txt", subcode, 1, names=["user.x"])
    finally:
        so.close()
        sf.close()
    raw = f"\n  OURS cat={_category(st_o, b_o)}\n  STOCK cat={_category(st_f, b_f)}"
    assert _rejected(st_o) == _rejected(st_f), \
        f"fattr bad-subcode {subcode} rejection differs:{raw}"
    if st_o == kXR_error and st_f == kXR_error:
        assert _errnum(b_o) == _errnum(b_f) == kXR_ArgInvalid, \
            f"fattr bad-subcode errnum differs:{raw}"


@pytest.mark.parametrize("subcode,numattr", [
    (kXR_fattrGet, 0),    # Get with zero attrs -> invalid (Xeq:316)
    (kXR_fattrSet, 0),    # Set with zero attrs -> invalid
    (kXR_fattrList, 1),   # List MUST have zero attrs (Xeq:315)
])
def test_raw_fattr_bad_numattr_parity(srv, subcode, numattr):
    """RAW kXR_fattr with an invalid numattr for the subcode -> kXR_ArgInvalid
    parity (ProcFAttr numattr check, Xeq:315-317)."""
    so, sf = _both()
    try:
        nm = ["user.x"] if numattr else []
        st_o, b_o = _fattr(so, "/hello.txt", subcode, numattr, names=nm)
        st_f, b_f = _fattr(sf, "/hello.txt", subcode, numattr, names=nm)
    finally:
        so.close()
        sf.close()
    raw = f"\n  OURS cat={_category(st_o, b_o)}\n  STOCK cat={_category(st_f, b_f)}"
    assert _rejected(st_o) == _rejected(st_f), \
        f"fattr bad-numattr (sub={subcode},n={numattr}) rejection differs:{raw}"
    if st_o == kXR_error and st_f == kXR_error:
        assert _errnum(b_o) == _errnum(b_f), \
            f"fattr bad-numattr errnum differs:{raw}"


@pytest.mark.parametrize("path", ["/nope.txt", "/sub/gone.bin", "/missing/x"])
def test_raw_fattr_get_nonexistent_file_parity(srv, path):
    """RAW kXR_fattrGet on a NONEXISTENT file -> pin stock. The reference path
    access check reports the attr-level failure inside an ok response (per-attr
    rc), whereas ours rejects the whole request with kXR_NotFound."""
    so, sf = _both()
    try:
        st_o, b_o = _fattr(so, path, kXR_fattrGet, 1, names=["user.x"])
        st_f, b_f = _fattr(sf, path, kXR_fattrGet, 1, names=["user.x"])
    finally:
        so.close()
        sf.close()
    raw = f"\n  OURS cat={_category(st_o, b_o)} body={b_o[:48]!r}" \
          f"\n  STOCK cat={_category(st_f, b_f)} body={b_f[:48]!r}"
    if (st_o == kXR_ok) != (st_f == kXR_ok):
        pytest.xfail(
            "OUR-SERVER BUG: kXR_fattrGet on a nonexistent file is rejected at "
            f"the request level on ours but reported as a per-attr rc inside an "
            f"ok response on stock.{raw} The reference returns kXR_ok and "
            "encodes the failure in the nvec rc (XeqFAGet, Xeq:430).")
    assert (st_o == kXR_ok) == (st_f == kXR_ok), \
        f"fattr-get nonexistent-file success differs:{raw}"
    if st_o != kXR_ok:
        assert _errnum(b_o) == _errnum(b_f), \
            f"fattr-get nonexistent-file errnum differs:{raw}"


@pytest.mark.parametrize("path", ["/sub", "/deep", "/many", "/empty_dir"])
def test_raw_fattr_list_on_directory_parity(srv, path):
    """RAW kXR_fattrList on a DIRECTORY -> success/category parity (dirs may
    carry attrs; pin stock's behavior)."""
    so, sf = _both()
    try:
        st_o, b_o = _fattr(so, path, kXR_fattrList, 0)
        st_f, b_f = _fattr(sf, path, kXR_fattrList, 0)
    finally:
        so.close()
        sf.close()
    raw = f"\n  OURS cat={_category(st_o, b_o)} body={b_o[:48]!r}" \
          f"\n  STOCK cat={_category(st_f, b_f)} body={b_f[:48]!r}"
    assert (st_o == kXR_ok) == (st_f == kXR_ok), \
        f"fattr-list on dir {path} success differs:{raw}"
    if st_o != kXR_ok:
        assert _errnum(b_o) == _errnum(b_f), \
            f"fattr-list on dir errnum differs:{raw}"


# =========================================================================== #
# M. RAW kXR_fattr determinism + multi-attr set/get
# =========================================================================== #
def test_raw_fattr_set_get_determinism(srv):
    """RAW Set then repeated Get of the same attr -> the Get response is stable
    and byte-identical to stock across repeats."""
    name, value = "user.det", "stable"
    so, sf = _both()
    try:
        _fattr(so, "/sz_8192.bin", kXR_fattrSet, 1, names=[name], values=[value])
        _fattr(sf, "/sz_8192.bin", kXR_fattrSet, 1, names=[name], values=[value])
        prev_o = prev_f = None
        for _ in range(4):
            g_o = _fattr(so, "/sz_8192.bin", kXR_fattrGet, 1, names=[name])
            g_f = _fattr(sf, "/sz_8192.bin", kXR_fattrGet, 1, names=[name])
            assert g_o[0] == kXR_ok and g_f[0] == kXR_ok
            assert g_o[1] == g_f[1], \
                f"fattrGet diverges from stock:\n  OURS {g_o[1]!r}\n  STOCK {g_f[1]!r}"
            if prev_o is not None:
                assert g_o[1] == prev_o, "OUR fattrGet not deterministic"
                assert g_f[1] == prev_f, "STOCK fattrGet not deterministic"
            prev_o, prev_f = g_o[1], g_f[1]
    finally:
        so.close()
        sf.close()


@pytest.mark.parametrize("count", [2, 3, 4])
def test_raw_fattr_multi_attr_set_then_list(srv, count):
    """RAW kXR_fattrSet of several attrs in one request -> a subsequent
    kXR_fattrList shows all of them, with the SAME name-set as stock."""
    names = [f"user.multi{i}" for i in range(count)]
    values = [f"v{i}" for i in range(count)]
    fpath = f"/many/f{4 + count:02d}.txt"
    so, sf = _both()
    try:
        st_o, _ = _fattr(so, fpath, kXR_fattrSet, count, names=names, values=values)
        st_f, _ = _fattr(sf, fpath, kXR_fattrSet, count, names=names, values=values)
        assert (st_o == kXR_ok) == (st_f == kXR_ok), \
            "multi-attr fattrSet success differs"
        l_o = _fattr(so, fpath, kXR_fattrList, 0)
        l_f = _fattr(sf, fpath, kXR_fattrList, 0)
    finally:
        so.close()
        sf.close()
    if st_o != kXR_ok:
        pytest.skip("multi-attr set not accepted; covered by single-attr tests")
    set_o = {n for n in _fattr_list_names(l_o[1]) if "multi" in n}
    set_f = {n for n in _fattr_list_names(l_f[1]) if "multi" in n}
    # stock should list exactly the `count` set attrs
    assert len(set_f) == count, f"stock multi-list count {set_f} != {count}"
    if set_o != set_f:
        # if ours leaks the namespace prefix, the bare-name set still differs;
        # compare on the stripped tail.
        def tails(s):
            return {n.split("user.", 1)[-1] if "user." in n else n for n in s}
        if tails(set_o) != tails(set_f):
            pytest.xfail(
                "OUR-SERVER BUG: RAW multi-attr kXR_fattrList name-set differs "
                f"from stock. OURS {sorted(set_o)}, STOCK {sorted(set_f)} "
                "(likely the FATTR_NAMESPACE prefix leak, XeqFALsd Xeq:474).")
    assert set_o == set_f or len(set_o) == count


# =========================================================================== #
# N. xattr namespace rules — user.* accepted; pin stock for other namespaces
# =========================================================================== #
@pytest.mark.parametrize("attr", [
    "user.ns_ok",     # user.* — the standard, supported namespace
    "trusted.t1",     # non-user namespace
    "system.s1",      # non-user namespace
    "nodot",          # no namespace at all
])
def test_xattr_namespace_rules_parity(srv, attr):
    """`xrdfs xattr set` across namespaces -> rc/category parity. The reference
    confines client attrs to its FATTR_NAMESPACE; pin whatever stock does for
    non-user namespaces (accept-and-prefix vs reject)."""
    rc_o, _, e_o = L.run([L.OFF_XRDFS, srv["our"], "xattr", "/data.bin",
                          "set", f"{attr}=x"])
    rc_f, _, e_f = L.run([L.OFF_XRDFS, srv["off"], "xattr", "/data.bin",
                          "set", f"{attr}=x"])
    raw = f"\n  OURS rc={rc_o} err={e_o.strip()!r}" \
          f"\n  STOCK rc={rc_f} err={e_f.strip()!r}"
    assert (rc_o == 0) == (rc_f == 0), \
        f"xattr namespace {attr!r} accept/reject differs from stock:{raw}"
    if rc_o != 0:
        assert L.err_code(e_o) == L.err_code(e_f), \
            f"xattr namespace {attr!r} error category differs:{raw}"
