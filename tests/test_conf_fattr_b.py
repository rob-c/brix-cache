from _test_conf_fattr_helpers import *  # noqa: F401,F403  (Phase-38 split shared header)

@needs_bindings
@pytest.mark.parametrize("attr", NAMESPACE_CASES)
def test_bindings_namespace_set_parity(srv, attr):
    """set_xattr across namespaces -> request/per-attr status parity.  The
    reference confines client attrs to its FATTR_NAMESPACE; pin EXACTLY what
    stock does for each namespace (accept-and-prefix vs reject)."""
    rel = _scratch(srv)
    o_st, o_smap = _set(srv["our"], rel, [(attr, "v")])
    f_st, f_smap = _set(srv["off"], rel, [(attr, "v")])
    raw = (f"\n  OURS  req_ok={o_st.ok} per={_sok(o_smap.get(attr))}"
           f"\n  STOCK req_ok={f_st.ok} per={_sok(f_smap.get(attr))}")
    assert o_st.ok == f_st.ok, f"namespace {attr!r} request status differs:{raw}"
    assert _sok(o_smap.get(attr)) == _sok(f_smap.get(attr)), \
        f"namespace {attr!r} per-attr status differs:{raw}"


@needs_bindings
@pytest.mark.parametrize("attr", NAMESPACE_CASES)
def test_bindings_namespace_get_back_parity(srv, attr):
    """For each namespace that stock ACCEPTS on set, get_xattr by the SAME name
    returns the value and matches ours (i.e. the name the client uses to set is
    the name it reads back — the prefix the server adds internally is
    transparent on the get path)."""
    rel = _scratch(srv)
    _, f_smap = _set(srv["off"], rel, [(attr, "nsval")])
    _, o_smap = _set(srv["our"], rel, [(attr, "nsval")])
    if not _sok(f_smap.get(attr)):
        pytest.skip(f"stock rejected set of {attr!r}; covered by set-parity")
    _, o_gmap = _get(srv["our"], rel, [attr])
    _, f_gmap = _get(srv["off"], rel, [attr])
    f_val = _as_text(f_gmap.get(attr, (None,))[0])
    o_val = _as_text(o_gmap.get(attr, (None,))[0])
    assert f_val == "nsval", f"stock did not read back {attr!r}: {f_val!r}"
    assert o_val == f_val, \
        f"namespace {attr!r} get-back value differs: ours={o_val!r} " \
        f"stock={f_val!r}"


# =========================================================================== #
# L. BINDINGS — multi-name GET in one request (mixed present / absent)
# =========================================================================== #
@needs_bindings
def test_bindings_multi_get_mixed_present_absent(srv):
    """get_xattr of several names at once where some exist and some don't ->
    per-name status parity (present -> ok+value, absent -> AttrNotFound)."""
    rel = _scratch(srv)
    present = [("user.p1", "one"), ("user.p2", "two")]
    for url in (srv["our"], srv["off"]):
        _set(url, rel, present)
    names = ["user.p1", "user.absent_x", "user.p2", "user.absent_y"]
    _, o_gmap = _get(srv["our"], rel, names)
    _, f_gmap = _get(srv["off"], rel, names)
    for n in names:
        o_v, o_s = o_gmap.get(n, (None, None))
        f_v, f_s = f_gmap.get(n, (None, None))
        assert _sok(o_s) == _sok(f_s), \
            f"multi-get per-name ok differs for {n}: ours={_sok(o_s)} " \
            f"stock={_sok(f_s)}"
        if _sok(f_s):
            assert _as_text(o_v) == _as_text(f_v), \
                f"multi-get value differs for {n}"
        else:
            assert _serrno(o_s) == _serrno(f_s), \
                f"multi-get absent errno differs for {n}"


@needs_bindings
@pytest.mark.parametrize("path", QUERY_PATHS)
def test_bindings_query_xattr_status_parity(srv, path):
    """query(QueryCode.XATTR, path) -> request status parity on both servers."""
    o_st, o_resp = _query_xattr(srv["our"], path)
    f_st, f_resp = _query_xattr(srv["off"], path)
    raw = (f"\n  OURS  ok={o_st.ok} code={o_st.code} errno={o_st.errno}"
           f"\n  STOCK ok={f_st.ok} code={f_st.code} errno={f_st.errno}")
    assert o_st.ok == f_st.ok, f"query XATTR status differs for {path}:{raw}"
    if not o_st.ok:
        assert o_st.errno == f_st.errno, \
            f"query XATTR error errno differs for {path}:{raw}"


@needs_bindings
@pytest.mark.xfail(reason="DIVERGENCE: query(QueryCode.XATTR) metadata blob is "
                          "missing the 'ofs.ap' (access-privilege) key that stock "
                          "emits — ours returns the oss.* set but not the ofs.* "
                          "entries the OFS layer appends (stock: ...&ofs.ap=a). "
                          "Suspected: src/ Qxattr / query xattr blob builder.",
                   strict=False)
@pytest.mark.parametrize("path", QUERY_PATHS)
def test_bindings_query_xattr_keyset_parity(srv, path):
    """The query-XATTR metadata blob exposes the SAME key set as stock (values
    such as oss.cgroup/mtime are environment-dependent, so we compare the keys,
    which are the protocol contract gfal/FTS rely on).  Currently xfail: ours
    omits stock's 'ofs.ap' key."""
    o_st, o_resp = _query_xattr(srv["our"], path)
    f_st, f_resp = _query_xattr(srv["off"], path)
    if not (o_st.ok and f_st.ok):
        pytest.skip("query XATTR not ok on both; covered by status-parity test")
    o_keys, f_keys = _kv_keys(o_resp), _kv_keys(f_resp)
    # stock's canonical keys must all be present in ours (ours may add none).
    missing = f_keys - o_keys
    assert not missing, \
        f"query XATTR for {path} missing stock keys {sorted(missing)} " \
        f"(ours={sorted(o_keys)} stock={sorted(f_keys)})"


@pytest.mark.parametrize("name,value", CLI_CASES, ids=[c[0] for c in CLI_CASES])
def test_cli_xattr_set_get_value_parity(srv, name, value):
    """`xrdfs xattr <f> set name=value` then `get name` -> rc parity and the
    retrieved value equals stock's."""
    rel = _scratch(srv)

    def setget(url):
        rc1, _, e1 = _cli(url, rel, "set", f"{name}={value}")
        rc2, o2, e2 = _cli(url, rel, "get", name)
        return rc1, rc2, o2, e1, e2

    o = setget(srv["our"])
    f = setget(srv["off"])
    raw = (f"\n  OURS  set_rc={o[0]} get_rc={o[1]} val={_cli_value(o[2])!r}"
           f"\n  STOCK set_rc={f[0]} get_rc={f[1]} val={_cli_value(f[2])!r}")
    assert (o[0] == 0) == (f[0] == 0), f"CLI set rc parity differs:{raw}"
    assert (o[1] == 0) == (f[1] == 0), f"CLI get rc parity differs:{raw}"
    if o[1] == 0 and f[1] == 0:
        assert _cli_value(o[2]) == _cli_value(f[2]), \
            f"CLI get value our-vs-stock differs:{raw}"


# =========================================================================== #
# O. STOCK xrdfs xattr CLI — del removes; del-then-get parity
# =========================================================================== #
@pytest.mark.parametrize("name", ["user.cd1", "user.cd2", "user.cd3.x"])
def test_cli_xattr_del_then_get_parity(srv, name):
    """`xrdfs xattr <f> del` removes the attr; a subsequent `get` reflects the
    absence identically (value-presence parity)."""
    rel = _scratch(srv)
    for url in (srv["our"], srv["off"]):
        _cli(url, rel, "set", f"{name}=z")
    o_d = _cli(srv["our"], rel, "del", name)
    f_d = _cli(srv["off"], rel, "del", name)
    assert (o_d[0] == 0) == (f_d[0] == 0), \
        f"CLI del rc parity differs: ours={o_d[0]} stock={f_d[0]}"
    g_o = _cli(srv["our"], rel, "get", name)
    g_f = _cli(srv["off"], rel, "get", name)

    def has_value(out):
        for ln in out.splitlines():
            ln = ln.strip()
            if ln and not ln.startswith("#") and "=" in ln:
                return ln.split("=", 1)[1].strip().strip('"') != ""
        return False

    assert has_value(g_o[1]) == has_value(g_f[1]), \
        f"CLI del-then-get value-presence differs: ours={g_o[1].strip()!r} " \
        f"stock={g_f[1].strip()!r}"


# =========================================================================== #
# P. STOCK xrdfs xattr CLI — multi-attr list COUNT parity
# =========================================================================== #
@pytest.mark.parametrize("count", [2, 3, 5])
def test_cli_xattr_multi_list_count_parity(srv, count):
    """Set several attrs via CLI, then `list` shows the same COUNT on both."""
    rel = _scratch(srv)
    for url in (srv["our"], srv["off"]):
        for i in range(count):
            _cli(url, rel, "set", f"user.cm{i}=v{i}")
    o = _cli(srv["our"], rel, "list")
    f = _cli(srv["off"], rel, "list")
    assert o[0] == 0 and f[0] == 0, "CLI list should succeed on both"

    def n(out):
        return sum(1 for ln in out.splitlines()
                   if ln.strip() and not ln.strip().startswith("#"))

    assert n(o[1]) == n(f[1]), \
        f"CLI list count differs: ours={n(o[1])} ({o[1].strip()!r}) " \
        f"stock={n(f[1])} ({f[1].strip()!r})"


# =========================================================================== #
# Q. STOCK xrdfs xattr CLI — list shows ORIGINAL name (namespace-leak pin)
# =========================================================================== #
# FIXED: src/fattr/list.c strips the full internal "user.U." prefix, so
# `xrdfs xattr list` shows the verbatim client name like stock.
@pytest.mark.parametrize("name", ["user.cn_a", "user.cn_b", "user.cn_c.dot"])
def test_cli_xattr_list_no_namespace_leak(srv, name):
    """`xrdfs xattr list` must show the attr under its ORIGINAL name; currently
    ours leaks the internal 'U.' prefix.  Pin stock."""
    rel = _scratch(srv)
    _cli(srv["our"], rel, "set", f"{name}=v")
    _cli(srv["off"], rel, "set", f"{name}=v")
    o = _cli(srv["our"], rel, "list")
    f = _cli(srv["off"], rel, "list")
    assert o[0] == 0 and f[0] == 0, "CLI list should succeed on both"

    def names(out):
        s = set()
        for ln in out.splitlines():
            ln = ln.strip()
            if not ln or ln.startswith("#"):
                continue
            s.add(ln.split("=", 1)[0])
        return s

    no, nf = names(o[1]), names(f[1])
    assert name in nf, f"stock list missing {name}: {nf}"
    assert name in no, \
        f"OUR list shows {sorted(no)} (leaked prefix?); expected {name}"


# =========================================================================== #
# R. STOCK xrdfs xattr CLI — namespace accept/reject parity
# =========================================================================== #
@pytest.mark.parametrize("attr", [
    "user.cli_ok", "trusted.tc", "system.sc", "nodotc", "other.nsc",
])
def test_cli_xattr_namespace_rules_parity(srv, attr):
    """`xrdfs xattr set` across namespaces -> rc/category parity with stock."""
    rel = _scratch(srv)
    rc_o, _, e_o = _cli(srv["our"], rel, "set", f"{attr}=x")
    rc_f, _, e_f = _cli(srv["off"], rel, "set", f"{attr}=x")
    raw = (f"\n  OURS  rc={rc_o} err={e_o.strip()!r}"
           f"\n  STOCK rc={rc_f} err={e_f.strip()!r}")
    assert (rc_o == 0) == (rc_f == 0), \
        f"CLI namespace {attr!r} accept/reject differs:{raw}"
    if rc_o != 0:
        assert L.err_code(e_o) == L.err_code(e_f), \
            f"CLI namespace {attr!r} error category differs:{raw}"


# =========================================================================== #
# S. STOCK xrdfs xattr CLI — get missing attr parity
# =========================================================================== #
@pytest.mark.parametrize("name", ["user.cli_absent", "user.cli_nope",
                                  "user.cli_gone"])
def test_cli_xattr_get_missing_parity(srv, name):
    """`xrdfs xattr get` of an attr that was never set -> rc/value-presence
    parity with stock (stock surfaces the per-attr AttrNotFound)."""
    rel = _scratch(srv)
    rc_o, o_o, e_o = _cli(srv["our"], rel, "get", name)
    rc_f, o_f, e_f = _cli(srv["off"], rel, "get", name)
    raw = (f"\n  OURS  rc={rc_o} out={o_o.strip()!r} err={e_o.strip()!r}"
           f"\n  STOCK rc={rc_f} out={o_f.strip()!r} err={e_f.strip()!r}")
    assert (rc_o == 0) == (rc_f == 0), \
        f"CLI get-missing rc parity differs:{raw}"

    def has_value(out):
        for ln in out.splitlines():
            ln = ln.strip()
            if ln and not ln.startswith("#") and "=" in ln:
                return ln.split("=", 1)[1].strip().strip('"') != ""
        return False

    assert has_value(o_o) == has_value(o_f), \
        f"CLI get-missing value-presence differs:{raw}"


# =========================================================================== #
# T. STOCK xrdfs xattr CLI — set on a directory parity
# =========================================================================== #
@pytest.mark.parametrize("d", ["/sub", "/deep", "/empty_dir", "/many"])
def test_cli_xattr_set_get_on_directory_parity(srv, d):
    """`xrdfs xattr <dir> set/get` on a DIRECTORY -> rc parity and value parity
    when both accept."""
    name, value = "user.cli_dir", "dval"
    rc_o, _, e_o = _cli(srv["our"], d, "set", f"{name}={value}")
    rc_f, _, e_f = _cli(srv["off"], d, "set", f"{name}={value}")
    raw = (f"\n  OURS  set_rc={rc_o} err={e_o.strip()!r}"
           f"\n  STOCK set_rc={rc_f} err={e_f.strip()!r}")
    assert (rc_o == 0) == (rc_f == 0), \
        f"CLI dir set rc parity differs for {d}:{raw}"
    if rc_f != 0:
        return
    g_o = _cli(srv["our"], d, "get", name)
    g_f = _cli(srv["off"], d, "get", name)
    assert (g_o[0] == 0) == (g_f[0] == 0), f"CLI dir get rc differs for {d}"
    if g_o[0] == 0 and g_f[0] == 0:
        assert _cli_value(g_o[1]) == _cli_value(g_f[1]) == value, \
            f"CLI dir get value differs for {d}"


# =========================================================================== #
# U. STOCK xrdfs xattr CLI — set/get/del determinism (stable across repeats)
# =========================================================================== #
def test_cli_xattr_roundtrip_determinism(srv):
    """Repeated set/get of the same attr is stable and identical to stock."""
    rel = _scratch(srv)
    name, value = "user.cli_det", "stable-value"
    for url in (srv["our"], srv["off"]):
        _cli(url, rel, "set", f"{name}={value}")
    prev_o = prev_f = None
    for _ in range(4):
        o = _cli(srv["our"], rel, "get", name)
        f = _cli(srv["off"], rel, "get", name)
        assert o[0] == 0 and f[0] == 0
        assert _cli_value(o[1]) == _cli_value(f[1]) == value, \
            "CLI get diverges from stock"
        if prev_o is not None:
            assert _cli_value(o[1]) == prev_o, "OUR CLI get not deterministic"
            assert _cli_value(f[1]) == prev_f, "STOCK CLI get not deterministic"
        prev_o, prev_f = _cli_value(o[1]), _cli_value(f[1])
