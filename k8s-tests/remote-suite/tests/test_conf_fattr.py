from _test_conf_fattr_helpers import *  # noqa: F401,F403  (Phase-38 split shared header)

@needs_bindings
@pytest.mark.parametrize("name,value", RT_VALUES,
                         ids=[c[0] for c in RT_VALUES])
def test_bindings_set_get_value_parity(srv, name, value):
    """set_xattr then get_xattr round-trips the EXACT value, and ours == stock.

    The fresh scratch file isolates the probe; the request-level status and the
    per-attr status must be ok on both servers, and the retrieved value must
    equal the value written (and match between servers)."""
    rel = _scratch(srv, b"payload")

    def setget(url):
        sst, smap = _set(url, rel, [(name, value)])
        gst, gmap = _get(url, rel, [name])
        return sst, smap, gst, gmap

    o_sst, o_smap, o_gst, o_gmap = setget(srv["our"])
    f_sst, f_smap, f_gst, f_gmap = setget(srv["off"])

    raw = (f"\n  OURS  set ok={o_sst.ok} per={_sok(o_smap.get(name))} "
           f"get ok={o_gst.ok} val={o_gmap.get(name)}"
           f"\n  STOCK set ok={f_sst.ok} per={_sok(f_smap.get(name))} "
           f"get ok={f_gst.ok} val={f_gmap.get(name)}")

    assert o_sst.ok == f_sst.ok, f"set request-status parity differs:{raw}"
    assert _sok(o_smap.get(name)) == _sok(f_smap.get(name)), \
        f"set per-attr status parity differs:{raw}"
    assert o_gst.ok == f_gst.ok, f"get request-status parity differs:{raw}"

    # both must have stored & returned it
    assert _sok(f_smap.get(name)), f"stock failed to SET {name}:{raw}"
    assert _sok(o_smap.get(name)), f"OUR server failed to SET {name}:{raw}"

    o_val = _as_text(o_gmap.get(name, (None,))[0])
    f_val = _as_text(f_gmap.get(name, (None,))[0])
    assert f_val == value, f"stock did not round-trip the value:{raw}"
    assert o_val == value, f"OUR server did not round-trip the value:{raw}"
    assert o_val == f_val, f"get value our-vs-stock differs:{raw}"


@needs_bindings
@pytest.mark.parametrize("name,value", RT_VALUES,
                         ids=[c[0] for c in RT_VALUES])
def test_bindings_set_perattr_status_ok_parity(srv, name, value):
    """Every set_xattr per-attr status.ok matches stock (one assertion per
    value-class)."""
    rel = _scratch(srv)
    _, o_smap = _set(srv["our"], rel, [(name, value)])
    _, f_smap = _set(srv["off"], rel, [(name, value)])
    assert _sok(o_smap.get(name)) == _sok(f_smap.get(name)), \
        f"set per-attr ok differs for {name}: ours={_sok(o_smap.get(name))} " \
        f"stock={_sok(f_smap.get(name))}"


@needs_bindings
@pytest.mark.parametrize("name,value", RT_VALUES,
                         ids=[c[0] for c in RT_VALUES])
def test_bindings_get_perattr_status_ok_parity(srv, name, value):
    """After a set, the get_xattr per-attr status.ok matches stock."""
    rel = _scratch(srv)
    _set(srv["our"], rel, [(name, value)])
    _set(srv["off"], rel, [(name, value)])
    _, o_gmap = _get(srv["our"], rel, [name])
    _, f_gmap = _get(srv["off"], rel, [name])
    o_ok = _sok(o_gmap.get(name, (None, None))[1])
    f_ok = _sok(f_gmap.get(name, (None, None))[1])
    assert o_ok == f_ok, \
        f"get per-attr ok differs for {name}: ours={o_ok} stock={f_ok}"


@needs_bindings
@pytest.mark.parametrize("v1,v2", OVERWRITE_PAIRS,
                         ids=[f"{i}" for i in range(len(OVERWRITE_PAIRS))])
def test_bindings_overwrite_existing_attr_parity(srv, v1, v2):
    """Setting an existing attr REPLACES its value (no isNew restriction by
    default); the post-overwrite get value equals v2 on both servers."""
    rel = _scratch(srv)
    name = "user.ow"
    for url in (srv["our"], srv["off"]):
        _set(url, rel, [(name, v1)])
        _set(url, rel, [(name, v2)])
    _, o_gmap = _get(srv["our"], rel, [name])
    _, f_gmap = _get(srv["off"], rel, [name])
    o_val = _as_text(o_gmap.get(name, (None,))[0])
    f_val = _as_text(f_gmap.get(name, (None,))[0])
    assert f_val == v2, f"stock overwrite did not take: {f_val!r} != {v2!r}"
    assert o_val == v2, f"OUR overwrite did not take: {o_val!r} != {v2!r}"
    assert o_val == f_val, \
        f"overwrite value our-vs-stock differs: ours={o_val!r} stock={f_val!r}"


@needs_bindings
@pytest.mark.parametrize("name", MISSING_NAMES)
def test_bindings_get_missing_attr_perattr_status_parity(srv, name):
    """get_xattr of an attr that was never set -> the REQUEST is ok on both, and
    the per-attr status reports failure with errno kXR_AttrNotFound (3027 ->
    ENOATTR).  Pin stock's code/errno exactly."""
    rel = _scratch(srv)
    o_st, o_gmap = _get(srv["our"], rel, [name])
    f_st, f_gmap = _get(srv["off"], rel, [name])
    raw = (f"\n  OURS  req_ok={o_st.ok} per={o_gmap.get(name)}"
           f"\n  STOCK req_ok={f_st.ok} per={f_gmap.get(name)}")
    assert o_st.ok == f_st.ok, f"missing-attr request status differs:{raw}"
    o_ps = o_gmap.get(name, (None, None))[1]
    f_ps = f_gmap.get(name, (None, None))[1]
    assert _sok(o_ps) == _sok(f_ps), \
        f"missing-attr per-attr ok differs:{raw}"
    assert _sok(f_ps) is False, f"stock should report missing attr as failed:{raw}"
    assert _serrno(o_ps) == _serrno(f_ps), \
        f"missing-attr errno differs: ours={_serrno(o_ps)} " \
        f"stock={_serrno(f_ps)}:{raw}"
    assert _serrno(f_ps) == kXR_AttrNotFound, \
        f"stock missing-attr errno is not kXR_AttrNotFound (3027):{raw}"
    assert _scode(o_ps) == _scode(f_ps), \
        f"missing-attr per-attr code differs:{raw}"


@needs_bindings
@pytest.mark.parametrize("name", DEL_NAMES)
def test_bindings_del_then_get_gone_parity(srv, name):
    """set -> del -> get: del succeeds, and the subsequent get reports the attr
    missing (per-attr failure, errno kXR_AttrNotFound), identically to stock."""
    rel = _scratch(srv)
    for url in (srv["our"], srv["off"]):
        _set(url, rel, [(name, "to-be-deleted")])
    o_dst, o_dmap = _del(srv["our"], rel, [name])
    f_dst, f_dmap = _del(srv["off"], rel, [name])
    assert o_dst.ok == f_dst.ok, "del request status differs"
    assert _sok(o_dmap.get(name)) == _sok(f_dmap.get(name)), \
        f"del per-attr ok differs for {name}"
    assert _sok(f_dmap.get(name)), f"stock del of present attr should succeed"

    _, o_gmap = _get(srv["our"], rel, [name])
    _, f_gmap = _get(srv["off"], rel, [name])
    o_ps = o_gmap.get(name, (None, None))[1]
    f_ps = f_gmap.get(name, (None, None))[1]
    assert _sok(o_ps) == _sok(f_ps), \
        f"post-del get per-attr ok differs for {name}: ours={_sok(o_ps)} " \
        f"stock={_sok(f_ps)}"
    assert _sok(f_ps) is False, "stock: deleted attr should be gone on get"
    assert _serrno(o_ps) == _serrno(f_ps), \
        f"post-del get errno differs for {name}"


# =========================================================================== #
# E. BINDINGS — del a MISSING attribute: per-attr status parity
# =========================================================================== #
@needs_bindings
@pytest.mark.parametrize("name", ["user.dm1", "user.dm2", "user.dm3"])
def test_bindings_del_missing_attr_parity(srv, name):
    """del_xattr of an attr that was never set -> per-attr status parity (stock
    pins whether deleting a nonexistent attr is a per-attr failure or a no-op
    success)."""
    rel = _scratch(srv)
    o_st, o_dmap = _del(srv["our"], rel, [name])
    f_st, f_dmap = _del(srv["off"], rel, [name])
    raw = (f"\n  OURS  req_ok={o_st.ok} per={o_dmap.get(name)}"
           f"\n  STOCK req_ok={f_st.ok} per={f_dmap.get(name)}")
    assert o_st.ok == f_st.ok, f"del-missing request status differs:{raw}"
    o_ps = o_dmap.get(name)
    f_ps = f_dmap.get(name)
    assert _sok(o_ps) == _sok(f_ps), f"del-missing per-attr ok differs:{raw}"
    assert _serrno(o_ps) == _serrno(f_ps), \
        f"del-missing per-attr errno differs:{raw}"


# =========================================================================== #
# F. BINDINGS — list on a file with NO attributes
# =========================================================================== #
@needs_bindings
def test_bindings_list_empty_parity(srv):
    """list_xattr on a fresh, attribute-free file -> request ok and an EMPTY
    name-set on both servers."""
    rel = _scratch(srv)
    o_st, o_map = _list(srv["our"], rel)
    f_st, f_map = _list(srv["off"], rel)
    assert o_st.ok == f_st.ok, "empty-list request status differs"
    assert len(f_map) == 0, f"stock listed attrs on a fresh file: {f_map}"
    assert len(o_map) == 0, f"OUR server listed attrs on a fresh file: {o_map}"


@needs_bindings
@pytest.mark.parametrize("count", MULTI_COUNTS)
def test_bindings_multi_set_list_count_parity(srv, count):
    """Set `count` attrs in one request, then list -> the listed COUNT matches
    stock.  (Count is namespace-prefix-agnostic, so this passes even while the
    name strings diverge — the name-set parity is checked separately and xfail'd
    for the known leak.)"""
    rel = _scratch(srv)
    pairs = [(f"user.m{i}", f"val{i}") for i in range(count)]
    for url in (srv["our"], srv["off"]):
        _set(url, rel, pairs)
    o_st, o_map = _list(srv["our"], rel)
    f_st, f_map = _list(srv["off"], rel)
    assert o_st.ok and f_st.ok, "multi-list should succeed on both"
    assert len(f_map) == count, \
        f"stock list count {len(f_map)} != {count} ({sorted(f_map)})"
    assert len(o_map) == len(f_map), \
        f"list count our-vs-stock differs: ours={sorted(o_map)} " \
        f"stock={sorted(f_map)}"


@needs_bindings
@pytest.mark.parametrize("count", MULTI_COUNTS)
def test_bindings_multi_set_list_value_parity(srv, count):
    """The list_xattr VALUES (this bindings version returns name+value) match
    stock when keyed by the bare attribute name (tail after the last
    namespace component), independent of any leaked prefix."""
    rel = _scratch(srv)
    pairs = [(f"user.mv{i}", f"VAL-{i}") for i in range(count)]
    for url in (srv["our"], srv["off"]):
        _set(url, rel, pairs)
    _, o_map = _list(srv["our"], rel)
    _, f_map = _list(srv["off"], rel)

    def bare(name):
        # strip any leading "U." internal prefix and keep the user.<tail> form
        return name[2:] if name.startswith("U.") else name

    o_by_bare = {bare(k): _as_text(v) for k, v in o_map.items()}
    f_by_bare = {bare(k): _as_text(v) for k, v in f_map.items()}
    assert o_by_bare == f_by_bare, \
        f"list values (by bare name) differ: ours={o_by_bare} stock={f_by_bare}"


@needs_bindings
@pytest.mark.parametrize("count", [2, 3, 4])
def test_bindings_multi_set_list_NAME_parity(srv, count):
    """The list_xattr NAME-SET must equal stock's.  FIXED: src/protocols/root/fattr/list.c now
    strips the full internal "user.U." prefix so the client sees the verbatim
    name it set (stock 'user.m0' == ours 'user.m0')."""
    rel = _scratch(srv)
    pairs = [(f"user.n{i}", "v") for i in range(count)]
    for url in (srv["our"], srv["off"]):
        _set(url, rel, pairs)
    _, o_map = _list(srv["our"], rel)
    _, f_map = _list(srv["off"], rel)
    assert set(o_map) == set(f_map), \
        f"list NAME-set differs: ours={sorted(o_map)} stock={sorted(f_map)}"


@needs_bindings
@pytest.mark.parametrize("d", DIRS)
def test_bindings_set_get_on_directory_parity(srv, d):
    """set_xattr then get_xattr on a DIRECTORY path -> per-attr status parity and
    (when both accept) value round-trip parity.  Pin stock for whatever it does
    (accept-and-store vs reject)."""
    name, value = "user.dirattr", "on-a-directory"
    o_sst, o_smap = _set(srv["our"], d, [(name, value)])
    f_sst, f_smap = _set(srv["off"], d, [(name, value)])
    raw = (f"\n  OURS  set ok={o_sst.ok} per={_sok(o_smap.get(name))}"
           f"\n  STOCK set ok={f_sst.ok} per={_sok(f_smap.get(name))}")
    assert o_sst.ok == f_sst.ok, f"dir set request status differs for {d}:{raw}"
    assert _sok(o_smap.get(name)) == _sok(f_smap.get(name)), \
        f"dir set per-attr status differs for {d}:{raw}"
    if not _sok(f_smap.get(name)):
        return  # stock rejected the set on a dir -> parity only
    _, o_gmap = _get(srv["our"], d, [name])
    _, f_gmap = _get(srv["off"], d, [name])
    o_val = _as_text(o_gmap.get(name, (None,))[0])
    f_val = _as_text(f_gmap.get(name, (None,))[0])
    assert f_val == value, f"stock dir get value wrong for {d}: {f_val!r}"
    assert o_val == f_val, \
        f"dir get value our-vs-stock differs for {d}: ours={o_val!r} " \
        f"stock={f_val!r}"


@needs_bindings
@pytest.mark.parametrize("name,value", BIN_EMPTY_VALUES,
                         ids=[c[0] for c in BIN_EMPTY_VALUES])
def test_bindings_binary_empty_value_roundtrip(srv, name, value):
    """Control-char / empty values round-trip EXACT and identically to stock."""
    rel = _scratch(srv)
    _, o_smap = _set(srv["our"], rel, [(name, value)])
    _, f_smap = _set(srv["off"], rel, [(name, value)])
    assert _sok(o_smap.get(name)) == _sok(f_smap.get(name)), \
        f"binary set per-attr status differs for {name}"
    if not _sok(f_smap.get(name)):
        return
    _, o_gmap = _get(srv["our"], rel, [name])
    _, f_gmap = _get(srv["off"], rel, [name])
    o_val = _as_text(o_gmap.get(name, (None,))[0])
    f_val = _as_text(f_gmap.get(name, (None,))[0])
    assert f_val == value, f"stock value round-trip wrong for {name}"
    assert o_val == value, f"OUR value round-trip wrong for {name}"
    assert o_val == f_val, f"value our-vs-stock differs for {name}"


@needs_bindings
@pytest.mark.parametrize("nlen", LONG_NAME_LENS)
def test_bindings_long_name_parity(srv, nlen):
    """Long attribute names (up to ~faMaxNlen 248) -> set/get accept-or-reject
    parity, and value round-trip parity when accepted."""
    rel = _scratch(srv)
    name = "user." + ("z" * max(1, nlen - len("user.")))
    value = "longname-val"
    o_sst, o_smap = _set(srv["our"], rel, [(name, value)])
    f_sst, f_smap = _set(srv["off"], rel, [(name, value)])
    raw = (f"\n  OURS  set ok={o_sst.ok} per={_sok(o_smap.get(name))}"
           f"\n  STOCK set ok={f_sst.ok} per={_sok(f_smap.get(name))}")
    assert _sok(o_smap.get(name)) == _sok(f_smap.get(name)), \
        f"long-name (len {nlen}) set per-attr status differs:{raw}"
    if not _sok(f_smap.get(name)):
        return
    _, o_gmap = _get(srv["our"], rel, [name])
    _, f_gmap = _get(srv["off"], rel, [name])
    assert _as_text(o_gmap.get(name, (None,))[0]) == value == \
        _as_text(f_gmap.get(name, (None,))[0]), \
        f"long-name (len {nlen}) value differs:{raw}"
