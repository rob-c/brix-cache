"""Differential conformance for kXR_fattr extended attributes (get/set/del/list)
driven through BOTH the REAL libXrdCl Python bindings *and* the stock `xrdfs`
`xattr` CLI, against BOTH servers (our nginx-xrootd and the stock XRootD data
server) launched on identical data trees by official_interop_lib.

This is exactly gfal/FTS/Rucio's code path: those tools call XrdCl's public
``FileSystem::SetXAttr / GetXAttr / ListXAttr / DelXAttr`` (exposed in the
Python bindings as ``fs.set_xattr / fs.get_xattr / fs.list_xattr / fs.del_xattr``)
and parse the per-attribute ``(name, [value,] status)`` tuples they return.  Each
case runs the SAME operation against ``ctx['our']`` and ``ctx['off']`` and asserts
the parsed results agree.

Philosophy (per the maintainer): STOCK IS TRUTH.  A divergence — wrong per-attr
status, a value that does not round-trip, a leaked internal namespace, a missing
sub-op — is a BUG IN OUR SERVER.  A confirmed our-bug that cannot be fixed from a
test is pinned with ``@pytest.mark.xfail`` carrying the exact OURS-vs-STOCK detail
(so the suite stays green and the diff is documented), never a bare skip.

The bindings run OUT-OF-PROCESS via the tests/_xrdcl_worker.py proxy (memory:
importing pyxrootd into pytest deadlocks XrdCl).  The proxy special-cases
``set_xattr(path, [(name, value), ...])`` (a list-of-pairs arg, see
_xrdcl_worker._call_method).  Through the proxy a per-attr XRootDStatus arrives
as a plain dict {ok, code, errno, ...}; through a direct import it is a Status
object — the helpers here accept either shape.

Wire/contract facts pinned (XProtocol.hh / XrdXrootd fattr path):

  * kXR_fattr == 3020 (XProtocol.hh:133).  Subcodes (XProtocol.hh:299):
    Del 0, Get 1, List 2, Set 3.  Limits (XProtocol.hh:309): faMaxVars 16,
    faMaxNlen 248, faMaxVlen 65536.  Options: isNew 0x01, aData 0x10.
  * Get of a MISSING attr is NOT a request-level error: the request returns
    kXR_ok and the absence is reported as a non-zero per-attr status whose errno
    is kXR_AttrNotFound (3027 -> ENOATTR; XProtocol.hh:1059, toErrno:1483).
  * The server stores client attrs under an internal FATTR_NAMESPACE ("user")
    prefix; the reference STRIPS that prefix in the List response (XeqFALsd).
  * kXR_query infotype kXR_Qxattr (4; XProtocol.hh:652) returns an oss.* /
    ofs.* metadata blob for the path.

  ** KNOWN DIVERGENCE (pinned xfail): our List/oss layer leaks the internal
     "U." namespace prefix — ours lists ``U.user.<name>`` where stock lists
     ``user.<name>``.  See the xfail'd list-name-parity cases.

Self-provisioning on assigned high ports; skips entirely without the stock
toolchain.

Run:
  PYTHONPATH=tests python3 -m pytest tests/test_conf_fattr.py -v \
      --tb=short -p no:cacheprovider
"""

import os

import pytest

import official_interop_lib as L

pytestmark = [pytest.mark.timeout(420),
              pytest.mark.skipif(not L.have_official(),
                                 reason="stock xrootd/xrdfs not installed")]

OUR_PORT = L.worker_port(14924)
OFF_PORT = L.worker_port(14925)
# kXR error codes referenced (XProtocol.hh:1031+)
kXR_AttrNotFound = 3027


# --------------------------------------------------------------------------- #
# Bindings gate: the shadow XRootD package proxies the real libXrdCl out of
# process.  If it (or the underlying pyxrootd) is unavailable, the binding-driven
# cases skip cleanly while the stock-xrdfs cases still run.
# --------------------------------------------------------------------------- #
try:
    from XRootD import client as _xrdcl
    from XRootD.client.flags import QueryCode as _QueryCode
    _HAVE_BINDINGS = True
except Exception:  # noqa: BLE001 — any import failure disables the binding lane
    _xrdcl = None
    _QueryCode = None
    _HAVE_BINDINGS = False

needs_bindings = pytest.mark.skipif(not _HAVE_BINDINGS,
                                    reason="libXrdCl python bindings unavailable")


# --------------------------------------------------------------------------- #
# server pair fixture (one pair for the whole module, on the assigned ports)
# --------------------------------------------------------------------------- #
@pytest.fixture(scope="module")
def srv(tmp_path_factory):
    base = str(tmp_path_factory.mktemp("conffattr"))
    try:
        procs, ctx = L.start_pair(base, our_port=OUR_PORT, off_port=OFF_PORT)
    except RuntimeError as e:
        pytest.skip(f"server pair did not start: {e}")
    yield ctx
    L.stop_pair(procs)


# --------------------------------------------------------------------------- #
# status-shape helpers (per-attr status is a dict via the proxy, a Status object
# via a direct import — accept either)
# --------------------------------------------------------------------------- #
def _sok(s):
    """Per-attr/request status truthiness regardless of dict-vs-object shape."""
    if s is None:
        return False
    if isinstance(s, dict):
        return bool(s.get("ok"))
    return bool(getattr(s, "ok", False))


def _serrno(s):
    if s is None:
        return 0
    if isinstance(s, dict):
        return int(s.get("errno", 0) or 0)
    return int(getattr(s, "errno", 0) or 0)


def _scode(s):
    if s is None:
        return 0
    if isinstance(s, dict):
        return int(s.get("code", 0) or 0)
    return int(getattr(s, "code", 0) or 0)


def _as_text(v):
    """Normalise an xattr value (str or bytes) to text for exact comparison.

    The bindings return values as `str`; we set them as `str` too (see the note
    on RT_VALUES).  This collapses both shapes so a get-vs-set / our-vs-stock
    comparison is value-exact regardless of which the binding hands back."""
    if v is None:
        return ""
    if isinstance(v, (bytes, bytearray, memoryview)):
        return bytes(v).decode("utf-8", "surrogateescape")
    return v


# --------------------------------------------------------------------------- #
# thin binding wrappers — each returns (request_status, parsed_tuples)
# --------------------------------------------------------------------------- #
def _fs(url):
    return _xrdcl.FileSystem(url)


def _set(url, path, pairs):
    """set_xattr(path, [(name, value), ...]) -> (status, {name: perattr_status})."""
    st, resp = _fs(url).set_xattr(path, [(n, v) for n, v in pairs])
    out = {}
    for t in (resp or []):
        out[t[0]] = t[1]
    return st, out


def _get(url, path, names):
    """get_xattr(path, [name, ...]) -> (status, {name: (value, perattr_status)})."""
    st, resp = _fs(url).get_xattr(path, list(names))
    out = {}
    for t in (resp or []):
        out[t[0]] = (t[1], t[2])
    return st, out


def _list(url, path):
    """list_xattr(path) -> (status, {name: value}).  In this bindings version a
    list tuple is (name, value, status); we key by the name the server returns
    (which is where the namespace-leak divergence surfaces)."""
    st, resp = _fs(url).list_xattr(path)
    out = {}
    for t in (resp or []):
        name = t[0]
        val = t[1] if len(t) >= 3 else None
        out[name] = val
    return st, out


def _del(url, path, names):
    """del_xattr(path, [name, ...]) -> (status, {name: perattr_status})."""
    st, resp = _fs(url).del_xattr(path, list(names))
    out = {}
    for t in (resp or []):
        out[t[0]] = t[1]
    return st, out


def _query_xattr(url, path):
    st, resp = _fs(url).query(_QueryCode.XATTR, path)
    return st, resp


# --------------------------------------------------------------------------- #
# per-test scratch file: created identically under BOTH data roots so a fresh,
# attribute-free file backs every probe (no cross-talk / xattr accumulation).
# --------------------------------------------------------------------------- #
def _our_disk(ctx, path):
    return os.path.join(ctx["our_data"], path.lstrip("/"))


def _off_disk(ctx, path):
    return os.path.join(ctx["off_data"], path.lstrip("/"))


def _make_pair_file(ctx, rel, payload=b""):
    for disk in (_our_disk(ctx, rel), _off_disk(ctx, rel)):
        os.makedirs(os.path.dirname(disk), exist_ok=True)
        with open(disk, "wb") as f:
            f.write(payload)


_counter = {"n": 0}


def _scratch(ctx, payload=b"x", suffix="bin"):
    """Allocate a unique scratch file present identically on both roots."""
    _counter["n"] += 1
    rel = f"/fa_scratch_{_counter['n']:04d}.{suffix}"
    _make_pair_file(ctx, rel, payload)
    return rel


# =========================================================================== #
# A. BINDINGS — set then get round-trip: VALUE equality our-vs-stock
# =========================================================================== #
# NOTE: the pyxrootd set_xattr binding accepts only `str` values (a `bytes`
# value makes the C method return NULL -> SystemError, identically on both
# servers), so the binding lane uses str values; the on-disk wire still carries
# the exact bytes via vvec.  Values are NUL-free (NUL cannot appear in a Python
# str passed through the binding, and the wire name records are NUL-terminated).
RT_VALUES = [
    ("user.simple", "bar"),
    ("user.empty", ""),
    ("user.spaced", "a b c"),
    ("user.eq", "k=v=w"),
    ("user.num", "1234567890"),
    ("user.dots", "a.b.c.d"),
    ("user.hex", "deadbeefcafef00d"),
    ("user.newline", "line1\nline2"),
    ("user.tab", "a\tb\tc"),
    ("user.unicode", "ünïcödé"),
    ("user.json", '{"k":[1,2,3],"s":"v"}'),
    ("user.amp", "a&b=c&d"),
    ("user.percent", "100%done"),
    ("user.quote", 'he said "hi"'),
    ("user.long", "L" * 4000),
    ("user.ctrl", "".join(chr(c) for c in range(1, 32))),  # control chars, no NUL
    ("user.highchars", "".join(chr(c) for c in range(0x80, 0x100))),
]


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


# =========================================================================== #
# B. BINDINGS — overwrite an existing attribute (value replaced, not appended)
# =========================================================================== #
OVERWRITE_PAIRS = [
    ("first", "second"),
    ("long-initial-" + "A" * 100, "short"),
    ("x", "Y" * 500),
    ("same", "same"),
    ("", "nowset"),
    ("nowcleared", ""),
]


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


# =========================================================================== #
# C. BINDINGS — get a MISSING attribute: per-attr status / errno parity
# =========================================================================== #
MISSING_NAMES = [
    "user.absent", "user.nope", "user.gone", "user.never_set",
    "user.deadbeef", "user.x.y.z",
]


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


# =========================================================================== #
# D. BINDINGS — del then get: the attribute is gone (per-attr failure)
# =========================================================================== #
DEL_NAMES = ["user.d1", "user.d2", "user.d3.dotted", "user.d_underscore",
             "user.delme", "user.temp"]


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


# =========================================================================== #
# G. BINDINGS — set MULTIPLE attrs then list: NAME-SET parity
#    (this is where our internal "U." namespace prefix leak surfaces)
# =========================================================================== #
MULTI_COUNTS = [1, 2, 3, 4, 8]


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
    """The list_xattr NAME-SET must equal stock's.  FIXED: src/fattr/list.c now
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


# =========================================================================== #
# H. BINDINGS — set/get on a DIRECTORY (dirs may carry attrs)
# =========================================================================== #
DIRS = ["/sub", "/deep", "/many", "/empty_dir", "/deep/a", "/deep/a/b"]


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


# =========================================================================== #
# I. BINDINGS — control-char and empty values explicitly
# =========================================================================== #
# The binding carries values as `str`; a NUL cannot appear in a wire-name-record
# context, and a `bytes` value is rejected by pyxrootd itself (see RT_VALUES).
# These probe the non-NUL control-character and empty-value edges.
BIN_EMPTY_VALUES = [
    ("user.b_empty", ""),
    ("user.b_plain", "abc"),
    ("user.b_ctrl", "".join(chr(c) for c in (1, 2, 3, 4, 5))),
    ("user.b_allchars_nonul", "".join(chr(c) for c in range(1, 128))),  # ASCII
    ("user.b_4k", "K" * 4096),  # large value (well under faMaxVlen 65536)
    ("user.b_singlespace", " "),
    ("user.b_onlyeq", "="),
]


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


# =========================================================================== #
# J. BINDINGS — long attribute NAMES
# =========================================================================== #
LONG_NAME_LENS = [16, 64, 128, 200, 240]


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


# =========================================================================== #
# K. BINDINGS — namespace handling: user.foo vs bare foo vs other namespaces
# =========================================================================== #
NAMESPACE_CASES = [
    "user.ns_user",      # the standard supported namespace
    "user.a.b.c",        # dotted under user
    "trusted.t1",        # non-user namespace
    "system.s1",         # non-user namespace
    "security.x",        # non-user namespace
    "nodot",             # no namespace component at all
    "foo.bar",           # arbitrary namespace
]


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


# =========================================================================== #
# M. BINDINGS — query XATTR (QueryCode.XATTR) metadata blob parity
# =========================================================================== #
QUERY_PATHS = ["/hello.txt", "/data.bin", "/sz_4096.bin", "/cksum.bin",
               "/empty.txt", "/many/f00.txt"]


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


def _kv_keys(resp):
    """Parse an oss.* query-xattr blob ('k=v&k=v...') into the set of keys."""
    if resp is None:
        return set()
    if isinstance(resp, bytes):
        resp = resp.split(b"\x00", 1)[0].decode("ascii", "replace")
    keys = set()
    for tok in resp.split("&"):
        tok = tok.strip()
        if "=" in tok:
            keys.add(tok.split("=", 1)[0])
    return keys


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


# =========================================================================== #
# N. STOCK xrdfs `xattr` CLI — set/get value round-trip parity
# =========================================================================== #
def _cli(url, rel, *args):
    return L.run([L.OFF_XRDFS, url, "xattr", rel, *args])


def _cli_value(out):
    """Extract the last name="value" line's value from xrdfs xattr get output."""
    for ln in reversed(out.splitlines()):
        ln = ln.strip()
        if not ln or ln.startswith("#"):
            continue
        if "=" in ln:
            return ln.split("=", 1)[1].strip().strip('"')
        return ln
    return ""


CLI_CASES = [
    ("user.cli_a", "alpha"),
    ("user.cli_b", "b e t a"),
    ("user.cli_empty", ""),
    ("user.cli_num", "0987654321"),
    ("user.cli_dots", "p.q.r.s"),
    ("user.cli_long", "C" * 2000),
    ("user.cli_eq", "a=b"),
    ("user.cli_hex", "0xfeedface"),
]


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
