# _test_conf_fattr_helpers.py - shared header/helpers/fixtures/constants for the Phase-38
# split of test_conf_fattr.py.  `from _test_conf_fattr_helpers import *` re-exports EVERYTHING via
# the __all__ below so the test functions keep their exact module namespace.


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
    # The fleet stock server runs as `nobody`; harmonize (owner triad mirrored
    # into group+other) so it can set/remove user.* xattrs on the seeded file as
    # our root-run server can (setxattr needs write permission).
    L.harmonize_perms(_our_disk(ctx, rel), _off_disk(ctx, rel))


_counter = {"n": 0}


def _scratch(ctx, payload=b"x", suffix="bin"):
    """Allocate a unique scratch file present identically on both roots.

    The name is tagged with the pytest-xdist worker id so that under
    `-n8 --dist load` a concurrent worker's xattr writes never land on the same
    file (which would inflate list-count / value differentials); the per-process
    counter keeps successive scratch files within a worker distinct."""
    _counter["n"] += 1
    rel = f"/fa_scratch_{L.worker_tag()}_{_counter['n']:04d}.{suffix}"
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


# =========================================================================== #
# C. BINDINGS — get a MISSING attribute: per-attr status / errno parity
# =========================================================================== #
MISSING_NAMES = [
    "user.absent", "user.nope", "user.gone", "user.never_set",
    "user.deadbeef", "user.x.y.z",
]


# =========================================================================== #
# D. BINDINGS — del then get: the attribute is gone (per-attr failure)
# =========================================================================== #
DEL_NAMES = ["user.d1", "user.d2", "user.d3.dotted", "user.d_underscore",
             "user.delme", "user.temp"]


# =========================================================================== #
# G. BINDINGS — set MULTIPLE attrs then list: NAME-SET parity
#    (this is where our internal "U." namespace prefix leak surfaces)
# =========================================================================== #
MULTI_COUNTS = [1, 2, 3, 4, 8]


# =========================================================================== #
# H. BINDINGS — set/get on a DIRECTORY (dirs may carry attrs)
# =========================================================================== #
DIRS = ["/sub", "/deep", "/many", "/empty_dir", "/deep/a", "/deep/a/b"]


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


# =========================================================================== #
# J. BINDINGS — long attribute NAMES
# =========================================================================== #
LONG_NAME_LENS = [16, 64, 128, 200, 240]


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


# =========================================================================== #
# M. BINDINGS — query XATTR (QueryCode.XATTR) metadata blob parity
# =========================================================================== #
QUERY_PATHS = ["/hello.txt", "/data.bin", "/sz_4096.bin", "/cksum.bin",
               "/empty.txt", "/many/f00.txt"]


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

__all__ = [n for n in dir() if not n.startswith('__')]
