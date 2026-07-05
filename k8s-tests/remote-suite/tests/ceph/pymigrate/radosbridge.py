"""radosbridge — pure-Python access to librados's C++-only manifest ops.

WHAT: A ctypes bridge exposing the four RADOS operations the zero-move
      migration depends on — set_redirect, copy_from, tier_promote,
      unset_manifest — plus the C-API plumbing they need (own connection,
      ioctxs, stat-for-version, stub create) and a libradosstriper reader for
      striper-side verification.

WHY:  These ops exist ONLY in librados's C++ API: librados.h has no trace of
      them and python-rados's WriteOp doesn't expose them, but librados.so.2
      exports the mangled symbols under the ABI-versioned inline namespace
      librados::v14_2_0 (unchanged since Nautilus). Calling them directly
      keeps the tools pure Python with distro-only dependencies.

HOW:  The C++ classes involved are ABI-friendly: librados::IoCtx is a
      single-pointer pimpl over the same impl the C API's rados_ioctx_t
      points at, and ObjectWriteOperation is {vptr, impl} whose base-class
      constructor/destructor are exported. The bridge fabricates the argument
      objects (CXX11 std::string included), calls the mangled member symbols,
      and submits via the C++ IoCtx::operate symbol. A pre-write SELF-TEST
      round-trips a scratch object through a real redirect before any
      migration writes. If symbol probing or the self-test fails, the bridge
      falls back to a small compiled C-ABI shim (pymigrate/shim/), loadable
      prebuilt or compiled on the spot; PYMIGRATE_FORCE_SHIM=1 forces that
      path so tests exercise it.

Proven end-to-end on reef 18.2 (see the e2e runner); the ABI-coupled pieces
live only in this file.
"""

from __future__ import annotations

import ctypes
import errno as _errno
import os
import subprocess
import tempfile
from typing import Any, Optional

# Inline-namespace versions to probe. librados has kept v14_2_0 since
# Nautilus; add future namespace strings here if the ABI version ever moves.
_ABI_NAMESPACES = ["v14_2_0"]

# Mangled C++ symbols, templated on the inline namespace. Verified against
# reef 18.2 (nm -D librados.so.2); the signatures are:
#   ObjectOperation::ObjectOperation()                       (base ctor)
#   ObjectOperation::~ObjectOperation()                      (base dtor)
#   ObjectWriteOperation::set_redirect(const std::string&, const IoCtx&,
#                                      uint64_t, int)
#   ObjectWriteOperation::copy_from(const std::string&, const IoCtx&,
#                                   uint64_t, uint32_t)
#   ObjectWriteOperation::tier_promote()
#   ObjectWriteOperation::unset_manifest()
#   IoCtx::operate(const std::string&, ObjectWriteOperation*)
_SYMBOLS = {
    "op_ctor": "_ZN8librados{ns}15ObjectOperationC1Ev",
    "op_dtor": "_ZN8librados{ns}15ObjectOperationD1Ev",
    "set_redirect": ("_ZN8librados{ns}20ObjectWriteOperation12set_redirect"
                     "ERKNSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEEE"
                     "RKNS0_5IoCtxEmi"),
    "copy_from": ("_ZN8librados{ns}20ObjectWriteOperation9copy_from"
                  "ERKNSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEEE"
                  "RKNS0_5IoCtxEmj"),
    "tier_promote": "_ZN8librados{ns}20ObjectWriteOperation12tier_promoteEv",
    "unset_manifest": "_ZN8librados{ns}20ObjectWriteOperation14unset_manifestEv",
    "ioctx_operate": ("_ZN8librados{ns}5IoCtx7operate"
                      "ERKNSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEEE"
                      "PNS0_20ObjectWriteOperationE"),
}

_SHIM_FUNCS = ["shim_set_redirect", "shim_copy_from",
               "shim_tier_promote", "shim_unset_manifest"]


class BridgeError(RuntimeError):
    """The manifest-op bridge is unusable or an operation failed."""


def _rc_error(what: str, rc: int) -> BridgeError:
    name = _errno.errorcode.get(-rc, str(rc))
    return BridgeError("%s failed: rc=%d (%s)" % (what, rc, name))


class _StdString(ctypes.Structure):
    """A CXX11-ABI std::string: {char *ptr; size_t size; char sso[16]}.
    Short strings self-point into the SSO buffer; long ones keep a live
    ctypes buffer reference on the instance."""
    _fields_ = [("ptr", ctypes.c_void_p),
                ("size", ctypes.c_size_t),
                ("buf", ctypes.c_char * 16)]

    @classmethod
    def make(cls, s: bytes) -> "_StdString":
        o = cls()
        if len(s) < 16:
            o.buf = s + b"\0" * (16 - len(s))
            o.ptr = ctypes.addressof(o) + cls.buf.offset
        else:
            o._keep = ctypes.create_string_buffer(s)   # noqa: SLF001
            o.ptr = ctypes.addressof(o._keep)
        o.size = len(s)
        return o


class _CxxIoCtx(ctypes.Structure):
    """librados::IoCtx — a single-pointer pimpl; the impl pointer is exactly
    what the C API hands out as rados_ioctx_t."""
    _fields_ = [("impl", ctypes.c_void_p)]


class _OpBuf(ctypes.Structure):
    """Backing storage for a librados::ObjectWriteOperation: {vptr, impl}.
    Initialized by the exported base-class constructor (which sets a real
    vptr and allocates impl); destroyed via the exported base dtor."""
    _fields_ = [("vptr", ctypes.c_void_p), ("impl", ctypes.c_void_p)]


class _CtypesOps:
    """The manifest ops via direct mangled-symbol calls (default backend)."""

    name = "ctypes"

    def __init__(self, lib: ctypes.CDLL):
        self._fn: "dict[str, Any]" = {}
        tried = []
        for ns in _ABI_NAMESPACES:
            mangled_ns = "7%s" % ns          # length-prefixed namespace token
            fns = {}
            try:
                for key, tpl in _SYMBOLS.items():
                    sym = tpl.format(ns=mangled_ns)
                    tried.append(sym)
                    fns[key] = getattr(lib, sym)
            except AttributeError:
                continue
            self._fn = fns
            break
        if not self._fn:
            raise BridgeError("no known librados C++ ABI namespace matched; "
                              "symbols tried:\n  " + "\n  ".join(tried))
        self._fn["ioctx_operate"].restype = ctypes.c_int
        for key in ("op_ctor", "op_dtor", "set_redirect", "copy_from",
                    "tier_promote", "unset_manifest"):
            self._fn[key].restype = None

    def _run_op(self, dst_ioctx: ctypes.c_void_p, dst_oid: bytes, build) -> int:
        """Construct an ObjectWriteOperation, let `build(op)` add the op,
        submit it on dst_oid, destroy the operation, return the operate rc."""
        op = _OpBuf()
        self._fn["op_ctor"](ctypes.byref(op))
        try:
            build(op)
            name = _StdString.make(dst_oid)
            ioctx = _CxxIoCtx(impl=dst_ioctx.value)
            return self._fn["ioctx_operate"](ctypes.byref(ioctx),
                                             ctypes.byref(name),
                                             ctypes.byref(op))
        finally:
            self._fn["op_dtor"](ctypes.byref(op))

    def set_redirect(self, dst_ioctx, dst_oid, src_ioctx, src_oid, ver) -> int:
        def build(op):
            src = _StdString.make(src_oid)
            io = _CxxIoCtx(impl=src_ioctx.value)
            self._fn["set_redirect"](ctypes.byref(op), ctypes.byref(src),
                                     ctypes.byref(io), ctypes.c_uint64(ver),
                                     ctypes.c_int(0))
        return self._run_op(dst_ioctx, dst_oid, build)

    def copy_from(self, dst_ioctx, dst_oid, src_ioctx, src_oid, ver) -> int:
        def build(op):
            src = _StdString.make(src_oid)
            io = _CxxIoCtx(impl=src_ioctx.value)
            self._fn["copy_from"](ctypes.byref(op), ctypes.byref(src),
                                  ctypes.byref(io), ctypes.c_uint64(ver),
                                  ctypes.c_uint32(0))
        return self._run_op(dst_ioctx, dst_oid, build)

    def tier_promote(self, ioctx, oid) -> int:
        return self._run_op(ioctx, oid,
                            lambda op: self._fn["tier_promote"](ctypes.byref(op)))

    def unset_manifest(self, ioctx, oid) -> int:
        return self._run_op(ioctx, oid,
                            lambda op: self._fn["unset_manifest"](ctypes.byref(op)))


class _ShimOps:
    """The manifest ops via the compiled C-ABI shim (fallback backend)."""

    name = "shim"

    def __init__(self, shim_path: str):
        lib = ctypes.CDLL(shim_path)
        self._fn = {}
        for f in _SHIM_FUNCS:
            fn = getattr(lib, f)
            fn.restype = ctypes.c_int
            self._fn[f] = fn

    def set_redirect(self, dst_ioctx, dst_oid, src_ioctx, src_oid, ver) -> int:
        return self._fn["shim_set_redirect"](dst_ioctx, dst_oid, src_ioctx,
                                             src_oid, ctypes.c_uint64(ver))

    def copy_from(self, dst_ioctx, dst_oid, src_ioctx, src_oid, ver) -> int:
        return self._fn["shim_copy_from"](dst_ioctx, dst_oid, src_ioctx,
                                          src_oid, ctypes.c_uint64(ver))

    def tier_promote(self, ioctx, oid) -> int:
        return self._fn["shim_tier_promote"](ioctx, oid)

    def unset_manifest(self, ioctx, oid) -> int:
        return self._fn["shim_unset_manifest"](ioctx, oid)


def _find_or_build_shim(reasons: "list[str]") -> Optional[str]:
    """Locate (or compile) the fallback shim. Order: $PYMIGRATE_SHIM, a
    prebuilt .so next to the module, on-the-spot g++ build (needs
    <rados/librados.hpp>, package libradospp-devel on el9). Returns the .so
    path or None, appending human-readable reasons on each miss."""
    envp = os.environ.get("PYMIGRATE_SHIM")
    if envp:
        if os.path.exists(envp):
            return envp
        reasons.append("$PYMIGRATE_SHIM=%s does not exist" % envp)

    here = os.path.dirname(os.path.abspath(__file__))
    prebuilt = os.path.join(here, "shim", "rados_manifest_shim.so")
    if os.path.exists(prebuilt):
        return prebuilt
    reasons.append("no prebuilt %s" % prebuilt)

    src = os.path.join(here, "shim", "rados_manifest_shim.cpp")
    if not os.path.exists(src):
        reasons.append("shim source %s missing" % src)
        return None
    out = os.path.join(tempfile.gettempdir(),
                       "rados_manifest_shim_%d.so" % os.getuid())
    cmd = ["g++", "-shared", "-fPIC", "-std=c++17", "-O2", src,
           "-lrados", "-o", out]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
    except (OSError, subprocess.TimeoutExpired) as e:
        reasons.append("shim build failed to run g++: %s" % e)
        return None
    if proc.returncode != 0:
        reasons.append("shim build failed (is libradospp-devel installed for "
                       "<rados/librados.hpp>?):\n%s" % proc.stderr.strip())
        return None
    return out


class ManifestBridge:
    """Self-contained librados connection + the C++-only manifest ops.

    Owns its own C-API cluster handle and per-pool ioctxs (so redirect ops and
    version stats share one connection), independent of any python-rados
    connection the tools also hold. Context manager; close() is idempotent.
    """

    def __init__(self, conf_path: str = "/etc/ceph/ceph.conf",
                 client: str = "admin", force_shim: Optional[bool] = None):
        self._lib = ctypes.CDLL("librados.so.2", mode=ctypes.RTLD_GLOBAL)
        self._striper_lib = None
        self._cluster = None
        self._ioctxs = {}

        if force_shim is None:
            force_shim = os.environ.get("PYMIGRATE_FORCE_SHIM", "") not in ("", "0")

        reasons: "list[str]" = []
        ops = None
        if not force_shim:
            try:
                ops = _CtypesOps(self._lib)
            except BridgeError as e:
                reasons.append(str(e))
        else:
            reasons.append("PYMIGRATE_FORCE_SHIM set")
        if ops is None:
            shim = _find_or_build_shim(reasons)
            if shim is None:
                raise BridgeError(
                    "manifest ops unavailable — ctypes path and shim fallback "
                    "both failed:\n- " + "\n- ".join(reasons))
            ops = _ShimOps(shim)
        self._ops = ops
        self.backend = self._ops.name

        self._c_setup()
        self._connect(conf_path, client)

    # ---- C API plumbing --------------------------------------------------

    def _c_setup(self):
        lib = self._lib
        lib.rados_create2.argtypes = [ctypes.POINTER(ctypes.c_void_p),
                                      ctypes.c_char_p, ctypes.c_char_p,
                                      ctypes.c_uint64]
        lib.rados_conf_read_file.argtypes = [ctypes.c_void_p, ctypes.c_char_p]
        lib.rados_connect.argtypes = [ctypes.c_void_p]
        lib.rados_shutdown.argtypes = [ctypes.c_void_p]
        lib.rados_shutdown.restype = None
        lib.rados_ioctx_create.argtypes = [ctypes.c_void_p, ctypes.c_char_p,
                                           ctypes.POINTER(ctypes.c_void_p)]
        lib.rados_ioctx_destroy.argtypes = [ctypes.c_void_p]
        lib.rados_ioctx_destroy.restype = None
        lib.rados_write_full.argtypes = [ctypes.c_void_p, ctypes.c_char_p,
                                         ctypes.c_char_p, ctypes.c_size_t]
        lib.rados_read.argtypes = [ctypes.c_void_p, ctypes.c_char_p,
                                   ctypes.c_char_p, ctypes.c_size_t,
                                   ctypes.c_uint64]
        lib.rados_remove.argtypes = [ctypes.c_void_p, ctypes.c_char_p]
        lib.rados_rmxattr.argtypes = [ctypes.c_void_p, ctypes.c_char_p,
                                      ctypes.c_char_p]
        lib.rados_stat.argtypes = [ctypes.c_void_p, ctypes.c_char_p,
                                   ctypes.POINTER(ctypes.c_uint64),
                                   ctypes.POINTER(ctypes.c_long)]
        lib.rados_get_last_version.argtypes = [ctypes.c_void_p]
        lib.rados_get_last_version.restype = ctypes.c_uint64
        lib.rados_create_write_op.restype = ctypes.c_void_p
        lib.rados_create_write_op.argtypes = []
        lib.rados_write_op_create.argtypes = [ctypes.c_void_p, ctypes.c_int,
                                              ctypes.c_char_p]
        lib.rados_write_op_create.restype = None
        lib.rados_write_op_operate.argtypes = [ctypes.c_void_p, ctypes.c_void_p,
                                               ctypes.c_char_p, ctypes.c_void_p,
                                               ctypes.c_int]
        lib.rados_release_write_op.argtypes = [ctypes.c_void_p]
        lib.rados_release_write_op.restype = None

    def _connect(self, conf_path: str, client: str):
        cl = ctypes.c_void_p()
        rc = self._lib.rados_create2(ctypes.byref(cl), b"ceph",
                                     ("client.%s" % client).encode(),
                                     ctypes.c_uint64(0))
        if rc < 0:
            raise _rc_error("rados_create2", rc)
        rc = self._lib.rados_conf_read_file(cl, conf_path.encode())
        if rc < 0:
            self._lib.rados_shutdown(cl)
            raise _rc_error("rados_conf_read_file(%s)" % conf_path, rc)
        rc = self._lib.rados_connect(cl)
        if rc < 0:
            self._lib.rados_shutdown(cl)
            raise _rc_error("rados_connect", rc)
        self._cluster = cl

    def ioctx(self, pool: str) -> ctypes.c_void_p:
        """The bridge's raw rados_ioctx_t for a pool (cached)."""
        if pool not in self._ioctxs:
            io = ctypes.c_void_p()
            rc = self._lib.rados_ioctx_create(self._cluster, pool.encode(),
                                              ctypes.byref(io))
            if rc < 0:
                raise _rc_error("rados_ioctx_create(%s)" % pool, rc)
            self._ioctxs[pool] = io
        return self._ioctxs[pool]

    def close(self):
        for io in self._ioctxs.values():
            self._lib.rados_ioctx_destroy(io)
        self._ioctxs.clear()
        if self._cluster is not None:
            self._lib.rados_shutdown(self._cluster)
            self._cluster = None

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()
        return False

    # ---- primitive object ops (C API) ------------------------------------

    def stat(self, pool: str, oid: str) -> "tuple[int, int]":
        """(size, version) of an object — the version comes from this
        connection's last-op tracking, which is why redirect targets must be
        stat'ed through the bridge."""
        io = self.ioctx(pool)
        size = ctypes.c_uint64()
        mtime = ctypes.c_long()
        rc = self._lib.rados_stat(io, oid.encode(), ctypes.byref(size),
                                  ctypes.byref(mtime))
        if rc < 0:
            raise _rc_error("rados_stat(%s/%s)" % (pool, oid), rc)
        return size.value, self._lib.rados_get_last_version(io)

    def create_stub(self, pool: str, oid: str):
        """Ensure the object exists (idempotent create, no data)."""
        io = self.ioctx(pool)
        op = ctypes.c_void_p(self._lib.rados_create_write_op())
        try:
            self._lib.rados_write_op_create(op, 0, None)  # IDEMPOTENT
            rc = self._lib.rados_write_op_operate(op, io, oid.encode(), None, 0)
            if rc < 0:
                raise _rc_error("create stub %s/%s" % (pool, oid), rc)
        finally:
            self._lib.rados_release_write_op(op)

    def remove(self, pool: str, oid: str) -> int:
        return self._lib.rados_remove(self.ioctx(pool), oid.encode())

    def rmxattr(self, pool: str, oid: str, name: str) -> int:
        """Tolerant xattr removal (rc passed through; missing attr is fine)."""
        return self._lib.rados_rmxattr(self.ioctx(pool), oid.encode(),
                                       name.encode())

    def write_full(self, pool: str, oid: str, data: bytes):
        rc = self._lib.rados_write_full(self.ioctx(pool), oid.encode(),
                                        data, len(data))
        if rc < 0:
            raise _rc_error("rados_write_full(%s/%s)" % (pool, oid), rc)

    def read(self, pool: str, oid: str, size: int, offset: int = 0) -> bytes:
        io = self.ioctx(pool)
        out = bytearray()
        while len(out) < size:
            want = min(size - len(out), 4 * 1024 * 1024)
            buf = ctypes.create_string_buffer(want)
            n = self._lib.rados_read(io, oid.encode(), buf, want,
                                     ctypes.c_uint64(offset + len(out)))
            if n < 0:
                raise _rc_error("rados_read(%s/%s)" % (pool, oid), n)
            if n == 0:
                break
            out += buf.raw[:n]
        return bytes(out)

    # ---- the manifest ops -------------------------------------------------

    def set_redirect(self, dst_pool: str, dst_oid: str,
                     src_pool: str, src_oid: str, src_version: int):
        """Make dst a redirect stub at src (created WITHOUT a reference, so
        deleting a detached stub can never garbage-collect the source)."""
        rc = self._ops.set_redirect(self.ioctx(dst_pool), dst_oid.encode(),
                                    self.ioctx(src_pool), src_oid.encode(),
                                    src_version)
        if rc < 0:
            raise _rc_error("set_redirect %s/%s -> %s/%s"
                            % (dst_pool, dst_oid, src_pool, src_oid), rc)

    def copy_from(self, dst_pool: str, dst_oid: str,
                  src_pool: str, src_oid: str, src_version: int):
        """Server-side (OSD->OSD) copy of src into dst."""
        rc = self._ops.copy_from(self.ioctx(dst_pool), dst_oid.encode(),
                                 self.ioctx(src_pool), src_oid.encode(),
                                 src_version)
        if rc < 0:
            raise _rc_error("copy_from %s/%s <- %s/%s"
                            % (dst_pool, dst_oid, src_pool, src_oid), rc)

    def tier_promote(self, pool: str, oid: str):
        """Materialize a redirect stub into an owned copy of its target."""
        rc = self._ops.tier_promote(self.ioctx(pool), oid.encode())
        if rc < 0:
            raise _rc_error("tier_promote %s/%s" % (pool, oid), rc)

    def unset_manifest(self, pool: str, oid: str) -> int:
        """Detach a stub from its redirect target. Returns the raw rc:
        callers tolerate failures on objects that were never manifests
        (copy-mode owned objects), exactly like the C++ tools."""
        return self._ops.unset_manifest(self.ioctx(pool), oid.encode())

    # ---- self-test ---------------------------------------------------------

    def self_test(self, scratch_pool: str):
        """Round-trip a throwaway redirect in `scratch_pool` before any real
        write: source blob -> stub -> set_redirect -> read-through compare ->
        unset_manifest -> delete both. Raises BridgeError on any mismatch."""
        src = "pymigrate_selftest_src_%d" % os.getpid()
        dst = "pymigrate_selftest_dst_%d" % os.getpid()
        payload = os.urandom(4096)
        try:
            self.write_full(scratch_pool, src, payload)
            _, ver = self.stat(scratch_pool, src)
            self.create_stub(scratch_pool, dst)
            self.set_redirect(scratch_pool, dst, scratch_pool, src, ver)
            got = self.read(scratch_pool, dst, len(payload))
            if got != payload:
                raise BridgeError(
                    "self-test read-through mismatch (%d bytes vs %d) — "
                    "manifest-op ABI bridge unusable" % (len(got), len(payload)))
            rc = self.unset_manifest(scratch_pool, dst)
            if rc < 0:
                raise _rc_error("self-test unset_manifest", rc)
        finally:
            self.remove(scratch_pool, dst)
            self.remove(scratch_pool, src)

    # ---- libradosstriper read (verification for the reverse tool) ----------

    def _striper(self):
        if self._striper_lib is None:
            lib = ctypes.CDLL("libradosstriper.so.1")
            lib.rados_striper_create.argtypes = [ctypes.c_void_p,
                                                 ctypes.POINTER(ctypes.c_void_p)]
            lib.rados_striper_read.argtypes = [ctypes.c_void_p, ctypes.c_char_p,
                                               ctypes.c_char_p, ctypes.c_size_t,
                                               ctypes.c_uint64]
            lib.rados_striper_destroy.argtypes = [ctypes.c_void_p]
            lib.rados_striper_destroy.restype = None
            self._striper_lib = lib
        return self._striper_lib

    def striper_read(self, pool: str, soid: str, size: int) -> bytes:
        """Read a whole libradosstriper object (what stock XrdCeph serves)."""
        lib = self._striper()
        st = ctypes.c_void_p()
        rc = lib.rados_striper_create(self.ioctx(pool), ctypes.byref(st))
        if rc < 0:
            raise _rc_error("rados_striper_create(%s)" % pool, rc)
        try:
            out = bytearray()
            while len(out) < size:
                want = min(size - len(out), 4 * 1024 * 1024)
                buf = ctypes.create_string_buffer(want)
                n = lib.rados_striper_read(st, soid.encode(), buf, want,
                                           ctypes.c_uint64(len(out)))
                if n < 0:
                    raise _rc_error("rados_striper_read(%s)" % soid, n)
                if n == 0:
                    break
                out += buf.raw[:n]
            return bytes(out)
        finally:
            lib.rados_striper_destroy(st)


if __name__ == "__main__":      # python3 -m pymigrate.radosbridge [scratch_pool]
    import sys as _sys
    _pool = _sys.argv[1] if len(_sys.argv) > 1 else "xrdtest"
    with ManifestBridge() as _b:
        _b.self_test(_pool)
        print("radosbridge self-test OK (backend=%s)" % _b.backend)
