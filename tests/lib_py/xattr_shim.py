"""``os.getxattr``/``setxattr``/``listxattr``/``removexattr`` for macOS Python.

CPython only exposes the extended-attribute functions in ``os`` on Linux.
Twelve test modules (and the helpers behind them) call ``os.getxattr`` &
co. directly to inspect the checksum / lock / pin attributes the module
writes, so on Darwin they raised ``AttributeError`` before reaching any
assertion.  ``install()`` adds ctypes-backed implementations with the Linux
signatures and semantics to the ``os`` module of THIS process when they are
missing; on Linux it is a no-op.

Semantics kept from Linux so callers need no branches:
  * paths may be ``str``, ``bytes``, ``os.PathLike`` or an open fd;
  * ``follow_symlinks=False`` maps to Darwin's ``XATTR_NOFOLLOW`` option;
  * ``os.XATTR_CREATE`` / ``os.XATTR_REPLACE`` carry the Linux values (1 / 2)
    and are translated to Darwin's (2 / 4);
  * a missing attribute raises ``OSError(errno.ENODATA)`` — Darwin reports
    ``ENOATTR`` (93), which ``errno.ENODATA`` (96) comparisons would miss.
"""
from __future__ import annotations

import ctypes
import ctypes.util
import errno
import os
import sys

XATTR_CREATE = 1        # Linux values, as os.XATTR_CREATE / os.XATTR_REPLACE
XATTR_REPLACE = 2
_DARWIN_NOFOLLOW = 0x0001
_DARWIN_CREATE = 0x0002
_DARWIN_REPLACE = 0x0004
_ENOATTR = 93


def _libc():
    return ctypes.CDLL(ctypes.util.find_library("c") or "/usr/lib/libc.dylib",
                       use_errno=True)


def _raise_errno():
    code = ctypes.get_errno()
    if code == _ENOATTR:
        code = errno.ENODATA
    raise OSError(code, os.strerror(code))


def _target(path):
    """(is_fd, path-bytes-or-fd) for the three call shapes ``os`` accepts."""
    if isinstance(path, int):
        return True, path
    return False, os.fsencode(path)


def _options(follow_symlinks, flags=0):
    opts = 0 if follow_symlinks else _DARWIN_NOFOLLOW
    if flags & XATTR_CREATE:
        opts |= _DARWIN_CREATE
    if flags & XATTR_REPLACE:
        opts |= _DARWIN_REPLACE
    return opts


def _get_raw(call, target, name, opts):
    """The attribute value, sized by a first probe call."""
    size = call(target, name, None, 0, 0, opts)
    if size < 0:
        _raise_errno()
    buf = ctypes.create_string_buffer(size or 1)
    got = call(target, name, buf, size, 0, opts)
    if got < 0:
        _raise_errno()
    return buf.raw[:got]


def _getxattr(path, attribute, *, follow_symlinks=True):
    libc = _libc()
    is_fd, target = _target(path)
    call = libc.fgetxattr if is_fd else libc.getxattr
    call.restype = ctypes.c_ssize_t
    return _get_raw(call, target, os.fsencode(attribute), _options(follow_symlinks))


def _setxattr(path, attribute, value, flags=0, *, follow_symlinks=True):
    libc = _libc()
    is_fd, target = _target(path)
    call = libc.fsetxattr if is_fd else libc.setxattr
    call.restype = ctypes.c_int
    value = bytes(value)
    if call(target, os.fsencode(attribute), value, len(value), 0,
            _options(follow_symlinks, flags)) < 0:
        _raise_errno()


def _list_raw(call, target, opts):
    """The NUL-separated name block, sized by a first probe call."""
    size = call(target, None, 0, opts)
    if size < 0:
        _raise_errno()
    if size == 0:
        return b""
    buf = ctypes.create_string_buffer(size)
    got = call(target, buf, size, opts)
    if got < 0:
        _raise_errno()
    return buf.raw[:got]


def _user_names(raw):
    """Darwin stamps files with its own attributes (com.apple.provenance,
    com.apple.quarantine); Linux callers only ever see the namespaces they
    wrote, so hide the system ones."""
    return [os.fsdecode(n) for n in raw.split(b"\0")
            if n and not n.startswith(b"com.apple.")]


def _listxattr(path=None, *, follow_symlinks=True):
    libc = _libc()
    is_fd, target = _target("." if path is None else path)
    call = libc.flistxattr if is_fd else libc.listxattr
    call.restype = ctypes.c_ssize_t
    return _user_names(_list_raw(call, target, _options(follow_symlinks)))


def _removexattr(path, attribute, *, follow_symlinks=True):
    libc = _libc()
    is_fd, target = _target(path)
    call = libc.fremovexattr if is_fd else libc.removexattr
    call.restype = ctypes.c_int
    if call(target, os.fsencode(attribute), _options(follow_symlinks)) < 0:
        _raise_errno()


def install() -> bool:
    """Add the xattr functions to ``os`` if this Python lacks them (Darwin)."""
    if hasattr(os, "getxattr") or sys.platform != "darwin":
        return False
    os.getxattr = _getxattr
    os.setxattr = _setxattr
    os.listxattr = _listxattr
    os.removexattr = _removexattr
    os.XATTR_CREATE = XATTR_CREATE
    os.XATTR_REPLACE = XATTR_REPLACE
    return True
