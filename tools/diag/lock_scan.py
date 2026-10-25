#!/usr/bin/env python3
"""Pre-upgrade inventory of live WebDAV locks per export (phase-107 C7).

WHAT: walk one or more export roots and list every resource carrying a LIVE
      (unexpired) lock record in its ``user.nginx_xrootd.lock`` xattr — the
      records the VFS lock gate will start refusing cross-protocol mutations
      for once ``brix_lock_enforcement strict`` is in effect.
WHY:  locks used to bind WebDAV clients only. An export upgraded to strict
      enforcement refuses ``root://``, S3, GridFTP and OCI writes under those
      same locks, so an operator must be able to look BEFORE upgrading. A
      stale long-lived lock found here is released with a WebDAV UNLOCK (or
      ``brix_webdav_lock_startup_sweep``), not by hand-editing xattrs.
HOW:  run from anywhere; roots are positional:

          python3 tools/diag/lock_scan.py /srv/export1 /srv/export2

      Decodes the schema-v2 pipe format (``v=2|token=..|owner=..|expires=..|
      scope=..|depth=..|null=..``). A legacy v1 record (no ``v=2``) carries a
      monotonic expiry that is meaningless across a reboot, so it is treated
      as already expired — exactly what brix_lock_record_decode() does.
      Expired records are counted but not listed (the gate treats them as
      absent; the writable WebDAV edge reaps them lazily). Lock TOKENS are
      bearer secrets and are never printed.

      Exit status: 0 = no live locks, 1 = live locks found, 2 = usage/IO error.
"""
import sys as _brix_log_sys
from pathlib import Path as _BrixLogPath
_brix_log_sys.path.insert(0, str(_BrixLogPath(__file__).resolve().parents[2]))
from tools.logging_support import diagnostic as _brix_diagnostic

import argparse
import ctypes
import ctypes.util
import errno
import os
import sys
import time

LOCK_XATTR = "user.nginx_xrootd.lock"


EXPIRED = "expired"                   # sentinel: a decoded record already lapsed


def _getxattr(path, name):
    """Read one xattr with the host API Python exposes.

    CPython exposes ``os.getxattr`` on Linux, not the BSDs. FreeBSD's native
    py-xattr package uses its user namespace without the Linux ``user.``
    prefix; Darwin has the six-argument libc ABI.
    """
    if hasattr(os, "getxattr"):
        return os.getxattr(path, name, follow_symlinks=False)
    if sys.platform.startswith('freebsd'):
        return _freebsd_getxattr(path, name)
    if sys.platform != "darwin":
        raise OSError(errno.ENOTSUP, "extended attributes are unavailable")
    return _darwin_getxattr(path, name)


def _freebsd_getxattr(path, name):
    """Use the existing native package; never fabricate an empty inventory."""
    try:
        import xattr
    except ImportError as error:
        raise OSError(errno.ENOTSUP, 'install the native FreeBSD py-xattr package') from error
    if not name.startswith('user.'):
        raise OSError(errno.ENOTSUP, 'only the user attribute namespace is supported')
    return xattr.getxattr(path, name[5:], symlink=True)


def _darwin_getxattr(path, name):
    """Read the link's own attribute through Darwin's no-follow ABI."""
    libc = ctypes.CDLL(ctypes.util.find_library("c") or "/usr/lib/libc.dylib",
                       use_errno=True)
    libc.getxattr.restype = ctypes.c_ssize_t
    target, attribute = os.fsencode(path), os.fsencode(name)
    size = libc.getxattr(target, attribute, None, 0, 0, 1)
    if size < 0:
        code = ctypes.get_errno()
        raise OSError(code, os.strerror(code))
    value = ctypes.create_string_buffer(size or 1)
    got = libc.getxattr(target, attribute, value, size, 0, 1)
    if got < 0:
        code = ctypes.get_errno()
        raise OSError(code, os.strerror(code))
    return value.raw[:got]


def _assign(rec, key, val):
    """Set one decoded field. Unparseable ints become 0, as the C decoder does."""
    if key not in ("expires", "v"):
        rec[key] = val
        return
    try:
        rec[key] = int(val)
    except ValueError:
        rec[key] = 0


def decode(raw):
    """Mirror brix_lock_record_decode(): pipe-separated key=val fields,
    unknown keys ignored, no token -> invalid, non-v2 -> expires forced to 0."""
    rec = {"token": "", "owner": "", "expires": 0,
           "scope": "shared", "depth": "0", "null": "0", "v": 0}
    for field in raw.decode("utf-8", errors="replace").split("|"):
        key, sep, val = field.partition("=")
        if sep and key in rec:
            _assign(rec, key, val)
    if not rec["token"]:
        return None
    if rec["v"] != 2:
        rec["expires"] = 0        # legacy monotonic expiry: already expired
    return rec


def probe(path, now):
    """One path's lock state: a live record, the EXPIRED sentinel, or None."""
    try:
        raw = _getxattr(path, LOCK_XATTR)
    except OSError as error:
        if error.errno in (getattr(errno, 'ENODATA', -1), getattr(errno, 'ENOATTR', -1)):
            return None
        raise                         # unreadable does not mean unlocked
    rec = decode(raw)
    if rec is None:
        return None
    return EXPIRED if rec["expires"] <= now else rec


def _walk(root):
    """Every path under root, root itself first — a Depth: infinity collection
    lock on the export root covers everything beneath it."""
    yield root
    for dirpath, dirnames, filenames in os.walk(root, onerror=_walk_error):
        for name in dirnames + filenames:
            yield os.path.join(dirpath, name)


def _walk_error(error):
    """An unreadable subtree must not disappear from a pre-upgrade inventory."""
    raise error


def scan_root(root, now):
    """Yield (path, rec) for every live lock under root, then a trailer
    ``(None, expired_count)``."""
    expired = 0
    for path in _walk(root):
        rec = probe(path, now)
        if rec is EXPIRED:
            expired += 1
        elif rec is not None:
            yield path, rec
    yield None, expired               # trailer: the expired count


def _format_lock(path, rec, now):
    kind = "lock-null" if rec["null"] == "1" else "lock"
    when = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(rec["expires"]))
    return (f"  LIVE {kind}  {path}\n"
            f"       owner={rec['owner'] or 'anonymous'}"
            f"  scope={rec['scope']}  depth={rec['depth']}"
            f"  expires in {rec['expires'] - now}s ({when})")


def report_root(root, now):
    """Print one export root's live locks; return how many there were."""
    live = expired = 0
    print(f"== {root}")
    for path, rec in scan_root(root, now):
        if path is None:
            expired = rec             # the trailer carries the expired count
            continue
        live += 1
        print(_format_lock(path, rec, now))
    print(f"  {live} live, {expired} expired (expired records are inert: "
          "the gate treats them as absent)")
    return live


def _parse_args(argv):
    ap = argparse.ArgumentParser(
        description="List live WebDAV locks per export root "
                    "(run before enabling brix_lock_enforcement strict).")
    ap.add_argument("roots", nargs="+", help="export root directories")
    return ap.parse_args(argv)


def _first_non_directory(roots):
    for root in roots:
        if not os.path.isdir(root):
            return root
    return None


def _report_total(live_total):
    if live_total:
        print(f"\n{live_total} live lock(s) total — under strict enforcement "
              "these refuse cross-protocol mutations until released or expired.")
    return 1 if live_total else 0


def main(argv=None):
    roots = _parse_args(argv).roots
    bad = _first_non_directory(roots)
    if bad is not None:
        _brix_diagnostic('ERROR', 'tools/diag/lock_scan.py', 'main', f"error: not a directory: {bad}", file=sys.stderr)
        return 2

    now = int(time.time())
    try:
        return _report_total(sum(report_root(root, now) for root in roots))
    except OSError as error:
        _brix_diagnostic('ERROR', 'tools/diag/lock_scan.py', 'inventory_incomplete',
                         f'lock inventory incomplete: errno={error.errno}', file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
