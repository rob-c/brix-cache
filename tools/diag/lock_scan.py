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
import argparse
import os
import sys
import time

LOCK_XATTR = "user.nginx_xrootd.lock"


EXPIRED = "expired"                   # sentinel: a decoded record already lapsed


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
        raw = os.getxattr(path, LOCK_XATTR, follow_symlinks=False)
    except OSError:
        return None                   # absent, unsupported, or unreadable
    rec = decode(raw)
    if rec is None:
        return None
    return EXPIRED if rec["expires"] <= now else rec


def _walk(root):
    """Every path under root, root itself first — a Depth: infinity collection
    lock on the export root covers everything beneath it."""
    yield root
    for dirpath, dirnames, filenames in os.walk(root):
        for name in dirnames + filenames:
            yield os.path.join(dirpath, name)


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
        print(f"error: not a directory: {bad}", file=sys.stderr)
        return 2

    now = int(time.time())
    return _report_total(sum(report_root(root, now) for root in roots))


if __name__ == "__main__":
    sys.exit(main())
