#!/usr/bin/env python3
"""xrdceph_striper_migrate.py — enable CephFS over an existing Glasgow/RAL
(libradosstriper / stock XrdCeph) RADOS pool. Pure-Python re-implementation of
xrdceph_striper_migrate.cpp with identical semantics plus --json / --state /
--prefix / --match / progress.

For every logical file the MDS builds the namespace (an empty file with a
layout matching the striper geometry allocates the inode + dentry +
backtrace), the checksum/xattrs are carried over, and the size is set via the
MDS. Striper and CephFS share Ceph's striping algorithm, so a file's object
index N maps to the same byte range in both; only the object NAME differs.

  --mode redirect  (DEFAULT, ZERO-MOVE) — a RADOS redirect stub at each
      <ino>.<objno> points at the existing striper object <soid>.<stripe>.
      No bytes copied; the source pool stays the single copy and is left
      intact. Reversible with --rollback. READ-ONLY ONLY: a write to a
      redirect-migrated file writes THROUGH to the source object, so the
      migrated CephFS MUST be served read-only until --finalize, or the
      original data is silently modified and rollback can no longer restore it.
  --mode copy — server-side copy_from (OSD->OSD): real owned copies,
      no host/WAN data movement, transient ~2x space. --delete-source
      reclaims the striper objects after verify (copy mode only).

--rollback removes the CephFS overlay for the listed/enumerated soids,
DETACHING every stub from its source first (a stub delete-throughs to its
target, so a plain unlink would destroy the source via the MDS purge).
--finalize materializes redirect stubs into owned objects (tier_promote,
in-cluster) so the result is a normal read-write CephFS and the striper pool
can be decommissioned.

USAGE:
  xrdceph_striper_migrate.py <striper_pool> <cephfs_data_pool> <dest_prefix>
      [--mode redirect|copy] [--rollback] [--finalize] [--list FILE]
      [--strip PFX] [--threads N] [--verify] [--delete-source] [--force]
      [--dry-run] [--conf PATH] [--json] [--state FILE] [--prefix PFX]
      [--match GLOB] [--progress]

Exit codes: 0 all ok/skipped, 1 any per-file failure, 2 usage/guard error.
Requires python3-rados + python3-cephfs; the redirect ops go through
pymigrate.radosbridge (ctypes, shim fallback — see PYMIGRATE_FORCE_SHIM).
"""

import argparse
import os
import re
import sys
import threading

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import cephfs                                              # noqa: E402
import rados                                               # noqa: E402

from pymigrate import common                               # noqa: E402
from pymigrate.radosbridge import BridgeError, ManifestBridge  # noqa: E402

STRIPE_RE_TPL = r"^%s\.(?P<idx>[0-9a-f]{16})$"
FIRST_SUFFIX = ".0000000000000000"
STRIPER_XATTRS = ("striper.layout.object_size", "striper.layout.stripe_unit",
                  "striper.layout.stripe_count", "striper.size",
                  "lock.striper.lock")


def parse_args(argv):
    ap = argparse.ArgumentParser(
        prog="xrdceph_striper_migrate.py",
        description="Migrate a libradosstriper (stock XrdCeph) pool into a "
                    "CephFS — zero-move redirects by default.")
    ap.add_argument("striper_pool")
    ap.add_argument("cephfs_data_pool")
    ap.add_argument("dest_prefix")
    ap.add_argument("--mode", choices=("redirect", "copy"), default="redirect")
    ap.add_argument("--rollback", action="store_true")
    ap.add_argument("--finalize", action="store_true")
    ap.add_argument("--list", dest="list_file")
    ap.add_argument("--strip", default="")
    ap.add_argument("--threads", type=int, default=4)
    ap.add_argument("--verify", action="store_true")
    ap.add_argument("--delete-source", dest="delete_source", action="store_true")
    ap.add_argument("--force", action="store_true")
    ap.add_argument("--dry-run", dest="dry_run", action="store_true")
    ap.add_argument("--conf", default=os.environ.get("CEPH_CONF",
                                                     "/etc/ceph/ceph.conf"))
    ap.add_argument("--json", dest="json_mode", action="store_true")
    ap.add_argument("--state", dest="state_file")
    ap.add_argument("--prefix")
    ap.add_argument("--match")
    ap.add_argument("--progress", action="store_true")
    args = ap.parse_args(argv)

    # --delete-source destroys the data the redirects point at.
    if args.delete_source and (args.mode == "redirect" or args.rollback):
        ap.error("--delete-source is invalid with --mode redirect / "
                 "--rollback (it would destroy the source data the "
                 "redirects reference)")
    if args.threads < 1:
        args.threads = 1
    return args


class Migrator:
    """One run's shared state: connections, the source-pool index, options."""

    def __init__(self, args, reporter, state):
        self.args = args
        self.rep = reporter
        self.state = state
        self.action = ("rollback" if args.rollback
                       else "finalize" if args.finalize else "migrate")

        self.cluster = rados.Rados(conffile=args.conf)
        self.cluster.connect()
        self.src = self.cluster.open_ioctx(args.striper_pool)
        self.dst = self.cluster.open_ioctx(args.cephfs_data_pool)

        self.fs = cephfs.LibCephFS(conffile=args.conf)
        self.fs.mount()

        self.bridge = ManifestBridge(conf_path=args.conf)
        self.index = {}
        self._dst_index = None
        self._dst_lock = threading.Lock()

    def close(self):
        self.bridge.close()
        try:
            self.fs.unmount()
            self.fs.shutdown()
        except cephfs.Error:
            pass
        self.src.close()
        self.dst.close()
        self.cluster.shutdown()

    def dst_stubs(self, ino):
        """The data-pool object indices belonging to an inode, found by
        enumerating the CephFS data pool (lazy, one pass, cached). Rollback
        and forced-overwrite detach MUST use this — the source-pool index
        cannot name the stubs once source objects are gone, and unlinking
        with attached stubs lets the async MDS purge delete-through into
        same-named (possibly re-created) source objects."""
        with self._dst_lock:
            if self._dst_index is None:
                pat = re.compile(r"^(?P<ino>[0-9a-f]+)\.(?P<objno>[0-9a-f]{8})$")
                index = {}
                for obj in self.dst.list_objects():
                    key = obj.key if isinstance(obj.key, str) else obj.key.decode()
                    m = pat.match(key)
                    if m is None:
                        continue
                    index.setdefault(int(m.group("ino"), 16), []).append(
                        int(m.group("objno"), 16))
                self._dst_index = index
        return sorted(self._dst_index.get(ino, []))

    # ---- discovery --------------------------------------------------------

    def warn_pool_snapshots(self):
        try:
            snaps = list(self.src.list_snaps())
        except (rados.Error, AttributeError):
            return
        if snaps:
            self.rep.note("WARN: striper pool '%s' has %d RADOS pool "
                          "snapshot(s) — these are NOT migrated (out of scope)"
                          % (self.args.striper_pool, len(snaps)))

    def index_source(self):
        """One pass over the source pool: soid -> sorted stripe indices.
        (The C++ tool rescans the whole pool per file — O(N^2); this is the
        Python tool's main performance fix.)"""
        pat = re.compile(r"^(?P<soid>.+)\.(?P<idx>[0-9a-f]{16})$")
        index = {}
        for obj in self.src.list_objects():
            key = obj.key if isinstance(obj.key, str) else obj.key.decode()
            m = pat.match(key)
            if m is None:
                continue
            index.setdefault(m.group("soid"), []).append(int(m.group("idx"), 16))
        for v in index.values():
            v.sort()
        self.index = index
        return sorted(index.keys())

    # ---- helpers ------------------------------------------------------------

    def _xattr_num(self, oid, name, default):
        try:
            return int(self.src.get_xattr(oid, name).decode())
        except (rados.Error, ValueError):
            return default

    def geometry(self, soid):
        """(object_size, stripe_unit, stripe_count, total_size) from the
        striper bookkeeping xattrs on stripe 0, or None if not a striper set."""
        first = soid + FIRST_SUFFIX
        osz = self._xattr_num(first, "striper.layout.object_size", -1)
        su = self._xattr_num(first, "striper.layout.stripe_unit", osz)
        sc = self._xattr_num(first, "striper.layout.stripe_count", 1)
        total = self._xattr_num(first, "striper.size", -1)
        if osz <= 0 or total < 0:
            return None
        return osz, su, sc, total

    def dest_path(self, soid):
        rel = soid
        if self.args.strip and rel.startswith(self.args.strip):
            rel = rel[len(self.args.strip):]
        return self.args.dest_prefix + "/" + rel.lstrip("/")

    def statx_quiet(self, path, want):
        try:
            return self.fs.statx(path.encode(), want, 0)
        except cephfs.Error:
            return None

    def mkparents(self, path):
        parent = os.path.dirname(path)
        if parent and parent != "/":
            try:
                self.fs.mkdirs(parent.encode(), 0o755)
            except cephfs.ObjectExists:
                pass

    def cephfs_adler32(self, path, size):
        """adler32 of the migrated CephFS file, or None on error/short read."""
        try:
            fd = self.fs.open(path.encode(), os.O_RDONLY)
        except cephfs.Error:
            return None
        try:
            a = 1
            got = 0
            import zlib
            while got < size:
                chunk = self.fs.read(fd, got, min(1 << 20, size - got))
                if not chunk:
                    break
                a = zlib.adler32(chunk, a)
                got += len(chunk)
            return ("%08x" % (a & 0xFFFFFFFF)) if got == size else None
        finally:
            self.fs.close(fd)

    def stripe_name(self, soid, idx):
        return "%s.%016x" % (soid, idx)

    def stub_name(self, ino, idx):
        return "%x.%08x" % (ino, idx)

    # ---- per-file operations -------------------------------------------------

    def migrate_one(self, soid):
        args = self.args
        indices = self.index.get(soid)
        if not indices:
            self.rep.item(soid, self.action, "fail",
                          error="no stripe objects found in source pool")
            self.state.record(soid, self.action, args.mode, "fail")
            return

        geo = self.geometry(soid)
        if geo is None:
            self.rep.item(soid, self.action, "fail",
                          error="not a striper object set")
            self.state.record(soid, self.action, args.mode, "fail")
            return
        osz, su, sc, total = geo
        cpath = self.dest_path(soid)

        # idempotency: already migrated at the right size?
        stx = self.statx_quiet(cpath, cephfs.CEPH_STATX_SIZE)
        if stx is not None and stx["size"] == total and not args.force:
            self.rep.item(soid, self.action, "skip", dest=cpath,
                          detail="already migrated")
            return

        if args.dry_run:
            self.rep.item(soid, self.action, "skip", dest=cpath,
                          detail="DRY-RUN %d bytes, os=%d su=%d sc=%d"
                                 % (total, osz, su, sc))
            return

        if stx is not None:
            # Clear a partial/forced target. DETACH its stubs first: the MDS
            # purge behind unlink is ASYNC and a still-attached redirect stub
            # DELETE-THROUGHS to the striper source when purged — without
            # this, a forced re-migrate destroys its own source objects
            # moments after verifying clean. (The C++ tool has this hazard.)
            old = self.statx_quiet(cpath, cephfs.CEPH_STATX_INO)
            if old is not None:
                for idx in self.dst_stubs(old["ino"]):
                    self.bridge.unset_manifest(args.cephfs_data_pool,
                                               self.stub_name(old["ino"], idx))
            self.fs.unlink(cpath.encode())

        # MDS: create the namespace entry with a layout matching the striper
        # geometry (must be set while the file is still empty).
        self.mkparents(cpath)
        fd = self.fs.open(cpath.encode(), os.O_CREAT | os.O_WRONLY | os.O_TRUNC,
                          0o644)
        for name, val in (("ceph.file.layout.object_size", osz),
                          ("ceph.file.layout.stripe_unit", su),
                          ("ceph.file.layout.stripe_count", sc)):
            self.fs.fsetxattr(fd, name, str(val).encode(), 0)
        self.fs.close(fd)

        stx = self.statx_quiet(cpath, cephfs.CEPH_STATX_INO)
        if stx is None:
            self.rep.item(soid, self.action, "fail", error="statx after create")
            self.state.record(soid, self.action, args.mode, "fail")
            return
        ino = stx["ino"]

        # map every stripe object into the CephFS-named data object
        for idx in indices:
            src_name = self.stripe_name(soid, idx)
            dst_name = self.stub_name(ino, idx)
            try:
                _, ver = self.bridge.stat(args.striper_pool, src_name)
                if args.mode == "redirect":
                    self.bridge.create_stub(args.cephfs_data_pool, dst_name)
                    self.bridge.set_redirect(args.cephfs_data_pool, dst_name,
                                             args.striper_pool, src_name, ver)
                else:
                    self.bridge.copy_from(args.cephfs_data_pool, dst_name,
                                          args.striper_pool, src_name, ver)
                    if idx == 0:
                        for j in STRIPER_XATTRS:
                            self.bridge.rmxattr(args.cephfs_data_pool,
                                                dst_name, j)
            except BridgeError as e:
                self.rep.item(soid, self.action, "fail", error=str(e))
                self.state.record(soid, self.action, args.mode, "fail")
                return

        # carry user.* xattrs (checksums etc.) onto the CephFS file
        carried_cksum = b""
        first = soid + FIRST_SUFFIX
        try:
            for name, val in self.src.get_xattrs(first):
                if not name.startswith("user."):
                    continue
                self.fs.setxattr(cpath.encode(), name, val, 0)
                if name == "user.XrdCks.adler32":
                    carried_cksum = val
        except rados.Error:
            pass

        # MDS: set the size
        self.fs.truncate(cpath.encode(), total)

        # verify
        if args.verify:
            if carried_cksum:
                got = self.cephfs_adler32(cpath, total)
                want = carried_cksum.decode(errors="replace").lower()
                if got is None or got != want:
                    self.rep.item(soid, self.action, "fail",
                                  error="checksum mismatch (got %s want %s)"
                                        % (got, want))
                    self.state.record(soid, self.action, args.mode, "fail")
                    return
            else:
                stx = self.statx_quiet(cpath, cephfs.CEPH_STATX_SIZE)
                if stx is None or stx["size"] != total:
                    self.rep.item(soid, self.action, "fail",
                                  error="size verify")
                    self.state.record(soid, self.action, args.mode, "fail")
                    return

        # optionally delete the source after a clean copy-migrate (+verify)
        deleted = 0
        if args.delete_source:
            for idx in indices:
                if self.src.remove_object(self.stripe_name(soid, idx)) is None:
                    deleted += 1
            try:
                self.src.remove_object(soid)        # bare control object, if any
            except rados.Error:
                pass
            with self.rep._lock:                    # noqa: SLF001
                self.rep.deleted += deleted

        detail = (" redirect" if args.mode == "redirect" else "") \
            + (", verified" if args.verify else "") \
            + (", source deleted" if args.delete_source else "")
        self.rep.item(soid, self.action, "ok", nbytes=total,
                      objects=len(indices), dest=cpath, detail=detail)
        self.state.record(soid, self.action, args.mode, "ok", bytes=total)

    def rollback_one(self, soid):
        """Remove the CephFS overlay for one soid, source left intact. A stub
        DELETE-THROUGHS to its source, so every stub is DETACHED
        (unset_manifest) before the unlink triggers the MDS purge."""
        args = self.args
        cpath = self.dest_path(soid)
        stx = self.statx_quiet(cpath, cephfs.CEPH_STATX_INO)
        if stx is None:
            self.rep.item(soid, self.action, "skip", dest=cpath,
                          detail="not present")
            return
        if args.dry_run:
            self.rep.item(soid, self.action, "skip", dest=cpath,
                          detail="DRY-RUN rollback")
            return
        ino = stx["ino"]
        for idx in self.dst_stubs(ino):
            # no-op on owned (copy-mode) objects, like the C++ tool
            self.bridge.unset_manifest(args.cephfs_data_pool,
                                       self.stub_name(ino, idx))
        try:
            self.fs.unlink(cpath.encode())
        except cephfs.Error as e:
            self.rep.item(soid, self.action, "fail", error="unlink: %s" % e)
            self.state.record(soid, self.action, args.mode, "fail")
            return
        self.rep.item(soid, self.action, "ok", dest=cpath,
                      detail=" stubs detached first; source intact")
        self.state.record(soid, self.action, args.mode, "ok")

    def finalize_one(self, soid):
        """Materialize a redirect-migrated file into owned CephFS objects
        (tier_promote + detach + strip striper bookkeeping) so the source
        striper pool becomes droppable."""
        args = self.args
        cpath = self.dest_path(soid)
        stx = self.statx_quiet(cpath, cephfs.CEPH_STATX_INO)
        if stx is None:
            self.rep.item(soid, self.action, "skip", dest=cpath,
                          detail="not migrated")
            return
        if args.dry_run:
            self.rep.item(soid, self.action, "skip", dest=cpath,
                          detail="DRY-RUN finalize")
            return
        ino = stx["ino"]
        n = 0
        for idx in self.index.get(soid, []):
            dst = self.stub_name(ino, idx)
            try:
                self.bridge.tier_promote(args.cephfs_data_pool, dst)
            except BridgeError as e:
                self.rep.item(soid, self.action, "fail", error=str(e))
                self.state.record(soid, self.action, args.mode, "fail")
                return
            self.bridge.unset_manifest(args.cephfs_data_pool, dst)
            for j in STRIPER_XATTRS:
                self.bridge.rmxattr(args.cephfs_data_pool, dst, j)
            n += 1
        self.rep.item(soid, self.action, "ok", objects=n, dest=cpath,
                      detail=" materialized; source now droppable")
        self.state.record(soid, self.action, args.mode, "ok")


def main(argv=None):
    args = parse_args(argv if argv is not None else sys.argv[1:])
    state = common.StateManifest(args.state_file)
    rep = common.Reporter(json_mode=args.json_mode,
                          progress=args.progress or sys.stderr.isatty())
    mig = Migrator(args, rep, state)
    try:
        mig.warn_pool_snapshots()
        enumerated = mig.index_source()
        work = common.filter_worklist(enumerated, args.list_file,
                                      args.prefix, args.match)
        rep.total = len(work)

        action = mig.action
        rep.note("xrdceph_striper_migrate: %d file(s) to consider "
                 "(%s, mode=%s, %d worker(s), dest %s, bridge=%s%s%s%s)"
                 % (len(work), action.upper() if action != "migrate" else
                    "migrate", args.mode, args.threads, args.dest_prefix,
                    mig.bridge.backend,
                    ", DRY-RUN" if args.dry_run else "",
                    ", verify" if args.verify else "",
                    ", delete-source" if args.delete_source else ""))

        # prove the redirect chain works before any real migration write
        if not args.dry_run and action in ("migrate", "finalize") and work:
            mig.bridge.self_test(args.cephfs_data_pool)

        def worker(soid):
            if state.done_ok(soid, action, args.mode) and not args.force:
                rep.item(soid, action, "skip", detail="state manifest: ok")
                return
            try:
                if action == "rollback":
                    mig.rollback_one(soid)
                elif action == "finalize":
                    mig.finalize_one(soid)
                else:
                    mig.migrate_one(soid)
            except (rados.Error, cephfs.Error, BridgeError, OSError) as e:
                rep.item(soid, action, "fail", error="%s: %s"
                         % (type(e).__name__, e))
                state.record(soid, action, args.mode, "fail")

        errors = common.run_parallel(work, worker, args.threads)
        for soid, exc in errors:
            rep.item(str(soid), action, "fail",
                     error="unhandled %s: %s" % (type(exc).__name__, exc))
        return rep.summary()
    finally:
        state.close()
        mig.close()


if __name__ == "__main__":
    sys.exit(main())
