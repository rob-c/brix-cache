#!/usr/bin/env python3
"""xrdceph_cephfs_to_striper.py — REVERSE migration (Lancaster/Manchester):
expose an UNMOUNTED CephFS as stock-XrdCeph (libradosstriper) storage,
zero-move via RADOS redirects, then finalize to a self-owned XrdCeph layout
and drop CephFS. Pure-Python re-implementation of
xrdceph_cephfs_to_striper.cpp with identical semantics plus --json / --state /
--list / --prefix / --match / progress.

REQUIRES THE CEPHFS TO BE QUIESCED/UNMOUNTED (MDS down or fs failed, journal
flushed): the namespace is walked directly from RADOS (no mount, no
libcephfs), and the MDS must not be mutating objects underneath us. The
--assume-quiesced flag is the operator's assertion of that state and is
MANDATORY.

Default (ZERO-MOVE redirect): walk the CephFS namespace from the metadata
pool; for each file create striper-named redirect stubs <soid>.<stripe16> in
the target pool pointing at the CephFS data objects <ino>.<objno8>, and stamp
the striper layout + size xattrs so libradosstriper (XrdCeph) can read <soid>
= the file path. No data is copied; CephFS data stays the single copy.
Reversible with --rollback (detaches stubs first). The striper-side estate
MUST be served read-only until --finalize (a write to a stub writes THROUGH
to the CephFS object).

--finalize materializes each stub into an OWNED striper object (tier_promote,
in-cluster), decoupling from CephFS so the whole CephFS (metadata + data
pools) can be torn down; --delete-source (finalize only) then removes the
CephFS data objects.

The namespace walk CLASSIFIES and REPORTS everything it does not migrate
(hardlink aliases, symlinks, specials, other-pool files, snapshot dentries,
truncated fragtrees/xattr sets, SnapServer state); --report-only stops after
the classification.

USAGE:
  xrdceph_cephfs_to_striper.py <meta_pool> <cephfs_data_pool> <striper_pool>
      --assume-quiesced [--finalize] [--rollback] [--strip PFX] [--threads N]
      [--verify] [--delete-source] [--dry-run] [--report-only] [--conf PATH]
      [--json] [--state FILE] [--list FILE] [--prefix PFX] [--match GLOB]
      [--progress]

Exit codes: 0 all ok/skipped, 1 any per-file failure, 2 usage/guard error.
Requires python3-rados; redirect ops + striper verification go through
pymigrate.radosbridge (ctypes, shim fallback — see PYMIGRATE_FORCE_SHIM).
"""

import argparse
import os
import sys
from dataclasses import dataclass, field

sys.path.insert(0, os.path.dirname(os.path.realpath(__file__)))

import rados                                               # noqa: E402

from pymigrate import cephfs_meta, common                  # noqa: E402
from pymigrate.radosbridge import BridgeError, ManifestBridge  # noqa: E402

FIRST_SUFFIX = ".0000000000000000"


def parse_args(argv):
    ap = argparse.ArgumentParser(
        prog="xrdceph_cephfs_to_striper.py",
        description="Expose a QUIESCED CephFS as stock-XrdCeph "
                    "(libradosstriper) storage — zero-move redirects by "
                    "default.")
    ap.add_argument("meta_pool", nargs="?")
    ap.add_argument("cephfs_data_pool", nargs="?")
    ap.add_argument("striper_pool", nargs="?")
    ap.add_argument("--config",
                    default=os.environ.get("XRDCEPH_MIGRATE_CONF"),
                    help="site profile file (striper_pool/meta_pool/"
                         "data_pool/conf/client/strip); default "
                         "$XRDCEPH_MIGRATE_CONF")
    ap.add_argument("--assume-quiesced", dest="quiesced", action="store_true")
    ap.add_argument("--finalize", action="store_true")
    ap.add_argument("--rollback", action="store_true")
    ap.add_argument("--strip", default="")
    ap.add_argument("--threads", type=int, default=4)
    ap.add_argument("--verify", action="store_true")
    ap.add_argument("--delete-source", dest="delete_source", action="store_true")
    ap.add_argument("--dry-run", dest="dry_run", action="store_true")
    ap.add_argument("--report-only", dest="report_only", action="store_true")
    ap.add_argument("--conf", default=None,
                    help="ceph.conf (CLI > config file > $CEPH_CONF > "
                         "/etc/ceph/ceph.conf)")
    ap.add_argument("--json", dest="json_mode", action="store_true")
    ap.add_argument("--state", dest="state_file")
    ap.add_argument("--list", dest="list_file")
    ap.add_argument("--prefix")
    ap.add_argument("--match")
    ap.add_argument("--progress", action="store_true")
    args = ap.parse_args(argv)
    cfg = _load_config(ap, args.config)
    _resolve_arguments(ap, args, cfg)
    _validate_arguments(ap, args)
    return args


def _load_config(parser, path):
    try:
        return common.load_tool_config(path) if path else {}
    except (OSError, ValueError) as error:
        parser.error("--config: %s" % error)


def _resolve_arguments(parser, args, config):
    _validate_positionals(parser, args)
    args.meta_pool = common.resolve_setting(args.meta_pool, config, "meta_pool")
    args.cephfs_data_pool = common.resolve_setting(args.cephfs_data_pool, config,
                                                   "data_pool")
    args.striper_pool = common.resolve_setting(args.striper_pool, config,
                                               "striper_pool")
    _require_settings(parser, (
        ("meta_pool", args.meta_pool), ("data_pool", args.cephfs_data_pool),
        ("striper_pool", args.striper_pool),
    ))
    args.strip = common.resolve_setting(args.strip, config, "strip", "")
    args.conf = common.resolve_setting(
        args.conf, config, "conf",
        os.environ.get("CEPH_CONF", "/etc/ceph/ceph.conf"))
    args.client = common.resolve_setting(None, config, "client", "admin")


def _validate_positionals(parser, args):
    given = [
        value is not None
        for value in (args.meta_pool, args.cephfs_data_pool, args.striper_pool)
    ]
    if any(given) and not all(given):
        parser.error("give all three positionals (<meta_pool> <cephfs_data_pool> "
                     "<striper_pool>) or none (with --config)")


def _require_settings(parser, values):
    for key, value in values:
        if not value:
            parser.error("missing %s: pass positionals or set it in --config" % key)


def _validate_arguments(parser, args):
    if not args.quiesced:
        parser.error("refusing to run: pass --assume-quiesced (CephFS MUST be "
                     "unmounted / fs failed, journal flushed)")
    if args.delete_source and not args.finalize:
        parser.error("--delete-source is only valid with --finalize")
    if args.threads < 1:
        args.threads = 1


@dataclass
class FileEnt:
    """A migratable regular file discovered by the namespace walk."""
    soid: str = ""                 # logical path (the XrdCeph object id)
    ino: int = 0
    object_size: int = 0
    stripe_unit: int = 0
    stripe_count: int = 0
    size: int = 0
    cksum: bytes = b""             # carried user.XrdCks.adler32, or empty


@dataclass
class Classification:
    """What the walk found, for the operator report (mirrors the C++ tool)."""
    files: int = 0
    dirs: int = 0
    hardlink_files: int = 0       # primaries with nlink>1 (UNVERIFIED)
    hardlink_aliases: int = 0     # remote dentries (NOT migrated)
    symlinks: int = 0
    special: int = 0
    otherpool: int = 0
    frag_trunc: int = 0
    xattr_trunc: int = 0
    stats: cephfs_meta.WalkStats = field(default_factory=cephfs_meta.WalkStats)
    snaptable_last_snap: int = 0


class Migrator:
    """One run's shared state: connections, data-pool index, walk results."""

    def __init__(self, args, reporter, state):
        self.args = args
        self.rep = reporter
        self.state = state
        self.action = ("rollback" if args.rollback
                       else "finalize" if args.finalize else "migrate")
        self.mode = self.action if self.action != "migrate" else "redirect"

        self.cluster = rados.Rados(conffile=args.conf, rados_id=args.client)
        self.cluster.connect()
        self.meta = self.cluster.open_ioctx(args.meta_pool)
        self.cdata = self.cluster.open_ioctx(args.cephfs_data_pool)
        self.sp = self.cluster.open_ioctx(args.striper_pool)
        self.data_pool_id = self.cdata.get_pool_id() \
            if hasattr(self.cdata, "get_pool_id") else -1

        self.bridge = ManifestBridge(conf_path=args.conf, client=args.client)
        self.objs = {}                 # ino -> sorted [objno]
        self.files = []                # [FileEnt]
        self.cls = Classification()

    def close(self):
        self.bridge.close()
        self.meta.close()
        self.cdata.close()
        self.sp.close()
        self.cluster.shutdown()

    # ---- pass 1: index the CephFS data pool --------------------------------

    def index_data_pool(self):
        for obj in self.cdata.list_objects():
            key = obj.key if isinstance(obj.key, str) else obj.key.decode()
            dot = key.find(".")
            if dot <= 0:
                continue
            try:
                ino = int(key[:dot], 16)
                objno = int(key[dot + 1:], 16)
            except ValueError:
                continue
            self.objs.setdefault(ino, []).append(objno)
        for v in self.objs.values():
            v.sort()

    # ---- pass 2: walk the namespace from RADOS ------------------------------

    def _omap_reader(self, oid, start_after):
        """Page one fragment object's dentry omap via python-rados."""
        try:
            with rados.ReadOpCtx() as op:
                it, ret = self.meta.get_omap_vals(op, start_after.decode(
                    "utf-8", "surrogateescape"), "", 1024)
                self.meta.operate_read_op(op, oid)
                entries = [(k.encode("utf-8", "surrogateescape")
                            if isinstance(k, str) else k, v)
                           for k, v in it]
        except rados.ObjectNotFound:
            return [], False
        return entries, len(entries) == 1024

    def check_snaptable(self):
        """SnapServer last_snap >= 2 => CephFS snapshots have been created."""
        try:
            buf = self.meta.read("mds_snaptable", 1 << 20, 0)
        except rados.Error:
            return
        self.cls.snaptable_last_snap = cephfs_meta.snaptable_last_snap(buf)

    def warn_pool_snapshots(self):
        try:
            snaps = list(self.cdata.list_snaps())
        except (rados.Error, AttributeError):
            return
        if snaps:
            self.rep.note("WARN: data pool '%s' has %d RADOS pool "
                          "snapshot(s) — NOT migrated"
                          % (self.args.cephfs_data_pool, len(snaps)))

    def walk(self):
        """Collect migratable regular files + the classification counters."""
        for entry in cephfs_meta.walk_namespace(self._omap_reader, stats=self.cls.stats):
            file_entry = self._file_entry(entry)
            if file_entry is not None:
                self.files.append(file_entry)
                self.cls.files += 1

    def _file_entry(self, entry):
        if entry.undecodable:
            self.rep.warn("WARN undecodable dentry, skipped: " + entry.path)
            return None
        if entry.kind != "file":
            self._note_non_file(entry)
            return None
        if self._wrong_pool(entry):
            return None
        self._note_file_limits(entry)
        return self._regular_file(entry)

    def _note_non_file(self, entry):
        handlers = {
            "remote": self._note_remote, "dir": self._note_directory,
            "symlink": self._note_symlink, "special": self._note_special,
        }
        handlers[entry.kind](entry)

    def _note_remote(self, entry):
        self.cls.hardlink_aliases += 1
        self.rep.warn("HARDLINK-ALIAS (UNVERIFIED, NOT migrated): %s -> ino 0x%x"
                      % (entry.path, entry.dentry.remote_ino))

    def _note_directory(self, entry):
        self.cls.dirs += 1
        if entry.dentry.frags_truncated:
            self.cls.frag_trunc += 1
            self.rep.warn("WARN directory fragtree truncated (listing may be partial): "
                          + entry.path)

    def _note_symlink(self, entry):
        self.cls.symlinks += 1
        self.rep.warn("SYMLINK (skipped — XrdCeph has no symlinks): " + entry.path)

    def _note_special(self, entry):
        self.cls.special += 1
        mode = entry.dentry.inode.mode & cephfs_meta.S_IFMT
        self.rep.warn("SPECIAL FILE (type 0%o, skipped — no data objects): %s"
                      % (mode, entry.path))

    def _wrong_pool(self, entry):
        pool_id = entry.dentry.inode.layout.pool_id
        if self.data_pool_id < 0 or pool_id == self.data_pool_id:
            return False
        self.cls.otherpool += 1
        self.rep.warn("OTHER-POOL file (skipped — data in pool id %d, not the target "
                      "data pool): %s" % (pool_id, entry.path))
        return True

    def _note_file_limits(self, entry):
        dentry = entry.dentry
        if dentry.xattrs_truncated:
            self.cls.xattr_trunc += 1
            self.rep.warn("WARN inode xattr set truncated (some xattrs not carried): "
                          + entry.path)
        if dentry.inode.nlink > 1:
            self.cls.hardlink_files += 1
            self.rep.warn("HARDLINKED FILE nlink=%d (UNVERIFIED: primary path migrates, "
                          "the other %d name(s) will be ABSENT in XrdCeph): %s"
                          % (dentry.inode.nlink, dentry.inode.nlink - 1, entry.path))

    def _regular_file(self, entry):
        dentry = entry.dentry
        soid = entry.path[1:]
        if self.args.strip and soid.startswith(self.args.strip):
            soid = soid[len(self.args.strip):]
        return FileEnt(
            soid=soid, ino=dentry.inode.ino,
            object_size=dentry.inode.layout.object_size,
            stripe_unit=dentry.inode.layout.stripe_unit,
            stripe_count=dentry.inode.layout.stripe_count,
            size=dentry.inode.size,
            cksum=dentry.xattrs.get(b"user.XrdCks.adler32", b""),
        )

    def report_classification(self):
        c = self.cls
        snap_note = ("(SNAPSHOTS HAVE BEEN CREATED — .snap data NOT migrated)"
                     if c.snaptable_last_snap >= 2 else "(no snapshots)")
        self.rep.note(
            "\n==== CephFS namespace classification ====\n"
            "  regular files to migrate : %d\n"
            "  directories              : %d\n"
            "  -- NOT handled / flagged --\n"
            "  hardlinked files         : %d  (UNVERIFIED — primary path "
            "migrates; alias names dropped)\n"
            "  hardlink alias dentries  : %d  (skipped — XrdCeph has no "
            "hardlinks)\n"
            "  symlinks                 : %d  (skipped — no data objects)\n"
            "  special files (dev/fifo) : %d  (skipped — no data objects)\n"
            "  files in other data pools: %d  (skipped — data not in the "
            "target pool)\n"
            "  snapshotted dir entries  : %d  (CoW-diverged; SNAPSHOT DATA IS "
            "NOT MIGRATED)\n"
            "  SnapServer last_snap     : %d %s\n"
            "  truncated fragtrees      : %d\n"
            "  truncated xattr sets     : %d\n"
            "  undecodable dentries     : %d\n"
            "  NOTE: RADOS pool snapshots, RBD/RGW pools, additional CephFS "
            "file systems,\n"
            "        and CephFS snapshots (.snap) are OUT OF SCOPE for this "
            "tool.\n"
            "========================================="
            % (c.files, c.dirs, c.hardlink_files, c.hardlink_aliases,
               c.symlinks, c.special, c.otherpool, c.stats.snap_dentries,
               c.snaptable_last_snap, snap_note, c.frag_trunc, c.xattr_trunc,
               c.stats.undecodable))

    # ---- per-file operations -------------------------------------------------

    def _stamp(self, first, fe):
        """Write the striper bookkeeping xattrs libradosstriper reads."""
        for name, val in (("striper.layout.object_size", fe.object_size),
                          ("striper.layout.stripe_unit", fe.stripe_unit),
                          ("striper.layout.stripe_count", fe.stripe_count),
                          ("striper.size", fe.size)):
            self.sp.set_xattr(first, name, str(val).encode())
        if fe.cksum:
            self.sp.set_xattr(first, "user.XrdCks.adler32", fe.cksum)

    def _verify(self, fe):
        data = self.bridge.striper_read(self.args.striper_pool, fe.soid,
                                        fe.size)
        if len(data) != fe.size:
            return "short striper read (%d of %d bytes)" % (len(data), fe.size)
        if fe.cksum:
            want = fe.cksum.decode(errors="replace").lower()
            got = common.adler32_hex([data])
            if got != want:
                return "checksum mismatch (got %s want %s)" % (got, want)
        return None

    def stripe_name(self, soid, idx):
        return "%s.%016x" % (soid, idx)

    def data_name(self, ino, objno):
        return "%x.%08x" % (ino, objno)

    def _rollback_overlay(self, fe, objnos, first):
        """Detach + remove the striper overlay stubs (CephFS data intact)."""
        args = self.args
        if args.dry_run:
            self.rep.item(fe.soid, self.action, "skip",
                          detail="DRY-RUN rollback")
            return
        for objno in objnos:
            stub = self.stripe_name(fe.soid, objno)
            self.bridge.unset_manifest(args.striper_pool, stub)  # detach
            self.bridge.remove(args.striper_pool, stub)
        try:
            self.sp.remove_object(first)      # stripe-0 stamp object
        except rados.Error:
            pass
        self.rep.item(fe.soid, self.action, "ok",
                      detail=" striper overlay removed (CephFS data intact)")
        self.state.record(fe.soid, self.action, self.mode, "ok")

    def _already_stamped(self, fe, first):
        """Idempotency (redirect mode only — finalize re-touches the stamped
        soid deliberately): True when stripe 0 is already stamped at size."""
        if self.args.finalize:
            return False
        try:
            stamped = self.sp.get_xattr(first, "striper.size")
            return int(stamped.decode()) == fe.size
        except (rados.Error, ValueError):
            return False

    def _map_objects(self, fe, objnos):
        """Promote (finalize) or redirect-stub every data object. Returns
        False after recording the failure when any bridge op fails."""
        args = self.args
        for objno in objnos:
            src = self.data_name(fe.ino, objno)
            dst = self.stripe_name(fe.soid, objno)
            try:
                if args.finalize:
                    self.bridge.tier_promote(args.striper_pool, dst)
                    self.bridge.unset_manifest(args.striper_pool, dst)
                else:
                    _, ver = self.bridge.stat(args.cephfs_data_pool, src)
                    self.bridge.create_stub(args.striper_pool, dst)
                    self.bridge.set_redirect(args.striper_pool, dst,
                                             args.cephfs_data_pool, src, ver)
            except BridgeError as e:
                self.rep.item(fe.soid, self.action, "fail", error=str(e))
                self.state.record(fe.soid, self.action, self.mode, "fail")
                return False
        return True

    def _verify_or_fail(self, fe):
        """True when --verify is off or passes; records the failure otherwise."""
        if not self.args.verify:
            return True
        err = self._verify(fe)
        if err is not None:
            self.rep.item(fe.soid, self.action, "fail", error=err)
            self.state.record(fe.soid, self.action, self.mode, "fail")
            return False
        return True

    def _delete_cephfs_source(self, fe, objnos):
        """Remove the CephFS data objects behind a finalize; returns count."""
        deleted = 0
        for objno in objnos:
            try:
                self.cdata.remove_object(self.data_name(fe.ino, objno))
                deleted += 1
            except rados.Error:
                pass
        with self.rep._lock:                  # noqa: SLF001
            self.rep.deleted += deleted
        return deleted

    def process(self, fe):
        args = self.args
        objnos = self._object_numbers(fe)
        if objnos is None:
            return
        first = fe.soid + FIRST_SUFFIX
        if self._skip_process(fe, objnos, first):
            return
        if not self._map_objects(fe, objnos):
            return
        self._stamp(first, fe)
        if not self._verify_or_fail(fe):
            return
        self._complete_process(fe, objnos)

    def _object_numbers(self, fe):
        objnos = self.objs.get(fe.ino)
        if objnos is not None or fe.size <= 0:
            return objnos or []
        self.rep.item(fe.soid, self.action, "fail",
                      error="no data objects for ino 0x%x" % fe.ino)
        self.state.record(fe.soid, self.action, self.mode, "fail")
        return None

    def _skip_process(self, fe, objnos, first):
        if self.args.rollback:
            self._rollback_overlay(fe, objnos, first)
            return True
        if self._already_stamped(fe, first):
            self.rep.item(fe.soid, self.action, "skip", detail="already present")
            return True
        if not self.args.dry_run:
            return False
        mode = "finalize" if self.args.finalize else "redirect"
        self.rep.item(fe.soid, self.action, "skip",
                      detail="DRY-RUN %s %d bytes, %d obj" % (mode, fe.size, len(objnos)))
        return True

    def _complete_process(self, fe, objnos):
        deleted = self._delete_if_requested(fe, objnos)
        detail = self._process_detail(deleted)
        self.rep.item(fe.soid, self.action, "ok", nbytes=fe.size,
                      objects=len(objnos), detail=detail)
        self.state.record(fe.soid, self.action, self.mode, "ok",
                          bytes=fe.size)

    def _delete_if_requested(self, fe, objnos):
        if self.args.finalize and self.args.delete_source:
            return self._delete_cephfs_source(fe, objnos)
        return 0

    def _process_detail(self, deleted):
        return (" finalize" if self.args.finalize else " redirect") \
            + (", verified" if self.args.verify else "") \
            + (", cephfs data deleted" if deleted else "")


def main(argv=None):
    return common.tool_main(argv, parse_args, Migrator, _run)


def _run(args, mig, reporter, state):
    work = _prepare_work(args, mig, reporter)
    if work is None:
        return 0
    _announce_work(args, mig, reporter, work)
    _self_test(args, mig, work)
    worker = lambda entry: _process_entry(entry, mig, reporter, state)
    errors = common.run_parallel(work, worker, args.threads)
    _report_parallel_errors(errors, mig.action, reporter)
    return reporter.summary()


def _prepare_work(args, mig, reporter):
    mig.warn_pool_snapshots()
    mig.check_snaptable()
    reporter.note("indexing CephFS data pool...")
    mig.index_data_pool()
    reporter.note("walking CephFS namespace...")
    mig.walk()
    mig.report_classification()
    if args.report_only:
        reporter.note("--report-only: inventory complete, nothing migrated.")
        return None
    by_soid = {entry.soid: entry for entry in mig.files}
    names = common.filter_worklist(
        sorted(by_soid), args.list_file, args.prefix, args.match,
    )
    work = [by_soid[name] for name in names]
    reporter.total = len(work)
    return work


def _announce_work(args, mig, reporter, work):
    action = mig.action.upper() if mig.action != "migrate" else "redirect(zero-move)"
    reporter.note("xrdceph_cephfs_to_striper: %d file(s) (%s, %d worker(s), "
                  "bridge=%s%s%s)" % (
                      len(work), action, args.threads, mig.bridge.backend,
                      ", DRY-RUN" if args.dry_run else "",
                      ", verify" if args.verify else "",
                  ))


def _self_test(args, mig, work):
    if not args.dry_run and mig.action in ("migrate", "finalize") and work:
        mig.bridge.self_test(args.striper_pool)


def _process_entry(entry, mig, reporter, state):
    if state.done_ok(entry.soid, mig.action, mig.mode):
        reporter.item(entry.soid, mig.action, "skip", detail="state manifest: ok")
        return
    try:
        mig.process(entry)
    except (rados.Error, BridgeError, OSError) as error:
        reporter.item(entry.soid, mig.action, "fail",
                      error="%s: %s" % (type(error).__name__, error))
        state.record(entry.soid, mig.action, mig.mode, "fail")


def _report_parallel_errors(errors, action, reporter):
    for entry, error in errors:
        reporter.item(getattr(entry, "soid", str(entry)), action, "fail",
                      error="unhandled %s: %s" % (type(error).__name__, error))


if __name__ == "__main__":
    sys.exit(main())
