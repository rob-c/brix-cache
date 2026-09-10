"""2.0 F3 — the OssArc backup queue: a dataset seal is a durable stage request.

WHAT: behind ``tape://<adapter>/<base>?arc=<depth>`` the completion marker's
      commit no longer composes and ships the archive on the client's close.
      The archiver answers "publish deferred" (``BRIX_MSS_MIGRATE_DEFERRED``),
      the frm driver submits an ``archive`` request to the durable stage
      engine, and the engine drives the seal off the event loop with the
      same journal, ``brix_frm_fail_backoff`` retry, restart replay and
      ``brix_frm_fail_retries`` dead-letter discipline as a flush.
WHY:  the 2.0 readiness register (axis (e) F3) pulled parity-audit oss row
      3.5 out of "partial": a synchronous seal hung the client for minutes of
      tape work and a crash mid-seal left an unsealed dataset nothing would
      revisit.  Everything below pins a behaviour that used to be a mystery:
      the close returns before the seal, members freeze from the marker's
      acceptance (not the seal), a transient tape failure is retried, an
      exhausted one is dead-lettered with the members still readable, a
      queued seal survives SIGKILL, a forged ``archive`` record can never
      seal anything, and an engine-less server still seals inline.
HOW:  one exec-adapter lab (``lc-r20-arc-seal``) whose stage command copies
      to a local "tape" directory and obeys two flag files: ``tape-down``
      (the archive migrate fails) and ``tape-slow`` (it blocks until the flag
      is removed).  The StageEvents feed (F2) is the oracle for every engine
      and adapter transition.  The register row cites this module's test
      count -- keep it current.
"""
import errno
import os
import signal
import shutil
import struct
import subprocess
import time
from pathlib import Path
from urllib.parse import unquote

import pytest

from settings import BIND_HOST
from server_registry import NginxInstanceSpec
from official_interop_lib import worker_reachable

from _test_release20_metrics_helpers import wait_port
from test_phase115_tape_arc import (MARKER, _assert_recall_from_archive,
                                    _put, _put_ok, _put_refused, _read_ok,
                                    _sidecar, _tape_zip, kXR_ItExists,
                                    kXR_NotAuthorized)
from test_release20_frm_knobs import _deadletter_records, _script, _wait_deadletter
from test_xfer_wt_journal import (BRIX_SREQ_FAILED, F_ATTEMPTS, F_DST_KEY,
                                  F_KIND, F_STATE, SREQ_FMT, _cstr,
                                  _read_request, _request_paths)
import _test_session_bind_helpers as H

pytestmark = [pytest.mark.uses_lifecycle_harness,
              pytest.mark.xdist_group("lc-r20-arc-seal")]

_SERVER = "lc-r20-arc-seal"
TEMPLATE = "nginx_lc_r20_frm_knobs.conf"
REPO = Path(__file__).resolve().parents[1]

BRIX_STAGE_ARCHIVE = 4
MEMBERS = {"f1": b"one " * 300, "f2": b"two " * 500, "sub/f4": b"four" * 100}


# ------------------------------------------------------------- static pins --

def test_the_archive_kind_and_the_seal_slot_are_wired_end_to_end():
    """Success (static): the pieces the live cells rely on exist by name, so
    a refactor that drops one fails here with a message, not as a hang."""
    src = REPO / "src"
    engine_h = (src / "fs/xfer/stage_engine.h").read_text()
    assert "BRIX_STAGE_ARCHIVE   = 4" in engine_h
    assert "int brix_stage_on_loop(void);" in engine_h
    assert 'case BRIX_STAGE_ARCHIVE:   return "archive";' in \
        (src / "fs/xfer/stage_engine.c").read_text()
    assert "return stage_reconcile_archive(path, &rec, log);" in \
        (src / "fs/xfer/stage_engine_reconcile.c").read_text()
    assert ".seal          = arc_seal," in (src / "fs/backend/frm/sd_frm_arc.c").read_text()
    assert "return BRIX_MSS_MIGRATE_DEFERRED;" in \
        (src / "fs/backend/frm/sd_frm_arc_seal.c").read_text()
    assert "brix_sd_frm_set_export_root(inst, e->root_canon);" in \
        (src / "fs/vfs/vfs_backend_registry_source.c").read_text()
    assert "src/fs/backend/frm/sd_frm_arc_seal.c" in (REPO / "config").read_text()


def test_a_failed_mss_verb_reports_a_deterministic_errno():
    """Success (static): the drop-vs-retry verdict for a failing seal is read
    off errno (stage_seal_drop_reason), but the MSS verbs report by exit code
    and set no errno of their own -- whatever the runner last left behind was
    being read instead.  The shared verb wrapper closes that: a verb that
    fails without a reason reports EIO, which is not a drop reason."""
    ops = (REPO / "src/fs/backend/frm/sd_frm_mss_ops.c").read_text()
    assert 'return mss_invoke_verb(h, mss, "migrate", key, online);' in ops
    assert 'return mss_invoke_verb(h, mss, "recall", key, online);' in ops
    assert "errno = EIO;" in ops
    reconcile = (REPO / "src/fs/xfer/stage_engine_reconcile.c").read_text()
    for err in ("EINVAL", "ENOENT", "ENOTSUP"):
        assert f"case {err}:" in reconcile        # the drop set, EIO absent
    assert "case EIO:" not in reconcile


def test_the_archive_vocabulary_is_documented():
    """Success (static): the operator-facing words the feed emits for a seal
    are all in directives.md -- the F2 vocabulary test pins the event names,
    this pins the kind and the four F3 drop reasons."""
    doc = (REPO / "docs/03-configuration/directives.md").read_text()
    for word in ("`archive`", "`not-anchored`", "`no-tape-tier`",
                 "`not-a-marker`", "`not-online`", "`no-archiver`",
                 "`seal-done`", "`seal-failed`"):
        assert word in doc, f"{word} missing from directives.md"


# ------------------------------------------------------------------ live ----

def _feed_events(feed: Path):
    """[(source, event, reqid, key, {name: value})] in file order."""
    out = []
    try:
        lines = feed.read_text().splitlines()
    except FileNotFoundError:
        return out
    for line in lines:
        parts = line.split(" ")
        if len(parts) < 5:
            continue
        pairs = {}
        for pair in parts[5:]:
            name, _eq, value = pair.partition("=")
            pairs[name] = unquote(value)
        out.append((parts[1], parts[2], parts[3], unquote(parts[4]), pairs))
    return out


def _matches(ev, source, event, key, pairs):
    if ev[0] != source or ev[1] != event:
        return False
    if key is not None and ev[3] != key:
        return False
    return all(ev[4].get(n) == v for n, v in pairs.items())


def _find(feed: Path, source, event, key=None, **pairs):
    hits = [ev for ev in _feed_events(feed) if _matches(ev, source, event, key, pairs)]
    return hits[0] if hits else None


def _wait_event(feed: Path, source, event, key=None, timeout=20.0, **pairs):
    deadline = time.time() + timeout
    while time.time() < deadline:
        ev = _find(feed, source, event, key, **pairs)
        if ev is not None:
            return ev
        time.sleep(0.2)
    raise AssertionError(
        f"{source} {event} {key or ''} {pairs or ''} never reached the feed:\n"
        + "\n".join(str(e) for e in _feed_events(feed)[-25:]))


class _Lab:
    """One exec-adapter tape lab: ``buffer`` is the tape:// base (online
    buffer + sidecars), ``tape`` the stage command's store, ``flags`` the
    directory the stage command consults."""

    def __init__(self, tmp_path: Path):
        self.root = tmp_path
        self.buffer = tmp_path / "buffer"
        self.tape = tmp_path / "tape"
        self.flags = tmp_path / "flags"
        self.ns = tmp_path / "ns"
        self.cache = tmp_path / "cache"
        self.journal = tmp_path / "journal"          # the worker creates it
        self.feed = tmp_path / "stage.events"
        for d in (self.buffer, self.tape, self.flags, self.ns, self.cache):
            d.mkdir(exist_ok=True)
        worker_reachable(self.buffer, self.tape, self.flags, self.ns, self.cache,
                         tmp_path)
        self.stagecmd = _script(tmp_path, "arc-stagecmd.sh", (
            "  migrate)\n"
            "    case \"$2\" in *.brixarc.zip)\n"
            f"      [ -e {self.flags}/tape-down ] && exit 1\n"
            f"      while [ -e {self.flags}/tape-slow ]; do sleep 0.2; done ;;\n"
            "    esac\n"
            f"    mkdir -p \"{self.tape}/$(dirname \"$2\")\" && cp \"$3\" \"{self.tape}/$2\" ;;\n"
            f"  exists) [ -e \"{self.tape}/$2\" ] ;;\n"
            f"  recall) mkdir -p \"$(dirname \"$3\")\" && cp \"{self.tape}/$2\" \"$3\" ;;\n"))

    def flag(self, name, on=True):
        p = self.flags / name
        if on:
            p.write_text("")
        else:
            p.unlink(missing_ok=True)

    def directives(self, engine=True):
        """Without brix_frm the F1 knobs are inert, so the engine-less lab
        hands the stage command to the adapter through the environment."""
        frm = (f"brix_frm on; brix_frm_queue_path {self.journal}; "
               f"brix_frm_stagecmd {self.stagecmd}; "
               "brix_frm_fail_retries 2; brix_frm_fail_backoff 1s; "
               f"brix_frm_stagemsg {self.feed}; ") if engine else ""
        return (f"brix_export {self.ns}; brix_cache_store posix:{self.cache}; "
                f"brix_cache_export /; " + frm)

    def start(self, lifecycle, engine=True):
        ep = lifecycle.start(NginxInstanceSpec(
            name=_SERVER,
            template=TEMPLATE,
            protocol="root",
            env={} if engine else {"BRIX_FRM_STAGECMD": str(self.stagecmd)},
            template_values={"BIND_HOST": BIND_HOST,
                             "BACKEND": f"tape://exec{self.buffer}?arc=1",
                             "MAIN_DIRECTIVES": "",
                             "SERVER_DIRECTIVES": self.directives(engine)},
            reason="2.0 F3 OssArc backup queue (deferred dataset seal)"))
        assert wait_port(ep.port), f"{_SERVER} never became connectable"
        self.ep = ep
        return ep

    def start_again(self, lifecycle):
        """Bring the instance back up after lifecycle.stop().

        Not start(): the name is already registered for this test, and
        registering it twice is a ValueError.
        """
        self.ep = lifecycle.start_registered(_SERVER)
        assert wait_port(self.ep.port), f"{_SERVER} never came back"
        return self.ep

    def put_dataset(self, ds="ds1"):
        for name, data in MEMBERS.items():
            _put_ok(self.ep.port, f"/{ds}/{name}", data)

    def marker(self, ds="ds1"):
        return f"/{ds}/{MARKER}"

    def active_records(self):
        recs = []
        for path in _request_paths(str(self.journal)):
            rec = _read_request(path)
            if rec is not None and rec[F_KIND] == BRIX_STAGE_ARCHIVE:
                recs.append((path, rec))
        return recs

    def failed_record(self, timeout=10.0):
        """The FAILED archive record once the engine has persisted it."""
        deadline = time.time() + timeout
        while time.time() < deadline:
            failed = [r for _p, r in self.active_records()
                      if r[F_STATE] == BRIX_SREQ_FAILED]
            if failed:
                return failed[0]
            time.sleep(0.2)
        return None

    def requeue_deadletters(self):
        dead_dir = self.journal / "deadletter"
        for name in os.listdir(dead_dir):
            if name.endswith(".req"):
                shutil.move(str(dead_dir / name), str(self.journal / name))

    def assert_sealed(self, ds="ds1"):
        with __import__("zipfile").ZipFile(_tape_zip(self.tape, ds)) as zf:
            assert sorted(zf.namelist()) == sorted(MEMBERS)
            assert {n: zf.read(n) for n in MEMBERS} == MEMBERS
        assert _sidecar(self.buffer, ds).exists(), "no sidecar index: not sealed"
        assert (self.tape / ds / MARKER).exists(), "the marker itself must migrate"


def _craft_record(reqid: str, kind: int, dst_key: str, export_root: str,
                  state: int = BRIX_SREQ_FAILED) -> bytes:
    """A journal record exactly as the engine persists one (identity through
    cred.deny, the bearer never hits disk)."""
    return struct.pack(SREQ_FMT, reqid.encode(), kind, state, b"frm",
                       dst_key.encode(), b"frm", dst_key.encode(),
                       export_root.encode(), 0, 0, 0,
                       int(time.time()) - 60, 0, int(time.time()) - 30,
                       0, 0, b"", b"", b"", 0)


def test_the_marker_close_returns_before_the_seal_and_the_engine_seals_it(
        lifecycle, tmp_path):
    """Success: with the tape slow, the marker's close comes back at once,
    the feed shows the archive request queued/started while the seal is still
    in flight, and once the tape answers the archive, sidecar and marker land,
    the journal record is gone, and the members recall from the archive."""
    lab = _Lab(tmp_path)
    lab.start(lifecycle)
    lab.put_dataset()
    lab.flag("tape-slow")

    t0 = time.time()
    status, body = _put(lab.ep.port, lab.marker(), b"")
    took = time.time() - t0
    assert status == H.kXR_ok, body
    assert took < 5.0, f"the close waited {took:.1f}s for a blocked seal"

    queued = _wait_event(lab.feed, "engine", "queued", lab.marker(), kind="archive")
    _wait_event(lab.feed, "engine", "started", lab.marker())
    assert lab.active_records(), "no durable archive record while the seal runs"
    assert not _tape_zip(lab.tape, "ds1").exists(), "the seal finished while blocked"

    lab.flag("tape-slow", on=False)
    _wait_event(lab.feed, "frm", "seal-done", lab.marker())
    done = _wait_event(lab.feed, "engine", "done", lab.marker(), kind="archive")
    assert done[2] == queued[2], "done must close the reqid that was queued"
    lab.assert_sealed()
    assert lab.active_records() == [], "a completed seal must leave the journal"
    _assert_recall_from_archive(lab.ep.port, lab.buffer, "ds1", MEMBERS)


def test_a_transient_tape_failure_is_retried_by_the_backoff_sweep(
        lifecycle, tmp_path):
    """Error: the archive migrate fails once (tape down); the record is kept
    FAILED with the errno, the members stay readable, and the 1 s sweep
    re-drives it to completion once the tape is back."""
    lab = _Lab(tmp_path)
    lab.start(lifecycle)
    lab.put_dataset()
    lab.flag("tape-down")

    status, body = _put(lab.ep.port, lab.marker(), b"")
    assert status == H.kXR_ok, body
    failed = _wait_event(lab.feed, "frm", "seal-failed", lab.marker())
    assert failed[4]["errno"].isdigit() and int(failed[4]["errno"]) > 0
    _wait_event(lab.feed, "engine", "failed", lab.marker())
    assert lab.failed_record() is not None, \
        "a transient seal failure must persist a FAILED record"
    assert _read_ok(lab.ep.port, "/ds1/f1", len(MEMBERS["f1"])) == MEMBERS["f1"], \
        "members must stay readable while the seal is pending"

    lab.flag("tape-down", on=False)
    replayed = _wait_event(lab.feed, "engine", "replayed", lab.marker())
    assert int(replayed[4]["attempts"]) >= 1
    lab.assert_sealed()
    assert lab.active_records() == []


def test_a_stage_command_that_merely_exits_nonzero_is_never_read_as_a_drop(
        lifecycle, tmp_path):
    """Error (regression, 2026-09-09): a stage command that exits non-zero is
    an MSS failure -- retry it.  It used to be judged on a stale errno the
    verb never set: a leftover ENOENT read as "not-online" DROPPED the
    journaled record, losing a pending archive silently, and a leftover
    ECHILD merely mislabelled the log line.  The record must be kept FAILED,
    re-driven, and only ever leave the journal through the deadletter."""
    lab = _Lab(tmp_path)
    lab.start(lifecycle)
    lab.put_dataset()
    lab.flag("tape-down")

    assert _put(lab.ep.port, lab.marker(), b"")[0] == H.kXR_ok
    failed = _wait_event(lab.feed, "engine", "failed", lab.marker())
    assert int(failed[4]["errno"]) == errno.EIO, \
        f"a non-zero stage command reported errno {failed[4]['errno']}"
    dead = _wait_deadletter(lab.journal, MARKER)
    assert dead is not None, "the record was dropped instead of dead-lettered"
    assert _find(lab.feed, "engine", "dropped", lab.marker()) is None, \
        "a stage command that merely exited non-zero was read as a drop reason"


def test_an_exhausted_seal_is_dead_lettered_and_the_operator_re_queues_it(
        lifecycle, tmp_path):
    """Error + recovery: tape down for good -> two re-drives -> deadletter/
    (reason unreachable), members still readable, dataset still frozen.  The
    operator fixes the tape, moves the record back and restarts: the restart
    reconcile replays it and the dataset seals."""
    lab = _Lab(tmp_path)
    lab.start(lifecycle)
    lab.put_dataset()
    lab.flag("tape-down")

    assert _put(lab.ep.port, lab.marker(), b"")[0] == H.kXR_ok
    dead = _wait_deadletter(lab.journal, MARKER)
    assert dead is not None, "the FAILED archive record was never dead-lettered"
    assert dead[F_KIND] == BRIX_STAGE_ARCHIVE and dead[F_ATTEMPTS] == 2
    _wait_event(lab.feed, "engine", "deadletter", lab.marker(), reason="unreachable")
    assert lab.active_records() == []
    assert _read_ok(lab.ep.port, "/ds1/f2", len(MEMBERS["f2"])) == MEMBERS["f2"]
    _put_refused(lab.ep.port, "/ds1/late", kXR_NotAuthorized)
    assert not _tape_zip(lab.tape, "ds1").exists()

    lab.flag("tape-down", on=False)
    lab.requeue_deadletters()
    lifecycle.restart(_SERVER)
    assert wait_port(lab.ep.port)
    _wait_event(lab.feed, "engine", "replayed", lab.marker())
    lab.assert_sealed()
    assert _deadletter_records(lab.journal) == []


def test_a_queued_seal_survives_a_worker_sigkill_and_replays(
        lifecycle, tmp_path):
    """Success (durability): the worker dies mid-seal; the respawned worker's
    restart reconcile finds the journaled archive request and seals."""
    lab = _Lab(tmp_path)
    lab.start(lifecycle)
    lab.put_dataset()
    lab.flag("tape-slow")

    assert _put(lab.ep.port, lab.marker(), b"")[0] == H.kXR_ok
    _wait_event(lab.feed, "engine", "started", lab.marker())
    lifecycle.kill_worker(_SERVER, signal.SIGKILL)
    subprocess.run(["pkill", "-f", str(lab.stagecmd)], check=False)   # the orphaned child
    lab.flag("tape-slow", on=False)

    replayed = _wait_event(lab.feed, "engine", "replayed", lab.marker(), timeout=30)
    assert replayed[4]["attempts"] == "0", "a replay after a crash is not a retry"
    lab.assert_sealed()
    assert lab.active_records() == []
    assert wait_port(lab.ep.port)
    assert _read_ok(lab.ep.port, "/ds1/sub/f4", len(MEMBERS["sub/f4"])) == MEMBERS["sub/f4"]


def test_members_freeze_from_the_marker_not_from_the_seal(lifecycle, tmp_path):
    """Security-negative: while the seal is pending a member write is refused
    kXR_NotAuthorized and a second marker kXR_ItExists -- nothing can slip a
    file into a dataset between its marker and its archive."""
    lab = _Lab(tmp_path)
    lab.start(lifecycle)
    lab.put_dataset()
    lab.flag("tape-slow")

    assert _put(lab.ep.port, lab.marker(), b"")[0] == H.kXR_ok
    _wait_event(lab.feed, "engine", "started", lab.marker())
    _put_refused(lab.ep.port, "/ds1/smuggled", kXR_NotAuthorized)
    _put_refused(lab.ep.port, "/ds1/sub/smuggled", kXR_NotAuthorized)
    _put_refused(lab.ep.port, lab.marker(), kXR_ItExists)
    assert not (lab.buffer / ".online/ds1/smuggled").exists()

    lab.flag("tape-slow", on=False)
    _wait_event(lab.feed, "engine", "done", lab.marker(), kind="archive")
    lab.assert_sealed()                     # exactly MEMBERS, nothing smuggled
    _put_refused(lab.ep.port, "/ds1/after", kXR_NotAuthorized)
    _put_refused(lab.ep.port, lab.marker(), kXR_ItExists)


def _plant_forged(lab, forged):
    for reqid, (key, root, _why) in forged.items():
        (lab.journal / f"{reqid}.req").write_bytes(
            _craft_record(reqid, BRIX_STAGE_ARCHIVE, key, root))


def _assert_each_dropped(lab, forged):
    for reqid, (key, _root, why) in forged.items():
        ev = _wait_event(lab.feed, "engine", "dropped", key, reason=why)
        assert ev[2] == reqid, ev


def test_a_forged_archive_record_cannot_seal_anything(lifecycle, tmp_path):
    """Security-negative: crafted archive records dropped into the journal
    (a member key, an unanchored one, one anchored to a non-tape export) are
    dropped with a reason on replay and never touch the tape."""
    lab = _Lab(tmp_path)
    lab.start(lifecycle)
    lab.put_dataset()
    lifecycle.stop(_SERVER)

    forged = {
        "forged-1-member": ("/ds1/f1", os.path.realpath(lab.ns), "not-a-marker"),
        "forged-2-unanchored": (lab.marker(), "", "not-anchored"),
        "forged-3-elsewhere": (lab.marker(), str(tmp_path / "not-an-export"),
                               "no-tape-tier"),
    }
    _plant_forged(lab, forged)

    lab.start_again(lifecycle)
    _assert_each_dropped(lab, forged)
    assert lab.active_records() == []
    assert _deadletter_records(lab.journal) == []
    assert not _tape_zip(lab.tape, "ds1").exists(), "a forged record sealed the dataset"
    assert not _sidecar(lab.buffer, "ds1").exists()
    assert _find(lab.feed, "engine", "dropped", reason="corrupt") is None, \
        "the crafted records were rejected as corrupt, so nothing above was exercised"
    _put_ok(lab.ep.port, "/ds1/still-open", b"x")   # the dataset never froze


def test_withdrawing_the_marker_drops_the_seal_and_reopens_the_dataset(
        lifecycle, tmp_path):
    """Error + recovery: the operator's other way out of a failing seal --
    delete the marker's online copy.  The next re-drive drops the record
    (reason not-online) instead of retrying forever, and the dataset accepts
    members again."""
    lab = _Lab(tmp_path)
    lab.start(lifecycle)
    lab.put_dataset()
    lab.flag("tape-down")

    assert _put(lab.ep.port, lab.marker(), b"")[0] == H.kXR_ok
    _wait_event(lab.feed, "engine", "failed", lab.marker())
    _put_refused(lab.ep.port, "/ds1/late", kXR_NotAuthorized)

    (lab.buffer / ".online/ds1" / MARKER).unlink()
    _wait_event(lab.feed, "engine", "dropped", lab.marker(), reason="not-online")
    assert lab.active_records() == []
    assert _deadletter_records(lab.journal) == []
    _put_ok(lab.ep.port, "/ds1/late", b"late")
    assert not _tape_zip(lab.tape, "ds1").exists()


def test_an_engine_less_server_still_seals_inline_on_close(lifecycle, tmp_path):
    """Success (fallback): without brix_frm there is no journal, so the marker's
    commit seals inline exactly as before F3 -- the archive exists when the
    close returns and no engine event is ever emitted."""
    lab = _Lab(tmp_path)
    lab.start(lifecycle, engine=False)
    lab.put_dataset()

    assert _put(lab.ep.port, lab.marker(), b"")[0] == H.kXR_ok
    lab.assert_sealed()
    assert not lab.journal.exists()
    assert not lab.feed.exists()
    _put_refused(lab.ep.port, "/ds1/late", kXR_NotAuthorized)
