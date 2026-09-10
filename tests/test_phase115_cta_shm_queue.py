"""
tests/test_phase115_cta_shm_queue.py — phase-115 W8.6: the CTA request queue
moved out of a per-worker process global into ONE shared-memory zone.

THE DEFECT.  ``cta_service.c`` held ``static brix_cta_queue_t *g_cta_queue``,
which is per-process.  Every worker replayed the same journal, so every worker
set ``next_id`` to the same ``max+1``, and every worker then allocated from its
own private copy — **two workers handed out the same request id**.  A ``query``
or ``cancel`` naming id 7 landed on whichever worker the connection happened to
reach, and could act on a different request than the client was told about.
That is a correctness bug visible to clients, not an internal tidy-up, and it
retires the "cross-worker SHM queue is deferred" ADR in ``svc_cta/README.md``.

The live class is the decisive one: two workers, concurrent submits, and every
id in the shared journal must be distinct.  Under the old code the id sequence
restarted in each worker, so the same ids appear twice.

The source classes pin the four design choices the fix rests on, each of which
would be silently undone by a plausible future edit:

  * the queue holds NO process-local pointers, because it is laid out in shared
    memory (the ``FILE *journal`` and the per-entry ``void *queue``
    back-pointer both had to go);
  * the locking lives in ``cta_shm.c``, not ``cta_queue.c``, so the queue stays
    pure C and its standalone suite still builds with ``gcc -Isrc``;
  * the zone lock is taken per transition and never across an executor run, via
    the ``cta_progress_t::transition`` seam;
  * one zone means one journal, so two server blocks naming different journals
    get a config-time WARN naming the ignored one — never a silent pick, never
    a failed config.

Run:
    TEST_SKIP_SERVER_SETUP=1 PYTHONPATH=tests pytest \
        tests/test_phase115_cta_shm_queue.py -v
"""

import concurrent.futures
import os
import re
import shutil
import subprocess

import pytest

from server_registry import NginxInstanceSpec
from settings import HOST
from test_ssi_async import _submit, kXR_waitresp
from test_ssi_cta import (CTA_RSP_SUCCESS, _collect_pushed_response,
                          build_request)
from test_ssi_wire import _handshake_login, _open_ssi

# Every class here shares one fixed-port lifecycle endpoint, so the whole
# module must stay on one xdist worker.
pytestmark = pytest.mark.xdist_group("lc-p115-cta-shm")

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SVC = os.path.join(REPO, "src/protocols/ssi/svc_cta")

CFLAGS = ["-std=c11", "-Wall", "-Wextra", "-Werror", "-Isrc",
          "-Isrc/protocols/ssi/svc_cta"]


def _src(rel):
    with open(os.path.join(REPO, rel), encoding="utf-8") as fh:
        return fh.read()


def _fn_body(text, name):
    """The body of the C function `name`, from its definition to the closing
    brace in column 0.

    Splitting on a bare occurrence count is what this replaces: `->init =
    cta_shm_init_zone;` and a doc comment naming the function are both
    occurrences, so the index that means "the body" moves whenever someone
    writes about the function.
    """
    defn = re.search(r"^" + re.escape(name) + r"\(", text, re.M)
    assert defn is not None, f"no definition of {name}()"
    body = text[defn.start():]
    end = body.find("\n}\n")
    assert end != -1, f"{name}() has no closing brace in column 0"
    return body[:end]


def _struct_body(text, name):
    """The members of `typedef struct { ... } name;` — the LAST such opener
    before the closing tag, so the comment above it (which names the removed
    `void *journal` and `void *queue` deliberately) is not read as a member."""
    close = text.index("} " + name + ";")
    open_at = text.rindex("typedef struct {", 0, close)
    return text[open_at:close]


# --------------------------------------------------------------------------- #
# A. The queue left its process global.                                        #
# --------------------------------------------------------------------------- #

class TestTheQueueLeftItsProcessGlobal:

    def test_the_per_worker_queue_global_is_gone(self):
        """The defect itself: a file-static queue pointer, one per process."""
        text = _src("src/protocols/ssi/svc_cta/cta_service.c")
        assert "g_cta_queue" not in text, \
            "the per-worker CTA queue global is back; every worker will " \
            "replay the journal into its own copy and hand out colliding ids"

    def test_the_service_never_creates_its_own_queue(self):
        """cta_queue_create() mallocs a PRIVATE queue.  The service must take
        the shared one; the standalone unit suites are what create() is for."""
        text = _src("src/protocols/ssi/svc_cta/cta_service.c")
        assert "cta_queue_create" not in text, \
            "cta_service.c allocates its own queue again"

    def test_the_service_refuses_when_the_zone_is_absent(self):
        """ERROR PATH.  No zone must mean a clean refusal, NOT a fallback to a
        private queue — that fallback is precisely the defect."""
        text = _src("src/protocols/ssi/svc_cta/cta_service.c")
        assert "brix_cta_shm_queue() == NULL" in text, \
            "the service no longer checks for a missing zone"
        guard = text.split("brix_cta_shm_queue() == NULL")[1].split("}")[0]
        assert "CTA_RSP_ERR_CTA" in guard and "unavailable" in guard, guard

    def test_every_queue_operation_goes_through_the_locked_wrappers(self):
        text = _src("src/protocols/ssi/svc_cta/cta_service.c")
        for wrapper in ("brix_cta_shm_submit(", "brix_cta_shm_active_count(",
                        "brix_cta_shm_transition"):
            assert wrapper in text, f"{wrapper} is no longer used"
        for direct in ("cta_queue_submit(", "cta_queue_active_count("):
            assert direct not in text, \
                f"{direct} bypasses the zone lock in cta_service.c"


# --------------------------------------------------------------------------- #
# B. The queue stayed pure C, and holds nothing process-local.                 #
# --------------------------------------------------------------------------- #

def _cc():
    cc = os.environ.get("CC") or shutil.which("gcc") or shutil.which("cc")
    if cc is None:
        pytest.skip("no C compiler available")
    return cc


def _build_and_run(tmp_path, name, sources):
    out = str(tmp_path / name)
    build = subprocess.run([_cc(), *CFLAGS, "-o", out, *sources],
                           cwd=REPO, capture_output=True, text=True)
    assert build.returncode == 0, build.stderr
    run = subprocess.run([out], cwd=REPO, capture_output=True, text=True,
                         env={**os.environ, "TMPDIR": str(tmp_path)})
    return run


class TestTheQueueStaysPureC:
    """The locking lives in cta_shm.c so that cta_queue.c keeps compiling with
    `gcc -Isrc` and no nginx at all.  Move a lock into cta_queue.c and these
    two suites stop building — which is the whole reason to keep them."""

    def test_the_queue_never_mentions_nginx(self):
        for rel in ("cta_queue.c", "cta_queue.h", "cta_exec.c", "cta_exec.h"):
            text = _src(f"src/protocols/ssi/svc_cta/{rel}")
            assert "ngx_" not in text, f"{rel} took an nginx dependency"

    def test_the_queue_holds_no_process_local_pointers(self):
        """A FILE* and a per-entry back-pointer are meaningless to a second
        process.  Both had to become plain data before the struct could be
        laid out in shared memory."""
        text = _src("src/protocols/ssi/svc_cta/cta_queue.h")
        struct_body = _struct_body(text, "brix_cta_queue_t")
        assert "void      *journal" not in struct_body
        assert "void *journal" not in struct_body
        assert "int       journal_fd" in struct_body, \
            "the journal is no longer an inheritable fd"
        entry = _struct_body(text, "cta_req_t")
        assert "queue" not in entry, \
            "a queue back-pointer is back on the entry; it cannot survive " \
            "being read by a second process"

    def test_the_queue_unit_suite_passes(self, tmp_path):
        run = _build_and_run(tmp_path, "cta_q_ut", [
            f"{SVC}/cta_queue_unittest.c", f"{SVC}/cta_queue.c"])
        assert run.returncode == 0, run.stdout + run.stderr
        assert "OK" in run.stdout, run.stdout

    def test_the_exec_unit_suite_passes(self, tmp_path):
        run = _build_and_run(tmp_path, "cta_e_ut", [
            f"{SVC}/cta_exec_unittest.c", f"{SVC}/cta_exec.c",
            f"{SVC}/cta_queue.c"])
        assert run.returncode == 0, run.stdout + run.stderr
        assert "OK" in run.stdout, run.stdout


# --------------------------------------------------------------------------- #
# C. The zone follows INVARIANT 10, and the lock stays off the executor.       #
# --------------------------------------------------------------------------- #

class TestTheZoneFollowsInvariantTen:

    def test_the_table_is_slab_allocated_not_laid_over_the_zone(self):
        """INVARIANT 10.  A struct laid over shm.addr is walked as an
        ngx_slab_pool_t by nginx's SIGCHLD ngx_unlock_mutexes on every child
        death."""
        text = _src("src/protocols/ssi/svc_cta/cta_shm.c")
        assert "brix_shm_table_alloc(" in text, \
            "the CTA table is no longer allocated from the slab pool"
        assert "ngx_shmtx_create" not in text, \
            "INVARIANT 10: create the table via brix_shm_table_*, never a " \
            "bare ngx_shmtx_create"
        assert "shm.addr" not in text
        assert "brix_shm_zone_size(" in text
        assert "brix_shm_zone_warn_on_resize(" in text

    def test_a_reattached_zone_keeps_its_live_state(self):
        """ERROR PATH.  On reload the zone is re-attached, not re-created;
        re-initialising it would drop every in-flight request."""
        text = _src("src/protocols/ssi/svc_cta/cta_shm.c")
        init = _fn_body(text, "cta_shm_init_zone")
        assert re.search(r"if \(!fresh\) \{\s*\n\s*return NGX_OK;", init), \
            "the zone init no longer short-circuits on a re-attach"

    def test_no_locked_wrapper_runs_an_executor(self):
        """A zone lock held across an archive or retrieve would serialise
        every worker behind one tape operation."""
        text = _src("src/protocols/ssi/svc_cta/cta_shm.c")
        assert "cta_exec" not in text, \
            "cta_shm.c reaches an executor; the lock must never span one"

    def test_the_executor_transitions_through_the_sink_hook(self):
        """The seam that keeps the lock off the executor run: the executor
        calls p->transition, which the nginx build binds to the locked
        wrapper, so the lock is taken once per transition and dropped."""
        exec_h = _src("src/protocols/ssi/svc_cta/cta_exec.h")
        assert "int (*transition)(brix_cta_queue_t *q, cta_req_t *e," in exec_h
        exec_c = _src("src/protocols/ssi/svc_cta/cta_exec.c")
        assert "p->transition(p->q, e, to)" in exec_c
        svc = _src("src/protocols/ssi/svc_cta/cta_service.c")
        assert "brix_cta_shm_transition" in svc, \
            "the service no longer binds the locked transition into the sink"

    def test_an_executor_with_no_queue_refuses(self):
        """SECURITY NEGATIVE (source half).  An executor handed no queue must
        fail rather than transition an entry it cannot journal — the shape a
        caller hits when the zone is absent.  Answering SUCCESS there would
        fabricate a durability guarantee.  The behavioural half of this is
        test_no_queue_refuses_every_op in cta_exec_unittest.c."""
        exec_c = _src("src/protocols/ssi/svc_cta/cta_exec.c")
        assert re.search(r"if \(p == NULL \|\| p->q == NULL\) \{\s*\n"
                         r"\s*return -1;", exec_c), \
            "advance() no longer refuses a sink with no queue"


# --------------------------------------------------------------------------- #
# D. One zone means one journal, opened once in the master.                    #
# --------------------------------------------------------------------------- #

class TestOneZoneOneJournal:

    def test_the_journal_is_opened_in_the_zone_init(self):
        """Zone init runs in the MASTER, before fork, so the fd is inherited:
        every worker shares one open file description and one O_APPEND offset,
        and one journal serves the whole set."""
        text = _src("src/protocols/ssi/svc_cta/cta_shm.c")
        init = _fn_body(text, "cta_shm_init_zone")
        assert "cta_queue_open_journal(q, cta_journal_path)" in init

    def test_an_unusable_journal_is_not_fatal(self):
        """ERROR PATH.  A permissions change on the journal must degrade
        restart recovery, not refuse to start a working deployment."""
        text = _src("src/protocols/ssi/svc_cta/cta_shm.c")
        init = _fn_body(text, "cta_shm_init_zone")
        assert "NGX_LOG_ERR" in init
        assert "return NGX_ERROR" not in init.split("cta_queue_init(q);")[1], \
            "an unusable journal now fails the whole zone init"

    def test_each_record_is_one_write(self):
        """What makes ONE journal safe for N workers: an O_APPEND write(2) of
        a whole record is atomic.  stdio promises nothing about where its
        buffer boundaries fall, so a partially-flushed record from worker A
        could be split by worker B's."""
        text = _src("src/protocols/ssi/svc_cta/cta_queue.c")
        append = text.split("journal_append")[1].split("\n}")[0]
        assert "write(" in append, "the journal append is no longer a write(2)"
        for buffered in ("fprintf(", "fwrite(", "fputs("):
            assert buffered not in append, \
                f"{buffered} is back on the append path; a record may be " \
                f"split across two workers' flushes"

    def test_the_ignored_journal_is_named_in_a_warning(self):
        """DESIGN CHOICE.  One zone can open one journal, so where two enabled
        blocks name different paths the first non-empty wins.  Silent would
        let an operator believe the second block was being journalled; fatal
        would take down deployments that have run this way until now."""
        text = _src("src/core/config/postconfiguration.c")
        pick = text.split("cta_journal_pick(ngx_conf_t")[1].split("\n}")[0]
        assert "NGX_LOG_WARN" in pick, "the conflicting journal is now silent"
        assert "NGX_LOG_EMERG" not in pick and "NGX_ERROR" not in pick, \
            "a journal conflict now fails the config"
        assert "is ignored" in pick and "declared first" in pick, pick

    def test_identical_journal_paths_are_not_a_conflict(self):
        """Two blocks naming the SAME journal is the ordinary case (an http
        and a stream face of one deployment); it must not warn."""
        text = _src("src/core/config/postconfiguration.c")
        pick = text.split("cta_journal_pick(ngx_conf_t")[1].split("\n}")[0]
        assert "ngx_strncmp(chosen->data, cand->data, cand->len) == 0" in pick

    def test_the_zone_is_registered_only_for_a_cta_block(self):
        """A config with no `brix_ssi_service cta` must allocate nothing."""
        text = _src("src/core/config/postconfiguration.c")
        fn = text.split("postconf_cta_queue(ngx_conf_t")[1].split("\n}\n")[0]
        assert "xcf->ssi_cta_enable" in fn
        assert re.search(r"if \(!any_cta\) \{\s*\n\s*return NGX_OK;", fn), \
            "the CTA zone is registered even with no cta server block"
        assert "brix_cta_shm_configure(cf, &journal)" in fn
        assert "postconf_cta_queue(cf, cmcf, cscfp)" in text, \
            "postconf_cta_queue is defined but never called"


# --------------------------------------------------------------------------- #
# E. Build registration.                                                       #
# --------------------------------------------------------------------------- #

class TestBuildRegistration:
    """A new src/ .c file that is not in ./config compiles for nobody.  This
    is the guard's own rule (check_config_coverage.py) restated at the point
    of use, so a future move of cta_shm.c cannot quietly unbuild it."""

    def test_the_zone_source_and_header_are_in_the_source_list(self):
        text = _src("config")
        assert "src/protocols/ssi/svc_cta/cta_shm.c" in text, \
            "cta_shm.c is not built"
        assert "src/protocols/ssi/svc_cta/cta_shm.h" in text

    def test_config_coverage_is_clean(self):
        run = subprocess.run(
            ["python3", "tools/ci/check_config_coverage.py"],
            cwd=REPO, capture_output=True, text=True)
        assert run.returncode == 0, run.stdout + run.stderr


# --------------------------------------------------------------------------- #
# F. LIVE — the defect itself, across two workers.                             #
# --------------------------------------------------------------------------- #

SUBMITS = 24


@pytest.fixture()
def cta_cluster(lifecycle, tmp_path):
    journal = tmp_path / "cta-shm.journal"
    data = tmp_path / "data-cta-shm"
    data.mkdir()
    port = lifecycle.start(NginxInstanceSpec(
        name="lc-p115-cta-shm",
        template="nginx_ssi_cta_shm.conf",
        data_root=str(data),
        template_values={"BIND_HOST": HOST, "JOURNAL": str(journal)},
        reason="phase-115 W8.6 cross-worker CTA queue")).port
    return port, journal


def _journal_ids(journal):
    """Every id in the journal, in order.  Records are one line each and the
    id is the first tab-separated field."""
    ids = []
    with open(journal, encoding="utf-8", errors="surrogateescape") as fh:
        for line in fh:
            line = line.rstrip("\n")
            if line:
                ids.append(line.split("\t")[0])
    return ids


def _archive_once(port, n):
    sock = _handshake_login(HOST, port)
    try:
        fh = _open_ssi(sock, "cta")
        req = build_request(4, "eosdev", f"u{n}", "grp",
                            f"/eos/p115/shm/f{n}", 1000 + n)
        assert _submit(sock, fh, 1, req) == kXR_waitresp
        _alerts, rsp = _collect_pushed_response(sock)
        return rsp.get(1)
    finally:
        sock.close()


@pytest.mark.uses_lifecycle_harness
class TestCrossWorkerIdsAreUnique:

    def test_concurrent_submits_across_two_workers_never_reuse_an_id(
            self, cta_cluster):
        """THE DEFECT.  With a per-worker queue each worker replayed the same
        journal, set the same next_id, and allocated from its own copy — so
        the same id was handed to two different clients, and a later query or
        cancel for it acted on whichever request the connection reached.  One
        shared zone makes the id space single."""
        port, journal = cta_cluster
        with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
            results = list(pool.map(lambda n: _archive_once(port, n),
                                    range(SUBMITS)))
        assert all(r == CTA_RSP_SUCCESS for r in results), results

        # a transition writes a further record for an id it already owns, so
        # count DISTINCT ids rather than total records.
        ids = _journal_ids(journal)
        assert len(set(ids)) == SUBMITS, (
            f"{len(set(ids))} distinct ids for {SUBMITS} submits — a "
            f"per-worker queue produces fewer, by reusing them", sorted(ids))

    def test_the_ids_form_one_unbroken_sequence(self, cta_cluster):
        """Corollary, and the sharper signal: one queue means one counter, so
        the ids are exactly 1..N with no gap and no repeat.  Two workers with
        private counters produce two overlapping runs instead."""
        port, journal = cta_cluster
        with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
            list(pool.map(lambda n: _archive_once(port, n), range(SUBMITS)))
        ids = sorted({int(i) for i in _journal_ids(journal)})
        assert ids == list(range(1, SUBMITS + 1)), ids

    def test_a_wire_path_cannot_forge_a_journal_record(self, cta_cluster):
        """SECURITY NEGATIVE, live.  The request path is up to 1023
        wire-chosen bytes of Notification.file.lpath.  Written raw into the
        tab-delimited, newline-terminated record grammar, a path carrying a
        newline appends a SECOND record of the submitter's choosing —
        including its `owner`, the principal cta_queue_cancel() gates on.  The
        forgery is inert until the next replay, so the request that plants it
        looks unremarkable at the time."""
        port, journal = cta_cluster
        forged = "/eos/p115/ok\n999999\t0\t0\troot\t/eos/p115/owned-by-root"
        sock = _handshake_login(HOST, port)
        try:
            fh = _open_ssi(sock, "cta")
            req = build_request(4, "eosdev", "mallory", "grp", forged, 7)
            assert _submit(sock, fh, 1, req) == kXR_waitresp
            _alerts, rsp = _collect_pushed_response(sock)
            assert rsp.get(1) == CTA_RSP_SUCCESS, rsp
        finally:
            sock.close()

        raw = journal.read_bytes()
        assert b"\n999999\t" not in raw, \
            "the submitted path forged a second journal record"
        ids = _journal_ids(journal)
        assert "999999" not in ids, ids
        assert all(i.isdigit() for i in ids), \
            f"a journal line does not begin with an id: {ids}"
        # the payload survived, whole and escaped, on mallory's own record
        assert b"\\n999999" in raw, \
            "the newline was dropped rather than escaped"
        assert b"\troot\t" not in raw, \
            "an attacker-chosen owner reached the journal's owner field"
