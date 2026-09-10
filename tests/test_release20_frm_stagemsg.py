"""2.0 F2 — `brix_frm_stagemsg <file>`: the StageEvents notification feed.

WHAT: the `oss.stagemsg` / `XRDOFSEVENTS` analogue. Every worker appends one
      `<utc> <source> <event> <reqid|-> <key|-> [name=value ...]` line per stage
      transition to one file, from three sources: the durable stage engine
      (`engine`), the kXR_prepare / Tape REST registry (`prepare`) and the
      `tape://` MSS adapter (`frm`).  `src/fs/xfer/stage_events.c` owns the
      writer; `src/core/config/tape_stage_conf.c` the directive.
WHY:  the 2.0 readiness register (axis (e) F2) pulled parity-audit oss row 12
      out of "not present".  Everything below pins a behaviour that used to be
      a mystery: the line grammar, the refusals, the best-effort contract (a
      broken feed never fails a stage and recovers without a reload), and that
      the vocabulary emitted by `src/` is exactly the documented one.
HOW:  static `nginx -t` cells reuse the F1 knob helpers; live cells run one
      exec-adapter lab (prepare -> recall -> online) and one dead-origin lab
      (flush -> failed -> deadletter) on the `lc-r20-frm-stagemsg` listener.
      The register row cites this module's test count -- keep it current.
"""
import os
import re
import time
from pathlib import Path
from urllib.parse import unquote

import pytest

from settings import BIND_HOST
from server_registry import NginxInstanceSpec
from official_interop_lib import worker_reachable

from _test_release20_metrics_helpers import wait_port
from _test_xfer_wt_wire import write_file
from test_phase115_tape_purge import _prepare_stage, _session
from test_release20_frm_knobs import (_error_log, _frm_on, _nginx_t, _rcreate,
                                      _script, _server, _wait_deadletter,
                                      _wait_log)
import _test_session_bind_helpers as H

pytestmark = [pytest.mark.uses_lifecycle_harness,
              pytest.mark.xdist_group("lc-r20-frm-stagemsg")]

_SERVER = "lc-r20-frm-stagemsg"
TEMPLATE = "nginx_lc_r20_frm_knobs.conf"
REPO = Path(__file__).resolve().parents[1]

_LINE = re.compile(r"^(\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ) (\S+) (\S+) (\S+) (\S+)"
                   r"((?: \S+=\S*)*)$")

# The documented vocabulary (directives.md "brix_frm_stagemsg" table).
VOCABULARY = {
    "engine": {"queued", "started", "done", "failed", "deadletter", "replayed",
               "dropped"},
    "prepare": {"queued", "staging", "online", "failed", "cancelled", "deleted",
                "expired"},
    "frm": {"recall-begin", "recall-online", "recall-failed", "migrate-done",
            "migrate-failed", "seal-done", "seal-failed"},
}


# ---------------------------------------------------------------- static ----

def test_stagemsg_parses_and_a_missing_file_is_fine(tmp_path):
    """Success: an absolute path that does not exist yet is accepted (the
    worker creates it); two servers publishing the same file are fine."""
    feed = tmp_path / "events" / "stage.log"
    rc, out = _nginx_t(tmp_path,
                       _server(tmp_path, _frm_on(tmp_path)
                               + f"brix_frm_stagemsg {feed};", "a")
                       + _server(tmp_path, _frm_on(tmp_path)
                                 + f"brix_frm_stagemsg {feed};", "b"))
    assert rc == 0, out
    assert "brix_frm_stagemsg" not in out


@pytest.mark.parametrize("value,needle", [
    ("events/stage.log", "must be an absolute path"),
    ("{root}", "is not a regular file"),           # an existing directory
])
def test_relative_or_directory_stagemsg_is_refused(tmp_path, value, needle):
    """Error: the two shapes a typo produces are refused by name at load."""
    conf = _frm_on(tmp_path) + f"brix_frm_stagemsg {value.format(root=tmp_path)};"
    rc, out = _nginx_t(tmp_path, _server(tmp_path, conf))
    assert rc != 0
    assert needle in out, out


def test_group_or_world_writable_stagemsg_is_refused(tmp_path):
    """Security negative: a feed anyone can append to is a forged tape-event
    stream for whatever tails it; the private copy of the same file passes."""
    feed = tmp_path / "stage.log"
    feed.write_text("")
    feed.chmod(0o666)
    rc, out = _nginx_t(tmp_path, _server(
        tmp_path, _frm_on(tmp_path) + f"brix_frm_stagemsg {feed};"))
    assert rc != 0
    assert ("is group- or world-writable; refusing to feed a file anyone "
            "else can append to") in out, out
    feed.chmod(0o600)
    rc, out = _nginx_t(tmp_path, _server(
        tmp_path, _frm_on(tmp_path) + f"brix_frm_stagemsg {feed};"))
    assert rc == 0, out


def test_stagemsg_must_agree_across_servers(tmp_path):
    """Error: the feed is process-wide like the other engine knobs."""
    rc, out = _nginx_t(tmp_path,
                       _server(tmp_path, _frm_on(tmp_path)
                               + f"brix_frm_stagemsg {tmp_path}/a.log;", "a")
                       + _server(tmp_path, _frm_on(tmp_path)
                                 + f"brix_frm_stagemsg {tmp_path}/b.log;", "b"))
    assert rc != 0
    assert (f'brix_frm_stagemsg "{tmp_path}/b.log" differs from the value '
            f'another brix_frm server published ("{tmp_path}/a.log")') in out, out


def test_stagemsg_on_a_frm_off_server_warns_ignored(tmp_path):
    """Error: the seventh inert-knob name -- accepted, warned, does nothing."""
    rc, out = _nginx_t(tmp_path, _server(
        tmp_path, f"brix_export {tmp_path}; brix_frm_stagemsg {tmp_path}/x.log;"))
    assert rc == 0, out
    assert "brix_frm_stagemsg is ignored: brix_frm is off in this server" in out


_EMIT = re.compile(r'brix_stage_events_emit\(\s*"([a-z]+)",\s*"([a-z-]+)"')
# The registry routes through srq_note(<event>, &rec) / srq_event_name().
_SRQ = re.compile(r'srq_note\("([a-z]+)"|return "([a-z]+)";')


def _scan_emits(seen, path: Path):
    for src, ev in _EMIT.findall(path.read_text(errors="replace")):
        assert src in VOCABULARY, f"{path}: undocumented source {src!r}"
        seen[src].add(ev)


def _emitted_vocabulary(root: Path):
    seen = {s: set() for s in VOCABULARY}
    for c in (root / "src").rglob("*.c"):
        _scan_emits(seen, c)
    mutate = (root / "src/fs/xfer/stage_request_registry_mutate.c").read_text()
    for direct, table in _SRQ.findall(mutate):
        seen["prepare"].add(direct or table)
    seen["prepare"].discard("freed")
    return seen


def test_emit_vocabulary_matches_the_documented_set():
    """Every (source, event) literal in src/ is documented, and every
    documented event is emitted somewhere -- nothing is a mystery either way."""
    seen = _emitted_vocabulary(REPO)
    doc = (REPO / "docs/03-configuration/directives.md").read_text()
    for src, events in VOCABULARY.items():
        assert seen[src] == events, (src, seen[src] ^ events)
        missing = [ev for ev in events if f"`{ev}`" not in doc]
        assert not missing, f"{src}: {missing} missing from directives.md"


# ------------------------------------------------------------------ live ----

def _launch(lifecycle, backend, server_directives, main="", env=None):
    ep = lifecycle.start(NginxInstanceSpec(
        name=_SERVER,
        template=TEMPLATE,
        protocol="root",
        env=env or {},
        template_values={"BIND_HOST": BIND_HOST, "BACKEND": backend,
                         "MAIN_DIRECTIVES": main,
                         "SERVER_DIRECTIVES": server_directives},
        reason="2.0 F2 brix_frm_stagemsg StageEvents feed"))
    assert wait_port(ep.port), f"{_SERVER} never became connectable"
    return ep


def _recall_lab(lifecycle, tmp_path, feed, env=None):
    """tape://exec lab whose every key is OFFLINE until `recall` copies the
    planted payload into the online buffer; the registry is armed
    (brix_frm_control_dir) so kXR_prepare records and reports."""
    buffer, ns, cache, ctl = (tmp_path / d for d in ("buffer", "ns", "cache", "ctl"))
    for d in (buffer, ns, cache, ctl):
        d.mkdir(exist_ok=True)
    planted = tmp_path / "planted.bin"
    planted.write_bytes(b"tape-resident payload\n")
    worker_reachable(buffer, ns, cache, ctl, tmp_path)
    cmd = _script(tmp_path, "mss.sh",
                  "  exists) exit 0 ;;\n"                 # 0 = OFFLINE
                  f'  recall) cp {planted} "$3"; exit 0 ;;\n')
    directives = (f"brix_export {ns}; brix_cache_store posix:{cache}; "
                  "brix_cache_export /; "
                  f"brix_frm on; brix_frm_queue_path {tmp_path}/journal; "
                  f"brix_frm_control_dir {ctl}; brix_frm_stage_wait 1; "
                  f"brix_frm_stagecmd {cmd}; "
                  + (f"brix_frm_stagemsg {feed}; " if feed else ""))
    return _launch(lifecycle, f"tape://exec{buffer}", directives, env=env)


def _dead_origin_lab(lifecycle, tmp_path, feed):
    """A brix_frm server whose async flush origin (root://127.0.0.1:1) is dead."""
    data, stage = tmp_path / "data", tmp_path / "stage"
    for d in (data, stage):
        d.mkdir(exist_ok=True)
    worker_reachable(data, stage, tmp_path)
    directives = (f"brix_export {data}; brix_stage on; "
                  f"brix_stage_store posix:{stage}; brix_stage_flush async; "
                  f"brix_frm on; brix_frm_queue_path {tmp_path}/journal; "
                  "brix_frm_fail_backoff 1s; brix_frm_fail_retries 2; "
                  f"brix_frm_stagemsg {feed};")
    return _launch(lifecycle, "root://127.0.0.1:1", directives)  # net-literal-allow: a dead origin, never a bind address


def _events(feed: Path):
    if not feed.exists():
        return []
    out = []
    for raw in feed.read_text(errors="replace").splitlines():
        m = _LINE.match(raw)
        assert m, f"malformed StageEvents line: {raw!r}"
        _ts, source, event, reqid, key, rest = m.groups()
        pairs = dict(p.split("=", 1) for p in rest.split())
        out.append((source, event, reqid, key, pairs))
    return out


def _wait_events(feed: Path, pred, timeout=25.0):
    deadline = time.time() + timeout
    evs = []
    while time.time() < deadline:
        evs = _events(feed)
        if any(pred(e) for e in evs):
            return evs
        time.sleep(0.2)
    raise AssertionError(f"event never reached {feed}:\n{evs}")


def _prepare(port, path):
    sock, _sessid, stream = _session(port)
    try:
        status, body = _prepare_stage(sock, stream, path)
    finally:
        sock.close()
    assert status == H.kXR_ok, f"kXR_prepare(stage) {path}: {status} {body!r}"
    return body


def _index(evs, source, event, key_suffix):
    for i, (s, e, _r, k, _p) in enumerate(evs):
        if s == source and e == event and k.endswith(key_suffix):
            return i
    raise AssertionError(f"no {source} {event} *{key_suffix} in {evs}")


def test_prepare_recall_feeds_prepare_and_frm_lines(lifecycle, tmp_path):
    """Success: one kXR_prepare(stage) of an offline key produces the
    documented prepare -> frm -> prepare sequence, the file is private and
    start-up announced the feed."""
    feed = tmp_path / "events" / "stage.log"
    feed.parent.mkdir()
    ep = _recall_lab(lifecycle, tmp_path, feed)
    _wait_log(ep, f'stage engine: StageEvents feed "{feed}"')
    _prepare(ep.port, "/tape/obj1")
    evs = _wait_events(feed, lambda e: e[:2] == ("prepare", "online")
                       and e[3].endswith("obj1"))
    assert (feed.stat().st_mode & 0o777) == 0o600
    q = _index(evs, "prepare", "queued", "obj1")
    b = _index(evs, "frm", "recall-begin", "obj1")
    o = _index(evs, "frm", "recall-online", "obj1")
    d = _index(evs, "prepare", "online", "obj1")
    assert q < b < o < d, evs
    assert evs[q][2] == evs[d][2] != "-", "prepare lines carry the request id"
    assert evs[b][2] == evs[o][2] == "-", "frm lines have no request id"
    assert "principal" in evs[q][4]
    assert "[error]" not in _error_log(ep), _error_log(ep)[-2000:]


def test_flush_engine_feeds_queued_started_failed_deadletter(lifecycle, tmp_path):
    """Success: the durable engine reports a flush's whole life -- queued,
    started, every failed attempt with its errno, and the dead-letter verdict
    with the attempt count and reason."""
    feed = tmp_path / "stage.log"
    ep = _dead_origin_lab(lifecycle, tmp_path, feed)
    write_file(BIND_HOST, ep.port, "/dead.bin", b"x" * 64)
    _wait_deadletter(tmp_path / "journal", "dead.bin")
    evs = _wait_events(feed, lambda e: e[:2] == ("engine", "deadletter"))
    q = _index(evs, "engine", "queued", "dead.bin")
    s = _index(evs, "engine", "started", "dead.bin")
    f = _index(evs, "engine", "failed", "dead.bin")
    d = _index(evs, "engine", "deadletter", "dead.bin")
    assert q < s < f < d, evs
    assert evs[q][4]["kind"] == "flush"
    assert evs[f][4]["errno"].isdigit() and evs[f][4]["errno"] != "0"
    assert evs[d][4] == {"attempts": "2", "reason": "unreachable"}, evs[d]
    reqids = {evs[i][2] for i in (q, s, f, d)}
    assert len(reqids) == 1 and "-" not in reqids, "one reqid threads the life"


def test_unwritable_feed_logs_once_never_fails_a_stage_and_recovers(
        lifecycle, tmp_path):
    """Error: a feed whose directory cannot be written logs one [error],
    staging goes on (prepare + rcreate answer kXR_ok), and the feed comes
    back on the next transition once the directory is repaired -- no reload."""
    locked = tmp_path / "locked"
    locked.mkdir()
    feed = locked / "stage.log"
    locked.chmod(0o500)
    try:
        ep = _recall_lab(lifecycle, tmp_path, feed)
        _wait_log(ep, f'brix_frm_stagemsg "{feed}": open failed; stage '
                      "notifications are off in this worker until the file is "
                      "writable again (staging itself is unaffected)")
        assert f'StageEvents feed "{feed}"' not in _error_log(ep)
        _prepare(ep.port, "/tape/first")
        assert _rcreate(ep.port, "/tape/newdir")[0] == H.kXR_ok
        time.sleep(1.0)
        assert not feed.exists()
        assert _error_log(ep).count("open failed; stage notifications are off") == 1
        locked.chmod(0o700)
        _prepare(ep.port, "/tape/second")
        evs = _wait_events(feed, lambda e: e[:2] == ("prepare", "online")
                           and e[3].endswith("second"))
        assert not any(e[3].endswith("first") for e in evs), "first was lost, by design"
        assert _error_log(ep).count("open failed; stage notifications are off") == 1
    finally:
        locked.chmod(0o700)


_SECRET_SHAPES = ("Bearer", "eyJ", "sss:", "BEGIN CERTIFICATE", "PRIVATE KEY",
                  "password", "token=")


def _assert_only_data(raw: str):
    for shape in _SECRET_SHAPES:
        assert shape not in raw, f"{shape!r} leaked into the StageEvents feed"
    for line in raw.splitlines():
        assert len(line.split(" ")) >= 5, f"not five fields: {line!r}"


def test_feed_escapes_keys_and_carries_no_credential(lifecycle, tmp_path):
    """Security negative: a key with a space, `%` and `#` still yields a line
    that splits on spaces and round-trips through URI unescaping, and nothing
    in the file is a secret (only keys, principals, kinds and numbers)."""
    feed = tmp_path / "stage.log"
    ep = _recall_lab(lifecycle, tmp_path, feed)
    _prepare(ep.port, "/tape/dir one/100%#x.dat")
    evs = _wait_events(feed, lambda e: e[:2] == ("prepare", "online")
                       and unquote(e[3]).endswith("100%#x.dat"))
    key = evs[_index(evs, "prepare", "queued", "x.dat")][3]
    assert " " not in key and {"%20", "%25", "%23"} <= set(re.findall("%..", key)), key
    assert unquote(key).endswith("dir one/100%#x.dat")
    _assert_only_data(feed.read_text())


def test_environment_cannot_enable_the_feed(lifecycle, tmp_path):
    """Security negative: there is no BRIX_FRM_STAGEMSG contract -- an operator
    environment cannot point a worker at a feed the config never named."""
    feed = tmp_path / "env.log"
    ep = _recall_lab(lifecycle, tmp_path, None,
                     env={"BRIX_FRM_STAGEMSG": str(feed)})
    _prepare(ep.port, "/tape/obj1")
    _wait_log(ep, "start worker process", timeout=5)
    time.sleep(1.0)
    assert not feed.exists()
    assert "StageEvents feed" not in _error_log(ep)
