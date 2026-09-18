"""2.0 F4 — per-space purge policy + external policy program of the tape-buffer
purge engine (release-2.0 readiness register, axis (e) row F4).

    brix_frm_purge_policy {*|<group>} <hi> <lo> [hold <time>] [polprog]
    brix_frm_purge_polprog <program>

The phase-115 engine had one export-wide LRU (watermark pair + owned-bytes
cap). F4 gives every `brix_oss_space` group its own owned-bytes arm, an
optional hold and, for `polprog` rules, an operator program that chooses which
of the group's eligible copies may go. Pinned here:

  success   a group rule releases its own group's coldest copies and nothing
            else; `*` covers ungrouped keys and groups without a rule; the
            program's choice is honoured; the program only runs under pressure
  error     hold keeps recently touched copies; a failing or hung program
            fails closed for ITS groups while the others still release
  security  a decision naming a key outside the program's own candidate list
            (another group, a traversal, an absolute path, the symlink, an
            unmigrated copy) is ignored, never released; group-writable
            programs are refused; the directives are stream-only

Lab: `lc-r20-purge-policy` (one root:// listener, fleet_ports_exclusive.py),
the phase-115 tape-purge template + a stub tape:// tier. One pass per test
(`brix_frm_purge_interval 1h`, first tick at 1 s).
"""

import os
import re
import stat
import time

import pytest

from test_phase115_tape_purge import (FILE_BYTES, _elog, _launch, _nginx_t,
                                      _payload, _summary, _wait_log)
from brix_suite.fd_probe import (parse_identity, write_fd_probe,
                                 write_identity_probe)
from test_release20_frm_knobs import _inherited_fds, _server_descriptors
from lib_py.util import budget_scale

# Each case boots an instance and waits for a purge pass to log its verdict;
# the default 30 s is under this file's own longest internal wait, so a loaded
# host times the TEST out before the wait it is measuring can finish.
pytestmark = [pytest.mark.uses_lifecycle_harness,
              pytest.mark.timeout(300 * budget_scale()),
              pytest.mark.xdist_group("lc-r20-purge-policy")]

_SERVER = "lc-r20-purge-policy"
REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

GROUPS = ("brix_oss_space atlas /atlas quota=4000; "
          "brix_oss_space cms /cms quota=-1; ")
INTERVAL = "brix_frm_purge_interval 1h; "

# migrated copies: key -> seconds before "now" the online copy was last touched
PLAN = {"atlas/a1": 500, "atlas/a2": 400, "atlas/a3": 300, "atlas/a4": 200,
        "cms/c1": 450, "cms/c2": 350, "cms/c3": 250,
        "misc/m1": 480, "misc/m2": 380}
ALL_ONLINE = sorted(list(PLAN) + ["misc/u", "evil"])

POLICY_RX = (r'tape purge "[^"]+/\.online" policy "([^"]+)": owned (\d+) -> (\d+) '
             r'bytes \(hi=(\d+) lo=(\d+) hold=(\d+) s(, polprog)?\), released '
             r'(\d+) file\(s\), (\d+) bytes')
PASS_RX = (r'policy pass: rules=(\d+) held=(\d+) unapproved=(\d+) '
           r'polprog=(\w+) approved=(\d+) ignored=(\d+)')
FAILED_RX = r'policy program "[^"]+" failed \(([^)]+)\); its groups release nothing'


def _plant(base):
    """Tape + online copies for three groups (atlas quota 4000, cms unlimited,
    misc ungrouped), one unmigrated online-only copy and a symlink pointing
    out of the buffer. Returns the symlink's target."""
    online = base / ".online"
    now = time.time()
    for key, back in PLAN.items():
        for root in (base, online):
            (root / key).parent.mkdir(parents=True, exist_ok=True)
            (root / key).write_bytes(_payload(key[-2:]))
        os.utime(online / key, (now - back, now - back))
    (online / "misc" / "u").write_bytes(_payload("u"))
    os.utime(online / "misc" / "u", (now - 600, now - 600))
    victim = base.parent / "victim.dat"
    victim.write_bytes(b"V" * FILE_BYTES)
    (online / "evil").symlink_to(victim)
    return victim


def _online(base):
    """Every name left under the buffer, buffer-relative, engine files aside."""
    root = base / ".online"
    names = []
    for dirpath, _dirs, files in os.walk(root):
        for f in files:
            rel = os.path.relpath(os.path.join(dirpath, f), root)
            if not rel.startswith(".brix-purge."):
                names.append(rel)
    return sorted(names)


def _program(tmp_path, name, body, mode=0o755):
    p = tmp_path / name
    p.write_text("#!/bin/sh\n" + body + "\n")
    p.chmod(mode)
    return p


def _lab(lifecycle, tmp_path, policy_lines):
    base = tmp_path / "tape"
    victim = _plant(base)
    ep = _launch(lifecycle, tmp_path, _SERVER, f"tape://{base}",
                 GROUPS + INTERVAL + policy_lines, first_ms=1000)
    return base, victim, _elog(ep)


def _policy_line(elog, group):
    m = _wait_log(elog, POLICY_RX.replace('"([^"]+)"', f'"({re.escape(group)})"'))
    assert m is not None, f"no policy line for {group!r}"
    return m


def _pass_line(elog):
    m = _wait_log(elog, PASS_RX)
    assert m is not None, "no policy pass line"
    return m


def _released(plan_keys, base):
    """The plan keys no longer online."""
    left = set(_online(base))
    return sorted(k for k in plan_keys if k not in left)


# --------------------------------------------------------------- static pins


def _src(rel):
    with open(os.path.join(REPO, rel)) as fh:
        return fh.read()


def test_f4_sources_directives_and_docs_are_wired():
    """The three F4 TUs are in `config`, both directives exist in the stream
    table, the rule type is part of the engine's policy, the server merge
    cross-checks rules against the space table, and both directives are
    documented."""
    config = _src("config")
    for tu in ("src/fs/backend/frm/sd_frm_purge_policy.c",
               "src/fs/backend/frm/sd_frm_purge_internal.h",
               "src/core/config/frm_purge_policy_conf.c"):
        assert tu in config, f"{tu} is not in the build source list"
    table = _src("src/protocols/root/stream/directives_net.h")
    assert 'ngx_string("brix_frm_purge_policy")' in table
    assert 'ngx_string("brix_frm_purge_polprog")' in table
    assert "brix_sd_frm_purge_rule_t" in _src("src/fs/backend/frm/sd_frm.h")
    assert "brix_frm_purge_policy_check(" in _src(
        "src/core/config/server_conf_merge_security.c")
    doc = _src("docs/03-configuration/directives.md")
    assert "#### `brix_frm_purge_policy " in doc
    assert "#### `brix_frm_purge_polprog " in doc


def test_both_frm_operator_programs_run_through_the_shared_runner():
    """(success, static) nginx calls ngx_process_get_status() for SIGCHLD in
    WORKERS too, so waitpid(-1, WNOHANG) there reaps any direct child of a
    worker before the feature's own wait sees it: the status is lost and the
    verb reports ECHILD.  Every operator program whose EXIT STATUS decides
    something therefore runs through brix_subprocess_run(), whose double-forked
    agent the worker never had as a child (2.0, 2026-09-09).

    The streaming `dread` listing in exec_list() is the one documented
    exception -- it is framed by its pipe reaching EOF, not by a status -- and
    it is the only remaining frm_exec_spawn() caller.
    """
    exec_c = _src("src/fs/backend/frm/sd_frm_exec.c")
    policy_c = _src("src/fs/backend/frm/sd_frm_purge_policy.c")
    for c in (exec_c, policy_c):
        assert "brix_subprocess_run(&req, NULL, &exit_code)" in c
        assert "core/compat/subprocess.h" in c
    assert "frm_exec_spawn" not in policy_c


def test_the_streaming_dread_listing_is_the_only_direct_child():
    """(success, static) the exception and its bounds: exec_list()'s `dread`
    is framed by its pipe reaching EOF rather than by an exit status, so it
    still forks directly -- and it is the last place that does.  The private
    waiter that used to lose the race with the SIGCHLD handler is gone from
    every FRM source (2.0, 2026-09-09)."""
    exec_c = _src("src/fs/backend/frm/sd_frm_exec.c")
    callers = [l for l in exec_c.splitlines() if "frm_exec_spawn(" in l]
    assert len(callers) == 2, callers      # the definition + exec_list's dread
    dread = exec_c.split('argv[1] = (char *) "dread";')[1].split("\n}\n")[0]
    assert "frm_exec_spawn(&pid" in dread, "the surviving caller is not dread"
    for text in (exec_c, _src("src/fs/backend/frm/sd_frm_purge_policy.c"),
                 _src("src/fs/backend/frm/sd_frm_internal.h")):
        assert "frm_exec_wait" not in text, "the private waiter is gone"


def test_the_shared_runner_gives_the_program_its_own_session_and_deadline():
    """(success, static) the two properties the FRM programs inherit from
    brix_subprocess_run(): setsid() in the child (so a deadline kill reaches
    the whole process group) and a pidfd-polled deadline that SIGKILLs -pid
    and reports ETIMEDOUT."""
    run_c = _src("src/core/compat/subprocess.c")
    assert "(void) setsid();" in run_c
    assert "(void) kill(-child, SIGKILL);" in run_c
    assert "errno = ETIMEDOUT;" in run_c
    # The deadline wait itself is per-host (Linux pidfd+poll, Darwin kqueue
    # EVFILT_PROC), so the portable runner names the PAL primitive and each
    # host body implements it.
    assert "brix_plat_wait_pid_timeout(" in run_c
    assert "__NR_pidfd_open" in _src("src/platform/linux/process_wrapper.c")
    assert "EVFILT_PROC" in _src("src/platform/darwin/process_wrapper.c")
    api = _src("src/core/compat/subprocess.h")
    assert "unsigned      timeout_ms;" in api
    assert "brix_subprocess_run(" in api


# ------------------------------------------------------------ group rules


def test_group_rule_releases_its_own_coldest_copies_only(lifecycle, tmp_path):
    """(success) `atlas 75% 25%` on a 4000-byte quota: owned 4000 > 3000, so
    the pass releases atlas's LRU tail down to 1000 and touches nothing of
    cms or misc; the export-wide arms stay unarmed."""
    base, victim, elog = _lab(lifecycle, tmp_path,
                              "brix_frm_purge_policy atlas 75% 25%;")
    assert _wait_log(elog, r'tape purge policy for export "[^"]+": 1 rule\(s\), '
                           r'program "\(none\)"') is not None
    assert _wait_log(elog, r"tape purge engine armed for export") is not None
    released, nbytes = _summary(elog)[:2]
    assert (released, nbytes) == (3, 3000)
    assert _released(PLAN, base) == ["atlas/a1", "atlas/a2", "atlas/a3"]
    m = _policy_line(elog, "atlas")
    assert m.groups() == ("atlas", "4000", "1000", "3000", "1000", "30", None,
                          "3", "3000")
    assert victim.read_bytes() == b"V" * FILE_BYTES


def test_default_rule_covers_ungrouped_keys_and_groups_without_a_rule(
        lifecycle, tmp_path):
    """(success) `*` is the rule of every key whose group has no rule of its
    own (cms) and of ungrouped keys (misc); the atlas rule keeps precedence.
    The unmigrated copy counts as owned but is never released."""
    base, _victim, elog = _lab(lifecycle, tmp_path,
                               "brix_frm_purge_policy atlas 75% 25%; "
                               "brix_frm_purge_policy * 2500 500;")
    assert _summary(elog)[:2] == [8, 8000]
    assert _online(base) == ["atlas/a4", "evil", "misc/u"]
    star = _policy_line(elog, "*")
    assert star.groups()[1:3] == ("6000", "1000")
    assert star.groups()[7:] == ("5", "5000")
    assert _policy_line(elog, "atlas").groups()[7:] == ("3", "3000")


@pytest.mark.parametrize("hold, held, released", [("1h", 3, 0), ("1m", 0, 3)])
def test_hold_keeps_copies_touched_within_the_window(lifecycle, tmp_path, hold,
                                                     held, released):
    """(error) `cms 1 0 hold <t>`: every cms copy is under pressure; with a
    one-hour hold all three (touched 250-450 s ago) are kept and booked as
    held, with a one-minute hold all three go."""
    base, _victim, elog = _lab(lifecycle, tmp_path,
                               f"brix_frm_purge_policy cms 1 0 hold {hold};")
    assert _summary(elog)[0] == released
    assert _pass_line(elog).group(2) == str(held)
    assert len(_released(PLAN, base)) == released
    assert all(k.startswith("cms/") for k in _released(PLAN, base))


# ---------------------------------------------------------- policy program


def _polprog(tmp_path, body):
    return _program(tmp_path, "polprog.sh", body)


def test_polprog_chooses_among_its_own_candidates(lifecycle, tmp_path):
    """(success) `atlas 50% 0% polprog`: the engine hands the program every
    atlas copy as `<group> <touched> <size> <key>`, releases exactly the keys
    the decision file names, books the rest as unapproved and removes both
    exchange files."""
    aside = tmp_path / "candidates.copy"
    prog = _polprog(tmp_path, f'cp "$1" {aside}\n'
                              'printf "/atlas/a2\\n/atlas/a3\\n" > "$2"')
    base, _victim, elog = _lab(lifecycle, tmp_path,
                               "brix_frm_purge_policy atlas 50% 0% polprog; "
                               f"brix_frm_purge_polprog {prog};")
    assert _summary(elog)[:2] == [2, 2000]
    assert _released(PLAN, base) == ["atlas/a2", "atlas/a3"]
    assert _pass_line(elog).groups() == ("1", "0", "2", "ok", "2", "0")
    lines = aside.read_text().splitlines()
    assert sorted(l.split()[3] for l in lines) == [f"/atlas/a{i}" for i in
                                                    range(1, 5)]
    assert all(re.fullmatch(r"atlas \d{9,} 1000 /atlas/a[1-4]", l) for l in lines)
    online = base / ".online"
    assert not (online / ".brix-purge.candidates").exists()
    assert not (online / ".brix-purge.decision").exists()


def test_polprog_decision_cannot_reach_outside_its_candidates(lifecycle,
                                                              tmp_path):
    """(security-neg) the program may only choose among the copies it was
    handed: another group's key, a traversal, an absolute path, the symlink
    and the unmigrated copy are ignored and nothing but the one legitimate
    key goes."""
    prog = _polprog(tmp_path, 'printf "/misc/m1\\n../../victim.dat\\n/etc/passwd'
                              '\\n/evil\\n/misc/u\\n/atlas/a1\\n" > "$2"')
    base, victim, elog = _lab(lifecycle, tmp_path,
                              "brix_frm_purge_policy atlas 50% 0% polprog; "
                              f"brix_frm_purge_polprog {prog};")
    assert _summary(elog)[:2] == [1, 1000]
    assert _released(ALL_ONLINE, base) == ["atlas/a1"]
    assert _pass_line(elog).groups() == ("1", "0", "3", "ok", "1", "5")
    assert victim.read_bytes() == b"V" * FILE_BYTES
    assert (base / ".online" / "evil").is_symlink()


def test_failing_polprog_fails_closed_for_its_groups_only(lifecycle, tmp_path):
    """(error) a non-zero exit releases nothing of the polprog rule's group
    this pass; the `*` rule still drains the others."""
    prog = _polprog(tmp_path, "exit 1")
    base, _victim, elog = _lab(lifecycle, tmp_path,
                               "brix_frm_purge_policy atlas 50% 0% polprog; "
                               "brix_frm_purge_policy * 2500 500; "
                               f"brix_frm_purge_polprog {prog};")
    assert _summary(elog)[:2] == [5, 5000]
    assert _wait_log(elog, FAILED_RX).group(1) == "non-zero exit"
    assert all(k.startswith("atlas/") for k in
               set(PLAN) - set(_released(PLAN, base)))
    assert _pass_line(elog).groups()[2:4] == ("4", "failed")


def test_hung_polprog_is_killed_at_the_exec_deadline(lifecycle, tmp_path):
    """(error) the program runs under brix_frm_copy_timeout: a hung one is
    SIGKILLed, the pass completes fail-closed, and the child is gone."""
    pidfile = tmp_path / "polprog.pid"
    prog = _polprog(tmp_path, f'echo $$ > {pidfile}\nexec sleep 300')
    # The deadline scales with the host: a fixed 2 s can expire before a
    # loaded machine has even scheduled the program's first line, and then it
    # is killed without recording the pid this test goes on to check.  It
    # stays far below the program's own sleep, so the kill is still the
    # deadline's doing and not the program finishing.
    deadline_s = max(2, int(2 * budget_scale()))
    base, _victim, elog = _lab(lifecycle, tmp_path,
                               "brix_frm_purge_policy atlas 50% 0% polprog; "
                               f"brix_frm_copy_timeout {deadline_s}s; "
                               f"brix_frm_purge_polprog {prog};")
    assert _wait_log(elog, FAILED_RX, 30).group(1) == "deadline exceeded, killed"
    assert _summary(elog)[0] == 0
    assert _released(PLAN, base) == []
    pid = int(pidfile.read_text())
    deadline = time.time() + 5
    while time.time() < deadline and _alive(pid):
        time.sleep(0.1)
    assert not _alive(pid), f"policy program {pid} still runs after the deadline"


def _alive(pid):
    try:
        with open(f"/proc/{pid}/stat") as fh:
            return fh.read().split()[2] != "Z"
    except FileNotFoundError:
        return False


def test_polprog_never_runs_without_pressure(lifecycle, tmp_path):
    """(success) a polprog rule whose group is under neither its own arm nor
    an export-wide one leaves the program unrun: `polprog=idle`."""
    marker = tmp_path / "ran"
    prog = _polprog(tmp_path, f'touch {marker}\n: > "$2"')
    base, _victim, elog = _lab(lifecycle, tmp_path,
                               "brix_frm_purge_policy atlas 200000 0 polprog; "
                               f"brix_frm_purge_polprog {prog};")
    assert _summary(elog)[0] == 0
    assert _pass_line(elog).group(4) == "idle"
    assert not marker.exists()
    assert _online(base) == ALL_ONLINE


def _run_polprog_once(lifecycle, tmp_path, prog):
    """One purge pass through `prog`; the pass line must report ok."""
    _base, _victim, elog = _lab(lifecycle, tmp_path,
                                "brix_frm_purge_policy atlas 50% 0% polprog; "
                                f"brix_frm_purge_polprog {prog};")
    assert _pass_line(elog).group(4) == "ok"






def test_the_policy_program_inherits_no_server_descriptors(lifecycle, tmp_path):
    """(security-neg) the program runs with stdin/stdout/stderr only -- the
    exec adapter's spawn hygiene (own session, fds above 2 closed) covers it
    exactly as it covers the stage command."""
    fds = tmp_path / "fds.txt"
    prog = write_fd_probe(tmp_path / "polprog.py", fds, decision_arg=2)
    _run_polprog_once(lifecycle, tmp_path, prog)
    listing = fds.read_text()
    assert set(_inherited_fds(listing)) >= {0, 1, 2}, listing   # a real listing
    assert not _server_descriptors(listing, prog), listing


def test_the_policy_program_leads_its_own_session(lifecycle, tmp_path):
    """(security-neg) the program is a session and process-group leader with
    no controlling terminal, so the deadline kill reaches everything it
    started and it shares no terminal with the server."""
    out = tmp_path / "identity.txt"
    probe = write_identity_probe(tmp_path / "identity.py")
    _run_polprog_once(lifecycle, tmp_path, _polprog(
        tmp_path, f'echo $$ > {out}\n{probe} >> {out}\n: > "$2"'))
    pid, pgrp, sid, tty = parse_identity(out.read_text())
    assert (pgrp, sid) == (pid, pid), (pid, pgrp, sid)
    assert tty == 0, "the program kept a controlling terminal"


# ----------------------------------------------------------------- grammar


def test_grammar_accepts_the_full_form(tmp_path):
    rc, out = _nginx_t(tmp_path, GROUPS +
                       "brix_frm_purge_policy atlas 90% 70% hold 2h polprog; "
                       "brix_frm_purge_policy * 10g 8g; "
                       "brix_frm_purge_polprog /bin/true;")
    assert rc == 0, out


def test_polprog_without_a_polprog_rule_warns(tmp_path):
    rc, out = _nginx_t(tmp_path, "brix_frm_purge_polprog /bin/true;")
    assert rc == 0 and "the program never runs" in out, out


REJECTED = [
    ("brix_frm_purge_policy lhcb 1g 500m;", "is not a brix_oss_space of this server"),
    ("brix_frm_purge_policy * 90% 80%;", "has no quota to scale percentages"),
    ("brix_frm_purge_policy cms 90% 80%;", "has no positive quota="),
    ("brix_frm_purge_policy atlas 10% 20%;", "must not exceed high"),
    ("brix_frm_purge_policy atlas 1g 20%;", "both be sizes or both percentages"),
    ("brix_frm_purge_policy atlas 1g 1m; brix_frm_purge_policy atlas 2g 1m;",
     "already has a policy"),
    ("brix_frm_purge_policy atlas 1g 1m hold;", "hold needs a time"),
    ("brix_frm_purge_policy atlas 1g 1m hold soon;", 'hold "soon" is not a time'),
    ("brix_frm_purge_policy atlas 1g 1m frobnicate;", "unknown option"),
    ("brix_frm_purge_policy atlas 1g 1m polprog;",
     "no brix_frm_purge_polprog is configured"),
    ("brix_frm_purge_policy atlas 1g 1m polprog; brix_frm_purge_polprog bin/pol;",
     "must be an absolute program path"),
    ("brix_frm_purge_policy at&las 1g 1m;", "is not a valid brix_oss_space name"),
    ("brix_frm_purge_policy atlas plenty 1m;", "thresholds are sizes"),
    ("brix_frm_purge_policy atlas 150% 10%;", "thresholds are sizes"),
    ("brix_frm_purge_policy atlas 1g;", "invalid number of arguments"),
]


@pytest.mark.parametrize("line, needle", REJECTED, ids=[r[1] for r in REJECTED])
def test_grammar_rejections(tmp_path, line, needle):
    """(error) every malformed rule is refused at parse or merge time with the
    message an operator can act on."""
    rc, out = _nginx_t(tmp_path, GROUPS + line)
    assert rc != 0 and needle in out, out


def test_group_writable_polprog_is_refused(tmp_path):
    """(security-neg) the program runs with the worker's credentials; one
    anybody else can rewrite is a privilege hand-off and is refused like
    brix_frm_stagecmd / brix_checksum_plugin."""
    prog = _program(tmp_path, "loose.sh", ": > \"$2\"", mode=0o775)
    assert stat.S_IMODE(prog.stat().st_mode) & stat.S_IWGRP
    rc, out = _nginx_t(tmp_path, GROUPS +
                       "brix_frm_purge_policy atlas 1g 1m polprog; "
                       f"brix_frm_purge_polprog {prog};")
    assert rc != 0 and "group- or world-writable" in out, out


def test_purge_policy_is_not_an_http_directive(tmp_path):
    """(security-neg, grammar) both are stream-server knobs of the tape tier."""
    rc, out = _nginx_t(tmp_path, "", http_directives="brix_frm_purge_policy * 1g 1m;")
    assert rc != 0 and "is not allowed here" in out, out
