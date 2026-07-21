"""Phase-89 D.1 — grammar pin for the surviving ``brix_frm_*`` directive surface.

The src/frm dissolution (phase-64) retired the FRM subsystem but 21
``brix_frm_*`` directives survived in
src/protocols/root/stream/directives_net.inc, contra the phase-64 §13c-step-4
plan.  ADR-3 (docs/refactor/phase-89-design-backlog-burndown.md §D.1) records
the ratify-vs-migrate decision as PENDING OP confirmation; until it is taken,
operator configs in the field depend on this exact grammar.

This pin freezes the contract with no server start (``nginx -t`` only):
  * success — every surviving directive parses with a representative value;
  * error   — a malformed numeric value is rejected with a diagnostic;
  * security-neg — the grammar is CLOSED: a directive name outside the pinned
    inventory ("unknown directive") is rejected, so a silent-accept regression
    (e.g. a wildcard handler swallowing typo'd knobs) cannot creep in.

If ADR-3 lands as "migrate to brix_stage_*", update this file in the SAME
change that removes the directives — a red pin here is the tripwire that the
config-compat break is deliberate.
"""

import subprocess

import pytest

from settings import NGINX_BIN

# The pinned inventory — must match directives_net.inc exactly.  A directive
# added or removed there without touching this list is the drift this test
# exists to catch (grep 'ngx_string("brix_frm' to regenerate).
FRM_DIRECTIVES = """\
brix_frm on;
brix_frm_queue_path {root}/frm.queue;
brix_frm_max_inflight 4;
brix_frm_max_per_source 2;
brix_frm_stagecmd "/bin/true %s";
brix_frm_copycmd "/bin/true %s %s";
brix_frm_copymax 3;
brix_frm_stage_ttl 30s;
brix_frm_xfrhold 5s;
brix_frm_stage_wait 10;
brix_frm_async_recall on;
brix_frm_fail_backoff 2s;
brix_frm_fail_retries 3;
brix_frm_residency_cmd "/bin/true %s";
brix_frm_copy_timeout 60s;
brix_frm_stage_dir {root}/frm-stage;
brix_frm_force_scratch off;
brix_frm_control_dir {root}/frm-ctl;
brix_frm_migrate_copycmd "/bin/true %s %s";
brix_frm_purge_watermark 0.90 0.80;
brix_frm_purge_interval 5m;
"""


def _nginx_t(root, srv_directives):
    (root / "logs").mkdir(exist_ok=True)
    (root / "data").mkdir(exist_ok=True)
    conf = root / "pin.conf"
    conf.write_text(f"""daemon off; error_log {root}/logs/e.log info;
pid {root}/n.pid; thread_pool default threads=2;
events {{ worker_connections 64; }}
stream {{ server {{ listen 127.0.0.1:13299;
    brix_root on;
    brix_storage_backend posix:{root}/data;
    brix_auth none;
    {srv_directives}
}} }}
""")
    p = subprocess.run([str(NGINX_BIN), "-t", "-p", str(root), "-c", str(conf)],
                       capture_output=True, text=True, timeout=30)
    return p.returncode, p.stderr + p.stdout


def test_frm_surviving_grammar_parses(tmp_path):
    rc, out = _nginx_t(tmp_path, FRM_DIRECTIVES.format(root=tmp_path))
    assert rc == 0, f"pinned brix_frm_* grammar no longer parses:\n{out}"


def test_frm_bad_value_rejected(tmp_path):
    rc, out = _nginx_t(tmp_path, "brix_frm on; brix_frm_max_inflight banana;")
    assert rc != 0, "malformed brix_frm_max_inflight unexpectedly accepted"
    assert "invalid number" in out, f"expected numeric diagnostic, got:\n{out}"


def test_frm_grammar_is_closed(tmp_path):
    rc, out = _nginx_t(tmp_path, "brix_frm on; brix_frm_bogus_knob 1;")
    assert rc != 0, "unknown brix_frm_* directive unexpectedly accepted"
    assert "unknown directive" in out, f"expected unknown-directive, got:\n{out}"
