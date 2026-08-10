"""brix_posc_persist — the ofs.persist analog (parity audit §1.9).

A crash mid non-staged write leaves a "<final>.xrd-tmp.<pid>.<rand>" temp
orphaned in the export tree; the boot-time reaper (src/core/compat/tmp_path.c,
run once at worker-0 startup) removes dead-owner orphans while keeping any whose
owner pid is still live (a draining worker during reload). Stock XRootD lets
`ofs.persist` govern that recovery. `brix_posc_persist <auto|manual|off>
[hold <time>]` now does the same:

  * auto (default) — reap dead-owner orphans (historical behaviour, unchanged)
  * manual / off   — KEEP orphans for an operator to inspect/recover
  * hold <time>    — grace period: an orphan is reaped only once it has been
                     idle at least <time>, so a temp whose writer is about to
                     reconnect-and-resume is not nuked mid-recovery

Two layers, no running server:

  * TestReaperPolicy   — the reaper behaviour, a standalone C unit test against
                         the real compiled tmp_path.o (auto/manual/off/hold plus
                         the security-negative that only ".xrd-tmp." names are
                         ever touched).
  * TestDirectiveParse — `nginx -t` accept/reject for the directive grammar.

Run:
    PYTHONPATH=tests pytest tests/test_posc_persist.py -v
"""

import os
import subprocess

import pytest

from cmdscripts import c_object_units
from cmdscripts.live_common import inject_nginx_load_modules
from settings import BIND_HOST, NGINX_BIN

_OBJS = os.environ.get("TEST_NGINX_OBJS", "/tmp/nginx-1.28.3/objs")
_TMP_PATH_O = os.path.join(_OBJS, "addon", "compat", "tmp_path.o")

pytestmark = [pytest.mark.timeout(120)]


# --------------------------------------------------------------------------- #
# Layer 1 — reaper behaviour (C unit test against the real tmp_path.o)
# --------------------------------------------------------------------------- #
class TestReaperPolicy:

    def test_reaper_policy_unit(self, tmp_path):
        """auto reaps dead-owner orphans (keeping live-owner + non-matching
        files); manual/off keep them; hold spares fresh orphans until they age
        out; and only ".xrd-tmp." names are ever removed (security-neg)."""
        if not os.path.exists(_TMP_PATH_O):
            pytest.skip(f"tmp_path.o not built under {_OBJS}; build the module first")
        (ok, out), = c_object_units.run_checks(tmp_path, ["tmp_reap"])
        if out.startswith("SKIP"):
            pytest.skip(out)
        assert ok, f"tmp_reap unit tests failed:\n{out}"
        assert "0 failed" in out, f"unexpected tmp_reap output:\n{out}"


# --------------------------------------------------------------------------- #
# Layer 2 — directive grammar (`nginx -t` only, no server start)
# --------------------------------------------------------------------------- #
def _nginx_t(root, srv_directives):
    (root / "logs").mkdir(exist_ok=True)
    (root / "data").mkdir(exist_ok=True)
    conf = root / "posc.conf"
    conf.write_text(f"""daemon off; error_log {root}/logs/e.log info;
pid {root}/n.pid; thread_pool default threads=2;
events {{ worker_connections 64; }}
stream {{ server {{ listen {BIND_HOST}:13299;
    brix_root on;
    brix_storage_backend posix:{root}/data;
    brix_auth none;
    {srv_directives}
}} }}
""")
    inject_nginx_load_modules(conf)
    p = subprocess.run([str(NGINX_BIN), "-t", "-p", str(root), "-c", str(conf)],
                       capture_output=True, text=True, timeout=30)
    return p.returncode, p.stderr + p.stdout


ACCEPT = [
    "brix_posc_persist auto;",
    "brix_posc_persist manual;",
    "brix_posc_persist off;",
    "brix_posc_persist auto hold 1h;",
    "brix_posc_persist manual hold 600;",
    "brix_posc_persist off hold 30m;",
]

# (directive-line, needle-in-diagnostic)
REJECT = [
    ("brix_posc_persist bogus;", "must be auto, manual or off"),
    ("brix_posc_persist auto wait 1h;", 'expected "hold"'),
    ("brix_posc_persist auto hold notatime;", "invalid hold time"),
    # arg-count is fixed at 1 or 3 by NGX_CONF_TAKE1|TAKE3 — 2 args is refused
    # by nginx itself before the setter runs.
    ("brix_posc_persist auto hold;", "invalid number of arguments"),
]


class TestDirectiveParse:

    @pytest.mark.parametrize("directive", ACCEPT)
    def test_accepted(self, tmp_path, directive):
        rc, out = _nginx_t(tmp_path, directive)
        assert rc == 0, f"expected accept for {directive!r}:\n{out}"
        assert "successful" in out

    @pytest.mark.parametrize("directive,needle", REJECT)
    def test_rejected(self, tmp_path, directive, needle):
        rc, out = _nginx_t(tmp_path, directive)
        assert rc != 0, f"expected reject for {directive!r}:\n{out}"
        assert needle in out, f"expected {needle!r} for {directive!r}, got:\n{out}"
