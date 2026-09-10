"""phase-115 W8.2 — a scalar directive that skips its UNSET sentinel is
rejected as "duplicate" on its FIRST use.

Discovered while wiring `brix_tpc_outbound_renew_lead` and
`brix_tpc_outbound_renew_strict`.  Both were declared correctly — directive
table entry, `common.*` field, merge default — and both were refused by
`nginx -t` the first time a config named them:

    nginx: [emerg] "brix_tpc_outbound_renew_lead" directive is duplicate

The stock `ngx_conf_set_*_slot` setters use the field's own value as the
"already set" marker: anything other than `NGX_CONF_UNSET` means a second
directive.  `ngx_pcalloc` hands out zeroed memory, and 0 is a perfectly
ordinary value for a `time_t` or an `ngx_flag_t` — so a field that is not
explicitly parked at its sentinel in `brix_shared_conf_init()` looks, to the
first directive that writes it, exactly like a second one.  The merge default
is defeated at the same time and for the same reason.

That makes this the rare class of defect whose symptom names the wrong cause:
the diagnostic says "duplicate", the config contains one line, and the
directive appears entirely correct at every site a reviewer would check.
`src/core/config/shared_conf.h` already carries a comment saying so, written
when phase-105 W2 hit it — a comment nothing enforced, which is why it was hit
again here.  These tests enforce it.

  1. STATIC — every scalar `common.*` slot directive in the tree is parked at
     its sentinel at create time.  Exhaustive over the directive tables, so a
     directive added tomorrow is covered without anyone remembering this file.
  2. LIVE — the two W8.2 directives are accepted on their first use, which is
     the exact assertion that failed before the fix, and a genuine duplicate
     is still rejected (the sentinel must not be bought by disabling the
     duplicate check).
  3. NEGATIVE — a non-value is still refused, so parking the field did not turn
     the setter into something that accepts anything.
  4. CENSUS — the http-plane adopt list.  Two stream-only flags are
     deliberately not adopted; pinning the pair means a THIRD one has to be
     argued for rather than merged silently.
"""

import re
import subprocess
from pathlib import Path

import pytest

from brix_suite.nginx_tools import _nginx_bin
from cmdscripts.live_common import inject_nginx_load_modules
from settings import BIND_HOST

REPO_ROOT = Path(__file__).resolve().parents[1]

#: The stock setters that treat the field's own value as the "seen already"
#: marker.  Str/ptr slots use NULL and are safe under pcalloc, so they are not
#: part of this invariant.
SENTINEL_SLOTS = (
    "ngx_conf_set_flag_slot", "ngx_conf_set_sec_slot",
    "ngx_conf_set_num_slot", "ngx_conf_set_msec_slot",
    "ngx_conf_set_size_slot", "ngx_conf_set_off_slot",
)

#: Stream-plane concepts the HTTP plane deliberately does not adopt: pgwrite is
#: a root-protocol wire verb, and read_only_public gates the root read-only
#: gateway role.  Neither has an HTTP meaning.
NOT_ADOPTED_BY_HTTP = {"require_pgwrite", "read_only_public"}

_ENTRY = re.compile(r'\{\s*ngx_string\("([a-z0-9_]+)"\)\s*,(.*?)NULL\s*\}', re.S)
_COMMON_FIELD = re.compile(r"offsetof\([^,]+,\s*common\.([a-z0-9_]+)\)")


def _slot_directives():
    """(directive, field, source file) for every scalar `common.*` slot."""
    found = []
    for path in sorted((REPO_ROOT / "src" / "protocols" / "root")
                       .glob("**/directives*.h")):
        text = path.read_text(encoding="utf-8")
        for match in _ENTRY.finditer(text):
            name, body = match.group(1), match.group(2)
            if not any(slot in body for slot in SENTINEL_SLOTS):
                continue
            field = _COMMON_FIELD.search(body)
            if field:
                found.append((name, field.group(1), path.name))
    return found


@pytest.fixture(scope="module")
def slots():
    found = _slot_directives()
    assert found, "the directive-table scan matched nothing; the entry shape " \
                  "changed and this guard has gone blind"
    return found


def test_every_scalar_common_slot_is_parked_at_its_sentinel(slots):
    """The invariant itself.  A field left at pcalloc's 0 makes its own
    directive unusable — the first line that names it is refused as a
    duplicate, and the merge default never applies."""
    init = (REPO_ROOT / "src" / "core" / "config" / "shared_conf.h").read_text(
        encoding="utf-8")
    missing = [(name, field, src) for name, field, src in slots
               if not re.search(r"conf->%s\s*=\s*NGX_CONF_UNSET" % field, init)]
    assert missing == [], (
        "these directives write a common.* scalar through a stock slot setter "
        "but their field is not parked at NGX_CONF_UNSET in "
        "brix_shared_conf_init(); each one is rejected as \"duplicate\" the "
        f"first time a config uses it: {missing}")


def test_the_two_renewal_directives_are_accepted_on_first_use(tmp_path):
    """The live regression.  Before the sentinels were added this asserted
    config failed with `[emerg] ... is duplicate` — one occurrence, one
    server block, nothing duplicated."""
    rc, out = _nginx_t(tmp_path,
                       "brix_tpc_outbound_renew_lead 3600;\n"
                       "    brix_tpc_outbound_renew_strict on;")
    assert rc == 0, out
    assert "duplicate" not in out, out


@pytest.mark.parametrize("directive,value", [
    ("brix_tpc_outbound_renew_lead", "3600"),
    ("brix_tpc_outbound_renew_strict", "on"),
])
def test_a_real_duplicate_is_still_rejected(tmp_path, directive, value):
    """The sentinel must be bought by initialising the field, never by
    weakening the duplicate check the setter performs for free."""
    rc, out = _nginx_t(tmp_path, f"{directive} {value};\n    {directive} {value};")
    assert rc != 0, out
    assert f'"{directive}" directive is duplicate' in out, out


@pytest.mark.parametrize("line,needle", [
    ("brix_tpc_outbound_renew_lead nonsense;", "invalid value"),
    ("brix_tpc_outbound_renew_strict maybe;", 'it must be "on" or "off"'),
    ("brix_tpc_outbound_renew_lead;", "invalid number of arguments"),
])
def test_a_bad_renewal_value_is_refused(tmp_path, line, needle):
    """Negative: parking the field at a sentinel must not make the setter
    accept values it should reject."""
    rc, out = _nginx_t(tmp_path, line)
    assert rc != 0, out
    assert needle in out, out


def test_the_http_adopt_census_is_the_known_stream_only_pair(slots):
    """The other half of the same wiring: a `common.*` scalar reaches the HTTP
    plane through http_common.c's BRIX_ADOPT_VAL list.  Two are deliberately
    absent; pinning the pair keeps a third from joining them silently."""
    adopt = (REPO_ROOT / "src" / "core" / "config" / "http_common.c").read_text(
        encoding="utf-8")
    absent = {field for _name, field, _src in slots
              if not re.search(r"BRIX_ADOPT_VAL\(\s*%s\s*," % field, adopt)}
    assert absent == NOT_ADOPTED_BY_HTTP, (
        "the set of common.* scalars the HTTP plane does not adopt moved. A "
        "new name here is a directive that silently has no effect over HTTP; a "
        f"missing one gained an HTTP meaning. absent={sorted(absent)}")


def _nginx_t(root, srv_directives):
    """`nginx -t` on a minimal stream server carrying `srv_directives`.
    Mirrors tests/test_cache_directive_parse.py:19, but execs the per-process
    FROZEN binary: the shared build tree can be relinked mid-run, and exec
    during that window fails with EACCES rather than a config verdict."""
    (root / "logs").mkdir(exist_ok=True)
    (root / "data").mkdir(exist_ok=True)
    conf = root / "sentinel.conf"
    conf.write_text(f"""daemon off; error_log {root}/logs/e.log info;
pid {root}/n.pid; thread_pool default threads=2;
events {{ worker_connections 64; }}
stream {{ server {{ listen {BIND_HOST}:13297;
    brix_root on;
    brix_storage_backend posix:{root}/data;
    brix_auth none;
    brix_tpc_allow_local on;
    {srv_directives}
}} }}
""")
    inject_nginx_load_modules(conf)
    proc = subprocess.run([_nginx_bin(), "-t", "-p", str(root), "-c", str(conf)],
                          capture_output=True, text=True, timeout=30)
    return proc.returncode, proc.stderr + proc.stdout
