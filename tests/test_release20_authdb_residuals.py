"""2.0 readiness F20 — the native-authdb grammar residuals.

F20 closed two silent-widening paths in ``src/auth/authz/``: field 1 of an
authdb line used to be truncated to its lead byte (so ``vl`` was read as ``v``
and matched **more** subjects than the operator wrote), and an unknown
privilege letter was dropped (so ``x`` — and every typo — evaporated).  Both
now refuse the line.  Field 1 is a SET of 1..6 distinct selectors from
``u g p a v l``; a compound rule splits its id on ``|`` into one component per
selector; ``x`` is the new stage/recall privilege kXR_prepare's ``kXR_stage`` /
``kXR_evict`` arms demand on top of ``r``.

Wiring F20 up end to end surfaced two defects that had never had a witness,
and both are pinned here:

* **the VOMS role never reached the identity.**  ``brix_collect_voms_vos``
  appended only bare VO names, and ``brix_vo_token_is_safe`` rejects ``/`` by
  design (a VO name is a metric label and a log field — INVARIANT 8), so
  ``acc_role_csv`` was ALWAYS empty: the new ``l`` selector and the XrdAcc
  engine's own ``role`` template could never match anything.  A dedicated raw
  FQAN channel (``brix_extract_voms_fqans`` → ``login.fqan_list`` →
  ``brix_identity_set_vos_fqans``) now feeds the attribute derivation while
  leaving ``vo_list``/``primary_vo`` and every log and metric consumer
  byte-identical.
* **compound ``v``+``l`` matched ACROSS FQAN tuples.**  The selectors were
  ANDed independently, so a credential holding cms/Role=NULL *plus*
  atlas/Role=production satisfied ``vl cms|production``.  ``adb_pair_matches``
  now pairs the two index-aligned CSVs positionally, exactly as the XrdAcc
  engine already did (``acc/entity.c::acc_entity_fill_tuples``).

Legs: a compound ``v``/``l`` rule matches only a subject satisfying both
selectors and an ``x`` rule grants exactly its privilege (success); an unknown
selector or privilege letter, a repeat, a wrong ``|`` arity and an
untokenizable line are each a refused line with its own message, not a dropped
character (error); a compound rule is strictly narrower than its lead
selector, a cross-tuple credential never satisfies a paired rule, ``x`` is not
implied by ``r``/``w``, one refused line refuses the WHOLE configuration, and
no metric label or log line ever carries an FQAN (security negative).  Plus
the compat layer: the xrdacc engine still accepts every line the native
grammar refuses, on both the stream and the HTTP plane.
"""
from __future__ import annotations

import os
import pathlib
import re
import subprocess

import pytest

from _test_release20_metrics_helpers import samples, scrape, wait_for, wait_port
from _test_vo_acl_helpers import (
    _gsi_env, _guard_vo_nginx_1, _guard_vo_nginx_2, _make_voms_proxy,
    _make_voms_proxy_multi, _make_voms_signing_cert, _make_vomsdir,
)
from server_registry import NginxInstanceSpec
from cmdscripts.live_common import inject_nginx_load_modules, inject_nginx_runtime_paths
from settings import (
    BIND_HOST, CA_CERT, CA_DIR, HOST, SERVER_CERT, SERVER_KEY, VOMSDIR,
)

pytestmark = [pytest.mark.uses_lifecycle_harness,
              pytest.mark.xdist_group("lc-r20-authdb-f20")]

NGINX_BIN = os.environ.get("NGINX_BIN", "/tmp/nginx-1.28.3/objs/nginx")

PKI = {"SERVER_CERT": SERVER_CERT, "SERVER_KEY": SERVER_KEY, "CA_CERT": CA_CERT,
       "CA_DIR": CA_DIR, "VOMSDIR": VOMSDIR, "BIND_HOST": BIND_HOST}

FQAN_CMS      = "/cms/Role=NULL/Capability=NULL"
FQAN_ATLAS_P  = "/atlas/Role=production/Capability=NULL"
FQAN_ATLAS_N  = "/atlas/Role=NULL/Capability=NULL"

# One export, one authdb.  Every arm below reads a verdict off THIS file, so
# the rule that produced it is always visible in the test source.
#
#   /public     `a *`                 — the open control, any identity
#   /roleonly   `l production`        — the `l` selector ALONE: nothing but a
#                                       real VOMS role can satisfy it
#   /vonly      `v atlas`             — the lead selector of the compound rule
#   /vlonly     `vl atlas|production` — the compound rule itself
#   /crosstuple `vl cms|production`   — satisfiable only by ONE FQAN that is
#                                       both cms and production; the
#                                       cross-tuple credential holds neither
#   /gvonly     `gv cms|cms`          — a compound rule mixing a VO-list
#                                       selector with an attribute selector
#   /stage      `a * rlx`             — the `x` privilege
#   /nostage    `a * rl`              — read yes, stage no
AUTHDB = """\
a * /public rl
l production /roleonly rl
v atlas /vonly rl
vl atlas|production /vlonly rl
vl cms|production /crosstuple rl
gv cms|cms /gvonly rl
a * /stage rlx
a * /nostage rl
"""

DIRS = ("public", "roleonly", "vonly", "vlonly", "crosstuple", "gvonly",
        "stage", "nostage")


class Lab:
    """The running F20 export plus the four differently-attributed proxies."""

    def __init__(self, ep, proxies, log_dir):
        self.ep = ep
        self.log_dir = log_dir
        for name, path in proxies.items():
            setattr(self, name, path)

    @property
    def url(self):
        return f"root://{HOST}:{self.ep.port}"

    def _run(self, argv, proxy):
        return subprocess.run(["xrdfs", self.url] + argv, env=_gsi_env(proxy),
                              capture_output=True, text=True, timeout=30)

    def cat(self, path, proxy):
        return self._run(["cat", path], proxy).returncode

    def stat(self, path, proxy):
        return self._run(["stat", path], proxy).returncode

    def prepare_stage(self, path, proxy):
        return self._run(["prepare", "-s", path], proxy).returncode

    def scrape(self):
        return scrape(self.ep.extra_ports["METRICS_PORT"])

    def error_log(self):
        return (self.log_dir / "error.log").read_text(errors="replace")


def _proxies(tmp_path):
    """The four credentials the arms need.  Only `cms` and `atlas` have LSC
    directories in the test vomsdir, so the arms vary the ROLE, not the VO —
    except `cross`, which is a genuine two-AC multi-VO proxy."""
    _guard_vo_nginx_1()
    _make_voms_signing_cert()
    _make_vomsdir()
    _guard_vo_nginx_2()

    out = {}
    for name, vo, fqan in (("cms", "cms", FQAN_CMS),
                           ("atlas_prod", "atlas", FQAN_ATLAS_P),
                           ("atlas_norole", "atlas", FQAN_ATLAS_N)):
        out[name] = str(tmp_path / f"proxy_{name}.pem")
        _make_voms_proxy(vo, fqan, out[name])

    # vorg_csv "cms,atlas", role_csv ",production": every selector is satisfied
    # by SOME tuple, no single tuple satisfies `vl cms|production`.
    out["cross"] = str(tmp_path / "proxy_cross.pem")
    _make_voms_proxy_multi([("cms", FQAN_CMS), ("atlas", FQAN_ATLAS_P)],
                           out["cross"])
    return out


@pytest.fixture
def lab(lifecycle, tmp_path):
    proxies = _proxies(tmp_path)

    data = tmp_path / "data"
    data.mkdir()
    (data / "authdb").write_text(AUTHDB)
    for d in DIRS:
        (data / d).mkdir()
        (data / d / "seed.txt").write_text(f"seed in {d}\n")

    ep = lifecycle.start(NginxInstanceSpec(
        name="lc-r20-authdb-f20", template="nginx_lc_r20_authdb_f20.conf",
        data_root=str(data), template_values=PKI,
        reason="2.0 readiness F20: the native-authdb grammar residuals"))

    lab = Lab(ep, proxies, pathlib.Path(ep.prefix) / "logs")
    if wait_for(lambda: True if lab.cat("/public/seed.txt", lab.cms) == 0
                else None, 25) is None:
        pytest.skip("lc-r20-authdb-f20 never answered a GSI read of /public")
    if not wait_port(ep.extra_ports["METRICS_PORT"]):
        pytest.skip("lc-r20-authdb-f20 exposed no /metrics")
    return lab


# ===========================================================================
# success
# ===========================================================================

def test_a_voms_role_now_reaches_authorization(lab):
    """(success) DISCOVERY: before F20's FQAN channel the identity's role CSV
    was ALWAYS empty, so `l production` matched nobody and the rule was dead
    config.  The production proxy reads /roleonly; the role-less cms proxy —
    which the `a *` rule proves is otherwise authenticated and served — does
    not."""
    assert lab.cat("/roleonly/seed.txt", lab.atlas_prod) == 0, \
        "the VOMS role did not reach the identity: `l production` matched nothing"
    assert lab.cat("/public/seed.txt", lab.cms) == 0
    assert lab.cat("/roleonly/seed.txt", lab.cms) != 0


def test_a_compound_rule_matches_a_subject_satisfying_both_selectors(lab):
    """(success) `vl atlas|production` admits the atlas/production proxy, and
    `gv cms|cms` admits the cms proxy through two DIFFERENT identity views (the
    VO list and the FQAN-derived vorg CSV) at once."""
    assert lab.cat("/vlonly/seed.txt", lab.atlas_prod) == 0
    assert lab.cat("/gvonly/seed.txt", lab.cms) == 0


def test_the_x_privilege_grants_exactly_the_stage(lab):
    """(success) `a * /stage rlx` grants the read AND kXR_prepare's kXR_stage
    arm on the same subtree."""
    assert lab.cat("/stage/seed.txt", lab.cms) == 0
    assert lab.prepare_stage("/stage/seed.txt", lab.cms) == 0


# ===========================================================================
# error — every refused line, by its own message
# ===========================================================================

def _nginx_t(root, authdb_text, extra="", engine_directive=""):
    """Parse-only arm: a prefix-relative Unix listener avoids path limits.
    `nginx -t` never binds it.  `brix_auth host` satisfies the native
    engine's "authdb needs an authenticating scheme" gate without any PKI."""
    (root / "logs").mkdir(parents=True, exist_ok=True)
    (root / "data").mkdir(exist_ok=True)
    (root / "authdb").write_text(authdb_text)
    conf = root / "authdb.conf"
    conf.write_text(f"""daemon off; error_log {root}/logs/e.log info;
pid {root}/n.pid; thread_pool default threads=2;
events {{ worker_connections 64; }}
stream {{ server {{ listen unix:s.sock;
    brix_root on; brix_storage_backend posix:{root}/data;
    brix_auth host; brix_host_allow localhost;  # net-literal-allow: host-auth configuration subject
    {engine_directive}
    brix_authdb {root}/authdb;
    {extra}
}} }}
""")  # net-literal-allow: host-auth config payload is the parser subject
    inject_nginx_load_modules(conf)
    inject_nginx_runtime_paths(conf, root)
    p = subprocess.run([NGINX_BIN, "-t", "-p", str(root), "-c", str(conf)],
                       capture_output=True, text=True, timeout=30)
    return p.returncode, p.stderr + p.stdout


# Each row: the offending line, and the substring of the refusal that names
# exactly what was wrong with it.  A dropped character would leave `nginx -t`
# green, which is the whole point of the F20 change.
REFUSALS = [
    pytest.param("z * /x r", "unknown identity selector 'z'", id="unknown-selector"),
    pytest.param("u * /x rQ", "unknown privilege letter 'Q'", id="unknown-privilege"),
    pytest.param("vv a|b /x r", "identity selector repeated 'v'", id="repeated-selector"),
    pytest.param("vl atlas /x r",
                 "exactly one '|'-separated id component per selector",
                 id="arity-too-few"),
    pytest.param("vl |production /x r", "empty id component", id="empty-component"),
    pytest.param("au *|* /x r", "cannot be combined with another selector",
                 id="any-combined"),
    pytest.param("u * /x", "expected `<selectors> <id> <path> <privs>`",
                 id="untokenizable"),
    pytest.param("ugpavlu a|b|c|d|e|f|g /x r",
                 "more identity selectors than", id="over-long-field-1"),
]


@pytest.mark.parametrize("line,needle", REFUSALS)
def test_a_bad_line_is_refused_by_name_not_silently_narrowed(tmp_path, line, needle):
    """(error) every byte of field 1 and field 4 is either understood or names
    itself in an `nginx -t` refusal — the pre-F20 behaviour was to truncate
    field 1 to its lead byte and drop an unknown privilege letter, both of
    which changed the rule the operator wrote without a word."""
    rc, out = _nginx_t(tmp_path, line + "\n")
    assert rc != 0, f"line {line!r} was ACCEPTED:\n{out}"
    assert needle in out, f"line {line!r} refused, but not for the stated reason:\n{out}"
    assert "line 1:" in out, f"the refusal does not name the line number:\n{out}"


def test_a_single_selector_rule_still_takes_its_id_verbatim(tmp_path):
    """(error, boundary) only a COMPOUND rule reads `|` as a separator.  A
    one-selector rule keeps taking its id byte for byte — DNs are full of
    punctuation and splitting them would break every deployed authdb — so the
    same token that is an arity error above is a legal literal id here."""
    rc, out = _nginx_t(tmp_path, "v atlas|production /x r\n")
    assert rc == 0, out


def test_a_good_file_still_parses(tmp_path):
    """(error, control) the same harness accepts the real grammar, so the arms
    above are refusing the LINE and not the surrounding configuration."""
    rc, out = _nginx_t(tmp_path, AUTHDB)
    assert rc == 0, out


# ===========================================================================
# security negative
# ===========================================================================

def test_a_compound_rule_never_grants_what_its_lead_selector_would(lab):
    """(security negative) the pre-F20 truncation read `vl atlas|production`
    as `v atlas`.  The role-less atlas proxy is admitted by the lead selector's
    own rule (/vonly) and REFUSED by the compound one (/vlonly), so a
    regression to the truncating parser fails here loudly."""
    assert lab.cat("/vonly/seed.txt", lab.atlas_norole) == 0
    assert lab.cat("/vlonly/seed.txt", lab.atlas_norole) != 0


def test_a_cross_tuple_credential_never_satisfies_a_paired_rule(lab):
    """(security negative) DISCOVERY: the `cross` proxy carries cms/Role=NULL
    AND atlas/Role=production, so its vorg CSV contains "cms" and its role CSV
    contains "production" — testing the two selectors independently grants
    `vl cms|production`, which no single FQAN of that credential supports.
    The pairing is positional, so /crosstuple is denied while the tuple the
    credential really holds (/vlonly) is served."""
    assert lab.cat("/vlonly/seed.txt", lab.cross) == 0, \
        "the multi-VO proxy did not authenticate at all — the arm below proves nothing"
    assert lab.cat("/vonly/seed.txt", lab.cross) == 0
    assert lab.cat("/crosstuple/seed.txt", lab.cross) != 0, \
        "a cross-tuple credential satisfied `vl cms|production`"


def test_no_holder_of_one_half_of_the_pair_gets_the_other(lab):
    """(security negative) neither single-VO proxy may reach /crosstuple: the
    cms proxy has the vorg and not the role, the atlas proxy the role and not
    the vorg."""
    assert lab.cat("/crosstuple/seed.txt", lab.cms) != 0
    assert lab.cat("/crosstuple/seed.txt", lab.atlas_prod) != 0


def test_the_stage_privilege_is_not_implied_by_read_or_write(lab):
    """(security negative) /nostage grants `rl` on a `brix_allow_write on`
    export.  Before 2.0 kXR_stage sat in the BRIX_AUTH_UPDATE range, so a `w`
    grant implied staging; it must now name `x`.  The read still works, which
    proves the denial is the privilege and not the path."""
    assert lab.stat("/nostage/seed.txt", lab.cms) == 0
    assert lab.cat("/nostage/seed.txt", lab.cms) == 0
    assert lab.prepare_stage("/nostage/seed.txt", lab.cms) != 0


def test_one_refused_line_refuses_the_whole_configuration(tmp_path):
    """(security negative) a defect on the LAST line refuses the file — the
    server never comes up holding the rules that parsed before it.  The
    alternative (skip the line, keep the rest) is a namespace whose policy
    silently differs from the file on disk."""
    rc, out = _nginx_t(tmp_path, AUTHDB + "u * /late rQ\n")
    assert rc != 0, out
    assert "unknown privilege letter 'Q'" in out
    assert f"line {len(AUTHDB.splitlines()) + 1}:" in out, out


def _label_is_clean(name, key, val):
    """INVARIANT 8: an FQAN carries '/' and '=' and is unbounded, so it may
    never be a label value; a VO NAME may, but only as the `vo` label of the
    bounded brix_vo_* families."""
    assert "Role=" not in val and "Capability=" not in val, (name, key, val)
    assert "/" not in val and "=" not in val, (name, key, val)
    if key == "vo":
        assert name.startswith("brix_vo_") and val in ("cms", "atlas"), (name, val)


def _every_label_is_clean(scrape):
    """No metric label anywhere in the scrape carries FQAN punctuation.  `export`
    is exempt: it is the configured export root, config-time and bounded."""
    for name, labels, _ in samples(scrape):
        for key, val in labels.items():
            if key != "export":
                _label_is_clean(name, key, val)


def _no_fqan_reached_the_log(log):
    """Neither a whole FQAN nor a bare `Role=` survives into the error log."""
    for fqan in (FQAN_CMS, FQAN_ATLAS_P, FQAN_ATLAS_N):
        assert fqan not in log, f"{fqan} was logged"
    assert not re.search(r"Role=[A-Za-z]", log), \
        "a VOMS role reached the error log"


def test_the_fqan_csv_is_never_a_label_and_never_a_log_field(lab):
    """(security negative) DISCOVERY: the raw FQAN channel is read exactly once,
    by brix_identity_set_vos_fqans.  Drive every proxy through the export, then
    prove the FQANs reached authorization without reaching /metrics or the
    error log — which is precisely why they could not simply be appended to
    vo_list."""
    for proxy in (lab.cms, lab.atlas_prod, lab.atlas_norole, lab.cross):
        lab.cat("/public/seed.txt", proxy)
    _every_label_is_clean(lab.scrape())
    _no_fqan_reached_the_log(lab.error_log())


# ===========================================================================
# compat layer — the xrdacc engine reads the same directive
# ===========================================================================

# An XrdAcc authfile is full of bytes the native grammar has never accepted;
# `brix_authdb` is nevertheless parsed by the NATIVE parser at directive time
# (the engine has not settled yet), so the defect is recorded and only raised
# at merge time, and only for the native engine.
XRDACC_FILE = """\
= grp /cms
u * /public rl
g cms /cms rl
"""


def test_the_xrdacc_engine_still_accepts_what_the_native_grammar_refuses(tmp_path):
    """(compat) the deferral: the same file that refuses under the native
    engine parses under `brix_authdb_engine xrdacc`, so 2.0's new strictness
    cannot refuse an existing XrdAcc deployment at startup."""
    rc, out = _nginx_t(tmp_path / "native", XRDACC_FILE)
    assert rc != 0, f"the native engine accepted an XrdAcc authfile:\n{out}"
    assert "brix_authdb_engine xrdacc" in out, \
        f"the refusal does not point at the engine that would accept it:\n{out}"

    rc, out = _nginx_t(tmp_path / "xrdacc", XRDACC_FILE,
                       engine_directive="brix_authdb_engine xrdacc;")
    assert rc == 0, f"the xrdacc engine refused its own authfile:\n{out}"


def _http_nginx_t(root, authdb_text, acc_format=""):
    """The HTTP plane's twin of _nginx_t: `brix_authdb` under a WebDAV
    location, with `brix_acc_format` selecting the engine.  The CA is what
    makes `brix_webdav`'s own verifier gate pass, so the only thing left that
    can refuse the configuration is the authdb grammar."""
    (root / "logs").mkdir(parents=True, exist_ok=True)
    (root / "data").mkdir(exist_ok=True)
    (root / "authdb").write_text(authdb_text)
    conf = root / "http_authdb.conf"
    conf.write_text(f"""daemon off; error_log {root}/logs/e.log info;
pid {root}/n.pid; thread_pool default threads=2;
events {{ worker_connections 64; }}
http {{
    access_log off;
    client_body_temp_path {root}/cbt;
    proxy_temp_path {root}/pt; fastcgi_temp_path {root}/ft;
    uwsgi_temp_path {root}/ut; scgi_temp_path {root}/st;
    server {{ listen unix:h.sock;
        location / {{
            brix_webdav on; brix_storage_backend posix:{root}/data;
            brix_trusted_ca {CA_CERT};
            {acc_format}
            brix_authdb {root}/authdb;
        }}
    }}
}}
""")
    inject_nginx_load_modules(conf)
    inject_nginx_runtime_paths(conf, root)
    p = subprocess.run([NGINX_BIN, "-t", "-p", str(root), "-c", str(conf)],
                       capture_output=True, text=True, timeout=30)
    return p.returncode, p.stderr + p.stdout


def test_the_http_plane_defers_the_same_defect_to_the_same_engine_choice(tmp_path):
    """(compat) `brix_http_conf_set_authdb` runs the native parser for the same
    reason the stream one does, so the HTTP plane must refuse and forgive the
    same file on the same engine choice."""
    rc, out = _http_nginx_t(tmp_path / "h-native", XRDACC_FILE)
    assert rc != 0, f"the HTTP native engine accepted an XrdAcc authfile:\n{out}"

    rc, out = _http_nginx_t(tmp_path / "h-xrdacc", XRDACC_FILE,
                            acc_format="brix_acc_format xrdacc;")
    assert rc == 0, f"the HTTP xrdacc engine refused its own authfile:\n{out}"
