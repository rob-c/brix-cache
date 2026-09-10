"""2.0 release-readiness pins for the *registered but never armed* class.

``test_release20_registered_nowhere.py`` closed the case where a directive has
everything except an ``ngx_command_t`` entry.  Registering the Pelican
advertiser exposed the next layer of the same disease, and it is worse because
``nginx -t`` is silent about it: the directive parses, the field is written,
the merge runs — and the runtime gate that decides whether the feature *does*
anything reads a DIFFERENT field that no directive can write.  The feature is
configurable and permanently off.

Every instance found in 2.0 read ``cache_origin_host`` / ``cache_origin_port``,
orphaned when the ``brix_cache_origin`` family was retired in phase-64 §14.
The fields survive only as the parameter block of the SYNTHETIC
``ngx_stream_brix_srv_conf_t`` that ``sd_xroot`` (and ``gsi_upstream_login``)
hands to the in-process origin wire client; on a real server conf they are
empty forever.  The six sites:

* D1 the Pelican advertiser's scheduler gate — registered in 2.0 and still
  inert, because the federation authority was read from the orphaned host.
  Fixed by ``brix_cache_advertise_federation``, the eighth name of the family.
* D2 the cache-bypass redirect (an object the admission policy declined):
  answered ``kXR_Unsupported`` instead of redirecting to the origin.
* D3 the ``kXR_Qcksum``-by-path cache-miss redirect: answered "not found".
* D4 the fill spine's backend resolution, skipped whenever an origin was
  "configured" — a branch that could never be taken.
* D5 the ``kXR_attrCache`` login advert's second arm — constant false.
* D6 the write-back stage builder's origin arm — constant false.

The class guard at the bottom is the durable part: it holds the orphaned
fields to the five files that legitimately touch them, so the next reader that
gates a feature on an unwritable field fails here rather than shipping.

Run:
  PYTHONPATH=tests python3 -m pytest tests/test_release20_never_armed.py -v
"""

from pathlib import Path
import re

import pytest

from config_parse import nginx_t
from csource_scan import function_body, strip_comments

REPO = Path(__file__).resolve().parent.parent
SRC = REPO / "src"
DOCS = REPO / "docs"
DIRECTIVES_MD = DOCS / "03-configuration" / "directives.md"
READINESS_MD = DOCS / "10-reference" / "release-2.0-readiness.md"
SCAFFOLD = "nginx_audit16nparse.conf"
PARSE_PORT = 13299   # never bound: `nginx -t` only

pytestmark = [pytest.mark.timeout(120)]

SLOTS = ("LOC_KNOBS", "SRV_KNOBS", "HTTP_KNOBS", "OUTER",
         "STREAM_KNOBS", "STREAM_MAIN", "EXTRA_LOC")

MISPLACED = ("is not allowed here", "unknown directive")

FED = "brix_cache_advertise_federation"


def _render(tmp_path, **placed):
    (tmp_path / "logs").mkdir(exist_ok=True)
    data = tmp_path / "data"
    data.mkdir(exist_ok=True)
    values = {slot: "" for slot in SLOTS}
    for slot, line in placed.items():
        values[slot] = f"        {line}\n"
    return nginx_t(SCAFFOLD, tmp_path, PORT=PARSE_PORT, STREAM_PORT=PARSE_PORT,
                   LOG_DIR=str(tmp_path / "logs"), DATA=str(data), **values)


def _read(*parts):
    return (SRC.joinpath(*parts)).read_text(encoding="utf-8")


def _code(*parts):
    """A file's code with its prose blanked — a pin must not match a comment."""
    return strip_comments(_read(*parts))


# ------------------------------------------------- (1) the federation grammar

ACCEPTED = [
    "osg-htc.org",
    "osg-htc.org:8443",
    "192.0.2.10:8443",
    "[2001:db8::1]:8443",
]


@pytest.mark.parametrize("value", ACCEPTED)
def test_federation_accepts_a_host_with_an_optional_port(tmp_path, value):
    """`host`, `host:port`, a literal v4 address and a bracketed v6 address are
    the four spellings a federation authority is written in.  The bare form
    defaults to 443 because the discovery document is fetched over HTTPS."""
    line = f"{FED} {value};"
    result = _render(tmp_path, STREAM_KNOBS=line)
    assert result.returncode == 0, f"{line!r} should parse:\n{result.stderr}"


REFUSED = [
    ("https://osg-htc.org", "expected host[:port]"),
    ("osg-htc.org/director", "expected host[:port]"),
    ("osg-htc.org:0", "expected host[:port]"),
    ("osg-htc.org:70000", "expected host[:port]"),
]


@pytest.mark.parametrize("value,needle", REFUSED, ids=[v for v, _n in REFUSED])
def test_federation_refuses_a_url_a_path_or_a_bad_port(tmp_path, value, needle):
    """Error case: the value is an authority, not a URL.  A silently accepted
    `https://` prefix would be baked into the well-known URL as
    `https://https://…` and every advertisement would fail at DNS time — long
    after `nginx -t` said the config was good."""
    line = f"{FED} {value};"
    result = _render(tmp_path, STREAM_KNOBS=line)
    assert result.returncode != 0, f"{line!r} should be refused"
    assert needle in result.stderr + result.stdout, \
        f"{line!r}: expected {needle!r} in:\n{result.stderr}"


@pytest.mark.parametrize("line,needle", [
    (f"{FED};", "invalid number of arguments"),
    (f"{FED} a.example.org b.example.org;", "invalid number of arguments"),
    (f"{FED} a.example.org; {FED} b.example.org;", "is duplicate"),
])
def test_federation_refuses_bad_arity_or_a_second_authority(tmp_path, line, needle):
    """A cache belongs to exactly one federation: a second directive is a
    configuration mistake, not a fallback list, and must not be silently
    last-one-wins."""
    result = _render(tmp_path, STREAM_KNOBS=line)
    assert result.returncode != 0, f"{line!r} should be refused"
    assert needle in result.stderr + result.stdout, \
        f"{line!r}: expected {needle!r} in:\n{result.stderr}"


def test_federation_is_refused_on_the_http_plane(tmp_path):
    """Security-negative: the authority names who may be told where this
    cache's data lives, and it is signed for with the advertise key.  It is a
    stream-server knob; accepted in an http location it would read as
    configured while the advertiser stayed disarmed — exactly the failure this
    whole suite exists to prevent."""
    line = f"{FED} osg-htc.org;"
    result = _render(tmp_path, LOC_KNOBS=line)
    assert result.returncode != 0, f"{line!r} should be refused"
    text = result.stderr + result.stdout
    assert any(n in text for n in MISPLACED), text


def test_federation_resolution_is_deferred_to_runtime():
    """INVARIANT 13: a config-time parse never resolves a name.  An operator
    who configures a federation that is briefly unresolvable must still be
    able to start nginx."""
    body = function_body(_code("fs", "cache", "directives.c"),
                         "brix_conf_set_cache_advertise_federation")
    assert re.search(r"no_resolve\s*=\s*1", body)
    assert "getaddrinfo" not in body


# ------------------------------------------------------ (2) D1..D6 site pins

def test_d1_advertiser_arms_on_the_federation_not_an_orphan_field():
    """D1: the scheduler declined forever because `cache_origin_host` is empty
    on every real conf.  The gate now reads the field a directive writes, and
    the discovery URL is built from it."""
    reg = _code("fs", "cache", "origin", "pelican_register.c")
    assert "cache_origin" not in reg
    assert "advertise.federation" in reg
    assert ".well-known/pelican-configuration" in reg


def test_d2_declined_admission_redirects_to_the_backend_endpoint():
    """D2: `brix_cache_bypass_redirect` resolves the origin from the task's
    source instance (the export's registered root:// backend), and the caller
    only errors when no endpoint can be named."""
    thread = _code("fs", "cache", "thread.c")
    assert "brix_sd_xroot_endpoint(t->source_inst" in thread
    assert "cache_origin" not in thread
    assert "brix_cache_bypass_redirect(t, ctx, c) != 0" in thread


def test_d3_qcksum_cache_miss_redirects_to_the_backend_endpoint():
    """D3: the by-path checksum miss resolves the backend through the VFS
    registry instead of the orphaned host, so it can redirect at all."""
    qck = _code("protocols", "root", "query", "checksum_qcksum_path.c")
    assert "brix_vfs_backend_resolve(conf->common.root_canon" in qck
    assert "brix_sd_xroot_endpoint(" in qck
    assert "cache_origin" not in qck


def test_d4_fill_spine_always_resolves_the_registered_backend():
    """D4: backend resolution used to be skipped when an origin was
    "configured"; the branch was unreachable, and removing it makes the
    registered backend the single source of a fill."""
    spine = _code("fs", "cache", "open_or_fill.c")
    assert "cache_origin" not in spine
    assert "brix_vfs_backend_resolve(conf->common.root_canon" in spine


def test_d5_attr_cache_advert_has_no_constant_false_arm():
    """D5: the login advert's cache bit is decided by the cache store alone."""
    proto = _code("protocols", "root", "session", "protocol.c")
    arm = proto.split("kXR_attrCache")[-2].rsplit("|", 1)[-1]
    assert "cache_root.len > 0" in arm
    assert "cache_origin" not in arm


def test_d6_write_back_stage_gates_on_the_write_through_origin():
    """D6: a write-back stage needs `brix_wt_origin`; the orphaned arm made the
    second half of the test constant-false, so the stage was built on the
    strength of `brix_wt_mode` alone."""
    body = function_body(_code("fs", "cache", "cache_storage.c"),
                         "cache_build_wt_stage")
    guard = body.split("return;")[0]
    assert "conf->wt.origin_host.len == 0" in guard
    assert "cache_origin" not in guard


def test_the_two_stale_operator_messages_name_a_live_directive():
    """The same defect at diagnostic level: the startup NOTICE printed an
    always-empty origin, and the TLS refusal told the operator to enable a
    directive retired two phases ago."""
    runtime = _code("core", "config", "runtime_server.c")
    notice = runtime.split('"brix: cache enabled')[1].split(";")[0]
    assert "common.storage_backend" in notice
    assert "cache_origin" not in notice
    boot = _code("fs", "cache", "origin_protocol_bootstrap.c")
    tls = boot.split("kXR_TLSRequired")[-1][:200]
    assert "roots://" in tls and "brix_storage_backend" in tls


# ------------------------------------------------------- (3) the class guard

# The only files that may name the orphaned synthetic fields: the declaration,
# the two synthetic-conf writers, and the two wire-client readers that run
# against a possibly-synthetic `t->conf`.  Matched by BASENAME on purpose — a
# path-keyed allowlist silently stops guarding whatever gets moved — with an
# existence assertion below so a rename cannot empty the guard either.
SYNTH_ONLY = {
    "srv_conf_fields_net.h": SRC / "core" / "types" / "srv_conf_fields_net.h",
    "sd_xroot.c": SRC / "fs" / "backend" / "xroot" / "sd_xroot.c",
    "origin_connection.c": SRC / "fs" / "cache" / "origin_connection.c",
    "origin_protocol_bootstrap.c": SRC / "fs" / "cache" / "origin_protocol_bootstrap.c",
    "gsi_upstream_login.c": SRC / "net" / "proxy" / "gsi_upstream_login.c",
}

ORPHANED = ("cache_origin_host", "cache_origin_port")


def _names_an_orphan(path):
    code = strip_comments(path.read_text(encoding="utf-8", errors="replace"))
    return any(field in code for field in ORPHANED)


def test_the_allowlisted_synthetic_conf_files_all_exist():
    """A moved or renamed file must break this pin loudly, not quietly widen
    the allowlist to nothing."""
    for name, path in SYNTH_ONLY.items():
        assert path.is_file(), f"{name} moved; re-point SYNTH_ONLY"


def test_no_new_reader_gates_a_feature_on_an_unwritable_field():
    """The durable class guard.  `cache_origin_host` / `cache_origin_port` are
    written by NO directive; anything outside the synthetic-conf plumbing that
    reads them is a feature that can never arm."""
    offenders = [str(path.relative_to(REPO)) for path in sorted(SRC.rglob("*.[ch]"))
                 if _names_an_orphan(path) and SYNTH_ONLY.get(path.name) != path]
    assert not offenders, (
        "these files gate on a field no directive writes: " + ", ".join(offenders))


def test_the_field_declaration_says_it_is_synthetic_only():
    """The next reader learns this from the struct, not from a bug report."""
    fields = _read("core", "types", "srv_conf_fields_net.h")
    block = fields.split("read-through cache")[1].split("cache_origin_bearer")[0]
    assert "SYNTHETIC-CONF ONLY" in block
    assert "brix_sd_xroot_endpoint" in block


def test_the_retired_origin_directives_are_registered_nowhere():
    """The other half of the contract: these names must stay unknown, so a
    config carrying them fails loudly instead of writing a field that only the
    synthetic path reads."""
    registry = strip_comments(
        "\n".join(p.read_text(encoding="utf-8")
                  for p in (SRC / "protocols" / "root" / "stream").glob("directives*.h")))
    for name in ("brix_cache_origin", "brix_cache_origin_tls",
                 "brix_cache_origin_proxy", "brix_cache_origin_token_file"):
        assert f'ngx_string("{name}")' not in registry


@pytest.mark.parametrize("value", ["brix_cache_origin host:1094;",
                                   "brix_cache_origin_tls on;"])
def test_a_config_using_a_retired_origin_directive_is_refused(tmp_path, value):
    """Security-negative: a copied-forward pre-2.0 config must not start a
    cache that silently ignores where its data was supposed to come from."""
    result = _render(tmp_path, STREAM_KNOBS=value)
    assert result.returncode != 0, f"{value!r} should be refused"
    assert "unknown directive" in result.stderr + result.stdout


# --------------------------------------------------------------- (4) prose

def test_the_federation_directive_is_documented_for_operators():
    """(d): an operator cannot guess that the advertiser needs an authority as
    well as a key — that is precisely what made the family inert."""
    text = DIRECTIVES_MD.read_text(encoding="utf-8")
    section = text.split("### Pelican federation cache advertisement")[1].split("\n---")[0]
    assert FED in section
    assert "pelican-configuration" in section


def test_the_class_is_recorded_in_the_readiness_register():
    """The register is the doc of record for 2.0; a defect class with no row
    there is a class the next audit re-discovers from scratch."""
    text = READINESS_MD.read_text(encoding="utf-8")
    assert "Registered but never armed" in text
    section = text.split("Registered but never armed")[1].split("\n## ")[0]
    for site in ("D1", "D2", "D3", "D4", "D5", "D6"):
        assert site in section, f"{site} has no register row"
    assert "test_release20_never_armed.py" in section
