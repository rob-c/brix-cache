"""2.0 release-readiness pins for the *registered nowhere* defect class.

A directive can be fully implemented — setter, config field, merge default,
runtime reader, header prose — and still be unreachable, because nothing puts
it in an ``ngx_command_t`` table.  ``nginx -t`` then answers "unknown
directive" and the code that reads the field only ever sees the merge default.
The 2.0 audit found three instances and one diagnostic-level cousin:

* ``brix_cache_verify_digest`` — the algorithm a NON-``root://`` origin is
  asked for when ``brix_cache_verify`` is armed; implemented, never
  registered, so an HTTP/Pelican origin was always asked for whatever it
  chose to volunteer.
* the whole ``brix_cache_advertise*`` Pelican family (eight names) — a signed
  ``OriginAdvertiseV2`` publisher with a per-worker timer, a JWT signer and a
  document builder, none of which an operator could switch on.  Seven were
  registered here; the eighth, ``brix_cache_advertise_federation``, was added
  when registration alone turned out not to arm the advertiser — see
  ``test_release20_never_armed.py`` for that second defect class.
* ``brix_cache_verify`` on the standalone (``brix_cache``) fill spine — the
  directive registered and parsed, but the spine read a *different*, unwritable
  field, so ``off`` and ``require`` were silently ignored there.
* nine ``ngx_conf_log_error`` diagnostics naming directives that do not exist
  (``brix_proxy_upstream`` for ``brix_tap_proxy_upstream``, and friends) — the
  same defect one level out: the operator is sent to a name nginx will refuse.

Every pin here is cheap: a tree scan or ``nginx -t`` against
``tests/configs/nginx_audit16nparse.conf``.  No server is started, so the file
runs under ``TEST_SKIP_SERVER_SETUP=1``.

Run:
  PYTHONPATH=tests python3 -m pytest tests/test_release20_registered_nowhere.py -v
"""

from pathlib import Path
import re
import sys

import pytest

from config_parse import nginx_t

REPO = Path(__file__).resolve().parent.parent
SRC = REPO / "src"
DOCS = REPO / "docs"
DIRECTIVES_MD = DOCS / "03-configuration" / "directives.md"
SCAFFOLD = "nginx_audit16nparse.conf"
PARSE_PORT = 13298   # never bound: `nginx -t` only

pytestmark = [pytest.mark.timeout(120)]

# ---------------------------------------------------------------- scaffolding

SLOTS = ("LOC_KNOBS", "SRV_KNOBS", "HTTP_KNOBS", "OUTER",
         "STREAM_KNOBS", "STREAM_MAIN", "EXTRA_LOC")

MISPLACED = ("is not allowed here", "unknown directive")


def _render(tmp_path, **placed):
    (tmp_path / "logs").mkdir(exist_ok=True)
    data = tmp_path / "data"
    data.mkdir(exist_ok=True)
    values = {slot: "" for slot in SLOTS}
    for slot, line in placed.items():
        values[slot] = f"        {line}\n"
    return nginx_t(SCAFFOLD, tmp_path, PORT=PARSE_PORT, STREAM_PORT=PARSE_PORT,
                   LOG_DIR=str(tmp_path / "logs"), DATA=str(data), **values)


def _assert_accepted(result, line):
    assert result.returncode == 0, f"{line!r} should parse:\n{result.stderr}"


def _assert_refused(result, line, *needles):
    assert result.returncode != 0, f"{line!r} should be refused"
    text = result.stderr + result.stdout
    assert any(n in text for n in needles), \
        f"{line!r}: expected one of {needles} in:\n{text}"


def _registered_names():
    sys.path.insert(0, str(REPO / "tools" / "ci"))
    import check_directive_registry as registry   # noqa: E402
    return {row[0] for row in registry.collect()}


def _src_files():
    return sorted(p for p in SRC.rglob("*.[ch]"))


# ------------------------------------------- (1) diagnostics name real knobs

_CONF_DIAG = re.compile(r"ngx_conf_log_error\s*\((.*?)\);", re.S)
_LITERAL = re.compile(r'"((?:[^"\\]|\\.)*)"')
_BRIX_TOKEN = re.compile(r"brix_[a-z0-9_]+")

# Non-directive brix_ tokens that a config-time diagnostic may legitimately
# name (helper functions, environment variables, file names).  Empty today:
# every brix_ token in every conf diagnostic is a directive an operator can
# actually write.  A new entry here is a deliberate declaration, not a waiver
# of the pin below.
DIAGNOSTIC_NON_DIRECTIVES: frozenset = frozenset({
    "brix_pki",  # PKI loader log prefix, not an operator-settable directive.
})


def _diagnostic_names(text):
    """Yield (line, brix_token) for every token inside a conf-time message."""
    for match in _CONF_DIAG.finditer(text):
        message = "".join(_LITERAL.findall(match.group(1)))
        line = text.count("\n", 0, match.start()) + 1
        for token in _BRIX_TOKEN.findall(message):
            yield line, token


def _unregistered_diagnostics(text, registered):
    return [(line, token) for line, token in _diagnostic_names(text)
            if token not in registered
            and token not in DIAGNOSTIC_NON_DIRECTIVES]


def test_conf_diagnostics_name_only_registered_directives():
    """An `nginx -t` error that names a directive must name a REAL one.

    Nine did not before 2.0: `brix_proxy_upstream`, `brix_proxy_auth`,
    `brix_proxy_login_user`, `brix_gridftp_require_vo`, `brix_kv`,
    `brix_s3_storage_credential`, `brix_webdav_storage_credential`,
    `brix_webdav_crl` and `brix_token`.  An operator who followed any of them
    got "unknown directive" from the very fix the server suggested.
    """
    registered = _registered_names()
    hits = []
    for path in _src_files():
        text = path.read_text(encoding="utf-8", errors="replace")
        hits += [f"{path.relative_to(REPO)}:{line}: {token}"
                 for line, token in _unregistered_diagnostics(text, registered)]
    assert not hits, "conf diagnostics naming unregistered directives:\n" + "\n".join(hits)


def test_diagnostic_scan_detects_a_planted_unregistered_name():
    """Security-negative for the scanner itself: the pin above is only worth
    its green if the scan would actually see a bad name.  A vacuous regex (a
    changed emitter, a reshaped literal) would pass silently forever."""
    planted = ('ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,\n'
               '    "brix_no_such_knob: set brix_also_not_a_knob first");\n')
    found = {token for _line, token in
             _unregistered_diagnostics(planted, _registered_names())}
    assert found == {"brix_no_such_knob", "brix_also_not_a_knob"}


def test_diagnostic_scan_accepts_a_planted_registered_name():
    """...and does not fire on a diagnostic that names a real directive."""
    planted = ('ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,\n'
               '    "brix_cache_verify require: set brix_cache_verify_digest");\n')
    assert _unregistered_diagnostics(planted, _registered_names()) == []


# ------------------------------------------------- (2) brix_cache_verify_digest

DIGEST_OK = [
    ("brix_cache_verify_digest adler32;", "STREAM_KNOBS"),
    ("brix_cache_verify_digest sha256;", "STREAM_KNOBS"),
    ("brix_cache_verify_digest md5;", "LOC_KNOBS"),
    ("brix_cache_verify_digest crc32c;", "SRV_KNOBS"),
    ("brix_cache_verify_digest sha1;", "HTTP_KNOBS"),
]


@pytest.mark.parametrize("line,slot", DIGEST_OK, ids=[f"{s}-{l.split()[1]}" for l, s in DIGEST_OK])
def test_cache_verify_digest_accepted_on_both_planes(tmp_path, line, slot):
    """It is registered at all — the whole point — on `stream server` and on
    every HTTP scope, because both planes can carry a composed cache tier."""
    _assert_accepted(_render(tmp_path, **{slot: line}), f"{slot}: {line}")


DIGEST_BAD = [
    ("brix_cache_verify_digest bogusalg;", "STREAM_KNOBS", "unknown algorithm"),
    ("brix_cache_verify_digest bogusalg;", "LOC_KNOBS", "unknown algorithm"),
    ("brix_cache_verify_digest;", "STREAM_KNOBS", "invalid number of arguments"),
    ("brix_cache_verify_digest md5 sha1;", "STREAM_KNOBS", "invalid number of arguments"),
]


@pytest.mark.parametrize("line,slot,needle", DIGEST_BAD,
                         ids=[f"{s}-{n.split()[0]}-{i}" for i, (l, s, n) in enumerate(DIGEST_BAD)])
def test_cache_verify_digest_bad_value_or_arity_refused(tmp_path, line, slot, needle):
    """An algorithm this build cannot compute locally is refused at `nginx -t`.
    Accepting it would arm a verify policy that can never succeed: with
    `require` every fill would fail at run time, on every file, in production."""
    _assert_refused(_render(tmp_path, **{slot: line}), line, needle)


def test_cache_verify_digest_duplicate_refused(tmp_path):
    """Two algorithms in one scope is an ambiguous integrity policy, not a
    last-one-wins convenience: refuse it where the operator can still see it."""
    result = _render(tmp_path, STREAM_KNOBS=(
        "brix_cache_verify_digest adler32;\n"
        "        brix_cache_verify_digest md5;"))
    _assert_refused(result, "duplicate digest", "is duplicate")


def test_cache_verify_digest_refused_in_stream_main(tmp_path):
    """Security-negative: a per-server integrity knob must not be accepted one
    scope wider, where an operator would believe it covered every export in
    `stream{}` while it silently covered none."""
    _assert_refused(_render(tmp_path, STREAM_MAIN="brix_cache_verify_digest md5;"),
                    "stream main", *MISPLACED)


def test_cache_verify_digest_is_read_by_both_fill_spines():
    """The registration is only half the fix: both spines must ASK the origin
    for the named digest.  The standalone spine reads the shared preamble
    field; the composed tier carries it by value in the cache policy."""
    fetch = (SRC / "fs" / "cache" / "fetch.c").read_text(encoding="utf-8")
    assert "common.cache_verify_digest" in fetch
    assert "brix_sd_query_origin_digest" in fetch
    pump = (SRC / "fs" / "backend" / "cache"
            / "sd_cache_fill_verify.c").read_text(encoding="utf-8")
    assert "policy.verify_digest" in pump
    assert "brix_sd_query_origin_digest" in pump


def test_cache_verify_digest_is_documented_with_its_algorithms():
    """(d): the operator needs to know WHICH names are legal and that an
    xroot:// origin ignores the knob."""
    text = DIRECTIVES_MD.read_text(encoding="utf-8")
    section = text.split("### `brix_cache_verify_digest")[1].split("\n---")[0]
    for needle in ("Want-Digest", "brix_checksum_plugin", "root://"):
        assert needle in section, f"{needle!r} missing from the digest prose"


# ---------------------------------------- (3) the standalone verify default

def test_standalone_spine_reads_verify_through_the_one_accessor():
    """`brix_cache_verify off` and `require` were dead on the standalone spine
    because it read a field no directive could write.  Pin the single accessor
    so a future edit cannot reintroduce a second, unwritable source of truth."""
    fetch = (SRC / "fs" / "cache" / "fetch.c").read_text(encoding="utf-8")
    assert fetch.count("brix_cache_verify_effective(") == 2
    assert "conf->cache_verify" not in fetch.replace("conf->cache_verify_", "")


def test_legacy_stream_only_verify_fields_are_gone():
    """Security-negative for the removal: the unwritable duplicates must not
    survive anywhere, or a later reader picks the dead one up again."""
    fields = (SRC / "core" / "types" / "srv_conf_fields_cache.h").read_text(encoding="utf-8")
    decls = [line for line in fields.splitlines()
             if re.search(r"\b(cache_verify|cache_verify_digest)\s*;", line)]
    assert not decls, f"legacy stream-only verify fields still declared: {decls}"


def test_the_two_verify_defaults_are_both_source_true_and_documented():
    """The standalone spine defaults to best-effort and the composed tier to
    off.  They differ on purpose; a doc that states only one is worse than
    none, because an operator reads it as covering both."""
    verify_h = (SRC / "fs" / "cache" / "verify.h").read_text(encoding="utf-8")
    assert "BRIX_CACHE_VERIFY_BESTEFFORT" in verify_h.split(
        "brix_cache_verify_effective")[-1]
    tier = (SRC / "core" / "config" / "runtime_server_backend_cache.c").read_text(encoding="utf-8")
    assert "BRIX_CACHE_VERIFY_OFF" in tier
    doc = DIRECTIVES_MD.read_text(encoding="utf-8")
    section = doc.split("### `brix_cache_verify off")[1].split("\n---")[0]
    assert "best-effort" in section and "composed" in section


# ------------------------------------------------ (4) the Pelican family

ADVERTISE = [
    ("brix_cache_advertise on;", "invalid value", "brix_cache_advertise maybe;"),
    ("brix_cache_advertise_key /etc/brix/ec.pem;", "invalid number of arguments",
     "brix_cache_advertise_key a b;"),
    ("brix_cache_advertise_data_url https://cache.example.org:8443;",
     "invalid number of arguments", "brix_cache_advertise_data_url;"),
    ("brix_cache_advertise_web_url https://cache.example.org;",
     "invalid number of arguments", "brix_cache_advertise_web_url a b;"),
    ("brix_cache_advertise_issuer https://issuer.example.org;",
     "invalid number of arguments", "brix_cache_advertise_issuer;"),
    ("brix_cache_advertise_interval 60s;", "invalid value",
     "brix_cache_advertise_interval never;"),
    ("brix_cache_advertise_namespace /cms;", "invalid number of arguments",
     "brix_cache_advertise_namespace /cms /atlas;"),
    ("brix_cache_advertise_federation osg-htc.org;", "expected host[:port]",
     "brix_cache_advertise_federation https://osg-htc.org;"),
]

ADVERTISE_IDS = [line.split()[0] for line, _needle, _bad in ADVERTISE]


@pytest.mark.parametrize("line,_needle,_bad", ADVERTISE, ids=ADVERTISE_IDS)
def test_advertise_directive_is_registered_on_the_stream_plane(tmp_path, line, _needle, _bad):
    """Before 2.0 every one of these was an unknown directive: the federation
    advertiser existed and could not be switched on from a config file."""
    _assert_accepted(_render(tmp_path, STREAM_KNOBS=line), line)


@pytest.mark.parametrize("line,needle,bad", ADVERTISE, ids=ADVERTISE_IDS)
def test_advertise_directive_rejects_a_bad_value_or_arity(tmp_path, line, needle, bad):
    _assert_refused(_render(tmp_path, STREAM_KNOBS=bad), bad, needle)


@pytest.mark.parametrize("line,_needle,_bad", ADVERTISE, ids=ADVERTISE_IDS)
def test_advertise_directive_refused_on_the_http_plane(tmp_path, line, _needle, _bad):
    """Security-negative: the family carries a PRIVATE SIGNING KEY path and the
    public URLs a Director will redirect clients to.  It is a stream-server
    knob; accepted silently in an http location it would read as configured
    while nothing ever advertised — or, worse, invite the key path into a
    scope the operator never audited."""
    _assert_refused(_render(tmp_path, LOC_KNOBS=line), line, *MISPLACED)


def test_advertise_family_is_registered_in_full():
    """Every operator-settable field of brix_cache_advertise_conf_t has a
    directive.  The one field without its own name — sitename — is filled by
    the pre-existing brix_sitename, which must therefore still target it."""
    registered = _registered_names()
    for name in ADVERTISE_IDS:
        assert name in registered, f"{name} is registered nowhere"
    cms = (SRC / "protocols" / "root" / "stream" / "directives_cms.h").read_text(encoding="utf-8")
    block = cms.split('ngx_string("brix_sitename")')[1].split("NULL },")[0]
    assert "advertise.sitename" in block


def test_advertise_stays_off_until_a_key_and_data_url_are_configured():
    """`brix_cache_advertise on` alone must not start publishing: an ad signed
    by no key, or naming no data URL, is either unsignable or useless.  The
    scheduler declines instead of aborting the worker."""
    reg = (SRC / "fs" / "cache" / "origin" / "pelican_register.c").read_text(encoding="utf-8")
    guard = reg.split("brix_cache_pelican_schedule_advertise")[-1]
    assert "advertise.enable" in guard
    assert "advertise.key.len == 0" in guard
    assert "advertise.federation.len == 0" in guard


def test_advertise_interval_is_clamped_to_the_federation_minimum(tmp_path):
    """A 1s re-advertise would hammer the Director; the merge clamps up to 60s
    rather than refusing, so a small value parses and behaves."""
    _assert_accepted(_render(tmp_path, STREAM_KNOBS="brix_cache_advertise_interval 1s;"),
                     "1s interval")
    merge = (SRC / "core" / "config" / "server_conf_merge_storage.c").read_text(encoding="utf-8")
    clamp = merge.split("advertise.interval")[1].split(";")[0] + merge.split(
        "advertise.interval")[2]
    assert "60000" in clamp


def test_advertise_family_is_documented_for_operators():
    """(d): the out-of-band registry handshake is the step an operator cannot
    guess, so the prose must say it is not performed here."""
    text = DIRECTIVES_MD.read_text(encoding="utf-8")
    section = text.split("### Pelican federation cache advertisement")[1].split("\n---")[0]
    for name in ADVERTISE_IDS:
        assert name in section, f"{name} has no operator prose"
    assert "registry" in section and "out-of-band" in section
    assert "brix_sitename" in section
