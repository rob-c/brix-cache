"""2.0 readiness F8 — site checksum plugins (`brix_checksum_plugin`).

A site whose clients negotiate an algorithm the built-ins do not cover loads a
shared object built against `src/core/compat/checksum_plugin_abi.h`; the
server validates it at config time and then answers the algorithm on every
checksum surface: kXR_query cks (`?cks.type=`), the Qconfig `chksum`
advertisement, `brix_checksum_default`, and WebDAV Want-Digest.

Legs: (success) the contrib FNV-1a plugin answers byte-identically to a Python
reference on root:// and WebDAV, from either the stream or the http main
block; (error) `nginx -t` refuses every malformed registration by name;
(security-negative) a writable object is refused, an unregistered name never
answers, the wire form is host-encoded hex; (pins) the loader's cycle-keyed
reset, RTLD flags, worker hook, command tables and build entries.
"""

import hashlib
import http.client
import os
import re
import struct
import subprocess
from pathlib import Path

import pytest

from settings import BIND_HOST
from server_registry import NginxInstanceSpec

import _test_session_bind_helpers as H
from _test_release20_metrics_helpers import wait_port
from csource_scan import function_body

REPO = Path(__file__).resolve().parents[1]
SRC = REPO / "src"
COMPAT = SRC / "core" / "compat"
ABI = COMPAT / "checksum_plugin_abi.h"
LOADER = COMPAT / "checksum_plugin.c"
CONTRIB = REPO / "contrib" / "checksum-plugins" / "brix_cks_fnv1a64.c"

_SERVER = "lc-r20-cks-plugin"
TEMPLATE = "nginx_lc_r20_cks_plugin.conf"
kXR_query = 3001
kXR_Qcksum = 3
kXR_Qconfig = 7
PAYLOAD = os.urandom(40_000)


def fnv1a64(data: bytes) -> str:
    h = 0xCBF29CE484222325
    for b in data:
        h = ((h ^ b) * 0x100000001B3) & 0xFFFFFFFFFFFFFFFF
    return "%016x" % h


# ---------------------------------------------------------------- plugin build

def _compile(src: Path, so: Path) -> Path:
    cmd = ["cc", "-shared", "-fPIC", "-O2", "-I", str(COMPAT), "-o", str(so), str(src)]
    r = subprocess.run(cmd, capture_output=True, text=True)
    if r.returncode != 0:
        pytest.skip(f"cannot build a plugin here: {r.stderr[:300]}")
    so.chmod(0o644)
    return so


@pytest.fixture(scope="module")
def plugin_dir(tmp_path_factory):
    return tmp_path_factory.mktemp("cks-plugins")


@pytest.fixture(scope="module")
def fnv_so(plugin_dir):
    return _compile(CONTRIB, plugin_dir / "brix_cks_fnv1a64.so")


def _variant(plugin_dir, tag, **subs) -> Path:
    """The contrib source with literal substitutions, compiled under `tag`."""
    text = CONTRIB.read_text()
    for old, new in subs.items():
        assert old in text, old
        text = text.replace(old, new, 1)
    src = plugin_dir / f"{tag}.c"
    src.write_text(text)
    return _compile(src, plugin_dir / f"{tag}.so")


# ------------------------------------------------------------------- harness

def _spec(plugin="", server="", http_main=""):
    return NginxInstanceSpec(
        name=_SERVER,
        template=TEMPLATE,
        template_values={"BIND_HOST": BIND_HOST, "PLUGIN_DIRECTIVES": plugin,
                         "SERVER_DIRECTIVES": server,
                         "HTTP_MAIN_DIRECTIVES": http_main},
        reason="2.0 readiness F8: site checksum plugin loader")


def _launch(lifecycle, **kw):
    ep = lifecycle.start(_spec(**kw))
    Path(ep.data_root, "f.bin").write_bytes(PAYLOAD)
    if not wait_port(ep.port) or not wait_port(ep.extra_ports["HTTP_PORT"]):
        pytest.skip("plugin lab did not come up")
    return ep


def _config_test(lifecycle, **kw) -> str:
    """Combined `nginx -t` output for a registration; '' when it passed."""
    lifecycle.register(_spec(**kw))
    lifecycle.reconfigure(_SERVER)
    r = lifecycle.nginx_test(_SERVER, check=False)
    if r.returncode == 0:
        return ""
    return r.stdout + r.stderr


def _query(port, subcode, payload):
    H.ANON_HOST = BIND_HOST
    sock, _sessid, stream = H._establish_primary(port)
    try:
        body = struct.pack(">H", subcode) + b"\x00" * 14
        status, resp = H._send_req(sock, stream, kXR_query, body=body,
                                   payload=payload)
        return status, resp.split(b"\x00", 1)[0]
    finally:
        sock.close()


def _cksum(port, path):
    status, resp = _query(port, kXR_Qcksum, path)
    assert status == H.kXR_ok, f"Qcksum {path!r}: status {status} {resp!r}"
    alg, _, hexval = resp.partition(b" ")
    return alg.decode(), hexval.decode().strip()


def _chksum_list(port):
    status, resp = _query(port, kXR_Qconfig, b"chksum")
    assert status == H.kXR_ok
    return resp.decode().strip().split(",")


def _digest_header(ep, want):
    conn = http.client.HTTPConnection(BIND_HOST, ep.extra_ports["HTTP_PORT"],
                                      timeout=20)
    try:
        conn.request("GET", "/f.bin", headers={"Want-Digest": want})
        resp = conn.getresponse()
        resp.read()
        return resp.status, resp.getheader("Digest")
    finally:
        conn.close()


def _register(so, name="fnv1a64", parms=""):
    tail = f' "{parms}"' if parms else ""
    return f"brix_checksum_plugin {name} {so}{tail};"


# -------------------------------------------------------------------- success

def test_plugin_answers_root_query_byte_identically_to_the_reference(lifecycle, fnv_so):
    ep = _launch(lifecycle, plugin=_register(fnv_so))
    alg, hexval = _cksum(ep.port, b"/f.bin?cks.type=fnv1a64")
    assert (alg, hexval) == ("fnv1a64", fnv1a64(PAYLOAD))
    assert re.fullmatch(r"[0-9a-f]{16}", hexval), "host-side lowercase hex"


def test_plugin_is_advertised_after_the_builtins_and_leads_as_default(lifecycle, fnv_so):
    ep = _launch(lifecycle, plugin=_register(fnv_so),
                 server="brix_checksum_default fnv1a64;")
    algs = _chksum_list(ep.port)
    assert algs[0] == "fnv1a64" and algs.count("fnv1a64") == 1, algs
    assert "adler32" in algs and "sha256" in algs, algs
    alg, hexval = _cksum(ep.port, b"/f.bin")
    assert (alg, hexval) == ("fnv1a64", fnv1a64(PAYLOAD)), "default drives bare Qcksum"


def test_plugin_registered_in_the_http_block_answers_on_both_listeners(lifecycle, fnv_so):
    ep = _launch(lifecycle, http_main=_register(fnv_so))
    algs = _chksum_list(ep.port)
    assert algs[-1] == "fnv1a64" and algs[0] == "adler32", algs
    assert _cksum(ep.port, b"/f.bin?cks.type=fnv1a64")[1] == fnv1a64(PAYLOAD)
    status, digest = _digest_header(ep, "fnv1a64")
    assert status == 200 and digest == f"fnv1a64={fnv1a64(PAYLOAD)}", digest


def test_parms_reach_the_plugin(lifecycle, plugin_dir, fnv_so):
    ep = _launch(lifecycle, plugin=_register(fnv_so, parms="basis=0000000000000000"))
    h = 0
    for b in PAYLOAD:
        h = ((h ^ b) * 0x100000001B3) & 0xFFFFFFFFFFFFFFFF
    assert _cksum(ep.port, b"/f.bin?cks.type=fnv1a64")[1] == "%016x" % h


# ---------------------------------------------------------------------- error

def _not_elf(plugin_dir):
    txt = plugin_dir / "text.so"
    txt.write_text("not a shared object\n")
    txt.chmod(0o644)
    return txt


# case -> (directive builder, the loader's refusal text). Builders take
# (plugin_dir, fnv_so) so the parametrized test stays a flat table lookup.
_MALFORMED = {
    "missing": (lambda d, so: _register(d / "nope.so"), "stat("),
    "not-elf": (lambda d, so: _register(_not_elf(d)), "dlopen("),
    "no-symbol": (lambda d, so: _register(_variant(
        d, "nosym", **{"brix_cks_plugin = {": "brix_other_symbol = {"})),
        "exports no brix_cks_plugin symbol"),
    "abi": (lambda d, so: _register(_variant(
        d, "abi", **{"    BRIX_CKS_PLUGIN_ABI,": "    BRIX_CKS_PLUGIN_ABI + 1,"})),
        "ABI version mismatch"),
    "name-mismatch": (lambda d, so: _register(so, name="fnv1a"),
                      "does not match the directive"),
    "builtin": (lambda d, so: _register(so, name="md5"), "collides with a built-in"),
    "alias": (lambda d, so: _register(so, name="crc64xz"), "collides with a built-in"),
    "duplicate": (lambda d, so: _register(so) + "\n    " + _register(so),
                  "collides with a built-in algorithm or an earlier plugin"),
    "bad-name": (lambda d, so: _register(so, name="fnv-1a64"), "letters or digits"),
    "relative": (lambda d, so: f"brix_checksum_plugin fnv1a64 {so.name};",
                 "must be absolute"),
    "self-test": (lambda d, so: _register(so, parms="nonsense"),
                  "failed its self-test"),
    "arity": (lambda d, so: f"brix_checksum_plugin fnv1a64 {so} a b;",
              "invalid number of arguments"),
}


@pytest.mark.parametrize("case", sorted(_MALFORMED))
def test_config_test_refuses_each_malformed_registration(lifecycle, plugin_dir, fnv_so, case):
    build, needle = _MALFORMED[case]
    out = _config_test(lifecycle, plugin=build(plugin_dir, fnv_so))
    assert out, f"{case}: nginx -t accepted the registration"
    assert needle in out, f"{case}: {out[-600:]}"


@pytest.mark.parametrize("block", ["plugin", "http_main"])
def test_a_well_formed_registration_passes_config_test(lifecycle, fnv_so, block):
    """One harness registration per test: the lifecycle names are unique."""
    assert _config_test(lifecycle, **{block: _register(fnv_so)}) == ""


# ---------------------------------------------------------- security-negative

def test_a_writable_plugin_is_refused(lifecycle, plugin_dir, fnv_so):
    """A file another account can rewrite is code injection into every worker."""
    loose = plugin_dir / "loose.so"
    loose.write_bytes(fnv_so.read_bytes())
    loose.chmod(0o666)
    out = _config_test(lifecycle, plugin=_register(loose))
    assert "group- or world-writable" in out, out[-600:]


def test_an_unregistered_name_never_answers(lifecycle):
    ep = _launch(lifecycle)
    assert "fnv1a64" not in _chksum_list(ep.port)
    status, resp = _query(ep.port, kXR_Qcksum, b"/f.bin?cks.type=fnv1a64")
    assert not resp.startswith(b"fnv1a64"), resp
    status, digest = _digest_header(ep, "fnv1a64")
    assert status == 200 and not (digest or "").startswith("fnv1a64="), digest


def _many(plugin_dir, n):
    lines = []
    for i in range(n):
        so = _variant(plugin_dir, f"p{i}", **{'"fnv1a64"': f'"p{i}x"'})
        lines.append(_register(so, name=f"p{i}x"))
    return "\n    ".join(lines)


def test_the_ninth_plugin_is_refused(lifecycle, plugin_dir):
    out = _config_test(lifecycle, plugin=_many(plugin_dir, 9))
    assert "at most 8 plugins" in out, out[-600:]


def test_eight_plugins_are_accepted(lifecycle, plugin_dir):
    assert _config_test(lifecycle, plugin=_many(plugin_dir, 8)) == ""


# ----------------------------------------------------------------------- pins

def test_abi_header_is_plain_c_with_no_server_dependency():
    text = ABI.read_text()
    includes = re.findall(r"^#include\s+(.+)$", text, re.M)
    assert includes == ["<stddef.h>"], includes
    assert "ngx_" not in text
    assert 'BRIX_CKS_PLUGIN_SYMBOL       "brix_cks_plugin"' in text
    assert "BRIX_CKS_PLUGIN_DIGEST_MAX   64" in text


def test_loader_pins_reset_flags_writable_check_and_host_side_encoding():
    loader = LOADER.read_text()
    reg = loader[loader.index("brix_cks_plugin_register(ngx_conf_t *cf"):]
    assert reg.index("cks_registry_reset(cf->cycle);") < reg.index("cks_normalize_name(")
    assert "dlopen((const char *) path->data, RTLD_NOW | RTLD_LOCAL)" in loader
    assert "(st.st_mode & (S_IWGRP | S_IWOTH)) != 0" in loader
    assert "BRIX_CKS_PLUGIN_DIGEST_MAX <= EVP_MAX_MD_SIZE" in loader
    cks = (COMPAT / "checksum.c").read_text()
    branch = cks[cks.index("if (brix_checksum_is_plugin(alg)) {\n        unsigned char digest"):]
    assert "brix_checksum_hex_encode(digest" in branch[:900], "host encodes the wire form"
    lookup = cks[cks.index("brix_checksum_lookup_alg("):]
    assert lookup.index('{ "sha512",') < lookup.index("brix_cks_plugin_lookup(lname, out)"), \
        "built-ins resolve before plugins"


def test_worker_hook_and_both_command_tables_carry_the_directive():
    proc = (SRC / "core" / "config" / "process.c").read_text()
    assert "brix_cks_plugins_init_worker(cycle);" in proc
    stream = (SRC / "protocols" / "root" / "stream" / "directives_tier.h").read_text()
    # The http registration lives in the COMMON http module (directive-registry
    # rule R5): a bare name owned by one protocol module is inert for the others.
    http = (SRC / "core" / "config" / "http_directives_ops.h").read_text()
    for table, scope in ((stream, "NGX_STREAM_MAIN_CONF"), (http, "NGX_HTTP_MAIN_CONF")):
        i = table.index('ngx_string("brix_checksum_plugin")')
        entry = table[i:i + 320]
        assert f"{scope} | NGX_CONF_TAKE23" in entry, entry
        assert "brix_checksum_plugin_directive" in entry
    config = (REPO / "config").read_text()
    for f in ("checksum_plugin.c", "checksum_plugin.h", "checksum_plugin_abi.h"):
        assert f"src/core/compat/{f}" in config, f


# ------------------------------------------- the advertisement is complete
#
# Found while checking a 2.0 doc row: sha512 is a built-in on every other
# checksum surface (Qcksum, ?cks.type=, Want-Digest, brix_checksum_default)
# but was missing from the ONE list clients negotiate from, and the "is this
# default answerable?" test walked that same short list. So a site that set
# `brix_checksum_default sha512` (or the documented alias crc64xz) advertised
# adler32 at the head and every WLCG client picked adler32 — the configured
# algorithm was computable, reachable by name, and invisible. The emitter now
# asks brix_checksum_parse, the resolver Qcksum itself uses, so the two
# surfaces cannot disagree again.


def _builtin_table() -> list[tuple[str, str]]:
    """(name, enum) rows of brix_checksum_lookup_alg's table, in order."""
    body = function_body((COMPAT / "checksum.c").read_text(), "brix_checksum_lookup_alg")
    return re.findall(r'\{\s*"([a-z0-9]+)",\s*(BRIX_CHECKSUM_[A-Z0-9]+)\s*\}', body)


def _canonical_builtins() -> list[str]:
    """One name per algorithm id — the first spelling; the rest are aliases."""
    seen, canonical = set(), []
    for name, enum in _builtin_table():
        if enum not in seen:
            seen.add(enum)
            canonical.append(name)
    return canonical


def _names_absent_from(rel: str, names) -> list[str]:
    """Which of `names` the doc at docs/<rel> never spells out."""
    text = (REPO / "docs" / rel).read_text(encoding="utf-8")
    return sorted(n for n in names if n not in text)

def test_sha512_is_advertised_and_leads_when_it_is_the_default(lifecycle):
    """success: the built-in appears, and a default spelling heads the list."""
    ep = _launch(lifecycle, server="brix_checksum_default sha512;")
    algs = _chksum_list(ep.port)
    assert algs[0] == "sha512", algs
    assert algs.count("sha512") == 1, algs
    alg, hexval = _cksum(ep.port, b"/f.bin")
    assert (alg, hexval) == ("sha512", hashlib.sha512(PAYLOAD).hexdigest())


def test_an_alias_spelling_of_the_default_still_leads_the_list(lifecycle):
    """success: crc64xz resolves to crc64, so it is answerable and advertised."""
    ep = _launch(lifecycle, server="brix_checksum_default crc64xz;")
    algs = _chksum_list(ep.port)
    assert algs[0] == "crc64xz", algs
    assert "crc64" in algs, "the canonical spelling stays on offer too"


def test_an_unanswerable_default_never_reaches_the_advertisement(lifecycle):
    """error: an unknown name is dropped, not echoed — no client negotiates it."""
    ep = _launch(lifecycle, server="brix_checksum_default blake3;")
    algs = _chksum_list(ep.port)
    assert "blake3" not in algs, algs
    assert algs[0] == "adler32", algs


def test_a_plugin_name_is_not_advertised_until_it_is_registered(lifecycle):
    """security negative: naming a plugin as the default cannot conjure it.

    The default is operator input that reaches an emitter; it must never
    widen what the server claims to answer beyond what it loaded.
    """
    ep = _launch(lifecycle, server="brix_checksum_default fnv1a64;")
    algs = _chksum_list(ep.port)
    assert "fnv1a64" not in algs, algs
    status, _ = _query(ep.port, kXR_Qcksum, b"fnv1a64:/f.bin")
    assert status == H.kXR_error


def test_every_non_alias_builtin_is_on_the_advertised_list():
    """The pin: a new built-in that skips the cslist is the same defect again."""
    cfg = (SRC / "protocols" / "root" / "query" / "config.c").read_text()
    advertised = re.findall(r'"([a-z0-9]+)"',
                            cfg.split("brix_qconf_chksum_algs[] = {")[1].split("};")[0])
    canonical = _canonical_builtins()
    assert canonical, "could not parse the built-in table"
    assert sorted(canonical) == sorted(advertised), (
        f"built-ins {sorted(canonical)} != advertised {sorted(advertised)}")


_COUNT_WORDS = {8: "eight", 9: "nine", 10: "ten", 11: "eleven", 12: "twelve"}


def test_the_comparison_docs_count_the_builtins_they_promise():
    """A migration argument that miscounts the built-ins understates the product.

    Both comparison pages phrase the checksum row as "<word> built-ins"; the word
    read "nine" while the code shipped ten, because zcrc32 -- a distinct algorithm
    id, not an alias -- was missing from the same enumeration the Qconfig cslist
    had dropped it from. Count from the table, never from memory.
    """
    canonical = {enum for _, enum in _builtin_table()}
    assert canonical, "could not parse the built-in table"
    word = _COUNT_WORDS[len(canonical)]
    for rel in ("10-reference/gaps-vs-xrootd.md",
                "10-reference/source-verified-xrootd-comparison.md"):
        text = (REPO / "docs" / rel).read_text(encoding="utf-8")
        claims = re.findall(r"([A-Za-z]+) built-ins", text)
        assert claims, f"{rel} no longer states a built-in count"
        assert {c.lower() for c in claims} == {word}, (
            f"{rel} claims {claims}, the table has {len(canonical)} ({word})")


def test_the_docs_that_enumerate_the_builtins_enumerate_all_of_them():
    """A short list in the operator guide is how a working algorithm stays unknown.

    Four pages spell the set out name by name: the Qconfig row in the CRC-64
    reference, the "request a different algorithm" prose in the operations guide,
    the migration row in the gap ledger, and the checksum section of the
    data-plane comparison — which listed nine and omitted `sha512` until
    2026-09-09. Each is checked against the table, so a new built-in cannot ship
    advertised on the wire and absent from the prose.
    """
    canonical = _canonical_builtins()
    assert len(canonical) >= 10, canonical
    unnamed = {rel: _names_absent_from(rel, canonical)
               for rel in ("10-reference/crc64-checksums.md",
                           "05-operations/management.md",
                           "10-reference/gaps-vs-xrootd.md",
                           "10-reference/comparison/xrootd-vs-nginx/"
                           "04-data-plane-and-performance.md")}
    offenders = {rel: names for rel, names in unnamed.items() if names}
    assert not offenders, f"docs that never name a built-in: {offenders}"


def test_the_default_gate_asks_the_shared_resolver_not_a_local_list():
    """Pin the fix itself: one resolver behind Qcksum and the advertisement."""
    cfg = (SRC / "protocols" / "root" / "query" / "config.c").read_text()
    gate = function_body(cfg, "qconf_chksum_default_known")
    assert "brix_checksum_parse" in gate
    assert "brix_qconf_chksum_algs" not in gate


def test_qconfig_emitter_appends_plugins_after_the_builtins():
    cfg = (SRC / "protocols" / "root" / "query" / "config.c").read_text()
    body = cfg[cfg.index("brix_qconfig_emit_chksum(ngx_stream_brix_srv_conf_t"):]
    assert body.index("brix_qconf_chksum_algs[i]") < body.index("brix_cks_plugin_name_at(i)")
    assert "qconf_chksum_default_known(dflt, dlen)" in body
