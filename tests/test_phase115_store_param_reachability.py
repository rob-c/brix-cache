"""Static guard: no `brix_storage_backend` param may be an unkeepable promise.

Phase-115 W4.3 shipped a store-line param — `verify_pages` — that NOTHING could
honour.  Three independent breaks stacked up, and each was individually silent:

  1. `brix_storage_backend` was NGX_CONF_TAKE1, so `nginx -t` refused any
     trailing token for ARITY before a parser ever saw it;
  2. the param's role gate admitted only BRIX_TIER_BACKEND, but the backend
     tier is never parsed through the tier composer — `brix_tier_build_stack`
     is dead code, and every live backend is built by `brix_vbr_build_*`;
  3. even had it parsed, nothing copied it onto the registry entry the builder
     reads, and `brix_vbr_build_xroot` never set the driver field.

The failure mode is the dangerous kind: an operator writes a word that asks for
verified bytes (or a protected data channel), the config loads, and no byte is
verified.  Nothing at runtime says otherwise.

So this file guards the SEAM by reading the sources, not by running a server.
It is deliberately structural: the behavioural rows live in
test_phase115_pgread_verify_parse.py and
test_phase115_gridftp_data_channel_parse.py, but those only prove a param
PARSES.  These prove it is also carried to the code that builds the driver.
"""

import re
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
SRC = REPO_ROOT / "src"

ARGS_C = SRC / "fs/tier/tier_config_args.c"
STAMP_C = SRC / "fs/vfs/vfs_backend_store_params.c"
ENTRY_H = SRC / "fs/vfs/vfs_backend_internal.h"
BUILDERS = sorted((SRC / "fs/vfs").glob("vfs_backend_registry*.c"))

# Params the tier composer owns and the LIVE BACKEND path deliberately does not
# carry, each with the reason it is not a hole.  Anything not listed here must
# be stamped onto the registry entry by vfs_backend_store_params.c.
COMPOSER_ONLY = {
    # The backend's credential arrives by its own richer path
    # (brix_vfs_backend_set_credential / brix_credential), which carries the
    # x509/token/S3/SSS quartet a tier cfg's single pointer cannot.
    "credential=",
    # pblock object geometry: brix_vfs_backend_config_str already takes
    # pblock_block_size as its own argument, straight off the merged conf.
    "block_size=",
    # tape residency is a SCHEME on the backend line (root+tape://), not a
    # trailing flag — see core/types/fs_list.h.  On a cache/stage line it
    # selects the nearline tier.
    "nearline",
}


# The dispatcher's keyword table.  Anchored on `static const ... [] = {` at
# column 0 and closed by a `};` at column 0, so a PROSE mention of the table
# cannot satisfy it — see `_params_declared` for why that distinction is the
# whole point of this constant existing separately.
KW_TABLE_RE = re.compile(
    r"^static const tier_arg_kw_t\s+tier_arg_kws\[\]\s*=\s*\{(.*?)^\};",
    re.S | re.M)


def _params_declared():
    r"""The store-line param keys the dispatcher routes.

    WHAT: the set of keywords `tier_parse_one_arg` can match, read out of the
    `tier_arg_kws[]` const table in tier_config_args.c.

    WHY it reads the TABLE and not the function body: the dispatch used to be a
    chain of cloned `if (tier_arg_is(arg, "verify_pages", ...))` ifs, and this
    guard scraped those string literals out of the body of the function.  The
    chain was later folded into a one-row-per-param const table, which moved
    every literal out of the function — leaving the scraper reading a body that
    contains no keywords at all.

    HOW that was allowed to go silent, which is the part worth keeping: the old
    regex was `tier_parse_one_arg\(.*?\n\{(.*?)\n\}`, and `tier_arg_is`'s
    own doc comment MENTIONS `tier_parse_one_arg` by name a hundred lines above
    the definition.  The pattern matched that prose, ran on to the next `\n{`,
    and returned a short bogus body — so the `assert m, "the dispatcher moved"`
    line that exists precisely to catch this never fired.  An anti-vacuity
    guard that can be satisfied by a comment is not an anti-vacuity guard, so
    the anchor below is column-anchored on the DEFINITION and the emptiness
    check is a separate, unconditional assertion rather than a side effect of
    the match succeeding.
    """
    body = ARGS_C.read_text()
    m = KW_TABLE_RE.search(body)
    assert m, ("the tier_arg_kws[] routing table is no longer where this guard "
               "reads it (%s) — every row below would go vacuously green"
               % ARGS_C.relative_to(REPO_ROOT))
    keys = set(re.findall(r'\{\s*"([^"]+)"', m.group(1)))
    assert keys, "tier_arg_kws[] matched but parsed to no keywords at all"
    return keys


def test_every_param_is_routed():
    """Sanity: the dispatcher still carries the params this file reasons about.
    A rename that emptied the set would make every row below vacuously green."""
    keys = _params_declared()
    for expected in ("verify_pages", "mode=", "prot=", "credential=",
                     "block_size=", "streams=", "nearline", "permit="):
        assert expected in keys, f"{expected} vanished from tier_arg_kws[]"
    # A census, not just a spot-check: the roster above must BE the table, or a
    # param added without a row here is reasoned about by nothing in this file.
    assert keys == {"verify_pages", "mode=", "prot=", "credential=",
                    "block_size=", "streams=", "nearline", "permit="}, (
        "tier_arg_kws[] carries params this guard has never considered: %s.  "
        "Add each to the roster above, and either stamp it in %s or list it in "
        "COMPOSER_ONLY with the reason it is not a hole."
        % (sorted(keys ^ {"verify_pages", "mode=", "prot=", "credential=",
                          "block_size=", "streams=", "nearline", "permit="}),
           STAMP_C.relative_to(REPO_ROOT)))


def test_no_backend_param_dies_in_the_tier_cfg():
    """THE guard.  Every store-line param that is not explicitly composer-only
    must be copied onto the VFS backend registry entry, because that entry —
    not the tier cfg — is what brix_vbr_build_* reads."""
    stamp = STAMP_C.read_text()
    unreachable = []
    for key in sorted(_params_declared() - COMPOSER_ONLY):
        field = key.rstrip("=")
        # the tier-cfg member the parser writes, e.g. mode= -> ftp_mode_e
        member = re.search(r"tier\.(\w*%s\w*)" % re.escape(field), stamp)
        if member is None:
            unreachable.append(key)
    assert not unreachable, (
        "store-line params parsed into a brix_tier_cfg_t and never carried to "
        "the live backend path — an operator can write them and nothing will "
        "honour them: %s.  Stamp them in %s, or list them in COMPOSER_ONLY "
        "with the reason they are not a hole."
        % (unreachable, STAMP_C.relative_to(REPO_ROOT)))


def test_every_stamped_field_is_read_by_a_builder():
    """The mirror hole, one layer down: a field stamped onto the entry that no
    brix_vbr_build_* reads is the same broken promise, just later.  This is
    exactly the shape `verify_pages` had before W5.1 — the tier path set it and
    brix_vbr_build_xroot ignored it."""
    stamped = set(re.findall(r"e->(origin_\w+)\s*=", STAMP_C.read_text()))
    assert stamped, "vfs_backend_store_params.c stamps nothing — did it move?"
    read = set()
    for src in BUILDERS:
        read |= set(re.findall(r"(?:e|entry)->(origin_\w+)", src.read_text()))
    orphans = sorted(stamped - read)
    assert not orphans, (
        "stamped onto brix_vfs_backend_entry_t but read by no builder in "
        "%s: %s" % ([b.name for b in BUILDERS], orphans))


def test_stamped_fields_are_declared_on_the_entry():
    """A typo'd field name would not compile, but a field declared and then
    orphaned by a rename would — pin the declaration side too."""
    decl = ENTRY_H.read_text()
    for field in sorted(re.findall(r"e->(origin_\w+)\s*=",
                                   STAMP_C.read_text())):
        assert re.search(r"\b%s\b" % field, decl), (
            f"{field} is stamped but not declared in {ENTRY_H.name}")


# ---- the arity break, in both directive planes ------------------------------

DIRECTIVE_TABLES = [
    pytest.param(SRC / "core/config/http_directives_core.h", id="http"),
    pytest.param(SRC / "core/config/stream_common.c", id="stream"),
]


@pytest.mark.parametrize("table", DIRECTIVE_TABLES)
def test_storage_backend_accepts_trailing_params(table):
    """Break #1, and the cheapest to reintroduce: a TAKE1 here makes every
    param above unreachable again, and `nginx -t` blames ARITY, so the
    diagnostic never mentions the param the operator actually wrote."""
    body = table.read_text()
    m = re.search(r'ngx_string\("brix_storage_backend"\)\s*,\s*([^,]+),',
                  body)
    assert m, f"brix_storage_backend not found in {table.name}"
    flags = m.group(1)
    assert "TAKE1234" in flags, (
        f"{table.name}: brix_storage_backend takes {flags.strip()} — the store "
        "line's trailing params (verify_pages, mode=, prot=) cannot be written")


@pytest.mark.parametrize("table", DIRECTIVE_TABLES)
def test_storage_backend_uses_the_store_slot_setter(table):
    """A TAKE1234 with the plain str setter would ACCEPT the params and then
    drop them on the floor — louder-looking than TAKE1 and just as silent."""
    body = table.read_text()
    i = body.index('ngx_string("brix_storage_backend")')
    entry = body[i:i + 600]
    assert "brix_conf_set_store_slot" in entry, (
        f"{table.name}: brix_storage_backend must use brix_conf_set_store_slot "
        "so args[2..] land in storage_backend_args")
    assert "storage_backend_args" in entry, (
        f"{table.name}: the setter's cmd->post must carry the "
        "storage_backend_args offset, or the params are parsed into nothing")


def test_the_params_are_adopted_alongside_the_url():
    """The FOURTH place the value can die, and the one that actually bit.

    Both planes route `brix_storage_backend` through a shared owner module, and
    each protocol ADOPTS the preamble from it at merge.  The adopt is an
    explicit field list: `storage_backend` was on it and `storage_backend_args`
    was not, so the url arrived and its params did not — `nginx -t` accepted
    every refusable store line in the suite and refused none of them.

    Any store field whose `<name>_args` companion exists must be adopted with
    it, or the same silent split reappears for the next param."""
    body = (SRC / "core/config/http_common.c").read_text()
    m = re.search(r"brix_shared_adopt_unified\(.*?\n\{(.*?)\n\}", body, re.S)
    assert m, "brix_shared_adopt_unified not found — the adopt table moved"
    adopted = set(re.findall(r"BRIX_ADOPT_\w+\((\w+)", m.group(1)))
    fields = _shared_conf_fields()
    missing = sorted(f"{n}_args" for n in adopted
                     if f"{n}_args" in fields and f"{n}_args" not in adopted)
    assert not missing, (
        "store urls adopted without their trailing params — the export runs "
        "with a policy the operator did not write: %s" % missing)


def _shared_conf_fields():
    """Every ngx_str_t / ngx_array_t* member of the shared config preamble.

    The preamble is split across shared_conf_fields*.h (the 600-line cap), so
    read all of them — a store url and its `_args` companion do not always
    live in the same file."""
    pattern = r"^\s*(?:ngx_array_t\s*\*|ngx_str_t\s+)(\w+)\s*;"
    names = set()
    for header in sorted((SRC / "core/config").glob("shared_conf_fields*.h")):
        names |= set(re.findall(pattern, header.read_text(), re.M))
    return names


def test_every_config_str_call_site_also_stamps_the_params():
    """Three protocol finalisers register the backend URL; each must carry the
    params too, or the params work on some protocols and not others — the
    worst outcome of the three, because it looks like it works."""
    missing = []
    for src in sorted(SRC.rglob("*.c")):
        body = src.read_text()
        if "brix_vfs_backend_config_str(cf" not in body:
            continue
        if "brix_vfs_backend_store_params(cf" not in body:
            missing.append(str(src.relative_to(REPO_ROOT)))
    assert not missing, (
        "these call brix_vfs_backend_config_str but never carry the store "
        "line's params: %s" % missing)


# ---- the guard's own anti-vacuity, pinned ----------------------------------
#
# These three rows exist because the check above ALREADY failed this way once:
# it went green for as long as the dispatch was a chain of ifs, then went to an
# empty keyword set when the chain became a table — and the assertion written
# to catch exactly that was itself satisfied by a comment.  A structural guard
# that can be quietly satisfied by prose reports silence as agreement, so the
# anchor is now pinned in all three directions.


def test_the_table_anchor_reads_the_real_table():
    """SUCCESS: the anchor finds the live table and every row in it."""
    keys = _params_declared()
    assert len(keys) == 8, sorted(keys)   # permit= joined the table (2.0 F5)
    assert "streams=" in keys, (
        "streams= is routed by tier_arg_kws[] and carried all the way to "
        "vfs_backend_registry_gsiftp.c; if it left the table, say so here")


def test_the_anchor_fails_loudly_when_the_table_is_gone():
    """ERROR: a source with no table must not parse to an empty, quiet set.

    The distinction this row buys: `_params_declared` must RAISE, not return
    `set()`.  Returning an empty set is what made every downstream row pass
    while checking nothing."""
    assert KW_TABLE_RE.search("static const tier_arg_kw_t other[] = {\n};\n") \
        is None, "the anchor matched a differently-named table"
    assert KW_TABLE_RE.search("/* no table here at all */\n") is None


def test_a_prose_mention_of_the_table_cannot_satisfy_the_anchor():
    """SECURITY-NEGATIVE for the guard itself: the exact shape of the miss.

    A comment naming `tier_arg_kws[]`, followed anywhere later in the file by
    an unrelated brace block, must not be mistaken for the table — that is
    precisely how the previous anchor matched `tier_arg_is`'s doc comment and
    handed back a body containing no keywords."""
    decoy = (
        "/* tier_arg_kws[] = the routing table; see tier_parse_one_arg. */\n"
        "static int unrelated(void)\n"
        "{\n"
        '    return ngx_strncmp(arg->data, "verify_pages", 12);\n'
        "}\n")
    assert KW_TABLE_RE.search(decoy) is None, (
        "a comment mentioning the table satisfied the anchor — the guard is "
        "back to reporting silence as agreement")
