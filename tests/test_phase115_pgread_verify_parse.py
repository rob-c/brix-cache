"""Config-parse units for the `verify_pages` store-line param (phase-115 W4.3).

`nginx -t` only (no server start).  `verify_pages` arms per-page origin
verification — every 4 KiB page of a root:// read arrives with its own CRC32c
via kXR_pgread and is checked before the byte reaches the caller — so the
PARSER is the first place the promise can be broken silently:

  * accepted where it does nothing (a posix store has no per-page checksum; a
    cache/stage tier is the destination, not the origin) would leave an
    operator believing bytes are verified when nothing verifies them;
  * a misspelled value quietly ignored would do the same.

Every case here is therefore either an accept that must parse or a refusal that
must fail `nginx -t` with a diagnostic naming the reason.  The `nearline` /
`credential=` / `block_size=` / unknown-token rows are not decoration: the same
change split the store-line param parser out of tier_config.c into
tier_config_args.c (the 600-line file cap), and these pin that every pre-existing
param survived the move with its exact operator-facing message.

Harness mirrors tests/test_cache_directive_parse.py:18.
"""

import subprocess

import pytest

from cmdscripts.live_common import inject_nginx_load_modules
from settings import BIND_HOST, NGINX_BIN

# A syntactically valid root:// authority.  Nothing connects during `nginx -t`,
# so the port need not be listening — and MUST NOT be a fleet port, since a
# parse-only suite has no business touching one.
ORIGIN = "root://127.0.0.1:1094"  # net-literal-allow: config directive text is the parser's input


def _nginx_t(root, store_lines):
    (root / "logs").mkdir(exist_ok=True)
    (root / "data").mkdir(exist_ok=True)
    (root / "cache").mkdir(exist_ok=True)
    conf = root / "pg.conf"
    conf.write_text(f"""daemon off; error_log {root}/logs/e.log info;
pid {root}/n.pid; thread_pool default threads=2;
events {{ worker_connections 64; }}
stream {{ server {{ listen {BIND_HOST}:13299;
    brix_root on;
    brix_auth none;
    {store_lines}
}} }}
""")
    inject_nginx_load_modules(conf)
    p = subprocess.run([str(NGINX_BIN), "-t", "-p", str(root), "-c", str(conf)],
                       capture_output=True, text=True, timeout=30)
    return p.returncode, p.stderr + p.stdout


def _backend(params=""):
    return f"brix_storage_backend {ORIGIN}{params};"


# ---- accepted ---------------------------------------------------------------

ACCEPT = [
    # The control: the same store line without the param must parse, so a red
    # row below is about `verify_pages` and not about the harness.
    pytest.param(_backend(), id="backend-plain"),
    # The bare token is REQUIRE, not a best-effort hint: an operator who writes
    # `verify_pages` is asking for verified bytes.
    pytest.param(_backend(" verify_pages"), id="bare"),
    pytest.param(_backend(" verify_pages=require"), id="require"),
    pytest.param(_backend(" verify_pages=best-effort"), id="best-effort"),
    # roots:// is the same xroot driver with TLS — the param must not be
    # accidentally scheme-locked to the cleartext spelling.
    pytest.param("brix_storage_backend roots://127.0.0.1:1094 verify_pages;",  # net-literal-allow: config directive text is the parser's input
                 id="roots-tls"),
    # Composes with the other store params, in either order.
    pytest.param(_backend(" verify_pages block_size=1m"), id="with-block-size"),
    pytest.param(_backend(" block_size=1m verify_pages=require"),
                 id="after-block-size"),
    pytest.param(_backend(" nearline verify_pages"), id="with-nearline"),
]


@pytest.mark.parametrize("store", ACCEPT)
def test_store_line_accepted(tmp_path, store):
    rc, out = _nginx_t(tmp_path, store)
    assert rc == 0, f"`nginx -t` rejected a valid store line:\n{out}"


# ---- refused ----------------------------------------------------------------

# (store-lines, needle the [emerg] must contain)
REJECT = [
    # ROLE: a cache/stage tier is where verified bytes LAND; it is not the link
    # they arrive over.  Accepting it there is the silent-no-op this refuses.
    pytest.param(f"{_backend()}\n    brix_cache_store posix:{{ROOT}}/cache "
                 f"verify_pages;\n    brix_cache_export /;",
                 "belongs on brix_storage_backend", id="role-cache"),
    # `brix_stage on` is not decoration: the stage store URL is parsed only
    # when staging is enabled, so without it the line is never read and the
    # row silently proves nothing.  (It did exactly that until W5.1 made this
    # file reachable at all.)
    pytest.param(f"{_backend()}\n    brix_stage on;\n"
                 f"    brix_stage_store posix:{{ROOT}}/cache verify_pages;",
                 "belongs on brix_storage_backend", id="role-stage"),
    # DRIVER: kXR_pgread is an XRootD request.  A posix/http/s3 store has no
    # per-page checksum at all, so the param could only ever be a lie there.
    pytest.param("brix_storage_backend posix:{ROOT}/data verify_pages;",
                 "needs a root:// origin", id="driver-posix"),
    pytest.param("brix_storage_backend https://example.invalid:443 "
                 "verify_pages;",
                 "needs a root:// origin", id="driver-http"),
    # VALUE: an unrecognised mode must fail loudly.  `verify_pages=off` is the
    # sharp one — it READS like a disarm an operator could rely on, and if it
    # parsed as one, `verify_pages=0ff` (a typo) would silently disarm too.
    pytest.param(_backend(" verify_pages=maybe"),
                 "invalid verify_pages value", id="value-unknown"),
    pytest.param(_backend(" verify_pages=off"),
                 "invalid verify_pages value", id="value-off"),
    pytest.param(_backend(" verify_pages="),
                 "invalid verify_pages value", id="value-empty"),
    pytest.param(_backend(" verify_pages=REQUIRE"),
                 "invalid verify_pages value", id="value-case"),
    # A near-miss token must not be swallowed by the prefix match.
    pytest.param(_backend(" verify_pagesss"),
                 "invalid verify_pages value", id="value-suffix-typo"),
    pytest.param(_backend(" verify_page"),
                 "unknown store param", id="token-truncated"),
    # ---- the split regression rows: every pre-existing param, unchanged ----
    pytest.param(f"{_backend()}\n    brix_cache_store posix:{{ROOT}}/cache "
                 f"nearline;\n    brix_cache_export /;",
                 "belongs on brix_storage_backend", id="nearline-role"),
    pytest.param(_backend(" credential=no_such_credential"),
                 "no brix_credential", id="credential-unknown"),
    # `credential=` with NO name is caught one layer up: the key= match
    # requires a token strictly longer than the key, so a bare `credential=`
    # never reaches the name validator and is refused as an unknown param.
    # Pinned because it is the shape a truncated config line takes.
    pytest.param(_backend(" credential="),
                 "unknown store param", id="credential-empty"),
    pytest.param(_backend(" credential=" + "x" * 300),
                 "invalid credential name", id="credential-overlong"),
    pytest.param(_backend(" block_size=twelve"),
                 "invalid block_size", id="block-size-bad"),
    pytest.param(_backend(" verify_paegs"),
                 "unknown store param", id="unknown-param"),
    # ---- bare keywords match EXACTLY --------------------------------------
    # Untested until the store-line dispatch became a keyword table (the
    # duplication burndown that removed five cloned `if`s).  `nearline` was
    # matched by a hand-written exact-length compare before that; on the
    # shared matcher it needs a shape of its own, because the matcher's
    # non-`key=` branch was deliberately loose for its only previous caller,
    # `verify_pages`, whose parser validates the tail itself.  `nearline` has
    # no value vocabulary, so nothing downstream would catch `nearlinex` —
    # it would set out->nearline and `nginx -t` would say OK.  These rows
    # fail on a table that reuses one "not key=value" flag for both.
    pytest.param(_backend(" nearlinex"),
                 "unknown store param", id="nearline-suffix-typo"),
    pytest.param(_backend(" nearline=on"),
                 "unknown store param", id="nearline-valued"),
    pytest.param(_backend(" nearlin"),
                 "unknown store param", id="nearline-truncated"),
]


@pytest.mark.parametrize("store,needle", REJECT)
def test_store_line_rejected(tmp_path, store, needle):
    rc, out = _nginx_t(tmp_path, store.replace("{ROOT}", str(tmp_path)))
    assert rc != 0, f"`nginx -t` ACCEPTED a store line it must refuse:\n{out}"
    assert needle in out, f"refused, but not for the stated reason:\n{out}"


def test_refusal_names_the_offending_directive(tmp_path):
    """The role refusal must name the directive the operator actually wrote —
    a message that says only "belongs on brix_storage_backend" leaves them
    hunting which of several store lines is wrong."""
    rc, out = _nginx_t(tmp_path,
                       f"{_backend()}\n    brix_cache_store posix:{tmp_path}/cache"
                       f" verify_pages;\n    brix_cache_export /;")
    assert rc != 0
    assert "brix_cache_store" in out, out


def test_stage_store_params_are_parsed_only_when_staging_is_on(tmp_path):
    """The trap this file fell into, pinned rather than merely commented.

    `brix_stage_store`'s URL and params are parsed by the stage registration,
    which returns early unless `brix_stage on` — so a refusal row written
    without it is green for the wrong reason: nothing read the line at all.
    Both halves are asserted here, so a future reader can see that the
    difference is real and not an accident of ordering."""
    line = (f"{_backend()}\n    brix_stage_store posix:{tmp_path}/cache "
            f"verify_pages;")
    rc_off, out_off = _nginx_t(tmp_path, line)
    rc_on, out_on = _nginx_t(
        tmp_path, line.replace("brix_stage_store",
                               "brix_stage on;\n    brix_stage_store"))
    assert rc_off == 0, (
        "a stage store line is expected to go UNREAD while staging is off; if "
        "that changed, the role rows above no longer need `brix_stage on` and "
        "this test is the place to say so:\n" + out_off)
    assert rc_on != 0, out_on
    assert "belongs on brix_storage_backend" in out_on, out_on
