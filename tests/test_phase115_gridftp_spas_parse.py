"""Config-parse units for the `streams=<n>` store-line param (phase-115 W5.3).

`nginx -t` only (no server start).  `streams=` is the ceiling on how many data
connections ONE GridFTP read may open, asked for with GFD.020 §5.1 SPAS.

It is the odd one out among the three GridFTP data-channel params.  `mode=` and
`prot=` say what the bytes ARE — framing and protection — and never degrade: an
origin that refuses fails the transfer.  `streams=` says how FAST the same,
identically verified bytes arrive, so it DOES degrade: an origin that does not
advertise SPAS, refuses it, or answers with more stripes than the budget is
served over the one pinned connection this driver has always used.

That makes the PARSER the only place the operator's intent can be checked at
all, which is why these rows matter more than the usual value-validation:

  * a bound (1..GFTP_STREAMS_MAX) — every stream is a socket held by one
    blocking VFS worker thread for the length of a transfer, so the ceiling is
    a resource decision the operator makes, not one an origin's SPAS reply
    makes for them;
  * `streams>1` REQUIRES `mode=e` — a striped transfer is reassembled from
    blocks carrying their own absolute offsets, which exist only in MODE E.
    Accepting `streams=4 mode=s` would arm nothing at all, silently.

The cross-check is order-INDEPENDENT on purpose: both spellings appear below,
because a rule that accepted one word order and refused the other would be an
operator trap rather than a rule.

Harness mirrors tests/test_phase115_gridftp_data_channel_parse.py.
"""

import subprocess

import pytest

from cmdscripts.live_common import inject_nginx_load_modules
from settings import BIND_HOST, NGINX_BIN

# Syntactically valid authorities.  Nothing connects during `nginx -t`.
GSIFTP = "gsiftp://gridftp.example.invalid:2811/store"
FTP = "ftp://gridftp.example.invalid:2811/store"

# Mirrors GFTP_STREAMS_MAX in src/fs/backend/gsiftp/gftp_client.h.  Pinned as a
# literal so a change to the C constant reds this suite rather than sliding
# through: the bound is an operator-visible contract, not an internal detail.
STREAMS_MAX = 16


def _nginx_t(root, store_lines):
    (root / "logs").mkdir(exist_ok=True)
    (root / "data").mkdir(exist_ok=True)
    (root / "cache").mkdir(exist_ok=True)
    conf = root / "spas.conf"
    conf.write_text(f"""daemon off; error_log {root}/logs/e.log info;
pid {root}/n.pid; thread_pool default threads=2;
events {{ worker_connections 64; }}
stream {{ server {{ listen {BIND_HOST}:13298;
    brix_root on;
    brix_auth none;
    {store_lines}
}} }}
""")
    inject_nginx_load_modules(conf)
    p = subprocess.run([str(NGINX_BIN), "-t", "-p", str(root), "-c", str(conf)],
                       capture_output=True, text=True, timeout=30)
    return p.returncode, p.stderr + p.stdout


# ---- accepted ---------------------------------------------------------------

ACCEPT = [
    # The control: `mode=e` alone still parses, so a red row below is about
    # `streams=` and not about the harness or the neighbouring param.
    pytest.param(f"brix_storage_backend {GSIFTP} mode=e;", id="mode-e-alone"),
    pytest.param(f"brix_storage_backend {GSIFTP} mode=e streams=2;",
                 id="streams-2"),
    pytest.param(f"brix_storage_backend {GSIFTP} mode=e "
                 f"streams={STREAMS_MAX};", id="streams-at-the-ceiling"),
    # Order-independence, both ways.  Neither parser can see the other's answer
    # while it runs, so this pair is what proves the check is a whole-line one.
    pytest.param(f"brix_storage_backend {GSIFTP} streams=4 mode=e;",
                 id="streams-before-mode"),
    pytest.param(f"brix_storage_backend {GSIFTP} mode=e streams=4;",
                 id="streams-after-mode"),
    # `streams=1` means "never ask for a striped channel", which is exactly
    # what stream mode already does — so it needs no mode=e and must parse.
    pytest.param(f"brix_storage_backend {GSIFTP} streams=1;",
                 id="streams-1-needs-no-mode-e"),
    pytest.param(f"brix_storage_backend {GSIFTP} mode=s streams=1;",
                 id="streams-1-with-explicit-mode-s"),
    # Composition with the whole W5.1 vocabulary on one line.
    pytest.param(f"brix_storage_backend {GSIFTP} mode=e prot=p streams=8;",
                 id="with-mode-and-prot"),
    # Striping is a FRAMING/perf choice, not a security one: as valid over a
    # plain ftp:// control channel as over a GSI one.  The SPAS reply is still
    # address-checked at dial time (see test_phase115_gridftp_spas.py).
    pytest.param(f"brix_storage_backend {FTP} mode=e streams=4;",
                 id="ftp-striped"),
]


@pytest.mark.parametrize("store", ACCEPT)
def test_store_line_accepted(tmp_path, store):
    rc, out = _nginx_t(tmp_path, store)
    assert rc == 0, f"`nginx -t` rejected a valid store line:\n{out}"


# ---- refused ----------------------------------------------------------------

REJECT = [
    # THE cross-param rule, in BOTH word orders.  A striped transfer needs the
    # per-block offsets only MODE E carries; without it the param arms nothing.
    pytest.param(f"brix_storage_backend {GSIFTP} streams=4;",
                 'needs "mode=e"', id="streams-without-mode-e"),
    pytest.param(f"brix_storage_backend {GSIFTP} mode=s streams=4;",
                 'needs "mode=e"', id="streams-with-explicit-mode-s"),
    pytest.param(f"brix_storage_backend {GSIFTP} streams=4 mode=s;",
                 'needs "mode=e"', id="streams-before-explicit-mode-s"),
    # BOUND.  Every stream is a socket held by one blocking VFS worker for the
    # length of a transfer; an unbounded value would let a config line pin
    # arbitrarily many, and a value above the ceiling would be silently capped.
    pytest.param(f"brix_storage_backend {GSIFTP} mode=e "
                 f"streams={STREAMS_MAX + 1};",
                 "invalid streams value", id="bound-just-over-the-ceiling"),
    pytest.param(f"brix_storage_backend {GSIFTP} mode=e streams=99;",
                 "invalid streams value", id="bound-far-over"),
    pytest.param(f"brix_storage_backend {GSIFTP} mode=e streams=0;",
                 "invalid streams value", id="bound-zero"),
    pytest.param(f"brix_storage_backend {GSIFTP} mode=e streams=-2;",
                 "invalid streams value", id="bound-negative"),
    # VALUES.  ngx_atoi refuses anything non-numeric, and must — a `streams=n`
    # typo that parsed as some default would be a silent config lie.
    pytest.param(f"brix_storage_backend {GSIFTP} mode=e streams=x;",
                 "invalid streams value", id="value-word"),
    pytest.param(f"brix_storage_backend {GSIFTP} mode=e streams=4x;",
                 "invalid streams value", id="value-trailing-junk"),
    pytest.param(f"brix_storage_backend {GSIFTP} mode=e streams=4.0;",
                 "invalid streams value", id="value-decimal"),
    pytest.param(f"brix_storage_backend {GSIFTP} mode=e streams=+4;",
                 "invalid streams value", id="value-signed"),
    # A bare `key=` is not longer than the key, so it never reaches the value
    # parser: it is an unknown token.  The shape a truncated config line takes.
    pytest.param(f"brix_storage_backend {GSIFTP} mode=e streams=;",
                 "unknown store param", id="empty-value"),
    # Near-miss tokens must not be swallowed by the prefix match.
    pytest.param(f"brix_storage_backend {GSIFTP} mode=e stream=4;",
                 "unknown store param", id="near-miss-singular"),
    pytest.param(f"brix_storage_backend {GSIFTP} mode=e streamsize=4;",
                 "unknown store param", id="near-miss-streamsize"),
    pytest.param(f"brix_storage_backend {GSIFTP} mode=e streams 4;",
                 "unknown store param", id="space-separated"),
    # DRIVER.  A driver with no GridFTP data channel has nothing to stripe.
    pytest.param("brix_storage_backend root://127.0.0.1:1094 streams=4;",  # net-literal-allow: config directive text is the parser's input
                 "no GridFTP data channel", id="driver-xroot"),
    pytest.param("brix_storage_backend https://example.invalid:443 streams=4;",
                 "no GridFTP data channel", id="driver-http"),
    pytest.param("brix_storage_backend posix:{ROOT}/data streams=4;",
                 "no GridFTP data channel", id="driver-posix-cleared-url"),
    # ROLE: a cache tier is a destination, not a GridFTP link.
    pytest.param(f"brix_storage_backend {GSIFTP} mode=e;\n"
                 "    brix_cache_store posix:{ROOT}/cache streams=4;\n"
                 "    brix_cache_export /;",
                 "no GridFTP data channel", id="role-cache-store"),
]


@pytest.mark.parametrize("store,needle", REJECT)
def test_store_line_rejected(tmp_path, store, needle):
    rc, out = _nginx_t(tmp_path, store.replace("{ROOT}", str(tmp_path)))
    assert rc != 0, f"`nginx -t` ACCEPTED a store line it must refuse:\n{out}"
    assert needle in out, f"refused, but not for the stated reason:\n{out}"


def test_the_driver_check_runs_before_the_value_check(tmp_path):
    """A bad value on a driver that cannot stripe reports the DRIVER.

    Order matters for the operator: told "invalid streams value" they would fix
    the number and hit a second [emerg] for the real problem.  The driver check
    is also the cheaper truth — the param means nothing here at any value."""
    rc, out = _nginx_t(tmp_path,
                       "brix_storage_backend root://127.0.0.1:1094 streams=0;")  # net-literal-allow: config directive text is the parser's input
    assert rc != 0
    assert "no GridFTP data channel" in out, out
    assert "invalid streams value" not in out, out


def test_the_bound_names_the_ceiling(tmp_path):
    """The refusal must print the ACCEPTED RANGE, not just "invalid".

    An operator who asked for 32 streams has a capacity plan in mind; telling
    them the answer is 1..16 lets them adjust it in one edit instead of
    bisecting the parser."""
    rc, out = _nginx_t(tmp_path,
                       f"brix_storage_backend {GSIFTP} mode=e streams=64;")
    assert rc != 0
    assert f"1..{STREAMS_MAX}" in out, out


def test_the_cross_check_message_renders_the_number(tmp_path):
    """REGRESSION (W5.3): tier_fail formats through C vsnprintf, not nginx's.

    The first draft of this message used nginx's `%ud`, whose trailing `d` is a
    width suffix ngx_vslprintf consumes — but C's vsnprintf does not, so the
    operator was told `"streams=4d" needs "mode=e"`.  A message that misquotes
    the operator's own config line back at them is worse than no message: it
    reads like the parser saw something they did not write.

    Pinned here for the whole tier_fail family, which is C-printf throughout."""
    rc, out = _nginx_t(tmp_path, f"brix_storage_backend {GSIFTP} streams=4;")
    assert rc != 0
    assert '"streams=4"' in out, out
    assert "4d" not in out, out


def test_the_cross_check_message_says_why_mode_e_is_needed(tmp_path):
    """The rule has to explain itself, or `mode=e` looks like a magic word.

    An operator who reads only "needs mode=e" will paste it in without knowing
    they have also changed the framing on the wire.  The message names the
    mechanism — per-block offsets — so the coupling is visible."""
    rc, out = _nginx_t(tmp_path, f"brix_storage_backend {GSIFTP} streams=4;")
    assert rc != 0
    assert "offsets" in out, out
