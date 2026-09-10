"""Config-parse units for the `mode=` / `prot=` store-line params (phase-115 W5.1).

`nginx -t` only (no server start).  These two params select the GridFTP DATA
channel a gsiftp:// backend transfers over:

  * `mode=e` — GFD.020 §3.4 extended block mode, where each block carries its
    own absolute offset and blocks may arrive out of order;
  * `prot=p` — TLS on the data socket (DCAU A), the peer chain PKIX-verified
    and its DN pinned to the control channel's X.509 identity.

Both are SECURITY-RELEVANT defaults, so the parser is the first place they can
be broken silently.  A `prot=p` that parsed on a plain `ftp://` store would
hand the operator a data channel that is encrypted to nobody in particular:
without GSI on the control channel there is no identity to pin the data peer
to, and an unpinned TLS channel authenticates no one.  A `mode=e` accepted on a
driver with no GridFTP data channel at all would be a word with no effect.

The rows below also pin the FIRST reachable use of the store-line param grammar
on `brix_storage_backend`.  Until W5.1 that directive was NGX_CONF_TAKE1, so
`nginx -t` refused any trailing token for ARITY before a parser ever saw it —
which is how W4.3's `verify_pages` shipped unreachable.  `param-arity-control`
below is the row that would have caught it.

Harness mirrors tests/test_phase115_pgread_verify_parse.py.
"""

import subprocess

import pytest

from cmdscripts.live_common import inject_nginx_load_modules
from settings import BIND_HOST, NGINX_BIN

# Syntactically valid authorities.  Nothing connects during `nginx -t`, so the
# hosts need not resolve and the ports need not listen — and MUST NOT be fleet
# ports, since a parse-only suite has no business touching one.
GSIFTP = "gsiftp://gridftp.example.invalid:2811/store"
FTP = "ftp://gridftp.example.invalid:2811/store"


def _nginx_t(root, store_lines):
    (root / "logs").mkdir(exist_ok=True)
    (root / "data").mkdir(exist_ok=True)
    (root / "cache").mkdir(exist_ok=True)
    conf = root / "dc.conf"
    conf.write_text(f"""daemon off; error_log {root}/logs/e.log info;
pid {root}/n.pid; thread_pool default threads=2;
events {{ worker_connections 64; }}
stream {{ server {{ listen {BIND_HOST}:13297;
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
    # The control: the same store line with no params must parse, so a red row
    # below is about the param and not about the harness or the scheme.
    pytest.param(f"brix_storage_backend {GSIFTP};", id="gsiftp-plain"),
    # THE arity row.  Any trailing token at all on brix_storage_backend was an
    # [emerg] until W5.1; this is the regression that keeps it reachable.
    pytest.param(f"brix_storage_backend {GSIFTP} mode=s;",
                 id="param-arity-control"),
    pytest.param(f"brix_storage_backend {GSIFTP} mode=e;", id="mode-e"),
    pytest.param(f"brix_storage_backend {GSIFTP} mode=E;", id="mode-e-upper"),
    pytest.param(f"brix_storage_backend {GSIFTP} prot=p;", id="prot-p"),
    pytest.param(f"brix_storage_backend {GSIFTP} prot=P;", id="prot-p-upper"),
    pytest.param(f"brix_storage_backend {GSIFTP} prot=c;", id="prot-c"),
    # Both, in either order — the params are independent knobs on one channel.
    pytest.param(f"brix_storage_backend {GSIFTP} mode=e prot=p;", id="both"),
    pytest.param(f"brix_storage_backend {GSIFTP} prot=p mode=e;",
                 id="both-reversed"),
    # MODE E is a FRAMING choice, not a security one: it is as valid on a plain
    # ftp:// control channel as on a GSI one.  Only prot=p needs the identity.
    pytest.param(f"brix_storage_backend {FTP} mode=e;", id="ftp-mode-e"),
    pytest.param(f"brix_storage_backend {FTP} prot=c;", id="ftp-prot-c"),
]


@pytest.mark.parametrize("store", ACCEPT)
def test_store_line_accepted(tmp_path, store):
    rc, out = _nginx_t(tmp_path, store)
    assert rc == 0, f"`nginx -t` rejected a valid store line:\n{out}"


# ---- refused ----------------------------------------------------------------

REJECT = [
    # SECURITY.  `prot=p` on a cleartext control channel: TLS with nothing to
    # pin the peer to.  The refusal must say so, not merely "invalid".
    pytest.param(f"brix_storage_backend {FTP} prot=p;",
                 "needs a gsiftp:// store", id="sec-prot-p-on-plain-ftp"),
    # DRIVER.  Neither param means anything without a GridFTP data channel.
    pytest.param("brix_storage_backend root://127.0.0.1:1094 mode=e;",  # net-literal-allow: config directive text is the parser's input
                 "no GridFTP data channel", id="driver-xroot-mode"),
    pytest.param("brix_storage_backend root://127.0.0.1:1094 prot=p;",  # net-literal-allow: config directive text is the parser's input
                 "no GridFTP data channel", id="driver-xroot-prot"),
    # SECURITY, and the reason the driver check runs BEFORE the TLS check:
    # roots:// IS a TLS scheme, so a prot= parser that looked only at the tls
    # flag would accept this and promise a protected GridFTP data channel on a
    # backend that speaks no GridFTP at all.
    pytest.param("brix_storage_backend roots://127.0.0.1:1094 prot=p;",  # net-literal-allow: config directive text is the parser's input
                 "no GridFTP data channel", id="sec-prot-p-on-roots-tls"),
    pytest.param("brix_storage_backend https://example.invalid:443 mode=e;",
                 "no GridFTP data channel", id="driver-http"),
    # The posix spelling reaches the parser with an already-CLEARED store url
    # (brix_storage_backend_posix_root folds posix:<path> into the export root).
    # The refusal must still name the driver, not the missing url.
    pytest.param("brix_storage_backend posix:{ROOT}/data mode=e;",
                 "no GridFTP data channel", id="driver-posix-cleared-url"),
    pytest.param("brix_storage_backend posix:{ROOT}/data prot=p;",
                 "no GridFTP data channel", id="driver-posix-prot"),
    # ROLE: a cache tier is a destination, not a GridFTP link.
    pytest.param(f"brix_storage_backend {GSIFTP};\n"
                 "    brix_cache_store posix:{ROOT}/cache mode=e;\n"
                 "    brix_cache_export /;",
                 "no GridFTP data channel", id="role-cache-store"),
    # VALUES.  Anything but the two letters is an operator error.  `mode=b`
    # (RFC 959 block mode) and `prot=s`/`prot=e` (RFC 2228 safe/confidential)
    # are real FTP spellings BriX does not implement — refusing them loudly is
    # the point: silently treating `prot=s` as protection would be a lie.
    pytest.param(f"brix_storage_backend {GSIFTP} mode=b;",
                 "invalid mode value", id="value-mode-b"),
    pytest.param(f"brix_storage_backend {GSIFTP} mode=x;",
                 "invalid mode value", id="value-mode-unknown"),
    pytest.param(f"brix_storage_backend {GSIFTP} mode=extended;",
                 "invalid mode value", id="value-mode-word"),
    pytest.param(f"brix_storage_backend {GSIFTP} prot=s;",
                 "invalid prot value", id="sec-value-prot-safe"),
    pytest.param(f"brix_storage_backend {GSIFTP} prot=e;",
                 "invalid prot value", id="sec-value-prot-confidential"),
    pytest.param(f"brix_storage_backend {GSIFTP} prot=private;",
                 "invalid prot value", id="value-prot-word"),
    # A bare `key=` is strictly not longer than the key, so it never reaches
    # the value parser: it is an unknown token.  Pinned because that is the
    # shape a truncated config line takes.
    pytest.param(f"brix_storage_backend {GSIFTP} mode=;",
                 "unknown store param", id="mode-empty"),
    pytest.param(f"brix_storage_backend {GSIFTP} prot=;",
                 "unknown store param", id="prot-empty"),
    # Near-miss tokens must not be swallowed by the prefix match.
    pytest.param(f"brix_storage_backend {GSIFTP} protect=p;",
                 "unknown store param", id="near-miss-protect"),
    pytest.param(f"brix_storage_backend {GSIFTP} mod=e;",
                 "unknown store param", id="near-miss-mod"),
    pytest.param(f"brix_storage_backend {GSIFTP} prot p;",
                 "unknown store param", id="space-separated"),
]


@pytest.mark.parametrize("store,needle", REJECT)
def test_store_line_rejected(tmp_path, store, needle):
    rc, out = _nginx_t(tmp_path, store.replace("{ROOT}", str(tmp_path)))
    assert rc != 0, f"`nginx -t` ACCEPTED a store line it must refuse:\n{out}"
    assert needle in out, f"refused, but not for the stated reason:\n{out}"


def test_prot_p_refusal_explains_the_pinning(tmp_path):
    """The `prot=p` refusal on ftp:// must say WHY, not just "wrong scheme".

    An operator who reads "needs a gsiftp:// store" and nothing else will just
    change the scheme; the message has to tell them the protection is worth
    something only because the data peer is pinned to the control channel's
    identity, so they understand what they are turning on."""
    rc, out = _nginx_t(tmp_path, f"brix_storage_backend {FTP} prot=p;")
    assert rc != 0
    assert "X.509 identity" in out, out


def test_params_compose_with_verify_pages_vocabulary(tmp_path):
    """One vocabulary on every store directive: the W4.3 param and the W5.1
    params share a parser, so a store line must not have to choose between
    them — and `verify_pages` must still be refused on a gsiftp:// store for
    its own reason (no kXR_pgread there), not swallowed by the new rows."""
    rc, out = _nginx_t(tmp_path, f"brix_storage_backend {GSIFTP} "
                                 f"mode=e verify_pages;")
    assert rc != 0
    assert "needs a root:// origin" in out, out
