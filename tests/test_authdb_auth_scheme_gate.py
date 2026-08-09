"""Config-parse units for the native-authdb auth-scheme gate.

`nginx -t` only (no server start).  `brix_authdb` in its native format needs an
authenticating scheme, because its `u`/`g` rules match the identity the scheme
established.  The gate used to whitelist only `gsi`/`token`/`both`, which
locked the four mechanisms that also stamp `ctx->login.dn` — `sss`, `krb5`,
`pwd`, `host` (and `unix`) — out of authorization entirely
(src/core/config/server_conf_merge_security.c).  It now rejects exactly one
thing: an anonymous server, where there is no identity to match.

Live enforcement behind those schemes is `test_authdb_mechanism_scope.py`;
this module pins the config-time contract on both sides of it.  Harness mirrors
tests/test_cache_directive_parse.py:17.
"""

import subprocess

import pytest

from cmdscripts.live_common import inject_nginx_load_modules
from settings import BIND_HOST, NGINX_BIN

GATE_NEEDLE = "requires an authenticating brix_auth scheme"

# Schemes that establish an identity and therefore may carry a native authdb.
# Only the ones that parse from directives alone are listed: gsi/token/sss/krb5
# each demand extra material at parse time (certificates, the
# JWKS/issuer/audience trio, a keytab, a service principal).  Those are covered
# live instead — sss and krb5 by test_authdb_mechanism_scope.py, gsi by
# test_authdb.py, token by test_macaroon_root_wire.py.
IDENTITY_SCHEMES = ("pwd", "host", "unix")


def _nginx_t(root, auth, extra=""):
    (root / "logs").mkdir(exist_ok=True)
    (root / "data").mkdir(exist_ok=True)
    (root / "data" / "scoped").mkdir(exist_ok=True)
    authdb = root / "authdb"
    authdb.write_text("u someuser /scoped rl\n")
    conf = root / "gate.conf"
    conf.write_text(f"""daemon off; error_log {root}/logs/e.log info;
pid {root}/n.pid; thread_pool default threads=2;
events {{ worker_connections 64; }}
stream {{ server {{ listen {BIND_HOST}:13299;
    brix_root on;
    brix_storage_backend posix:{root}/data;
    brix_auth {auth};
    brix_authdb {authdb};
    {extra}
}} }}
""")
    inject_nginx_load_modules(conf)
    p = subprocess.run([str(NGINX_BIN), "-t", "-p", str(root), "-c", str(conf)],
                       capture_output=True, text=True, timeout=30)
    return p.returncode, p.stderr + p.stdout


# ---- success: every identity-establishing scheme may carry a native authdb -- #

@pytest.mark.parametrize("auth", IDENTITY_SCHEMES)
def test_identity_scheme_accepts_native_authdb(tmp_path, auth):
    rc, out = _nginx_t(tmp_path, auth)
    assert rc == 0, f"brix_auth {auth} + native authdb rejected:\n{out}"


# ---- error: an anonymous server has no identity to match -------------------- #

def test_anonymous_server_refuses_native_authdb(tmp_path):
    rc, out = _nginx_t(tmp_path, "none")
    assert rc != 0, "anonymous + native authdb must be refused"
    assert GATE_NEEDLE in out, out


def test_anonymous_server_accepts_xrdacc_authdb(tmp_path):
    """The documented escape hatch is unchanged: the xrdacc engine authorizes
    anonymous `u *` rules, so it stays exempt from the gate."""
    rc, out = _nginx_t(tmp_path, "none", extra="brix_authdb_format xrdacc;")
    assert rc == 0, f"anonymous + xrdacc authdb rejected:\n{out}"


# ---- security-negative: the gate must not become a rubber stamp ------------- #

def test_gate_still_fires_when_format_is_native_by_default(tmp_path):
    """`brix_authdb_format native` is the default, so an anonymous server that
    never names a format must still be refused — the rejection cannot depend on
    the directive being written out."""
    rc, out = _nginx_t(tmp_path, "none", extra="brix_authdb_format native;")
    assert rc != 0, "explicit native format + anonymous must be refused"
    assert GATE_NEEDLE in out, out
