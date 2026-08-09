"""Config-parse units for the shared `protbind` directive grammar.

`nginx -t` only (no server start): every case renders a minimal config and
asserts accept (rc==0) or reject (rc!=0 + the exact [emerg] diagnostic the
shared setter emits).  Both frontends are covered because both `brix_protbind`
(stream) and `brix_webdav_protbind` (http) delegate to ONE parser
(src/auth/protbind/config.c) — the point of these tests is that the two
directives cannot drift apart.

The resolution semantics behind the grammar (host-template matching, none /
only / default, first-match-wins, the membership gate) are unit-tested against
the real objects in tests/c/protbind_test.c.  Harness mirrors
tests/test_cache_directive_parse.py.
"""

import subprocess

import pytest

from cmdscripts.live_common import (
    inject_nginx_load_modules,
    inject_nginx_runtime_paths,
)
from settings import BIND_HOST, NGINX_BIN

STREAM_PORT = 13401
HTTP_PORT = 13402


def _nginx_t(root, stream_directives="", http_directives=""):
    (root / "logs").mkdir(exist_ok=True)
    (root / "data").mkdir(exist_ok=True)
    (root / "htpasswd").write_text("alice:$apr1$salt$hash\n")
    conf = root / "protbind.conf"
    conf.write_text(f"""daemon off; error_log {root}/logs/e.log info;
pid {root}/n.pid; thread_pool default threads=2;
events {{ worker_connections 64; }}
stream {{ server {{ listen {BIND_HOST}:{STREAM_PORT};
    brix_root on;
    brix_storage_backend posix:{root}/data;
    brix_auth unix;
    {stream_directives}
}} }}
http {{ server {{ listen {BIND_HOST}:{HTTP_PORT};
    location / {{
        brix_webdav on;
        root {root}/data;
        brix_webdav_auth optional;
        brix_webdav_pwd_file {root}/htpasswd;
        {http_directives}
    }}
}} }}
""")
    inject_nginx_load_modules(conf)
    inject_nginx_runtime_paths(conf, root)
    p = subprocess.run([str(NGINX_BIN), "-t", "-p", str(root), "-c", str(conf)],
                       capture_output=True, text=True, timeout=30)
    return p.returncode, p.stderr + p.stdout


# Directive tails accepted by the shared grammar on BOTH frontends.  Only
# unix/host appear: naming gsi/ztn/sss/krb5 pulls the stream listener into that
# scheme's startup loader, which then demands its keys (see
# test_protbind_names_a_scheme_the_build_lacks_credentials_for) — a separate
# property from the grammar under test here.
ACCEPT = [
    pytest.param("* unix", id="wildcard-single"),
    pytest.param("* unix host", id="wildcard-multi"),
    pytest.param("* only unix", id="only"),
    pytest.param("* none", id="none"),
    pytest.param("*.farm.local only unix host", id="suffix-template-only"),
    pytest.param("lxplus* unix", id="prefix-template"),
    pytest.param("pps*.gridpp.uk unix", id="split-template"),
    pytest.param("node7.example.org host", id="exact-template"),
    pytest.param("10.0.0.* unix", id="ip-template"),
    pytest.param("* host unix", id="order-reversed"),
]

# Every protocol word the grammar knows, checked on the HTTP frontend — which
# has no per-scheme startup loader, so a name that parses is simply accepted.
# gsi/ztn/pwd are the three with an actual HTTP transport; the rest are legal
# in a shared policy and ignored at request time.
ACCEPT_HTTP_ONLY = [
    pytest.param("* gsi ztn sss unix krb5 host pwd", id="every-protocol"),
    pytest.param("* token", id="token-alias"),
    pytest.param("* only gsi ztn", id="only-http-transports"),
]

# (directive tail, expected [emerg] needle).  These are the security-relevant
# rejections: a typo in a policy that decides WHO may authenticate must fail
# the config, never silently bind a smaller or larger protocol set.
REJECT = [
    pytest.param("* bogus", "unknown protocol name", id="unknown-proto"),
    pytest.param("* unix unix", "lists the same protocol twice", id="dup"),
    pytest.param("* only unix unix", "lists the same protocol twice",
                 id="dup-only"),
    pytest.param("* none unix", '"none" takes no protocol list', id="none-tail"),
    pytest.param("* only", '"only" must be followed by at least one protocol',
                 id="only-bare"),
    pytest.param('"" unix', "empty host template", id="empty-template"),
    pytest.param("* unix host gsi ztn sss krb5 pwd token",
                 "lists the same protocol twice", id="alias-dup"),
]


@pytest.mark.parametrize("tail", ACCEPT)
def test_stream_protbind_accepts(tmp_path, tail):
    # success: the stream directive parses every legal sec.protbind form.
    rc, out = _nginx_t(tmp_path, stream_directives=f"brix_protbind {tail};")
    assert rc == 0, f"brix_protbind {tail} rejected:\n{out}"


@pytest.mark.parametrize("tail", ACCEPT + ACCEPT_HTTP_ONLY)
def test_webdav_protbind_accepts(tmp_path, tail):
    # success: the HTTP directive shares the grammar, so it accepts the same
    # set — including protocols with no HTTP transport, which are ignored at
    # request time rather than rejected at parse time (one policy, all
    # frontends).
    rc, out = _nginx_t(tmp_path,
                       http_directives=f"brix_webdav_protbind {tail};")
    assert rc == 0, f"brix_webdav_protbind {tail} rejected:\n{out}"


@pytest.mark.parametrize("tail,needle", REJECT)
def test_stream_protbind_rejects(tmp_path, tail, needle):
    # error/security-negative: a malformed binding is a hard config failure.
    rc, out = _nginx_t(tmp_path, stream_directives=f"brix_protbind {tail};")
    assert rc != 0, f"brix_protbind {tail} accepted:\n{out}"
    assert needle in out, f"expected {needle!r} in:\n{out}"
    assert "brix_protbind:" in out, f"diagnostic must name the directive:\n{out}"


@pytest.mark.parametrize("tail,needle", REJECT)
def test_webdav_protbind_rejects(tmp_path, tail, needle):
    # error/security-negative: the HTTP directive must reject exactly what the
    # stream one does, with its own name on the diagnostic.
    rc, out = _nginx_t(tmp_path,
                       http_directives=f"brix_webdav_protbind {tail};")
    assert rc != 0, f"brix_webdav_protbind {tail} accepted:\n{out}"
    assert needle in out, f"expected {needle!r} in:\n{out}"
    assert "brix_webdav_protbind:" in out, \
        f"diagnostic must name the directive:\n{out}"


def test_protbind_requires_two_arguments(tmp_path):
    # error: nginx's own NGX_CONF_2MORE arity check fires before the setter, so
    # a bare template with no policy can never reach the rule array.
    rc, out = _nginx_t(tmp_path, stream_directives="brix_protbind *;")
    assert rc != 0
    assert "invalid number of arguments" in out, out


def test_protbind_ordered_ruleset_accepted(tmp_path):
    # success: the canonical multi-rule policy — specific templates first, "*"
    # catch-all last (first match wins, exactly as XRootD orders sec.protbind).
    rc, out = _nginx_t(tmp_path, stream_directives="""
    brix_protbind mon.example.org none;
    brix_protbind *.farm.local only unix host;
    brix_protbind * unix;
    """)
    assert rc == 0, out


def test_protbind_token_alias_reaches_the_token_loader(tmp_path):
    # success (grammar) + error (prerequisite): `token` is BriX's spelling of
    # the ztn protocol.  Naming it must parse — proven by the diagnostic being
    # the token loader's prerequisite check rather than a grammar rejection —
    # and must pull the listener into token configuration.
    rc, out = _nginx_t(tmp_path, stream_directives="brix_protbind * token;")
    assert rc != 0, out
    assert "unknown protocol name" not in out, out
    assert "requires brix_token_jwks" in out, out


def test_protbind_names_a_scheme_the_build_lacks_credentials_for(tmp_path):
    # error: naming gsi in a rule pulls the listener into GSI configuration
    # even though brix_auth is unix — so the missing certificate is caught at
    # config time instead of failing the first handshake.  This is the whole
    # reason brix_protbind_any_names() exists.
    rc, out = _nginx_t(tmp_path, stream_directives="brix_protbind * gsi;")
    assert rc != 0, f"gsi binding without certificates accepted:\n{out}"
    assert "requires brix_certificate" in out, out


def test_protbind_none_rule_does_not_pull_in_gsi(tmp_path):
    # success: a `none` rule lists no protocols, so it must NOT drag the GSI
    # trust-store requirement in behind it.
    rc, out = _nginx_t(tmp_path, stream_directives="brix_protbind * none;")
    assert rc == 0, out
