"""test_authdb_engine_split.py — phase-101 W5: the authdb name-collision fix.

Before W5 the bare name ``brix_authdb`` meant two different engines depending on
plane: the XrdAcc engine on HTTP (``http_common`` str slot -> ``common.acc.authdb``)
and the native u/g/p engine on stream (``brix_root``'s ``brix_conf_set_authdb``);
WebDAV carried BOTH under near-identical names (native ``brix_webdav_authdb`` +
XrdAcc ``brix_authdb``).  W5 makes the prefix name the engine on HTTP exactly as
on the stream reference plane:

    * bare ``brix_authdb``  == the NATIVE u/g/p engine (webdav access phase),
    * ``brix_acc_*``        == the XrdAcc engine (``brix_acc_authdb`` + the three
                              ``brix_acc_format`` / ``_audit`` / ``_refresh`` tuners).

so ``brix_webdav_authdb`` and the HTTP spellings ``brix_authdb_engine`` /
``_audit`` / ``_refresh`` are gone from the HTTP planes (stock ``unknown directive``
/ ``not allowed here``), and the XrdAcc engine is reachable on HTTP only through
``brix_acc_*``.

These are ``nginx -t`` config-parse assertions only (no server start, no fleet),
so they run everywhere the binary is built — the security-neg pin the phase doc
calls for lives here, where CI always exercises it, rather than in the GSI/KDC
lifecycle suite (``test_authdb_mechanism_scope.py``) that skips without the client.

The security guarantee W5 delivers is that the bare name can no longer *silently*
select XrdAcc on HTTP: the XrdAcc-selection spelling ``brix_authdb_engine`` is a
loud ``nginx -t`` failure on HTTP, so an XrdAcc HTTP config cannot be carried
forward unchanged and quietly reinterpreted.  (The native parser itself is
deliberately lenient — ``brix_parse_authdb`` skips unrecognized lines rather than
erroring, see ``src/auth/authz/authdb_parse.c`` — so the guarantee rides on the
dead selection spelling, NOT on the parser rejecting an XrdAcc file.)

Run:  PYTHONPATH=. python3 -m pytest test_authdb_engine_split.py -p no:xdist -q
"""

import os
import subprocess
import tempfile

import pytest

from settings import NGINX_BIN

pytestmark = pytest.mark.skipif(
    not os.path.exists(NGINX_BIN),
    reason="nginx binary (set NGINX_BIN) not available",
)


def _load_lines():
    modules = [m for m in os.environ.get("TEST_NGINX_LOAD_MODULES", "").split(os.pathsep) if m]
    return "".join(f"load_module {m};\n" for m in modules)


def _authdb_file(d, contents):
    p = os.path.join(d, "authdb")
    with open(p, "w") as fh:
        fh.write(contents)
    return p


def _nginx_t_http(body):
    """`nginx -t` a full http{} config with `body` spliced into a server{}."""
    with tempfile.TemporaryDirectory() as d:
        for sub in ("logs", "tmp"):
            os.makedirs(os.path.join(d, sub), exist_ok=True)
        conf = os.path.join(d, "nginx.conf")
        with open(conf, "w") as fh:
            fh.write(
                _load_lines()
                + f"error_log {d}/logs/e.log info;\npid {d}/logs/n.pid;\n"
                + "events {}\n"
                + "http {\n"
                + f"  access_log {d}/logs/a.log; client_body_temp_path {d}/tmp/c;\n"
                + f"  proxy_temp_path {d}/tmp/p; fastcgi_temp_path {d}/tmp/f;\n"
                + f"  uwsgi_temp_path {d}/tmp/u; scgi_temp_path {d}/tmp/s;\n"
                + "  brix_storage_backend posix:/tmp;\n"
                + "  server { listen 127.0.0.1:28571;\n"  # net-literal-allow: parse-only config template listen (nginx -t, never bound)
                + body(d)
                + "  }\n"
                + "}\n")
        r = subprocess.run([NGINX_BIN, "-t", "-c", conf, "-p", d],
                           capture_output=True, text=True, timeout=30)
    return r.returncode, r.stdout + r.stderr


def _nginx_t_stream(body):
    """`nginx -t` a full stream{} config with `body` spliced into a server{}."""
    with tempfile.TemporaryDirectory() as d:
        os.makedirs(os.path.join(d, "logs"), exist_ok=True)
        conf = os.path.join(d, "nginx.conf")
        with open(conf, "w") as fh:
            fh.write(
                _load_lines()
                + f"error_log {d}/logs/e.log info;\npid {d}/logs/n.pid;\n"
                + "events {}\n"
                + "stream {\n"
                + "  server { listen 127.0.0.1:28572;\n"  # net-literal-allow: parse-only config template listen (nginx -t, never bound)
                + "    brix_root on;\n"
                + body(d)
                + "  }\n"
                + "}\n")
        r = subprocess.run([NGINX_BIN, "-t", "-c", conf, "-p", d],
                           capture_output=True, text=True, timeout=30)
    return r.returncode, r.stdout + r.stderr


_NATIVE = "u * /public rl\n"      # a rule both engines accept
_XRDACC = "u nobody 1\n/private r\n"   # XrdAcc-flavoured continuation line


# --------------------------------------------------------------------------- #
# XrdAcc reached ONLY via brix_acc_* — on every HTTP plane (ALL_CONF).         #
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize("proto_block", [
    "    location /dav/ { brix_webdav on; brix_webdav_auth none;\n",
    "    location /s3/ { brix_s3 on; brix_s3_bucket b; brix_webdav_auth none;\n",
    "    location /cvmfs/ { brix_cvmfs on;\n",
], ids=["webdav", "s3", "cvmfs"])
def test_brix_acc_family_parses_on_every_http_plane(proto_block):
    def body(d):
        adb = _authdb_file(d, _NATIVE)
        return (proto_block
                + f"      brix_acc_authdb {adb};\n"
                + "      brix_acc_format xrdacc;\n"
                + "      brix_acc_audit all;\n"
                + "      brix_acc_refresh 60; }\n")
    rc, out = _nginx_t_http(body)
    assert rc == 0, f"brix_acc_* (XrdAcc) must parse on every HTTP plane:\n{out}"
    assert "successful" in out, out


# --------------------------------------------------------------------------- #
# Bare brix_authdb == the NATIVE engine on webdav (HTTP).                      #
# --------------------------------------------------------------------------- #

def test_bare_authdb_is_native_on_webdav():
    def body(d):
        adb = _authdb_file(d, _NATIVE)
        return (f"    location /dav/ {{ brix_webdav on; brix_webdav_auth none;\n"
                + f"      brix_authdb {adb}; }}\n")
    rc, out = _nginx_t_http(body)
    assert rc == 0, f"bare brix_authdb (native) must parse on webdav:\n{out}"
    assert "successful" in out, out


# --------------------------------------------------------------------------- #
# The old HTTP spellings are gone — stock loud failures, never silent.        #
# --------------------------------------------------------------------------- #

def test_brix_webdav_authdb_is_unknown_directive():
    def body(d):
        adb = _authdb_file(d, _NATIVE)
        return (f"    location /dav/ {{ brix_webdav on; brix_webdav_auth none;\n"
                + f"      brix_webdav_authdb {adb}; }}\n")
    rc, out = _nginx_t_http(body)
    assert rc != 0, f"brix_webdav_authdb must be gone (W5):\n{out}"
    assert 'unknown directive "brix_webdav_authdb"' in out, out


@pytest.mark.parametrize("directive", [
    "brix_authdb_engine xrdacc",
    "brix_authdb_format xrdacc",
    "brix_authdb_audit all",
    "brix_authdb_refresh 60",
], ids=["engine-on-http", "format-retired", "audit-retired", "refresh-retired"])
def test_stream_only_and_retired_spellings_rejected_on_http(directive):
    """phase-105 W3: the engine SELECTOR (brix_authdb_engine, ex
    brix_authdb_format) is stream-only, so it is rejected in an http context;
    the retired brix_authdb_{format,audit,refresh} spellings are gone from
    BOTH planes (hard rename — stock unknown directive)."""
    def body(d):
        return (f"    location /dav/ {{ brix_webdav on; brix_webdav_auth none;\n"
                + f"      {directive}; }}\n")
    rc, out = _nginx_t_http(body)
    assert rc != 0, f"{directive} must be rejected on HTTP:\n{out}"


@pytest.mark.parametrize("directive", [
    "brix_acc_audit all",
    "brix_acc_refresh 60",
], ids=["audit", "refresh"])
def test_unified_acc_tuners_accepted_on_http(directive):
    """phase-105 W3: brix_acc_audit / brix_acc_refresh are ONE spelling on
    both planes now (the stream plane joined HTTP's brix_acc_* prefix), so
    they parse on HTTP exactly as before the stream rename."""
    def body(d):
        return (f"    location /dav/ {{ brix_webdav on; brix_webdav_auth none;\n"
                + f"      {directive}; }}\n")
    rc, out = _nginx_t_http(body)
    assert rc == 0, f"{directive} must parse on HTTP:\n{out}"


# --------------------------------------------------------------------------- #
# SECURITY-NEG PIN: the bare name can no longer silently select XrdAcc on      #
# HTTP.  The old XrdAcc HTTP recipe (bare brix_authdb + brix_authdb_engine     #
# xrdacc) now fails nginx -t loudly, so it cannot be carried forward and       #
# quietly reinterpreted under a different engine.                              #
# --------------------------------------------------------------------------- #

def test_legacy_xrdacc_http_config_fails_loudly():
    def body(d):
        adb = _authdb_file(d, _XRDACC)
        return (f"    location /dav/ {{ brix_webdav on; brix_webdav_auth none;\n"
                + f"      brix_authdb {adb};\n"
                + "      brix_authdb_engine xrdacc; }\n")   # dead selection spelling
    rc, out = _nginx_t_http(body)
    assert rc != 0, (
        "a pre-W5 XrdAcc HTTP config (bare brix_authdb + brix_authdb_engine "
        f"xrdacc) MUST fail nginx -t — the engine cannot be silently mis-selected:\n{out}")


def test_migrated_xrdacc_http_config_parses():
    """The forward-migration of the same intent (brix_acc_authdb +
    brix_acc_format xrdacc) parses cleanly — the loud failure above is a
    migration signal, not a dead end."""
    def body(d):
        adb = _authdb_file(d, _XRDACC)
        return (f"    location /dav/ {{ brix_webdav on; brix_webdav_auth none;\n"
                + f"      brix_acc_authdb {adb};\n"
                + "      brix_acc_format xrdacc; }\n")
    rc, out = _nginx_t_http(body)
    assert rc == 0, f"migrated XrdAcc HTTP config must parse:\n{out}"


# --------------------------------------------------------------------------- #
# The stream reference plane is UNCHANGED — bare brix_authdb + brix_authdb_*   #
# tuners still parse there (polymorphic engine via brix_authdb_engine).        #
# --------------------------------------------------------------------------- #

def test_stream_authdb_family_unchanged():
    # brix_authdb_engine xrdacc keeps the reference-plane config anonymous-valid
    # (native format additionally requires an authenticating brix_auth scheme —
    # a pre-existing stream invariant, unrelated to the W5 rename); the point here
    # is that all four brix_authdb* spellings still register on stream.
    def body(d):
        adb = _authdb_file(d, _NATIVE)
        return (f"    brix_authdb {adb};\n"
                + "    brix_authdb_engine xrdacc;\n"
                + "    brix_acc_audit all;\n"
                + "    brix_acc_refresh 60;\n")
    rc, out = _nginx_t_stream(body)
    assert rc == 0, f"stream reference plane must keep brix_authdb* unchanged:\n{out}"
    assert "successful" in out, out


def test_stream_brix_acc_authdb_is_not_a_stream_directive():
    """brix_acc_authdb is an HTTP-only spelling; on stream the engine entry stays
    bare brix_authdb, so brix_acc_authdb must be rejected there — proving the
    rename did not leak the HTTP spelling onto the reference plane."""
    def body(d):
        adb = _authdb_file(d, _NATIVE)
        return f"    brix_acc_authdb {adb};\n"
    rc, out = _nginx_t_stream(body)
    assert rc != 0, f"brix_acc_authdb must not be a stream directive:\n{out}"
