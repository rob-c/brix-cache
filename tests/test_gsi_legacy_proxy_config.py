"""brix_gsi_legacy_proxy — the parse tier, on both planes, with ``nginx -t``.

The directive is ``NGX_STREAM_SRV_CONF | NGX_CONF_TAKE1`` on the stream plane
(root/stream/directives_auth.h) and ``BRIX_HTTP_ALL_CONF | NGX_CONF_TAKE1`` on
the http plane (core/config/http_directives_auth.h); both read the same
three-token enum table {off, on, full-only} through ngx_conf_set_enum_slot.

Measured here, per plane:

  * every token in the table parses — on a stream ``server {}`` and at the
    http, server and location levels of the http plane;
  * a token outside the table (``legacy``, ``1``) is "invalid value";
  * a second argument is "invalid number of arguments";
  * the directive omitted parses (the merge default is `on`, pinned live by
    test_gsi_legacy_proxy.py);
  * the stream directive is refused at ``stream {}`` level (server-only).

The stream half renders the audit-15v parse scaffold (one server, KNOBS slot);
the http half writes its own body through ``config_parse.nginx_t_text`` the
way test_voms_unification.py does.  ``nginx -t`` binds the listen, so both use
the lane's non-registered placeholder ports.
"""

import os

import pytest

from config_parse import nginx_t, nginx_t_text
from fleet_lifecycle_ports import (PARSE_PLACEHOLDER_PORT,
                                   SHARED_PARSE_PLACEHOLDER_PORT)
from settings import NGINX_BIN

pytestmark = pytest.mark.skipif(
    not os.path.exists(NGINX_BIN),
    reason="nginx binary (set NGINX_BIN) not available",
)

TOKENS = ("off", "on", "full-only")
BAD_TOKENS = ("legacy", "1")
LEVELS = ("http", "server", "location")


# --------------------------------------------------------------------------- #
# Renderers                                                                    #
# --------------------------------------------------------------------------- #

def _stream(tmp_path, knobs="", stream_extra=""):
    """One stream server (brix_auth none) plus `knobs`; returns (rc, output)."""
    data = tmp_path / "data"
    data.mkdir(exist_ok=True)
    body = "        brix_auth none;\n" + "".join(
        f"        {line}\n" for line in knobs.splitlines())
    result = nginx_t("nginx_audit15v_sigparse.conf", tmp_path,
                     PORT=PARSE_PLACEHOLDER_PORT, DATA_ROOT=str(data),
                     LOG_DIR=str(tmp_path), KNOBS=body,
                     STREAM_EXTRA=stream_extra)
    return result.returncode, (result.stdout or "") + (result.stderr or "")


def _http(tmp_path, http="", server="", location=""):
    """One http server with a webdav location (auth none) and a line at each
    of the three levels; returns (rc, output)."""
    data = tmp_path / "data"
    data.mkdir(exist_ok=True)
    text = (
        "worker_processes 1;\n"
        f"error_log {tmp_path}/error.log info;\n"
        f"pid {tmp_path}/nginx.pid;\n"
        "daemon on;\n"
        "events { worker_connections 64; }\n"
        "http {\n"
        f"    {http}\n"
        f"    server {{ listen {SHARED_PARSE_PLACEHOLDER_PORT};\n"
        f"        {server}\n"
        "        location / { brix_webdav on; brix_webdav_auth none;\n"
        f"            brix_storage_backend posix:{data};\n"
        f"            {location} }}\n"
        "    }\n"
        "}\n")
    result = nginx_t_text(text, tmp_path)
    return result.returncode, (result.stdout or "") + (result.stderr or "")


def _http_at(tmp_path, level, line):
    return _http(tmp_path, **{level: line})


# --------------------------------------------------------------------------- #
# Stream plane                                                                 #
# --------------------------------------------------------------------------- #

class TestStreamPlane:

    @pytest.mark.parametrize("token", TOKENS)
    def test_each_token_parses_on_a_server(self, tmp_path, token):
        rc, out = _stream(tmp_path, f"brix_gsi_legacy_proxy {token};")
        assert rc == 0, f"brix_gsi_legacy_proxy {token} was refused:\n{out}"

    def test_the_directive_omitted_parses(self, tmp_path):
        rc, out = _stream(tmp_path)
        assert rc == 0, out

    @pytest.mark.parametrize("token", BAD_TOKENS)
    def test_a_value_outside_the_table_is_refused(self, tmp_path, token):
        """`legacy` is the word an operator reaches for; `1` is the raw value
        behind BRIX_LEGACY_PROXY_ON — neither may parse into a default."""
        rc, out = _stream(tmp_path, f"brix_gsi_legacy_proxy {token};")
        assert rc != 0, f"brix_gsi_legacy_proxy {token} parsed:\n{out}"
        assert "invalid value" in out, out

    def test_a_second_argument_is_refused(self, tmp_path):
        rc, out = _stream(tmp_path, "brix_gsi_legacy_proxy on full-only;")
        assert rc != 0, out
        assert "invalid number of arguments" in out, out

    def test_the_directive_is_refused_outside_a_server(self, tmp_path):
        """NGX_STREAM_SRV_CONF only: a stream-level line is a parse error, not
        a default inherited by every server."""
        rc, out = _stream(tmp_path,
                          stream_extra="    brix_gsi_legacy_proxy off;\n")
        assert rc != 0, f"accepted in stream {{}}:\n{out}"
        assert "directive is not allowed here" in out, out


# --------------------------------------------------------------------------- #
# Http plane                                                                   #
# --------------------------------------------------------------------------- #

class TestHttpPlane:

    @pytest.mark.parametrize("level", LEVELS)
    @pytest.mark.parametrize("token", TOKENS)
    def test_each_token_parses_at_every_level(self, tmp_path, level, token):
        rc, out = _http_at(tmp_path, level, f"brix_gsi_legacy_proxy {token};")
        assert rc == 0, \
            f"brix_gsi_legacy_proxy {token} at {level} was refused:\n{out}"

    def test_the_directive_omitted_parses(self, tmp_path):
        rc, out = _http(tmp_path)
        assert rc == 0, out

    @pytest.mark.parametrize("token", BAD_TOKENS)
    def test_a_value_outside_the_table_is_refused(self, tmp_path, token):
        rc, out = _http_at(tmp_path, "location",
                           f"brix_gsi_legacy_proxy {token};")
        assert rc != 0, f"brix_gsi_legacy_proxy {token} parsed:\n{out}"
        assert "invalid value" in out, out

    def test_a_second_argument_is_refused(self, tmp_path):
        rc, out = _http_at(tmp_path, "server",
                           "brix_gsi_legacy_proxy on full-only;")
        assert rc != 0, out
        assert "invalid number of arguments" in out, out

    def test_a_bare_directive_is_refused(self, tmp_path):
        rc, out = _http_at(tmp_path, "http", "brix_gsi_legacy_proxy;")
        assert rc != 0, out
        assert "invalid number of arguments" in out, out
