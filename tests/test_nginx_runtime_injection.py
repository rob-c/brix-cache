"""inject_nginx_runtime_paths anchors on real config syntax, not comment text.

Regression: tests/configs/nginx_zip.conf says "at http{} scope" in a comment.
The injector's first-match splice put the whole http runtime block inside that
comment — its tail lines landed at MAIN scope and every fleet start-all died
with `"access_log" directive is not allowed here`.
"""

from pathlib import Path

from cmdscripts.live_common import inject_nginx_runtime_paths

CONFIGS = Path(__file__).parent / "configs"


def _inject(tmp_path, body):
    conf = tmp_path / "nginx.conf"
    conf.write_text(body, encoding="utf-8")
    inject_nginx_runtime_paths(conf, tmp_path / "prefix")
    return conf.read_text(encoding="utf-8")


def _http_block_of(text):
    opener = [l for l in text.splitlines() if l.split("#")[0].strip() == "http {"]
    assert len(opener) == 1, text
    return text.split(opener[0], 1)[1]


# --- success ---------------------------------------------------------------


def test_the_block_lands_inside_the_real_http_block_not_a_comment(tmp_path):
    text = _inject(tmp_path, (
        "# directives are set ONCE at http{} scope, see the guide\n"
        "http {\n"
        "    server { }\n"
        "}\n"))
    assert "# directives are set ONCE at http{} scope, see the guide" in text
    assert "access_log" in _http_block_of(text)
    assert "client_body_temp_path" in _http_block_of(text)


def test_the_shipped_zip_template_survives_injection(tmp_path):
    template = (CONFIGS / "nginx_zip.conf").read_text(encoding="utf-8")
    body = template.replace("{DATA_DIR}", str(tmp_path / "data")) \
        .replace("{LOG_DIR}", str(tmp_path / "logs")) \
        .replace("{PORT}", "1").replace("{HTTP_WEBDAV_PORT}", "2") \
        .replace("{S3_PORT}", "3")
    text = _inject(tmp_path, body)
    before_http = text.split("\nhttp {", 1)[0]
    for line in before_http.splitlines():
        assert "temp_path" not in line.split("#")[0], line


# --- error -----------------------------------------------------------------


def test_a_commented_directive_name_does_not_suppress_injection(tmp_path):
    text = _inject(tmp_path, (
        "# access_log and client_body_temp_path are injected by the runner\n"
        "http {\n"
        "}\n"))
    block = _http_block_of(text)
    assert "access_log" in block
    assert "client_body_temp_path" in block


# --- negative --------------------------------------------------------------


def test_a_streams_only_config_gets_no_http_directives(tmp_path):
    text = _inject(tmp_path, (
        "# tune at http{} scope when an http block exists\n"
        "stream { server { } }\n"))
    assert "access_log" not in text.replace(
        "# tune at http{} scope when an http block exists", "")
    assert "client_body_temp_path" not in text
    assert "pid " in text          # main-scope confinement still applies
