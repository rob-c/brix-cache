"""Phase-115 W1 — the deployment surface is executable, and its guard is honest.

W1 shipped a container image workflow, nine compose stacks under deploy/compose/,
and `tools/ci/check_example_configs.py`, which renders every shipped example
config (compose stacks, *.conf.example, README + configuration-reference fences)
into a scratch tree and runs `nginx -t` on it. Writing the guard surfaced a row
of discoveries; each is pinned here so it cannot silently regress:

  * registry     — `check_directive_registry._ENTRY` was blind to any
                   ngx_command_t entry with a C comment between its fields
                   (brix_root, brix_auth, brix_scvmfs_x509_dn were invisible);
  * classify     — the marker grammar, the placeholder/template skips, and the
                   context heuristics that decide how a fence is wrapped;
  * render       — logical (non-filesystem) paths are never rewritten, every
                   materialised path lands under the scratch prefix (security:
                   an example can never make the checker touch /etc), and the
                   per-directive materialisation rules (RSA JWKS, htpasswd,
                   executable stubs, authdb files, CA directories);
  * nginx_t      — the one root-only [emerg] is tolerated only when it is the
                   ONLY emerg; a real error still fails;
  * guard        — end to end on a fixture tree: a valid tree passes, an unknown
                   directive fails, and the headline regression (a fence using
                   the retired `brix_cache_origin`) fails;
  * fences       — HTML `<pre><code class="language-nginx">` blocks are
                   discovered and entity-unescaped; excluded trees stay out;
  * compat       — `brix_tap_proxy_path_rewrite` is registered again (the
                   32698a676 rename dropped the registration while the setter
                   and the runtime survived; the docs kept advertising it):
                   success (TAKE2 parses), error (one argument is refused);
  * compose      — the nine stacks have the agreed shape, every conf parses,
                   and each locally runnable stack boots on remapped ports and
                   passes its own smoke.sh (the same script the `client`
                   compose service runs).

Run:
    PYTHONPATH=tests pytest tests/test_phase115_example_configs.py -v
"""
from __future__ import annotations

import json
import os
import re
import shutil
import socket
import subprocess
import sys
import time
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "tools" / "ci"))
import check_directive_registry as registry  # noqa: E402
import check_example_configs as guard        # noqa: E402
import example_config_lib as lib             # noqa: E402
from settings import HOST                     # noqa: E402

from compose_stack_ports import _lease_bindable, lease_port_range  # noqa: E402

pytestmark = [pytest.mark.timeout(600),
              pytest.mark.xdist_group("phase115-example-configs")]

COMPOSE = ROOT / "deploy" / "compose"
STACKS = ("standalone", "xrootd-proxy", "webdav-edge", "gridftp-gateway",
          "httpg-proxy", "cms-cluster", "s3-frontend", "xcache", "cvmfs")
LOCAL_STACKS = tuple(s for s in STACKS if s != "cvmfs")   # cvmfs is image-only
NGINX = lib.nginx_bin()
XRDCP = ROOT / "client" / "bin" / "xrdcp"
HAVE_NGINX = Path(NGINX).exists()

needs_nginx = pytest.mark.skipif(not HAVE_NGINX, reason=f"no nginx binary at {NGINX}")
needs_xrdcp = pytest.mark.skipif(not XRDCP.exists(), reason="client/bin/xrdcp not built")


# --------------------------------------------------------------------------- #
# registry: comment tolerance                                                 #
# --------------------------------------------------------------------------- #

COMMENTED_ENTRY = '''
    { ngx_string("brix_demo_flag"),   /* the flag */
      NGX_STREAM_SRV_CONF | NGX_CONF_FLAG,   /* stream only */
      ngx_conf_set_flag_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_brix_srv_conf_t, demo),
      NULL },
'''


def test_registry_regex_tolerates_c_comments_between_fields():
    m = registry._ENTRY.search(COMMENTED_ENTRY)
    assert m is not None, "an entry with comments between its fields was invisible"
    assert m.group(1) == "brix_demo_flag"
    assert m.group(3) == "ngx_conf_set_flag_slot"


def test_registry_sees_the_previously_invisible_directives():
    names = {n for n, *_ in registry.collect()}
    for name in ("brix_root", "brix_auth", "brix_scvmfs_x509_dn", "brix_tap_proxy_path_rewrite"):
        assert name in names, f"{name} missing from the registry"


def test_registry_refuses_a_commented_out_entry():
    # Security negative: a comment that merely *mentions* an entry is not one,
    # whether the comment wraps the whole entry or just sits inside it.
    whole = '/* { ngx_string("brix_ghost"), NGX_STREAM_SRV_CONF, ngx_conf_set_flag_slot, */'
    assert registry._literal_regs(whole, "src/ghost.h") == []
    live = ('{ ngx_string("brix_live"), /* { ngx_string("brix_ghost"), */\n'
            '  NGX_STREAM_SRV_CONF, ngx_conf_set_flag_slot, 0, 0, NULL },')
    assert [n for n, *_ in registry._literal_regs(live, "src/live.h")] == ["brix_live"]


# --------------------------------------------------------------------------- #
# classify + marker grammar                                                   #
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize("text,expected", [
    ("# check_example_configs: skip — proposed grammar\nbrix_future on;", "skip"),
    ("# check_example_configs: context=location\nbrix_webdav on;", "location"),
    ("server {\n    listen 1094;\n    brix_root on;\n}", "server-stream"),
    ("server {\n    listen 8443 ssl;\n    location / { brix_webdav on; }\n}", "server-http"),
    ("location / {\n    brix_webdav on;\n}", "location"),
    ("events { worker_connections 64; }\nstream { }", "full"),
    ("worker_processes 1;\nevents {}\n", "full"),
    ("server {\n    listen ...;\n}", "skip"),                # prose placeholder
    ("server {\n    brix_export <path>;\n}", "skip"),        # angle placeholder
    ("server {\n    listen @PORT@;\n}", "skip"),             # sed template
    ("brix_webdav on;\nbrix_allow_write on;", "skip"),       # bare: context unknown
])
def test_classify(text, expected):
    assert lib.classify(text) == expected


def test_placeholder_inside_a_comment_does_not_skip():
    # Comments are stripped before the placeholder heuristics run.
    text = "server {\n    # replace <host> with ... your host\n    listen 1094;\n    brix_root on;\n}"
    assert lib.classify(text) == "server-stream"


def test_marked_skip_only_honours_the_skip_marker():
    assert lib.marked_skip("# check_example_configs: skip\nx")
    assert not lib.marked_skip("# check_example_configs: context=http\nx")
    assert not lib.marked_skip("# skip\nx")


def test_wrap_refuses_unknown_context():
    with pytest.raises(ValueError):
        lib._wrap("x", "bogus")


# --------------------------------------------------------------------------- #
# render: path rewriting + materialisation                                    #
# --------------------------------------------------------------------------- #

RENDER_EXAMPLE = """\
server {
    listen 8443 ssl;
    ssl_certificate     /etc/brix/pki/hostcert.pem;
    ssl_certificate_key /etc/brix/pki/hostkey.pem;
    brix_client_certificate_folder /etc/grid-security/certificates;
    location / {
        brix_webdav on;
        brix_webdav_auth required;
        brix_token_jwks /etc/brix/jwks.json;
        brix_token_issuer https://issuer.site.example/;
        brix_token_audience https://storage.site.example;
        brix_storage_backend posix:/srv/data;
        brix_dashboard_browse_root /;              # logical: not a filesystem path
        brix_webdav_tpc_curl /usr/bin/curl;
        brix_dashboard_users /etc/brix/.htpasswd;
        brix_authdb /etc/brix/authdb;
        brix_allow_write on;
    }
}
"""


@pytest.fixture(scope="module")
def rendered(tmp_path_factory):
    prefix = tmp_path_factory.mktemp("render")
    ex = lib.Example("fixture#1", RENDER_EXAMPLE, lib.classify(RENDER_EXAMPLE))
    return prefix, lib.render(ex, prefix), ex


def test_render_rewrites_filesystem_paths_under_prefix(rendered):
    prefix, r, _ = rendered
    body = r.conf.read_text()
    assert f"posix:{prefix}/srv/data" in body
    assert f"ssl_certificate     {prefix}/etc/brix/pki/hostcert.pem" in body
    assert "listen 8443 ssl;" in body


def test_render_leaves_logical_paths_and_comments_alone(rendered):
    _, r, _ = rendered
    body = r.conf.read_text()
    assert re.search(r"^\s*brix_dashboard_browse_root /;", body, re.M)
    assert "# logical: not a filesystem path" in body


def test_render_never_materialises_outside_the_prefix(rendered):
    # Security: an example naming /etc/... must not make the checker touch /etc.
    prefix, r, _ = rendered
    assert r.created, "nothing was materialised"
    for path in r.created:
        assert str(path).startswith(str(prefix)), f"{path} escaped the scratch prefix"
    for line in r.conf.read_text().splitlines():
        for m in lib._ABS_RE.finditer(line.partition(" #")[0]):
            path = m.group(2)
            if path in ("/", "/dev/stderr", "/dev/stdout", "/dev/null"):
                continue
            if line.strip().split()[0] in lib.LOGICAL_PATH_DIRECTIVES:
                continue
            assert path.startswith(str(prefix)), f"unrewritten absolute path: {line.strip()}"


def test_render_hosts_are_aliased_to_localhost(rendered):
    _, r, _ = rendered
    body = r.conf.read_text()
    assert "issuer.site.example" not in body and "https://localhost/" in body  # net-literal-allow: the rendered doc text is the subject
    aliases = r.hostaliases.read_text()
    for h in ("origin", "manager", "backend"):
        assert f"{h} localhost" in aliases  # net-literal-allow: the host-alias mechanism is the subject under test


def test_materialised_jwks_is_a_real_rsa_key(rendered):
    prefix, _, _ = rendered
    doc = json.loads((prefix / "etc/brix/jwks.json").read_text())
    key = doc["keys"][0]
    assert key["kty"] == "RSA" and key["e"] == "AQAB" and len(key["n"]) > 300


def test_materialised_htpasswd_exec_stub_and_authdb(rendered):
    prefix, _, _ = rendered
    users = (prefix / "etc/brix/.htpasswd").read_text()
    assert re.match(r"^[a-z]+:\S+", users), users
    curl = prefix / "usr/bin/curl"
    assert curl.is_file() and os.access(curl, os.X_OK)
    assert (prefix / "etc/brix/authdb").is_file(), "authdb must be a file, not a directory"
    ca_dir = prefix / "etc/grid-security/certificates"
    assert ca_dir.is_dir() and any(ca_dir.glob("*.0")), "CA-ish dir must carry the demo CA"


def test_demo_pki_layout(rendered):
    prefix, _, _ = rendered
    pki = prefix / "_pki"
    for name in ("hostcert.pem", "hostkey.pem", "usercert.pem", "userkey.pem", "userproxy.pem"):
        assert (pki / name).is_file(), name
    assert (pki / "ca" / "ca.pem").is_file()
    assert any((pki / "ca").glob("*.signing_policy"))


def test_render_leaves_log_files_to_nginx(tmp_path):
    # A log path used to get the opaque placeholder body every other unknown
    # file gets — the guard audit log then opened with a bogus first line.
    text = ("server {\n    listen 8443;\n    error_log /var/log/brix/error.log;\n"
            "    location / {\n        brix_guard on;\n"
            "        brix_guard_audit_log /var/log/brix/guard-audit.log;\n    }\n}\n")
    lib.render(lib.Example("log#1", text, "http"), tmp_path)
    assert (tmp_path / "var/log/brix").is_dir()
    assert not (tmp_path / "var/log/brix/guard-audit.log").exists()
    assert not (tmp_path / "var/log/brix/error.log").exists()


def test_render_makes_the_credential_store_private(tmp_path):
    # brix refuses to write a delegated key into a store that is not 0700
    # (EPERM → 507 on every delegation PUT), so the rendered tree must match
    # what brix_shared_credential_dir_ensure() would have created itself.
    text = ("server {\n    listen 8443;\n    brix_storage_credential_dir /var/lib/brix/creds;\n"
            "    brix_export /data;\n    location / { brix_webdav on; }\n}\n")
    r = lib.render(lib.Example("cred#1", text, "http"), tmp_path)
    store = tmp_path / "var/lib/brix/creds"
    assert store.is_dir()
    assert (store.stat().st_mode & 0o777) == 0o700
    # Ordinary data directories stay group/other-readable as before.
    assert ((tmp_path / "data").stat().st_mode & 0o077) != 0


def _x509_ext(pem, name):
    return subprocess.run(["openssl", "x509", "-in", str(pem), "-noout", "-ext", name],
                          check=True, capture_output=True, text=True).stdout


def test_demo_pki_trust_dir_holds_no_private_key(rendered):
    # The CA dir is scanned file by file by brix_trusted_ca_dir / X509_CERT_DIR;
    # a key in it was logged as "PEM no start line, Expecting: CERTIFICATE".
    pki = rendered[0] / "_pki"
    assert (pki / "ca.key").is_file()
    assert not list((pki / "ca").glob("*.key"))
    for f in (pki / "ca").iterdir():
        assert "PRIVATE KEY" not in f.read_text(), f


def test_demo_pki_signing_policy_names_the_ca_in_slash_form(rendered):
    # access_id_CA is matched against the oneline slash DN brix logs; RFC 2253
    # order made the CA "may not sign subject" for every client cert.
    policy = next((rendered[0] / "_pki" / "ca").glob("*.signing_policy")).read_text()
    assert "access_id_CA  X509  '/DC=demo/DC=brix/CN=BriX Demo CA'" in policy
    assert "CN=BriX Demo CA,DC=" not in policy
    assert "cond_subjects globus '\"/DC=demo/DC=brix/*\"'" in policy


def test_demo_pki_end_entity_certs_may_sign_proxies(rendered):
    # RFC 3820: the user cert issues the delegated proxy, so it must carry
    # keyUsage digitalSignature or every gsiftp / TPC delegation fails with
    # "signer lacks keyUsage".
    pki = rendered[0] / "_pki"
    for name in ("usercert.pem", "hostcert.pem"):
        assert "Digital Signature" in _x509_ext(pki / name, "keyUsage"), name
    assert "TLS Web Client Authentication" in _x509_ext(pki / "usercert.pem", "extendedKeyUsage")
    assert "Certificate Sign" in _x509_ext(pki / "ca" / "ca.pem", "keyUsage")


# --------------------------------------------------------------------------- #
# nginx -t wrapper                                                            #
# --------------------------------------------------------------------------- #

def _render_text(tmp_path, text, name="probe"):
    ex = lib.Example(name, text, lib.classify(text))
    return lib.render(ex, tmp_path / name)


@needs_nginx
def test_nginx_t_accepts_a_valid_example(tmp_path):
    ok, err = lib.nginx_t(_render_text(tmp_path, RENDER_EXAMPLE))
    assert ok, err


@needs_nginx
def test_nginx_t_rejects_a_real_error(tmp_path):
    bad = RENDER_EXAMPLE.replace("brix_allow_write on;", "brix_allow_write maybe;")
    ok, err = lib.nginx_t(_render_text(tmp_path, bad, "bad"))
    assert not ok and "brix_allow_write" in err


@pytest.mark.skipif(os.geteuid() == 0, reason="root-only exemption is moot as root")
@needs_nginx
def test_nginx_t_tolerates_only_the_needs_root_emerg(tmp_path):
    # brix_idmap map needs a root master: tolerated alone …
    text = ("server {\n    listen 1094;\n    brix_root on;\n    brix_auth none;\n"
            "    brix_storage_backend posix:/srv/data;\n    brix_idmap map;\n}\n")
    ok, err = lib.nginx_t(_render_text(tmp_path, text, "idmap"))
    assert ok, err
    # … but not when a real emerg rides alongside it (security negative: the
    # exemption must not launder unrelated errors).
    ok, err = lib.nginx_t(_render_text(tmp_path, text.replace("brix_auth none;", "brix_auth nope;"), "idmap2"))
    assert not ok


# --------------------------------------------------------------------------- #
# the guard end to end, on a fixture tree                                     #
# --------------------------------------------------------------------------- #

GOOD_README = """# demo

```nginx
server {
    listen 1094;
    brix_root on;
    brix_auth none;
    brix_storage_backend posix:/srv/data;
}
```
"""


def _fixture_tree(tmp_path, readme=GOOD_README, extra=None):
    (tmp_path / "docs").mkdir()
    (tmp_path / "README.md").write_text(readme)
    (tmp_path / "deploy" / "compose" / "demo").mkdir(parents=True)
    if extra is not None:
        (tmp_path / "deploy" / "compose" / "demo" / "nginx.conf").write_text(extra)
    return tmp_path


def _run_guard(root, capsys, *extra):
    argv = ["--root", str(root), *extra]
    if not HAVE_NGINX:
        argv += ["--nginx", "/nonexistent/nginx"]
    rc = guard.main(argv)
    return rc, capsys.readouterr().out


def test_guard_passes_a_valid_tree(tmp_path, capsys):
    rc, out = _run_guard(_fixture_tree(tmp_path), capsys)
    assert rc == 0, out
    assert "1 examples" in out


def test_guard_fails_an_unknown_directive(tmp_path, capsys):
    bad = GOOD_README.replace("brix_auth none;", "brix_auth none;\n    brix_not_a_directive on;")
    rc, out = _run_guard(_fixture_tree(tmp_path, bad), capsys)
    assert rc == 1 and "unknown directive(s) brix_not_a_directive" in out


def test_guard_fails_the_headline_regression_retired_cache_origin(tmp_path, capsys):
    # The README carried brix_cache_origin for months after phase-64 retired it.
    stale = GOOD_README.replace("brix_storage_backend posix:/srv/data;",
                                "brix_cache on;\n    brix_cache_origin origin.site.example:1094;")
    rc, out = _run_guard(_fixture_tree(tmp_path, stale), capsys)
    assert rc == 1 and "brix_cache_origin" in out


def test_guard_honours_the_skip_marker(tmp_path, capsys):
    skipped = GOOD_README.replace("```nginx\n", "```nginx\n# check_example_configs: skip — proposed\n") \
                         .replace("brix_auth none;", "brix_future_grammar on;")
    rc, out = _run_guard(_fixture_tree(tmp_path, skipped), capsys)
    assert rc == 0, out


@needs_nginx
def test_guard_parses_compose_files_strictly(tmp_path, capsys):
    broken = "events {}\nstream {\n server {\n  listen 1094;\n  brix_root maybe;\n  brix_auth none;\n }\n}\n"
    rc, out = _run_guard(_fixture_tree(tmp_path, extra=broken), capsys)
    assert rc == 1 and "nginx -t failed" in out and "brix_root" in out


def test_guard_list_mode(tmp_path, capsys):
    rc, out = _run_guard(_fixture_tree(tmp_path), capsys, "--list")
    assert rc == 0 and "README.md#1" in out


# --------------------------------------------------------------------------- #
# fence discovery                                                             #
# --------------------------------------------------------------------------- #

def test_html_fences_are_discovered_and_unescaped(tmp_path):
    doc = tmp_path / "docs" / "x.md"
    doc.parent.mkdir()
    doc.write_text('<pre><code class="language-nginx">location / {\n brix_webdav on;\n'
                   ' brix_token_audience &quot;https://a&amp;b&quot;;\n}\n</code></pre>\n')
    (tmp_path / "README.md").write_text("")
    found = list(lib.iter_fences(tmp_path))
    assert len(found) == 1
    assert '"https://a&b"' in found[0].text


def test_excluded_trees_are_not_scanned(tmp_path):
    for sub in ("docs/_legacy", "docs/refactor", "docs/doxygen", "docs/live"):
        (tmp_path / sub).mkdir(parents=True)
        (tmp_path / sub / "a.md").write_text("```nginx\nlocation / { brix_webdav on; }\n```\n")
    (tmp_path / "docs" / "history-x.md").write_text("```nginx\nlocation / { brix_webdav on; }\n```\n")
    (tmp_path / "README.md").write_text("")
    sources = {e.source for e in lib.iter_fences(tmp_path)}
    assert sources == {"docs/live/a.md#1"}, sources


def test_strict_docs_are_the_configuration_references():
    for name in ("README.md", "docs/02-concepts/deployment-modes.md",
                 "docs/03-configuration/examples.md"):
        assert any(name in s for s in lib.STRICT_DOCS), name


# --------------------------------------------------------------------------- #
# compat: brix_tap_proxy_path_rewrite is registered again                     #
# --------------------------------------------------------------------------- #

PATH_REWRITE = ("server {\n    listen 1094;\n    brix_root on;\n    brix_auth none;\n"
                "    brix_tap_proxy on;\n    brix_tap_proxy_upstream origin:1095;\n"
                "    brix_tap_proxy_auth anonymous;\n    brix_tap_proxy_path_rewrite {args};\n}\n")


@needs_nginx
def test_path_rewrite_directive_parses_with_two_arguments(tmp_path):
    ok, err = lib.nginx_t(_render_text(tmp_path, PATH_REWRITE.replace("{args}", "/brix /data"), "prw"))
    assert ok, err


@needs_nginx
def test_path_rewrite_directive_refuses_one_argument(tmp_path):
    ok, err = lib.nginx_t(_render_text(tmp_path, PATH_REWRITE.replace("{args}", "/brix"), "prw1"))
    assert not ok and "brix_tap_proxy_path_rewrite" in err


def test_path_rewrite_is_documented_under_its_live_name():
    ref = (ROOT / "docs/03-configuration/directives.md").read_text()
    assert "brix_tap_proxy_path_rewrite" in ref
    assert "brix_proxy_path_rewrite" not in ref


# --------------------------------------------------------------------------- #
# the compose tree                                                            #
# --------------------------------------------------------------------------- #

def _compose(stack):
    return yaml.safe_load((COMPOSE / stack / "docker-compose.yml").read_text())


def _assert_server_service(stack, name, svc):
    """Every brix server in a stack: published image, healthcheck, waits for the
    PKI job, and mounts exactly one conf file that exists in the stack dir."""
    assert svc["image"].startswith("${BRIX_IMAGE:-ghcr.io/"), name
    assert "healthcheck" in svc, f"{name} has no healthcheck"
    assert svc["depends_on"]["pki"]["condition"] == "service_completed_successfully"
    confs = [v for v in svc["volumes"] if v.endswith(":/etc/brix/nginx.conf:ro")]
    assert len(confs) == 1 and (COMPOSE / stack / confs[0].split(":")[0]).is_file(), name


@pytest.mark.parametrize("stack", STACKS)
def test_stack_has_the_agreed_shape(stack):
    services = _compose(stack)["services"]
    assert "client" in services and services["client"].get("profiles") == ["smoke"]
    if stack == "cvmfs":
        assert "build" in services["cache"]
        return
    assert services["pki"]["command"] == ["brix-pki-init"]
    assert (COMPOSE / stack / "smoke.sh").stat().st_mode & 0o111
    for name, svc in services.items():
        if name not in ("pki", "client"):
            _assert_server_service(stack, name, svc)


ENTRYPOINT = ROOT / "deploy/docker/entrypoint.sh"


def test_entrypoint_keeps_the_credential_store_private():
    # Found by the httpg-proxy smoke: `chmod a+rwX` over the store made every
    # delegation PUT a 507 — brix writes delegated keys only into a 0700,
    # worker-owned directory. The volume mount arrives root-owned, so the
    # entrypoint must hand it over (as root) and tighten it, never loosen it.
    body = ENTRYPOINT.read_text()
    loosened = re.search(r"chmod a\+rwX[^\n]*", body).group(0)
    assert "/var/lib/brix/creds" not in loosened, loosened
    assert "chmod 0700 /var/lib/brix/creds" in body
    assert re.search(r'chown "\$\{worker_user:-nobody\}" /var/lib/brix/creds', body)
    assert '[ "$(id -u)" = 0 ]' in body


def test_entrypoint_derives_the_worker_user_from_the_config(tmp_path):
    # The chown target is nginx's `user` directive (default nobody); run the
    # extraction pipeline exactly as the script does.
    body = ENTRYPOINT.read_text()
    pipeline = re.search(r'worker_user="\$\((.*)\)"\n', body).group(1)
    conf = tmp_path / "nginx.conf"
    for text, want in (("user brix;\n", "brix"), ("  user  nginx nginx;\n", "nginx"),
                       ("worker_processes 2;\n", ""), ("# user root;\n", "")):
        conf.write_text(text)
        out = subprocess.run(["bash", "-c", pipeline], env={"BRIX_CONF": str(conf), "PATH": os.environ["PATH"]},
                             capture_output=True, text=True, check=True).stdout.strip()
        assert out == want, (text, out)


@pytest.mark.parametrize("stack", LOCAL_STACKS)
def test_smoke_scripts_are_posix_sh(stack):
    rc = subprocess.run(["sh", "-n", str(COMPOSE / stack / "smoke.sh")], capture_output=True, text=True)
    assert rc.returncode == 0, rc.stderr
    text = (COMPOSE / stack / "smoke.sh").read_text()
    assert f"SMOKE OK: {stack}" in text


@needs_nginx
@pytest.mark.parametrize("conf", sorted(COMPOSE.glob("*/nginx*.conf")),
                         ids=lambda path: str(path.relative_to(COMPOSE)))
def test_every_compose_conf_parses(tmp_path, conf):
    ex = lib.Example(str(conf.relative_to(ROOT)), conf.read_text(), "full")
    reason = lib.unsupported_reason(ex, NGINX)
    if reason:
        pytest.skip(reason)
    ok, err = lib.nginx_t(lib.render(ex, tmp_path))
    if not ok and lib.host_limitation(err):
        pytest.skip(f"{ex.source}: {lib.host_limitation(err)}")
    assert ok, f"{ex.source}: {err}"


# --------------------------------------------------------------------------- #
# live: boot each stack on this host and run its own smoke.sh                 #
# --------------------------------------------------------------------------- #

# Container ports → published ports come from the compose file; 9100 is the
# per-container observability port, so it is remapped per conf, not per stack.
OBS_PORT = 9100
SMOKE_PORT_ENV = {
    "standalone":      {"ROOT_PORT": 1094, "DAV_PORT": 8443},
    "xrootd-proxy":    {"ROOT_PORT": 1094, "ORIGIN_PORT": 1095},
    "webdav-edge":     {"DAV_PORT": 8443},
    "gridftp-gateway": {"GSIFTP_PORT": 2811, "FTP_PORT": 2121},
    "httpg-proxy":     {"FRONT_PORT": 8443, "BACKEND_PORT": 8444},
    "cms-cluster":     {"MANAGER_PORT": 1094, "DS1_PORT": 1095, "DS2_PORT": 1096},
    "s3-frontend":     {"S3_PORT": 9000, "DAV_PORT": 8443},
    "xcache":          {"CACHE_PORT": 1094, "ORIGIN_PORT": 1095},
}
# Which conf carries the stack's published 9100 (the client's OBS_PORT).
OBS_CONF = {"xrootd-proxy": "nginx-proxy.conf", "httpg-proxy": "nginx-front.conf",
            "cms-cluster": "nginx-manager.conf", "xcache": "nginx-cache.conf"}


def _published_ports(stack):
    ports = set()
    for svc in _compose(stack)["services"].values():
        for p in svc.get("ports", []):
            container = str(p).split(":")[-1]
            if "-" not in container:
                ports.add(int(container))
    ports.discard(OBS_PORT)
    return sorted(ports)


#: A pinned FTP passive data range makes concurrent copies of the same stack
#: fight for the same ports — the loser answers "425 Can't open data
#: connection".  Each rendered config gets its own leased block instead.
_PASV_RANGE = re.compile(r"(brix_gridftp_pasv_port_range\s+)(\d+)(\s+)(\d+)")


def _lease_pasv_ranges(text):
    def swap(m):
        width = int(m.group(4)) - int(m.group(2)) + 1
        low, high = lease_port_range(width)
        return f"{m.group(1)}{low}{m.group(3)}{high}"
    return _PASV_RANGE.sub(swap, text)


def _remap(text, mapping):
    for old, new in mapping.items():
        text = re.sub(rf"(?<![\d.]){old}(?![\d.])", str(new), text)
    return text


_RUNTIME_HOSTS = re.compile(r"(?<![\w.-])(?:%s)(?=:\d)"
                            % "|".join(re.escape(h) for h in lib.HOST_ALIASES if h != "localhost"))  # net-literal-allow: the host-alias mechanism is the subject under test


def _localise(text):
    """Point every server-side `<service>:<port>` at 127.0.0.1 for a local run.

    In the compose stacks the service names resolve through Docker's DNS. On
    this host they exist only in the HOSTALIASES file, which glibc honours for
    `nginx -t` and the master's config-time probes but not for the lookups a
    worker performs per request (a remote root:// open, a CMS join, proxy_pass).
    Only `host:port` positions change; server_name / proxy_ssl_name / paths and
    the client-facing smoke environment keep the service names.
    """
    return _RUNTIME_HOSTS.sub("127.0.0.1", text)  # net-literal-allow: the localiser's replacement is the subject


def _wait_ports(ports, log, deadline=30.0):
    end = time.monotonic() + deadline
    for port in ports:
        while True:
            try:
                with socket.create_connection((HOST, port), timeout=0.5):
                    break
            except OSError:
                if time.monotonic() > end:
                    pytest.fail(f"port {port} never opened\n{log.read_text()[-4000:]}")
                time.sleep(0.1)



class _Stack:
    """Every nginx*.conf of one compose stack, running on this host."""

    def __init__(self, stack, base):
        self.stack, self.base, self.procs = stack, base, []
        self.ports = {p: _lease_bindable() for p in _published_ports(stack)}
        self.obs_ports = {}
        pki_root = base / "shared"
        self.pki = lib._demo_pki(pki_root)[2].parent
        self.env = dict(os.environ, HOSTALIASES=str(base / "hostaliases"))
        (base / "hostaliases").write_text("".join(f"{h} localhost\n" for h in lib.HOST_ALIASES))  # net-literal-allow: the host-alias mechanism is the subject under test
        for conf in sorted((COMPOSE / stack).glob("nginx*.conf")):
            self._boot(conf)

    def _boot(self, conf):
        prefix = self.base / conf.stem
        prefix.mkdir()
        os.symlink(self.pki, prefix / "_pki")
        obs = _lease_bindable()
        self.obs_ports[conf.name] = obs
        text = _localise(_remap(conf.read_text(), {**self.ports, OBS_PORT: obs}))
        text = _lease_pasv_ranges(text)
        r = lib.render(lib.Example(f"{self.stack}/{conf.name}", text, "full"), prefix)
        lib.prepare_nginx(r, NGINX)
        log = prefix / "stderr.log"
        proc = subprocess.Popen([NGINX, "-p", str(prefix), "-c", str(r.conf), "-g", "daemon off;"],
                                env=self.env, stdout=log.open("wb"), stderr=subprocess.STDOUT)
        self.procs.append(proc)
        listens = [int(p) for p in re.findall(r"^\s*listen\s+(\d+)", text, re.M)]
        _wait_ports(listens, log)

    def smoke_env(self):
        env = {k: str(self.ports[v]) for k, v in SMOKE_PORT_ENV[self.stack].items()}
        obs_conf = OBS_CONF.get(self.stack, "nginx.conf")
        env.update(BRIX_HOST="localhost", OBS_PORT=str(self.obs_ports[obs_conf]),  # net-literal-allow: the host-alias mechanism is the subject under test
                   XRDCP=str(XRDCP), BRIX_PKI_DIR=str(self.pki),
                   SMOKE_TMP=str(self.base / "smoke-tmp"), PATH=os.environ["PATH"],
                   HOME=os.environ.get("HOME", "/tmp"))
        return env

    def logs(self):
        return "\n".join(f"--- {p}\n{p.read_text()[-3000:]}" for p in self.base.glob("*/stderr.log"))

    def stop(self):
        for proc in self.procs:
            proc.terminate()
        for proc in self.procs:
            try:
                proc.wait(timeout=10)
            except subprocess.TimeoutExpired:
                proc.kill()


@needs_nginx
@needs_xrdcp
@pytest.mark.parametrize("stack", LOCAL_STACKS)
def test_stack_boots_and_passes_its_smoke(stack, tmp_path):
    if shutil.which("curl") is None:
        pytest.skip("curl not installed")
    _require_stack_nginx(stack)
    st = _Stack(stack, tmp_path)
    try:
        rc = subprocess.run(["sh", str(COMPOSE / stack / "smoke.sh")], env=st.smoke_env(),
                            capture_output=True, text=True, timeout=300)
        assert rc.returncode == 0, f"smoke.sh failed\n{rc.stdout}\n{rc.stderr}\n{st.logs()}"
        # A Grid CA dir holds <hash>.signing_policy next to <hash>.0; loading
        # it used to leave PEM_R_NO_START_LINE on OpenSSL's error queue and
        # every later handshake logged "ignoring stale global SSL error".
        logs = st.logs()
        assert "stale global SSL error" not in logs, logs
        assert "no start line" not in logs, logs
        assert f"SMOKE OK: {stack}" in rc.stdout
    finally:
        st.stop()


def _require_stack_nginx(stack):
    for conf in sorted((COMPOSE / stack).glob("nginx*.conf")):
        ex = lib.Example(str(conf.relative_to(ROOT)), conf.read_text(), "full")
        reason = lib.unsupported_reason(ex, NGINX)
        if reason:
            pytest.skip(reason)


@needs_nginx
def test_stack_port_remap_is_word_bounded(tmp_path):
    # 1094 must not rewrite 11094 or 1094.5; 9100 must be independent per conf.
    text = "listen 1094;\nlisten 11094;\nbrix_cms_manager manager:1213;\nx 1094.5;\n"
    out = _remap(text, {1094: 40000, 1213: 40001})
    assert out == "listen 40000;\nlisten 11094;\nbrix_cms_manager manager:40001;\nx 1094.5;\n"


def test_localise_points_only_service_host_ports_at_loopback():
    text = ("brix_storage_backend root://origin:1095;\nbrix_cms_manager manager:1213;\n"
            "proxy_pass https://backend:8444;\nbrix_tap_proxy_upstream origin:1095;\n")
    assert _localise(text) == ("brix_storage_backend root://127.0.0.1:1095;\n"  # net-literal-allow: config directive text is the parser's input
                               "brix_cms_manager 127.0.0.1:1213;\nproxy_pass https://127.0.0.1:8444;\n"
                               "brix_tap_proxy_upstream 127.0.0.1:1095;\n")


def test_localise_leaves_names_that_are_not_resolved_at_runtime():
    # TLS names, server_name, real DNS names, paths and env assignments stay.
    text = ("server_name origin;\nproxy_ssl_name backend;\nlisten localhost:1094;\n"  # net-literal-allow: config directive text is the parser's input
            "upstream x { server origin.example.org:1095; server my-origin:1095; }\n"
            "brix_export /data/origin;\nBRIX_HOST=origin\n")
    assert _localise(text) == text


def test_localise_does_not_reach_the_client_facing_smoke_environment(tmp_path):
    # The smoke scripts talk to localhost by name; only the servers' own
    # upstream references are rewritten, so a smoke that resolved `origin`
    # would still exercise the HOSTALIASES path exactly as nginx -t does.
    env_names = {v for v in SMOKE_PORT_ENV.get("xcache", {})}
    assert env_names == {"CACHE_PORT", "ORIGIN_PORT"}
    assert not _RUNTIME_HOSTS.search("localhost:1094 origin origin/1095 origin:x")  # net-literal-allow: config directive text is the parser's input
