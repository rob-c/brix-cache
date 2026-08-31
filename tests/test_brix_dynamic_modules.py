"""Dynamic-module (load_module) conformance (phase-106 W7).

The RPM ships brix as TWO combined dynamic objects — ngx_stream_brix_module.so
(every stream + http brix module compiled together) and the xrdhttp filter —
loaded with `load_module`, not compiled in. The phase-106-specific risk is that
variables are registered in `preconfiguration`, whose call ORDER differs
between static and dynamic builds; a variable surface that only worked
compiled-in would ship broken packages while every dev-tree test stayed green.

Needs a dynamic build tree (default /home/rcurrie/nginx-dyn, override with
BRIX_DYN_NGINX): a plain nginx binary plus the two .so files, built with
--with-compat --add-dynamic-module. Skips cleanly when absent, so the fast
lane does not depend on the second tree existing.

  * success   — a config that load_modules both objects passes nginx -t with
                brix directives AND $brix_* variables on both planes
  * error     — a load_module path that does not exist fails at config time
                with nginx's own diagnostic, not a crash
  * security  — the dynamically loaded module still refuses the misspelled
                variable (the registration really ran; nothing silently
                degraded to "unknown variables accepted")

Run:
    PYTHONPATH=tests pytest tests/test_brix_dynamic_modules.py -v
"""

from __future__ import annotations

import os
import subprocess
from pathlib import Path

import pytest

pytestmark = [pytest.mark.timeout(120),
              pytest.mark.xdist_group("brix-dynamic-modules")]

DYN_ROOT = Path(os.environ.get("BRIX_DYN_NGINX", "/home/rcurrie/nginx-dyn"))
DYN_NGINX = Path(os.environ.get("BRIX_DYN_NGINX_BIN", DYN_ROOT / "objs" / "nginx"))
# The two module .so files. Overridable individually so the SAME test can run
# against a PACKAGED artifact (an unpacked .deb / installed rpm at
# usr/lib/nginx/modules) rather than only the dev build tree — that is how W7's
# "the packaged RPM and deb pass the same test" acceptance is met.
DYN_STREAM_SO = Path(os.environ.get(
    "BRIX_DYN_STREAM_SO", DYN_ROOT / "objs" / "ngx_stream_brix_module.so"))
DYN_FILTER_SO = Path(os.environ.get(
    "BRIX_DYN_FILTER_SO",
    DYN_ROOT / "objs" / "ngx_http_brix_xrdhttp_filter_module.so"))

_missing = [p for p in (DYN_NGINX, DYN_STREAM_SO, DYN_FILTER_SO)
            if not p.exists()]
if _missing:
    pytestmark.append(pytest.mark.skip(
        reason=f"dynamic build tree not present: {_missing[0]} "
               "(build with --with-compat --add-dynamic-module; "
               "see phase-106 W7)"))


def _conf(tmp_path, *, stream_so=DYN_STREAM_SO, filter_so=DYN_FILTER_SO,
          log_format_line=None):
    """Render the W7 template (tests/configs/nginx_dyn_modules.conf)."""
    from config_templates import render_config_to_path
    from fleet_lifecycle_ports import SHARED_PARSE_PLACEHOLDER_PORT
    from settings import BIND_HOST

    (tmp_path / "logs").mkdir(exist_ok=True)
    (tmp_path / "data").mkdir(exist_ok=True)
    conf = tmp_path / "nginx.conf"
    render_config_to_path(
        "nginx_dyn_modules.conf", conf,
        STREAM_SO=str(stream_so),
        FILTER_SO=str(filter_so),
        PREFIX=str(tmp_path),
        BIND_HOST=BIND_HOST,
        HTTP_PORT=SHARED_PARSE_PLACEHOLDER_PORT,
        STREAM_PORT=SHARED_PARSE_PLACEHOLDER_PORT + 1,
        DATA_DIR=str(tmp_path / "data"),
        HTTP_LOG_FORMAT=log_format_line or (
            "log_format dyn 'cache=$brix_cache_status tls=$brix_tls "
            "proto=$brix_protocol dn=$brix_dn tier=$brix_tier';"))
    return conf


def _nginx_t(tmp_path, conf):
    return subprocess.run(
        [str(DYN_NGINX), "-t", "-p", str(tmp_path), "-c", str(conf)],
        capture_output=True, text=True, timeout=60)


def test_load_module_resolves_directives_and_variables_on_both_planes(tmp_path):
    """(success) The dlopen'd modules provide their directives AND the $brix_*
    variable surface on the http and stream planes alike — proving the
    preconfiguration registration ran under dynamic load."""
    r = _nginx_t(tmp_path, _conf(tmp_path))
    assert r.returncode == 0, r.stderr


def test_missing_module_object_fails_with_nginx_diagnostic(tmp_path):
    """(error) A load_module path that does not exist is a clean config-time
    failure naming the path — never a crash, never a silent skip that would
    leave brix directives 'unknown'."""
    r = _nginx_t(tmp_path, _conf(tmp_path,
                                 stream_so=tmp_path / "no-such-module.so"))
    assert r.returncode != 0
    assert "no-such-module.so" in r.stderr, r.stderr


def test_dynamic_registration_still_refuses_unknown_variables(tmp_path):
    """(security-neg / non-vacuity) Under dlopen the misspelled variable is
    still refused. If registration had silently not run, the SUCCESS case
    would fail on the real names — this cell pins the opposite direction:
    dynamic load must not somehow accept what static load refuses."""
    bad = ("log_format dyn 'x=$brix_cache_stats';")
    r = _nginx_t(tmp_path, _conf(tmp_path, log_format_line=bad))
    assert r.returncode != 0
    assert 'unknown "brix_cache_stats" variable' in r.stderr, r.stderr


def test_packaged_deb_artifact_loads(tmp_path):
    """(W7 acceptance) The modules unpacked from a real .deb load the same way.

    Builds a binary .deb from the built module .so files with dpkg-deb — the
    package ships exactly these two objects at usr/lib/nginx/modules/ (see
    packaging/deb/debian/nginx-mod-brix-cache.install) — unpacks it, and runs
    the same directives+variables check against the UNPACKED .so files. This is
    the "packaged deb passes the same test" half of W7's acceptance, done
    without the full debhelper pipeline (which is not present on every dev box).

    The RPM half needs rpmbuild (absent on this box; present in the almalinux:9
    CI container) — the same test runs against it by pointing
    BRIX_DYN_STREAM_SO / BRIX_DYN_FILTER_SO at the installed rpm's modules.
    """
    import shutil
    import subprocess

    if shutil.which("dpkg-deb") is None:
        pytest.skip("dpkg-deb not available")

    stage = tmp_path / "pkg"
    (stage / "usr/lib/nginx/modules").mkdir(parents=True)
    (stage / "DEBIAN").mkdir()
    # dpkg-deb rejects a control dir outside 0755..0775; the test's umask is
    # environment-dependent, so set the mode explicitly rather than inherit it.
    (stage / "DEBIAN").chmod(0o755)
    for so in (DYN_STREAM_SO, DYN_FILTER_SO):
        shutil.copy(so, stage / "usr/lib/nginx/modules" / so.name)
    (stage / "DEBIAN" / "control").write_text(
        "Package: nginx-mod-brix-cache\n"
        "Version: 0-test\nArchitecture: amd64\n"
        "Maintainer: test <noreply@example.com>\n"
        "Description: phase-106 W7 packaged-artifact test\n")
    deb = tmp_path / "pkg.deb"
    r = subprocess.run(["dpkg-deb", "--build", "--root-owner-group",
                        str(stage), str(deb)],
                       capture_output=True, text=True, timeout=120)
    assert r.returncode == 0, r.stderr

    extract = tmp_path / "x"
    subprocess.run(["dpkg-deb", "-x", str(deb), str(extract)],
                   check=True, timeout=60)
    mods = extract / "usr/lib/nginx/modules"

    conf = _conf(tmp_path,
                 stream_so=mods / "ngx_stream_brix_module.so",
                 filter_so=mods / "ngx_http_brix_xrdhttp_filter_module.so")
    r = _nginx_t(tmp_path, conf)
    assert r.returncode == 0, r.stderr
