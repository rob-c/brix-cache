"""Low-complexity operations shared by both launcher compatibility surfaces."""

from __future__ import annotations

import os
from pathlib import Path
import shutil
import subprocess

import pytest


def _kind_row(namespace, spec):
    return namespace["LAUNCHER_KINDS"].get(spec.kind)


def _quiescence_mode(row):
    if row is None:
        return "pidfile"
    return row.quiescence


def _has_runtime_handle(launcher, name):
    return name in launcher._external_stops or name in launcher._xrootd_procs


def _ports_are_idle(spec, listeners, declared_ports):
    return not any(port in listeners for port in declared_ports(spec))


def _may_be_quiescent(launcher, spec, listeners, row, declared_ports):
    mode = _quiescence_mode(row)
    return all(
        (
            listeners is not None,
            not _has_runtime_handle(launcher, spec.name),
            mode != "never",
            _ports_are_idle(spec, listeners or {}, declared_ports),
        )
    )


def _endpoint_or_none(spec, endpoint_for):
    try:
        return endpoint_for(spec)
    except ValueError:
        return None


def _quiescence_pidfile(endpoint, row):
    relpath = None if row is None else row.pidfile
    if relpath:
        return os.path.join(endpoint.prefix, relpath)
    return endpoint.pidfile


def quiescent(launcher, spec, listeners, namespace):
    """Return whether a registry instance has no observable live resources."""
    row = _kind_row(namespace, spec)
    declared_ports = namespace["declared_ports"]
    if not _may_be_quiescent(launcher, spec, listeners, row, declared_ports):
        return False
    endpoint = _endpoint_or_none(spec, namespace["endpoint_for"])
    if endpoint is None:
        return False
    if _quiescence_mode(row) == "ports-only":
        return True
    return not os.path.exists(_quiescence_pidfile(endpoint, row))


def _dispatch_special(launcher, spec, namespace):
    row = _kind_row(namespace, spec)
    if row is None or row.start_method is None:
        return False
    getattr(launcher, row.start_method)(spec)
    return True


def _prepare_nginx_permissions(launcher, endpoint):
    if os.geteuid() != 0:
        return
    if os.path.isdir(endpoint.data_root):
        launcher._chmod_r(endpoint.data_root, 0o777, add_only=True)
    logs_dir = os.path.join(endpoint.prefix, "logs")
    if os.path.isdir(logs_dir):
        launcher._chmod_add(logs_dir, 0o777)


def _master_owns_prefix(launcher, endpoint):
    master = launcher._read_pid(endpoint.pidfile)
    if master is None:
        return False
    try:
        os.kill(master, 0)
        with open(f"/proc/{master}/cmdline", "rb") as handle:
            command = handle.read().replace(b"\0", b" ")
    except (OSError, ValueError):
        return False
    return endpoint.prefix.encode() in command


def _launch_nginx(launcher, spec, endpoint, namespace):
    failure_type = namespace["RegistryCommandFailure"]
    try:
        launcher._nginx(
            ["-p", endpoint.prefix, "-c", "conf/nginx.conf"],
            spec=spec,
            env=spec.env,
        )
    except failure_type:
        if not _master_owns_prefix(launcher, endpoint):
            raise
        launcher._wait_ready(endpoint.host, endpoint.port, spec.readiness)


def start_nginx(launcher, spec, namespace):
    """Dispatch special kinds or start one rendered nginx instance."""
    if _dispatch_special(launcher, spec, namespace):
        return
    endpoint = launcher.render_nginx(spec)
    _prepare_nginx_permissions(launcher, endpoint)
    launcher.nginx_test(spec)
    _launch_nginx(launcher, spec, endpoint, namespace)
    launcher._wait_ready(endpoint.host, endpoint.port, spec.readiness)
    launcher._owned.append(spec)


def _xrootd_binary(namespace):
    selected = namespace["BRIX_BIN"]
    binary = shutil.which(selected)
    if not binary:
        pytest.skip(f"selected xrootd binary is unavailable: {selected}")
    return binary


def _prepare_xrootd_paths(endpoint):
    prefix = Path(endpoint.prefix)
    paths = {
        "prefix": prefix,
        "admin": prefix / "admin",
        "run": prefix / "run",
        "logs": prefix / "logs",
        "tmp": prefix / "tmp",
    }
    for path in (
        prefix / "conf",
        paths["logs"],
        paths["admin"],
        paths["run"],
        Path(endpoint.data_root),
    ):
        path.mkdir(parents=True, exist_ok=True)
    return paths


def _base_xrootd_values(launcher, spec, endpoint, paths):
    return {
        **launcher._session_values(spec),
        "PORT": endpoint.port,
        "DATA_ROOT": endpoint.data_root,
        "DATA_DIR": endpoint.data_root,
        "LOG_DIR": str(paths["logs"]),
        "TMP_DIR": str(paths["tmp"]),
        "ADMIN_DIR": str(paths["admin"]),
        "RUN_DIR": str(paths["run"]),
        **endpoint.extra_ports,
        **launcher._endpoint_template_values(),
        **spec.template_values,
    }


def _add_security_library(launcher, values):
    security = launcher._find_xrd_library("libXrdSec-5.so", "libXrdSec.so")
    if security and "SECLIB" not in values:
        values["SECLIB"] = str(security)


def _render_xrootd_config(spec, path, values, namespace):
    namespace["render_config_to_path"](
        spec.template,
        str(path),
        strict=namespace["REGISTRY_STRICT_TEMPLATES"],
        **values,
    )


def _process_environment(extra):
    environment = os.environ.copy()
    if extra:
        environment.update(extra)
    return environment


def _xrootd_argv(launcher, binary, config, log_path):
    argv = [binary, "-c", str(config), "-l", str(log_path)]
    run_as = launcher._xrootd_runas_user(
        config.read_text(encoding="utf-8"), str(log_path)
    )
    if run_as:
        argv.extend(("-R", run_as))
    return argv


def _spawn_xrootd(argv, environment):
    return subprocess.Popen(
        argv,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        start_new_session=True,
        env=environment,
    )


def _track_xrootd(launcher, spec, endpoint, process):
    launcher._xrootd_procs[spec.name] = process
    try:
        launcher._wait_ready(endpoint.host, endpoint.port, spec.readiness)
    except Exception:
        launcher._kill_xrootd(spec.name)
        raise
    launcher._owned.append(spec)


def start_xrootd(launcher, spec, namespace):
    binary = _xrootd_binary(namespace)
    endpoint = namespace["endpoint_for"](spec)
    paths = _prepare_xrootd_paths(endpoint)
    values = _base_xrootd_values(launcher, spec, endpoint, paths)
    _add_security_library(launcher, values)
    config = paths["prefix"] / "conf" / "xrootd.cfg"
    _render_xrootd_config(spec, config, values, namespace)
    log_path = paths["logs"] / "xrootd.log"
    argv = _xrootd_argv(launcher, binary, config, log_path)
    process = _spawn_xrootd(argv, _process_environment(spec.env))
    _track_xrootd(launcher, spec, endpoint, process)


def _http_libraries(launcher):
    libraries = {
        "HTTP_LIB": launcher._find_xrd_library("libXrdHttp-5.so", "libXrdHttp.so"),
        "TPC_LIB": launcher._find_xrd_library("libXrdHttpTPC-5.so", "libXrdHttpTPC.so"),
        "SECLIB": launcher._find_xrd_library("libXrdSec-5.so", "libXrdSec.so"),
    }
    if not libraries["HTTP_LIB"] or not libraries["TPC_LIB"]:
        pytest.skip("XrdHttp/XrdHttpTPC libraries not installed")
    return libraries


def _http_values(launcher, spec, endpoint, paths, libraries, ca_public):
    values = _base_xrootd_values(launcher, spec, endpoint, paths)
    values.update(
        {
            "HTTP_LIB": str(libraries["HTTP_LIB"]),
            "TPC_LIB": str(libraries["TPC_LIB"]),
            "SECLIB": str(libraries["SECLIB"] or "/usr/lib64/libXrdSec-5.so"),
            "CA_DIR": str(ca_public),
        }
    )
    return values


def start_xrdhttp(launcher, spec, namespace):
    binary = _xrootd_binary(namespace)
    libraries = _http_libraries(launcher)
    endpoint = namespace["endpoint_for"](spec)
    paths = _prepare_xrootd_paths(endpoint)
    ca_public = paths["prefix"] / "ca-public"
    pki_dir = os.environ.get("PKI_DIR") or str(namespace["PKI_DIR"])
    launcher._public_cadir(pki_dir, str(ca_public))
    values = _http_values(launcher, spec, endpoint, paths, libraries, ca_public)
    config = paths["prefix"] / "conf" / "xrdhttp.cfg"
    _render_xrootd_config(spec, config, values, namespace)
    log_path = paths["logs"] / "xrdhttp.log"
    argv = _xrootd_argv(launcher, binary, config, log_path)
    process = _spawn_xrootd(argv, _process_environment(spec.env))
    _track_xrootd(launcher, spec, endpoint, process)
