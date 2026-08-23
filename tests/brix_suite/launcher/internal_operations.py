"""Privilege, readiness, and disk-teardown operations for fleet launchers."""

from __future__ import annotations

import glob
import os
from pathlib import Path
import re
import shutil
import signal
import socket
import subprocess
import time


def _directive(config, name):
    match = re.search(rf"^{re.escape(name)}\s+(\S+)", config, re.M)
    if match is None:
        return None
    return match.group(1)


def _prepare_control_paths(launcher, config, user):
    for key in ("all.adminpath", "all.pidpath"):
        path = _directive(config, key)
        if not path:
            continue
        Path(path).mkdir(parents=True, exist_ok=True)
        launcher._chown_r(path, user)


def _prepare_local_root(launcher, config):
    local_root = _directive(config, "oss.localroot")
    if local_root:
        launcher._chmod_r(local_root, 0o777, add_only=True)


def _prepare_log(log_path, user):
    log_dir = os.path.dirname(log_path)
    Path(log_dir).mkdir(parents=True, exist_ok=True)
    os.chmod(log_dir, 0o777)
    Path(log_path).write_text("", encoding="utf-8")
    shutil.chown(log_path, user)


def _open_pki_directories(launcher, pki_dir):
    directories = (
        pki_dir,
        os.path.join(pki_dir, "ca"),
        os.path.join(pki_dir, "server"),
    )
    for directory in directories:
        if os.path.isdir(directory):
            launcher._chmod_add(directory, 0o555)


def _open_public_certificates(launcher, pki_dir):
    hostcert = os.path.join(pki_dir, "server", "hostcert.pem")
    if os.path.exists(hostcert):
        launcher._chmod_add(hostcert, 0o444)
    for pem in glob.glob(os.path.join(pki_dir, "ca", "*.pem")):
        launcher._chmod_add(pem, 0o444)


def _secure_host_key(pki_dir, user):
    hostkey = os.path.join(pki_dir, "server", "hostkey.pem")
    if not os.path.exists(hostkey):
        return
    shutil.chown(hostkey, user)
    os.chmod(hostkey, 0o400)


def _prepare_pki(launcher, pki_dir, user):
    if not pki_dir or not os.path.isdir(pki_dir):
        return
    _open_pki_directories(launcher, pki_dir)
    _open_public_certificates(launcher, pki_dir)
    _secure_host_key(pki_dir, user)


def xrootd_runas_user(launcher, config, log_path, namespace):
    """Prepare paths for XRootD's root-to-unprivileged user transition."""
    if os.geteuid() != 0:
        return None
    user = os.environ.get("REF_RUNAS_USER", "nobody")
    _prepare_control_paths(launcher, config, user)
    _prepare_local_root(launcher, config)
    _prepare_log(log_path, user)
    pki_dir = os.environ.get("PKI_DIR") or str(namespace["PKI_DIR"])
    _prepare_pki(launcher, pki_dir, user)
    return user


def _chmod_path(launcher, path, bits, add_only):
    if add_only:
        launcher._chmod_add(path, bits)
        return
    try:
        os.chmod(path, bits)
    except OSError:
        pass


def chmod_recursive(launcher, path, bits, add_only=False):
    for root, directories, files in os.walk(path):
        entries = [root]
        entries.extend(os.path.join(root, name) for name in directories + files)
        for entry in entries:
            _chmod_path(launcher, entry, bits, add_only)


def _environment(extra):
    merged = os.environ.copy()
    if extra:
        merged.update(extra)
    return merged


def _failure_paths(spec, endpoint_for):
    if spec is None:
        return "", ""
    endpoint = endpoint_for(spec)
    return endpoint.config, str(Path(endpoint.prefix, "logs"))


def _raise_command_failure(result, binary, args, spec, namespace):
    config_path, logs_dir = _failure_paths(spec, namespace["endpoint_for"])
    raise namespace["RegistryCommandFailure"](
        config_path=config_path,
        logs_dir=logs_dir,
        command=(binary, *args),
        returncode=result.returncode,
        stdout_tail=result.stdout[-4000:],
        stderr_tail=result.stderr[-4000:],
    )


def nginx(args, spec, env, check, namespace):
    binary = namespace["_nginx_bin"]()
    result = subprocess.run(
        [binary, *args],
        capture_output=True,
        text=True,
        env=_environment(env),
    )
    if check and result.returncode != 0:
        _raise_command_failure(result, binary, args, spec, namespace)
    return result


def _readiness_kind(readiness):
    tcp_kinds = {"root", "webdav", "s3", "metrics", "cms", "tcp"}
    if readiness in tcp_kinds:
        return "tcp"
    return readiness


def _tcp_ready(host, port):
    try:
        with socket.create_connection((host, port), timeout=0.5):
            return True
    except OSError:
        return False


def wait_ready(host, port, readiness):
    if port is None or readiness == "none":
        return
    kind = _readiness_kind(readiness)
    if kind != "tcp":
        raise ValueError(f"unknown registry readiness probe: {kind}")
    deadline = time.time() + 10
    while time.time() < deadline:
        if _tcp_ready(host, port):
            return
        time.sleep(0.1)
    raise RuntimeError(f"server did not become ready on {host}:{port}")


def _port_released(port):
    probe = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    probe.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        probe.bind(("0.0.0.0", port))  # net-literal-allow: availability probe
        return True
    except OSError:
        return False
    finally:
        probe.close()


def _wait_port_released(port, deadline):
    while True:
        if _port_released(port) or time.time() >= deadline:
            return
        time.sleep(0.05)


def wait_ports_released(spec, timeout, declared_ports):
    deadline = time.time() + timeout
    for port in declared_ports(spec):
        _wait_port_released(port, deadline)


def _stop_external(spec):
    stop_argv = list(spec.template_values.get("stop_argv", ()))
    if not stop_argv:
        return
    subprocess.run(
        stop_argv,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        env={**os.environ, **spec.env},
    )


def _kill_port_processes(endpoint):
    from lib_py.util import pids_on_port

    for pid in pids_on_port(int(endpoint.port)):
        try:
            os.kill(pid, signal.SIGKILL)
        except OSError:
            pass


def _wait_disk_process(launcher, pidfile, master, grace):
    if master is None or not grace:
        return
    deadline = time.time() + grace
    while time.time() < deadline:
        if launcher._process_exited(master):
            return
        time.sleep(0.05)
    launcher._kill_pidfile(pidfile, signal.SIGKILL, process_group=True)


def _stop_pidfile_process(launcher, endpoint, row):
    pidfile = str(Path(endpoint.prefix) / row.pidfile)
    master = launcher._read_pid(pidfile)
    launcher._kill_pidfile(pidfile, signal.SIGTERM, process_group=True)
    _wait_disk_process(launcher, pidfile, master, row.kill_grace)


def stop_from_disk(launcher, spec, endpoint, namespace):
    row = namespace["LAUNCHER_KINDS"].get(spec.kind)
    strategy = None if row is None else row.profile.stop
    if strategy is namespace["external_stop"]:
        _stop_external(spec)
        return
    if strategy == "port-kill":
        _kill_port_processes(endpoint)
        return
    _stop_pidfile_process(launcher, endpoint, row)
