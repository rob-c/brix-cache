"""Teardown and process-inspection operations shared by launcher facades."""

from __future__ import annotations

import os
from pathlib import Path
import shutil
import signal
import subprocess
import time


def _make_directory_writable(path):
    try:
        os.chmod(path, 0o755)
    except OSError:
        pass


def _remove_public_ca_entry(path):
    try:
        os.chmod(path, 0o644)
        path.unlink()
    except OSError:
        pass


def _copy_public_ca_entry(entry, destination):
    if entry.suffix in (".key", ".srl"):
        return
    try:
        target = destination / entry.name
        shutil.copyfile(entry.resolve(), target)
        os.chmod(target, 0o444)
    except OSError:
        pass


def _source_ca_directory(source):
    if not source:
        return None
    return Path(source) / "ca"


def _clear_public_ca(directory):
    for entry in directory.iterdir():
        _remove_public_ca_entry(entry)


def _copy_public_ca(source, destination):
    for entry in source.iterdir():
        _copy_public_ca_entry(entry, destination)


def _lock_public_ca(directory):
    try:
        os.chmod(directory, 0o555)
    except OSError:
        pass


def public_cadir(source, destination):
    """Build a read-only CA directory without private keys or serial files."""
    source_dir = _source_ca_directory(source)
    target_dir = Path(destination)
    target_dir.mkdir(parents=True, exist_ok=True)
    _make_directory_writable(target_dir)
    _clear_public_ca(target_dir)
    if source_dir is None or not source_dir.is_dir():
        return
    _copy_public_ca(source_dir, target_dir)
    _lock_public_ca(target_dir)


def _forget_owned(launcher, name):
    launcher._owned = [item for item in launcher._owned if item.name != name]


def _stop_external(launcher, name):
    if name not in launcher._external_stops:
        return False
    stop_argv, environment = launcher._external_stops.pop(name)
    subprocess.run(
        stop_argv,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        env=environment,
    )
    _forget_owned(launcher, name)
    return True


def _stop_tracked_process(launcher, name):
    if name not in launcher._xrootd_procs:
        return False
    launcher._kill_xrootd(name)
    _forget_owned(launcher, name)
    return True


def _registered_spec(name, registered_specs):
    return next((item for item in registered_specs() if item.name == name), None)


def _stop_from_disk(launcher, spec, endpoint, row):
    if row is None or not row.stop_from_disk:
        return False
    launcher._stop_from_disk(spec, endpoint)
    _forget_owned(launcher, spec.name)
    return True


def _signal_nginx_quit(launcher, spec, endpoint, master):
    if master is None:
        return
    try:
        launcher._nginx(
            ["-p", endpoint.prefix, "-c", "conf/nginx.conf", "-s", "quit"],
            spec=spec,
            check=False,
        )
    except OSError:
        pass


def _master_exited(master):
    try:
        os.kill(master, 0)
        return False
    except OSError:
        return True


def _kill_master(master):
    try:
        os.kill(master, signal.SIGKILL)
    except OSError:
        pass


def _wait_master_exit(master):
    if master is None:
        return
    deadline = time.time() + 10
    while time.time() < deadline:
        if _master_exited(master):
            return
        time.sleep(0.05)
    _kill_master(master)


def _stop_nginx(launcher, spec, endpoint):
    master = launcher._read_pid(endpoint.pidfile)
    _signal_nginx_quit(launcher, spec, endpoint, master)
    launcher._kill_pidfile(endpoint.pidfile, signal.SIGTERM, process_group=True)
    _wait_master_exit(master)
    launcher._reap_orphan_nginx_workers(spec)
    launcher._wait_ports_released(spec)


def stop(launcher, name, namespace):
    """Stop one instance using tracked state or its on-disk ownership proof."""
    if _stop_external(launcher, name):
        return
    if _stop_tracked_process(launcher, name):
        return
    spec = _registered_spec(name, namespace["registered_specs"])
    if spec is None:
        return
    endpoint = namespace["endpoint_for"](spec)
    row = namespace["LAUNCHER_KINDS"].get(spec.kind)
    if _stop_from_disk(launcher, spec, endpoint, row):
        return
    _stop_nginx(launcher, spec, endpoint)


def _candidate_pids(spec, declared_ports):
    from lib_py.util import pids_on_port

    candidates = set()
    for port in declared_ports(spec):
        candidates.update(pids_on_port(port))
    return candidates


def _process_title(pid):
    try:
        import server_launcher as launcher

        path_type = getattr(launcher, "Path", Path)
        return path_type(f"/proc/{pid}/cmdline").read_bytes().replace(b"\0", b" ")
    except OSError:
        return b""


def reap_orphan_nginx_workers(spec, declared_ports):
    from lib_py.util import kill_pid_list

    workers = [
        pid
        for pid in _candidate_pids(spec, declared_ports)
        if _process_title(pid).strip().startswith(b"nginx: worker process")
    ]
    if workers:
        kill_pid_list(workers)


def _master_pid(endpoint):
    pidfile = Path(endpoint.pidfile)
    if not pidfile.exists():
        return None
    master = pidfile.read_text(encoding="utf-8").strip()
    return master or None


def _process_rows():
    return subprocess.run(
        ["ps", "-o", "pid=,ppid=,command=", "-e"],
        capture_output=True,
        text=True,
        check=False,
    ).stdout.splitlines()


def _snapshot_row(line, master):
    parts = line.strip().split(None, 2)
    if len(parts) != 3:
        return None
    pid, parent_pid, command = parts
    if pid != master and parent_pid != master:
        return None
    return int(pid), command


def process_snapshot(name, namespace):
    spec = next(
        item for item in namespace["registered_specs"]() if item.name == name
    )
    endpoint = namespace["endpoint_for"](spec)
    master = _master_pid(endpoint)
    if master is None:
        return []
    rows = []
    for line in _process_rows():
        row = _snapshot_row(line, master)
        if row is not None:
            rows.append(row)
    return rows
