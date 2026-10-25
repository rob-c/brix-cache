"""Detect a usable Linux procfs, not merely FreeBSD's empty /proc directory."""

import os
import errno
import json
import re
from pathlib import Path
import subprocess
import sys
import time


def nginx_worker_title(command):
    """Recognize nginx's native role, including the copied BSD program name.

    This is classification, not ownership: callers must separately prove the
    test root and listener before signalling. Do not match helpers carrying a
    worker phrase in an argument or a different role after the same prefix.
    """
    pattern = (rb"(nginx(?:-[0-9a-f]{8})?): worker process"
               rb"(?: is shutting down)?(?: \(\1\))?")
    return re.fullmatch(pattern, command.strip()) is not None


def procfs_available(root="/proc"):
    """Route process inspection only when the required native files exist."""
    entries = (Path(root) / "self" / name for name in ("stat", "cmdline", "comm"))
    return all(entry.is_file() and os.access(entry, os.R_OK) for entry in entries)


def native_process_record(pid, collection, option):
    """Read one exact FreeBSD process record; missing/malformed is not empty."""
    result = subprocess.run(['/usr/bin/procstat', '--libxo', 'json', option, str(pid)],
                            check=True, capture_output=True, text=True, timeout=10)
    try:
        record = json.loads(result.stdout)['procstat'][collection][str(pid)]
        if type(record['process_id']) is not int or record['process_id'] != pid:
            raise ValueError('native process identity mismatch')
        return record
    except (ValueError, KeyError, TypeError) as error:
        raise RuntimeError('invalid native process report') from error


def native_no_new_privileges(pid):
    """Read FreeBSD's actual procctl state, never fabricate Linux cap fields."""
    if type(pid) is not int or pid <= 0:
        raise ValueError('invalid native process identity')
    result = subprocess.run(['/usr/bin/proccontrol', '-m', 'nonewprivs', '-q',
                             '-p', str(pid)], check=True, capture_output=True,
                            text=True, timeout=10)
    verdict = result.stdout.strip()
    if verdict not in ('enabled', 'disabled'):
        raise RuntimeError('invalid native no-new-privileges report')
    return verdict == 'enabled'


def _native_descriptor_row(row):
    """Validate one actual handle or recognize a native pseudo-descriptor."""
    descriptor = row['fd']
    if descriptor in ('text', 'ctty', 'cwd', 'root', 'jail'):
        return None  # procstat's pseudo-descriptors are not inherited handles
    if type(descriptor) is not int or descriptor < 0:
        raise RuntimeError('invalid native descriptor number')
    target = row['path']
    if not isinstance(target, str):
        raise RuntimeError('invalid native descriptor path')
    if row['fd_type'] == 'socket' and row['protocol'] not in ('UDS', 'UDD', 'UDQ'):
        target = 'network:' + row['protocol'] + ':' + target
    return descriptor, target


def native_descriptor_targets(pid):
    """Descriptor targets including explicit network-socket classifications."""
    record = native_process_record(pid, 'files', '-f')
    targets = {}
    for row in record['files']:
        entry = _native_descriptor_row(row)
        if entry is None:
            continue
        descriptor, target = entry
        if descriptor in targets:
            raise RuntimeError('duplicate native descriptor number')
        targets[descriptor] = target
    return targets


def _environment_tokens(info):
    """Keep unreadable own state distinct from an empty/foreign environment."""
    environment = info["environ"]
    if environment is not None:
        return [name + "=" + value for name, value in environment.items()]
    credentials = info["uids"]
    if credentials and credentials.real == os.geteuid():
        return None
    return []


def _native_process_row(info):
    """Keep argument/environment boundaries and ignore already-exited zombies."""
    if info["status"] == "zombie":
        return None
    values = [info[key] if info[key] is not None else default
              for key, default in (("ppid", 0), ("name", ""), ("cmdline", []))]
    return (*values, _environment_tokens(info))


def _live_native_process_row(process):
    """Discard a process proven gone/reused after the multi-sysctl snapshot.

    A child can exit between reading its UID and environment. Never turn an
    unreadable live owner's environment into empty data; only is_running's
    PID/creation-time check can remove an already-dead snapshot here.
    """
    row = _native_process_row(process.info)
    return row if row is not None and process.is_running() else None


def _retry_busy_native_environment(process):
    """Allow at most 60 ms for exec/exit, without treating unknown as empty.

    FreeBSD can report a new process as running before kvm_getenvv can read its
    image. Retry only that process, not the entire changing host snapshot.
    Unrelated errors and vanished identities retain their existing contracts.
    """
    import psutil

    for _attempt in range(3):
        time.sleep(0.02)
        try:
            return process.environ()
        except psutil.AccessDenied:
            # Match as_dict(ad_value=None): retain unreadable ownership rather
            # than abort the whole host snapshot or invent an empty environment.
            return None
        except OSError as error:
            if error.errno != errno.EBUSY:
                raise
    return None


def _native_process_info(process, fields):
    """Preserve unknown ownership when FreeBSD cannot read a busy environment.

    kvm_getenvv can return EBUSY while a process exits or changes its image.
    Collect the other fields separately; never invent an empty environment
    for a live process owned by this user. The caller still verifies lifetime.
    """
    try:
        return process.as_dict(attrs=fields, ad_value=None)
    except OSError as error:
        if error.errno != errno.EBUSY:
            raise
        info = process.as_dict(attrs=[name for name in fields if name != 'environ'],
                               ad_value=None)
        info['environ'] = _retry_busy_native_environment(process)
        return info


def native_process_table():
    """FreeBSD's native sysctl-backed API avoids lossy ps environment text."""
    try:
        import psutil
    except ImportError as error:
        raise RuntimeError("native process inspection requires psutil") from error
    fields = ["ppid", "name", "cmdline", "environ", "uids", "status"]
    table = {}
    try:
        for process in psutil.process_iter():
            try:
                process.info = _native_process_info(process, fields)
            except psutil.NoSuchProcess:
                continue
            row = _live_native_process_row(process)
            if row is not None:
                table[process.pid] = row
    except (psutil.Error, OSError) as error:
        raise RuntimeError("cannot inspect native process ownership") from error
    return table


def _sockstat_rows(contents):
    """Require a native socket collection, not an empty verdict for bad JSON."""
    try:
        body = json.loads(contents)["sockstat"]
        rows = body.get("socket", [])
        if not isinstance(body, dict) or not isinstance(rows, list):
            raise ValueError("invalid socket collection")
        return rows
    except (ValueError, KeyError, TypeError, AttributeError) as error:
        raise RuntimeError("cannot parse native listener ownership") from error


def _sockstat_fields(row):
    """Validate native scalar types before interpreting any socket state."""
    port, pid = row["local"]["port"], row.get("pid")
    if type(port) is not int or not 0 <= port <= 65535:
        raise ValueError("invalid listener port")
    if pid is not None and type(pid) is not int:
        raise ValueError("invalid listener owner")
    return port, pid, row["conn-state"]


def _sockstat_owner(row):
    """Validate ownership; FreeBSD also lists CLOSED, unbound sockets with -l."""
    try:
        port, pid, state = _sockstat_fields(row)
        if state == "CLOSED":
            return None
        if state != "LISTEN" or port == 0:
            raise ValueError("invalid listener state")
        return port, pid
    except (ValueError, KeyError, TypeError, AttributeError) as error:
        raise RuntimeError("cannot parse native listener ownership") from error


def _sockstat_listener_pids(contents):
    """Keep every inherited socket holder and unreadable-owner occupancy."""
    listeners = {}
    for row in _sockstat_rows(contents):
        owner = _sockstat_owner(row)
        if owner is None:
            continue
        port, pid = owner
        owners = listeners.setdefault(port, set())
        if pid is not None and pid > 0:
            owners.add(pid)
    return listeners


def native_listener_pids():
    """FreeBSD sockstat is bounded and retains ALL prefork socket owners.

    FreeBSD's psutil global connection table credits a shared socket to just
    one PID. Never use that lossy table to authorize process cleanup.
    """
    if not sys.platform.startswith("freebsd"):
        return None
    try:
        result = subprocess.run(["sockstat", "--libxo=json", "-l", "-s", "-P", "tcp"],
                                capture_output=True, text=True, timeout=5, check=True)
    except (OSError, subprocess.SubprocessError) as error:
        raise RuntimeError("cannot inspect native listener ownership") from error
    return _sockstat_listener_pids(result.stdout)
