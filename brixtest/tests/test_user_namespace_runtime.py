"""Local user-namespace translation and privileged-map helper contracts."""

import argparse
import os
import pwd
import subprocess
import sys
from pathlib import Path

import pytest

from brixtest import identity
from brixtest.errors import SpecError
from brixtest.runtime.launcher_identity import process_identity_argv
from brixtest.runtime.userns_exec import _apply_maps, _mapping, _status_code


def test_process_identity_wraps_exact_maps_without_a_shell(monkeypatch):
    runner = identity(
        "runner", uid=0, gid=0, groups=(7,), user_namespace=True,
        uid_map=((0, 100000, 1),), gid_map=((0, 200000, 1), (7, 200007, 1)),
    )
    monkeypatch.setattr(
        "brixtest.runtime.launcher_identity.shutil.which",
        lambda name: "/usr/bin/" + name,
    )
    argv = process_identity_argv(runner, ("python3", "-c", "print('safe')"))

    assert argv[1:4] == ("-m", "brixtest.runtime.userns_exec", "--uid")
    assert "--uid-map" in argv and "0:100000:1" in argv
    assert "--gid-map" in argv and "7:200007:1" in argv
    assert argv[argv.index("--") + 1:][:2] == ("setpriv", "--no-new-privs")
    assert argv[-3:] == ("-c", "print('safe')") or argv[-3:] == (
        "python3", "-c", "print('safe')",
    )


def test_user_namespace_mapper_invokes_only_uid_and_gid_helpers(monkeypatch):
    calls = []
    monkeypatch.setattr(
        "brixtest.runtime.userns_exec.shutil.which",
        lambda name: "/usr/bin/" + name,
    )
    monkeypatch.setattr(
        "brixtest.runtime.userns_exec.subprocess.run",
        lambda argv, **options: calls.append((tuple(argv), options))
        or subprocess.CompletedProcess(argv, 0, "", ""),
    )

    _apply_maps(321, ((0, 1000, 1),), ((0, 2000, 1),))

    assert [call[0][0] for call in calls] == ["/usr/bin/newuidmap", "/usr/bin/newgidmap"]
    assert calls[0][0][1:] == ("321", "0", "1000", "1")
    assert all(call[1]["check"] is False for call in calls)


def test_user_namespace_map_parser_and_status_are_strict():
    assert _mapping("0:1000:2") == (0, 1000, 2)
    with pytest.raises(argparse.ArgumentTypeError):
        _mapping("0:1000:0")
    with pytest.raises(argparse.ArgumentTypeError):
        _mapping("$(id)")
    assert _status_code(3 << 8) == 3


def test_identity_rejects_overlapping_or_unmapped_id_ranges():
    with pytest.raises(SpecError, match="inside ID ranges must not overlap"):
        identity("runner", uid_map=((0, 1000, 2), (1, 2000, 1)))
    with pytest.raises(SpecError, match="covered by identity.gid_map"):
        identity("runner", gid=4, groups=(8,), gid_map=((4, 1000, 1),))


def _subordinate_id(kind):
    name = pwd.getpwuid(os.getuid()).pw_name
    path = Path("/etc/sub%s" % kind)
    if not path.is_file():
        return None
    row = next((line for line in path.read_text().splitlines() if line.startswith(name + ":")), "")
    return int(row.split(":")[1]) if row else None


def _subordinate_pair():
    uid, gid = _subordinate_id("uid"), _subordinate_id("gid")
    if uid is None or gid is None:
        pytest.skip("host has no subordinate UID/GID allocation")
    return uid, gid


def _available_result(result):
    if result.returncode == 125:
        pytest.skip(result.stderr.strip())
    return result


def test_live_user_namespace_clears_inherited_groups_when_host_permits_it():
    uid, gid = _subordinate_pair()
    result = subprocess.run(
        [
            sys.executable, "-m", "brixtest.runtime.userns_exec",
            "--uid", "0", "--gid", "0", "--uid-map", "0:%d:1" % uid,
            "--gid-map", "0:%d:1" % gid, "--", "/usr/bin/id",
        ],
        capture_output=True, text=True, timeout=10.0, check=False,
    )
    result = _available_result(result)
    assert result.returncode == 0
    assert "uid=0(root) gid=0(root) groups=0(root)" in result.stdout
