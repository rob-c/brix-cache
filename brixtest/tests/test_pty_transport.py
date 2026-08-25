"""Real PTY allocation, capture, input, and termination contracts."""

import subprocess
import sys

import pytest

from brixtest.runtime.commands import CommandRunner


def _runner(tmp_path):
    return CommandRunner(tmp_path / "commands", cwd=tmp_path)


def test_pty_connects_all_streams_and_supplies_declared_input(tmp_path, capsys):
    result = _runner(tmp_path).run(
        sys.executable, "-c",
        (
            "import os,sys;"
            "print(os.isatty(0),os.isatty(1),os.isatty(2));"
            "size=os.get_terminal_size();print(size.lines,size.columns);"
            "print(input())"
        ),
        input="hello from BriXTest\n", mode="pty",
    )

    rows = result.stdout.splitlines()
    assert rows[0] == "True True True"
    assert all(int(value) > 0 for value in rows[1].split())
    assert rows[2] == "hello from BriXTest"
    assert result.stderr == ""
    assert "True True True" in capsys.readouterr().out


def test_pty_capture_is_bounded_while_live_output_is_drained(tmp_path, capsys):
    result = _runner(tmp_path).run(
        sys.executable, "-c", "print('x' * 10000)",
        mode="pty", output_limit=128,
    )

    assert len(result.stdout.encode()) <= 128
    assert result.stdout_truncated
    assert "BriXTest output truncated" in result.stdout
    assert len(capsys.readouterr().out) >= 10000


def test_pty_timeout_kills_the_process_group_and_archives_failure(tmp_path):
    with pytest.raises(subprocess.TimeoutExpired):
        _runner(tmp_path).run(
            sys.executable, "-c",
            "import time;print('started',flush=True);time.sleep(30)",
            mode="pty", timeout=0.1,
        )

    metadata = (tmp_path / "commands" / "0001.json").read_text()
    assert '"error": "TimeoutExpired"' in metadata
    assert (tmp_path / "commands" / "0001.stdout.log").is_file()
