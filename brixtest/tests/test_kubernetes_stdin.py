"""Binary-safe stdin contracts shared by local and Kubernetes tools."""

import dataclasses
import json
import subprocess
import sys

import pytest

from brixtest import Placement, SpecError, command, tool
from brixtest.runtime.commands import CommandRunner
from brixtest.runtime.executors import (
    ToolExecutionContext,
    ToolExecutionRequest,
    tool_executor,
)
from brixtest.runtime import executor_kubernetes


_IMAGE = "registry.test/tool@sha256:" + "a" * 64


class _KubernetesCalls:
    def __init__(self, *, attach_error=""):
        self.attach_error = attach_error
        self.calls = []
        self.manifest = None
        self.attached = None
        self.status_reads = 0

    def __call__(self, executable, *args, input_text="", **options):
        self.calls.append((args, input_text, options))
        if args[:3] == ("apply", "-f", "-"):
            self.manifest = json.loads(input_text)
        if "get" in args:
            self.status_reads += 1
            return self._status(executable, args)
        if "attach" in args:
            self.attached = input_text
            code = 1 if self.attach_error else 0
            return subprocess.CompletedProcess(args, code, "", self.attach_error)
        if "logs" in args:
            return subprocess.CompletedProcess(args, 0, "received\n", "")
        return subprocess.CompletedProcess(args, 0, "", "")

    def _status(self, executable, args):
        phase = "Running" if self.status_reads == 1 else "Succeeded"
        status = {"phase": phase}
        if phase == "Succeeded":
            status["containerStatuses"] = [{
                "state": {"terminated": {"exitCode": 0}},
            }]
        return subprocess.CompletedProcess(
            args, 0, json.dumps({"status": status}), "",
        )


def _request(value):
    return ToolExecutionRequest(
        name="reader", argv=("/tool",), env={}, cwd=None, timeout=2.0,
        input=value, expected_exit_codes=(0,), output_limit=1024,
        mode="capture", retries=0, encoding="latin-1", check=False,
        placement=Placement(backend="kubernetes", image=_IMAGE), image=_IMAGE,
    )


def _context(tmp_path):
    return ToolExecutionContext(
        "unit::stdin", tmp_path, tmp_path, "kubernetes", namespace="unit",
    )


def test_raw_bytes_are_preserved_by_local_command_transport(tmp_path):
    payload = b"\x00\xffraw\n"
    result = CommandRunner(None, cwd=tmp_path).run(
        sys.executable, "-c",
        "import sys;sys.stdout.buffer.write(sys.stdin.buffer.read())",
        input=payload, encoding="latin-1",
    )
    assert result.stdout.encode("latin-1") == payload
    assert command("reader", input=payload).input == payload
    assert tool("reader", command=("reader",), input=payload).input == payload


def test_kubernetes_tool_attaches_binary_stdin_and_collects_result(tmp_path, monkeypatch):
    calls = _KubernetesCalls()
    monkeypatch.setattr(executor_kubernetes, "_kubectl", calls)
    payload = b"\x00\xffpayload"

    result = tool_executor("kubernetes").execute(
        _context(tmp_path), _request(payload),
    )

    container = calls.manifest["spec"]["containers"][0]
    assert (container["stdin"], container["stdinOnce"]) == (True, True)
    assert calls.attached == payload
    assert (result.returncode, result.stdout) == (0, "received\n")
    assert any("delete" in row[0] for row in calls.calls)


def test_kubernetes_stdin_attach_failure_is_not_silently_ignored(tmp_path, monkeypatch):
    calls = _KubernetesCalls(attach_error="attach denied")
    monkeypatch.setattr(executor_kubernetes, "_kubectl", calls)

    result = tool_executor("kubernetes").execute(
        _context(tmp_path), _request("request"),
    )

    assert result.returncode == 1
    assert result.stderr == "attach denied"
    assert any("delete" in row[0] for row in calls.calls)


def test_kubernetes_pty_allocates_terminal_and_uses_tty_attach(tmp_path, monkeypatch):
    calls = _KubernetesCalls()
    attached = {}
    request = dataclasses.replace(_request("hello\n"), mode="pty")

    def run_pty(argv, **options):
        attached.update({"argv": tuple(argv), **options})
        return 0, b"terminal output\r\n", b""

    monkeypatch.setattr(executor_kubernetes, "_kubectl", calls)
    monkeypatch.setattr(executor_kubernetes, "_run_pty", run_pty)
    result = tool_executor("kubernetes").execute(_context(tmp_path), request)

    container = calls.manifest["spec"]["containers"][0]
    assert container["tty"] is True
    assert (container["stdin"], container["stdinOnce"]) == (True, True)
    offset = attached["argv"].index("attach")
    assert attached["argv"][offset:offset + 3] == ("attach", "-i", "-t")
    assert attached["input"] == "hello\n"
    assert attached["stream"] is True
    assert (result.returncode, result.stdout) == (0, "received\n")


def test_stdin_declarations_reject_mutable_binary_buffers():
    with pytest.raises(SpecError, match="text, bytes"):
        command("reader", input=bytearray(b"mutable"))
