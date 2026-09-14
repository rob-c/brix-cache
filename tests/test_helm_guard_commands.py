"""Offline subprocess contracts for the optional Helm rendering guard."""

from pathlib import Path
import subprocess

import pytest

import test_k8s_gridftp_gateway_guard as guard


_INCLUDE = "include /usr/share/nginx/modules/*.conf;"
_STREAM = "stream " + "{"
_RENDERED = _INCLUDE + "\n" + _STREAM


def _responses(monkeypatch, outcomes):
    remaining = iter(outcomes)
    calls = []

    def run(command, **kwargs):
        calls.append(command)
        chart = Path(command[-1])
        assert all((chart.parent / name / "Chart.yaml").is_file()
                   for name in ("brix-common", "topology-role", "gridftp-interop"))
        assert chart != guard.GRIDFTP_CHART
        if command[1:3] == ["dependency", "build"]:
            (chart / "Chart.lock").write_text("private dependency write\n")
        return subprocess.CompletedProcess(command, *next(remaining))

    monkeypatch.setattr(guard.subprocess, "run", run)
    return calls


def test_helm_guard_renders_private_chart_without_mutating_source(monkeypatch, tmp_path):
    lock = guard.GRIDFTP_CHART / "Chart.lock"
    before = lock.read_bytes()
    calls = _responses(monkeypatch, [(0, "", ""), (0, _RENDERED, "")])
    guard.test_helm_render_puts_module_include_before_stream_block(tmp_path)
    assert [command[1] for command in calls] == ["dependency", "template"]
    assert Path(calls[0][-1]) == tmp_path / "charts/gridftp-interop"
    assert lock.read_bytes() == before
    assert (Path(calls[0][-1]) / "Chart.lock").read_text() == "private dependency write\n"


@pytest.mark.parametrize("outcomes, message, expected_calls", [
    ([(1, "", "stale lock")], "helm dependency build failed: stale lock", 1),
    ([(0, "", ""), (1, "", "render error")], "helm template failed: render error", 2),
    ([(0, "", ""), (0, _STREAM, "")], "missing the module include", 2),
    ([(0, "", ""), (0, _INCLUDE, "")], "module include must precede", 2),
    ([(0, "", ""), (0, _STREAM + "\n" + _INCLUDE, "")],
     "module include must precede", 2),
], ids=["dependency-error", "render-error", "missing-include", "missing-stream", "wrong-order"])
def test_helm_guard_rejects_failed_preparation_and_invalid_render(
        monkeypatch, tmp_path, outcomes, message, expected_calls):
    lock = guard.GRIDFTP_CHART / "Chart.lock"
    before = lock.read_bytes()
    calls = _responses(monkeypatch, outcomes)
    with pytest.raises(AssertionError, match=message):
        guard.test_helm_render_puts_module_include_before_stream_block(tmp_path)
    assert len(calls) == expected_calls
    assert lock.read_bytes() == before
