"""Credential replay launchers retain runtime preparation and process isolation."""

import ast
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock

import pytest


def _functions(namespace):
    path = Path(__file__).parent / "cmdscripts/user_backend_cred_part2.py"
    tree = ast.parse(path.read_text(), filename=str(path))
    names = {"_base_assert_replay", "_base_check_journal_replay"}
    selected = [node for node in tree.body
                if isinstance(node, ast.FunctionDef) and node.name in names]
    assert len(selected) == 2
    exec(compile(ast.Module(body=selected, type_ignores=[]), str(path), "exec"),
         namespace)
    return namespace


@pytest.fixture(params=["_base_assert_replay", "_base_check_journal_replay"])
def launcher(request, tmp_path):
    prepare = Mock(return_value=["prepared-nginx", "prepared-config"])
    run = SimpleNamespace(nginx=tmp_path / "nginx", _prepare_command=prepare)
    front = tmp_path / "front"
    config = front / "nginx.conf"
    state = SimpleNamespace(run=run, front=front, suite=Mock(),
                            front_port=123, origin_port=456)
    process = SimpleNamespace(run=Mock(), PIPE=object())
    namespace = _functions({
        "subprocess": process, "PROXY_STD": "fixture-proxy",
        "_truncate": Mock(), "_base_front_conf": Mock(return_value=config),
        "_base_values": Mock(return_value=(
            run, state.suite, tmp_path / "origin", front, tmp_path / "creds",
            None, None, tmp_path / "origin.log", tmp_path / "front.log",
            "fixture-url", tmp_path / "payload", tmp_path / "credential")),
    })
    arguments = (state,)
    if request.param == "_base_check_journal_replay":
        arguments = (state, config, [tmp_path / "record.req"])
    return SimpleNamespace(call=namespace[request.param], arguments=arguments,
                           process=process, prepare=prepare,
                           original=[str(run.nginx), "-p", str(front),
                                     "-c", str(config)])


def test_prepared_command_reaches_an_isolated_captured_launch(launcher):
    launcher.process.run.side_effect = RuntimeError("captured launch boundary")
    with pytest.raises(RuntimeError, match="captured launch boundary"):
        launcher.call(*launcher.arguments)
    launcher.prepare.assert_called_once_with(launcher.original, cwd=None)
    launcher.process.run.assert_called_once_with(
        launcher.prepare.return_value, start_new_session=True,
        stdout=launcher.process.PIPE, stderr=launcher.process.PIPE, text=True)


def test_preparation_failure_prevents_launch(launcher):
    launcher.prepare.side_effect = ValueError("invalid runtime configuration")
    with pytest.raises(ValueError, match="invalid runtime configuration"):
        launcher.call(*launcher.arguments)
    launcher.process.run.assert_not_called()


def test_launch_error_propagates_after_preparation(launcher):
    failure = OSError("executable unavailable")
    launcher.process.run.side_effect = failure
    with pytest.raises(OSError) as raised:
        launcher.call(*launcher.arguments)
    assert raised.value is failure
    launcher.prepare.assert_called_once_with(launcher.original, cwd=None)
