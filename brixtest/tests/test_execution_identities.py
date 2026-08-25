"""Identity enforcement contracts for client/tool executor boundaries."""

import pytest

from brixtest import (
    CommandResult,
    Placement,
    ToolExecutionContext,
    ToolExecutionRequest,
    case,
    client,
    identity,
)
from brixtest.errors import SpecError
from brixtest.runtime.executors import tool_executor
from brixtest.runtime.manager import CaseManager


def _definition(*resources):
    @case(*resources, observe=(), keep="always")
    def declared(run):
        return None

    return declared.__brixtest_case__


def _request(placement):
    return ToolExecutionRequest(
        "identity", ("id",), {}, None, 5.0, None, (0,), 4096,
        "capture", 0, "utf-8", True, placement,
    )


def test_local_client_identity_is_enforced_by_public_executor(tmp_path, monkeypatch):
    observed = {}
    runner = identity("runner", uid=1200, gid=1300, groups=(1400,))
    actor = client("identity", command=("id",), placement=Placement(identity=runner))

    def completed(self, *argv, **options):
        observed["argv"] = tuple(argv)
        return CommandResult(tuple(argv), 0, "uid=1200\n", "", 0.01)

    monkeypatch.setattr("brixtest.clients.configured.CommandRunner.run", completed)
    monkeypatch.setattr(
        "brixtest.runtime.launcher_identity.shutil.which", lambda name: "/usr/bin/setpriv",
    )
    manager = CaseManager(
        _definition(runner, actor), "identity::client", root=tmp_path / "run",
    )
    run = manager.start()
    result = run.client(actor).run()

    assert result.argv == ("id",) and result.stdout == "uid=1200\n"
    assert observed["argv"][:2] == ("setpriv", "--no-new-privs")
    assert observed["argv"][observed["argv"].index("--groups") + 1] == "1400"
    manager.close()


def test_executor_rejects_identity_missing_from_context(tmp_path):
    runner = identity("runner", uid=1200, gid=1300)
    request = _request(Placement(identity=runner))
    context = ToolExecutionContext(
        "identity::missing", tmp_path, tmp_path, "local",
        local_execute=lambda value: pytest.fail("identity must fail before execution"),
    )
    with pytest.raises(SpecError, match="not available in this execution context"):
        tool_executor("local").execute(context, request)


def test_context_rejects_mismatched_identity_catalog_key(tmp_path):
    runner = identity("runner")
    with pytest.raises(SpecError, match="map each declared identity name"):
        ToolExecutionContext(
            "identity::catalog", tmp_path, tmp_path, "local",
            identities={"different": runner},
        )
