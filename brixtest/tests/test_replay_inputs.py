"""Exact rerun input, graph, and executable provenance contracts."""

import hashlib
import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from brixtest import SpecError, binary, case, get_case
from brixtest.cli.rerun import _replay
from brixtest.pytest_protocol import _replay_identity
from brixtest.runtime.binaries import BinaryStore, REPLAY_BINARIES_ENV
from brixtest.runtime.manager import CaseManager
from brixtest.runtime.replay import archive_replay_inputs


def _digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _archived_inputs(tmp_path):
    executable = tmp_path / "objects" / "tool"
    library = tmp_path / "objects" / "libtool.so"
    executable.parent.mkdir(parents=True)
    executable.write_bytes(b"#!/bin/sh\nexit 0\n")
    library.write_bytes(b"archived-library\x00")
    return executable, library


def _replay_manifest(executable, library):
    return {"tool": {
        "path": str(executable), "sha256": _digest(executable),
        "libraries": [{"path": str(library), "sha256": _digest(library)}],
    }}


def test_binary_store_recaptures_exact_archived_executable_and_libraries(
    tmp_path, monkeypatch,
):
    executable, library = _archived_inputs(tmp_path)
    manifest = _replay_manifest(executable, library)
    monkeypatch.setenv(REPLAY_BINARIES_ENV, json.dumps(manifest))
    declaration = binary("tool", "/original/build/tool", discover_libraries=False)

    captured = BinaryStore(tmp_path / "run", tmp_path).capture(declaration)

    assert captured.sha256 == manifest["tool"]["sha256"]
    assert captured.path.read_bytes() == executable.read_bytes()
    assert [item.read_bytes() for item in captured.libraries] == [library.read_bytes()]
    assert captured.overridden and captured.verify()


def test_binary_store_rejects_corrupted_archived_replay_input(tmp_path, monkeypatch):
    executable, library = _archived_inputs(tmp_path)
    manifest = _replay_manifest(executable, library)
    executable.write_bytes(b"changed after archival")
    monkeypatch.setenv(REPLAY_BINARIES_ENV, json.dumps(manifest))

    with pytest.raises(SpecError, match="archived executable"):
        BinaryStore(tmp_path / "run", tmp_path).capture(
            binary("tool", "/original/build/tool", discover_libraries=False),
        )


def test_binary_store_recaptures_archived_runtime_files(tmp_path, monkeypatch):
    executable, library = _archived_inputs(tmp_path)
    plugin = tmp_path / "objects" / "db2.so"
    plugin.write_bytes(b"archived-plugin")
    manifest = _replay_manifest(executable, library)
    manifest["tool"]["runtime_files"] = [{
        "destination": "/usr/lib/krb5/plugins/db2.so",
        "path": str(plugin), "sha256": _digest(plugin),
    }]
    monkeypatch.setenv(REPLAY_BINARIES_ENV, json.dumps(manifest))

    captured = BinaryStore(tmp_path / "run", tmp_path).capture(
        binary("tool", "/original/tool", discover_libraries=False),
    )

    assert captured.runtime_files["/usr/lib/krb5/plugins/db2.so"].read_bytes() == b"archived-plugin"
    assert captured.verify()


def test_replay_graph_mismatch_fails_before_run_root_creation(tmp_path, monkeypatch):
    @case(keep="never")
    def managed(run):
        pass

    root = tmp_path / "not-created"
    monkeypatch.setenv("BRIXTEST_REPLAY_GRAPH_FINGERPRINT", "0" * 64)
    with pytest.raises(SpecError, match="archived fingerprint"):
        CaseManager(get_case(managed), "unit::graph-mismatch", root=root)
    assert not root.exists()


def test_replay_identity_and_cli_transport_use_session_objects(tmp_path, monkeypatch):
    executable, library = _archived_inputs(tmp_path)
    payload = _helper_payload(tmp_path, executable, library)
    replay = {
        "argv": ["pytest", "test_x.py::test_x"], "cwd": str(tmp_path),
        **_replay_identity(payload, tmp_path),
    }
    seen = {}
    monkeypatch.setattr(
        "brixtest.cli.rerun.subprocess.call",
        lambda argv, **options: seen.update(argv=argv, **options) or 0,
    )

    assert _replay({"nodeid": "test_x.py::test_x", "replay": replay}) == 0
    transported = json.loads(seen["env"][REPLAY_BINARIES_ENV])
    assert transported["tool"]["path"] == str(executable)
    assert transported["tool"]["libraries"][0]["path"] == str(library)
    assert transported["tool"]["runtime_files"][0]["destination"] == "/etc/tool/runtime.conf"
    assert seen["env"]["BRIXTEST_REPLAY_GRAPH_FINGERPRINT"] == "f" * 64


def _helper_payload(session, executable, library):
    def row(path, role):
        return {
            "object": str(path.relative_to(session)), "role": role,
            "sha256": _digest(path),
        }

    runtime = session / "objects" / "runtime.conf"
    runtime.write_text("immutable runtime\n")
    return {"evidence": {
        "artifacts": [
            row(executable, "replay-binary:tool"),
            row(library, "replay-library:tool"),
            row(runtime, "replay-runtime:tool:%2Fetc%2Ftool%2Fruntime.conf"),
        ],
        "provenance": {"extra": {
            "resource_graph": {"fingerprint": "f" * 64},
        }},
    }}


def test_replay_archive_assigns_executable_and_library_roles(tmp_path):
    executable, library = _archived_inputs(tmp_path)
    runtime = tmp_path / "objects" / "runtime.conf"
    runtime.write_text("runtime\n")
    calls = []
    manager = SimpleNamespace(
        binary_store=SimpleNamespace(_captured={
            "tool": SimpleNamespace(
                path=executable, libraries=(library,), sha256=_digest(executable),
                runtime_files={"/etc/tool/runtime.conf": runtime},
            ),
        }),
        evidence=SimpleNamespace(attach=lambda path, **metadata: calls.append(
            (path, metadata),
        )),
    )

    archive_replay_inputs(manager)

    assert [row[1]["role"] for row in calls] == [
        "replay-binary:tool", "replay-library:tool",
        "replay-runtime:tool:%2Fetc%2Ftool%2Fruntime.conf",
    ]
