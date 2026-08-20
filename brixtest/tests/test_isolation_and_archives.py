"""Success, error, and security contracts for the expanded runtime surface."""

import json
import sqlite3
import zlib
from argparse import Namespace

import pytest
from brixtest.archive import (
    archive_case_logs,
    post_search_archive,
    write_bulk_archive,
    write_sqlite_archive,
)
from brixtest.cli.rerun import run_command as rerun
from brixtest.errors import SpecError
from brixtest.isolation import Isolation, build_launch
from brixtest.runtime.manager import CaseManager

from brixtest import binary, case, client, docker, nsenter, podman, runc


def _launch(tmp_path, isolation):
    control = tmp_path / (isolation.kind + "-control")
    control.mkdir()
    return build_launch(
        isolation, ["/host/python", "-m", "pytest", "test_x.py"],
        {"BRIXTEST_HELPER": "1", "BRIXTEST_TEST_ENV_KEYS_JSON": "[]"},
        cwd=tmp_path, readonly_roots=(tmp_path,), writable_root=tmp_path,
        control_dir=control, validate_executable=False,
    )


def test_all_isolation_backends_build_shell_free_commands(tmp_path):
    digest = "example.test/brixtest@sha256:" + "a" * 64
    docker_launch = _launch(tmp_path, docker(digest))
    podman_launch = _launch(tmp_path, podman(digest))
    namespace_launch = _launch(tmp_path, nsenter(42, namespaces=("mount", "net")))
    assert docker_launch.argv[0] == "docker" and "--env-file" in docker_launch.argv
    assert "--user" in docker_launch.argv
    assert podman_launch.argv[0] == "podman" and digest in podman_launch.argv
    assert namespace_launch.argv[:3] == ("nsenter", "--target", "42")
    assert "--brixtest-nsenter-namespace" in nsenter(
        42, namespaces=("mount", "net")
    ).cli_args()
    assert all(isinstance(value, str) for value in docker_launch.argv)


def test_runc_derives_a_private_oci_config(tmp_path):
    bundle = tmp_path / "bundle"
    (bundle / "rootfs").mkdir(parents=True)
    (bundle / "config.json").write_text(json.dumps({
        "ociVersion": "1.0.2", "root": {"path": "rootfs"},
        "process": {"args": ["true"], "cwd": "/", "env": ["PATH=/bin"]},
        "linux": {"namespaces": [
            {"type": name} for name in ("mount", "pid", "uts", "ipc", "network")
        ]},
        "mounts": [],
    }))
    launch = _launch(tmp_path, runc(bundle))
    derived = tmp_path / "runc-control" / "oci-bundle" / "config.json"
    spec = json.loads(derived.read_text())
    assert launch.argv[0] == "runc"
    assert spec["process"]["args"][:3] == ["python3", "-m", "pytest"]
    assert "PATH=/bin" in spec["process"]["env"]
    assert spec["root"]["path"] == str((bundle / "rootfs").resolve())
    assert spec["root"]["readonly"] is True
    assert spec["process"]["noNewPrivileges"] is True
    assert all(not values for values in spec["process"]["capabilities"].values())


def test_runc_refuses_bundle_that_shares_host_namespaces(tmp_path):
    bundle = tmp_path / "unsafe-bundle"
    (bundle / "rootfs").mkdir(parents=True)
    (bundle / "config.json").write_text(json.dumps({
        "ociVersion": "1.0.2", "root": {"path": "rootfs"},
        "process": {"args": ["true"], "cwd": "/", "env": []},
        "linux": {"namespaces": [{"type": "mount"}]}, "mounts": [],
    }))
    with pytest.raises(SpecError, match="must isolate"):
        _launch(tmp_path, runc(bundle))


def test_isolation_rejects_ambiguous_or_privilege_bypassing_specs(tmp_path):
    with pytest.raises(SpecError, match="digest pinned"):
        docker("latest")
    with pytest.raises(SpecError, match="framework-owned"):
        podman("latest", allow_mutable=True, extra_args=("--mount=/etc:/host",))
    with pytest.raises(SpecError, match="positive PID"):
        nsenter(0)
    with pytest.raises(SpecError, match="bundle"):
        Isolation(kind="runc")


@pytest.mark.parametrize("argument", ["--cap-add=SYS_ADMIN", "--device=/dev/mem", "-p8080:80"])
def test_container_isolation_args_cannot_escape_helper_boundaries(argument):
    with pytest.raises(SpecError, match="framework-owned privilege"):
        docker("example/helper:dev", allow_mutable=True, extra_args=(argument,))


def test_binary_and_client_env_overrides_are_captured_once(tmp_path, monkeypatch):
    original = tmp_path / "original"
    replacement = tmp_path / "replacement"
    original.write_text("#!/bin/sh\nprintf original")
    replacement.write_text("#!/bin/sh\nprintf '%s' \"$SUITE_VALUE\"")
    original.chmod(0o700)
    replacement.chmod(0o700)
    tool = binary("tool", original, discover_libraries=False)
    command = client("command", command=[tool])

    @case(clients=[command], binaries=[tool], keep="never")
    def declared(run):
        pass

    session = tmp_path / "session"
    monkeypatch.setenv("BRIXTEST_METRICS_SESSION", str(session))
    monkeypatch.setenv("BRIXTEST_BINARY_OVERRIDES_JSON", json.dumps({"tool": str(replacement)}))
    monkeypatch.setenv("BRIXTEST_CLIENT_ENV_JSON", json.dumps({"SUITE_VALUE": "replacement"}))
    manager = CaseManager(declared.__brixtest_case__, "test_override", root=tmp_path / "run")
    run = manager.start()
    captured = run.binary(tool)
    assert run.client(command).run().stdout == "replacement"
    assert captured.path != replacement and captured.source == replacement
    assert captured.overridden is True
    manager.set_outcome("passed")
    manager.close()
    assert not manager.root.exists()
    assert list((session / "logs").rglob("*.stdout.log"))


def test_logs_sqlite_bulk_and_symlink_confinement(tmp_path):
    session = tmp_path / "session"
    run = tmp_path / "run"
    logs = run / "runtime" / "logs"
    logs.mkdir(parents=True)
    (logs / "server.log").write_text("server output\n")
    outside = tmp_path / "secret.log"
    outside.write_text("do not archive")
    (logs / "escape.log").symlink_to(outside)
    helper = tmp_path / "helper.log"
    helper.write_text("helper output\n")
    rows = archive_case_logs(session, "tests/test_x.py::test_x", run, helper_log=helper)
    assert {row["name"] for row in rows} == {"server.log", "helper.log"}
    payload = {
        "session_id": "s1", "generated_at": "now", "exitstatus": 1,
        "tests": [{
            "nodeid": "tests/test_x.py::test_x", "outcome": "failed",
            "backend": "local", "isolation": "process", "wall_seconds": 1.0,
            "error": "boom", "logs": rows, "replay": {"argv": ["secret"]},
            "metrics": {"samples": [{"name": "x", "value": 1, "unit": "s",
                                      "kind": "gauge", "labels": {}, "at_seconds": 0}]},
        }],
    }
    database = write_sqlite_archive(payload, session, tmp_path / "archive.sqlite3")
    connection = sqlite3.connect(str(database))
    try:
        content, encoding = connection.execute("SELECT content, encoding FROM logs LIMIT 1").fetchone()
        assert encoding == "zlib" and zlib.decompress(content)
        assert connection.execute("SELECT count(*) FROM metrics").fetchone()[0] == 1
    finally:
        connection.close()
    bulk = write_bulk_archive(payload, session, tmp_path / "archive.ndjson")
    text = bulk.read_text()
    assert "brixtest-tests" in text and "brixtest-logs" in text
    assert '"replay"' not in text and "do not archive" not in text


def test_rerun_replays_an_exact_record(tmp_path):
    runs = tmp_path / "runs"
    session = runs / "metrics" / "s1"
    session.mkdir(parents=True)
    sentinel = tmp_path / "replayed"
    (session / "session.json").write_text(json.dumps({
        "session_id": "s1", "generated_at": "now", "tests": [{
            "nodeid": "test_x.py::test_x", "outcome": "failed",
            "replay": {"argv": ["/bin/sh", "-c", "printf done > replayed"],
                       "cwd": str(tmp_path)},
        }],
    }))
    args = Namespace(runs=str(runs), session="s1", test=None, all=False)
    assert rerun(args) == 0
    assert sentinel.read_text() == "done"


def test_search_archive_uses_bulk_api_without_exporting_replay(tmp_path, monkeypatch):
    captured = {}

    class Response:
        def __enter__(self):
            return self

        def __exit__(self, *args):
            return None

        def read(self):
            return b'{"errors":false}'

    def open_request(request, timeout):
        captured["url"] = request.full_url
        captured["body"] = request.data.decode()
        captured["auth"] = request.get_header("Authorization")
        assert timeout == 30
        return Response()

    monkeypatch.setattr("brixtest.archive.urllib.request.urlopen", open_request)
    monkeypatch.setenv("BRIXTEST_SEARCH_BEARER_TOKEN", "controller-secret")
    payload = {
        "session_id": "s1", "tests": [{
            "nodeid": "test_x", "outcome": "failed", "logs": [],
            "replay": {"argv": ["must-not-export"]}, "metrics": {"samples": []},
        }],
    }
    post_search_archive(payload, tmp_path, "https://search.example", index="brixtest-ci")
    assert captured["url"] == "https://search.example/_bulk"
    assert captured["auth"] == "Bearer controller-secret"
    assert "must-not-export" not in captured["body"]
