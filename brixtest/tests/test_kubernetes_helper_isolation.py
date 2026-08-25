"""Contracts for bundled pytest helpers executed as Kubernetes Jobs."""

import base64
import json
import subprocess
import sys
import zipfile
from pathlib import Path
from types import SimpleNamespace

import pytest

from brixtest import SpecError, host_mapping, kubernetes
from brixtest.helper_bundle import archive_helper_bundle, build_helper_bundle
from brixtest.helper_transport import FrameDecoder, HelperMessage, apply_message
from brixtest.isolation import build_launch
from brixtest.kubernetes_helper_bridge import _stream_test, _use_minikube_image
from brixtest.kubernetes_helper_manifest import helper_resources

_DIGEST = "registry.test/python@sha256:" + "a" * 64


def test_kubernetes_factory_is_digest_pinned_and_replayable():
    selected = kubernetes(
        _DIGEST, context="minikube", namespace="tests", service_account="runner",
        python="/usr/local/bin/python",
    )
    assert (
        selected.kind, selected.context, selected.namespace, selected.service_account,
    ) == ("kubernetes", "minikube", "tests", "runner")
    assert selected.cli_args() == [
        "--brixtest-isolation", "kubernetes",
        "--brixtest-isolation-image", _DIGEST,
        "--brixtest-container-python", "/usr/local/bin/python",
        "--brixtest-kubernetes-context", "minikube",
        "--brixtest-kubernetes-namespace", "tests",
        "--brixtest-kubernetes-service-account", "runner",
    ]


@pytest.mark.parametrize("operation", [
    lambda: kubernetes("python:latest"),
    lambda: kubernetes(_DIGEST, namespace="Bad_Name"),
    lambda: kubernetes(_DIGEST, service_account=""),
])
def test_kubernetes_factory_rejects_ambiguous_or_unsafe_identity(operation):
    with pytest.raises(SpecError):
        operation()


def test_helper_manifest_uses_secret_environment_and_restricted_job():
    selected = kubernetes(_DIGEST, namespace="tests", service_account="runner")
    resources = helper_resources(
        selected, job="brixtest-unit", secret="brixtest-unit-env",
        environment={"TOKEN": "controller-secret", "MULTILINE": "a\nb"},
        host_aliases=(host_mapping(
            "origin", "origin.test", address="192.0.2.10", libc=True,
            targets=("test",),
        ),),
    )
    secret, job = resources["items"]
    assert base64.b64decode(secret["data"]["TOKEN"]) == b"controller-secret"
    assert "controller-secret" not in json.dumps(resources)
    spec = job["spec"]["template"]["spec"]
    container = spec["containers"][0]
    assert spec["serviceAccountName"] == "runner"
    assert spec["restartPolicy"] == "Never" and job["spec"]["backoffLimit"] == 0
    assert container["securityContext"] == {
        "allowPrivilegeEscalation": False,
        "capabilities": {"drop": ["ALL"]},
        "readOnlyRootFilesystem": True,
    }
    assert spec["hostAliases"] == [{"ip": "192.0.2.10", "hostnames": ["origin.test"]}]


def test_content_addressed_helper_bundle_is_stable_and_confined(tmp_path, monkeypatch):
    project = tmp_path / "project"
    tests = project / "tests"
    tests.mkdir(parents=True)
    (project / "pytest.ini").write_text("[pytest]\n")
    (project / "k8s").mkdir()
    (project / "k8s" / "cluster.json").write_text('{"profile":"unit"}\n')
    (tests / "conftest.py").write_text("VALUE = 1\n")
    (tests / "test_remote.py").write_text("def test_remote(): assert True\n")
    package_file = Path(__file__).resolve().parents[1] / "src" / "brixtest" / "__init__.py"
    monkeypatch.setattr(
        "brixtest.helper_bundle._runtime_files",
        lambda modules: {"opt/brixtest/python/brixtest/__init__.py": package_file},
    )
    monkeypatch.setattr("brixtest.helper_bundle._runtime_tools", lambda: {})
    first = build_helper_bundle(project, "tests/test_remote.py::test_remote", tmp_path / "out")
    second = build_helper_bundle(project, "tests/test_remote.py::test_remote", tmp_path / "out")
    assert first == second and first.path.name.endswith(first.fingerprint + ".zip")
    with zipfile.ZipFile(first.path) as archive:
        names = set(archive.namelist())
        manifest = json.loads(archive.read("opt/brixtest/bundle.json"))
    assert {
        "workspace/pytest.ini", "workspace/tests/conftest.py",
        "workspace/tests/test_remote.py", "opt/brixtest/python/brixtest/__init__.py",
        "workspace/k8s/cluster.json",
    } <= names
    assert manifest["fingerprint"] == first.fingerprint
    assert all(not name.startswith("/") and ".." not in Path(name).parts for name in names)
    archived = archive_helper_bundle(first.as_dict(), tmp_path / "session")
    assert Path(tmp_path / "session" / archived["object"]).read_bytes() == first.path.read_bytes()
    assert archived["fingerprint"] == first.fingerprint and archived["sha256"] == first.sha256


def test_framed_transport_preserves_arbitrary_output_and_projects_messages(tmp_path):
    heartbeat = tmp_path / "heartbeat.json"
    result = tmp_path / "result.json"
    messages = []
    decoder = FrameDecoder(messages.append)
    frame = HelperMessage("result", {"outcome": "failed", "traceback": "full"}).frame()
    observed = decoder.feed(b"ordinary-prefix" + frame[:7])
    observed += decoder.feed(frame[7:] + b"ordinary-suffix") + decoder.close()
    assert observed == b"ordinary-prefixordinary-suffix"
    assert len(messages) == 1
    apply_message(messages[0], heartbeat=heartbeat, result=result)
    assert json.loads(result.read_text()) == {"outcome": "failed", "traceback": "full"}


def test_bridge_streams_partial_output_and_decodes_live_result(tmp_path, capsys):
    heartbeat = tmp_path / "heartbeat.json"
    result = tmp_path / "result.json"
    journal = tmp_path / "messages.ndjson"
    frames = (
        HelperMessage("heartbeat", {"time": 1}).frame()
        + HelperMessage("result", {"outcome": "failed", "longrepr": "trace"}).frame()
    )
    script = "import os;os.write(1,b'partial\\n'+%r);raise SystemExit(7)" % frames
    code = _stream_test(
        [sys.executable, "-c", script], heartbeat=heartbeat,
        result=result, journal=journal,
    )
    assert code == 7 and capsys.readouterr().out == "partial\n"
    assert json.loads(result.read_text())["longrepr"] == "trace"
    assert json.loads(heartbeat.read_text())["payload"] == {"time": 1}


def test_launch_builds_private_bridge_spec_without_secret_argv(tmp_path, monkeypatch):
    bundle_path = tmp_path / "bundle.zip"
    bundle_path.write_bytes(b"zip")
    fake = SimpleNamespace(
        path=bundle_path,
        as_dict=lambda: {"path": str(bundle_path), "sha256": "a" * 64},
    )
    monkeypatch.setattr("brixtest.isolation_launch.build_helper_bundle", lambda *a, **k: fake)
    root = tmp_path / "project"
    root.mkdir()
    (root / "test_remote.py").write_text("def test_remote(): pass\n")
    control = tmp_path / "control"
    control.mkdir()
    run = tmp_path / "run"
    session = tmp_path / "session"
    environment = {
        "BRIXTEST_HELPER": "1", "BRIXTEST_HELPER_RESULT": str(control / "result.json"),
        "BRIXTEST_CASE_RUN": str(run), "BRIXTEST_METRICS_SESSION": str(session),
        "BRIXTEST_HELPER_HEARTBEAT": str(control / "heartbeat.json"),
        "BRIXTEST_HELPER_CANCEL": str(control / "cancel.json"),
        "BRIXTEST_TEST_ENV_KEYS_JSON": '["TOKEN"]', "TOKEN": "secret-value",
    }
    launch = build_launch(
        kubernetes(_DIGEST, context="minikube", namespace="tests", service_account="runner"),
        [sys.executable, "-m", "pytest", "test_remote.py::test_remote"], environment,
        cwd=root, readonly_roots=(root,), writable_root=tmp_path,
        control_dir=control, validate_executable=False,
    )
    assert launch.argv[1:3] == ("-m", "brixtest.kubernetes_helper_bridge")
    assert "secret-value" not in " ".join(launch.argv)
    spec = json.loads(Path(launch.argv[-1]).read_text())
    manifest = json.loads(Path(spec["manifest"]).read_text())
    assert spec["pytest"][:2] == ["-m", "pytest"]
    assert spec["run"] == str(run) and spec["bundle_identity"]["sha256"] == "a" * 64
    assert base64.b64decode(manifest["items"][0]["data"]["TOKEN"]) == b"secret-value"
    assert launch.cleanup[0][0:3] == ("kubectl", "--context", "minikube")


def _image_manifest(path):
    path.write_text(json.dumps({
        "items": [{"kind": "Secret"}, {"kind": "Job", "spec": {
            "template": {"spec": {"containers": [{
                "image": _DIGEST, "imagePullPolicy": "IfNotPresent",
            }]}}
        }}],
    }))


def test_verified_local_runtime_is_loaded_into_minikube_without_pulling(tmp_path, monkeypatch):
    manifest = tmp_path / "manifest.json"
    _image_manifest(manifest)
    commands = []

    def run(command, **_options):
        if "status" in command:
            output = b'{"Host":"Running","APIServer":"Running"}'
        else:
            output = json.dumps([{"Id": "sha256:%s" % ("a" * 64)}]).encode()
        return subprocess.CompletedProcess(command, 0, output)

    monkeypatch.setattr("brixtest.kubernetes_helper_bridge._run", run)
    monkeypatch.setattr(
        "brixtest.kubernetes_helper_bridge._checked",
        lambda command, action, **options: commands.append(command) or b"",
    )
    _use_minikube_image({
        "minikube": "/usr/bin/minikube", "docker": "/usr/bin/docker",
        "context": "brixtest", "image": _DIGEST, "manifest": str(manifest),
    })
    container = json.loads(manifest.read_text())["items"][1]["spec"]["template"]["spec"]["containers"][0]
    assert container["image"] == "brixtest.local/helper-runtime:sha256-%s" % ("a" * 64)
    assert container["imagePullPolicy"] == "Never"
    assert commands[0][:2] == ["/usr/bin/docker", "tag"]
    assert commands[1][:4] == ["/usr/bin/minikube", "-p", "brixtest", "image"]


def test_unverified_local_image_is_never_substituted(tmp_path, monkeypatch):
    manifest = tmp_path / "manifest.json"
    _image_manifest(manifest)

    def run(command, **_options):
        output = b'{"Host":"Running","APIServer":"Running"}' if "status" in command \
            else b'[{"Id":"sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"}]'
        return subprocess.CompletedProcess(command, 0, output)

    monkeypatch.setattr("brixtest.kubernetes_helper_bridge._run", run)
    _use_minikube_image({
        "minikube": "minikube", "docker": "docker", "context": "brixtest",
        "image": _DIGEST, "manifest": str(manifest),
    })
    container = json.loads(manifest.read_text())["items"][1]["spec"]["template"]["spec"]["containers"][0]
    assert container == {"image": _DIGEST, "imagePullPolicy": "IfNotPresent"}
