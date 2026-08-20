"""Content-first configs, convenience IO, and managed-code containment."""

import hashlib
import json
import os
import sqlite3
import subprocess
import sys
from pathlib import Path

import pytest

from brixtest import (
    binary,
    case,
    load_template,
    server,
    server_config,
    text_artifact,
)
from brixtest.config.material import identity, material
from brixtest.errors import SpecError
from brixtest.runtime.artifacts import ArtifactStore
from brixtest.runtime.commands import CommandRunner
from brixtest.runtime.configs import ConfigStore
from brixtest.test_policy import TestPolicyError as PolicyError, _stdlib, enforce
from brixtest.topology.model import derive, pool_key


def _definition(item):
    @case(servers=[item], observe=[])
    def declared(run):
        pass

    return declared.__brixtest_case__


def test_supported_python_versions_recognize_stdlib_extension_modules():
    assert "zlib" in _stdlib()


def test_pure_python_collection_imports_can_be_explicitly_trusted(tmp_path):
    path = tmp_path / "test_trusted.py"
    path.write_text(
        "import hypothesis\nfrom brixtest import case\n"
        "@case()\ndef test_managed(run): pass\n"
    )
    with pytest.raises(PolicyError, match="hypothesis"):
        enforce(path)
    enforce(path, allowed_imports=("hypothesis",))


def test_native_client_import_cannot_be_added_to_the_collection_allowlist(tmp_path):
    path = tmp_path / "test_native.py"
    path.write_text(
        "import XRootD\nfrom brixtest import case\n"
        "@case()\ndef test_managed(run): pass\n"
    )
    with pytest.raises(PolicyError, match="cannot include native clients"):
        enforce(path, allowed_imports=("XRootD",))


def _run_pytest(tmp_path: Path, source_text: str, **extra_env: str):
    case_file = tmp_path / "test_sample.py"
    case_file.write_text(source_text)
    source = Path(__file__).resolve().parents[1] / "src"
    env = dict(os.environ)
    for name in tuple(env):
        if name.startswith("BRIXTEST_"):
            env.pop(name)
    env.update({
        "PYTHONPATH": str(source),
        "PYTEST_DISABLE_PLUGIN_AUTOLOAD": "1",
        "PYTHONPYCACHEPREFIX": str(tmp_path / "pycache"),
        "BRIXTEST_RUNS": str(tmp_path / "runs"),
    })
    env.update(extra_env)
    return subprocess.run(
        [sys.executable, "-m", "pytest", str(case_file),
         "-p", "brixtest.pytest_plugin", "-q"],
        cwd=tmp_path, env=env, capture_output=True, text=True,
        timeout=40, check=False,
    )


def test_inline_server_config_preserves_supplied_text_and_filename(tmp_path):
    declaration = server_config(
        "listen={port}\nmessage=hello\n", filename="daemon.conf",
    )
    item = server("daemon", command=["daemon", "{config}"], config=declaration)
    captured = ConfigStore(tmp_path / "captured", tmp_path).capture(
        item, {"port": 41234},
    )
    assert captured.source is None
    assert captured.filename == "daemon.conf"
    assert captured.snapshot.read_text() == "listen={port}\nmessage=hello\n"
    assert captured.rendered.read_text() == "listen=41234\nmessage=hello\n"
    assert captured.source_sha256 == hashlib.sha256(
        captured.snapshot.read_bytes()
    ).hexdigest()
    assert captured.sha256 == hashlib.sha256(captured.rendered.read_bytes()).hexdigest()


def test_template_fill_completes_user_fields_before_runtime_fields(tmp_path):
    path = tmp_path / "origin.conf.in"
    path.write_text("mode={mode}\nlisten={host}:{port}\n")
    config = load_template(path).fill(filename="origin.conf", mode="production")
    selected = material(config, tmp_path)
    assert selected.source_text == "mode={mode}\nlisten={host}:{port}\n"
    assert selected.declared_text == "mode=production\nlisten={host}:{port}\n"
    assert identity(config, tmp_path)["declared_sha256"] == selected.declared_sha256


def test_template_fill_rejects_misspelled_fields(tmp_path):
    path = tmp_path / "origin.conf.in"
    path.write_text("listen={port}\n")
    with pytest.raises(SpecError, match="does not name a placeholder"):
        material(load_template(path).fill(prot=8080), tmp_path)


def test_template_fill_rejects_executable_value_objects(tmp_path):
    path = tmp_path / "origin.conf.in"
    path.write_text("listen={value}\n")
    with pytest.raises(SpecError, match="values must be"):
        load_template(path).fill(value=object())


def test_identical_effective_template_content_has_one_pool(tmp_path):
    first = tmp_path / "first.in"
    second = tmp_path / "second.in"
    first.write_text("mode={mode}\nlisten={port}\n")
    second.write_text("mode=production\nlisten={port}\n")
    left = server(
        "origin", command=["daemon", "{config}"],
        config=load_template(first).fill(filename="origin.conf", mode="production"),
        scope="session",
    )
    right = server(
        "origin", command=["daemon", "{config}"],
        config=load_template(second).fill(filename="origin.conf"), scope="session",
    )
    left_definition = _definition(left)
    right_definition = _definition(right)
    assert pool_key(left_definition) == pool_key(right_definition)
    plans = derive([("test_a", left_definition), ("test_b", right_definition)])
    assert len(plans) == 1 and plans[0].tests == ("test_a", "test_b")


def test_different_effective_template_content_uses_different_pools(tmp_path):
    path = tmp_path / "origin.in"
    path.write_text("mode={mode}\nlisten={port}\n")
    first = server(
        "origin", command=["daemon", "{config}"],
        config=load_template(path).fill(mode="one"), scope="session",
    )
    second = server(
        "origin", command=["daemon", "{config}"],
        config=load_template(path).fill(mode="two"), scope="session",
    )
    assert pool_key(_definition(first)) != pool_key(_definition(second))


def test_binary_plus_args_is_the_concise_server_launch_surface():
    executable = binary("daemon_bin", sys.executable)
    item = server(
        "daemon", binary=executable, args=["-m", "http.server", "{port}"],
        config=server_config("unused\n"),
    )
    assert item.command == (executable, "-m", "http.server", "{port}")
    with pytest.raises(SpecError, match=r"command or binary\+args"):
        server(
            "bad", command=["daemon"], binary=executable,
            config=server_config("unused\n"),
        )
    with pytest.raises(SpecError, match="argv sequence"):
        server(
            "bad_args", binary=executable, args="--serve",
            config=server_config("unused\n"),
        )


def test_command_runner_returns_text_and_archives_both_streams(tmp_path):
    runner = CommandRunner(tmp_path / "logs", cwd=tmp_path)
    result = runner.run(
        sys.executable, "-c",
        "import sys;print('normal');print('diagnostic',file=sys.stderr)",
    )
    assert result.ok and result.stdout == "normal\n" and result.stderr == "diagnostic\n"
    assert isinstance(result.stdout, str) and isinstance(result.stderr, str)
    assert (tmp_path / "logs" / "0001.stdout.log").read_text() == "normal\n"
    assert json.loads((tmp_path / "logs" / "0001.json").read_text())["returncode"] == 0


def test_command_runner_can_return_an_expected_failure(tmp_path):
    result = CommandRunner(tmp_path / "logs", cwd=tmp_path).run(
        sys.executable, "-c", "import sys;print('bad',file=sys.stderr);sys.exit(7)",
        check=False,
    )
    assert not result.ok and result.returncode == 7 and result.stderr == "bad\n"


def test_artifacts_have_direct_text_bytes_path_and_file_access(tmp_path):
    store = ArtifactStore(tmp_path / "artifacts", tmp_path)
    artifact = store.materialize(text_artifact("message", "hello\n"))
    assert artifact.read_text() == "hello\n"
    assert artifact.read_bytes() == b"hello\n"
    assert artifact.path.is_file()
    with artifact.open("r") as handle:
        assert handle.read() == "hello\n"


def test_managed_function_runs_on_named_worker_and_uses_convenience_api(tmp_path):
    result = _run_pytest(
        tmp_path,
        "import sys\n"
        "from brixtest import case,text_artifact\n"
        "MESSAGE=text_artifact('message','hello worker')\n"
        "@case(artifacts=[MESSAGE],keep='always')\n"
        "def test_sample(run):\n"
        " import threading\n"
        " assert threading.current_thread().name=='brixtest-test-worker'\n"
        " assert run.artifact_text(MESSAGE)=='hello worker'\n"
        " assert run.artifact_bytes(MESSAGE)==b'hello worker'\n"
        " assert run.artifact_file(MESSAGE).is_file()\n"
        " result=run.command(sys.executable,'-c','import sys;print(\"out\");print(\"err\",file=sys.stderr)')\n"
        " assert result.stdout=='out\\n' and result.stderr=='err\\n'\n",
    )
    assert result.returncode == 0, result.stdout + result.stderr
    logs = list((tmp_path / "runs").glob("**/runtime/command-logs/0001.json"))
    # Retention plus the structured log archive may expose more than one path
    # to the same invocation; every preserved copy must describe it correctly.
    assert logs
    assert all(json.loads(path.read_text())["returncode"] == 0 for path in logs)


def test_module_scope_native_import_is_rejected_before_import(tmp_path):
    sentinel = tmp_path / "imported.txt"
    (tmp_path / "XRootD.py").write_text(
        "import os\nopen(os.environ['SENTINEL'],'w').write('imported')\n"
    )
    result = _run_pytest(
        tmp_path,
        "import XRootD\n"
        "from brixtest import case\n"
        "@case()\n"
        "def test_sample(run): pass\n",
        SENTINEL=str(sentinel),
    )
    assert result.returncode != 0
    assert "module-level import 'XRootD'" in result.stdout + result.stderr
    assert not sentinel.exists()


def test_function_local_native_import_runs_only_in_helper_worker(tmp_path):
    sentinel = tmp_path / "imported.txt"
    (tmp_path / "XRootD.py").write_text(
        "import os,threading\n"
        "open(os.environ['SENTINEL'],'w').write(os.environ.get('BRIXTEST_HELPER','0')+':'"
        "+threading.current_thread().name)\n"
    )
    result = _run_pytest(
        tmp_path,
        "from brixtest import case\n"
        "@case(keep='never')\n"
        "def test_sample(run):\n"
        " import XRootD\n"
        " assert XRootD is not None\n",
        SENTINEL=str(sentinel),
    )
    assert result.returncode == 0, result.stdout + result.stderr
    assert sentinel.read_text() == "1:brixtest-test-worker"


def test_module_scope_blocking_call_is_rejected(tmp_path):
    result = _run_pytest(
        tmp_path,
        "import time\n"
        "from brixtest import case\n"
        "time.sleep(60)\n"
        "@case()\n"
        "def test_sample(run): pass\n",
    )
    assert result.returncode != 0
    assert "module-level call time.sleep()" in result.stdout + result.stderr


def test_server_database_rows_have_first_class_ports_and_config_fields(tmp_path):
    database = sqlite3.connect(":memory:")
    from brixtest.evidence.store import write_entities
    payload = {
        "schema_version": 1, "session_id": "s", "generated_at": "now", "tests": [],
        "topology": {"pools": [{
            "pool_id": "p", "result": {}, "services": {"origin": {
                "instance_id": "i", "name": "origin", "scope": "session",
                "ports": {"http": 41234}, "config": "/run/origin.conf",
                "config_filename": "origin.conf", "config_sha256": "a" * 64,
            }},
        }]},
    }
    write_entities(database, payload)
    row = database.execute(
        "select ports, config_filename, config_sha256 from evidence_server_instances"
    ).fetchone()
    assert json.loads(row[0]) == {"http": 41234}
    assert row[1:] == ("origin.conf", "a" * 64)
