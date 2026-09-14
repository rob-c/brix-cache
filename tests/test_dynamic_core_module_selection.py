"""Render matched dynamic-core selection without executing an nginx binary."""

import importlib.util
import json
import os
import shutil
import subprocess
from types import SimpleNamespace
from pathlib import Path

import pytest

import config_templates


@pytest.fixture
def module_case(monkeypatch, tmp_path):
    root = tmp_path / "matched-build"
    root.mkdir()
    for name in ("nginx", "brix.so", "filter.so", "selected core.so"):
        (root / name).write_bytes(b"inert offline module selection")
    monkeypatch.setenv("BRIX_DYN_NGINX_BIN", str(root / "nginx"))
    monkeypatch.setenv("BRIX_DYN_STREAM_SO", str(root / "brix.so"))
    monkeypatch.setenv("BRIX_DYN_FILTER_SO", str(root / "filter.so"))
    monkeypatch.setenv("TEST_NGINX_LOAD_MODULES", str(tmp_path / "unrelated.so"))
    monkeypatch.setattr(config_templates, "CONFIG_DIR", Path(__file__).parent / "configs")

    def load(core):
        if core is None:
            monkeypatch.delenv("BRIX_DYN_NGX_STREAM_MODULE", raising=False)
        else:
            monkeypatch.setenv("BRIX_DYN_NGX_STREAM_MODULE", str(root / core))
        path = Path(__file__).with_name("test_brix_dynamic_modules.py")
        spec = importlib.util.spec_from_file_location("dynamic_core_subject", path)
        subject = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(subject)
        return subject

    return root, load


def _loads(subject, prefix, **values):
    prefix.mkdir()
    body = subject._conf(prefix, **values).read_text()
    _assert_owned_runtime_paths(prefix, body)
    return [line for line in body.splitlines() if line.startswith("load_module ")]


def test_selected_core_loads_before_both_brix_objects(module_case, tmp_path):
    root, load = module_case
    subject = load("selected core.so")
    directives = _loads(subject, tmp_path / "prefix")
    assert directives == ["load_module " + json.dumps(str(root / "selected core.so")) + ";",
                          "load_module " + str(root / "brix.so") + ";",
                          "load_module " + str(root / "filter.so") + ";"]
    assert subject._missing == []


def test_static_core_does_not_inherit_unrelated_global_modules(module_case, tmp_path):
    root, load = module_case
    subject = load(None)
    assert _loads(subject, tmp_path / "prefix") == [
        "load_module " + str(root / "brix.so") + ";",
        "load_module " + str(root / "filter.so") + ";",
    ]
    assert subject.DYN_NGX_STREAM_MODULE is None


def test_explicit_absent_core_is_a_recorded_missing_prerequisite(module_case):
    root, load = module_case
    subject = load("missing-core.so")
    assert subject._missing == [root / "missing-core.so"]
    assert [mark.name for mark in subject.pytestmark].count("skip") == 1
    assert str(root / "missing-core.so") in subject.pytestmark[-1].kwargs["reason"]


def test_missing_brix_negative_keeps_its_exact_path_with_core_selected(module_case, tmp_path):
    root, load = module_case
    subject = load("selected core.so")
    missing = tmp_path / "no-such-module.so"
    directives = _loads(subject, tmp_path / "prefix", stream_so=missing)
    assert directives[0] == "load_module " + json.dumps(str(root / "selected core.so")) + ";"
    assert directives[1] == "load_module " + str(missing) + ";"
    assert len(directives) == 3


def _assert_owned_runtime_paths(prefix, body):
    for name in ("proxy", "fastcgi", "uwsgi", "scgi"):
        directive = name + "_temp_path " + json.dumps(str(prefix / "tmp" / name)) + ";"
        assert body.count(directive) == 1
    assert (prefix / "tmp").is_dir()
    assert body.count("client_body_temp_path " + str(prefix / "logs") + ";") == 1
    assert "access_log " + str(prefix / "logs" / "dyn.log") + " dyn;" in body


def _package_runner(case, calls, module_root):
    def run(command, **kwargs):
        calls.append((command, kwargs))
        if "--build" in command:
            code = 2 if case == "build-error" else 0
            return SimpleNamespace(returncode=code, stderr="fixture package build error")
        if case == "extract-error":
            raise subprocess.CalledProcessError(2, command)
        target = Path(command[-1]) / "usr/lib/nginx/modules"
        target.mkdir(parents=True)
        for name in ("ngx_stream_brix_module.so", "ngx_http_brix_xrdhttp_filter_module.so"):
            shutil.copy(module_root / name, target / name)
        return SimpleNamespace(returncode=0, stderr="")
    return run


def _package_subject(module_case, monkeypatch, tmp_path, case):
    module_root, load = module_case
    subject = load(None)
    for attribute, name in (("DYN_STREAM_SO", "ngx_stream_brix_module.so"),
                            ("DYN_FILTER_SO", "ngx_http_brix_xrdhttp_filter_module.so")):
        artifact = module_root / name
        artifact.write_bytes(b"inert packaged module bytes")
        monkeypatch.setattr(subject, attribute, artifact)
    calls, configs = [], []
    monkeypatch.setenv("TMPDIR", str(tmp_path / "uncreated-inherited-temp"))
    monkeypatch.setenv("BRIX_DYN_OFFLINE_SENTINEL", "preserved")
    monkeypatch.setattr(shutil, "which", lambda _name: "/fixture/bin/dpkg-deb")
    monkeypatch.setattr(subprocess, "run", _package_runner(case, calls, module_root))

    def render(prefix, **modules):
        configs.append(modules)
        return prefix / "nginx.conf"

    monkeypatch.setattr(subject, "_conf", render)
    monkeypatch.setattr(subject, "_nginx_t", lambda *_args: SimpleNamespace(returncode=0, stderr=""))
    return subject, calls, configs


def _assert_package_environment(calls, tmp_path):
    assert os.environ["TMPDIR"] == str(tmp_path / "uncreated-inherited-temp")
    assert not Path(os.environ["TMPDIR"]).exists()
    for _command, kwargs in calls:
        assert kwargs["env"] is not os.environ
        assert kwargs["env"]["TMPDIR"] == str(tmp_path)
        assert Path(kwargs["env"]["TMPDIR"]).is_dir()
        assert kwargs["env"]["BRIX_DYN_OFFLINE_SENTINEL"] == "preserved"


@pytest.mark.parametrize("case", ["success", "build-error", "extract-error"])
def test_package_commands_use_owned_temp_without_mutating_environment(module_case,
                                                                       monkeypatch,
                                                                       tmp_path, case):
    subject, calls, configs = _package_subject(module_case, monkeypatch, tmp_path, case)
    if case == "success":
        subject.test_packaged_deb_artifact_loads(tmp_path)
        assert len(configs) == 1
        modules = tmp_path / "x/usr/lib/nginx/modules"
        assert (modules / subject.DYN_STREAM_SO.name).read_bytes() == subject.DYN_STREAM_SO.read_bytes()
        assert (modules / subject.DYN_FILTER_SO.name).read_bytes() == subject.DYN_FILTER_SO.read_bytes()
        assert configs[0] == {
            "stream_so": modules / "ngx_stream_brix_module.so",
            "filter_so": modules / "ngx_http_brix_xrdhttp_filter_module.so",
        }
    else:
        error = AssertionError if case == "build-error" else subprocess.CalledProcessError
        with pytest.raises(error):
            subject.test_packaged_deb_artifact_loads(tmp_path)
        assert configs == []
    assert len(calls) == (1 if case == "build-error" else 2)
    _assert_package_environment(calls, tmp_path)
