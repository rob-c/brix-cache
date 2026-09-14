"""Offline selector regressions without importing live fixture modules."""

import ast
import os
from pathlib import Path
from types import SimpleNamespace

import pytest


def _source(relative):
    return ast.parse((Path(__file__).parent / relative).read_text())


def _assignment(relative, name, environment, **values):
    tree = _source(relative)
    selected = [node for node in tree.body if isinstance(node, ast.Assign)
                and any(isinstance(target, ast.Name) and target.id == name
                        for target in node.targets)]
    assert len(selected) == 1
    namespace = {"os": SimpleNamespace(environ=environment, path=os.path), **values}
    code = ast.Module(body=selected, type_ignores=[])
    exec(compile(code, relative, "exec"), namespace)
    return namespace[name]


def _object_selector(relative, environment, selected_binary):
    selected = [node for node in _source(relative).body
                if isinstance(node, ast.FunctionDef)
                and node.name == "objs_dir_from_nginx"]
    assert len(selected) == 1
    namespace = {"Path": Path, "NGINX_BIN": selected_binary,
                 "os": SimpleNamespace(environ=environment)}
    exec(compile(ast.Module(body=selected, type_ignores=[]), relative, "exec"),
         namespace)
    return namespace["objs_dir_from_nginx"]


@pytest.mark.parametrize("relative", [
    "test_cache_lock_reclaim.py", "test_ratelimit_gauge_reset.py",
    "test_shm_mutex_recovery.py",
])
@pytest.mark.parametrize("environment, objects, expected", [
    ({"NGX_SRC": "/selected/nginx-src"}, "/selected/modules", "/selected/nginx-src"),
    ({}, "/custom/nginx/objs", "/custom/nginx"),
    ({"NGX_SRC": "/missing/explicit/source"}, "/existing/objs", "/missing/explicit/source"),
])
def test_c_regression_source_selection(relative, environment, objects, expected):
    assert _assignment(relative, "_NGX_SRC", environment, _OBJS=objects) == expected


@pytest.mark.parametrize("environment, binary, expected", [
    ({"TEST_NGINX_OBJS": "/selected/modules"}, "/usr/sbin/nginx", "/selected/modules"),
    ({}, "/custom/nginx/objs/nginx", "/custom/nginx/objs"),
    ({"TEST_NGINX_OBJS": "/missing/explicit/objects"}, "/existing/objs/nginx", "/missing/explicit/objects"),
])
def test_cache_metrics_object_selection(environment, binary, expected):
    assert _assignment("test_cache_reap_metrics.py", "_OBJS", environment,
                       NGINX_BIN=binary) == expected


@pytest.mark.parametrize("relative", [
    "cmdscripts/cache_reaper.py", "cmdscripts/cache_watermark.py",
])
@pytest.mark.parametrize("environment, selected_binary, requested_binary, expected", [
    ({"TEST_NGINX_OBJS": "/selected/modules"}, "/usr/sbin/nginx", None, "/selected/modules"),
    ({}, "/custom/nginx/objs/nginx", None, "/custom/nginx/objs"),
    ({"TEST_NGINX_OBJS": "/missing/explicit/objects"}, "/usr/sbin/nginx", None, "/missing/explicit/objects"),
    ({"TEST_NGINX_OBJS": "/selected/modules"}, "/usr/sbin/nginx", "/other/nginx/objs/nginx", "/other/nginx/objs"),
    ({}, "/usr/sbin/nginx", None, "/tmp/nginx-1.28.3/objs"),
])
def test_cache_command_object_selection(relative, environment, selected_binary,
                                        requested_binary, expected):
    select = _object_selector(relative, environment, selected_binary)
    actual = select() if requested_binary is None else select(requested_binary)
    assert actual == Path(expected)
