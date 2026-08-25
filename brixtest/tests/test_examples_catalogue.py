"""Keep the public examples complete, self-contained, and safely configured."""

import ast
import sys
import sysconfig
from pathlib import Path

EXAMPLES = Path(__file__).resolve().parents[1] / "examples"


def _modules():
    return sorted(EXAMPLES.glob("test_*.py"))


def _capability_modules():
    return sorted((EXAMPLES / "capabilities").glob("test_*.py"))


def _stdlib_names():
    names = getattr(sys, "stdlib_module_names", None)
    if names is not None:
        return set(names)
    root = Path(sysconfig.get_paths()["stdlib"])
    return set(sys.builtin_module_names) | {
        path.stem if path.is_file() else path.name
        for path in root.iterdir()
        if path.suffix == ".py" or path.is_dir()
    }


def test_example_catalogue_contains_exactly_twenty_compilable_tests():
    names = [name for path in _modules() for name in _test_names(path)]
    numbers = [int(name.split("_", 2)[1]) for name in names]
    assert (len(names), numbers) == (20, list(range(1, 21)))


def test_examples_import_only_stdlib_pytest_and_brixtest():
    allowed = {"brixtest", "pytest"} | _stdlib_names()
    for path in (*_modules(), *_capability_modules()):
        _assert_safe_example(path, allowed)


def test_advanced_capability_examples_cover_the_migration_surface():
    names = {
        name for path in _capability_modules() for name in _test_names(path)
    }
    expected = {
        "test_ipv6_uses_a_real_socket",
        "test_udp_has_the_same_service_surface",
        "test_server_to_server_reverse_callback",
        "test_resources_and_tools_share_one_pythonic_run_surface",
        "test_rbac_identity_and_provider_volume_are_ordinary_resources",
        "test_user_namespace_applies_uid_gid_and_supplementary_groups",
        "test_fuse_mount_is_supervised_and_always_unmounted",
        "test_init_and_sidecar_members_need_only_a_shared_group_name",
        "test_environment_names_are_the_only_cluster_topology_boilerplate",
    }
    assert expected <= names


def test_advanced_examples_do_not_import_runtime_or_cluster_orchestration():
    forbidden = {"docker", "kubernetes", "subprocess"}
    for path in _capability_modules():
        tree = ast.parse(path.read_text(), filename=str(path))
        imported = {name for node in ast.walk(tree) for name in _import_roots(node)}
        assert not (imported & forbidden), path


def _test_names(path):
    tree = ast.parse(path.read_text(), filename=str(path))
    return [
        node.name for node in tree.body
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
        and node.name.startswith("test_")
    ]


def _assert_safe_example(path, allowed):
    tree = ast.parse(path.read_text(), filename=str(path))
    imports = [name for node in ast.walk(tree) for name in _import_roots(node)]
    assert (set(imports) <= allowed, "../" not in path.read_text()) == (True, True), (
        path, imports,
    )


def _import_roots(node):
    if isinstance(node, ast.Import):
        return [item.name.split(".")[0] for item in node.names]
    if isinstance(node, ast.ImportFrom) and node.module:
        return [node.module.split(".")[0]]
    return []


def test_nginx_example_is_loopback_dynamic_and_unprivileged():
    template = (EXAMPLES / "configs" / "nginx.conf.in").read_text()
    assert "listen {host}:{port};" in template
    assert "root {artifact_nginx_page_dir};" in template
    assert "daemon off;" in template
    assert "listen 80" not in template
    assert "user root" not in template
