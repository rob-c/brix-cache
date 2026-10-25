"""Phase-118 scratch-capability guard controls and security negatives."""

import importlib.util
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
GUARD_PATH = ROOT / "tools" / "ci" / "check_conform_scratch.py"
SPEC = importlib.util.spec_from_file_location("check_conform_scratch", GUARD_PATH)
assert SPEC is not None and SPEC.loader is not None
GUARD = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(GUARD)


def test_current_conformance_runner_uses_only_scratch_capability():
    assert GUARD.current_violations(ROOT) == []


def test_guard_rejects_target_path_mutation_security_negative():
    source = "brix_rm(&connection, execution->run->config.target, &status);\n"
    violations = GUARD.violations_for_text("bad.c", source)
    assert len(violations) == 1
    assert "brix_rm" in violations[0]


def test_guard_accepts_builder_owned_path_control():
    source = (
        "xrd_conform_scratch_object scratch_object;\n"
        "brix_rm(&connection, scratch_object.path, &status);\n"
    )
    assert GUARD.violations_for_text("good.c", source) == []


def test_guard_rejects_capability_name_spoof_security_negative():
    source = "brix_rm(&connection, scratch_object.path, &status);\n"
    violations = GUARD.violations_for_text("spoof.c", source)
    assert len(violations) == 1


def test_guard_accepts_capability_passed_through_typed_helper():
    source = (
        'void restore(const xrd_conform_scratch_object *object) {\n'
        'brix_rmdir(connection, object->path, status);\n}\n'
    )
    assert GUARD.violations_for_text('typed.c', source) == []


def test_guard_rejects_helper_that_erases_the_capability_type():
    source = (
        'void restore(const char *path) {\n'
        'brix_rmdir(connection, path, status);\n}\n'
    )
    assert len(GUARD.violations_for_text('erased.c', source)) == 1


def test_guard_rejects_untyped_pointer_with_capability_shaped_member():
    source = (
        'void restore(const impostor *object) {\n'
        'brix_rmdir(connection, object->path, status);\n}\n'
    )
    assert len(GUARD.violations_for_text('impostor.c', source)) == 1
