"""
tests/test_registry_keep_logs.py — TEST_REGISTRY_KEEP_LOGS=1 keeps the fleet's
error.logs through the session-end wipe.

The knob was a settings field with no consumer: ``_remove_test_root()`` wiped
every registry instance's ``logs/`` at session end, so a fail-fast halt's
only evidence was gone before the run script's EXIT line (race-hunt run 40's
post-EXIT tar came out empty; history §21(g)).  ``preserve_registry_logs``
now moves each instance's ``logs/`` to ``<TEST_ROOT>.logs/<instance>/logs``
before the wipe, and conftest_part5 calls it only when the knob is set.

  success       — two instances with non-empty logs move to the sibling
                  tree, names returned in order, and an instance whose logs
                  are all empty is left for the wipe;
  error         — a missing registry root, a prefix without logs, and a
                  failed move are skipped without raising;
  security-neg  — only a directory literally named ``logs`` directly under
                  an instance prefix moves (data roots, pidfiles and a file
                  named ``logs`` stay), and the conftest wiring is guarded by
                  the knob and ordered before the rmtree.

Run:
    PYTHONPATH=tests pytest tests/test_registry_keep_logs.py -v
"""
import re
import shutil
from pathlib import Path

import settings
from brix_suite.harness.log_preserve import preserve_registry_logs


def _instance(root: Path, name: str, error_log: str = "") -> Path:
    prefix = root / name
    (prefix / "logs").mkdir(parents=True)
    (prefix / "logs" / "error.log").write_text(error_log)
    (prefix / "conf").mkdir()
    (prefix / "conf" / "nginx.conf").write_text("events {}\n")
    return prefix


# --------------------------------------------------------------------------
# success


def test_non_empty_instance_logs_move_aside_in_name_order(tmp_path):
    root = tmp_path / "registry"
    _instance(root, "lc-b", "2026/09/07 13:01:47 [alert] worker process exited on signal 11\n")
    _instance(root, "lc-a", "notice: started\n")
    _instance(root, "lc-empty")
    dest = tmp_path / "root.logs"

    assert preserve_registry_logs(root, dest) == ["lc-a", "lc-b"]

    assert "signal 11" in (dest / "lc-b" / "logs" / "error.log").read_text()
    assert (dest / "lc-a" / "logs" / "error.log").read_text() == "notice: started\n"
    assert not (root / "lc-a" / "logs").exists()
    assert (root / "lc-a" / "conf" / "nginx.conf").exists(), "only logs/ moves"
    assert (root / "lc-empty" / "logs" / "error.log").exists(), "empty logs stay for the wipe"
    assert not (dest / "lc-empty").exists()


# --------------------------------------------------------------------------
# error


def test_missing_root_bare_prefix_and_failed_move_are_skipped(tmp_path, monkeypatch):
    assert preserve_registry_logs(tmp_path / "absent", tmp_path / "dest") == []

    root = tmp_path / "registry"
    (root / "no-logs").mkdir(parents=True)
    (root / "no-logs" / "nginx.pid").write_text("1\n")
    _instance(root, "lc-ok", "line\n")
    assert preserve_registry_logs(root, tmp_path / "dest") == ["lc-ok"]

    _instance(root, "lc-fail", "line\n")

    def _boom(src, dst):
        raise OSError("read-only destination")

    monkeypatch.setattr(shutil, "move", _boom)
    assert preserve_registry_logs(root, tmp_path / "dest2") == []
    assert (root / "lc-fail" / "logs" / "error.log").exists()


# --------------------------------------------------------------------------
# security-neg


def test_only_a_logs_directory_directly_under_a_prefix_moves(tmp_path):
    root = tmp_path / "registry"
    prefix = _instance(root, "lc-x", "line\n")
    (prefix / "data" / "logs").mkdir(parents=True)
    (prefix / "data" / "logs" / "user.log").write_text("user payload\n")
    (root / "file-named-logs").mkdir()
    (root / "file-named-logs" / "logs").write_text("not a directory\n")
    (root / "manifest.json").write_text("{}\n")
    dest = tmp_path / "dest"

    assert preserve_registry_logs(root, dest) == ["lc-x"]

    assert (prefix / "data" / "logs" / "user.log").exists(), "nested data logs stay"
    assert (root / "file-named-logs" / "logs").is_file()
    assert (root / "manifest.json").exists()
    assert sorted(p.name for p in dest.iterdir()) == ["lc-x"]


def test_conftest_wiring_is_knob_guarded_and_precedes_the_wipe():
    src = (Path(settings.TESTS_DIR) / "conftest_part5.py").read_text()
    body = src[src.index("def _remove_test_root"):]
    body = body[:body.index("\ndef ", 1)]
    guard = body.index("if REGISTRY_KEEP_LOGS:")
    call = body.index("preserve_registry_logs(Path(REGISTRY_ROOT), Path(f\"{TEST_ROOT}.logs\"))")
    wipe = body.index("shutil.rmtree(TEST_ROOT")
    assert guard < call < wipe
    assert re.search(r"^from brix_suite\.harness\.log_preserve import preserve_registry_logs$",
                     src, re.M)
    assert isinstance(settings.REGISTRY_KEEP_LOGS, bool)
