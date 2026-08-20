"""TS-0 surface-inventory script: the dump is right, loud, and honest.

Triad for tools/ci/dump_suite_surface.py (testsuite-modernization-plan
§11 TS-0): success on a fixture tree, error on a syntax-broken module,
and the negative that matters for shim completeness — a name a shard
module uses but only its exec'ing parent defines is reported as
*shard-implicit*, never as public surface.
"""

import json
import subprocess
import sys
from pathlib import Path

_SCRIPT = Path(__file__).resolve().parents[1] / "tools/ci/dump_suite_surface.py"


def _run_dump(tests_root: Path, out_dir: Path, *extra: str):
    cmd = [
        sys.executable, str(_SCRIPT),
        "--tests-root", str(tests_root),
        "--json", str(out_dir / "surface.json"),
        "--md", str(out_dir / "surface.md"),
        *extra,
    ]
    proc = subprocess.run(cmd, capture_output=True, text=True)
    return proc.returncode, proc.stdout + proc.stderr


def _fixture_tree(tmp_path: Path) -> Path:
    root = tmp_path / "mini-tests"
    root.mkdir()
    (root / "widgets.py").write_text(
        "WIDGET_LIMIT = 3\n"
        "default_kind = 'square'\n"
        "class Widget:\n    pass\n"
        "def make_widget(kind):\n    return Widget()\n"
    )
    (root / "test_widgets.py").write_text(
        "from widgets import make_widget, WIDGET_LIMIT\n"
        "import widgets\n"
        "def test_make():\n    assert make_widget('x')\n"
    )
    return root


def test_dump_surface_fixture_tree_and_idempotence(tmp_path):
    root = _fixture_tree(tmp_path)
    rc, out = _run_dump(root, tmp_path)
    assert rc == 0, out
    inventory = json.loads((tmp_path / "surface.json").read_text())
    widgets = inventory["surface"]["widgets"]
    assert widgets["functions"] == ["make_widget"]
    assert widgets["classes"] == ["Widget"]
    assert widgets["constants"] == ["WIDGET_LIMIT"]
    assert widgets["variables"] == ["default_kind"]
    assert widgets["shard_implicit"] == []
    edges = inventory["importers"]["widgets"]["test_widgets.py"]
    assert edges == ["<module>", "WIDGET_LIMIT", "make_widget"]
    assert "`widgets`" in (tmp_path / "surface.md").read_text()
    rc, out = _run_dump(root, tmp_path, "--check")
    assert rc == 0, "fresh dump immediately stale: %s" % out


def test_dump_surface_syntax_broken_module_fails_loudly(tmp_path):
    root = _fixture_tree(tmp_path)
    (root / "broken.py").write_text("def oops(:\n")
    rc, out = _run_dump(root, tmp_path)
    assert rc != 0, "syntax-broken infra module went unreported"
    assert "broken.py" in out, out


def test_dump_surface_exec_shard_name_is_implicit_not_public(tmp_path):
    root = _fixture_tree(tmp_path)
    # the fleet_specs.py:405 pattern: parent defines _data then execs the
    # shard; the shard's call-time use of _data is NOT its public surface
    (root / "specs_parent.py").write_text(
        "def _data(name):\n    return '/srv/' + name\n"
        "exec((__file__.replace('parent', 'shard')), globals())\n"
    )
    (root / "specs_shard.py").write_text(
        "def ha_specs():\n    return [_data('data'), _data('logs')]\n"
    )
    rc, out = _run_dump(root, tmp_path)
    assert rc == 0, out
    inventory = json.loads((tmp_path / "surface.json").read_text())
    shard = inventory["surface"]["specs_shard"]
    assert shard["shard_implicit"] == ["_data"]
    for bucket in ("functions", "classes", "constants", "variables"):
        assert "_data" not in shard[bucket]
    assert shard["functions"] == ["ha_specs"]
    parent = inventory["surface"]["specs_parent"]
    assert parent["shard_implicit"] == []
