"""Evaluate real Nix source filtering without compiling packages or using caches."""

import json
import os
from pathlib import Path
import shutil
import subprocess

import pytest


@pytest.fixture
def source_tree(tmp_path):
    if shutil.which("nix") is None or not os.environ.get("BRIX_NIXPKGS_SOURCE"):
        pytest.skip("Use nix develop for the pinned Nix source-filter contracts")
    (tmp_path / "src").mkdir()
    (tmp_path / "src/main.c").write_text("int main(void) { return 0; }\n")
    return tmp_path


def _filtered(tree):
    repo = Path(__file__).resolve().parents[1]
    expression = f'''
let
  repo = builtins.toPath {json.dumps(str(repo))};
  pkgs = import (builtins.toPath {json.dumps(os.environ["BRIX_NIXPKGS_SOURCE"])}) {{
    system = builtins.currentSystem;
  }};
  packages = import (repo + "/packaging/nix/package.nix") {{
    inherit pkgs;
    src = builtins.toPath {json.dumps(str(tree))};
  }};
in packages.brix-cache-client.src.outPath
'''
    checked = subprocess.run(
        ["nix", "--extra-experimental-features", "nix-command flakes", "eval",
         "--offline", "--impure", "--raw", "--expr", expression],
        capture_output=True, text=True, timeout=120)
    assert checked.returncode == 0, checked.stderr
    return Path(checked.stdout)


def test_development_inputs_do_not_rebuild_native_code(source_tree):
    before = _filtered(source_tree)
    (source_tree / "tests").mkdir()
    (source_tree / "tests/test_new.py").write_text("assert True\n")
    (source_tree / "flake.nix").write_text("development metadata\n")
    (source_tree / "._main.c").write_bytes(b"archive sidecar")
    assert _filtered(source_tree) == before


def test_production_edits_cannot_reuse_an_old_native_source(source_tree):
    before = _filtered(source_tree)
    (source_tree / "src/main.c").write_text("int main(void) { return 1; }\n")
    assert _filtered(source_tree) != before


def test_client_tests_and_deployment_assets_are_retained(source_tree):
    for relative in ("client/tests/c/unit.c", "docs/05-operations/deploy/cvmfs/key",
                     "tools/brix_config_migrate.py", "packaging/brixcvmfs@.service"):
        target = source_tree / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text("retained input\n")
    filtered = _filtered(source_tree)
    assert (filtered / "src/main.c").is_file()
    for relative in ("client/tests/c/unit.c", "docs/05-operations/deploy/cvmfs/key",
                     "tools/brix_config_migrate.py", "packaging/brixcvmfs@.service"):
        assert (filtered / relative).read_text() == "retained input\n"
