"""Execute the real ``tools/ci`` Python guards inside the pytest suite.

``test_source_guards.py`` asserts the pure-Python *verdict twins* and drives
their injected-tree negatives; this module runs the actual ``tools/ci/*.py``
guard scripts — the exact artifacts ``.github/workflows/guards.yml`` invokes —
so a guard that reddens in CI reddens the local suite too. The fleet was ported
``.sh`` → ``.py`` on 2026-07-21; no bash is involved.

Lanes:
  - fast static guards — text scans, well under the 30s cap; asserted green.
  - lizard-backed guards (CCN + copy-paste) — skipped when the analyzer is
    absent (CI pip-installs it); given headroom past the default timeout.
  - analyzer/coverage runners — need a configured nginx build plus an external
    tool and run for minutes, so they are ``slow`` (nightly) and self-skip when
    their prerequisites are missing.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

pytestmark = pytest.mark.xdist_group("ci-guards")

CI = Path(__file__).resolve().parents[1] / "tools" / "ci"


def _run(name: str) -> tuple[int, str]:
    p = subprocess.run(
        [sys.executable, str(CI / f"{name}.py")],
        capture_output=True,
        text=True,
    )
    return p.returncode, p.stdout + p.stderr


def _have(tool: str) -> bool:
    return bool(shutil.which(tool) or shutil.which(str(Path.home() / ".local/bin" / tool)))


# --- fast static guards -------------------------------------------------------
# The blocking guards.yml set (plus the shm-mutex/sd-driver/vfs guards): pure
# text scans that must exit 0 on the tree.
_FAST = [
    "check_config_coverage",
    "check_client_build_coverage",
    "check_make_recipes",
    "check_curl_enum_ifdef",
    "check_http_helper_reimpl",
    "check_metric_cardinality",
    "check_metric_names",
    "check_client_flags_doc",
    "check_auth_verdict_sentinel",
    "check_shm_mutex",
    "check_sd_driver_conformance",
    "check_file_size",
    "check_todo_fixme",
    "check_doc_paths",
    "check_doc_links",
    "check_readme_coverage",
    "check_ports_doc",
    "check_template_refs",
    "check_vfs_seam",
    "check_vfs_identity_branch",
    "check_brix_namespace",
    "check_gridftp_interop_image",
    "check_python_deps",
    "check_version_sync",
    "check_ratchet_monotonic",
    # TS-2/TS-4/TS-5 suite-modernization guards.  `guard_set.prepush_guards()`
    # GLOBS `tools/ci/check_*.py`, so each of these joined the pre-push set the
    # moment its file existed, while this list — maintained by hand — did not
    # follow.  `test_fast_lane_covers_the_prepush_guard_set` is what noticed.
    "check_shim_completeness",
    "check_shim_entrypoints",
    "check_shard_entrypoints",
    "check_import_direction",
    # Complexity-contract wave (7a8009af): the shard-name collision guard and
    # the Python quality contract.  `test_fast_lane_covers_the_prepush_guard_set`
    # pins this list to the pre-push glob, so slow members stay HERE and the
    # green test carries the timeout headroom instead (lizard-class guards run
    # ~23s serially and starve under a loaded 12-worker box).
    "check_shard_name_collisions",
    "check_python_quality",
]

def _load_check_file_size():
    import importlib.util

    path = CI / "check_file_size.py"
    spec = importlib.util.spec_from_file_location("check_file_size", path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod



def _load_check_make_recipes():
    import importlib.util

    path = CI / "check_make_recipes.py"
    spec = importlib.util.spec_from_file_location("check_make_recipes", path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _fake_tree(root: Path, bodies: dict[str, str]) -> None:
    """Write a Makefile for every directory the guard checks."""
    cmr = _load_check_make_recipes()
    for rel in cmr.MAKEFILES:
        d = root / rel
        d.mkdir(parents=True, exist_ok=True)
        (d / "Makefile").write_text(bodies.get(rel, "all:\n\t@true\n"))


@pytest.mark.skipif(not _have("make"), reason="needs make to parse the Makefile")

def _load(stem: str):
    """Import a tools/ci module by path — that tree has no ``__init__.py``."""
    import importlib.util

    spec = importlib.util.spec_from_file_location(stem, CI / f"{stem}.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


_GUARD_SET = _load("guard_set")
# Defined here (not only in the parent test modules) so this helper's functions
# and every reexporting test file (test_ci_guards, test_ci_guards_b) resolve
# them: reexport copies helper->test, so a name the helper/sibling USES must
# live in the helper, not be stranded in one test module's top-level code.
_DEPS = _load("check_python_deps")
_HOOK = CI.parents[1] / "tools" / "git-hooks" / "pre-push"


def _ci_guard_scripts() -> list[Path]:
    return _GUARD_SET.guard_scripts()

def _deps_tree(tmp_path: Path, required: str, optional: str, source: str) -> Path:
    (tmp_path / "tests").mkdir(parents=True)
    (tmp_path / "requirements.txt").write_text(required)
    (tmp_path / "requirements-optional.txt").write_text(optional)
    (tmp_path / "requirements-dev.txt").write_text("lizard>=1.17,<2\n")
    (tmp_path / "k8s-tests/pytests").mkdir(parents=True)
    (tmp_path / "k8s-tests/pytests/requirements.txt").write_text("pytest>=7.0,<10\n")
    (tmp_path / "tests/test_thing.py").write_text(source)
    # `check_python_deps.PYPROJECT_FILES` (TS-1) treats a declared manifest that
    # is not on disk as a finding, so a synthetic root without one fails R0 for
    # a reason that has nothing to do with the case under test.  Minimal and
    # empty on purpose: these fixtures assert about the *requirements* lanes,
    # and a manifest with dependencies in it would quietly join every one of
    # them.
    (tmp_path / "brixtest").mkdir(parents=True)
    (tmp_path / "brixtest/pyproject.toml").write_text(
        '[project]\nname = "brixtest"\nversion = "0"\ndependencies = []\n'
    )
    return tmp_path



def _vsync_tree(
    tmp_path: Path,
    ident: str = "1.4.0",
    spec_fallback: str = "1.4.0",
    spec_changelog: str = "1.4.0-1\n- notes\n",
    changelog: str = "## v1.4.0 — 2026-08-03\n",
) -> Path:
    (tmp_path / "src/core").mkdir(parents=True)
    (tmp_path / "src/core/ident.h").write_text(
        f'#define BRIX_SERVER_VERSION_BARE  "{ident}"\n'
    )
    (tmp_path / "packaging/rpm").mkdir(parents=True)
    (tmp_path / "packaging/rpm/nginx-mod-brix-cache.spec").write_text(
        "%global upstream_version %{?version_override}"
        f"%{{!?version_override:{spec_fallback}}}\n"
        "Version:        %{upstream_version}\n\n"
        f"%changelog\n* Mon Aug 03 2026 Rob Currie <r@e> - {spec_changelog}"
    )
    (tmp_path / "CHANGELOG.md").write_text(f"# Changelog\n\n{changelog}\nnotes\n")
    return tmp_path



def _hook_repo(tmp_path: Path, resolver: str, guards: dict[str, str]) -> Path:
    """A minimal tree the pre-push hook accepts, wired to fake guards."""
    repo = tmp_path / "repo"
    (repo / "tools/ci").mkdir(parents=True)
    (repo / "tests/cmdscripts").mkdir(parents=True)
    (repo / "tests/cmdscripts/operator_runtime.py").write_text("")

    for name, body in guards.items():
        g = repo / "tools/ci" / name
        g.write_text(body)
        g.chmod(0o755)

    rs = repo / "tools/ci/guard_set.py"
    rs.write_text(resolver)
    rs.chmod(0o755)

    fake_git = tmp_path / "bin" / "git"
    fake_git.parent.mkdir()
    fake_git.write_text(f'#!/bin/sh\necho "{repo}"\n')
    fake_git.chmod(0o755)
    return repo


def _run_hook(repo: Path) -> subprocess.CompletedProcess:
    env = {**os.environ, "PATH": f"{repo.parent / 'bin'}:{os.environ['PATH']}"}
    env.pop("SKIP_FAST_TESTS", None)
    return subprocess.run(
        ["bash", str(_HOOK)], cwd=repo, env=env, capture_output=True, text=True
    )


_RESOLVER = "#!/usr/bin/env python3\nprint({paths!r})\n"
