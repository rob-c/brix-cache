"""Surface for tests/test_fs_id_map.c — the fs_list.h backend-census unit test.

The census (core/types/fs_list.h) is THE single declaration of every storage
driver: the name→driver registry, the per-backend SHM metric arrays, and the
exporter labels all generate from it. This test roundtrips every row
(name → id → name), pins the always-present anchors (posix/cache/xroot/frm and
the wave-34 `mirage` synthetic backend), and enforces the append-only rule
(posix stays row 0 — a renumbering would silently re-key the SHM byte
counters across a reload).

The C test was previously ORPHANED (no surface ran it); it builds standalone —
`sd_fs_id.c` is ngx-free — exactly per its own header comment: no nginx tree,
no objs, just cc.
"""

import os
import subprocess

import pytest

_REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def test_fs_id_census_roundtrip(tmp_path):
    cc = os.environ.get("CC", "cc")
    exe = tmp_path / "test_fs_id_map"
    build = subprocess.run(
        [cc, "-Wall", "-Werror", "-I", os.path.join(_REPO, "src"),
         "-o", str(exe),
         os.path.join(_REPO, "tests", "test_fs_id_map.c"),
         os.path.join(_REPO, "src", "fs", "backend", "sd_fs_id.c")],
        capture_output=True, text=True, timeout=60)
    if build.returncode != 0 and "not found" in build.stderr.lower():
        pytest.skip(f"no C compiler: {build.stderr.splitlines()[:1]}")
    assert build.returncode == 0, f"census unit test failed to build:\n{build.stderr}"

    run = subprocess.run([str(exe)], capture_output=True, text=True, timeout=30)
    assert run.returncode == 0, f"census checks failed:\n{run.stdout}{run.stderr}"
    assert "ALL PASS" in run.stdout, run.stdout
