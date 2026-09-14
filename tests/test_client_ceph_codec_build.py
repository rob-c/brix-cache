"""Actual client codec recipes retain PIE under normal and sanitizer builds."""

from pathlib import Path
import shlex
import subprocess

import pytest


REPO = Path(__file__).resolve().parents[1]
CODECS = ("cephfs_denc", "cephfs_layout")
SANITIZERS = "-fsanitize=address,undefined -fno-omit-frame-pointer -g -O1"


def _compile_codecs(directory, flags):
    owned = directory / "apps/ceph"
    owned.mkdir(parents=True)
    (owned / "ngx_shim.h").symlink_to(REPO / "client/apps/ceph/ngx_shim.h")
    command = ["make", "-f", str(REPO / "client/Makefile"), "-j1",
               f"REPO={REPO}", f"CFLAGS={flags}",
               *(f"apps/ceph/{name}.o" for name in CODECS)]
    result = subprocess.run(command, cwd=directory, capture_output=True, text=True,
                            timeout=60)
    return result, [owned / f"{name}.o" for name in CODECS]


def _link_and_run(directory, objects, name, flags):
    binary = directory / name
    command = ["cc", "-fPIE", "-pie", *shlex.split(flags),
               "-I", str(REPO / "src/fs/backend/rados"),
               str(REPO / f"tests/ceph/{name}_unittest.c"),
               *(str(path) for path in objects), "-o", str(binary)]
    result = subprocess.run(command, capture_output=True, text=True, timeout=60)
    assert result.returncode == 0, result.stdout + result.stderr
    header = subprocess.run(["readelf", "-d", str(binary)], capture_output=True,
                            text=True, check=True).stdout
    assert any("FLAGS_1" in line and "PIE" in line for line in header.splitlines())
    result = subprocess.run([str(binary)], capture_output=True, text=True, timeout=30)
    assert result.returncode == 0, result.stdout + result.stderr


@pytest.mark.parametrize("flags", ["", SANITIZERS], ids=["normal", "sanitized"])
def test_actual_codec_recipes_link_pie_and_pass_decoder_bounds(tmp_path, flags):
    result, objects = _compile_codecs(tmp_path, flags)
    assert result.returncode == 0, result.stdout + result.stderr
    for name in CODECS:
        _link_and_run(tmp_path, objects, name, flags)


def test_actual_codec_recipe_propagates_compiler_errors(tmp_path):
    result, objects = _compile_codecs(tmp_path, "-fbrix-invalid-compiler-option")
    assert result.returncode != 0
    assert "-fbrix-invalid-compiler-option" in result.stderr
    assert not any(path.exists() for path in objects)
