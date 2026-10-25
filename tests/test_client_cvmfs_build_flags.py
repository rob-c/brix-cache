"""Compile an actual CVMFS static-pattern target without shared build outputs."""

from pathlib import Path
import shutil
import subprocess
import sys

import pytest
from brix_suite.client_build import client_make


REPO = Path(__file__).resolve().parents[1]


def _compile_hash(directory, flags):
    shared = directory / "shared"
    grammar = shared / "cvmfs/grammar"
    grammar.mkdir(parents=True)
    for name in ("hash.c", "hash.h"):
        shutil.copy2(REPO / "shared/cvmfs/grammar" / name, grammar / name)
    output = grammar / "hash.o"
    command = ["-f", str(REPO / "client/Makefile"), "-j1",
               f"REPO={REPO}", f"SHARED_DIR={shared}", f"CFLAGS={flags}", str(output)]
    result = client_make(directory, *command, cwd=directory,
                         capture_output=True, text=True, timeout=60)
    return result, output


def _symbols(output):
    return subprocess.run(["nm", str(output)], capture_output=True, text=True,
                          check=True, timeout=10).stdout


def test_cvmfs_default_recipe_keeps_its_public_object_contract(tmp_path):
    result, output = _compile_hash(tmp_path, "")
    assert result.returncode == 0, result.stdout + result.stderr
    public_name = "_cvmfs_hash_parse" if sys.platform == "darwin" else "cvmfs_hash_parse"
    assert " T " + public_name in _symbols(output)


def test_cvmfs_recipe_instruments_the_actual_object(tmp_path):
    result, output = _compile_hash(tmp_path, "-fsanitize=address,undefined -O1")
    assert result.returncode == 0, result.stdout + result.stderr
    symbols = _symbols(output)
    assert "__asan_init" in symbols
    assert "__ubsan_handle_" in symbols


def test_cvmfs_recipe_propagates_invalid_caller_flags(tmp_path):
    result, output = _compile_hash(tmp_path, "-fbrix-invalid-compiler-option")
    assert result.returncode != 0
    assert "-fbrix-invalid-compiler-option" in result.stderr
    assert not output.exists()


@pytest.mark.parametrize('host,names,shared', [
    ('freebsd', ('posix',), True), ('darwin', ('posix',), True),
    ('linux', ('posix',), False), ('windows', ('posix',), False),
    ('freebsd', ('mounts',), False), ('freebsd', (), False),
])
def test_standalone_client_pal_preserves_the_shared_fuse_link_closure(
        monkeypatch, host, names, shared):
    """BSD POSIX users link FUSE policy once; unrelated bodies never borrow it."""
    from cmdscripts import compile_run

    prefix = 'client/lib/platform/' + host
    monkeypatch.setattr(compile_run, 'CLIENT_PAL_HOST_DIR', prefix)
    expected = [prefix + '/' + name + '.c' for name in names]
    if shared:
        expected.append('client/lib/platform/fuse_bsd.c')
    assert compile_run.client_pal_host_sources(*names) == expected
