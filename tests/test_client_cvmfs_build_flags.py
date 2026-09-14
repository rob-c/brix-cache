"""Compile an actual CVMFS static-pattern target without shared build outputs."""

from pathlib import Path
import shutil
import subprocess


REPO = Path(__file__).resolve().parents[1]


def _compile_hash(directory, flags):
    shared = directory / "shared"
    grammar = shared / "cvmfs/grammar"
    grammar.mkdir(parents=True)
    for name in ("hash.c", "hash.h"):
        shutil.copy2(REPO / "shared/cvmfs/grammar" / name, grammar / name)
    output = grammar / "hash.o"
    command = ["make", "-f", str(REPO / "client/Makefile"), "-j1",
               f"REPO={REPO}", f"SHARED_DIR={shared}", f"CFLAGS={flags}", str(output)]
    result = subprocess.run(command, cwd=directory, capture_output=True, text=True,
                            timeout=60)
    return result, output


def _symbols(output):
    return subprocess.run(["nm", str(output)], capture_output=True, text=True,
                          check=True, timeout=10).stdout


def test_cvmfs_default_recipe_keeps_its_public_object_contract(tmp_path):
    result, output = _compile_hash(tmp_path, "")
    assert result.returncode == 0, result.stdout + result.stderr
    assert " T cvmfs_hash_parse" in _symbols(output)


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
