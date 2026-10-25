"""Namespace labs honor allocated subordinate ids, without changing the host."""

from pathlib import Path
import subprocess

import pytest


@pytest.fixture(scope="module")
def subid_parser(tmp_path_factory):
    """Compile the same header used by the real broker and full-stack launchers."""
    source = Path(__file__).with_name("userns") / "c/subid_ranges_test.c"
    output = tmp_path_factory.mktemp("subid-parser") / "parser"
    subprocess.run(["cc", "-std=c11", "-D_GNU_SOURCE", "-Wall", "-Wextra", "-Werror",
                    str(source), "-o", str(output)], check=True, capture_output=True,
                   text=True, timeout=30)
    return output


@pytest.mark.parametrize("row,expected", [
    ("fixture:200000:65536", "200000"),
    ("2100:524288:131072", "524288"),
    ("fixture:200000:65535", None),
    ("someone-else:100000:65536", None),
    ("fixture:0:65536", None),
    ("fixture:-1:65536", None),
    ("fixture:4294967290:65536", None),
    ("fixture:200000:18446744073709551615", None),
    ("fixture:200000:65536:injected", None),
])
def test_native_subordinate_range_selection(subid_parser, row, expected):
    """Accept allocated rows and reject insufficient, foreign or malformed ids."""
    result = subprocess.run([str(subid_parser), row, "fixture"], capture_output=True,
                            text=True, timeout=5)
    assert result.returncode == (1 if expected is None else 0), result.stderr
    assert result.stdout.strip() == (expected or "")
