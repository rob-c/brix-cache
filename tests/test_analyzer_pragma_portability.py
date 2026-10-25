"""Analyzer suppressions must not break strict GCC8 or Clang builds.

Exercise each production preprocessor condition rather than depending on the
host compiler's version. Actual module builds additionally compile the pragma.
"""

from pathlib import Path
import re
import shutil
import subprocess

import pytest


ROOT = Path(__file__).resolve().parents[1]
SOURCES = (
    "fs/backend/ram/sd_ram_staged.c",
    "fs/backend/ram/sd_ram_xattr.c",
    "fs/backend/pblock/sd_pblock_catalog_ns.c",
    "fs/backend/frm/sd_frm_arc.c",
    "fs/backend/frm/sd_frm_arc_store.c",
    "fs/backend/frm/sd_frm_purge.c",
    "fs/cache/evict_candidates.c",
)


@pytest.mark.parametrize("relative", SOURCES)
@pytest.mark.parametrize("version,clang,enabled", [
    (8, False, False), (9, False, False), (10, False, True),
    (11, False, True), (17, False, True), (17, True, False),
])
def test_analyzer_warning_is_only_selected_by_a_supporting_compiler(
        relative, version, clang, enabled):
    """Old GCC and GNU-compatible Clang cannot select an unknown warning."""
    compiler = shutil.which("cc")
    if compiler is None:
        pytest.skip("C preprocessor required for compiler compatibility checks")
    source = (ROOT / "src" / relative).read_text()
    block = re.search(
        r'(^#if[^\n]+\n)#pragma GCC diagnostic ignored '
        r'"-Wanalyzer-malloc-leak"\n#endif', source, re.MULTILINE)
    assert block, f"{relative}: analyzer diagnostic lost its compiler gate"
    probe = block[1] + "analyzer_diagnostic_enabled\n#endif\n"
    command = [compiler, "-E", "-P", "-x", "c", "-", "-U__GNUC__",
               "-U__clang__", f"-D__GNUC__={version}"]
    if clang:
        command.append("-D__clang__=1")
    result = subprocess.run(command, input=probe, capture_output=True,
                            text=True, timeout=10)
    assert result.returncode == 0, result.stderr
    assert ("analyzer_diagnostic_enabled" in result.stdout) is enabled
