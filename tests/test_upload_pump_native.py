"""Exercise actual upload chunk selection with an in-memory transport boundary."""

from pathlib import Path
import subprocess

import pytest

from _test_data_substreams_parallel_helpers import _client_fanout_size
from test_platform_linux_native import native_compile


@pytest.fixture(scope="module")
def upload_pump_binary(native_compile):
    root = Path(__file__).resolve().parents[1]
    code = (root / "tests/c/upload_pump_test.c").read_text()
    return native_compile(
        "upload-pump", code,
        ["client/lib/xfer/copy_pump.c", "client/lib/core/types/status.c"],
        ["-I" + str(root / "client/lib"), "-DXRDPROTO_NO_NGX",
         "-ffunction-sections", "-fdata-sections", "-Wl,--gc-sections",
         "-fsanitize=address,undefined", "-fno-sanitize-recover=all"],
    )


@pytest.mark.parametrize("case", ["single-chunk", "fanout", "fallback", "denied"])
def test_upload_pump_chunk_selection(upload_pump_binary, case):
    result = subprocess.run([str(upload_pump_binary), case], capture_output=True,
                            text=True, timeout=10)
    assert result.returncode == 0, result.stdout + result.stderr


def test_fanout_fixture_spans_canonical_chunks():
    assert _client_fanout_size() == 40 * 1024 * 1024


@pytest.mark.parametrize("definition", ["(16u * 1024u * 1024u)", "new_chunk_size"])
def test_fanout_fixture_reports_changed_chunk_contract(tmp_path, definition):
    header = tmp_path / "copy_internal.h"
    header.write_text("#define XRDC_COPY_CHUNK " + definition + "\n")
    with pytest.raises(AssertionError, match="fanout fixture"):
        _client_fanout_size(header)
