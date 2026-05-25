"""
Official xrdcp client-option coverage for the nginx-xrootd root:// endpoint.

These tests intentionally exercise the command-line client rather than the
PyXRootD API so client-side options keep working against the nginx module.
"""

import hashlib
import os
import shutil
import subprocess
from pathlib import Path

import pytest

from settings import XRDCP_BIN


pytestmark = pytest.mark.timeout(240)

PREFIX = "_xrdcp_client_opts_"
DEFAULT_STREAM_TEST_SIZE = 64 * 1024 * 1024


def _require_xrdcp():
    if shutil.which(XRDCP_BIN) is None:
        pytest.skip(f"{XRDCP_BIN} not found on PATH")


def _anon_env() -> dict:
    env = os.environ.copy()
    for key in (
        "X509_CERT_DIR",
        "X509_USER_PROXY",
        "X509_USER_CERT",
        "X509_USER_KEY",
        "XrdSecPROTOCOL",
        "XRD_SECPROTOCOL",
    ):
        env.pop(key, None)
    return env


def _remote(test_env, name: str) -> str:
    return f"{test_env['anon_url']}//{name}"


def _run_xrdcp(args, *, timeout=120):
    return subprocess.run(
        [XRDCP_BIN, "-s", *args],
        env=_anon_env(),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=timeout,
    )


def _assert_xrdcp_ok(result):
    if result.returncode == 0:
        return

    stdout = result.stdout.decode(errors="replace")
    stderr = result.stderr.decode(errors="replace")
    pytest.fail(
        f"xrdcp failed with rc={result.returncode}\n"
        f"command: {result.args!r}\n"
        f"stdout:\n{stdout}\n"
        f"stderr:\n{stderr}\n"
    )


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def _write_pattern(path: Path, size: int):
    block = bytes((idx * 37 + 11) & 0xFF for idx in range(1024 * 1024))
    remaining = size

    with path.open("wb") as fh:
        while remaining > 0:
            n = min(len(block), remaining)
            fh.write(block[:n])
            remaining -= n


def _access_log_path(test_env) -> Path:
    return Path(test_env["log_dir"]) / "xrootd_access_anon.log"


def _count_access_log(test_env, needle: str) -> int:
    path = _access_log_path(test_env)
    if not path.exists():
        return 0

    return path.read_text(errors="replace").count(needle)


def _tail_access_log(test_env, lines: int = 80) -> str:
    path = _access_log_path(test_env)
    if not path.exists():
        return "<access log missing>"

    return "\n".join(path.read_text(errors="replace").splitlines()[-lines:])


@pytest.fixture(autouse=True)
def cleanup_client_option_artifacts(test_env):
    yield

    data_dir = Path(test_env["data_dir"])
    for child in data_dir.iterdir():
        if not child.name.startswith(PREFIX):
            continue
        if child.is_dir() and not child.is_symlink():
            shutil.rmtree(child)
        else:
            child.unlink(missing_ok=True)


def test_xrdcp_streams_uses_secondary_bind_and_round_trips(test_env, tmp_path):
    """xrdcp --streams should complete and attach secondary data channels."""
    _require_xrdcp()

    size = int(os.environ.get("XRDCP_STREAM_TEST_SIZE", DEFAULT_STREAM_TEST_SIZE))
    local_src = tmp_path / "streams-src.bin"
    local_out = tmp_path / "streams-out.bin"
    remote_name = f"{PREFIX}streams.bin"
    remote_url = _remote(test_env, remote_name)

    _write_pattern(local_src, size)
    expected_hash = _sha256(local_src)
    bind_before = _count_access_log(test_env, '"BIND - -" OK')

    put = _run_xrdcp(
        ["-f", "--streams", "4", str(local_src), remote_url],
        timeout=240,
    )
    _assert_xrdcp_ok(put)

    get = _run_xrdcp(
        ["-f", "--streams", "4", remote_url, str(local_out)],
        timeout=240,
    )
    _assert_xrdcp_ok(get)

    assert _sha256(local_out) == expected_hash

    bind_after = _count_access_log(test_env, '"BIND - -" OK')
    assert bind_after > bind_before, (
        "xrdcp --streams completed without any kXR_bind access-log entries; "
        "the transfer may have fallen back to a single primary connection.\n"
        f"access log tail:\n{_tail_access_log(test_env)}"
    )


def test_xrdcp_parallel_multi_file_uploads(test_env, tmp_path):
    """xrdcp --parallel should upload several files in one client invocation."""
    _require_xrdcp()

    remote_dir = f"{PREFIX}parallel"
    remote_disk_dir = Path(test_env["data_dir"]) / remote_dir
    remote_disk_dir.mkdir()

    sources = []
    for idx, size in enumerate((257, 4096, 1024 * 1024 + 17)):
        path = tmp_path / f"parallel-{idx}.dat"
        _write_pattern(path, size)
        sources.append(path)

    result = _run_xrdcp(
        [
            "-f",
            "--parallel",
            "3",
            *(str(path) for path in sources),
            _remote(test_env, f"{remote_dir}/"),
        ],
        timeout=120,
    )
    _assert_xrdcp_ok(result)

    for src in sources:
        dest = remote_disk_dir / src.name
        assert dest.exists(), f"{dest} was not uploaded"
        assert _sha256(dest) == _sha256(src)


def test_xrdcp_posc_upload_with_adler32_checksum_verification(test_env, tmp_path):
    """xrdcp --posc plus --cksum should verify against server checksum query."""
    _require_xrdcp()

    local_src = tmp_path / "posc-cksum.bin"
    remote_name = f"{PREFIX}posc_cksum.bin"
    _write_pattern(local_src, 2 * 1024 * 1024 + 123)

    result = _run_xrdcp(
        [
            "-f",
            "--posc",
            "--cksum",
            "adler32:source",
            str(local_src),
            _remote(test_env, remote_name),
        ],
        timeout=120,
    )
    _assert_xrdcp_ok(result)

    remote_disk = Path(test_env["data_dir"]) / remote_name
    assert remote_disk.exists()
    assert _sha256(remote_disk) == _sha256(local_src)


def test_xrdcp_posc_upload_with_crc32c_checksum_verification(test_env, tmp_path):
    """xrdcp --posc plus --cksum crc32c should verify against kXR_Qcksum."""
    _require_xrdcp()

    local_src = tmp_path / "posc-crc32c.bin"
    remote_name = f"{PREFIX}posc_crc32c.bin"
    _write_pattern(local_src, 1024 * 1024 + 321)

    result = _run_xrdcp(
        [
            "-f",
            "--posc",
            "--cksum",
            "crc32c:source",
            str(local_src),
            _remote(test_env, remote_name),
        ],
        timeout=120,
    )
    _assert_xrdcp_ok(result)

    remote_disk = Path(test_env["data_dir"]) / remote_name
    assert remote_disk.exists()
    assert _sha256(remote_disk) == _sha256(local_src)


def test_xrdcp_continue_resumes_partial_download(test_env, tmp_path):
    """xrdcp --continue should resume reading from an existing local partial."""
    _require_xrdcp()

    remote_name = f"{PREFIX}continue.bin"
    remote_disk = Path(test_env["data_dir"]) / remote_name
    local_out = tmp_path / "continue-out.bin"
    total_size = 3 * 1024 * 1024 + 333
    partial_size = 1024 * 1024 + 77

    _write_pattern(remote_disk, total_size)
    with remote_disk.open("rb") as src, local_out.open("wb") as dst:
        dst.write(src.read(partial_size))

    result = _run_xrdcp(
        ["--continue", _remote(test_env, remote_name), str(local_out)],
        timeout=120,
    )
    _assert_xrdcp_ok(result)

    assert _sha256(local_out) == _sha256(remote_disk)


def test_xrdcp_recursive_upload(test_env, tmp_path):
    """xrdcp --recursive should create and populate a remote directory tree."""
    _require_xrdcp()

    local_tree = tmp_path / "recursive-src"
    nested = local_tree / "subdir"
    nested.mkdir(parents=True)
    _write_pattern(local_tree / "one.dat", 1234)
    _write_pattern(nested / "two.dat", 4321)

    remote_parent = f"{PREFIX}recursive"
    remote_parent_disk = Path(test_env["data_dir"]) / remote_parent
    remote_parent_disk.mkdir()

    result = _run_xrdcp(
        [
            "-f",
            "--recursive",
            str(local_tree),
            _remote(test_env, f"{remote_parent}/"),
        ],
        timeout=120,
    )
    _assert_xrdcp_ok(result)

    remote_tree = remote_parent_disk / local_tree.name
    assert _sha256(remote_tree / "one.dat") == _sha256(
        local_tree / "one.dat"
    )
    assert _sha256(remote_tree / "subdir" / "two.dat") == _sha256(
        nested / "two.dat"
    )
