"""PAL ownership must preserve the server and native-client storage seams.

These are source fixtures in an isolated temporary tree. No live source file
or server is changed while checking accepted owners and rejected bypasses.
"""

from pathlib import Path

import pytest

from _test_ci_guards_helpers import _load

SEAM = _load("check_vfs_seam")


@pytest.fixture()
def source_tree(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    return tmp_path


def _source(root, name, body):
    path = root / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(body + "\n", encoding="utf-8")


@pytest.mark.parametrize("path,body", [
    ("src/fs/backend/posix.c", "return pread(fd, buf, len, off);"),
    ("src/platform/linux/posix_wrapper.c",
     "return sendfile(out, fd, off, len); "
     "/* vfs-seam-allow: SEAM_CORRECT - PAL storage implementation */"),
    ("src/platform/darwin/copy_range.c",
     "brix_platform_copy_range(in, off, out, off, len, flags);"),
    ("src/protocols/webdav/get.c", "return brix_vfs_pread_full(f, b, n, off);"),
])
def test_storage_owners_and_vfs_calls_pass(source_tree, path, body):
    _source(source_tree, path, body)
    assert SEAM.current_raw_tier1() == []
    assert SEAM.current_bypasses() == []


@pytest.mark.parametrize("marker", [
    "", "/* vfs-seam-allow: NOT_STORAGE - unsupported byte exemption */",
    "/* vfs-seam-allow: SEAM_CORRECT_MISSPELLED - malformed */",
])
def test_pal_raw_byte_call_requires_exact_owner_marker(source_tree, marker):
    _source(source_tree, "src/platform/linux/posix_wrapper.c",
            "return sendfile(out, fd, off, len); " + marker)
    assert len(SEAM.current_raw_tier1()) == 1


@pytest.mark.parametrize("path", [
    "src/protocols/webdav/get.c", "src/platform/linux/unreviewed.c",
    "src/platform/linux/posix_wrapper.c_extra.c",
])
def test_marker_cannot_grant_raw_bytes_to_other_files(source_tree, path):
    _source(source_tree, path, "return pread(fd, buf, len, off); "
            "/* vfs-seam-allow: SEAM_CORRECT - claimed ownership */")
    assert len(SEAM.current_raw_tier1()) == 1


@pytest.mark.parametrize("symbol", [
    "brix_plat_sendfile", "brix_platform_sendfile", "brix_plat_copy_range",
    "brix_platform_copy_range", "brix_plat_copy_range_apple",
])
@pytest.mark.parametrize("path,checker", [
    ("src/protocols/webdav/get.c", SEAM.current_raw_tier1),
    ("client/apps/copy.c", SEAM.current_raw_client),
])
def test_pal_alias_cannot_bypass_byte_storage_seam(
    source_tree, symbol, path, checker
):
    _source(source_tree, path, f"return {symbol}(fd, buf, len, off);")
    assert len(checker()) == 1


@pytest.mark.parametrize("symbol", [
    "brix_plat_getxattr", "brix_plat_fsetxattr", "brix_plat_flistxattr",
    "brix_plat_removexattr", "brix_plat_clonefile", "brix_plat_get_clone_stats",
    "brix_apple_clonefile", "brix_apple_clonefileat",
])
def test_pal_metadata_alias_requires_vfs_in_handler(source_tree, symbol):
    _source(source_tree, "src/protocols/webdav/props.c",
            f"return {symbol}(path, name, value);")
    assert len(SEAM.current_bypasses()) == 1


def test_pal_metadata_implementation_and_backend_pass(source_tree):
    for path in ("src/platform/linux/posix_wrapper.c", "src/fs/backend/posix.c"):
        _source(source_tree, path, "brix_plat_getxattr(path, name, buf, size);")
    assert SEAM.current_bypasses() == []


def test_pal_alias_mentions_in_comments_are_ignored(source_tree):
    _source(source_tree, "src/protocols/webdav/get.c",
            "/* brix_plat_copy_range(fd, off, out, off, len, flags); */")
    assert SEAM.current_raw_tier1() == []


def test_backlogs_remain_closed():
    root = Path(__file__).resolve().parents[1]
    for name in (SEAM.BACKLOG, SEAM.BACKLOG_NS, SEAM.BACKLOG_CLIENT):
        assert SEAM._backlog_patterns(root / name) == []
