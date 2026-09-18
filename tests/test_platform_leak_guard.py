"""OS-specific branches live only behind the PAL (tools/ci/check_platform_leak.py).

The guard is exercised against source fixtures in a temporary tree, so no live
source file is edited. The last tests run the real guard on the real tree.
"""

import re
from pathlib import Path

import pytest

from _test_ci_guards_helpers import _load

GUARD = _load("check_platform_leak")
ROOT = Path(__file__).resolve().parents[1]


def _source(root: Path, name: str, body: str) -> None:
    path = root / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(body + "\n", encoding="utf-8")


@pytest.fixture()
def tree(tmp_path: Path) -> Path:
    for name in GUARD.SCAN_DIRS:
        (tmp_path / name).mkdir()
    return tmp_path


def _hits(root: Path) -> dict[str, list[tuple[int, str]]]:
    return GUARD.scan(root)


# --- success: what the seam allows ------------------------------------------

@pytest.mark.parametrize("path,body", [
    ("src/platform/darwin/posix_wrapper.c",
     "#if defined(__APPLE__) && defined(__MACH__)\n#include <sys/xattr.h>\n#endif"),
    ("src/platform/darwin/host_posix.h", "#include <sys/xattr.h>\n#include <libkern/OSByteOrder.h>"),
    ("src/platform/linux/host_posix.h", "#if BRIX_PLATFORM_LINUX\n#include <endian.h>\n#endif"),
    ("src/platform/linux/event_wrapper.c", "#include <sys/epoll.h>"),
    ("src/platform/windows/xattr.c", "#ifdef _WIN32\n#include <windows.h>\n#endif"),
    ("client/lib/platform/darwin/epoll.c", "#ifdef __APPLE__\n#include <sys/event.h>\n#endif"),
    ("client/lib/platform/linux/host.h", "#include <sys/epoll.h>"),
    ("shared/cvmfs/platform/platform.c", "#ifdef __linux__\nint y;\n#endif"),
])
def test_owner_directories_may_branch_on_the_host(tree: Path, path: str, body: str) -> None:
    _source(tree, path, body)
    assert _hits(tree) == {}
    assert GUARD.main(["--root", str(tree)]) == 0


@pytest.mark.parametrize("body", [
    "/* Darwin has no <endian.h>; see __APPLE__ in the PAL */\nint z;",
    "// #ifdef __linux__ used to live here\nint z;",
    'const char *why = "built for __APPLE__ with <sys/xattr.h>";',
    "#include \"platform/platform_api.h\"\nint r(void) { return brix_plat_random(0, 0); }",
    "#include \"platform/platform_api.h\"\nint v = brix_plat_openat2(fd, rel, 0, 0, RESOLVE_BENEATH);",
    "#include \"platform/platform_api.h\"\n#if BRIX_HAS_SPLICE\nint s;\n#endif",
    "#define BRIX_CRED_STAGE_BASE BRIX_PLAT_SHM_DIR \"/brix-creds\"",
])
def test_portable_callers_feature_gates_and_prose_are_not_hits(tree: Path, body: str) -> None:
    _source(tree, "src/fs/vfs/vfs_xattr.c", body)
    _source(tree, "client/lib/fs/overlay.c", body)
    assert _hits(tree) == {}


def test_unit_tests_are_outside_the_seam(tree: Path) -> None:
    _source(tree, "src/fs/path/beneath_unittest.c", "#ifdef __APPLE__\nint t;\n#endif")
    assert _hits(tree) == {}


# --- error: what the seam rejects --------------------------------------------

@pytest.mark.parametrize("path,body,token", [
    ("src/fs/path/beneath.c", "#if defined(__APPLE__) && defined(__MACH__)\n#endif", "__APPLE__"),
    ("src/core/config/shared_conf.h", "#ifdef __linux__\n#endif", "__linux__"),
    ("src/net/proxy/events_read.c", "#if BRIX_PLATFORM_DARWIN\n#endif", "BRIX_PLATFORM_DARWIN"),
    ("src/fs/cache/cinfo.c", "#include <sys/xattr.h>", "<sys/xattr.h>"),
    ("src/fs/backend/posix/sd_posix.c", "#include <linux/fs.h>", "<linux/fs.h>"),
    ("src/tpc/outbound/tpc_token.c", "#ifdef _WIN32\n#endif", "_WIN32"),
    ("src/core/aio/uring_bringup.c", "#include <sys/eventfd.h>", "<sys/eventfd.h>"),
    ("client/lib/core/aio/epoll_compat.h", "#include <sys/event.h>", "<sys/event.h>"),
    ("client/lib/brix.h", "#if defined(__APPLE__) && !defined(MSG_NOSIGNAL)\n#endif", "__APPLE__"),
    ("client/apps/ceph/xrdceph_migrate.cpp", "#ifdef __linux__\n#endif", "__linux__"),
    ("shared/compat/endian_compat.h", "#include <libkern/OSByteOrder.h>", "<libkern/OSByteOrder.h>"),
    ("shared/oci/tar.c", "#include <sys/sysmacros.h>", "<sys/sysmacros.h>"),
])
def test_host_branch_outside_an_owner_fails(tree: Path, path: str, body: str, token: str) -> None:
    _source(tree, path, body)
    hits = _hits(tree)
    assert list(hits) == [path]
    assert token in [t for _, t in hits[path]]
    problems = GUARD.violations(hits)
    assert len(problems) == 1 and path in problems[0] and "owner" in problems[0]
    assert GUARD.main(["--root", str(tree)]) == 1


@pytest.mark.parametrize("body,bad", [
    ("return (inst->driver->getxattr)(inst, path, name, buf, cap);", False),
    ("n = (D->listxattr)(inst, p, buf, sizeof(buf));", False),
    ("return inst->driver->getxattr(inst, path, name, buf, cap);", True),
    ("(void) store->driver->removexattr(store, key, name);", True),
    ("rc = drv.fsetxattr(fd, n, v, s, f);", True),
    ("/* driver->getxattr(inst, ...) is the slot */\nint z;", False),
])
def test_xattr_member_calls_must_be_parenthesised(tree: Path, body: str, bad: bool) -> None:
    _source(tree, "src/fs/backend/sd_cred_forward.h", body)
    hits = _hits(tree)
    assert bool(hits) is bad
    if bad:
        assert "unparenthesised member call" in hits["src/fs/backend/sd_cred_forward.h"][0][1]


def test_every_leaking_file_is_reported_not_just_the_first(tree: Path) -> None:
    _source(tree, "src/fs/a.c", "#ifdef __APPLE__\n#endif")
    _source(tree, "client/lib/b.c", "#ifdef __linux__\n#endif")
    _source(tree, "shared/oci/c.c", "#include <endian.h>")
    assert sorted(_hits(tree)) == ["client/lib/b.c", "shared/oci/c.c", "src/fs/a.c"]
    assert len(GUARD.violations(_hits(tree))) == 3


def test_missing_production_tree_fails_loudly(tmp_path: Path) -> None:
    (tmp_path / "src").mkdir()
    assert GUARD.main(["--root", str(tmp_path)]) == 1


# --- security-neg: no way to smuggle a branch past the seam ------------------

@pytest.mark.parametrize("path", [
    "src/platform/platform_api_posix.h",      # the interface is host-free
    "src/platform/platform.h",
    "src/platform/platform_runtime.c",
    "client/lib/platform/platform.h",         # the client umbrella too
    "src/platform_helpers/darwin.c",          # prefix collision with an owner
    "src/fs/platform/darwin/open.c",          # owner-shaped path in the wrong tree
    "client/apps/platform/darwin/mount.c",    # client owner is client/lib/platform only
    "shared/platform/darwin/endian.c",        # shared owner is shared/cvmfs/platform only
    "shared/compat/xattr_compat.h",           # the deleted shim location is not an owner
])
def test_owner_lookalike_paths_do_not_own(tree: Path, path: str) -> None:
    _source(tree, path, "#ifdef __APPLE__\nint a;\n#endif")
    assert list(_hits(tree)) == [path]


@pytest.mark.parametrize("body", [
    "#ifdef __APPLE__ /* pal-seam-allow: reviewed */\n#endif",
    "#ifdef __APPLE__ /* vfs-seam-allow: SEAM_CORRECT */\n#endif",
    "#  if   defined( __APPLE__ )\n#endif",
    "#define HOST_IS_MAC defined(__APPLE__)",
    "#if __APPLE__ + 0\n#endif",
    "# include<sys/xattr.h>",
    "#include <linux/openat2.h> // portable enough",
    "#if TARGET_OS_MAC\n#endif",
])
def test_no_marker_or_spelling_grants_a_waiver(tree: Path, body: str) -> None:
    _source(tree, "src/fs/path/beneath.c", body)
    assert list(_hits(tree)) == ["src/fs/path/beneath.c"]


def test_guard_has_no_backlog_or_regen_path() -> None:
    """Zero tolerance is structural: nothing to append to, nothing to refreeze."""
    assert not hasattr(GUARD, "read_backlog")
    assert not hasattr(GUARD, "write_backlog")
    assert not (ROOT / "tools/ci/platform_leak_backlog.txt").exists()
    ratchet = _load("check_ratchet_monotonic")
    assert not any("platform_leak" in k for k in ratchet.RATCHETS)


# --- the real tree -------------------------------------------------------------

def test_live_tree_has_no_platform_branch_outside_the_pal() -> None:
    current = GUARD.scan(ROOT)
    assert current == {}, "\n".join(GUARD.violations(current))


def test_owner_roots_are_the_pal_host_directories() -> None:
    expected = {Path("src/platform/linux"), Path("src/platform/darwin"),
                Path("src/platform/windows"), Path("client/lib/platform/linux"),
                Path("client/lib/platform/darwin"), Path("shared/cvmfs/platform")}
    assert set(GUARD.OWNER_ROOTS) == expected


_ALLOWED_INTERFACE_CONDITIONS = ("BRIX_PLATFORM_H", "_ARCH_", "__aarch64__",
                                 "__x86_64__", "BRIX_PLATFORM_HOST")


_CONDITION = re.compile(r"^[ \t]*#[ \t]*(?:if|elif)\b[^\n]*", re.M)


def _host_conditionals(path: Path) -> list[str]:
    """Preprocessor conditions in `path` that name anything but an include
    guard, the CPU architecture or the build-provided host name."""
    conditions = _CONDITION.findall(GUARD.mask_noncode(path.read_text()))
    return [c.strip() for c in conditions
            if not any(a in c for a in _ALLOWED_INTERFACE_CONDITIONS)]


def test_pal_interface_headers_select_the_host_without_conditionals() -> None:
    """platform.h / platform_api*.h and the client umbrella carry no #if on the
    host: one computed include from BRIX_PLATFORM_HOST does the selection."""
    interface = sorted((ROOT / "src/platform").glob("platform*.h")) + \
        [ROOT / "client/lib/platform/platform.h", ROOT / "src/platform/openat2_abi.h"]
    offenders = {p.relative_to(ROOT).as_posix(): _host_conditionals(p) for p in interface}
    assert all(not v for v in offenders.values()), offenders
    assert 'BRIX_PLAT_HOST_HEADER(host.h)' in (ROOT / "src/platform/platform.h").read_text()
