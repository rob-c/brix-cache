"""Darwin workers must reject subprocess-backed features explicitly."""

from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def _read(path: str) -> str:
    return (ROOT / path).read_text(encoding="utf-8")


def test_worker_exec_capability_is_host_explicit() -> None:
    """Success: Linux retains worker exec while hardened Darwin refuses it."""
    assert "#define BRIX_HAS_WORKER_EXEC 1" in _read("src/platform/linux/host.h")
    assert "#define BRIX_HAS_WORKER_EXEC 0" in _read("src/platform/darwin/host.h")
    assert "#define BRIX_HAS_WORKER_EXEC 0" in _read("src/platform/windows/host.h")


def test_darwin_incompatible_configuration_fails_early() -> None:
    """Error: every configured worker-program surface has a host gate."""
    cases = {
        "src/core/config/server_conf_merge_security.c": "brix_prepare_command is unsupported",
        "src/core/config/tape_stage_conf.c": "brix_frm_stagecmd and brix_frm_purge_polprog are unsupported",
        "src/core/config/cms_fsxeq_conf.c": "brix_cms_fsxeq is unsupported",
        "src/core/config/server_conf_merge_cluster.c": "brix_cms_perf_pgm is unsupported",
    }
    for path, diagnostic in cases.items():
        source = _read(path)
        assert "BRIX_HAS_WORKER_EXEC" in source
        assert diagnostic in source


def test_runtime_paths_cannot_reach_exec_on_darwin() -> None:
    """Security-negative: dynamic server modes fail before helper execution."""
    frm = _read("src/fs/backend/frm/sd_frm_adapter.c")
    webdav = _read("src/protocols/webdav/tpc_cred.c")
    root_tpc = _read("src/tpc/outbound/tpc_token.c")
    native = _read("tests/c/darwin_security_fail_closed_test.c")

    assert "if (!BRIX_HAS_WORKER_EXEC)" in frm and "errno = ENOTSUP" in frm
    assert webdav.count("if (!BRIX_HAS_WORKER_EXEC)") >= 2
    assert root_tpc.count("if (!BRIX_HAS_WORKER_EXEC)") >= 2
    assert 'execl("/usr/bin/true"' in native
    assert "errno == EPERM" in native
