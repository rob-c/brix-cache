"""Python ports for object-linked C regression shell runners."""

from __future__ import annotations

from collections.abc import Iterable
from pathlib import Path
import os
import shutil
import subprocess
import tempfile

from cmdscripts.compile_run import REPO_ROOT, result, run
from cmdscripts.command_results import print_results


DEFAULT_NGX_SRC = Path(os.environ.get(
    "NGX_SRC",
    "/tmp/nginx-1.28.3" if Path("/tmp/nginx-1.28.3/src/core/ngx_config.h").exists()
    else "/tmp/nginx-1.24.0",
))
TEST_C = REPO_ROOT / "tests" / "c"


def sd_remote_server_copy(base: Path, ngx_src: Path = DEFAULT_NGX_SRC) -> tuple[bool, str]:
    # driver->server_copy -> sd_remote_server_copy -> sd_s3_copy -> transport.
    # Same object closure as sd_remote_wrongkind (the copy path lives in
    # sd_remote_meta.o + sd_s3_meta.o and signs via sd_s3_sign.o); sd_s3_list.o
    # is pulled in transitively by sd_remote.o's dir slots.
    names = SD_REMOTE_OBJS
    objs: list[Path] = []
    for name in names:
        obj = _find_obj(ngx_src, name)
        if obj is None:
            return result(True, f"SKIP: build first; missing {name}")
        objs.append(obj)
    return _compile_and_run(
        base / "test_sd_remote_server_copy",
        ["-O", "-Wall", str(TEST_C / "test_sd_remote_server_copy.c"), *[str(obj) for obj in objs], *_nginx_includes(ngx_src), "-lssl", "-lcrypto"],
    )


def sd_remote_opendir(base: Path, ngx_src: Path = DEFAULT_NGX_SRC) -> tuple[bool, str]:
    # driver->opendir/readdir/closedir -> sd_remote_opendir -> sd_s3_list_page ->
    # transport. Same object closure as sd_remote_server_copy PLUS sd_s3_list.o
    # (the ListObjectsV2 pager + XML scanner) which the dir slots delegate to.
    names = SD_REMOTE_OBJS
    objs: list[Path] = []
    for name in names:
        obj = _find_obj(ngx_src, name)
        if obj is None:
            return result(True, f"SKIP: build first; missing {name}")
        objs.append(obj)
    return _compile_and_run(
        base / "test_sd_remote_opendir",
        ["-O", "-Wall", str(TEST_C / "test_sd_remote_opendir.c"), *[str(obj) for obj in objs], *_nginx_includes(ngx_src), "-lssl", "-lcrypto"],
    )


def sd_remote_rename(base: Path, ngx_src: Path = DEFAULT_NGX_SRC) -> tuple[bool, str]:
    # driver->mkdir/rename/rename_cred/unlink + directory-aware stat -> the
    # sd_remote namespace-mutation slots (sd_remote_meta.o + sd_remote_write.o)
    # over sd_s3_copy/delete/open_write (sd_s3_meta.o + sd_s3_write.o) and the
    # empty-vs-non-empty child probe (sd_s3_list.o). Same object closure as
    # sd_remote_opendir.
    names = SD_REMOTE_OBJS
    objs: list[Path] = []
    for name in names:
        obj = _find_obj(ngx_src, name)
        if obj is None:
            return result(True, f"SKIP: build first; missing {name}")
        objs.append(obj)
    return _compile_and_run(
        base / "test_sd_remote_rename",
        ["-O", "-Wall", str(TEST_C / "test_sd_remote_rename.c"), *[str(obj) for obj in objs], *_nginx_includes(ngx_src), "-lssl", "-lcrypto"],
    )


def sd_remote_setattr(base: Path, ngx_src: Path = DEFAULT_NGX_SRC) -> tuple[bool, str]:
    # driver->setxattr/removexattr/setattr (+ _cred) -> the sd_remote metadata-
    # mutation slots (sd_remote_xattr.o) which read-merge-write the S3 user-meta
    # set via sd_s3_list_meta/get_meta/set_meta (sd_s3_meta.o) and patch the
    # advisory blob (meta_advisory.o). Same object closure as sd_remote_rename
    # plus sd_remote_xattr.o.
    names = SD_REMOTE_OBJS
    objs: list[Path] = []
    for name in names:
        obj = _find_obj(ngx_src, name)
        if obj is None:
            return result(True, f"SKIP: build first; missing {name}")
        objs.append(obj)
    return _compile_and_run(
        base / "test_sd_remote_setattr",
        ["-O", "-Wall", str(TEST_C / "test_sd_remote_setattr.c"), *[str(obj) for obj in objs], *_nginx_includes(ngx_src), "-lssl", "-lcrypto"],
    )


def sd_http_dir(base: Path, ngx_src: Path = DEFAULT_NGX_SRC) -> tuple[bool, str]:
    # driver->opendir/readdir/closedir (+ opendir_cred) -> sd_http_opendir
    # (sd_http_dir.o) which issues a WebDAV PROPFIND Depth:1 via sd_http_request_fo
    # (sd_http_select.o) and parses the 207 Multistatus. The driver table + create
    # live in sd_http.o; the cred gate/resolver in sd_http_read.o; the staged-PUT
    # slots the table references in sd_http_write.o (its Content-MD5 path pulls
    # EVP_* -> libcrypto). The ngx logging seam is stubbed in the test (instances
    # built log=NULL, so sd_http_live_log short-circuits and nothing logs).
    # select.o also reaches the phase-104 D1.4 redirect kernel (sd_http_redirect.o),
    # which parses the Location with shared/oci/url.c -> url.o, and url.c in turn
    # calls brix_oci_url_authority() -> authority.o (host:port splitting, incl. the
    # bracketed-IPv6 form) -- link it or the object set is one symbol short.
    names = ["sd_http.o", "sd_http_select.o", "sd_http_read.o", "sd_http_write.o",
             "sd_http_dir.o", "sd_http_mutate.o", "sd_http_redirect.o",
             "url.o", "authority.o"]
    objs: list[Path] = []
    for name in names:
        obj = _find_obj(ngx_src, name)
        if obj is None:
            return result(True, f"SKIP: build first; missing {name}")
        objs.append(obj)
    return _compile_and_run(
        base / "test_sd_http_dir",
        ["-O", "-Wall", str(TEST_C / "test_sd_http_dir.c"), *[str(obj) for obj in objs], *_nginx_includes(ngx_src, http=True), "-lssl", "-lcrypto"],
    )


def sd_http_mutate(base: Path, ngx_src: Path = DEFAULT_NGX_SRC) -> tuple[bool, str]:
    # driver->mkdir/rename -> sd_http_mkdir (WebDAV MKCOL) / sd_http_rename (MOVE)
    # in sd_http_write.o, wired into the driver table (sd_http.o) in phase-92 so an
    # http:// export advertises CAP_DIRS_WRITE + CAP_HARD_RENAME. Same link set as
    # sd_http_dir (write.o pulls EVP_* -> libcrypto); the ngx logging seam is
    # stubbed in the test (instances built log=NULL, sd_http_live_log short-circuits).
    # select.o also reaches the phase-104 D1.4 redirect kernel (sd_http_redirect.o),
    # which parses the Location with shared/oci/url.c -> url.o, and url.c in turn
    # calls brix_oci_url_authority() -> authority.o (host:port splitting, incl. the
    # bracketed-IPv6 form) -- link it or the object set is one symbol short.
    names = ["sd_http.o", "sd_http_select.o", "sd_http_read.o", "sd_http_write.o",
             "sd_http_dir.o", "sd_http_mutate.o", "sd_http_redirect.o",
             "url.o", "authority.o"]
    objs: list[Path] = []
    for name in names:
        obj = _find_obj(ngx_src, name)
        if obj is None:
            return result(True, f"SKIP: build first; missing {name}")
        objs.append(obj)
    return _compile_and_run(
        base / "test_sd_http_mutate",
        ["-O", "-Wall", str(TEST_C / "test_sd_http_mutate.c"), *[str(obj) for obj in objs], *_nginx_includes(ngx_src, http=True), "-lssl", "-lcrypto"],
    )


def sd_mkdir_cred_forward(base: Path, ngx_src: Path = DEFAULT_NGX_SRC) -> tuple[bool, str]:
    # brix_sd_mkdir_maybe_cred (src/fs/backend/sd_cred_forward.h) — the mkdir
    # credential-forwarding dispatch that makes the xroot driver's new mkdir_cred
    # slot reachable. Header-only inline over a fake driver: no origin, no network,
    # so it links with no addon objects (only the nginx include path for the SD
    # struct + ngx_inline). Exercises cred+slot -> cred slot, NULL/allow-mode
    # fallback -> plain slot, and the deny-mode security property (fallback_deny +
    # no cred slot -> EACCES, plain never called).
    return _compile_and_run(
        base / "test_sd_mkdir_cred_forward",
        ["-O", "-Wall", str(TEST_C / "test_sd_mkdir_cred_forward.c"), *_nginx_includes(ngx_src)],
    )


def reservation(base: Path, ngx_src: Path = DEFAULT_NGX_SRC) -> tuple[bool, str]:
    # XrdBwm bandwidth-reservation engine (reservation.o) wired in phase-92 to the
    # root:// read-open path. Pure C over libc (snprintf/strcmp) — no ngx runtime —
    # so it links with no stubs. Exercises grant/byte-precise-release, over-budget
    # refusal, and the no-over-commit / no-inflation security properties.
    obj = _find_obj(ngx_src, "reservation.o")
    if obj is None:
        return result(True, "SKIP: build first; missing reservation.o")
    return _compile_and_run(
        base / "test_reservation",
        ["-O", "-Wall", str(TEST_C / "test_reservation.c"), str(obj), *_nginx_includes(ngx_src)],
    )


SRC_GSIFTP = REPO_ROOT / "src" / "fs" / "backend" / "gsiftp"


def gftp_parse(base: Path, ngx_src: Path = DEFAULT_NGX_SRC) -> tuple[bool, str]:
    # Outbound gsiftp:// control-channel reply parser + MLSx fact-line parser
    # (phase-91 Wave-A protocol kernels). Pure C over libc, no ngx runtime and no
    # live server, so it links with no objects/stubs. Exercises single/multiline
    # reply framing, the SSRF-relevant 227/229 address decoders (out-of-range
    # octet + short delimiter-run reject), and MLSx traversal/control-byte name
    # rejection + overflow-size drop.
    return _compile_and_run(
        base / "gftp_parse_test",
        [
            "-O",
            "-Wall",
            "-Wextra",
            "-Werror",
            "-I",
            str(SRC_GSIFTP),
            str(TEST_C / "gftp_parse_test.c"),
            str(SRC_GSIFTP / "gftp_reply.c"),
            str(SRC_GSIFTP / "gftp_mlsx.c"),
        ],
    )


CLIENT = REPO_ROOT / "client"


def cvmfs_url_rewrite(base: Path, ngx_src: Path = DEFAULT_NGX_SRC) -> tuple[bool, str]:
    # The CVMFS mirror URL builders (client/apps/fs/brixcvmfs_transport.c), unit-
    # tested by including the TU and stubbing its ten project externals — no
    # network, no curl handle is ever initialised. Locks in the -Wformat-truncation
    # fix two ways: -Werror under -O2 -D_FORTIFY_SOURCE=2 (the exact shape that
    # warned) makes the warning itself a build failure, and the assertions pin the
    # semantics — a rewrite that would not fit reports "not rewritten" instead of
    # emitting a shortened URL, which would name a different object.
    return _compile_and_run(
        base / "cvmfs_url_rewrite_test",
        [
            "-std=c11",
            "-O2",
            "-D_FORTIFY_SOURCE=2",
            "-Wall",
            "-Wextra",
            "-Werror",
            "-D_GNU_SOURCE",
            "-DXRDPROTO_NO_NGX",
            "-DBRIX_HAVE_KRB5",
            "-DBRIX_HAVE_LIBURING",
            "-I",
            str(CLIENT),
            "-I",
            str(CLIENT / "lib"),
            "-I",
            str(REPO_ROOT / "src"),
            "-I",
            str(REPO_ROOT / "shared"),
            "-I",
            "/usr/include/fuse3",
            str(TEST_C / "cvmfs_url_rewrite_test.c"),
            "-lcurl",
            "-lpthread",
        ],
    )


def oci_parse(base: Path, ngx_src: Path = DEFAULT_NGX_SRC) -> tuple[bool, str]:
    """Compile the standalone OCI challenge, URL, and authority parser contract."""
    del ngx_src
    oci = REPO_ROOT / "shared" / "oci"
    return _compile_and_run(
        base / "oci_parse_test",
        [
            "-std=c11", "-O2", "-Wall", "-Wextra", "-Werror",
            "-I", str(REPO_ROOT / "shared"),
            str(TEST_C / "oci_parse_test.c"),
            str(oci / "challenge.c"),
            str(oci / "url.c"),
            str(oci / "authority.c"),
        ],
    )


RUNNERS = {
    "cache_lock_reclaim": cache_lock_reclaim,
    "flush_deadletter": flush_deadletter,
    "shm_mutex_recovery": shm_mutex_recovery,
    "ratelimit_gauge_reset": ratelimit_gauge_reset,
    "delegation_store": delegation_store,
    "pblock": pblock,
    "mu_unit": mu_unit,
    "chunk_geometry": chunk_geometry,
    "staged_commit_contract": staged_commit_contract,
    "staged_contract_tiers": staged_contract_tiers,
    "staged_contract_origin": staged_contract_origin,
    "shared_thread_pool": shared_thread_pool,
    "fd_kind": fd_kind,
    "stage_reconcile": stage_reconcile,
    "compression": compression,
    "sreq_compat": sreq_compat,
    "stage_bearer_thread": stage_bearer_thread,
    "sd_remote_wrongkind": sd_remote_wrongkind,
    "sd_remote_server_copy": sd_remote_server_copy,
    "sd_remote_opendir": sd_remote_opendir,
    "sd_remote_rename": sd_remote_rename,
    "sd_remote_setattr": sd_remote_setattr,
    "sd_http_dir": sd_http_dir,
    "sd_http_mutate": sd_http_mutate,
    "sd_mkdir_cred_forward": sd_mkdir_cred_forward,
    "reservation": reservation,
    "gftp_parse": gftp_parse,
    "cvmfs_url_rewrite": cvmfs_url_rewrite,
    "oci_parse": oci_parse,
    "frm_stage_metrics": frm_stage_metrics,
    "tpc_progress_total": tpc_progress_total,
    "tpc_xfr_cap": tpc_xfr_cap,
    "tier_s3_creds": tier_s3_creds,
}


def run_checks(base: Path, names: Iterable[str] | None = None) -> list[tuple[bool, str]]:
    results = []
    for name in list(names or RUNNERS):
        runner = RUNNERS.get(name)
        if runner is None:
            results.append(result(False, f"unknown C regression runner: {name}"))
            continue
        work = base / name
        work.mkdir(parents=True, exist_ok=True)
        results.append(runner(work))
    return results


def entry(argv: list[str]) -> int:
    selected = argv or list(RUNNERS)
    with tempfile.TemporaryDirectory(prefix="c_regression.") as tmp:
        results = run_checks(Path(tmp), selected)
    return print_results(results, "c_regression_units")


if __name__ == "__main__":
    from cmdscripts import main

    raise SystemExit(main(entry))
