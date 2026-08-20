"""Python ports for object-linked C regression shell runners."""

from __future__ import annotations

from collections.abc import Iterable
from pathlib import Path
import os
import shutil
import subprocess
import tempfile

from cmdscripts.compile_run import REPO_ROOT, result, run


DEFAULT_NGX_SRC = Path(os.environ.get(
    "NGX_SRC",
    "/tmp/nginx-1.28.3" if Path("/tmp/nginx-1.28.3/src/core/ngx_config.h").exists()
    else "/tmp/nginx-1.24.0",
))
TEST_C = REPO_ROOT / "tests" / "c"


def staged_contract_origin(base: Path, ngx_src: Path = DEFAULT_NGX_SRC) -> tuple[bool, str]:
    """Same ownership contract for the ORIGIN-side publishers: sd_http (PUT),
    sd_xroot (Mode-A write-through) and the sd_cache forwarding slots. These three
    obey it today — the unit pins it per driver, over a scripted fake transport and
    stubbed origin wire calls, under ASan. See test_staged_contract_origin.c."""
    # sd_http_redirect.o + url.o come along for select.o's D1.4 redirect kernel.
    names = ["sd_http.o", "sd_http_select.o", "sd_http_read.o", "sd_http_write.o",
             "sd_http_dir.o", "sd_http_mutate.o", "sd_http_redirect.o",
             "url.o", "sd_xroot_staged.o", "sd_cache_forward.o"]
    objs: list[Path] = []
    for name in names:
        obj = _find_obj(ngx_src, name)
        if obj is None:
            return result(True, f"SKIP: build first; missing {name}")
        objs.append(obj)
    return _compile_and_run(
        base / "test_staged_contract_origin",
        [
            "-O1",
            "-g",
            "-D_GNU_SOURCE",
            "-fsanitize=address",
            "-fno-omit-frame-pointer",
            "-Wall",
            *_nginx_includes(ngx_src, http=True, stream=True),
            str(TEST_C / "test_staged_contract_origin.c"),
            *[str(obj) for obj in objs],
            "-lssl",
            "-lcrypto",
        ],
    )


def shared_thread_pool(base: Path, ngx_src: Path = DEFAULT_NGX_SRC) -> tuple[bool, str]:
    """brix_shared_thread_pool() lazy-resolve contract: a per-location common
    loc-conf (thread_pool NULL after postconfig) still resolves + caches its
    async pool by name, so WebDAV TPC/PUT offload instead of running sync. The
    helper is a header-only static inline, so only the test TU compiles (nginx
    ngx_thread_pool_get / ngx_cycle are stubbed). See test_shared_thread_pool.c."""
    return _compile_and_run(
        base / "test_shared_thread_pool",
        [
            "-O1",
            "-g",
            "-D_GNU_SOURCE",
            "-Wall",
            *_nginx_includes(ngx_src, http=True),
            str(TEST_C / "test_shared_thread_pool.c"),
        ],
    )


def chunk_geometry(base: Path, ngx_src: Path = DEFAULT_NGX_SRC) -> tuple[bool, str]:
    """brix_chunk_geometry wire-frame split contract at the phase-33 P3-B1
    BRIX_READ_CHUNK_MAX (32 MiB): ceil-divide, exact-boundary, zero-remainder
    remap, and the request-max header-budget invariant.  Links the real
    buffers.o so the shipped constant is exercised; the 6 sibling symbols
    buffers.o pulls in are stubbed (geometry calls none). See
    test_chunk_geometry.c."""
    obj = _need_obj(ngx_src, "objs/addon/aio/buffers.o")
    if isinstance(obj, str):
        return result(True, obj)
    stub = base / "chunk_geometry_stubs.c"
    stub.write_text(
        "#include <ngx_config.h>\n#include <ngx_core.h>\n"
        "void ngx_log_error_core(ngx_uint_t l, ngx_log_t *lg, ngx_err_t e,\n"
        "    const char *f, ...){(void)l;(void)lg;(void)e;(void)f;}\n"
    )
    return _compile_and_run(
        base / "test_chunk_geometry",
        [
            "-O",
            "-g",
            "-D_GNU_SOURCE",
            "-Wall",
            *_nginx_includes(ngx_src),
            str(TEST_C / "test_chunk_geometry.c"),
            str(obj),
            str(stub),
        ],
    )


def mu_unit(base: Path, ngx_src: Path = DEFAULT_NGX_SRC) -> tuple[bool, str]:
    return _compile_and_run(
        base / "idmap_collapse_test",
        [
            "-O2",
            "-D_GNU_SOURCE",
            "-Wall",
            "-Wextra",
            *_nginx_includes(ngx_src),
            str(TEST_C / "idmap_collapse_test.c"),
            str(REPO_ROOT / "src/auth/impersonate/idmap.c"),
            str(REPO_ROOT / "src/auth/impersonate/idmap_denylist.c"),
            str(REPO_ROOT / "src/auth/impersonate/idmap_gridmap.c"),
        ],
    )


def fd_kind(base: Path) -> tuple[bool, str]:
    return _compile_and_run(
        base / "fd_kind_test",
        [
            "-O",
            "-Wall",
            "-Wextra",
            str(TEST_C / "fd_kind_test.c"),
            str(REPO_ROOT / "src/core/aio/fd_kind.c"),
        ],
    )


def stage_reconcile(base: Path, ngx_src: Path = DEFAULT_NGX_SRC) -> tuple[bool, str]:
    obj = _need_obj(ngx_src, "objs/addon/xfer/stage_engine.o")
    journal = _need_obj(ngx_src, "objs/addon/xfer/stage_engine_journal.o")
    reconcile = _need_obj(ngx_src, "objs/addon/xfer/stage_engine_reconcile.o")
    if isinstance(obj, str):
        return result(True, obj)
    if isinstance(journal, str) or isinstance(reconcile, str):
        return result(True, journal if isinstance(journal, str) else reconcile)
    return _compile_and_run(
        base / "test_stage_reconcile",
        ["-O", "-Wall", *_nginx_includes(ngx_src), str(TEST_C / "test_stage_reconcile_nullcycle.c"), str(obj), str(journal), str(reconcile)],
    )


def compression(base: Path) -> tuple[bool, str]:
    proto = REPO_ROOT / "shared/xrdproto/libxrdproto.a"
    zip_c = REPO_ROOT / "client/lib/protocols/shared/zip.c"
    zip_write_c = REPO_ROOT / "client/lib/protocols/shared/zip_write.c"
    zip_kernel_c = REPO_ROOT / "src/protocols/root/zip/zip_kernel.c"
    if not proto.exists():
        return result(True, f"SKIP: {proto} not found; build client/shared lib first")
    lz4_cflags = run(["pkg-config", "--cflags", "liblz4"], cwd=REPO_ROOT).stdout.split()
    codec_libs = ["-lz", "-lzstd", "-llzma", "-lbrotlienc", "-lbrotlidec", "-lbz2", "-l:liblz4.so.1", "-lcrypto"]
    cm = REPO_ROOT / "src/core/compat"
    zip_write_current = base / "zip_write_test.current.c"
    zip_write_src = (TEST_C / "zip_write_test.c").read_text()
    zip_write_src = zip_write_src.replace(
        'w = brix_zip_writer_new_append(membuf_write, &app_arc, cd_off,\n'
        '                                       seed, (size_t) cd_size, (size_t) n);',
        'brix_zip_seed zs = { seed, (size_t) cd_size, (size_t) n };\n'
        '        w = brix_zip_writer_new_append(membuf_write, &app_arc, cd_off,\n'
        '                                       &zs);',
    )
    zip_write_current.write_text(zip_write_src)
    jobs = [
        ("codec_test", ["-I", str(cm), str(TEST_C / "codec_test.c"), str(proto), *codec_libs]),
        ("codec_edge_test", ["-I", str(cm), str(TEST_C / "codec_edge_test.c"), str(proto), *codec_libs]),
        (
            "zcrc32_test",
            [
                "-D_GNU_SOURCE",
                "-I",
                str(cm),
                *_nginx_includes(DEFAULT_NGX_SRC),
                str(TEST_C / "zcrc32_test.c"),
                str(proto),
                *codec_libs,
            ],
        ),
        (
            "zip_test",
            [
                "-D_GNU_SOURCE",
                "-I",
                str(REPO_ROOT / "client/lib"),
                "-I",
                str(REPO_ROOT / "client/lib/protocols/shared"),
                "-I",
                str(REPO_ROOT / "src"),
                str(TEST_C / "zip_test.c"),
                str(zip_c),
                str(zip_kernel_c),
                "-lz",
            ],
        ),
        (
            "zip_fuzz_test",
            [
                "-D_GNU_SOURCE",
                "-I",
                str(REPO_ROOT / "client/lib"),
                "-I",
                str(REPO_ROOT / "client/lib/protocols/shared"),
                "-I",
                str(REPO_ROOT / "src"),
                str(TEST_C / "zip_fuzz_test.c"),
                str(zip_c),
                str(zip_kernel_c),
                "-lz",
            ],
        ),
        (
            "zip_write_test",
            [
                "-D_GNU_SOURCE",
                "-I",
                str(REPO_ROOT / "client/lib"),
                "-I",
                str(REPO_ROOT / "client/lib/protocols/shared"),
                "-I",
                str(REPO_ROOT / "src"),
                str(zip_write_current),
                str(zip_c),
                str(zip_write_c),
                str(zip_kernel_c),
                "-lz",
            ],
        ),
        (
            "codec_nolib_test",
            [
                "-DBRIX_HAVE_ZLIB",
                "-I",
                str(cm),
                str(TEST_C / "codec_nolib_test.c"),
                str(cm / "codec_core.c"),
                str(cm / "codec_zlib.c"),
                str(cm / "codec_zstd.c"),
                str(cm / "codec_lzma.c"),
                str(cm / "codec_brotli.c"),
                str(cm / "codec_bzip2.c"),
                str(cm / "codec_lz4.c"),
                "-lz",
            ],
        ),
    ]
    for name, args in jobs:
        if name == "zip_write_test" and shutil.which("unzip") is None:
            continue
        check = _compile_and_run(base / name, ["-std=c11", "-O2", "-Wall", "-Wextra", *lz4_cflags, *args])
        if not check[0]:
            return result(False, f"{name}: {check[1]}")
    return result(True, "ALL COMPRESSION C-UNIT TESTS PASSED")


def sreq_compat(base: Path, ngx_src: Path = DEFAULT_NGX_SRC) -> tuple[bool, str]:
    obj = _need_obj(ngx_src, "objs/addon/xfer/stage_engine.o")
    if isinstance(obj, str):
        return result(True, obj)
    stub = base / "sreq_stubs.c"
    stub.write_text(SREQ_STUB)
    return _compile_and_run(
        base / "test_sreq_compat",
        ["-O", "-Wall", *_nginx_includes(ngx_src), str(TEST_C / "test_sreq_compat.c"), str(obj), str(stub)],
    )


def stage_bearer_thread(base: Path, ngx_src: Path = DEFAULT_NGX_SRC) -> tuple[bool, str]:
    """Token write-back bearer threading: brix_stage_run_inline_cred (the sync
    inline FLUSH the WebDAV/https whole-object gateway uses) presents a live WLCG
    bearer to the destination backend's staged_open_cred, closing the token+https
    write-back gap. Mock src/dst drivers capture the cred the backend receives;
    the four stage_engine.o externals are stubbed in the test. See
    test_stage_bearer_thread.c."""
    obj = _need_obj(ngx_src, "objs/addon/xfer/stage_engine.o")
    if isinstance(obj, str):
        return result(True, obj)
    return _compile_and_run(
        base / "test_stage_bearer_thread",
        ["-O", "-Wall", *_nginx_includes(ngx_src), str(TEST_C / "test_stage_bearer_thread.c"), str(obj)],
    )


def _brix_have_defines(ngx_src: Path) -> list[str]:
    """The -DBRIX_HAVE_*=n feature flags the module was actually built with.

    ngx_brix_metrics_t has feature-gated fields BEFORE `frm` (e.g. the pblock
    counter under BRIX_HAVE_SQLITE), so a unit that reads frm.* by name must see
    the SAME struct layout as the linked object. Mirror the build's flags rather
    than hard-coding, so the test tracks whichever features ./config detected."""
    makefile = ngx_src / "objs" / "Makefile"
    if not makefile.exists():
        return []
    import re
    seen = dict.fromkeys(re.findall(r"-DBRIX_HAVE_[A-Z0-9_]+=[0-9]+", makefile.read_text()))
    return list(seen)


def frm_stage_metrics(base: Path, ngx_src: Path = DEFAULT_NGX_SRC) -> tuple[bool, str]:
    # O-1: the durable stage-request registry lifecycle drives the brix_frm_*
    # tape-stage counters. Link the substrate + the instrumented mutate ops +
    # crc32c (record CRC) + ngx_string (ngx_cpystrn/ngx_snprintf); the test
    # supplies the POSIX SD driver stub, the fake SHM zone, and nginx doubles.
    mutate = _need_obj(ngx_src, "objs/addon/xfer/stage_request_registry_mutate.o")
    subst = _need_obj(ngx_src, "objs/addon/xfer/stage_request_registry.o")
    crc = _need_obj(ngx_src, "objs/addon/compat/crc32c.o")
    crchw = _need_obj(ngx_src, "objs/addon/compat/crc32c_hw.o")
    ngxstr = _need_obj(ngx_src, "objs/src/core/ngx_string.o")
    for dep in (mutate, subst, crc, crchw, ngxstr):
        if isinstance(dep, str):
            return result(True, dep)
    return _compile_and_run(
        base / "test_frm_stage_metrics",
        [
            "-O", "-Wall",
            *_brix_have_defines(ngx_src),
            *_nginx_includes(ngx_src),
            str(TEST_C / "test_frm_stage_metrics.c"),
            str(mutate), str(subst), str(crc), str(crchw), str(ngxstr),
            "-pthread",
        ],
    )


def tpc_progress_total(base: Path, ngx_src: Path = DEFAULT_NGX_SRC) -> tuple[bool, str]:
    # O-2: brix_tpc_progress_emit threads bytes_total through to the registry.
    # Link the real registry.o; the test doubles the shm-slot + shmtx surface so
    # the module's own shm_init runs over a heap-backed slot table.
    reg = _need_obj(ngx_src, "objs/addon/common/registry.o")
    prog = _need_obj(ngx_src, "objs/addon/common/progress.o")
    for dep in (reg, prog):
        if isinstance(dep, str):
            return result(True, dep)
    return _compile_and_run(
        base / "test_tpc_progress_total",
        [
            "-O", "-Wall",
            *_nginx_includes(ngx_src, stream=True),
            str(TEST_C / "test_tpc_progress_total.c"),
            str(reg), str(prog),
        ],
    )


def tier_s3_creds(base: Path, ngx_src: Path = DEFAULT_NGX_SRC) -> tuple[bool, str]:
    # F2: brix_tier_s3_apply_creds() copies a tier credential's static S3 keys
    # into the remote-origin conf. Link tier_build.o; the test doubles the whole
    # SD-factory closure (none of it is reached by the credential-copy helper).
    obj = _need_obj(ngx_src, "objs/addon/tier/tier_build.o")
    if isinstance(obj, str):
        return result(True, obj)
    return _compile_and_run(
        base / "test_tier_s3_creds",
        [
            "-O", "-Wall",
            *_nginx_includes(ngx_src),
            str(TEST_C / "test_tier_s3_creds.c"),
            str(obj),
        ],
    )


# Object closure every sd_remote unit links: the driver, its S3 transport and
# the crypto/format leaves the signer reaches. sd_s3_sign_ext.o carries
# sd_s3_sign_ext(), which sd_s3_meta.c calls for the extended-header signature —
# it lands in sd_remote.o's rodata slots, so the link needs it even when the
# test never signs anything. Kept in one place: five runners share it, and a
# per-runner copy is how sd_s3_sign_ext.o went missing from exactly one of them.
SD_REMOTE_OBJS = [
    "sd_remote.o", "sd_remote_meta.o", "sd_remote_xattr.o", "sd_remote_write.o",
    "sd_remote_dir.o",
    "sd_s3.o", "sd_s3_meta.o", "sd_s3_list.o", "meta_advisory.o", "sd_s3_write.o",
    "sd_s3_sign.o", "sd_s3_sign_ext.o", "crypto.o", "hex.o", "sigv4.o", "uri.o",
    "host_format.o", "crc32_ieee.o",
]


def sd_remote_wrongkind(base: Path, ngx_src: Path = DEFAULT_NGX_SRC) -> tuple[bool, str]:
    # sd_remote's getxattr/listxattr path (S3 x-amz-meta passthrough) pulls in
    # sd_s3_meta.o, which in turn needs meta_advisory.o for the advisory
    # encode/decode helpers — both were added when S3 listxattr landed but were
    # never reflected in this hand-maintained object closure. sd_remote_dir.o
    # closes sd_remote's dir slots (opendir/readdir -> sd_s3_list_page in
    # sd_s3_list.o); the whole closure now lives in SD_REMOTE_OBJS.
    names = SD_REMOTE_OBJS
    objs: list[Path] = []
    for name in names:
        obj = _find_obj(ngx_src, name)
        if obj is None:
            return result(True, f"SKIP: build first; missing {name}")
        objs.append(obj)
    return _compile_and_run(
        base / "test_sd_remote_wrongkind",
        ["-O", "-Wall", str(TEST_C / "test_sd_remote_wrongkind.c"), *[str(obj) for obj in objs], *_nginx_includes(ngx_src), "-lssl", "-lcrypto"],
    )


