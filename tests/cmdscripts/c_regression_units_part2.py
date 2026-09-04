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
    # The sd_http closure (SD_HTTP_OBJS) plus the two sibling publishers this
    # contract also pins: sd_xroot's staged leg and the sd_cache forwarders.
    objs = _sd_http_objs(ngx_src, extra=["sd_xroot_staged.o", "sd_cache_forward.o"])
    if isinstance(objs, str):
        return result(True, objs)
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
            *objs,
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


def service_publish(base: Path, ngx_src: Path = DEFAULT_NGX_SRC) -> tuple[bool, str]:
    """phase-108 C10: the domain-gated service-publish verb
    (compat/service_publish.c) over the REAL phase-107 primitives it composes —
    the staged temp + confined durable commit (staged_file.o), the confined
    openat2 layer (beneath.o), the temp-name kernel (tmp_path.o), and the typed
    domain claim + read-only mutation kernel (vfs_policy_domain.o + vfs_policy.o).
    Only the surfaces the normal-server path never reaches are doubled in the
    test TU (impersonation inactive, the chmod broker, the resume hash, the
    metric sink) — so the durable rename, the EROFS export refusal, and the
    short-write reap all run through production code. ASan on the test TU catches
    a torn temp lifecycle. See test_service_publish.c."""
    objs = [
        _need_obj(ngx_src, "objs/addon/compat/service_publish.o"),
        _need_obj(ngx_src, "objs/addon/compat/staged_file.o"),
        _need_obj(ngx_src, "objs/addon/compat/tmp_path.o"),
        _need_obj(ngx_src, "objs/addon/path/beneath.o"),
        _need_obj(ngx_src, "objs/addon/vfs/vfs_policy.o"),
        _need_obj(ngx_src, "objs/addon/vfs/vfs_policy_domain.o"),
    ]
    for dep in objs:
        if isinstance(dep, str):
            return result(True, dep)
    return _compile_and_run(
        base / "test_service_publish",
        [
            "-O1",
            "-g",
            "-D_GNU_SOURCE",
            "-fsanitize=address",
            "-fno-omit-frame-pointer",
            "-Wall",
            *_nginx_includes(ngx_src),
            str(TEST_C / "test_service_publish.c"),
            *[str(o) for o in objs],
            "-ldl",  # dlsym(RTLD_NEXT) for the fsync-ordering interposer
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


def tpc_xfr_cap(base: Path, ngx_src: Path = DEFAULT_NGX_SRC) -> tuple[bool, str]:
    # §6.9: brix_tpc_registry_add's max_active parameter — the explicit
    # concurrency cap (brix_webdav_tpc_xfr). Same real-registry + shm-double
    # scaffolding as tpc_progress_total; drives the cap/refuse/release logic.
    reg = _need_obj(ngx_src, "objs/addon/common/registry.o")
    if isinstance(reg, str):
        return result(True, reg)
    return _compile_and_run(
        base / "test_tpc_xfr_cap",
        [
            "-O", "-Wall",
            *_nginx_includes(ngx_src, stream=True),
            str(TEST_C / "test_tpc_xfr_cap.c"),
            str(reg),
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
            *_nginx_includes(ngx_src, stream=True),
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
# The sd_http driver's link closure, shared by every runner that builds a real
# instance through brix_sd_http_create. The driver TABLE (sd_http.o) names every
# slot, so a runner exercising ONE of them still needs all of their translation
# units — that is why the read/write/dir/mutate objects are here regardless of
# what the test calls. select.o reaches the phase-104 D1.4 redirect kernel
# (sd_http_redirect.o), which parses the Location with shared/oci/url.c -> url.o,
# and url.c calls brix_oci_url_authority() -> authority.o (host:port splitting,
# incl. the bracketed-IPv6 form). sd_http_digest.o is the checksum-offload slot;
# it parses the origin's RFC-3230 Digest reply with the shared grammar
# (digest_header.o -> hex.o), whose base64 decode is nginx's own — see
# SD_HTTP_NGX_OBJS. sd_http_space.o is the RFC-4331 quota slot, which shares
# dir.o's PROPFIND issuer and tag scanner. sd_http_xattr.o + sd_http_xattr_write.o
# are the two halves of the dead-property xattr mapping, and they land here for
# the same reason as the rest: the driver table names their eight slots, so every
# sd_http runner needs them linked whether or not it calls one. Kept in one place:
# five runners share it, and a per-runner copy is how sd_s3_sign_ext.o went
# missing from exactly one of them.
SD_HTTP_OBJS = [
    "sd_http.o", "sd_http_select.o", "sd_http_read.o", "sd_http_readv.o",
    "sd_http_write.o",
    "sd_http_dir.o", "sd_http_mutate.o", "sd_http_redirect.o",
    "sd_http_digest.o", "sd_http_space.o",
    "sd_http_xattr.o", "sd_http_xattr_write.o",
    # The driver TABLE names every slot, so the closure is the whole vtable and
    # not the slots a given test calls: sd_http.o's .rodata references every
    # function it names, and one missing TU is an undefined reference in EVERY
    # sd_http runner at once. sd_http_setattr.o reaches the advisory-attr codec
    # (meta_advisory_sd.o -> meta_advisory.o), which is why those two are here
    # rather than in the setattr runner alone.
    "sd_http_nearline.o", "sd_http_setattr.o",
    "meta_advisory_sd.o", "meta_advisory.o",
    # The Tape REST API answers in JSON, so the nearline TU reaches the shared
    # minimal parser (json_min.o) and its array walker (json_iter.o).
    "json_min.o", "json_iter.o",
    "digest_header.o", "hex.o", "url.o", "authority.o",
]

# nginx's own objects the sd_http closure needs, by path under the nginx tree
# (_find_obj only searches objs/addon). digest_header.c decodes a base64 digest
# value with ngx_decode_base64 rather than carrying a second copy of it, which
# pulls ngx_string.o and its allocator closure. A test that links these must NOT
# define its own ngx_string.c functions — the stub and the real symbol collide.
SD_HTTP_NGX_OBJS = [
    "objs/src/core/ngx_string.o",
    "objs/src/core/ngx_palloc.o",
    "objs/src/os/unix/ngx_alloc.o",
]

def _sd_http_objs(ngx_src: Path, extra: list[str] | None = None) -> list[str] | str:
    """Resolve the sd_http link closure to absolute object paths.

    Returns the argv fragment, or a "SKIP: ..." message when the tree has not
    been built yet (the runners turn that into a skip, not a failure)."""
    out: list[str] = []
    for name in SD_HTTP_OBJS + list(extra or []):
        obj = _find_obj(ngx_src, name)
        if obj is None:
            return f"SKIP: build first; missing {name}"
        out.append(str(obj))
    for rel in SD_HTTP_NGX_OBJS:
        obj = _need_obj(ngx_src, rel)
        if isinstance(obj, str):
            return obj
        out.append(str(obj))
    return out


SD_REMOTE_OBJS = [
    "sd_remote.o", "sd_remote_meta.o", "sd_remote_xattr.o", "sd_remote_write.o",
    "sd_remote_dir.o", "sd_remote_checksum.o", "sd_remote_enum.o",
    # The nearline pair, for the same table-wide reason the sd_http closure
    # carries sd_http_nearline.o: sd_remote.o names recall/residency in .rodata.
    # sd_s3_archive.o is the HEAD-header reader and RestoreObject poster the
    # pair delegates to; meta_advisory_sd.o is reached from sd_remote_xattr.o's
    # setattr, which the table has named since the advisory blob landed.
    "sd_remote_nearline.o", "sd_s3_archive.o", "meta_advisory_sd.o",
    # sd_s3_list.o split when the flat (catalog) lister landed: sd_s3_list_scan.o
    # holds the XML scanner + signed-request plumbing BOTH listers call, so it is
    # in the closure of every sd_remote unit, not just the enumerate one.
    # sd_s3_batch.o: the phase-107 C2 bulk plane (sd_s3_delete_many, one
    # DeleteObjects POST) — reached from sd_remote_write.o's delete_many relay.
    "sd_s3.o", "sd_s3_meta.o", "sd_s3_list.o", "sd_s3_list_scan.o",
    "sd_s3_list_flat.o", "sd_s3_batch.o", "meta_advisory.o", "sd_s3_write.o",
    "sd_s3_sign.o", "sd_s3_sign_ext.o", "crypto.o", "hex.o", "sigv4.o", "uri.o",
    "host_format.o", "crc32_ieee.o", "digest_header.o",
]


def _sd_remote_objs(ngx_src: Path) -> list[str] | str:
    """Resolve the sd_remote link closure to absolute object paths.

    The driver TABLE names every slot, so a new slot widens this closure for
    every runner at once -- sd_remote_checksum.o brought the shared digest
    grammar (digest_header.o) and, through its base64 decode, nginx's own string
    kernel (SD_HTTP_NGX_OBJS). Kept in one place for the same reason the sd_http
    closure is: a per-runner copy is how an object went missing from exactly one
    of them before."""
    out: list[str] = []
    for name in SD_REMOTE_OBJS:
        obj = _find_obj(ngx_src, name)
        if obj is None:
            return f"SKIP: build first; missing {name}"
        out.append(str(obj))
    for rel in SD_HTTP_NGX_OBJS:
        obj = _need_obj(ngx_src, rel)
        if isinstance(obj, str):
            return obj
        out.append(str(obj))
    # ngx_string.o + the allocator objects reference ngx_cycle/ngx_log_error_core;
    # one shared TU defines them for every sd_remote unit (tests/c/ngx_link_stubs.c).
    out.append(str(TEST_C / "ngx_link_stubs.c"))
    return out


def sd_remote_wrongkind(base: Path, ngx_src: Path = DEFAULT_NGX_SRC) -> tuple[bool, str]:
    # sd_remote's getxattr/listxattr path (S3 x-amz-meta passthrough) pulls in
    # sd_s3_meta.o, which in turn needs meta_advisory.o for the advisory
    # encode/decode helpers — both were added when S3 listxattr landed but were
    # never reflected in this hand-maintained object closure. sd_remote_dir.o
    # closes sd_remote's dir slots (opendir/readdir -> sd_s3_list_page in
    # sd_s3_list.o); the whole closure now lives in SD_REMOTE_OBJS.
    objs = _sd_remote_objs(ngx_src)
    if isinstance(objs, str):
        return result(True, objs)
    return _compile_and_run(
        base / "test_sd_remote_wrongkind",
        ["-O", "-Wall", str(TEST_C / "test_sd_remote_wrongkind.c"), *objs, *_nginx_includes(ngx_src), "-lssl", "-lcrypto"],
    )
