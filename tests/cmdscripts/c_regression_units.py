"""Python ports for object-linked C regression shell runners."""

from __future__ import annotations

from collections.abc import Iterable
from pathlib import Path
import os
import subprocess
import tempfile

from cmdscripts.compile_run import REPO_ROOT, result, run


DEFAULT_NGX_SRC = Path(os.environ.get("NGX_SRC", "/tmp/nginx-1.28.3"))
TEST_C = REPO_ROOT / "tests" / "c"


def _tail(proc: subprocess.CompletedProcess) -> str:
    return (proc.stderr or proc.stdout or "")[-3000:]


def _nginx_includes(ngx_src: Path, *, http: bool = False, stream: bool = False) -> list[str]:
    incs = [
        "-I",
        str(ngx_src / "src/core"),
        "-I",
        str(ngx_src / "src/event"),
        "-I",
        str(ngx_src / "src/event/modules"),
        "-I",
        str(ngx_src / "src/os/unix"),
        "-I",
        str(ngx_src / "objs"),
    ]
    if stream:
        incs += ["-I", str(ngx_src / "src/stream")]
    if http:
        incs += ["-I", str(ngx_src / "src/http"), "-I", str(ngx_src / "src/http/modules")]
    return incs + ["-I", str(REPO_ROOT / "src")]


def _find_obj(ngx_src: Path, name: str, under: str = "addon") -> Path | None:
    root = ngx_src / "objs" / under
    matches = sorted(root.rglob(name)) if root.exists() else []
    return matches[0] if matches else None


def _need_obj(ngx_src: Path, rel: str) -> Path | str:
    obj = ngx_src / rel
    return obj if obj.exists() else f"SKIP: {obj} not found; build the module first"


def _nm_has(symbol: str, objects: Iterable[Path]) -> bool:
    argv = ["nm", *[str(obj) for obj in objects]]
    proc = run(argv, cwd=REPO_ROOT)
    return proc.returncode == 0 and symbol in proc.stdout


def _cc(argv: list[str]) -> subprocess.CompletedProcess:
    return run([os.environ.get("CC", "cc"), *argv], cwd=REPO_ROOT)


def _compile_and_run(binary: Path, argv: list[str]) -> tuple[bool, str]:
    built = _cc(["-o", str(binary), *argv])
    if built.returncode != 0:
        return result(False, f"compile failed: {_tail(built)}")
    ran = run([str(binary)], cwd=REPO_ROOT)
    return result(ran.returncode == 0, f"{binary.name} exited {ran.returncode}: {_tail(ran)}")


DEADLETTER_STUB = r"""
#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_thread_pool.h>
void *brix_vfs_backend_resolve(const char *r, void *l) {(void)r;(void)l;return NULL;}
unsigned brix_sd_cache_instance_is(void *i) {(void)i;return 0;}
void *brix_sd_cache_source_instance(void *i) {(void)i;return NULL;}
unsigned brix_sd_stage_instance_is(void *i) {(void)i;return 0;}
ngx_int_t brix_sd_stage_reflush(void *i, const char *k, const void *c)
{(void)i;(void)k;(void)c;return NGX_ERROR;}
void brix_xfer_finish(int k, const char *d, const char *p, const char *pr,
    size_t b, int r, int e, void *l)
{(void)k;(void)d;(void)p;(void)pr;(void)b;(void)r;(void)e;(void)l;}
ngx_pool_t *ngx_create_pool(size_t s, ngx_log_t *l){(void)s;(void)l;return NULL;}
void ngx_destroy_pool(ngx_pool_t *p){(void)p;}
ngx_thread_pool_t *ngx_thread_pool_get(ngx_cycle_t *c, ngx_str_t *n)
{(void)c;(void)n;return NULL;}
ngx_thread_task_t *ngx_thread_task_alloc(ngx_pool_t *p, size_t s)
{(void)p;(void)s;return NULL;}
ngx_int_t ngx_thread_task_post(ngx_thread_pool_t *tp, ngx_thread_task_t *t)
{(void)tp;(void)t;return NGX_ERROR;}
ngx_int_t brix_sd_ucred_resolve(const char *d, const char *k, void *out)
{(void)d;(void)k;(void)out;return NGX_ERROR;}
void brix_sd_ucred_wipe(void *c){(void)c;}
#if (NGX_THREADS)
void brix_task_bind(ngx_thread_task_t *task,
    void (*handler)(void *, ngx_log_t *),
    void (*completion)(ngx_event_t *))
{(void)task;(void)handler;(void)completion;}
#endif
"""

SREQ_STUB = DEADLETTER_STUB + r"""
void ngx_log_error_core(ngx_uint_t l, ngx_log_t *lg, ngx_err_t e,
    const char *f, ...) { (void)l;(void)lg;(void)e;(void)f; }
volatile ngx_cycle_t *ngx_cycle = NULL;
"""

RATELIMIT_STUB = r"""
#include <ngx_config.h>
#include <ngx_core.h>
#include <stdlib.h>
#define UNUSED(x) (void)(x)
void *ngx_slab_alloc(ngx_slab_pool_t *p, size_t s){UNUSED(p);UNUSED(s);abort();}
void *ngx_slab_alloc_locked(ngx_slab_pool_t *p, size_t s){UNUSED(p);UNUSED(s);abort();}
void ngx_slab_free_locked(ngx_slab_pool_t *p, void *v){UNUSED(p);UNUSED(v);abort();}
void ngx_rbtree_insert(ngx_rbtree_t *t, ngx_rbtree_node_t *n){UNUSED(t);UNUSED(n);abort();}
void ngx_rbtree_delete(ngx_rbtree_t *t, ngx_rbtree_node_t *n){UNUSED(t);UNUSED(n);abort();}
ngx_int_t ngx_memn2cmp(u_char *a,u_char *b,size_t la,size_t lb){UNUSED(a);UNUSED(b);UNUSED(la);UNUSED(lb);abort();}
void *ngx_pcalloc(ngx_pool_t *p, size_t s){UNUSED(p);UNUSED(s);abort();}
ngx_shm_zone_t *ngx_shared_memory_add(ngx_conf_t *cf, ngx_str_t *n, size_t s, void *t){UNUSED(cf);UNUSED(n);UNUSED(s);UNUSED(t);abort();}
u_char *ngx_sprintf(u_char *b, const char *f, ...){UNUSED(b);UNUSED(f);abort();}
void ngx_conf_log_error(ngx_uint_t l, ngx_conf_t *cf, ngx_err_t e, const char *f, ...){UNUSED(l);UNUSED(cf);UNUSED(e);UNUSED(f);}
void *ngx_brix_shm_zone;
"""


def cache_lock_reclaim(base: Path, ngx_src: Path = DEFAULT_NGX_SRC) -> tuple[bool, str]:
    obj = _need_obj(ngx_src, "objs/addon/cache/lock.o")
    if isinstance(obj, str):
        return result(True, obj)
    san = ["-fsanitize=thread"] if _nm_has("__tsan_", [obj]) else []
    return _compile_and_run(
        base / "test_cache_lock_reclaim",
        ["-O", "-Wall", *san, *_nginx_includes(ngx_src, http=True, stream=True), str(TEST_C / "test_cache_lock_reclaim.c"), str(obj)],
    )


def flush_deadletter(base: Path, ngx_src: Path = DEFAULT_NGX_SRC) -> tuple[bool, str]:
    obj = _need_obj(ngx_src, "objs/addon/xfer/stage_engine.o")
    journal = _need_obj(ngx_src, "objs/addon/xfer/stage_engine_journal.o")
    if isinstance(obj, str):
        return result(True, obj)
    if isinstance(journal, str):
        return result(True, journal)
    stub = base / "deadletter_stubs.c"
    stub.write_text(DEADLETTER_STUB)
    return _compile_and_run(
        base / "test_flush_deadletter",
        ["-O", "-Wall", *_nginx_includes(ngx_src), str(TEST_C / "test_flush_deadletter.c"), str(obj), str(journal), str(stub)],
    )


def shm_mutex_recovery(base: Path, ngx_src: Path = DEFAULT_NGX_SRC) -> tuple[bool, str]:
    shm = _need_obj(ngx_src, "objs/addon/compat/shm_slots.o")
    shmtx = _need_obj(ngx_src, "objs/src/core/ngx_shmtx.o")
    if isinstance(shm, str) or isinstance(shmtx, str):
        return result(True, shm if isinstance(shm, str) else shmtx)
    san = ["-fsanitize=thread"] if _nm_has("__tsan", [shm, shmtx]) else []
    return _compile_and_run(
        base / "test_shm_mutex_recovery",
        ["-O", "-Wall", *san, *_nginx_includes(ngx_src), str(TEST_C / "test_shm_mutex_recovery.c"), str(shm), str(shmtx), "-pthread"],
    )


def ratelimit_gauge_reset(base: Path, ngx_src: Path = DEFAULT_NGX_SRC) -> tuple[bool, str]:
    obj = _need_obj(ngx_src, "objs/addon/ratelimit/ratelimit_zone.o")
    if isinstance(obj, str):
        return result(True, obj)
    stub = base / "rl_stubs.c"
    stub.write_text(RATELIMIT_STUB)
    san = ["-fsanitize=thread"] if _nm_has("__tsan", [obj]) else []
    return _compile_and_run(
        base / "test_rl_gauge_reset",
        ["-O", "-Wall", *san, *_nginx_includes(ngx_src, http=True, stream=True), str(TEST_C / "test_ratelimit_gauge_reset.c"), str(stub), str(obj)],
    )


def delegation_store(base: Path, ngx_src: Path = DEFAULT_NGX_SRC) -> tuple[bool, str]:
    names = ["hex.o", "ucred.o", "ucred_parse.o", "store_policy.o", "signing_policy.o", "proxy_req.o"]
    objs: list[Path] = []
    for name in names:
        obj = _find_obj(ngx_src, name)
        if obj is None:
            return result(True, f"SKIP: build first; missing {name}")
        objs.append(obj)
    if not (REPO_ROOT / "src/protocols/webdav/delegation.c").exists():
        return result(True, "SKIP: delegation.c not found")
    return _compile_and_run(
        base / "test_delegation_store",
        [
            "-O",
            "-Wall",
            "-Wno-unused-function",
            str(TEST_C / "test_delegation_store.c"),
            *[str(obj) for obj in objs],
            *_nginx_includes(ngx_src, http=True),
            "-lcrypto",
            "-lssl",
        ],
    )


def pblock(base: Path) -> tuple[bool, str]:
    have_sqlite = run(["pkg-config", "--exists", "sqlite3"], cwd=REPO_ROOT).returncode == 0 or Path("/usr/include/sqlite3.h").exists()
    if not have_sqlite:
        return result(True, "SKIP run_pblock_tests: libsqlite3 development headers not found")
    cflags = run(["pkg-config", "--cflags", "sqlite3"], cwd=REPO_ROOT).stdout.split()
    libs_proc = run(["pkg-config", "--libs", "sqlite3"], cwd=REPO_ROOT)
    libs = libs_proc.stdout.split() if libs_proc.returncode == 0 and libs_proc.stdout.strip() else ["-lsqlite3"]
    backend = REPO_ROOT / "src/fs/backend"
    cat = _compile_and_run(
        base / "pb_cat_ut",
        [
            "-O2",
            "-Wall",
            "-Wextra",
            "-DBRIX_HAVE_SQLITE=1",
            "-I",
            str(backend / "pblock"),
            "-I",
            str(backend),
            "-I",
            str(REPO_ROOT / "src"),
            *cflags,
            str(backend / "pblock/sd_pblock_catalog_unittest.c"),
            str(backend / "pblock/sd_pblock_catalog.c"),
            str(backend / "pblock/sd_pblock_catalog_objects.c"),
            str(backend / "pblock/sd_pblock_catalog_ns.c"),
            *libs,
        ],
    )
    if not cat[0]:
        return cat
    drv = _compile_and_run(
        base / "pb_ut",
        [
            "-O2",
            "-Wall",
            "-Wextra",
            "-DBRIX_HAVE_SQLITE=1",
            "-DXRDPROTO_NO_NGX",
            "-I",
            str(backend / "pblock"),
            "-I",
            str(backend),
            "-I",
            str(REPO_ROOT / "src"),
            *cflags,
            str(backend / "pblock/sd_pblock_unittest.c"),
            str(backend / "pblock/sd_pblock_unittest_core.c"),
            str(backend / "pblock/sd_pblock_unittest_block.c"),
            str(backend / "pblock/sd_pblock_unittest_ident.c"),
            str(backend / "pblock/sd_pblock_unittest_lab.c"),
            str(backend / "pblock/sd_pblock_unittest_dedup.c"),
            str(backend / "pblock/sd_pblock.c"),
            str(backend / "pblock/sd_pblock_lifecycle.c"),
            str(backend / "pblock/sd_pblock_open.c"),
            str(backend / "pblock/sd_pblock_namespace_copy.c"),
            str(backend / "pblock/sd_pblock_io.c"),
            str(backend / "pblock/pblock_ctl.c"),
            str(backend / "pblock/pblock_fault.c"),
            str(backend / "pblock/pblock_csi.c"),
            str(backend / "pblock/pblock_quota.c"),
            str(backend / "pblock/pblock_nearline.c"),
            str(backend / "pblock/pblock_anomaly.c"),
            str(backend / "pblock/pblock_locks.c"),
            str(backend / "pblock/pblock_refs.c"),
            str(backend / "pblock/pblock_snap.c"),
            str(backend / "pblock/pblock_hist.c"),
            str(REPO_ROOT / "src/core/compat/crc32c.c"),
            str(REPO_ROOT / "src/core/compat/crc32c_hw.c"),
            str(REPO_ROOT / "src/core/compat/wverify.c"),
            str(backend / "pblock/sd_pblock_namespace.c"),
            str(backend / "pblock/sd_pblock_staged.c"),
            str(backend / "pblock/sd_pblock_ident.c"),
            str(backend / "pblock/sd_pblock_cred.c"),
            str(backend / "pblock/pblock_store.c"),
            str(backend / "pblock/pblock_xform.c"),
            str(backend / "pblock/sd_pblock_catalog.c"),
            str(backend / "pblock/sd_pblock_catalog_objects.c"),
            str(backend / "pblock/sd_pblock_catalog_ns.c"),
            *libs,
            "-lpthread",
            "-lz",
        ],
    )
    return drv if not drv[0] else result(True, "run_pblock_tests: ALL PASS")


def staged_commit_contract(base: Path, ngx_src: Path = DEFAULT_NGX_SRC) -> tuple[bool, str]:
    """POSIX staged_commit ownership contract: a failed publish leaves the handle
    valid for the caller's abort (free-on-success only). Drives the real
    sd_posix_ns.c wrapper over the real compat/staged_file.c publish, under ASan,
    so the pre-fix double-free would abort. See test_staged_commit_contract.c."""
    ns = _need_obj(ngx_src, "objs/addon/posix/sd_posix_ns.o")
    staged = _need_obj(ngx_src, "objs/addon/compat/staged_file.o")
    if isinstance(ns, str):
        return result(True, ns)
    if isinstance(staged, str):
        return result(True, staged)
    return _compile_and_run(
        base / "test_staged_commit_contract",
        [
            "-O1",
            "-g",
            "-D_GNU_SOURCE",
            "-fsanitize=address",
            "-fno-omit-frame-pointer",
            "-Wall",
            *_nginx_includes(ngx_src),
            str(TEST_C / "test_staged_commit_contract.c"),
            str(ns),
            str(staged),
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


def sd_remote_wrongkind(base: Path, ngx_src: Path = DEFAULT_NGX_SRC) -> tuple[bool, str]:
    # sd_remote's getxattr/listxattr path (S3 x-amz-meta passthrough) pulls in
    # sd_s3_meta.o, which in turn needs meta_advisory.o for the advisory
    # encode/decode helpers — both were added when S3 listxattr landed but were
    # never reflected in this hand-maintained object closure. sd_s3_list.o closes
    # sd_remote's dir slots (opendir/readdir -> sd_s3_list_page).
    names = ["sd_remote.o", "sd_remote_meta.o", "sd_remote_xattr.o", "sd_remote_write.o", "sd_s3.o", "sd_s3_meta.o", "sd_s3_list.o", "meta_advisory.o", "sd_s3_write.o", "sd_s3_sign.o", "crypto.o", "hex.o", "sigv4.o", "uri.o", "host_format.o", "crc32_ieee.o"]
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


def sd_remote_server_copy(base: Path, ngx_src: Path = DEFAULT_NGX_SRC) -> tuple[bool, str]:
    # driver->server_copy -> sd_remote_server_copy -> sd_s3_copy -> transport.
    # Same object closure as sd_remote_wrongkind (the copy path lives in
    # sd_remote_meta.o + sd_s3_meta.o and signs via sd_s3_sign.o); sd_s3_list.o
    # is pulled in transitively by sd_remote.o's dir slots.
    names = ["sd_remote.o", "sd_remote_meta.o", "sd_remote_xattr.o", "sd_remote_write.o", "sd_s3.o", "sd_s3_meta.o", "sd_s3_list.o", "meta_advisory.o", "sd_s3_write.o", "sd_s3_sign.o", "crypto.o", "hex.o", "sigv4.o", "uri.o", "host_format.o", "crc32_ieee.o"]
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
    names = ["sd_remote.o", "sd_remote_meta.o", "sd_remote_xattr.o", "sd_remote_write.o", "sd_s3.o", "sd_s3_meta.o", "sd_s3_list.o", "meta_advisory.o", "sd_s3_write.o", "sd_s3_sign.o", "crypto.o", "hex.o", "sigv4.o", "uri.o", "host_format.o", "crc32_ieee.o"]
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
    names = ["sd_remote.o", "sd_remote_meta.o", "sd_remote_xattr.o", "sd_remote_write.o", "sd_s3.o", "sd_s3_meta.o", "sd_s3_list.o", "meta_advisory.o", "sd_s3_write.o", "sd_s3_sign.o", "crypto.o", "hex.o", "sigv4.o", "uri.o", "host_format.o", "crc32_ieee.o"]
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
    names = ["sd_remote.o", "sd_remote_meta.o", "sd_remote_xattr.o", "sd_remote_write.o", "sd_s3.o", "sd_s3_meta.o", "sd_s3_list.o", "meta_advisory.o", "sd_s3_write.o", "sd_s3_sign.o", "crypto.o", "hex.o", "sigv4.o", "uri.o", "host_format.o", "crc32_ieee.o"]
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
    names = ["sd_http.o", "sd_http_select.o", "sd_http_read.o", "sd_http_write.o", "sd_http_dir.o"]
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
    names = ["sd_http.o", "sd_http_select.o", "sd_http_read.o", "sd_http_write.o", "sd_http_dir.o"]
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
    "frm_stage_metrics": frm_stage_metrics,
    "tpc_progress_total": tpc_progress_total,
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
    for ok, message in results:
        print(f"  {'ok  ' if ok else 'FAIL'} {message}")
    return 0 if all(ok for ok, _ in results) else 1


if __name__ == "__main__":
    from cmdscripts import main

    raise SystemExit(main(entry))
