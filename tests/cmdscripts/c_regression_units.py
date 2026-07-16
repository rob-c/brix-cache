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
    names = ["hex.o", "ucred.o", "store_policy.o", "signing_policy.o", "proxy_req.o"]
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
            str(backend / "pblock/sd_pblock.c"),
            str(backend / "pblock/sd_pblock_io.c"),
            str(backend / "pblock/sd_pblock_namespace.c"),
            str(backend / "pblock/sd_pblock_staged.c"),
            str(backend / "pblock/sd_pblock_ident.c"),
            str(backend / "pblock/sd_pblock_cred.c"),
            str(backend / "pblock/pblock_store.c"),
            str(backend / "pblock/sd_pblock_catalog.c"),
            str(backend / "pblock/sd_pblock_catalog_objects.c"),
            str(backend / "pblock/sd_pblock_catalog_ns.c"),
            *libs,
            "-lpthread",
        ],
    )
    return drv if not drv[0] else result(True, "run_pblock_tests: ALL PASS")


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


def sd_remote_wrongkind(base: Path, ngx_src: Path = DEFAULT_NGX_SRC) -> tuple[bool, str]:
    names = ["sd_remote.o", "sd_s3.o", "sd_s3_write.o", "sd_s3_sign.o", "crypto.o", "hex.o", "sigv4.o", "uri.o", "host_format.o"]
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


RUNNERS = {
    "cache_lock_reclaim": cache_lock_reclaim,
    "flush_deadletter": flush_deadletter,
    "shm_mutex_recovery": shm_mutex_recovery,
    "ratelimit_gauge_reset": ratelimit_gauge_reset,
    "delegation_store": delegation_store,
    "pblock": pblock,
    "mu_unit": mu_unit,
    "stage_reconcile": stage_reconcile,
    "compression": compression,
    "sreq_compat": sreq_compat,
    "sd_remote_wrongkind": sd_remote_wrongkind,
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
