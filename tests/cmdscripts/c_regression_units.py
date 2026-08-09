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
        incs += [
            "-I", str(ngx_src / "src/http"),
            "-I", str(ngx_src / "src/http/modules"),
            "-I", str(ngx_src / "src/http/v2"),
        ]
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


def _gcov_flags(objects: Iterable[Path]) -> list[str]:
    """`--coverage` when the linked nginx objects are gcov-instrumented.

    A coverage build (the lcov lane's ./configure --with-cc-opt=--coverage) stamps
    __gcov_init/__gcov_exit/__gcov_merge_add references into every object, so a
    harness that links one without the runtime dies at LD time — which is exactly
    how the whole object-linked lane failed in a coverage tree. Detecting it from
    the objects themselves keeps every runner working in both trees."""
    objs = list(objects)
    return ["--coverage"] if objs and _nm_has("__gcov_init", objs) else []


def _sanitizer_flags(objects: Iterable[Path]) -> list[str]:
    """`-fsanitize=...` when the linked nginx objects were built under a sanitizer.

    Same idea as _gcov_flags: an object compiled with -fsanitize=address/undefined/
    thread embeds __asan_*/__ubsan_*/__tsan_* references, so a harness linking it
    without the matching runtime dies at LD time with `undefined reference to
    __asan_*`.  This is exactly the contaminated-addon-object case (an nginx tree
    built with -fsanitize whose objs/ the object-linked units reuse).  One nm pass
    over the objects picks the right flags so the units link against whatever the
    tree was built with — plain, ASan, UBSan, or both."""
    objs = list(objects)
    if not objs:
        return []
    proc = run(["nm", *[str(o) for o in objs]], cwd=REPO_ROOT)
    syms = proc.stdout if proc.returncode == 0 else ""
    flags = []
    if "__asan_" in syms:
        flags.append("-fsanitize=address")
    if "__ubsan_" in syms or "__ubsan" in syms:
        flags.append("-fsanitize=undefined")
    if "__tsan_" in syms:
        flags.append("-fsanitize=thread")
    return flags


def _cc(argv: list[str]) -> subprocess.CompletedProcess:
    return run([os.environ.get("CC", "cc"), *argv], cwd=REPO_ROOT)


def _compile_and_run(binary: Path, argv: list[str]) -> tuple[bool, str]:
    objs = [Path(a) for a in argv if a.endswith(".o") and Path(a).exists()]
    built = _cc(["-o", str(binary), *argv, *_gcov_flags(objs), *_sanitizer_flags(objs)])
    if built.returncode != 0:
        return result(False, f"compile failed: {_tail(built)}")
    # A gcov-instrumented harness would otherwise write .gcda beside the shared
    # nginx objects and clobber the lcov lane's profile with a foreign timestamp.
    ran = run([str(binary)], cwd=REPO_ROOT,
              env={"GCOV_PREFIX": str(binary.parent), "GCOV_PREFIX_STRIP": "99",
                   # An object-linked unit that inherits -fsanitize=address from a
                   # contaminated tree would otherwise fail on LeakSanitizer's
                   # exit-time report (the driver is not written to free); disable
                   # only leak detection — real heap errors (double-free/UAF, which
                   # the intentional-ASan units assert on) still abort.
                   "ASAN_OPTIONS": "detect_leaks=0"})
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


def staged_contract_tiers(base: Path, ngx_src: Path = DEFAULT_NGX_SRC) -> tuple[bool, str]:
    """Same ownership contract for the TIER-side publishers: sd_stage (write-stage
    decorator) and sd_frm (tape migrate). Both used to free the handle on a FAILED
    commit, so the caller's mandatory abort ran on freed memory; sd_stage also
    re-aborted the inner store handle its own commit had already consumed. Drives
    the real objects with fake store/source drivers, stubbed stage-engine entry
    points and a scriptable MSS adapter, under ASan. See
    test_staged_contract_tiers.c."""
    stage = _need_obj(ngx_src, "objs/addon/stage/sd_stage_write.o")
    frm = _need_obj(ngx_src, "objs/addon/frm/sd_frm.o")
    if isinstance(stage, str):
        return result(True, stage)
    if isinstance(frm, str):
        return result(True, frm)
    return _compile_and_run(
        base / "test_staged_contract_tiers",
        [
            "-O1",
            "-g",
            "-D_GNU_SOURCE",
            "-fsanitize=address",
            "-fno-omit-frame-pointer",
            "-Wall",
            *_nginx_includes(ngx_src, http=True, stream=True),
            str(TEST_C / "test_staged_contract_tiers.c"),
            str(stage),
            str(frm),
            "-lcrypto",
        ],
    )

from split_continuation import load as _load_continuations
_load_continuations(globals(), __file__, "c_regression_units_part2.py",
                    "c_regression_units_part3.py")
