#ifndef BRIX_FS_BACKEND_FRM_SD_FRM_LIB_ABI_H
#define BRIX_FS_BACKEND_FRM_SD_FRM_LIB_ABI_H

/*
 * sd_frm_lib_abi.h — the library-native HSM adapter ABI (phase-64).
 *
 * WHAT: the C entry points a shared object must export to serve as a
 *       library-native MSS back end for the "lib" / "libhpss" / "libcta" FRM
 *       dialects. The sd_frm "lib" adapter dlopen()s the .so and dlsym()s these
 *       symbols; each verb is an in-process function call, NOT a fork+exec of a
 *       stage command. That is the whole point of this adapter: on a busy silo
 *       the exec transport forks a `hsi`/`eos` helper per recall/residency probe,
 *       and the per-verb fork+exec+wait dominates the latency of small-object
 *       staging — a native library call removes it.
 * WHY:  a header both the real vendor shim and the test mock include, so the
 *       symbol names and signatures cannot drift between producer and consumer.
 * HOW:  the online buffer is still a local directory the adapter manages
 *       (open/create/pread live in the adapter); the library only owns the
 *       tape<->online-buffer transfer and residency. Recall is expected to
 *       BLOCK until the object is in `online_path` (the adapter runs it off the
 *       event loop, on the cache-fill path), returning 0 on success.
 *
 * Contract (all return 0 = success unless noted; called off the event loop):
 *   int brix_frm_hsm_exists (const char *key);
 *        0 = key is known to the MSS (on tape / recallable); non-0 = absent.
 *   int brix_frm_hsm_recall (const char *key, const char *online_path);
 *        materialise `key` into `online_path` (parents pre-created); 0 = online.
 *   int brix_frm_hsm_migrate(const char *key, const char *online_path);
 *        copy the online-buffer object back to tape; 0 = migrated.
 *   int brix_frm_hsm_purge  (const char *key);          [OPTIONAL — may be absent]
 *        drop the MSS-side staged copy of `key`; 0 = ok.
 */

typedef int (*brix_frm_hsm_exists_fn)(const char *key);
typedef int (*brix_frm_hsm_recall_fn)(const char *key, const char *online_path);
typedef int (*brix_frm_hsm_migrate_fn)(const char *key, const char *online_path);
typedef int (*brix_frm_hsm_purge_fn)(const char *key);

#define BRIX_FRM_HSM_SYM_EXISTS   "brix_frm_hsm_exists"
#define BRIX_FRM_HSM_SYM_RECALL   "brix_frm_hsm_recall"
#define BRIX_FRM_HSM_SYM_MIGRATE  "brix_frm_hsm_migrate"
#define BRIX_FRM_HSM_SYM_PURGE    "brix_frm_hsm_purge"

#endif /* BRIX_FS_BACKEND_FRM_SD_FRM_LIB_ABI_H */
