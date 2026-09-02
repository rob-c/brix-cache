/*
 * sd_value_types.h — the plain-value types a storage driver reads and fills:
 * residency, space, catalog entries, stat, dirent, setattr.  Split out of sd.h
 * (which stays the slot table + instance/object model) to keep sd.h under the
 * 600-line cap, the same cut that produced sd_accessors.h and sd_batch_types.h.
 *
 * Everything here is standard-C only (off_t/time_t/uint64_t/struct timespec) —
 * no ngx types — so the header serves the XRDPROTO_NO_NGX libxrdproto plane
 * unshimmed.  Contract text lives with each type; sd.h's slot comments refer
 * back here by type name.
 */
#ifndef BRIX_SD_VALUE_TYPES_H
#define BRIX_SD_VALUE_TYPES_H

#include <stdint.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <time.h>

/* Residency of a nearline (tape/MSS) object — the online/offline model the VFS
 * residency seam (brix_vfs_residency) exposes to protocol handlers so they can
 * advertise tape state (the HTTP Tape REST API, S3 InvalidObjectState /
 * x-amz-storage-class, root:// stat's nearline flag) WITHOUT forcing a recall. A
 * non-nearline driver has no residency slot; the seam reports ONLINE for it (a
 * plain disk/object export is always resident). */
typedef enum {
    BRIX_SD_RES_ONLINE   = 0,  /* resident in the online buffer, readable now      */
    BRIX_SD_RES_NEARLINE = 1,  /* on the backend, stageable (a recall faults it in) */
    BRIX_SD_RES_OFFLINE  = 2,  /* on the backend, not retrievable right now         */
    BRIX_SD_RES_LOST     = 3   /* the object is gone                                */
} brix_sd_residency_t;

/* Driver space report (optional `space` slot, phase-83 F5): the backend's own
 * view of total/used/free bytes for the export — quota-aware logical space for
 * catalog backends (pblock), rather than the raw statvfs(2) of the filesystem
 * under it. Consumers: kXR_statvfs, SRR reporting. */
typedef struct {
    uint64_t total_bytes;
    uint64_t used_bytes;
    uint64_t free_bytes;
} brix_sd_space_t;

/* One entry the catalog-enumeration verb (driver->enumerate) reports per stored
 * backend object — independent of the namespace. `key` is the backend object key
 * (always present). `path` is the logical path the driver recovered for it, or
 * NULL when it cannot (⇒ an orphan-object candidate). size/mtime are valid only
 * when have_stat (the enumerator was asked for stats and the per-object stat
 * succeeded). All pointers are owned by the enumerator and valid only for the
 * duration of the callback. */
typedef struct {
    const char *key;
    const char *path;
    int         have_stat;
    off_t       size;
    time_t      mtime;
} brix_sd_catalog_ent_t;

/* Per-object callback fired by driver->enumerate. Return 0 to continue the
 * enumeration, non-zero to abort it (that code is returned to the caller). */
typedef int (*brix_sd_catalog_cb)(void *ctx, const brix_sd_catalog_ent_t *ent);

/* Protocol-neutral stat the driver fills; the VFS maps it to brix_vfs_stat_t.
 * uid/gid are the owner ids in the driver's own namespace (POSIX: kernel ids;
 * pblock: catalog-internal synthetic ids); 0 for backends with no owner model. */
typedef struct {
    off_t       size;
    time_t      mtime;
    time_t      ctime;
    mode_t      mode;
    ino_t       ino;
    uid_t       uid;
    gid_t       gid;
    unsigned    is_dir:1;
    unsigned    is_reg:1;
} brix_sd_stat_t;

/* One directory entry name (NUL-terminated). POSIX = a dirent name; object =
 * the final path component synthesized from a key under the listing prefix.
 * d_type is the entry's DT_* kind (dirent.h) when the backend can classify it
 * cheaply, else DT_UNKNOWN (= 0, what a memzero'd entry reads) — consumers
 * fall back to a stat; a backend must never guess. NEVER an authorization or
 * confinement input (a spoofed d_type may only cost a fallback stat). */
typedef struct {
    char           name[256];
    unsigned char  d_type;
} brix_sd_dirent_t;

/* Metadata-mutation request for the driver's setattr slot — the storage-neutral
 * union of kXR_chmod (mode) and kXR_setattr (times + owner). Each set_* flag gates
 * its field group; an unset group is left untouched. atime/mtime carry per-field
 * UTIME_OMIT / UTIME_NOW in tv_nsec (utimensat(2) semantics). uid/gid of
 * (uid_t)-1 / (gid_t)-1 leave that id unchanged. A driver applies what its
 * namespace can represent (e.g. a catalog backend may not track owner/atime). */
typedef struct {
    unsigned         set_mode:1;
    unsigned         set_times:1;
    unsigned         set_owner:1;
    mode_t           mode;
    struct timespec  atime;
    struct timespec  mtime;
    uid_t            uid;
    gid_t            gid;
} brix_sd_setattr_t;

#endif /* BRIX_SD_VALUE_TYPES_H */
