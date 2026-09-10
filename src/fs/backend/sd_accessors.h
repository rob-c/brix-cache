/*
 * sd_accessors.h — object release + capability-gated accessor surface of the
 * storage-driver seam. A verbatim relocation (phase-107 W6, the same pure
 * textual split that created sd_cred_forward.h) of brix_sd_obj_release and the
 * caps/fd/name/supports/cred_accept accessors out of sd.h, keeping every SD
 * header < 600 LOC after the C2 lifecycle slots (recall_cred / evict /
 * evict_cred) grew the vtable. Zero behaviour change. Depends on the struct
 * definitions above it in sd.h and is included from there AFTER those structs
 * are defined — never on its own.
 */
#ifndef BRIX_SD_ACCESSORS_H
#define BRIX_SD_ACCESSORS_H

/* Release a driver object obtained from driver->open() by a caller that holds it
 * by POINTER (not the VFS, which adopts the object by value and frees the shell
 * itself in vfs_open.c): close it via its own vtable, then free a heap-allocated
 * shell (heap_shell=1, e.g. POSIX's malloc'd obj — allocated off inst->pool so a
 * cache-fill thread never touches the thread-unsafe ngx_cycle->pool). NULL-safe;
 * a pool-allocated shell (heap_shell=0) is just closed. */
static inline void
brix_sd_obj_release(brix_sd_obj_t *o)
{
    if (o == NULL) {
        return;
    }
    if (o->driver != NULL && o->driver->close != NULL) {
        o->driver->close(o);
    }
    if (o->heap_shell) {
        free(o);
    }
}

/* ---- capability-gated accessors (never poke the vtable directly) ---------- */

/* The instance's capability bitmap (0 when inst/driver is NULL). */
uint32_t brix_sd_caps(const brix_sd_instance_t *inst);
/* The object's real fd, or NGX_INVALID_FILE when the backend lacks CAP_FD. */
ngx_fd_t brix_sd_fd(const brix_sd_obj_t *obj);
/* The backend driver name ("posix" by default; "?" when inst is NULL). */
const char *brix_sd_backend_name(const brix_sd_instance_t *inst);
/* 1 iff the instance advertises ALL bits in required_caps. */
ngx_int_t brix_sd_supports(const brix_sd_instance_t *inst,
    uint32_t required_caps);
/* The instance's accepted-credential-kind bitmap (0 when inst/driver is NULL). */
uint32_t brix_sd_cred_accept(const brix_sd_instance_t *inst);

/* brix_sd_query_origin_digest — ask an OPEN object's driver for the digest a
 * verifying cache fill can compare its bytes against, in the algorithm
 * `pref` names (brix_cache_verify_digest).  This is the non-root:// half of
 * checksum-on-fill: root:// carries kXR_Qcksum in band, every other origin has
 * to be asked, and only the operator can say which algorithm to ask for (an
 * HTTP origin answers exactly one Want-Digest token).
 *
 * Best-effort by contract: with no preference, no driver slot, or any
 * DECLINED/ERROR answer, alg/hex come back EMPTY and the caller's verify policy
 * decides — best-effort publishes unverified, require refuses.  Never fails a
 * fill by itself. */
static inline void
brix_sd_query_origin_digest(brix_sd_obj_t *obj, const char *pref,
    char *alg, size_t algsz, char *hex, size_t hexsz)
{
    if (algsz) { alg[0] = '\0'; }
    if (hexsz) { hex[0] = '\0'; }

    if (obj == NULL || obj->driver == NULL
        || obj->driver->query_checksum == NULL
        || pref == NULL || pref[0] == '\0')
    {
        return;
    }

    if (obj->driver->query_checksum(obj, pref, hex, hexsz) != NGX_OK) {
        if (hexsz) { hex[0] = '\0'; }
        return;
    }

    ngx_cpystrn((u_char *) alg, (u_char *) pref, algsz);
}

#endif /* BRIX_SD_ACCESSORS_H */
