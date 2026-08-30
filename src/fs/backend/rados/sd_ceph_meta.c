/*
 * sd_ceph_meta.c — the two object-metadata slots of the flat RADOS driver:
 * `setattr` (advisory POSIX mode/owner/mtime) and `query_checksum` (a CRC32C the
 * OSDs compute over the object's own bytes, without shipping them).
 *
 * WHY THIS FILE EXISTS
 *   Both slots were NULL on this driver, and both had a visible consequence.
 *   A NULL `setattr` makes chmod/kXR_setattr over a ceph:// export a silent
 *   no-op — the VFS treats the missing slot as "nothing to do", so the client is
 *   told the change succeeded and the mode reads back unchanged. A NULL
 *   `query_checksum` makes every checksum request a full-object read back across
 *   the cluster network to hash bytes the OSDs can hash in place.
 *
 *   They live together because they are the same shape: one object, addressed by
 *   its oid, interrogated or amended WITHOUT an open handle in the namespace
 *   case. They are in a file of their own rather than appended to sd_ceph_io.c
 *   or sd_ceph_object.c because both of those are already close to the 600-line
 *   cap.
 *
 * ADVISORY METADATA
 *   RADOS has no POSIX metadata: an object has bytes, an mtime and xattrs, and
 *   nothing else. The approved model (see meta_advisory.h) is to persist mode /
 *   uid+gid / mtime as one reserved-xattr string and overlay it on stat, exactly
 *   as the S3 backend persists the same string in x-amz-meta-xrd-unixattr. The
 *   translation from the setattr request to that string is shared with the S3
 *   backend (meta_advisory_sd.h) so the two cannot disagree about what
 *   UTIME_OMIT, UTIME_NOW or a lone (uid_t)-1 mean.
 *
 * CHECKSUM CONDITIONING — the part that is easy to get silently wrong
 *   The OSD's CRC32C op is a table-driven CRC32C *update* seeded with the
 *   caller's init value, with no pre- or post-conditioning of its own. The
 *   canonical "crc32c" this project speaks (XRootD's XrdCksCalccrc32C, and the
 *   S3 x-amz-checksum-crc32c value) is the standard Castagnoli CRC32C, which is
 *   that same update seeded with 0xFFFFFFFF and finished by XOR with 0xFFFFFFFF.
 *   So the seed and the final XOR below are not decoration; drop either and the
 *   driver hands back a confident, authoritative, wrong digest. Every path that
 *   cannot establish the value with certainty returns NGX_DECLINED instead —
 *   per the slot contract a decline costs one byte-reading recompute, while a
 *   wrong digest is presented to the client as fact.
 */
#include "sd_ceph_internal.h"

#include <stdint.h>
#include <stdio.h>
#include <string.h>

/*
 * WHAT: Turn one OSD CRC32C reply buffer into lowercase hex.
 * WHY:  Split out of the slot, and left OUTSIDE the BRIX_HAVE_CEPH gate, so the
 *       conditioning arithmetic above is exercised by the cluster-free unit
 *       suite (sd_ceph_unittest.c) rather than only by a lab with a live pool.
 *       This is the half that decides whether the digest is right.
 * HOW:  The reply is a little-endian uint32 count followed by that many
 *       little-endian CRC32C values. Chunking is not requested, so the only
 *       shape this driver can interpret is a count of exactly one; anything
 *       else — a short buffer, a chunked reply from a future OSD, a count of
 *       zero — is reported as uninterpretable (-1) and declined by the caller.
 *       Returns 0 on success with `hex` NUL-terminated, -1 otherwise.
 */
int
sd_ceph_ck_crc32c_hex(const unsigned char *reply, size_t len, char *hex,
    size_t cap)
{
    uint32_t count, crc;

    if (reply == NULL || hex == NULL || cap < 9 || len < 8) {
        return -1;
    }
    count = (uint32_t) reply[0]        | ((uint32_t) reply[1] << 8)
          | ((uint32_t) reply[2] << 16) | ((uint32_t) reply[3] << 24);
    if (count != 1 || len < 4 + 4 * (size_t) count) {
        return -1;
    }
    crc = (uint32_t) reply[4]        | ((uint32_t) reply[5] << 8)
        | ((uint32_t) reply[6] << 16) | ((uint32_t) reply[7] << 24);

    /* Post-conditioning: see the file header. The OSD returns the raw running
     * value; the standard CRC32C is that value XOR 0xFFFFFFFF. */
    crc ^= 0xFFFFFFFFu;

    (void) snprintf(hex, cap, "%08x", (unsigned) crc);
    return 0;
}

#if BRIX_HAVE_CEPH

#include "fs/backend/meta_advisory_sd.h"

#include <errno.h>
#include <rados/librados.h>

/* Upper bound on the advisory blob. The encoded form is five short `key=val`
 * tokens after a version token — under 100 bytes in practice; 512 leaves room
 * for a future field without ever being large enough to matter on the stack. */
#define SD_CEPH_ADVISORY_MAX 512

/*
 * WHAT: Apply a setattr request to `path` by patching its advisory blob.
 * WHY:  The ioctx-explicit core (see sd_ceph_internal.h): in RADOS the ioctx IS
 *       the identity asserted at the OSDs, so the credential-scoped twin must be
 *       able to run this exact body on the CALLER's connection. A body that
 *       reached st->ioctx would write the caller's metadata under the export's
 *       authority.
 * HOW:  Read the current blob, patch in the representable fields, write it back.
 *       The read is where the object's existence is established: a missing xattr
 *       and a missing object both come back as -ENODATA/-ENOENT depending on the
 *       OSD, so an absent blob is disambiguated with a rados_stat before it is
 *       treated as "empty" — otherwise setattr on a path that does not exist
 *       would CREATE an object carrying nothing but a mode, and stat would
 *       thereafter report a file that was never written.
 */
ngx_int_t
sd_ceph_setattr_io(sd_ceph_state_t *st, rados_ioctx_t io, const char *path,
    const brix_sd_setattr_t *attr)
{
    brix_meta_advisory_t delta;
    char                 oid[1024];
    char                 blob[SD_CEPH_ADVISORY_MAX];
    uint64_t             size = 0;
    time_t               mtime = 0;
    int                  n;

    if (attr == NULL) {
        errno = EINVAL;
        return NGX_ERROR;
    }
    /* Nothing the advisory model can represent (an atime-only request, say) is
     * success without a write — and it is decided before any cluster round
     * trip. */
    if (!brix_meta_advisory_from_setattr(attr, &delta)) {
        return NGX_OK;
    }
    if (sd_ceph_key(st->key_prefix, path, oid, sizeof(oid)) != 0) {
        return NGX_ERROR;
    }

    n = rados_getxattr(io, oid, BRIX_META_ADVISORY_XATTR, blob,
                       sizeof(blob) - 1);
    if (n < 0) {
        if (n != -ENODATA && n != -ENOENT) {
            errno = -n;
            return NGX_ERROR;
        }
        /* No blob yet — but is there an OBJECT? Never fabricate one. */
        if (sd_ceph_set_errno(rados_stat(io, oid, &size, &mtime))) {
            return NGX_ERROR;
        }
        n = 0;
    }
    blob[n] = '\0';

    if (brix_meta_advisory_patch(blob, sizeof(blob), &delta) < 0) {
        errno = EIO;
        return NGX_ERROR;
    }
    if (sd_ceph_set_errno(rados_setxattr(io, oid, BRIX_META_ADVISORY_XATTR,
                                         blob, strlen(blob))))
    {
        return NGX_ERROR;
    }
    return NGX_OK;
}

/*
 * WHAT: The plain `setattr` vtable slot.
 * WHY:  Two lines over the core, on the export's own ioctx — the same shape
 *       every other namespace slot in this driver has.
 * HOW:  See sd_ceph_setattr_io.
 */
ngx_int_t
sd_ceph_setattr(brix_sd_instance_t *inst, const char *path,
    const brix_sd_setattr_t *attr)
{
    sd_ceph_state_t *st = inst->state;

    return sd_ceph_setattr_io(st, st->ioctx, path, attr);
}

/*
 * WHAT: The `query_checksum` vtable slot — answer a crc32c request from the
 *       OSDs instead of reading the object back to hash it.
 * WHY:  A checksum over a ceph:// export otherwise pulls the whole object
 *       across the cluster network for a value the OSDs can compute where the
 *       bytes already are. For a WLCG dataset that is the entire transfer, paid
 *       again.
 * HOW:  A rados_stat first, then one read op carrying the checksum action over
 *       [0, size). The stat is not redundant: the length to checksum has to be
 *       fixed when the op is BUILT, and obj->state's cached size was taken at
 *       open — checksumming a stale length would digest a prefix of the object
 *       and present it as the whole. It also establishes existence, so a missing
 *       object is ENOENT rather than a checksum of nothing.
 *
 *       Only "crc32c" is offered: the OSD also computes xxhash32/xxhash64, and
 *       neither is in this project's canonical algorithm set. A STRIPED object
 *       declines — its bytes live in sibling stripe objects, and a checksum of
 *       the head object alone would be the digest of a fraction of the file
 *       presented as the digest of the whole. Worker-safe: it touches only the
 *       object state and its own stack, exactly like sd_ceph_pread.
 */
ngx_int_t
sd_ceph_query_checksum(brix_sd_obj_t *obj, const char *algo, char *hex_out,
    size_t hex_sz)
{
    sd_ceph_obj_state_t *os;
    rados_read_op_t      op;
    unsigned char        reply[64];
    /* Seed: the standard CRC32C pre-conditioning — see the file header. */
    const unsigned char  init[4] = { 0xFF, 0xFF, 0xFF, 0xFF };
    uint64_t             size = 0;
    time_t               mtime = 0;
    int                  prval = 0;
    int                  rc;

    if (obj == NULL || obj->state == NULL || algo == NULL || hex_out == NULL
        || hex_sz < 9)
    {
        return NGX_DECLINED;
    }
    if (strcmp(algo, "crc32c") != 0) {
        return NGX_DECLINED;          /* the OSD holds no other canonical digest */
    }
    os = obj->state;
    if (os->striped) {
        return NGX_DECLINED;          /* head object is not the file */
    }
    if (sd_ceph_set_errno(rados_stat(os->ioctx, os->oid, &size, &mtime))) {
        return NGX_ERROR;
    }
    if (size == 0) {
        /* CRC32C of no bytes is 0xFFFFFFFF ^ 0xFFFFFFFF; asking the OSD for a
         * zero-length checksum returns an empty reply we would have to
         * decline. */
        (void) snprintf(hex_out, hex_sz, "%08x", 0u);
        return NGX_OK;
    }

    op = rados_create_read_op();
    if (op == NULL) {
        return NGX_ERROR;
    }
    /* Zeroed first: the OSD fills only as much of `reply` as it produced, and a
     * short or absent reply must parse as uninterpretable rather than as
     * whatever the stack happened to hold. */
    memset(reply, 0, sizeof(reply));
    rados_read_op_checksum(op, LIBRADOS_CHECKSUM_TYPE_CRC32C,
                           (const char *) init, sizeof(init),
                           0, (size_t) size, 0,
                           (char *) reply, sizeof(reply), &prval);
    rc = rados_read_op_operate(op, os->ioctx, os->oid, 0);
    rados_release_read_op(op);

    if (rc < 0 || prval < 0) {
        errno = -(rc < 0 ? rc : prval);
        return NGX_ERROR;             /* the caller recomputes from the bytes */
    }
    if (sd_ceph_ck_crc32c_hex(reply, sizeof(reply), hex_out, hex_sz) != 0) {
        return NGX_DECLINED;          /* uninterpretable: never guess a digest */
    }
    return NGX_OK;
}

#endif /* BRIX_HAVE_CEPH */
