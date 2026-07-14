/*
 * integrity_info_record.c — record-DIGEST checksum fallback for exports without
 * user xattrs (split from integrity_info.c, phase-79).
 *
 * WHAT: Reads and writes a file's checksum as a DIGEST entry inside the file's
 *       unified xmeta record, keyed and validated against the live file's
 *       mtime+size. integrity_record_read returns 1 with a populated
 *       brix_integrity_info_t on a fresh hit; integrity_record_write persists a
 *       computed value best-effort.
 * WHY:  Filesystems that lack user extended attributes cannot use the primary
 *       "user.XrdCks.<alg>" xattr cache, so the checksum must ride in the same
 *       xmeta record that already carries block metadata (which itself falls back
 *       to a stock-readable "<path>.cinfo" sidecar) — ONE metadata form. Keeping
 *       this fallback path in its own file holds the checksum service under the
 *       500-line cap and focused: integrity_info.c owns the xattr layer and the
 *       orchestration, this file owns the record-DIGEST layer.
 * HOW:  integrity_alg_id maps an algorithm name to its BRIX_XMETA_ALG_* id;
 *       integrity_record_read loads the xmeta record and scans its DIGEST entries
 *       for a matching, still-current value; integrity_record_write locks, loads
 *       (or initialises a fresh record for a foreign/live export file), sets the
 *       DIGEST entry, and saves.
 */

#include "integrity_info.h"
#include "integrity_info_internal.h"   /* INTEGRITY_XATTR_VAL_MAX + cross-file decls */
#include "fs/meta/xmeta_path.h"   /* record-DIGEST fallback carrier (§8.2) */
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>

/* Record-DIGEST fallback (§8.2, xmeta P4) — for exports without user xattrs.
 * Instead of the retired "<path>.cks" sidecar, the checksum rides as a DIGEST
 * entry in the file's unified xmeta record (which itself falls back to the
 * stock-readable "<path>.cinfo" sidecar on such filesystems — ONE metadata
 * form). Entry value = "<hex> <mtime_sec> <mtime_nsec> <size>", keyed and
 * validated on the live file's mtime+size, mirroring the xattr policy. Stock
 * interop is untouched: xattr-capable exports keep user.XrdCks.<alg>. */

static uint16_t
integrity_alg_id(const char *algo)
{
    static const struct { const char *name; uint16_t id; } map[] = {
        { "adler32",   BRIX_XMETA_ALG_ADLER32   },
        { "crc32",     BRIX_XMETA_ALG_CRC32     },
        { "crc32c",    BRIX_XMETA_ALG_CRC32C    },
        { "md5",       BRIX_XMETA_ALG_MD5       },
        { "sha1",      BRIX_XMETA_ALG_SHA1      },
        { "sha256",    BRIX_XMETA_ALG_SHA256    },
        { "crc64",     BRIX_XMETA_ALG_CRC64XZ   },
        { "crc64nvme", BRIX_XMETA_ALG_CRC64NVME },
        { "zcrc32",    BRIX_XMETA_ALG_ZCRC32    },
        { NULL, 0 },
    };
    int i;

    for (i = 0; map[i].name != NULL; i++) {
        if (strcmp(map[i].name, algo) == 0) {
            return map[i].id;
        }
    }
    return 0;                       /* unmapped: no record caching */
}

int
integrity_record_read(const char *path, const char *algo,
    brix_integrity_info_t *out)
{
    brix_xmeta_t xm;
    struct stat    st;
    uint16_t       want = integrity_alg_id(algo);
    uint32_t       idx;
    int            found = 0;

    if (path == NULL || want == 0 || stat(path, &st) != 0
        || brix_xmeta_path_load(path, &xm) != BRIX_XMETA_OK)
    {
        return 0;
    }
    for (idx = 0; ; idx++) {
        uint16_t       alg = 0, vlen = 0;
        const uint8_t *val = NULL;
        char           rec[INTEGRITY_XATTR_VAL_MAX + 64];
        char           rhex[INTEGRITY_XATTR_VAL_MAX];
        long           ms, mn;
        long long      sz;

        if (brix_xmeta_digest_get(&xm, idx, &alg, &val, &vlen)
            != BRIX_XMETA_OK)
        {
            break;
        }
        if (alg != want || vlen == 0 || vlen >= sizeof(rec)) {
            continue;
        }
        memcpy(rec, val, vlen);
        rec[vlen] = 0;
        if (sscanf(rec, "%159s %ld %ld %lld", rhex, &ms, &mn, &sz) != 4) {
            continue;
        }
        if ((long) st.st_mtim.tv_sec == ms
            && (long) st.st_mtim.tv_nsec == mn
            && (long long) st.st_size == sz)
        {
            ngx_cpystrn((u_char *) out->hex, (u_char *) rhex,
                        sizeof(out->hex));
            out->from_cache = 1;
            found = 1;
        }
        break;                      /* entry found (fresh or stale) */
    }
    brix_xmeta_free(&xm);
    return found;
}

void
integrity_record_write(const char *path, const char *algo, const char *hexval)
{
    brix_xmeta_t xm;
    struct stat    st;
    char           rec[INTEGRITY_XATTR_VAL_MAX + 64];
    uint16_t       id = integrity_alg_id(algo);
    int            n, rc, lockfd;

    if (path == NULL || id == 0 || stat(path, &st) != 0) {
        return;
    }
    n = snprintf(rec, sizeof(rec), "%s %ld %ld %lld", hexval,
                 (long) st.st_mtim.tv_sec, (long) st.st_mtim.tv_nsec,
                 (long long) st.st_size);
    if (n <= 0 || (size_t) n >= sizeof(rec)) {
        return;
    }

    lockfd = brix_xmeta_path_lock(path);
    if (lockfd < 0) {
        return;
    }
    rc = brix_xmeta_path_load(path, &xm);
    if (rc == BRIX_XMETA_ERR
        || (rc == BRIX_XMETA_FOREIGN
            && brix_xmeta_init(&xm, st.st_size, 1024 * 1024)
               != BRIX_XMETA_OK))
    {
        brix_xmeta_path_unlock(lockfd);
        return;
    }
    if (rc == BRIX_XMETA_FOREIGN) {
        /* fresh record for a live export file: fully present, no CRC table */
        xm.origin_mtime = (uint64_t) st.st_mtime;
        if (xm.nblocks > 0) {
            memset(xm.bitmap, 0xFF, (size_t) ((xm.nblocks + 7) / 8));
        }
        xm.have_blockcrc = 0;
    }
    if (brix_xmeta_digest_set(&xm, id, rec, (uint16_t) n)
        == BRIX_XMETA_OK)
    {
        (void) brix_xmeta_path_save(path, &xm);   /* best-effort cache */
    }
    brix_xmeta_free(&xm);
    brix_xmeta_path_unlock(lockfd);
}
