/* object_write.c — CVMFS CAS object writer. See object_write.h. */
#include "cvmfs/object/object_write.h"
#include "cvmfs/object/object.h"

#include <zlib.h>

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

int cvmfs_objstore_open(cvmfs_objstore_t *s, const char *repo_dir) {
    char data[600];
    int  w = snprintf(data, sizeof(data), "%s/data", repo_dir);
    if (w < 0 || (size_t) w >= sizeof(data)) { errno = ENAMETOOLONG; return -1; }
    return brix_cas_init(&s->cas, data, 0);
}

void cvmfs_objstore_close(cvmfs_objstore_t *s) {
    brix_cas_destroy(&s->cas);
}

/* "<hex><suffix>" CAS key for hash+suffix. */
static int obj_key(const cvmfs_hash_t *h, char suffix, char *buf, size_t cap) {
    return cvmfs_hash_to_hex(h, suffix, buf, cap) < 0 ? -1 : 0;
}

int cvmfs_object_store(cvmfs_objstore_t *s, const unsigned char *plain, size_t len,
                       char suffix, int compress_it, cvmfs_hash_t *out, size_t *stored_len) {
    unsigned char       *zbuf = NULL;
    const unsigned char *stored = plain;
    size_t               stored_n = len;

    if (compress_it) {
        uLongf cap = compressBound(len);
        zbuf = malloc(cap ? cap : 1);
        if (zbuf == NULL) return -1;
        if (compress(zbuf, &cap, plain, len) != Z_OK) { free(zbuf); return -1; }
        stored = zbuf;
        stored_n = cap;
    }

    char key[64];
    int  rc = cvmfs_object_hash(CVMFS_HASH_SHA1, stored, stored_n, out);
    if (rc == 0) rc = obj_key(out, suffix, key, sizeof(key));
    if (rc == 0) rc = brix_cas_put(&s->cas, key, stored, stored_n);
    if (rc == 0 && stored_len != NULL) *stored_len = stored_n;
    free(zbuf);
    return rc;
}

int cvmfs_object_present(cvmfs_objstore_t *s, const cvmfs_hash_t *hash, char suffix) {
    char key[64];
    return obj_key(hash, suffix, key, sizeof(key)) == 0 && brix_cas_has(&s->cas, key);
}

long cvmfs_object_read_stored(cvmfs_objstore_t *s, const cvmfs_hash_t *hash, char suffix,
                              unsigned char *out, size_t outcap) {
    char key[64];
    if (obj_key(hash, suffix, key, sizeof(key)) != 0) return -1;
    int fd = brix_cas_open(&s->cas, key);
    if (fd < 0) return -1;

    size_t off = 0;
    for (;;) {
        if (off == outcap) { close(fd); return -1; }        /* overflow */
        ssize_t r = read(fd, out + off, outcap - off);
        if (r < 0) { if (errno == EINTR) continue; close(fd); return -1; }
        if (r == 0) break;
        off += (size_t) r;
    }
    close(fd);
    return (long) off;
}

int cvmfs_object_delete(cvmfs_objstore_t *s, const cvmfs_hash_t *hash, char suffix) {
    char key[64];
    if (obj_key(hash, suffix, key, sizeof(key)) != 0) return -1;
    if (!brix_cas_has(&s->cas, key)) return 0;
    return brix_cas_del(&s->cas, key);
}
