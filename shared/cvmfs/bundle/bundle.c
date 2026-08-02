/* bundle.c — CVMFS chunk-bundle wire framing.  See bundle.h. */
#include "cvmfs/bundle/bundle.h"

#include <string.h>

void cvmfs_bundle_put_u32(unsigned char *p, uint32_t v) {
    p[0] = (unsigned char) (v);
    p[1] = (unsigned char) (v >> 8);
    p[2] = (unsigned char) (v >> 16);
    p[3] = (unsigned char) (v >> 24);
}

void cvmfs_bundle_put_u64(unsigned char *p, uint64_t v) {
    cvmfs_bundle_put_u32(p, (uint32_t) v);
    cvmfs_bundle_put_u32(p + 4, (uint32_t) (v >> 32));
}

uint32_t cvmfs_bundle_get_u32(const unsigned char *p) {
    return (uint32_t) p[0] | ((uint32_t) p[1] << 8)
         | ((uint32_t) p[2] << 16) | ((uint32_t) p[3] << 24);
}

uint64_t cvmfs_bundle_get_u64(const unsigned char *p) {
    return (uint64_t) cvmfs_bundle_get_u32(p)
         | ((uint64_t) cvmfs_bundle_get_u32(p + 4) << 32);
}

void cvmfs_bundle_hdr_encode(unsigned char *out, uint32_t item_count) {
    memcpy(out, CVMFS_BUNDLE_MAGIC, 4);
    cvmfs_bundle_put_u32(out + 4, item_count);
}

int cvmfs_bundle_item_encode(unsigned char *out, size_t cap,
                             const char *path, size_t path_len,
                             uint64_t data_len) {
    size_t need = 4 + path_len + 8;

    if (path_len == 0 || path_len > CVMFS_BUNDLE_MAX_PATH || cap < need)
        return -1;
    cvmfs_bundle_put_u32(out, (uint32_t) path_len);
    memcpy(out + 4, path, path_len);
    cvmfs_bundle_put_u64(out + 4 + path_len, data_len);
    return (int) need;
}

int cvmfs_bundle_iter_init(cvmfs_bundle_iter_t *it,
                           const unsigned char *stream, size_t len) {
    memset(it, 0, sizeof(*it));
    if (len < CVMFS_BUNDLE_HDR_LEN
        || memcmp(stream, CVMFS_BUNDLE_MAGIC, 4) != 0)
        return -1;
    it->remaining = cvmfs_bundle_get_u32(stream + 4);
    if (it->remaining > CVMFS_BUNDLE_MAX_ITEMS)
        return -1;
    it->p = stream + CVMFS_BUNDLE_HDR_LEN;
    it->n = len - CVMFS_BUNDLE_HDR_LEN;
    return 0;
}

int cvmfs_bundle_next(cvmfs_bundle_iter_t *it, cvmfs_bundle_item_t *item) {
    uint32_t plen;
    uint64_t dlen;

    memset(item, 0, sizeof(*item));
    if (it->remaining == 0)
        return (it->n == 0) ? 0 : -1;        /* trailing garbage = malformed */

    if (it->n < 4)
        return -1;
    plen = cvmfs_bundle_get_u32(it->p);
    if (plen == 0 || plen > CVMFS_BUNDLE_MAX_PATH || it->n < 4 + (size_t) plen + 8)
        return -1;
    item->path     = (const char *) (it->p + 4);
    item->path_len = plen;
    dlen = cvmfs_bundle_get_u64(it->p + 4 + plen);
    it->p += 4 + plen + 8;
    it->n -= 4 + plen + 8;

    if (dlen == CVMFS_BUNDLE_MISS) {
        item->miss = 1;
    } else {
        if (dlen > CVMFS_BUNDLE_MAX_OBJ || it->n < dlen)
            return -1;
        item->data     = it->p;
        item->data_len = dlen;
        it->p += dlen;
        it->n -= (size_t) dlen;
    }
    it->remaining--;
    return 1;
}
