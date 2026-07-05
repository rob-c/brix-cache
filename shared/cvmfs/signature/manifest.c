/* manifest.c — parse a CVMFS .cvmfspublished manifest. See manifest.h. */
#include "cvmfs/signature/manifest.h"

#include <string.h>
#include <stdlib.h>

/* Find "\n--\n"; returns the offset of the marker's first '-' or (size_t)-1. */
static size_t find_marker(const unsigned char *b, size_t len) {
    for (size_t i = 0; i + 3 < len; i++) {
        if (b[i] == '\n' && b[i + 1] == '-' && b[i + 2] == '-' && b[i + 3] == '\n')
            return i + 1;
    }
    return (size_t) -1;
}

static void parse_kv_line(char key, const char *v, size_t vlen, cvmfs_manifest_t *o) {
    char   tmp[257];
    size_t n = vlen < sizeof(tmp) - 1 ? vlen : sizeof(tmp) - 1;

    memcpy(tmp, v, n);
    tmp[n] = '\0';

    switch (key) {
    case 'C': cvmfs_hash_parse(v, vlen, &o->root_catalog); break;
    case 'X': cvmfs_hash_parse(v, vlen, &o->certificate);  break;
    case 'B': o->catalog_size = atol(tmp); break;
    case 'S': o->revision     = atol(tmp); break;
    case 'D': o->ttl          = atol(tmp); break;
    case 'T': o->timestamp    = atol(tmp); break;
    case 'N': memcpy(o->repo_name, tmp, n); o->repo_name[n] = '\0'; break;
    default:  break;
    }
}

int cvmfs_manifest_parse(const unsigned char *buf, size_t len, cvmfs_manifest_t *out) {
    memset(out, 0, sizeof(*out));

    size_t marker = find_marker(buf, len);
    if (marker == (size_t) -1) return -1;

    /* Walk key-value lines in [0, marker). */
    size_t i = 0;
    while (i < marker) {
        size_t j = i;
        while (j < marker && buf[j] != '\n') j++;
        if (j > i)
            parse_kv_line((char) buf[i], (const char *) buf + i + 1, j - i - 1, out);
        i = j + 1;
    }

    out->signed_body = buf;
    out->signed_body_len = marker + 3;      /* include "--\n" */
    if (out->root_catalog.len == 0) return -1;

    /* After "--\n": a hash line, then the raw signature to EOF. */
    size_t p = out->signed_body_len;
    size_t h = p;
    while (h < len && buf[h] != '\n') h++;
    if (h >= len) return -1;
    cvmfs_hash_parse((const char *) buf + p, h - p, &out->signed_hash);
    out->signed_hash_text = buf + p;
    out->signed_hash_text_len = h - p;
    out->signature = buf + h + 1;
    out->signature_len = len - (h + 1);
    if (out->signature_len == 0) return -1;
    return 0;
}
