/* pathidx.c — G6 mmap path index: build/write + mmap read. See pathidx.h. */
#ifndef _DEFAULT_SOURCE
#define _DEFAULT_SOURCE 1        /* openat/renameat/fstat under strict -std=c11 */
#endif

#include "cvmfs/index/pathidx.h"
#include "cvmfs/platform/platform.h"

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <zlib.h>

#define PIDX_MAX_BYTES (1u << 30)   /* refuse absurd sidecars outright */

typedef struct {
    cvmfs_pathidx_ent_t *ents;
    uint32_t            *buckets;
    char                *blob;
    size_t               blob_len;
    uint64_t             nbuckets;
} pathidx_image_t;

/* Same canonical FNV-1a-64 as cas_pack.c's key table (local per sibling
 * idiom — the standalone unit lanes compile with -I shared only). */
static uint64_t fnv1a(const char *k, size_t n) {
    uint64_t h = 1469598103934665603ull;
    for (size_t i = 0; i < n; i++) { h ^= (unsigned char) k[i]; h *= 1099511628211ull; }
    return h;
}

static uint32_t hdr_crc(const cvmfs_pathidx_hdr_t *h) {
    cvmfs_pathidx_hdr_t c = *h;
    c.hdr_crc = 0;
    return (uint32_t) crc32(crc32(0L, Z_NULL, 0),
                            (const unsigned char *) &c, (uInt) sizeof(c));
}

/* ---- builder ------------------------------------------------------------- */

void cvmfs_pathidx_build_init(cvmfs_pathidx_build_t *b) {
    memset(b, 0, sizeof(*b));
}

void cvmfs_pathidx_build_free(cvmfs_pathidx_build_t *b) {
    for (size_t i = 0; i < b->n; i++) {
        free(b->v[i].path);
        free(b->v[i].link);
    }
    free(b->v);
    memset(b, 0, sizeof(*b));
}

int cvmfs_pathidx_build_add(cvmfs_pathidx_build_t *b, const char *path,
                            const cvmfs_dirent_t *e) {
    if (b->oom) return -1;
    if (b->n == b->cap) {
        size_t ncap = b->cap ? b->cap * 2 : 256;
        cvmfs_pathidx_bent_t *nv = realloc(b->v, ncap * sizeof(*nv));
        if (nv == NULL) { b->oom = 1; return -1; }
        b->v = nv;
        b->cap = ncap;
    }
    cvmfs_pathidx_bent_t *be = &b->v[b->n];
    memset(be, 0, sizeof(*be));
    be->path = strdup(path);
    if (be->path == NULL) { b->oom = 1; return -1; }
    if ((e->flags & CVMFS_FLAG_LINK) && e->symlink[0] != '\0') {
        be->link = strdup(e->symlink);
        if (be->link == NULL) { free(be->path); b->oom = 1; return -1; }
    }
    be->size = e->size;
    be->mtime = e->mtime;
    be->mode = e->mode;
    be->flags = e->flags;
    be->uid = e->uid;
    be->gid = e->gid;
    be->linkcount = e->linkcount;
    be->has_hash = e->has_hash != 0;
    be->hash = e->hash;
    b->n++;
    return 0;
}

static uint32_t bent_dlen(const cvmfs_pathidx_bent_t *e) {
    const char *s = strrchr(e->path, '/');
    return s == NULL ? 0 : (uint32_t) (s - e->path);
}

/* Order by (dirname, name) so each directory's children form one run. */
static int bent_cmp(const void *pa, const void *pb) {
    const cvmfs_pathidx_bent_t *a = pa, *b = pb;
    uint32_t da = bent_dlen(a), db = bent_dlen(b);
    uint32_t m = da < db ? da : db;
    int c = memcmp(a->path, b->path, m);
    if (c != 0) return c;
    if (da != db) return da < db ? -1 : 1;
    const char *na = a->path[0] ? a->path + da + 1 : "";
    const char *nb = b->path[0] ? b->path + db + 1 : "";
    return strcmp(na, nb);
}

static int write_all(int fd, const void *buf, size_t len) {
    const unsigned char *p = buf;
    for (size_t off = 0; off < len; ) {
        ssize_t r = write(fd, p + off, len - off);
        if (r < 0) { if (errno == EINTR) continue; return -1; }
        off += (size_t) r;
    }
    return 0;
}

/*
 * WHAT: Release all transient buffers used to construct a path-index image.
 * WHY:  Every allocation and I/O failure must share the same complete cleanup.
 * HOW:  Free entries, buckets, and string blob independently, then clear state.
 */
static void image_free(pathidx_image_t *image) {
    free(image->ents);
    free(image->buckets);
    free(image->blob);
    memset(image, 0, sizeof(*image));
}

/*
 * WHAT: Allocate the entries, hash buckets, and string blob for one index.
 * WHY:  Image sizing and allocation are independent from entry serialization.
 * HOW:  Sum string storage, choose a power-of-two table, and allocate all parts.
 */
static int image_alloc(const cvmfs_pathidx_build_t *b,
                       pathidx_image_t *image) {
    size_t i;

    memset(image, 0, sizeof(*image));
    for (i = 0; i < b->n; i++) {
        image->blob_len += strlen(b->v[i].path) + 1;
        if (b->v[i].link != NULL)
            image->blob_len += strlen(b->v[i].link) + 1;
    }
    image->nbuckets = 8;
    while (image->nbuckets < 2 * (uint64_t) b->n)
        image->nbuckets *= 2;
    image->ents = calloc(b->n, sizeof(*image->ents));
    image->buckets = calloc(image->nbuckets, sizeof(*image->buckets));
    image->blob = malloc(image->blob_len ? image->blob_len : 1);
    if (image->ents == NULL || image->buckets == NULL || image->blob == NULL) {
        image_free(image);
        return -1;
    }
    return 0;
}

/*
 * WHAT: Serialize one builder entry into the in-memory index image.
 * WHY:  String layout and fixed metadata copying form one repeatable operation.
 * HOW:  Append path/link bytes, copy scalars, and install one hash-table slot.
 */
static void image_add_entry(const cvmfs_pathidx_bent_t *be, size_t index,
                            pathidx_image_t *image, size_t *blob_offset) {
    cvmfs_pathidx_ent_t *entry = &image->ents[index];
    size_t               path_len = strlen(be->path);
    uint64_t             slot;

    entry->path_off = *blob_offset;
    entry->path_len = (uint32_t) path_len;
    entry->dlen = bent_dlen(be);
    memcpy(image->blob + *blob_offset, be->path, path_len + 1);
    *blob_offset += path_len + 1;
    if (be->link != NULL) {
        size_t link_len = strlen(be->link);

        entry->link_off = *blob_offset;
        entry->link_len = (uint32_t) link_len;
        memcpy(image->blob + *blob_offset, be->link, link_len + 1);
        *blob_offset += link_len + 1;
    }
    entry->size = be->size;
    entry->mtime = be->mtime;
    entry->mode = be->mode;
    entry->flags = be->flags;
    entry->uid = be->uid;
    entry->gid = be->gid;
    entry->linkcount = be->linkcount;
    entry->has_hash = be->has_hash;
    entry->hash = be->hash;

    slot = fnv1a(be->path, path_len) & (image->nbuckets - 1);
    while (image->buckets[slot] != 0)
        slot = (slot + 1) & (image->nbuckets - 1);
    image->buckets[slot] = (uint32_t) index + 1;
}

/*
 * WHAT: Populate a newly allocated image from sorted builder entries.
 * WHY:  The image must keep entry order while independently indexing paths.
 * HOW:  Serialize each entry and return the exact used string-blob length.
 */
static size_t image_fill(const cvmfs_pathidx_build_t *b,
                         pathidx_image_t *image) {
    size_t blob_offset = 0;
    size_t i;

    for (i = 0; i < b->n; i++)
        image_add_entry(&b->v[i], i, image, &blob_offset);
    return blob_offset;
}

/*
 * WHAT: Construct a checksummed on-disk header for an in-memory index image.
 * WHY:  Geometry and ABI values must describe exactly the payload being written.
 * HOW:  Fill fixed fields, derive contiguous offsets, then calculate header CRC.
 */
static void header_build(cvmfs_pathidx_hdr_t *h,
                         const cvmfs_pathidx_build_t *b,
                         const cvmfs_hash_t *root,
                         const pathidx_image_t *image, size_t blob_len) {
    memset(h, 0, sizeof(*h));
    h->magic = CVMFS_PATHIDX_MAGIC;
    h->version = CVMFS_PATHIDX_VERSION;
    h->hash_sz = (uint32_t) sizeof(cvmfs_hash_t);
    h->ent_sz = (uint32_t) sizeof(cvmfs_pathidx_ent_t);
    h->root = *root;
    h->count = b->n;
    h->nbuckets = image->nbuckets;
    h->ents_off = sizeof(*h);
    h->buckets_off = h->ents_off + (uint64_t) b->n * sizeof(*image->ents);
    h->blob_off = h->buckets_off + image->nbuckets * sizeof(*image->buckets);
    h->blob_len = blob_len;
    h->file_len = h->blob_off + blob_len;
    h->hdr_crc = hdr_crc(h);
}

/*
 * WHAT: Write one complete path-index payload to an already open temporary fd.
 * WHY:  Atomic publication is separate from ordered, exact-length serialization.
 * HOW:  Write header, entries, buckets, and used blob bytes in layout order.
 */
static int image_write_fd(int fd, const cvmfs_pathidx_hdr_t *h,
                          const pathidx_image_t *image) {
    if (write_all(fd, h, sizeof(*h)) != 0)
        return -1;
    if (write_all(fd, image->ents, h->count * sizeof(*image->ents)) != 0)
        return -1;
    if (write_all(fd, image->buckets,
                  h->nbuckets * sizeof(*image->buckets)) != 0)
        return -1;
    return write_all(fd, image->blob, (size_t) h->blob_len);
}

/*
 * WHAT: Atomically publish a fully constructed path-index image.
 * WHY:  Readers must observe either the old complete sidecar or the new one.
 * HOW:  Write and close a sibling temporary file, rename on success, unlink else.
 */
static int image_publish(int dfd, const char *name,
                         const cvmfs_pathidx_hdr_t *h,
                         const pathidx_image_t *image) {
    char tmp[300];
    int  name_len = snprintf(tmp, sizeof(tmp), "%s.tmp", name);
    int  fd;
    int  rc = -1;

    if (name_len <= 0 || (size_t) name_len >= sizeof(tmp))
        return -1;
    fd = openat(dfd, tmp, O_CREAT | O_TRUNC | O_WRONLY | O_CLOEXEC, 0644);
    if (fd < 0)
        return -1;
    if (image_write_fd(fd, h, image) == 0 && close(fd) == 0) {
        fd = -1;
        rc = renameat(dfd, tmp, dfd, name) == 0 ? 0 : -1;
    }
    if (fd >= 0)
        close(fd);
    if (rc != 0)
        unlinkat(dfd, tmp, 0);
    return rc;
}

int cvmfs_pathidx_write(cvmfs_pathidx_build_t *b, const cvmfs_hash_t *root,
                        int dfd, const char *name) {
    pathidx_image_t    image;
    cvmfs_pathidx_hdr_t header;
    size_t              blob_len;
    int                 rc;

    if (b->oom || b->n == 0)
        return -1;
    qsort(b->v, b->n, sizeof(*b->v), bent_cmp);
    if (image_alloc(b, &image) != 0)
        return -1;
    blob_len = image_fill(b, &image);
    header_build(&header, b, root, &image, blob_len);
    rc = image_publish(dfd, name, &header, &image);
    image_free(&image);
    return rc;
}

/* ---- mmap reader --------------------------------------------------------- */

/*
 * WHAT: Validate path-index identity, ABI, checksum, and declared file size.
 * WHY:  Foreign or corrupt headers must be refused before geometry is trusted.
 * HOW:  Compare fixed fields only against compiled types and mapped length.
 */
static int header_identity_valid(const cvmfs_pathidx_hdr_t *h, size_t len) {
    return h->magic == CVMFS_PATHIDX_MAGIC &&
           h->version == CVMFS_PATHIDX_VERSION &&
           h->hash_sz == sizeof(cvmfs_hash_t) &&
           h->ent_sz == sizeof(cvmfs_pathidx_ent_t) &&
           h->hdr_crc == hdr_crc(h) && h->file_len == len;
}

/*
 * WHAT: Validate entry and bucket counts against mapped-file capacity.
 * WHY:  Counts drive pointer arithmetic and hash probing after open succeeds.
 * HOW:  Require non-empty bounded entries and a bounded power-of-two table.
 */
static int header_counts_valid(const cvmfs_pathidx_hdr_t *h, size_t len) {
    return h->count > 0 &&
           h->count <= len / sizeof(cvmfs_pathidx_ent_t) &&
           h->nbuckets > 0 && (h->nbuckets & (h->nbuckets - 1)) == 0 &&
           h->nbuckets <= len / sizeof(uint32_t);
}

/*
 * WHAT: Validate that every serialized section is contiguous and in bounds.
 * WHY:  Mmap pointers are derived directly from these attacker-readable offsets.
 * HOW:  Recompute each successor offset and require the blob to end at EOF.
 */
static int header_layout_valid(const cvmfs_pathidx_hdr_t *h, size_t len) {
    uint64_t ents_bytes = h->count * sizeof(cvmfs_pathidx_ent_t);

    return h->ents_off == sizeof(*h) &&
           h->buckets_off == h->ents_off + ents_bytes &&
           h->blob_off == h->buckets_off + h->nbuckets * sizeof(uint32_t) &&
           h->blob_off + h->blob_len == len;
}

int cvmfs_pathidx_open(cvmfs_pathidx_t *ix, int dfd, const char *name) {
    memset(ix, 0, sizeof(*ix));
    int fd = openat(dfd, name, O_RDONLY | O_CLOEXEC);
    if (fd < 0) return -1;
    struct stat st;
    if (fstat(fd, &st) != 0 || st.st_size < (off_t) sizeof(cvmfs_pathidx_hdr_t)
        || st.st_size > (off_t) PIDX_MAX_BYTES) {
        close(fd);
        return -1;
    }
    size_t len = (size_t) st.st_size;
    void *map = brix_plat_map_ro(fd, len);
    close(fd);
    if (map == NULL) return -1;

    const cvmfs_pathidx_hdr_t *h = map;
    if (!header_identity_valid(h, len) || !header_counts_valid(h, len) ||
        !header_layout_valid(h, len)) {
        brix_plat_unmap(map, len);
        return -1;
    }
    ix->map = map;
    ix->maplen = len;
    ix->hdr = h;
    ix->ents = (const cvmfs_pathidx_ent_t *) ((const char *) map + h->ents_off);
    ix->buckets = (const uint32_t *) ((const char *) map + h->buckets_off);
    ix->blob = (const char *) map + h->blob_off;
    return 0;
}

void cvmfs_pathidx_close(cvmfs_pathidx_t *ix) {
    brix_plat_unmap(ix->map, ix->maplen);
    memset(ix, 0, sizeof(*ix));
}

const cvmfs_hash_t *cvmfs_pathidx_root(const cvmfs_pathidx_t *ix) {
    return &ix->hdr->root;
}

/* Bounds-check one entry against the blob and dirent limits. Entry payloads
 * are unverified mmap bytes — never index the blob with them unchecked. */
static int ent_valid(const cvmfs_pathidx_t *ix, const cvmfs_pathidx_ent_t *e) {
    uint64_t bl = ix->hdr->blob_len;
    if (e->path_off >= bl || e->path_len >= bl - e->path_off
        || ix->blob[e->path_off + e->path_len] != '\0')
        return 0;
    if (e->path_len > 0
        && (e->dlen + 1 >= e->path_len
            || ix->blob[e->path_off + e->dlen] != '/'
            || e->path_len - e->dlen - 1 >= sizeof(((cvmfs_dirent_t *) 0)->name)))
        return 0;
    if (e->link_len > 0
        && (e->link_off >= bl || e->link_len >= bl - e->link_off
            || ix->blob[e->link_off + e->link_len] != '\0'
            || e->link_len >= sizeof(((cvmfs_dirent_t *) 0)->symlink)))
        return 0;
    if (e->hash.len > sizeof(e->hash.bytes)) return 0;
    return 1;
}

static void ent_fill(const cvmfs_pathidx_t *ix, const cvmfs_pathidx_ent_t *e,
                     cvmfs_dirent_t *out) {
    memset(out, 0, sizeof(*out));
    if (e->path_len > 0) {
        const char *nm = ix->blob + e->path_off + e->dlen + 1;
        size_t nl = e->path_len - e->dlen - 1;
        memcpy(out->name, nm, nl);
    }
    out->flags = e->flags;
    out->mode = e->mode;
    out->size = e->size;
    out->mtime = e->mtime;
    out->uid = e->uid;
    out->gid = e->gid;
    out->linkcount = e->linkcount;
    if (e->link_len > 0)
        memcpy(out->symlink, ix->blob + e->link_off, e->link_len);
    out->has_hash = e->has_hash != 0;
    if (out->has_hash) out->hash = e->hash;
}

int cvmfs_pathidx_lookup(const cvmfs_pathidx_t *ix, const char *path,
                         cvmfs_dirent_t *out) {
    size_t plen = strlen(path);
    uint64_t mask = ix->hdr->nbuckets - 1;
    uint64_t slot = fnv1a(path, plen) & mask;
    for (uint64_t probes = 0; probes < ix->hdr->nbuckets; probes++) {
        uint32_t v = ix->buckets[slot];
        if (v == 0) return 0;                       /* complete set: absent */
        if ((uint64_t) v - 1 >= ix->hdr->count) return -1;
        const cvmfs_pathidx_ent_t *e = &ix->ents[v - 1];
        if (!ent_valid(ix, e)) return -1;
        if (e->path_len == plen
            && memcmp(ix->blob + e->path_off, path, plen) == 0) {
            ent_fill(ix, e, out);
            return 1;
        }
        slot = (slot + 1) & mask;
    }
    return -1;   /* full-table probe without an empty slot: corrupt buckets */
}

/* Compare entry i's dirname against (dir, dl). */
static int dir_cmp(const cvmfs_pathidx_t *ix, uint64_t i,
                   const char *dir, size_t dl) {
    const cvmfs_pathidx_ent_t *e = &ix->ents[i];
    size_t edl = e->dlen;
    size_t m = edl < dl ? edl : dl;
    int c = memcmp(ix->blob + e->path_off, dir, m);
    if (c != 0) return c;
    if (edl != dl) return edl < dl ? -1 : 1;
    return 0;
}

int cvmfs_pathidx_readdir(const cvmfs_pathidx_t *ix, const char *dir,
                          cvmfs_readdir_cb cb, void *ud) {
    cvmfs_dirent_t d;
    int found = cvmfs_pathidx_lookup(ix, dir, &d);
    if (found != 1 || (d.flags & CVMFS_FLAG_DIR) == 0)
        return -1;                        /* not an indexed directory */

    /* Binary-search the first entry whose dirname >= dir, then walk the run.
     * A dir's own entry shares its CHILDREN's dirname only at the root
     * ("" == dirname of "/x"), where path_len 0 skips it. */
    size_t dl = strlen(dir);
    uint64_t lo = 0, hi = ix->hdr->count;
    while (lo < hi) {
        uint64_t mid = lo + (hi - lo) / 2;
        if (!ent_valid(ix, &ix->ents[mid])) return -1;
        if (dir_cmp(ix, mid, dir, dl) < 0) lo = mid + 1;
        else hi = mid;
    }
    int n = 0;
    for (uint64_t i = lo; i < ix->hdr->count; i++) {
        const cvmfs_pathidx_ent_t *e = &ix->ents[i];
        if (!ent_valid(ix, e)) return -1;
        if (dir_cmp(ix, i, dir, dl) != 0) break;
        if (e->path_len == 0) continue;          /* the root's own entry */
        cvmfs_dirent_t out;
        ent_fill(ix, e, &out);
        cb(&out, ud);
        n++;
    }
    return n;
}
