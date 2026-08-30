/*
 * pblock_store.c — packed-block storage engine (see pblock_store.h).
 *
 * Blob-id/object-dir/block-path computation and the read/write/remove/copy of
 * the fixed-size block files that make up a blob.  Split out of sd_pblock.c;
 * the brix_sd_pblock_driver vtable ops (sd_pblock.c) call these via
 * pblock_store.h.  Stateless: the export state is passed in on every call.
 */

#include "pblock_store.h"

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <sys/random.h>
#include <sys/stat.h>
#include <sys/uio.h>

/* ---- small helpers -------------------------------------------------------- */

int64_t
pblock_now(void)
{
    return (int64_t) time(NULL);
}

/* pblock_last_block — index of the last block holding a file of `size` bytes
 * with stripe `bs`; block 0 always exists, so a 0-byte file has last block 0. */
int64_t
pblock_last_block(int64_t size, int64_t bs)
{
    return size <= 0 ? 0 : (size - 1) / bs;
}

/* pblock_fnv — stable 64-bit hash of a logical path, used as a synthetic inode
 * (the namespace lives in the catalog, not on a filesystem with real inodes). */
uint64_t
pblock_fnv(const char *s)
{
    uint64_t h = 1469598103934665603ULL;   /* FNV-1a offset basis */

    while (*s != '\0') {
        h ^= (unsigned char) *s++;
        h *= 1099511628211ULL;             /* FNV prime */
    }
    return h;
}

/* pblock_mkdir_p — create `path` and any missing parents (mode 0700), tolerating
 * components that already exist. Returns 0 or -1/errno. */
int
pblock_mkdir_p(const char *path)
{
    char   tmp[PATH_MAX];
    char  *p;
    size_t len;

    len = (size_t) snprintf(tmp, sizeof(tmp), "%s", path);
    if (len == 0 || len >= sizeof(tmp)) {
        errno = len == 0 ? EINVAL : ENAMETOOLONG;
        return -1;
    }
    if (tmp[len - 1] == '/') {
        tmp[len - 1] = '\0';
    }

    for (p = tmp + 1; *p != '\0'; p++) {
        if (*p == '/') {
            *p = '\0';
            if (mkdir(tmp, 0700) != 0 && errno != EEXIST) {
                return -1;
            }
            *p = '/';
        }
    }
    if (mkdir(tmp, 0700) != 0 && errno != EEXIST) {
        return -1;
    }
    return 0;
}

/* pblock_gen_blob_id — fill out[] with 32 lowercase hex chars from 16 CSPRNG
 * bytes. Returns 0 or -1/errno. */
int
pblock_gen_blob_id(char out[PBLOCK_BLOB_ID_CAP])
{
    static const char hex[] = "0123456789abcdef";
    unsigned char     raw[16];
    size_t            got = 0;
    int               i;

    while (got < sizeof(raw)) {
        ssize_t n = getrandom(raw + got, sizeof(raw) - got, 0);

        if (n < 0) {
            if (errno == EINTR) {
                continue;
            }
            return -1;
        }
        got += (size_t) n;
    }
    for (i = 0; i < 16; i++) {
        out[i * 2]     = hex[raw[i] >> 4];
        out[i * 2 + 1] = hex[raw[i] & 0x0f];
    }
    out[PBLOCK_BLOB_ID_HEX] = '\0';
    return 0;
}

/* pblock_obj_dir — compose the per-object directory
 * <data_dir>/<b0b1>/<b2b3>/<blob_id> into out[cap]. Returns 0 or -1/ENAMETOOLONG. */
int
pblock_obj_dir(const pblock_state_t *st, const char *blob_id, char *out,
    size_t cap)
{
    int n = snprintf(out, cap, "%s/%c%c/%c%c/%s", st->data_dir,
                     blob_id[0], blob_id[1], blob_id[2], blob_id[3], blob_id);

    if (n < 0 || (size_t) n >= cap) {
        errno = ENAMETOOLONG;
        return -1;
    }
    return 0;
}

/* pblock_block_path — compose the path of block `idx` of an object into out[cap]:
 * <data_dir>/<b0b1>/<b2b3>/<blob_id>/<idx>. Returns 0 or -1/ENAMETOOLONG. */
int
pblock_block_path(const pblock_state_t *st, const char *blob_id, int64_t idx,
    char *out, size_t cap)
{
    int n = snprintf(out, cap, "%s/%c%c/%c%c/%s/%lld", st->data_dir,
                     blob_id[0], blob_id[1], blob_id[2], blob_id[3], blob_id,
                     (long long) idx);

    if (n < 0 || (size_t) n >= cap) {
        errno = ENAMETOOLONG;
        return -1;
    }
    return 0;
}

/* pblock_ensure_obj_dir — create the fan-out + per-object directory for a blob.
 * Returns 0 or -1/errno. */
int
pblock_ensure_obj_dir(const pblock_state_t *st, const char *blob_id)
{
    char d[PATH_MAX];

    if (pblock_obj_dir(st, blob_id, d, sizeof(d)) != 0) {
        return -1;
    }
    return pblock_mkdir_p(d);
}

/* pblock_fill_sd_stat — map a cached catalog row to the protocol-neutral stat the
 * VFS consumes, synthesizing the inode from the logical path. */
void
pblock_fill_sd_stat(const pblock_meta *m, const char *path,
    brix_sd_stat_t *out)
{
    ngx_memzero(out, sizeof(*out));
    out->size   = m->size;
    out->mtime  = m->mtime;
    out->ctime  = m->ctime;
    out->mode   = m->mode;
    out->ino    = (ino_t) pblock_fnv(path);
    out->uid    = (uid_t) m->uid;
    out->gid    = (gid_t) m->gid;
    out->is_dir = m->is_dir ? 1 : 0;
    out->is_reg = m->is_dir ? 0 : 1;
}

/* ---- block-striped byte I/O ----------------------------------------------- */

/* One striped segment of a logical [off, off+len) transfer: which block the
 * cursor `off+done` lands in, the offset within that block, and how many of
 * the remaining bytes fit before its end. Shared by all four stripe loops. */
typedef struct {
    int64_t idx;                        /* block index */
    int64_t boff;                       /* offset within the block */
    size_t  chunk;                      /* bytes of this segment */
} pblock_seg_t;

static void
pblock_seg_at(int64_t bs, off_t off, size_t done, size_t len, pblock_seg_t *sg)
{
    size_t room;

    sg->idx  = (off + (off_t) done) / bs;
    sg->boff = (off + (off_t) done) % bs;
    room     = (size_t) (bs - sg->boff);
    sg->chunk = len - done < room ? len - done : room;
}

/* pblock_write_blocks — write `len` bytes of buf at file offset `off`, striped
 * across the object's block files. blk0_fd (>=0) is reused for block 0; higher
 * blocks (and block 0 when blk0_fd<0) are opened O_RDWR|O_CREAT transiently.
 * Returns bytes written, or -1/errno when nothing was written. */
/* pblock_xform_write — read-modify-write path for a transform-configured export.
 * Every block (including block 0) is a headered file the block-0 fd never serves,
 * so the persistent fd is ignored; each touched block is loaded whole, overlaid
 * with the new bytes, and re-encoded. Returns bytes written or -1/errno. */
static ssize_t
pblock_xform_write(const pblock_state_t *st, const char *blob_id, int64_t bs,
    const void *buf, size_t len, off_t off)
{
    const char    *p = buf;
    size_t         done = 0;
    unsigned char *scratch = malloc((size_t) bs);

    if (scratch == NULL) {
        errno = ENOMEM;
        return -1;
    }
    while (done < len) {
        pblock_seg_t sg;
        char         bp[PATH_MAX];
        uint32_t     llen, nl;

        pblock_seg_at(bs, off, done, len, &sg);
        if (pblock_block_path(st, blob_id, sg.idx, bp, sizeof(bp)) != 0
            || pblock_xform_block_load(&st->xform, sg.idx, bp, scratch, bs,
                                       &llen) != 0)
        {
            break;
        }
        memcpy(scratch + sg.boff, p + done, sg.chunk);
        nl = (uint32_t) (sg.boff + (int64_t) sg.chunk);
        if (llen > nl) {
            nl = llen;
        }
        if (pblock_xform_block_store(&st->xform, sg.idx, bp, scratch, nl, bs)
            != 0)
        {
            break;
        }
        done += sg.chunk;
    }
    free(scratch);
    return done ? (ssize_t) done : -1;
}

/*
 * WHAT: Open the block file needed for one logical pblock write segment.
 * WHY:  Block zero can reuse its persistent handle while later blocks are owned.
 * HOW:  Return block zero directly or resolve and open a transient block path.
 */
static int
pblock_write_fd(const pblock_state_t *st, const char *blob_id, int64_t index,
    int block_zero_fd, int *transient)
{
    char path[PATH_MAX];

    *transient = 0;
    if (index == 0 && block_zero_fd >= 0)
        return block_zero_fd;
    if (pblock_block_path(st, blob_id, index, path, sizeof(path)) != 0)
        return -1;
    *transient = 1;
    return open(path, O_RDWR | O_CREAT, 0600);
}

/*
 * WHAT: Write one buffer slice completely at a block-relative offset.
 * WHY:  EINTR and short writes must not escape the logical block writer.
 * HOW:  Loop pwrite until complete, returning partial progress on hard failure.
 */
static ssize_t
pblock_write_chunk(int fd, const char *data, size_t length, off_t offset)
{
    size_t written = 0;

    while (written < length) {
        ssize_t result = pwrite(fd, data + written, length - written,
                                offset + (off_t) written);

        if (result < 0) {
            if (errno == EINTR)
                continue;
            return written ? (ssize_t) written : -1;
        }
        if (result == 0)
            return written ? (ssize_t) written : -1;
        written += (size_t) result;
    }
    return (ssize_t) written;
}

ssize_t
pblock_write_blocks(const pblock_state_t *st, const char *blob_id, int64_t bs,
    int blk0_fd, const void *buf, size_t len, off_t off)
{
    const char *bytes = buf;
    size_t      done = 0;

    if (pblock_xform_active(&st->xform))
        return pblock_xform_write(st, blob_id, bs, buf, len, off);
    while (done < len) {
        pblock_seg_t sg;
        int          transient;
        int          fd;
        ssize_t      written;

        pblock_seg_at(bs, off, done, len, &sg);
        fd = pblock_write_fd(st, blob_id, sg.idx, blk0_fd, &transient);
        if (fd < 0)
            return done ? (ssize_t) done : -1;
        written = pblock_write_chunk(fd, bytes + done, sg.chunk, sg.boff);
        if (transient)
            close(fd);
        if (written < 0)
            return done ? (ssize_t) done : -1;
        done += (size_t) written;
        if ((size_t) written != sg.chunk)
            return (ssize_t) done;
    }
    return (ssize_t) done;
}

/* pblock_read_blocks — read `len` bytes at file offset `off` (the caller has
 * already clamped len to the file size), striped across block files. blk0_fd
 * (>=0) is reused for block 0. Missing blocks and short blocks read back as
 * zeros (holes). Returns bytes produced, or -1/errno. */
/* pblock_xform_read — decode path for a transform-configured export: load each
 * touched block whole (holes and short blocks zero-fill) and copy out the wanted
 * sub-range. Returns bytes produced or -1/errno. */
static ssize_t
pblock_xform_read(const pblock_state_t *st, const char *blob_id, int64_t bs,
    void *buf, size_t len, off_t off)
{
    char          *p = buf;
    size_t         done = 0;
    unsigned char *scratch;

    if (len == 0) {
        return 0;
    }
    scratch = malloc((size_t) bs);
    if (scratch == NULL) {
        errno = ENOMEM;
        return -1;
    }
    while (done < len) {
        pblock_seg_t sg;
        char         bp[PATH_MAX];
        uint32_t     llen;

        pblock_seg_at(bs, off, done, len, &sg);
        if (pblock_block_path(st, blob_id, sg.idx, bp, sizeof(bp)) != 0
            || pblock_xform_block_load(&st->xform, sg.idx, bp, scratch, bs,
                                       &llen) != 0)
        {
            break;
        }
        memcpy(p + done, scratch + sg.boff, sg.chunk);
        done += sg.chunk;
    }
    free(scratch);
    return done ? (ssize_t) done : -1;
}

ssize_t
pblock_read_blocks(const pblock_state_t *st, const char *blob_id, int64_t bs,
    int blk0_fd, void *buf, size_t len, off_t off)
{
    char  *p = buf;
    size_t done = 0;

    if (pblock_xform_active(&st->xform)) {
        return pblock_xform_read(st, blob_id, bs, buf, len, off);
    }

    while (done < len) {
        pblock_seg_t sg;
        int          fd, transient = 0;
        ssize_t      r;

        pblock_seg_at(bs, off, done, len, &sg);
        if (sg.idx == 0 && blk0_fd >= 0) {
            fd = blk0_fd;
        } else {
            char bp[PATH_MAX];

            if (pblock_block_path(st, blob_id, sg.idx, bp, sizeof(bp)) != 0) {
                return done ? (ssize_t) done : -1;
            }
            fd = open(bp, O_RDONLY);
            if (fd < 0) {
                if (errno == ENOENT) {
                    memset(p + done, 0, sg.chunk);   /* whole-block hole */
                    done += sg.chunk;
                    continue;
                }
                return done ? (ssize_t) done : -1;
            }
            transient = 1;
        }

        r = pread(fd, p + done, sg.chunk, sg.boff);
        if (transient) {
            close(fd);
        }
        if (r < 0) {
            return done ? (ssize_t) done : -1;
        }
        if ((size_t) r < sg.chunk) {
            memset(p + done + (size_t) r, 0, sg.chunk - (size_t) r);  /* tail hole */
        }
        done += sg.chunk;
    }
    return (ssize_t) done;
}

/* pblock_advise_blocks — issue posix_fadvise(2) over the block files backing
 * [off, off+len), translating each block's slice into a block-local range.
 *
 * WHAT: The advisory twin of pblock_read_blocks — same segment walk, same
 *       block-0-fd reuse, but the pread is replaced by an fadvise and a missing
 *       block is skipped instead of zero-filled.
 * WHY:  A striped object is many files, so a single fadvise on the object's
 *       block-0 fd (the only persistent one) describes at most the first block —
 *       a sequential or WILLNEED hint over a multi-block read has to reach every
 *       block file, or the readahead the caller asked for simply never happens.
 * HOW:  Transient blocks are opened O_RDONLY for the hint and closed
 *       immediately. Advisory throughout: a per-block failure is skipped, and
 *       only a caller error (bad path) returns -1. A transform-configured export
 *       returns 0 without hinting — the block bytes are encoded, so an advice
 *       range computed in plaintext coordinates would describe the wrong bytes.
 */
int
pblock_advise_blocks(const pblock_state_t *st, const char *blob_id, int64_t bs,
    int blk0_fd, size_t len, off_t off, int advice)
{
#if defined(POSIX_FADV_SEQUENTIAL)
    size_t done = 0;

    if (pblock_xform_active(&st->xform)) {
        return 0;
    }

    while (done < len) {
        pblock_seg_t sg;
        int          fd, transient = 0;

        pblock_seg_at(bs, off, done, len, &sg);
        if (sg.idx == 0 && blk0_fd >= 0) {
            fd = blk0_fd;
        } else {
            char bp[PATH_MAX];

            if (pblock_block_path(st, blob_id, sg.idx, bp, sizeof(bp)) != 0) {
                return -1;
            }
            fd = open(bp, O_RDONLY);
            if (fd < 0) {
                done += sg.chunk;       /* hole / unwritten block: nothing to hint */
                continue;
            }
            transient = 1;
        }

        (void) posix_fadvise(fd, sg.boff, (off_t) sg.chunk, advice);
        if (transient) {
            close(fd);
        }
        done += sg.chunk;
    }
    return 0;
#else
    (void) st; (void) blob_id; (void) bs; (void) blk0_fd;
    (void) len; (void) off; (void) advice;
    return 0;
#endif
}

/* pblock_remove_blocks — unlink every block file of an object and remove its
 * per-object directory (and best-effort the now-possibly-empty fan-out dirs). */
void
pblock_remove_blocks(const pblock_state_t *st, const char *blob_id,
    int64_t size, int64_t bs)
{
    int64_t last = pblock_last_block(size, bs);
    int64_t i;
    char    path[PATH_MAX];

    for (i = 0; i <= last; i++) {
        if (pblock_block_path(st, blob_id, i, path, sizeof(path)) == 0) {
            unlink(path);
        }
    }
    if (pblock_obj_dir(st, blob_id, path, sizeof(path)) == 0) {
        rmdir(path);
    }
    /* best-effort: drop the now-empty fan-out directories (skip on truncation) */
    if (snprintf(path, sizeof(path), "%s/%c%c/%c%c", st->data_dir,
                 blob_id[0], blob_id[1], blob_id[2], blob_id[3])
        < (int) sizeof(path))
    {
        rmdir(path);
    }
    if (snprintf(path, sizeof(path), "%s/%c%c", st->data_dir, blob_id[0],
                 blob_id[1]) < (int) sizeof(path))
    {
        rmdir(path);
    }
}

/* pblock_copy_one_block — copy one source block file to a destination block path
 * via a pread/pwrite loop; a missing source block (hole) is skipped. Returns the
 * bytes copied (>=0) or -1/errno. */
ssize_t
pblock_copy_one_block(const char *src_path, const char *dst_path)
{
    char    buf[65536];
    off_t   off = 0;
    int     sfd, dfd;
    ssize_t copied = 0;

    sfd = open(src_path, O_RDONLY);
    if (sfd < 0) {
        return errno == ENOENT ? 0 : -1;   /* hole: nothing to copy */
    }
    dfd = open(dst_path, O_RDWR | O_CREAT | O_EXCL, 0600);
    if (dfd < 0) {
        close(sfd);
        return -1;
    }

    for ( ;; ) {
        ssize_t n = pread(sfd, buf, sizeof(buf), off);
        ssize_t w = 0;

        if (n < 0) {
            close(sfd);
            close(dfd);
            return -1;
        }
        if (n == 0) {
            break;
        }
        while (w < n) {
            ssize_t k = pwrite(dfd, buf + w, (size_t) (n - w), off + w);

            if (k < 0) {
                close(sfd);
                close(dfd);
                return -1;
            }
            w += k;
        }
        off += n;
    }
    close(sfd);
    close(dfd);
    copied = off;
    return copied;
}
