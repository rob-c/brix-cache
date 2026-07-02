/*
 * fs/backend/csi_tagstore.c — persistent per-page CRC32C tagstore (see header).
 *
 * WHAT: Open/read/write/truncate of the ".xrdt" sidecar that holds one CRC32C
 *       per 4096-byte data page, plus the 24-byte versioned header. WHY: gives
 *       XRootD-OssCsi-style at-rest + on-read page integrity. HOW: a confined
 *       openat2(RESOLVE_BENEATH) under the prefix root; all tag pread/pwrite are
 *       local to this backend module (INVARIANT 11). CRC32C via the shared
 *       compat engine.
 */

#include "csi_tagstore.h"
#include "compat/crc32c.h"
#include "path/beneath.h"

#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <stdio.h>

/* csi_pread_full — loop pread until len or EOF/error */static ssize_t
csi_pread_full(int fd, void *buf, size_t len, off_t off)
{
    size_t done = 0;

    while (done < len) {
        ssize_t n = pread(fd, (char *) buf + done, len - done, off + done);
        if (n == 0) {
            break;
        }
        if (n < 0) {
            if (errno == EINTR) {
                continue;
            }
            return -1;
        }
        done += (size_t) n;
    }
    return (ssize_t) done;
}

/* csi_pwrite_full — loop pwrite until len or error */static ssize_t
csi_pwrite_full(int fd, const void *buf, size_t len, off_t off)
{
    size_t done = 0;

    while (done < len) {
        ssize_t n = pwrite(fd, (const char *) buf + done, len - done,
                           off + done);
        if (n < 0) {
            if (errno == EINTR) {
                continue;
            }
            return -1;
        }
        done += (size_t) n;
    }
    return (ssize_t) done;
}

/* csi_read_header — parse + verify the 24-byte header */static int
csi_read_header(xrootd_csi_t *c)
{
    unsigned char b[XROOTD_CSI_HDR_LEN];
    uint32_t      magic, flags, want, got;
    uint16_t      version, page_log2;

    if (csi_pread_full(c->tfd, b, XROOTD_CSI_HDR_LEN, 0) != XROOTD_CSI_HDR_LEN) {
        return XROOTD_CSI_NOTAGS;
    }
    memcpy(&magic, b + 0, 4);
    if (magic != XROOTD_CSI_MAGIC) {
        return XROOTD_CSI_ERR;
    }
    memcpy(&version,   b + 4, 2);
    memcpy(&page_log2, b + 6, 2);
    memcpy(&c->tracked_len, b + 8, 8);
    memcpy(&flags, b + 16, 4);
    want = xrootd_crc32c_value(b, 20);
    memcpy(&got, b + 20, 4);
    if (want != got || version != 1 || page_log2 != 12) {
        return XROOTD_CSI_ERR;
    }
    c->fill = (flags & 1u) ? 1 : 0;
    return XROOTD_CSI_OK;
}

/* xrootd_csi_sync_header — write the current header to disk */int
xrootd_csi_sync_header(xrootd_csi_t *c)
{
    unsigned char b[XROOTD_CSI_HDR_LEN];
    uint32_t      magic = XROOTD_CSI_MAGIC;
    uint32_t      flags = c->fill ? 1u : 0u;
    uint32_t      crc;
    uint16_t      version = 1, page_log2 = 12;

    memset(b, 0, sizeof(b));
    memcpy(b + 0, &magic, 4);
    memcpy(b + 4, &version, 2);
    memcpy(b + 6, &page_log2, 2);
    memcpy(b + 8, &c->tracked_len, 8);
    memcpy(b + 16, &flags, 4);
    crc = xrootd_crc32c_value(b, 20);
    memcpy(b + 20, &crc, 4);

    return (csi_pwrite_full(c->tfd, b, XROOTD_CSI_HDR_LEN, 0)
            == XROOTD_CSI_HDR_LEN) ? XROOTD_CSI_OK : XROOTD_CSI_ERR;
}

/* xrootd_csi_open — confined open of the sidecar tag file */int
xrootd_csi_open(xrootd_csi_t *c, int rootfd, const char *rel_data_path,
    const char *prefix, int create)
{
    char tagrel[4096];
    int  flags;
    int  rc;

    c->tfd = -1;
    c->tracked_len = 0;

    /* xrootd_open_beneath() resolves relative to the export rootfd under
     * RESOLVE_BENEATH, which rejects absolute paths — so strip any leading '/'
     * from both the prefix and the data path before composing the tag path. */
    while (prefix != NULL && prefix[0] == '/') {
        prefix++;
    }
    while (rel_data_path != NULL && rel_data_path[0] == '/') {
        rel_data_path++;
    }

    if (prefix != NULL && prefix[0] != '\0') {
        snprintf(tagrel, sizeof(tagrel), "%s/%s.xrdt", prefix, rel_data_path);
    } else {
        snprintf(tagrel, sizeof(tagrel), "%s.xrdt", rel_data_path);
    }

    /* xrootd_open_beneath(O_CREAT) does NOT create intermediate directories;
     * the tag tree mirrors the data tree under the prefix, so mkdir each parent
     * component (confined) before creating the tag file. */
    if (create) {
        char  *slash;
        size_t off = 0;

        while ((slash = strchr(tagrel + off, '/')) != NULL) {
            *slash = '\0';
            (void) xrootd_mkdir_beneath(rootfd, tagrel, 0700); /* EEXIST ok */
            *slash = '/';
            off = (size_t) (slash - tagrel) + 1;
        }
    }

    flags = O_RDWR | (create ? O_CREAT : 0);
    c->tfd = xrootd_open_beneath(rootfd, tagrel, flags, 0600);
    if (c->tfd < 0) {
        return (errno == ENOENT) ? XROOTD_CSI_NOTAGS : XROOTD_CSI_ERR;
    }

    rc = csi_read_header(c);
    if (rc == XROOTD_CSI_OK) {
        return XROOTD_CSI_OK;
    }
    if (rc == XROOTD_CSI_NOTAGS && create) {
        return xrootd_csi_sync_header(c);            /* fresh tag file */
    }
    xrootd_csi_close(c);
    return rc;
}

/* xrootd_csi_read_tags / _write_tags */ssize_t
xrootd_csi_read_tags(xrootd_csi_t *c, uint32_t *tags, off_t page0, size_t n)
{
    off_t   off = XROOTD_CSI_HDR_LEN + page0 * (off_t) sizeof(uint32_t);
    ssize_t got = csi_pread_full(c->tfd, tags, n * sizeof(uint32_t), off);

    return (got < 0) ? XROOTD_CSI_ERR : got / (ssize_t) sizeof(uint32_t);
}

ssize_t
xrootd_csi_write_tags(xrootd_csi_t *c, const uint32_t *tags, off_t page0,
    size_t n)
{
    off_t   off = XROOTD_CSI_HDR_LEN + page0 * (off_t) sizeof(uint32_t);
    ssize_t put = csi_pwrite_full(c->tfd, tags, n * sizeof(uint32_t), off);

    return (put < 0) ? XROOTD_CSI_ERR : put / (ssize_t) sizeof(uint32_t);
}

/* xrootd_csi_truncate */int
xrootd_csi_truncate(xrootd_csi_t *c, off_t new_len)
{
    off_t npages = (new_len + XROOTD_CSI_PAGE - 1) / XROOTD_CSI_PAGE;

    if (ftruncate(c->tfd,
                  XROOTD_CSI_HDR_LEN + npages * (off_t) sizeof(uint32_t)) != 0)
    {
        return XROOTD_CSI_ERR;
    }
    c->tracked_len = (uint64_t) new_len;
    return xrootd_csi_sync_header(c);
}

/* xrootd_csi_close */void
xrootd_csi_close(xrootd_csi_t *c)
{
    if (c->tfd >= 0) {
        close(c->tfd);
        c->tfd = -1;
    }
}
