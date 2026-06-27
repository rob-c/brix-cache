/*
 * zip_internal.h - private split contract for zip.c and its Phase-38 siblings.
 * Not a public API: include only from client/lib/.  See docs/refactor/phase-38-file-size-unix-modularity.md.
 */
#ifndef XROOTD_ZIP_INTERNAL_H
#define XROOTD_ZIP_INTERNAL_H

#include "zip.h"
#include <stdlib.h>
#include <string.h>
#include <zlib.h>
#include <unistd.h>      
#include <sys/stat.h>    
#include <errno.h>

#define SIG_EOCD     0x06054b50u
#define SIG_Z64LOC   0x07064b50u
#define SIG_Z64EOCD  0x06064b50u
#define SIG_CDFH     0x02014b50u
#define SIG_LFH      0x04034b50u
#define SIG_Z64EOCD_W  0x06064b50u
#define SIG_Z64LOC_W   0x07064b50u
#define ZIP_U32_MAX    0xffffffffu
struct xrdc_zip_writer {
    xrdc_zip_write_fn wr;
    void             *ctx;
    uint64_t          offset;    /* next byte offset to write */
    uint8_t          *cd;        /* accumulated central directory records */
    size_t            cd_len;
    size_t            cd_cap;
    size_t            n;         /* entry count */
    int               any_zip64; /* a member needed a ZIP64 CD entry */
    int               err;       /* sticky negative error code */
};


/* zip.c */
uint16_t le16(const uint8_t *p);
uint32_t le32(const uint8_t *p);
uint64_t le64(const uint8_t *p);
int read_exact(xrdc_zip_pread_fn pread, void *ctx, uint64_t off, uint64_t archive_size, void *buf, size_t len);
int find_eocd(xrdc_zip_pread_fn pread, void *ctx, uint64_t asize, uint64_t *cd_off, uint64_t *cd_size, uint64_t *n_entries);
void apply_zip64_extra(xrdc_zip_entry *ent, const uint8_t *extra, size_t extra_len);
int member_data_offset(xrdc_zip_pread_fn pread, void *ctx, uint64_t asize, const xrdc_zip_entry *e, uint64_t *data_off);
int sink_output(xrdc_zip_sink_fn sink, void *sink_ctx, const uint8_t *data, size_t len, uLong *crc, uint64_t *produced, uint64_t uncomp_size);
void put16(uint8_t *p, uint16_t v);
void put32(uint8_t *p, uint32_t v);
void put64(uint8_t *p, uint64_t v);

/* zip_write.c */
int cd_append(xrdc_zip_writer *w, const uint8_t *p, size_t len);
int w_emit(xrdc_zip_writer *w, const void *p, size_t len);

#endif /* XROOTD_ZIP_INTERNAL_H */
