/*
 * ops_internal.h - private split contract for ops_file.c and its Phase-38 siblings.
 * Not a public API: include only from client/lib/.  See docs/refactor/phase-38-file-size-unix-modularity.md.
 */
#ifndef XROOTD_OPS_INTERNAL_H
#define XROOTD_OPS_INTERNAL_H

#include "xrdc.h"
#include "core/compat/crc32c.h"   
#include "core/compat/pgio.h"     
#include "core/compat/codec_core.h" 
#include "protocols/root/protocol/frame_hdr.h"
#include "protocols/root/protocol/open_flags.h"
#include "protocols/root/protocol/readv_seg.h"
#include "protocols/root/protocol/codec/wire_codec.h"   /* shared per-opcode wire-body codec */
#include <arpa/inet.h>
#include <endian.h>
#include <string.h>
#include <stdlib.h>
#include <stddef.h>

#define XRDC_PG_STATUSBODY 24   /* ServerResponseBody_Status(16) + offset(8) */
#define XRDC_PGW_MAX_RETRY 3


/* ops_file_pg.c */
int read_status_frame(xrdc_conn *c, uint16_t want_sid, uint8_t *resptype, uint32_t *pgdlen, int64_t *foff, xrdc_status *st);
ssize_t decode_pages(const uint8_t *pg, uint32_t pglen, int64_t file_off, uint8_t *dst, size_t dstcap, xrdc_status *st);
int pgwrite_retry_one(xrdc_conn *c, xrdc_file *f, const uint8_t *buf, int64_t base, size_t len, int64_t pgoff, xrdc_status *st);

#endif /* XROOTD_OPS_INTERNAL_H */
