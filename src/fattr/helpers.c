/*
 * WHAT: This file provides shared helper functions for the XRootD fattr protocol handlers. Maps POSIX errno values to kXR error codes, encodes per-attribute result codes into wire-format response buffers, parses nvec request payloads (attribute name lists with embedded result slots), and builds vector status responses for set/del operations.
 *
 * WHY: Multiple fattr sub-code handlers (get, set, del) share common patterns — errno→kXR mapping, rc encoding in network byte order, nvec parsing. Centralizing these helpers avoids duplication and ensures consistent error code translation across all fattr operations. ---- */
#include "fattr/ngx_xrootd_fattr.h"
#include "../compat/error_mapping.h"
#include "../compat/fattr_codec.h"   /* shared nvec entry parser (libxrdproto) */
#include <errno.h>
#include <string.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/xattr.h>
#include <arpa/inet.h>
#include "../compat/alloc_guard.h"

uint16_t
fattr_errno_to_xrd(int err)
{
    switch (err) {
    case ENODATA:  return kXR_AttrNotFound;
    case ERANGE:   return kXR_ArgTooLong;
    default:       return xrootd_kxr_from_errno(err);
    }
}
/* WHAT: Maps POSIX errno values to XRootD kXR error codes. ENODATA → kXR_AttrNotFound (attribute not found), ERANGE → kXR_ArgTooLong (value too long for buffer). All other errnos delegate to xrootd_kxr_from_errno() which uses the standard errno→kXR mapping table. */
/* WHY: POSIX filesystem xattr syscalls return ENODATA/ERANGE/etc but XRootD wire protocol expects kXR codes. This translation ensures error responses match the XRootD spec regardless of underlying filesystem behavior. The default case delegates to the shared errno→kXR converter for consistency across all modules. */
/* HOW: switch(err) — ENODATA returns kXR_AttrNotFound; ERANGE returns kXR_ArgTooLong; any other value calls xrootd_kxr_from_errno(err). Returns uint16_t kXR code. Used by fattr_set_rc() and all fattr handlers when getxattr/fgetxattr/setxattr/removexattr return negative with errno set. */

void
fattr_set_rc(xrootd_fattr_entry_t *attr, uint16_t rc)
{
    uint16_t rc_be;

    attr->errcode = rc;

    rc_be = htons(rc);
    ngx_memcpy(attr->rc_ptr, &rc_be, 2);
}
/* WHAT: Encodes a per-attribute result code into the wire-format response buffer. Sets both the in-memory errcode field and writes the network-byte-order (big-endian) 16-bit value at rc_ptr for direct inclusion in the response payload. */
/* WHY: fattr responses embed per-attribute status codes as 2-byte big-endian values at fixed positions within nvec_copy buffers. The caller allocates these buffers and rc_ptr points back into them so later operations can overwrite only the result slot without shifting other entries. Setting both errcode (in-memory) and rc_ptr (wire-format) ensures consistency for error counting and response building. */
/* HOW: Sets attr->errcode = rc in memory, then calls htons(rc) to convert to network byte order, copies 2 bytes via ngx_memcpy(attr->rc_ptr, &rc_be, 2). No validation — accepts any uint16_t rc value including 0 (success). Used by fattr_get() and all set/del handlers. */

ssize_t
fattr_parse_nvec(ngx_log_t *log, u_char *nvec_copy, size_t buflen,
    int numattr, xrootd_fattr_entry_t *attrs)
{
    u_char *cursor;
    int     attr_index;

    /*
     * nvec is repeated as:
     *   [2-byte per-attribute result slot][NUL-terminated attribute name]
     *
     * The request payload is copied before parsing, so rc_ptr can safely point
     * back into nvec_copy.  Later operations overwrite only the result slot.
     */
/* WHY: nvec is the XRootD request payload for set/del/fattrGet — it carries attribute names with embedded 2-byte result slots that handlers overwrite with per-attribute status codes. Parsing into attr[] entries enables subsequent operations to read names, compute xkey prefixes, and write rc values at fixed positions. */
/* HOW: Initializes cursor = nvec_copy, end = nvec_copy + buflen. Loop over numattr entries: checks cursor+2 <= end (truncation guard), sets attrs[i].rc_ptr=cursor, errcode=0, value=NULL, vlen=0; advances cursor by 2. Scans for NUL terminator to find name length — if cursor >= end logs "name not null-terminated" and returns -1. Validates name_len > 0 && <= kXR_faMaxNlen — otherwise logs invalid length and returns -1. Sets attrs[i].name=name_start, nlen=name_len; snprintf xkey with XROOTD_FATTR_XKEY_PFX prefix + %.*s format. Advances cursor past NUL. Returns (ssize_t)(cursor - nvec_copy) = bytes consumed. */
    cursor = nvec_copy;

    for (attr_index = 0; attr_index < numattr; attr_index++) {
        const uint8_t *name_p;
        size_t         name_len, off, next;

        /* Shared read-only scan of one [int16 rc][name\0] entry (libxrdproto).
         * The rc slot lives at cursor; we hold that pointer ourselves so the
         * set/del handlers can rewrite it in place (fattr_set_rc) — the shared
         * parser never touches the buffer. */
        off = (size_t) (cursor - nvec_copy);
        if (xrdp_fattr_nvec_parse(nvec_copy, buflen, off, NULL,
                                  &name_p, &name_len, &next) != 0) {
            ngx_log_error(NGX_LOG_WARN, log, 0,
                          "xrootd: fattr nvec truncated/unterminated at entry %d",
                          attr_index);
            return -1;
        }

        /* Name-length policy is server-side (the wire parser is policy-free). */
        if (name_len == 0 || name_len > kXR_faMaxNlen) {
            ngx_log_error(NGX_LOG_WARN, log, 0,
                          "xrootd: fattr name length %uz invalid",
                          name_len);
            return -1;
        }

        attrs[attr_index].rc_ptr = cursor;        /* the 2-byte rc slot */
        attrs[attr_index].errcode = 0;
        attrs[attr_index].value = NULL;
        attrs[attr_index].vlen = 0;
        attrs[attr_index].name = (char *) name_p;
        attrs[attr_index].nlen = name_len;
        snprintf(attrs[attr_index].xkey, sizeof(attrs[attr_index].xkey),
                 XROOTD_FATTR_XKEY_PFX "%.*s", (int) name_len, name_p);

        cursor = nvec_copy + next;
    }

    return (ssize_t) (cursor - nvec_copy);
}

ngx_int_t
fattr_send_vector_status(xrootd_ctx_t *ctx, ngx_connection_t *c,
    u_char *nvec_copy, size_t nvec_len, int numattr,
    xrootd_fattr_entry_t *attrs)
{
    ngx_pool_t *pool;
    u_char     *response;
    size_t      response_size;
    int         error_count;
    int         attr_index;

    pool = c->pool;
    error_count = 0;

    for (attr_index = 0; attr_index < numattr; attr_index++) {
        if (attrs[attr_index].errcode) {
            error_count++;
        }
    }

    response_size = 2 + nvec_len;
    XROOTD_PALLOC_OR_RETURN(response, pool, response_size, xrootd_send_error(ctx, c, kXR_NoMemory, "out of memory"));

    response[0] = (u_char) error_count;
    response[1] = (u_char) numattr;
    ngx_memcpy(response + 2, nvec_copy, nvec_len);

    XROOTD_OP_OK(ctx, XROOTD_OP_FATTR);
    return xrootd_send_ok(ctx, c, response, (uint32_t) response_size);
}
/* WHAT: Builds a vector status response for fattr set/del operations — encodes error_count + numattr header bytes, copies nvec payload, and sends via xrootd_send_ok(). Used by set.c and del.c to return per-attribute results in wire format. */
/* WHY: After setxattr/removexattr operations complete, each attribute has an errcode set in attrs[]. This function counts errors for the response header byte (error_count), allocates a minimal 2 + nvec_len response buffer, and sends it with XROOTD_OP_OK marker. No per-attribute values are included — only status codes. */
/* HOW: Counts error entries via loop over attrs[] checking errcode != 0. Allocates response = ngx_palloc(pool, 2 + nvec_len) — if OOM returns xrootd_send_error(kXR_NoMemory). Writes response[0]=error_count, response[1]=numattr; memcpy(nvec_copy) at offset 2. Calls XROOTD_OP_OK() then returns xrootd_send_ok(). */
