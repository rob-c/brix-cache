/*
 * tap_audit.c — single-line JSON formatter for a tapped frame.
 *
 * Pure string building into a caller buffer (no I/O, no allocation): the consumer
 * decides where the line goes (error.log, a dedicated audit file). Path bytes from
 * the wire are JSON-escaped (", \\, and control bytes) and bounded by path_len —
 * the wire path is NOT NUL-terminated, so we never treat it as a C string.
 */

#include "tap.h"
#include "protocols/root/protocol/opcodes.h"

#include <stdio.h>
#include <string.h>

/* Compact opcode → name for the audited request ops; NULL → numeric fallback. */
static const char *
tap_opcode_name(uint16_t op)
{
    switch (op) {
    case kXR_open:     return "open";
    case kXR_stat:     return "stat";
    case kXR_statx:    return "statx";
    case kXR_mkdir:    return "mkdir";
    case kXR_rm:       return "rm";
    case kXR_rmdir:    return "rmdir";
    case kXR_mv:       return "mv";
    case kXR_truncate: return "truncate";
    case kXR_dirlist:  return "dirlist";
    case kXR_locate:   return "locate";
    case kXR_read:     return "read";
    case kXR_write:    return "write";
    case kXR_close:    return "close";
    default:           return NULL;
    }
}

/* Append a JSON-escaped, length-bounded string value. Returns 0 on overflow. */
static int
tap_json_append_escaped(char *out, size_t outsz, size_t *pos,
    const uint8_t *s, size_t slen)
{
    size_t i;
    for (i = 0; i < slen; i++) {
        unsigned char ch = s[i];
        char esc[8];
        const char *seg;
        size_t seglen;
        if (ch == '"' || ch == '\\') {
            esc[0] = '\\'; esc[1] = (char) ch; seglen = 2; seg = esc;
        } else if (ch < 0x20) {
            seglen = (size_t) snprintf(esc, sizeof(esc), "\\u%04x", ch);
            seg = esc;
        } else {
            esc[0] = (char) ch; seglen = 1; seg = esc;
        }
        if (*pos + seglen >= outsz) { return 0; }
        memcpy(out + *pos, seg, seglen);
        *pos += seglen;
    }
    return 1;
}

size_t
brix_tap_audit_format(const brix_tap_frame_t *f, brix_tap_dir_t dir,
    char *out, size_t outsz)
{
    const char *dirs = (dir == BRIX_TAP_C2U) ? "c2u" : "u2c";
    const char *opn;
    size_t pos;
    int n;

    if (f == NULL || out == NULL || outsz == 0) {
        return 0;
    }

    /* Fixed prefix + numeric fields via snprintf (bounded). */
    if (f->is_request) {
        opn = tap_opcode_name(f->opcode);
        if (opn != NULL) {
            n = snprintf(out, outsz,
                "{\"dir\":\"%s\",\"streamid\":%u,\"op\":\"%s\",\"dlen\":%u",
                dirs, f->streamid, opn, f->dlen);
        } else {
            n = snprintf(out, outsz,
                "{\"dir\":\"%s\",\"streamid\":%u,\"op\":%u,\"dlen\":%u",
                dirs, f->streamid, f->opcode, f->dlen);
        }
    } else {
        n = snprintf(out, outsz,
            "{\"dir\":\"%s\",\"streamid\":%u,\"status\":%u,\"dlen\":%u",
            dirs, f->streamid, f->status, f->dlen);
    }
    if (n < 0 || (size_t) n >= outsz) {
        return 0;
    }
    pos = (size_t) n;

    /* Optional escaped path. */
    if (f->path != NULL && f->path_len > 0) {
        const char *pkey = ",\"path\":\"";
        size_t klen = strlen(pkey);
        if (pos + klen >= outsz) { return 0; }
        memcpy(out + pos, pkey, klen);
        pos += klen;
        if (!tap_json_append_escaped(out, outsz, &pos, f->path, f->path_len)) {
            return 0;
        }
        if (pos + 1 >= outsz) { return 0; }
        out[pos++] = '"';
    }

    if (pos + 1 >= outsz) { return 0; }  /* room for '}' + NUL */
    out[pos++] = '}';
    out[pos]   = '\0';
    return pos;
}
