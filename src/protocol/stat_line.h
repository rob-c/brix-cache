/*
 * stat_line.h — XRootD stat-response line grammar (single source of truth).
 *
 * WHAT: the ASCII body of a kXR_stat / kXR_statx reply (and each kXR_dstat
 *       directory entry) is a space-separated line:
 *         "<id> <size> <flags> <mtime>"
 *       with an OPTIONAL extended tail some servers (EOS) append:
 *         " <ctime> <atime> <mode-octal> <owner> <group>"
 *       This header holds BOTH directions of that one grammar:
 *         - xrootd_statline_format: fields  -> line   (the server is the encoder)
 *         - xrootd_statline_parse:  line    -> fields (the client is the decoder)
 * WHY:  the encoder lived in the module (src/path/stat_body.c, via snprintf) and
 *       the decoder lived in the native client (client/lib/ops_meta.c, via sscanf)
 *       with NOTHING but human discipline keeping the two in step. They are exact
 *       inverse operations on a wire-visible textual spec: if the field order, the
 *       octal-mode encoding, or the mtime units ever drift on one side, stat/dirlist
 *       interop breaks silently. Co-locating both directions (with a round-trip
 *       contract) makes the grammar a single audited artifact.
 * HOW:  header-only static inlines — no ngx, no allocation, no OpenSSL — so the
 *       same code compiles into both the nginx module and the ngx-free client.
 *       The flag *values* (kXR_isDir/kXR_readable/...) are caller policy and stay
 *       at the call sites; this header only owns the line's lexical shape.
 *
 * ROUND-TRIP CONTRACT: for any (id, size, flags, mtime),
 *   xrootd_statline_parse(buf-from-xrootd_statline_format(id,size,flags,mtime))
 *   recovers the same four mandatory fields (have_ext == 0).
 *
 * Clean-room: grammar from src/protocol wire docs (vs XProtocol stat reply).
 */
#ifndef XROOTD_PROTOCOL_STAT_LINE_H
#define XROOTD_PROTOCOL_STAT_LINE_H

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

/* Optional extended tail (EOS long-stat form). All zeroed when absent. */
typedef struct {
    int       have_ext;     /* 1 if the 5-field tail was present, else 0 */
    long      ctime;
    long      atime;
    unsigned  mode;         /* decoded from the octal mode token on the wire */
    char      owner[64];
    char      group[64];
} xrootd_statline_ext;

/*
 * Encode the mandatory 4-field stat line. Returns snprintf's value (the number of
 * bytes that would be written, excluding the NUL) so callers can detect
 * truncation. The integer widths mirror the historical wire encoding exactly:
 * id as %llu, size as %lld, flags as %d, mtime as %ld.
 */
static inline int
xrootd_statline_format(char *out, size_t outsz, unsigned long long id,
                       long long size, int flags, long mtime)
{
    return snprintf(out, outsz, "%llu %lld %d %ld", id, size, flags, mtime);
}

/*
 * Decode a stat line. Fills the four mandatory fields (any out-pointer may be
 * NULL) and, when `ext` is non-NULL, the optional EOS tail (have_ext records
 * whether it was present; the mode token is interpreted as octal). Returns 0 on
 * success, -1 if the line does not carry at least the four mandatory fields.
 */
static inline int
xrootd_statline_parse(const char *s, uint64_t *id, int64_t *size,
                      int *flags, long *mtime, xrootd_statline_ext *ext)
{
    unsigned long long pid    = 0;
    long long          psize  = 0;
    int                pflags = 0;
    long               pmtime = 0, pctime = 0, patime = 0;
    char               modebuf[32], owner[64], group[64];
    int                nf;

    modebuf[0] = owner[0] = group[0] = '\0';

    nf = sscanf(s, "%llu %lld %d %ld %ld %ld %31s %63s %63s",
                &pid, &psize, &pflags, &pmtime,
                &pctime, &patime, modebuf, owner, group);
    if (nf < 4) {
        return -1;
    }

    if (id != NULL)    { *id    = (uint64_t) pid; }
    if (size != NULL)  { *size  = (int64_t) psize; }
    if (flags != NULL) { *flags = pflags; }
    if (mtime != NULL) { *mtime = pmtime; }

    if (ext != NULL) {
        ext->have_ext = 0;
        ext->ctime    = 0;
        ext->atime    = 0;
        ext->mode     = 0;
        ext->owner[0] = '\0';
        ext->group[0] = '\0';

        if (nf >= 9) {
            ext->have_ext = 1;
            ext->ctime    = pctime;
            ext->atime    = patime;
            ext->mode     = (unsigned) strtoul(modebuf, NULL, 8);
            snprintf(ext->owner, sizeof(ext->owner), "%s", owner);
            snprintf(ext->group, sizeof(ext->group), "%s", group);
        }
    }

    return 0;
}

#endif /* XROOTD_PROTOCOL_STAT_LINE_H */
