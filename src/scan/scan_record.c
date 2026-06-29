/*
 * scan_record.c — NDJSON record formatting (see scan_record.h).
 *
 * Pure, ngx-free, allocation-free. Each formatter renders exactly one line into
 * a caller buffer and returns its length, or -1 if it would not fit (it never
 * emits a truncated, invalid JSON line). Unit-tested by scan_unittest.c.
 */
#include "scan_record.h"

#include <stdio.h>
#include <string.h>

/* Bound on a single escaped logical path rendered into a record. Export paths
 * are far shorter; an over-long path yields -1 rather than a truncated line. */
#define SCAN_ESC_MAX 2048

int
xrootd_scan_json_escape(const char *in, size_t len, char *out, size_t cap)
{
    size_t      o = 0;
    size_t      i;
    const char *esc;

    for (i = 0; i < len; i++) {
        unsigned char ch = (unsigned char) in[i];
        char          ubuf[7];

        switch (ch) {
        case '"':  esc = "\\\""; break;
        case '\\': esc = "\\\\"; break;
        case '\b': esc = "\\b";  break;
        case '\f': esc = "\\f";  break;
        case '\n': esc = "\\n";  break;
        case '\r': esc = "\\r";  break;
        case '\t': esc = "\\t";  break;
        default:
            if (ch < 0x20) {
                snprintf(ubuf, sizeof(ubuf), "\\u%04x", ch);
                esc = ubuf;
            } else {
                /* room for the byte + NUL */
                if (o + 1 >= cap) {
                    return -1;
                }
                out[o++] = (char) ch;
                continue;
            }
        }
        {
            size_t elen = strlen(esc);
            if (o + elen >= cap) {
                return -1;
            }
            memcpy(out + o, esc, elen);
            o += elen;
        }
    }
    if (o >= cap) {
        return -1;
    }
    out[o] = '\0';
    return (int) o;
}

int
xrootd_scan_record_file(char *buf, size_t cap, const char *path, int64_t size,
                        int64_t mtime, const char *alg, const char *stored,
                        const char *computed, const char *status)
{
    char esc[SCAN_ESC_MAX];
    char stored_part[160];
    char computed_part[160];
    int  n;

    if (xrootd_scan_json_escape(path, strlen(path), esc, sizeof(esc)) < 0) {
        return -1;
    }
    if (stored != NULL) {
        snprintf(stored_part, sizeof(stored_part), "\"stored\":\"%s\"", stored);
    } else {
        snprintf(stored_part, sizeof(stored_part), "\"stored\":null");
    }
    if (computed != NULL) {
        snprintf(computed_part, sizeof(computed_part),
                 ",\"computed\":\"%s\"", computed);
    } else {
        computed_part[0] = '\0';
    }

    n = snprintf(buf, cap,
        "{\"t\":\"file\",\"path\":\"%s\",\"size\":%lld,\"mtime\":%lld,"
        "\"alg\":\"%s\",%s%s,\"status\":\"%s\"}",
        esc, (long long) size, (long long) mtime, alg,
        stored_part, computed_part, status);
    if (n < 0 || (size_t) n >= cap) {
        return -1;
    }
    return n;
}

int
xrootd_scan_record_inspect(char *buf, size_t cap, const char *path,
                           const char *backend, int64_t size, int64_t mtime,
                           const char *stored_src, int ns_consistent)
{
    char esc[SCAN_ESC_MAX];
    int  n;

    if (xrootd_scan_json_escape(path, strlen(path), esc, sizeof(esc)) < 0) {
        return -1;
    }
    n = snprintf(buf, cap,
        "{\"t\":\"inspect\",\"path\":\"%s\",\"backend\":\"%s\",\"size\":%lld,"
        "\"mtime\":%lld,\"stored_src\":\"%s\",\"namespace_consistent\":%s}",
        esc, backend, (long long) size, (long long) mtime, stored_src,
        ns_consistent ? "true" : "false");
    if (n < 0 || (size_t) n >= cap) {
        return -1;
    }
    return n;
}

int
xrootd_scan_record_health(char *buf, size_t cap, const char *backend,
                          uint64_t total_bytes, uint64_t free_bytes,
                          uint64_t used_bytes)
{
    int n = snprintf(buf, cap,
        "{\"t\":\"health\",\"backend\":\"%s\",\"total_bytes\":%llu,"
        "\"free_bytes\":%llu,\"used_bytes\":%llu}",
        backend, (unsigned long long) total_bytes,
        (unsigned long long) free_bytes, (unsigned long long) used_bytes);
    if (n < 0 || (size_t) n >= cap) {
        return -1;
    }
    return n;
}

int
xrootd_scan_record_cursor(char *buf, size_t cap, const char *after)
{
    char esc[SCAN_ESC_MAX];
    int  n;

    if (xrootd_scan_json_escape(after, strlen(after), esc, sizeof(esc)) < 0) {
        return -1;
    }
    n = snprintf(buf, cap, "{\"t\":\"cursor\",\"after\":\"%s\"}", esc);
    if (n < 0 || (size_t) n >= cap) {
        return -1;
    }
    return n;
}

int
xrootd_scan_record_summary(char *buf, size_t cap, const xrootd_scan_summary_t *s)
{
    int n = snprintf(buf, cap,
        "{\"t\":\"summary\",\"files\":%llu,\"bytes\":%llu,\"ok\":%llu,"
        "\"mismatch\":%llu,\"missing\":%llu,\"unreadable\":%llu,"
        "\"filled\":%llu,\"already\":%llu,\"elapsed_s\":%.2f}",
        (unsigned long long) s->files, (unsigned long long) s->bytes,
        (unsigned long long) s->ok, (unsigned long long) s->mismatch,
        (unsigned long long) s->missing, (unsigned long long) s->unreadable,
        (unsigned long long) s->filled, (unsigned long long) s->already,
        s->elapsed_s);
    if (n < 0 || (size_t) n >= cap) {
        return -1;
    }
    return n;
}
