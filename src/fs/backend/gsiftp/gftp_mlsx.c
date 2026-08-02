/*
 * gftp_mlsx.c — see gftp_mlsx.h. Pure, allocation-free MLSx fact-line parsing
 * for the outbound gsiftp:// driver.
 */

#include "gftp_mlsx.h"


static int
ci_eq(const char *a, size_t alen, const char *b)
{
    size_t i;
    for (i = 0; i < alen; i++) {
        char c = a[i];
        if (c >= 'A' && c <= 'Z') { c = (char) (c - 'A' + 'a'); }
        if (b[i] == '\0' || c != b[i]) {
            return 0;
        }
    }
    return b[alen] == '\0';
}


/* Parse an unsigned decimal in [p,end); *ok=0 on non-digit/empty/overflow. */
static unsigned long long
parse_u64(const char *p, const char *end, int *ok)
{
    unsigned long long v = 0;
    int                n = 0;
    *ok = 0;
    for (; p < end; p++) {
        if (*p < '0' || *p > '9') {
            return 0;
        }
        if (v > (~0ULL - 9) / 10) {          /* would overflow */
            return 0;
        }
        v = v * 10 + (unsigned) (*p - '0');
        n++;
    }
    *ok = (n > 0);
    return v;
}


/* Days since the Unix epoch for a civil (y,m,d), m in 1..12. Hinnant's
 * algorithm — timezone-free, so MLSx `modify=` (always UTC) needs no libc. */
static long long
days_from_civil(long long y, unsigned m, unsigned d)
{
    y -= (m <= 2);
    {
        long long era = (y >= 0 ? y : y - 399) / 400;
        unsigned  yoe = (unsigned) (y - era * 400);
        unsigned  doy = (153 * (m + (m > 2 ? -3 : 9)) + 2) / 5 + d - 1;
        unsigned  doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
        return era * 146097 + (long long) doe - 719468;
    }
}


/* Decode a modify= fact "YYYYMMDDHHMMSS" (optionally ".sss") to a UTC epoch.
 * Returns 0 and sets *out on success, -1 on a malformed timestamp. */
static int
parse_modify(const char *p, size_t len, long long *out)
{
    int  v[6];               /* year, month, day, hour, min, sec */
    int  i, j;
    if (len < 14) {
        return -1;
    }
    for (i = 0, j = 0; i < 6; i++) {
        int width = (i == 0) ? 4 : 2;
        int n = 0, k;
        for (k = 0; k < width; k++, j++) {
            if (p[j] < '0' || p[j] > '9') {
                return -1;
            }
            n = n * 10 + (p[j] - '0');
        }
        v[i] = n;
    }
    if (v[1] < 1 || v[1] > 12 || v[2] < 1 || v[2] > 31
        || v[3] > 23 || v[4] > 59 || v[5] > 60)          /* 60: leap second */
    {
        return -1;
    }
    *out = days_from_civil(v[0], (unsigned) v[1], (unsigned) v[2]) * 86400LL
         + (long long) v[3] * 3600 + (long long) v[4] * 60 + v[5];
    return 0;
}


static void
apply_fact(const char *key, size_t klen, const char *val, size_t vlen,
    gftp_mlsx_ent_t *out)
{
    if (ci_eq(key, klen, "type")) {
        out->is_dir = ci_eq(val, vlen, "dir")
                   || ci_eq(val, vlen, "cdir")
                   || ci_eq(val, vlen, "pdir");
        return;
    }
    if (ci_eq(key, klen, "size")) {
        int ok;
        unsigned long long s = parse_u64(val, val + vlen, &ok);
        if (ok) { out->size = s; out->has_size = 1; }
        return;
    }
    if (ci_eq(key, klen, "modify")) {
        long long   t;
        const char *dot = val;
        size_t      base = vlen;
        size_t      z;
        for (z = 0; z < vlen; z++) {              /* drop a fractional part */
            if (dot[z] == '.') { base = z; break; }
        }
        if (parse_modify(val, base, &t) == 0) {
            out->mtime = t; out->has_mtime = 1;
        }
        return;
    }
    /* Unknown facts (perm, unix.mode, unique, …) are ignored by design. */
}


int
gftp_mlsx_parse(const char *line, size_t len, gftp_mlsx_ent_t *out)
{
    size_t sep, i, fstart;

    out->name = NULL; out->name_len = 0; out->is_dir = 0;
    out->has_size = 0; out->size = 0; out->has_mtime = 0; out->mtime = 0;

    /* Facts and the pathname are separated by exactly one space; a fact value
     * never contains a space, so the first space is the boundary. */
    sep = len;
    for (i = 0; i < len; i++) {
        if (line[i] == ' ') { sep = i; break; }
    }
    if (sep == len || sep + 1 >= len) {
        return -1;                                /* no name present */
    }

    out->name     = line + sep + 1;
    out->name_len = len - (sep + 1);
    for (i = 0; i < out->name_len; i++) {
        char c = out->name[i];
        if (c == '\0' || c == '\r' || c == '\n' || c == '/') {
            return -1;                            /* hostile / traversal name */
        }
    }

    /* Walk the `;`-separated key=value facts in [0,sep). A stray token with no
     * '=' is tolerated (skipped) — only a missing name is fatal. */
    fstart = 0;
    for (i = 0; i <= sep; i++) {
        if (i == sep || line[i] == ';') {
            size_t tlen = i - fstart;
            size_t e;
            for (e = fstart; e < i; e++) {
                if (line[e] == '=') { break; }
            }
            if (e < i && e > fstart) {
                apply_fact(line + fstart, e - fstart,
                           line + e + 1, i - (e + 1), out);
            }
            (void) tlen;
            fstart = i + 1;
        }
    }
    return 0;
}
