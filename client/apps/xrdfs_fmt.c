/*
 * xrdfs_fmt.c - extracted concern
 * Phase-38 split of xrdfs.c; behavior-identical.
 */
#include "xrdfs_internal.h"

int
endpoint_to_url(const char *ep, xrdc_url *u, xrdc_status *st)
{
    char resolved[XRDC_PATH_MAX];
    xrdc_alias_resolve(ep, resolved, sizeof(resolved));
    return xrdc_endpoint_parse(resolved, u, st);
}


/* Resolve `arg` (absolute or relative to `cwd`) into a clean absolute path in
 * out[outsz], collapsing "." / ".." / duplicate slashes. */
void
build_path(const char *cwd, const char *arg, char *out, size_t outsz)
{
    xrdc_path_resolve(cwd, arg, out, outsz);   /* shared (lib/path.c) */
}


void
flags_to_str(int f, char *out, size_t sz)
{
    int first = 1;
    out[0] = '\0';

#define XRDFS_ADD(bit, name)                                      \
    do {                                                          \
        if (f & (bit)) {                                          \
            if (!first) { strncat(out, "|", sz - strlen(out) - 1); } \
            strncat(out, (name), sz - strlen(out) - 1);           \
            first = 0;                                             \
        }                                                         \
    } while (0)

    XRDFS_ADD(kXR_xset,     "XBitSet");
    XRDFS_ADD(kXR_isDir,    "IsDir");
    XRDFS_ADD(kXR_other,    "Other");
    XRDFS_ADD(kXR_offline,  "Offline");
    XRDFS_ADD(kXR_readable, "IsReadable");
    XRDFS_ADD(kXR_writable, "IsWritable");
    XRDFS_ADD(kXR_poscpend, "POSCPending");
    XRDFS_ADD(kXR_bkpexist, "BackUpExists");
#undef XRDFS_ADD

    if (first) {
        snprintf(out, sz, "none");
    }
}


/* Forward decls for the recursive-walk helpers (defined with the power tools). */

/* command handlers — argv[0] is the command name; argv[1..argc-1] args */

/* Print one labelled "%Y-%m-%d %H:%M:%S" time line in UTC (matching official
 * xrdfs, which formats stat times with gmtime); falls back to the raw epoch. */
void
print_stat_time(const char *label, long epoch)
{
    time_t    t = (time_t) epoch;
    struct tm tmv;
    char      tb[32];

    if (gmtime_r(&t, &tmv) != NULL
        && strftime(tb, sizeof(tb), "%Y-%m-%d %H:%M:%S", &tmv) > 0) {
        printf("%s%s\n", label, tb);
    } else {
        printf("%s%ld\n", label, epoch);
    }
}


/* Print a stat report in the official xrdfs field order. CTime/ATime/Mode/
 * Owner/Group are emitted only when the server supplied them (have_ext). */
void
print_statinfo(const char *path, const xrdc_statinfo *si)
{
    char fbuf[256];

    flags_to_str(si->flags, fbuf, sizeof(fbuf));
    printf("Path:   %s\n", path);
    printf("Id:     %llu\n", (unsigned long long) si->id);
    printf("Size:   %lld\n", (long long) si->size);
    print_stat_time("MTime:  ", si->mtime);
    if (si->have_ext) {
        print_stat_time("CTime:  ", si->ctime);
        print_stat_time("ATime:  ", si->atime);
    }
    printf("Flags:  %d (%s)\n", si->flags, fbuf);
    if (si->have_ext) {
        printf("Mode:   0%03o\n", si->mode & 07777);
        printf("Owner:  %s\n", si->owner);
        printf("Group:  %s\n", si->group);
    }
}


/* parse_chmod_mode — accept the stock xrdfs 9-char symbolic form ("rwxr-xr-x",
 * XrdClFS.cc ConvertMode) AND an octal absolute mode ("755") as a local
 * extension. Returns the permission bits, or -1 on a malformed mode. The stock
 * client takes ONLY the symbolic 9-char form, so users/tools that pass it (and
 * our own conformance suite) must get the right bits — previously strtol(…,8)
 * turned "rwxr-xr-x" into 0, silently setting mode 000. */
int
parse_chmod_mode(const char *s)
{
    size_t n = strlen(s);

    if (n == 9) {
        int i, m = 0, ok = 1;
        for (i = 0; i < 9; i++) {
            char want = "rwx"[i % 3];
            if (s[i] == want) {
                m |= (1 << (8 - i));    /* pos 0 -> 0400 … pos 8 -> 0001 */
            } else if (s[i] != '-') {
                ok = 0;
                break;
            }
        }
        if (ok) {
            return m;
        }
    }

    {
        char *endp = NULL;
        long  v    = strtol(s, &endp, 8);
        if (endp != s && *endp == '\0' && v >= 0) {
            return (int) (v & 07777);
        }
    }
    return -1;
}


/* Pull one "oss.<key>=<u64>" field out of a Qspace reply. Returns the value, or -1
 * if the key is absent. */
int64_t
df_field(const char *reply, const char *key)
{
    const char *p = strstr(reply, key);
    return (p != NULL) ? (int64_t) strtoll(p + strlen(key), NULL, 10) : -1;
}


/* Parse a kXR_Qspace "oss.*" reply into byte counts. Returns 0 if any field was
 * recognized (absent fields stay -1), or -1 for an unrecognized shape. */
int
df_parse_space(const char *reply, int64_t *total, int64_t *avail, int64_t *used,
               int64_t *largest)
{
    *total   = df_field(reply, "oss.space=");
    *avail   = df_field(reply, "oss.free=");
    *used    = df_field(reply, "oss.used=");
    *largest = df_field(reply, "oss.maxf=");
    return (*total < 0 && *avail < 0 && *used < 0 && *largest < 0) ? -1 : 0;
}


/* Two-octal-digit reader for touch_parse_time. Caller guarantees p[0..1] are digits. */
int
two_digits(const char *p)
{
    return (p[0] - '0') * 10 + (p[1] - '0');
}


/* Parse a POSIX touch -t stamp: [[CC]YY]MMDDhhmm[.ss] (local time) into *out
 * (tv_nsec = 0). Returns 0 / -1 on a malformed stamp. */
int
touch_parse_time(const char *s, struct timespec *out)
{
    char        d[16];
    size_t      dn = 0, i;
    int         sec = 0, year, mon, day, hour, min;
    const char *dot = strchr(s, '.');
    const char *p;
    struct tm   tmv;
    time_t      now = time(NULL), t;

    for (i = 0; s[i] != '\0' && s[i] != '.'; i++) {
        if (!isdigit((unsigned char) s[i]) || dn >= sizeof(d) - 1) { return -1; }
        d[dn++] = s[i];
    }
    d[dn] = '\0';
    if (dot != NULL) {
        if (strlen(dot + 1) != 2 || !isdigit((unsigned char) dot[1])
            || !isdigit((unsigned char) dot[2])) {
            return -1;
        }
        sec = two_digits(dot + 1);
    }
    if (dn != 8 && dn != 10 && dn != 12) { return -1; }

    localtime_r(&now, &tmv);              /* default year from "now" */
    year = tmv.tm_year + 1900;
    p = d;
    if (dn == 12) {                       /* CCYYMMDDhhmm */
        year = two_digits(p) * 100 + two_digits(p + 2);
        p += 4;
    } else if (dn == 10) {                /* YYMMDDhhmm (POSIX pivot at 69) */
        int yy = two_digits(p);
        year = (yy >= 69) ? 1900 + yy : 2000 + yy;
        p += 2;
    }
    mon = two_digits(p); day = two_digits(p + 2);
    hour = two_digits(p + 4); min = two_digits(p + 6);

    memset(&tmv, 0, sizeof(tmv));
    tmv.tm_year  = year - 1900;
    tmv.tm_mon   = mon - 1;
    tmv.tm_mday  = day;
    tmv.tm_hour  = hour;
    tmv.tm_min   = min;
    tmv.tm_sec   = sec;
    tmv.tm_isdst = -1;
    t = mktime(&tmv);
    if (t == (time_t) -1) { return -1; }
    out->tv_sec  = t;
    out->tv_nsec = 0;
    return 0;
}


/* dd / upload — windowed, rate-limited block I/O */

/* Parse a byte count with an optional 1024-based K/M/G/T suffix (e.g. "10M",
 * "1.5G", "4096"). Returns the byte count, or -1 on a malformed value. */
int64_t
parse_bytes(const char *s)
{
    return xrdc_parse_bytes(s);   /* shared (lib/units.c) */
}


void
rate_pace(const struct timespec *start, int64_t sent, double rate)
{
    xrdc_rate_pace(start, sent, rate);   /* shared (lib/units.c) */
}


/* Strict non-negative decimal parse: rejects empty, trailing garbage, sign, and
 * overflow. Fills *out and returns 0; on any error returns -1. */
int
parse_u64_strict(const char *s, unsigned long long *out)
{
    char              *end;
    unsigned long long v;
    if (s == NULL || *s == '\0' || *s == '-') {
        return -1;
    }
    errno = 0;
    v = strtoull(s, &end, 10);
    if (errno != 0 || end == s || *end != '\0') {
        return -1;
    }
    *out = v;
    return 0;
}


/* power tools — recursive walk: du / tree / find / ls -R              */


/* "." / ".." dirent test. */
int
is_dot(const char *name)
{
    return name[0] == '.'
        && (name[1] == '\0' || (name[1] == '.' && name[2] == '\0'));
}


/* Render a byte count: raw decimal, or a human 1.2K/3.4M/… when human != 0. */
void
fmt_size(int64_t n, char *out, size_t sz, int human)
{
    xrdc_fmt_size(n, out, sz, human);   /* shared (lib/units.c) */
}


/* Join dir + name into out (path separator aware). Returns 0, or -1 if too long. */
int
join_path(const char *dir, const char *name, char *out, size_t sz)
{
    size_t dl = strlen(dir);
    const char *sep = (dl > 0 && dir[dl - 1] == '/') ? "" : "/";
    return ((size_t) snprintf(out, sz, "%s%s%s", dir, sep, name) >= sz) ? -1 : 0;
}
