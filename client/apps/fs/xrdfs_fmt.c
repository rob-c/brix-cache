/*
 * xrdfs_fmt.c - extracted concern
 * Phase-38 split of xrdfs.c; behavior-identical.
 */
#include "xrdfs_internal.h"

int
endpoint_to_url(const char *ep, brix_url *u, brix_status *st)
{
    char resolved[XRDC_PATH_MAX];
    brix_alias_resolve(ep, resolved, sizeof(resolved));
    return brix_endpoint_parse(resolved, u, st);
}


/* Resolve `arg` (absolute or relative to `cwd`) into a clean absolute path in
 * out[outsz], collapsing "." / ".." / duplicate slashes. */
void
build_path(const char *cwd, const char *arg, char *out, size_t outsz)
{
    brix_path_resolve(cwd, arg, out, outsz);   /* shared (lib/path.c) */
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
print_statinfo(const char *path, const brix_statinfo *si)
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


/* WHAT: emit one stat result as a single-line JSON object for xrdfs stat -j.
 * WHY:  separates JSON formatting from command logic; JSON path is cleanly
 *       isolated so any change to the wire fields is confined here.
 * HOW:  jsonout helpers handle all string escaping so hostile path components
 *       (quotes, control bytes) cannot produce malformed JSON.  Extended fields
 *       (mode/owner/group) are guarded by have_ext to match the human output. */
void
json_statinfo(const char *path, const brix_statinfo *si)
{
    fputc('{', stdout);
    brix_json_kv_str(stdout, "path",   path,                           1);
    brix_json_kv_ll(stdout,  "size",   (long long) si->size,           1);
    brix_json_kv_ll(stdout,  "mtime",  (long long) si->mtime,          1);
    brix_json_kv_ll(stdout,  "flags",  (long long) si->flags,          1);
    brix_json_kv_bool(stdout, "is_dir", (si->flags & kXR_isDir) != 0,
                      si->have_ext);
    if (si->have_ext) {
        /* mode as a leading-zero octal string ("0755") rather than a decimal
         * integer: octal is the conventional POSIX representation and avoids
         * ambiguity (493 vs "0755").  Consumers compare strings, not integers. */
        char modebuf[8];
        snprintf(modebuf, sizeof(modebuf), "0%03o", si->mode & 07777);
        brix_json_kv_str(stdout, "mode",  modebuf,                       1);
        brix_json_kv_str(stdout, "owner", si->owner,                     1);
        brix_json_kv_str(stdout, "group", si->group,                     0);
    }
    fputs("}\n", stdout);
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


/* ---- Collect the leading digit run of a touch -t stamp ----
 *
 * WHAT: Copy the run of decimal digits at the head of `s` (everything up to a
 *       '.' or end-of-string) into `d`, NUL-terminating it and returning the
 *       count via *dn_out. Returns 0 on success, or -1 if a non-digit appears
 *       before the '.' or the run would overflow `d`.
 *
 * WHY:  The date/time digits of a POSIX touch stamp must be isolated (and
 *       length-validated) before they can be sliced into year/month/day fields;
 *       pulling the scan into its own helper keeps touch_parse_time flat.
 *
 * HOW:  1. Walk `s` until '\0' or '.'.
 *       2. Reject any byte that is not a digit, or that would fill `d` past its
 *          NUL slot (dcap - 1).
 *       3. Append each accepted digit; NUL-terminate and publish the count. */
static int
touch_collect_digits(const char *s, char *d, size_t dcap, size_t *dn_out)
{
    size_t dn = 0, i;

    for (i = 0; s[i] != '\0' && s[i] != '.'; i++) {
        if (!isdigit((unsigned char) s[i]) || dn >= dcap - 1) { return -1; }
        d[dn++] = s[i];
    }
    d[dn] = '\0';
    *dn_out = dn;
    return 0;
}


/* ---- Parse the optional ".ss" seconds field of a touch -t stamp ----
 *
 * WHAT: If `dot` is non-NULL it points at the '.' introducing the two-digit
 *       seconds field; validate it is exactly two digits and store the value in
 *       *sec_out. Returns 0 on success (leaving *sec_out untouched when `dot` is
 *       NULL), or -1 on a malformed seconds field.
 *
 * WHY:  The ".ss" suffix is optional and independently validated; isolating it
 *       keeps the seconds rule (exactly two digits) in one place.
 *
 * HOW:  1. With no '.', succeed without changing *sec_out.
 *       2. Otherwise require strlen(dot+1) == 2 and both chars digits.
 *       3. Decode the two digits into *sec_out. */
static int
touch_parse_seconds(const char *dot, int *sec_out)
{
    if (dot == NULL) {
        return 0;
    }
    if (strlen(dot + 1) != 2 || !isdigit((unsigned char) dot[1])
        || !isdigit((unsigned char) dot[2])) {
        return -1;
    }
    *sec_out = two_digits(dot + 1);
    return 0;
}


/* ---- Resolve the year and month cursor from the digit run ----
 *
 * WHAT: Given the digit run `d` of length `dn` (already validated as 8, 10, or
 *       12) and the current time `now`, return the effective year and advance
 *       *p_out to the first month digit.
 *
 * WHY:  The year is either explicit (CCYY / YY with the POSIX 69 pivot) or
 *       defaulted from "now"; folding this branch into a helper keeps the caller
 *       a straight-line sequence of field extractions.
 *
 * HOW:  1. Default the year from localtime_r(now) and point the cursor at d[0].
 *       2. dn==12: take CCYY, advance the cursor 4 digits.
 *       3. dn==10: take YY, pivot <69 -> 2000s else 1900s, advance 2 digits.
 *       4. dn==8: keep the defaulted year and cursor at d[0]. */
static int
touch_resolve_year(size_t dn, const char *d, time_t now, const char **p_out)
{
    struct tm   tmv;
    const char *p = d;
    int         year;

    localtime_r(&now, &tmv);              /* default year from "now" */
    year = tmv.tm_year + 1900;
    if (dn == 12) {                       /* CCYYMMDDhhmm */
        year = two_digits(p) * 100 + two_digits(p + 2);
        p += 4;
    } else if (dn == 10) {                /* YYMMDDhhmm (POSIX pivot at 69) */
        int yy = two_digits(p);
        year = (yy >= 69) ? 1900 + yy : 2000 + yy;
        p += 2;
    }
    *p_out = p;
    return year;
}


/* Parse a POSIX touch -t stamp: [[CC]YY]MMDDhhmm[.ss] (local time) into *out
 * (tv_nsec = 0). Returns 0 / -1 on a malformed stamp. */
int
touch_parse_time(const char *s, struct timespec *out)
{
    char        d[16];
    size_t      dn = 0;
    int         sec = 0, year, mon, day, hour, min;
    const char *dot = strchr(s, '.');
    const char *p;
    struct tm   tmv;
    time_t      now = time(NULL), t;

    if (touch_collect_digits(s, d, sizeof(d), &dn) != 0) { return -1; }
    if (touch_parse_seconds(dot, &sec) != 0) { return -1; }
    if (dn != 8 && dn != 10 && dn != 12) { return -1; }

    year = touch_resolve_year(dn, d, now, &p);
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
    return brix_parse_bytes(s);   /* shared (lib/units.c) */
}


void
rate_pace(const struct timespec *start, int64_t sent, double rate)
{
    brix_rate_pace(start, sent, rate);   /* shared (lib/units.c) */
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
    brix_fmt_size(n, out, sz, human);   /* shared (lib/units.c) */
}


/* Join dir + name into out (path separator aware). Returns 0, or -1 if too long. */
int
join_path(const char *dir, const char *name, char *out, size_t sz)
{
    size_t dl = strlen(dir);
    const char *sep = (dl > 0 && dir[dl - 1] == '/') ? "" : "/";
    return ((size_t) snprintf(out, sz, "%s%s%s", dir, sep, name) >= sz) ? -1 : 0;
}
