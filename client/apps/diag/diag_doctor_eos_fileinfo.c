/*
 * diag_doctor_eos_fileinfo.c — unprivileged EOS FST discovery via `fileinfo`.
 *
 * EOS gates the farm-enumeration commands (`fs ls`, `node ls`) behind an admin
 * role: an identity the MGM maps to `nobody` gets NotAuthorized on /proc/admin/.
 * But `fileinfo` is a *user*-plane command, and on any readable file it prints
 * the FSTs holding that file's replicas. So when doctor_eos_map's admin `fs ls`
 * is gated, we fall back here: walk a bounded sample of files under the target
 * root, read each one's `fileinfo` replica table, and union the FSTs they name.
 *
 * Coverage is partial by construction — only FSTs that happen to hold a sampled
 * file surface — so callers label these nodes "via fileinfo replica sampling",
 * never as a complete inventory. The MGM answers `fileinfo` with a human table
 * (it ignores the `-m` monitoring flag on the /proc route), so doctor_eos_parse_
 * fileinfo tokenises that table; every parser here is pure over a caller buffer
 * and unit-tested off recorded eospublic output. Only the walk touches the wire.
 */
#include "diag_internal.h"

#include "brix_ops.h"

/* Bounds on the sampling walk — keep the wire traffic modest and predictable. */
#define EOS_WALK_DIRS   24   /* max directory listings                        */
#define EOS_WALK_FILES  16   /* max fileinfo probes                           */
#define EOS_WALK_FSTS   32   /* stop once this many distinct FSTs are found   */
#define EOS_WALK_STACK  48   /* pending-directory stack depth                 */

/* ---- pure helpers ------------------------------------------------------- */

/* Extract the path component of an endpoint URL into `out` (absolute, leading
 * single slash; any opaque `?...` and duplicate leading slashes dropped). The
 * XRootD `root://host//eos` double slash and the plain `root://host/eos` both
 * yield "/eos". "/" when the URL carries no path. Returns 0 always (out filled). */
int
doctor_eos_url_path(const char *url, char *out, size_t osz)
{
    const char *p, *q;
    size_t      j = 0;

    if (out == NULL || osz == 0) { return -1; }
    out[0] = '\0';
    if (url == NULL) { return 0; }

    p = strstr(url, "://");
    p = (p != NULL) ? p + 3 : url;          /* past the scheme, at the authority */
    q = strchr(p, '/');                     /* first slash ends the authority    */
    if (q == NULL) { snprintf(out, osz, "/"); return 0; }

    while (*q == '/') { q++; }              /* collapse the // (or /) separator  */
    out[j++] = '/';
    for (; *q != '\0' && *q != '?' && j < osz - 1; q++) {
        out[j++] = *q;
    }
    /* trim a trailing slash (but never the root "/") */
    while (j > 1 && out[j - 1] == '/') { j--; }
    out[j] = '\0';
    return 0;
}

/* Copy `src` into `dst` (max dsz-1) dropping ANSI CSI escape sequences
 * (ESC '[' ... final-byte in 0x40..0x7e) — the EOS table colours the `active`
 * column, and a stripped copy tokenises cleanly. NUL-terminates `dst`. */
static void
eos_strip_ansi(const char *src, char *dst, size_t dsz)
{
    size_t j = 0;

    while (*src != '\0' && j < dsz - 1) {
        if (src[0] == 0x1b && src[1] == '[') {
            src += 2;
            while (*src != '\0' && (*src < 0x40 || *src > 0x7e)) { src++; }
            if (*src != '\0') { src++; }     /* consume the final byte */
            continue;
        }
        dst[j++] = *src++;
    }
    dst[j] = '\0';
}

/* 1 iff `s` is non-empty and every byte is an ASCII digit. */
static int
eos_all_digits(const char *s)
{
    if (s == NULL || *s == '\0') { return 0; }
    for (; *s != '\0'; s++) {
        if (*s < '0' || *s > '9') { return 0; }
    }
    return 1;
}

/* 1 iff `s` contains at least one ASCII letter (a host column, not a number). */
static int
eos_has_alpha(const char *s)
{
    for (; s != NULL && *s != '\0'; s++) {
        if ((*s >= 'a' && *s <= 'z') || (*s >= 'A' && *s <= 'Z')) { return 1; }
    }
    return 0;
}

/* Split `rec` (mutated in place, NUL-terminating each token) on runs of spaces
 * and tabs, recording up to `max` token start pointers into `tok`. Returns the
 * token count. */
static int
eos_tokenise(char *rec, char **tok, int max)
{
    int n = 0;

    while (*rec != '\0' && n < max) {
        while (*rec == ' ' || *rec == '\t') { rec++; }
        if (*rec == '\0') { break; }
        tok[n++] = rec;
        while (*rec != '\0' && *rec != ' ' && *rec != '\t') { rec++; }
        if (*rec != '\0') { *rec++ = '\0'; }
    }
    return n;
}

/* Copy the next '\n'-delimited line of [s,s+len) starting at *i into `out`,
 * advancing *i past the newline. Returns 1 if a line was read, 0 at end. */
static int
eos_next_line(const char *s, int len, int *i, char *out, size_t osz)
{
    int j = 0;

    if (*i >= len) { return 0; }
    while (*i < len && s[*i] != '\n') {
        if (j < (int) osz - 1) { out[j++] = s[*i]; }
        (*i)++;
    }
    out[j] = '\0';
    if (*i < len) { (*i)++; }               /* consume the newline */
    return 1;
}

/* 1 iff the tokenised line is an `fs-id host ...` replica row: at least through
 * the `active` column, first two tokens all-digits, host token alphabetic —
 * which rejects the box-drawing header/rule lines and the trailing summary. */
static int
eos_is_replica_row(char *const *tok, int nt)
{
    return nt >= 9 && eos_all_digits(tok[0]) && eos_all_digits(tok[1])
           && eos_has_alpha(tok[2]);
}

/* Fill one replica record from a validated token row (geotag = tok[9], optional).
 * Precision `%.*s` copies keep the FORTIFY truncation analyzer quiet on the
 * pointer-typed tokens. */
static void
eos_fill_rep(char *const *tok, int nt, doctor_eos_rep *r)
{
    char *colon;

    memset(r, 0, sizeof(*r));
    snprintf(r->host, sizeof(r->host), "%.*s", (int) sizeof(r->host) - 1, tok[2]);
    colon = strrchr(r->host, ':');
    if (colon != NULL) { *colon = '\0'; r->port = atoi(colon + 1); }
    if (r->port == 0) { r->port = 1095; }   /* fileinfo omits the port */
    snprintf(r->cfgstatus, sizeof(r->cfgstatus), "%.*s",
             (int) sizeof(r->cfgstatus) - 1, tok[6]);
    r->booted = (strcmp(tok[5], "booted") == 0);
    r->active = (strcmp(tok[8], "online") == 0);
    if (nt >= 10) {
        snprintf(r->geotag, sizeof(r->geotag), "%.*s",
                 (int) sizeof(r->geotag) - 1, tok[9]);
    }
}

/* Parse an EOS `fileinfo` reply's stdout span, extracting one replica record per
 * table row into out[0..cap). Pure: no allocation, no wire. Returns the row
 * count written. */
int
doctor_eos_parse_fileinfo(const char *sout, int len, doctor_eos_rep *out, int cap)
{
    int  i = 0, k = 0, nt;
    char raw[1024], rec[1024];
    char *tok[16];

    if (sout == NULL || out == NULL) { return 0; }

    while (k < cap && eos_next_line(sout, len, &i, raw, sizeof(raw))) {
        eos_strip_ansi(raw, rec, sizeof(rec));
        nt = eos_tokenise(rec, tok, 16);
        if (!eos_is_replica_row(tok, nt)) { continue; }
        eos_fill_rep(tok, nt, &out[k++]);
    }
    return k;
}

/* ---- wire: sample + walk ------------------------------------------------- */

/* 1 iff `host` is already present as an FST endpoint in arr[start..n). */
static int
eos_fst_present(const doctor_ep *arr, int start, int n, const char *host)
{
    int i;

    for (i = start; i < n; i++) {
        if (arr[i].eos.kind == DOC_EOS_FST
            && strcmp(arr[i].host, host) == 0) {
            return 1;
        }
    }
    return 0;
}

/* Materialise one discovered replica FST as a doctor_ep at arr[*n], mirroring the
 * `fs ls` path's field mapping (CMS-plane data-server typing, rw/ro from config-
 * status) but tagged `sampled`. fileinfo carries no filesystem capacity, so the
 * cfg space fields stay unset (the "NN% free" line is simply omitted). */
static void
eos_add_fst(doctor_ep *e, const doctor_eos_rep *r)
{
    memset(e, 0, sizeof(*e));
    e->proto = DXP_ROOT;
    e->port = r->port;
    snprintf(e->host, sizeof(e->host), "%.*s", (int) sizeof(e->host) - 1,
             r->host);

    e->eos.kind = DOC_EOS_FST;
    e->eos.sampled = 1;
    snprintf(e->eos.geotag, sizeof(e->eos.geotag), "%.*s",
             (int) sizeof(e->eos.geotag) - 1, r->geotag);
    snprintf(e->eos.cfgstatus, sizeof(e->eos.cfgstatus), "%.*s",
             (int) sizeof(e->eos.cfgstatus) - 1, r->cfgstatus);
    e->eos.booted = r->booted;
    e->eos.active = r->active;

    e->cms.reported = 1;
    e->cms.role = DOC_CMS_SERVER;
    e->cms.write = (strstr(r->cfgstatus, "rw") != NULL);
}

/* Read one file's `fileinfo` replica table and append the FSTs it names that we
 * have not already recorded into arr[*n..cap). Returns the count newly added. */
static int
eos_sample_file(brix_conn *c, const char *path, doctor_ep *arr, int cap,
                int start, int *n, brix_status *st)
{
    char           opaque[XRDC_PATH_MAX + 32];
    char          *body = NULL;
    const char    *sout;
    int            slen, nrep, i, added = 0;
    doctor_eos_rep reps[16];

    snprintf(opaque, sizeof(opaque), "mgm.cmd=fileinfo&mgm.path=%s", path);
    if (doctor_eos_proc(c, "/proc/user/", opaque, &body, st) != 0) { return 0; }
    if (doctor_eos_stdout(body, &sout, &slen) != 0) { free(body); return 0; }

    nrep = doctor_eos_parse_fileinfo(sout, slen, reps,
                                     (int) (sizeof(reps) / sizeof(reps[0])));
    for (i = 0; i < nrep && *n < cap; i++) {
        if (eos_fst_present(arr, start, *n, reps[i].host)) { continue; }
        eos_add_fst(&arr[*n], &reps[i]);
        (*n)++;
        added++;
    }
    free(body);
    return added;
}

/* Build "<dir>/<name>" into `full` (length-checked with memcpy, so a path too
 * long to hold is skipped rather than silently truncated into a bogus one) and
 * reject the "."/".." / empty entries. Returns 0 on success, -1 to skip. */
static int
eos_child_path(const char *dir, int dl, const char *name, char *full, size_t fsz)
{
    size_t nl, base;

    if (name[0] == '\0' || strcmp(name, ".") == 0 || strcmp(name, "..") == 0) {
        return -1;
    }
    nl = strlen(name);
    base = (dl > 0 && dir[dl - 1] == '/') ? (size_t) dl : (size_t) dl + 1;
    if (base + nl + 1 > fsz) { return -1; }
    memcpy(full, dir, (size_t) dl);
    if (base != (size_t) dl) { full[dl] = '/'; }
    memcpy(full + base, name, nl + 1);
    return 0;
}

/* Descend the caller-scoped walk state through one listed directory: push each
 * child directory (bounded by the stack) and sample each child file (bounded by
 * *files), unioning FSTs into arr. Stops early at the FST budget or cap. */
static void
eos_walk_dir(brix_conn *c, const char *dir, brix_dirent *ents, size_t ne,
             char (*stack)[XRDC_PATH_MAX], int *sp, doctor_ep *arr, int cap,
             int start, int *n, int *files, brix_status *st)
{
    int    dl = (int) strlen(dir);
    size_t i;

    for (i = 0; i < ne && *n < cap; i++) {
        char full[XRDC_PATH_MAX];
        int  isdir = ents[i].have_stat && (ents[i].st.flags & kXR_isDir);

        if (eos_child_path(dir, dl, ents[i].name, full, sizeof(full)) != 0) {
            continue;
        }
        if (isdir) {
            if (*sp < EOS_WALK_STACK) {
                snprintf(stack[(*sp)++], XRDC_PATH_MAX, "%.*s",
                         XRDC_PATH_MAX - 1, full);
            }
        } else if (*files < EOS_WALK_FILES) {
            eos_sample_file(c, full, arr, cap, start, n, st);
            (*files)++;
        }
        if ((*n - start) >= EOS_WALK_FSTS) { break; }
    }
}

/* Bounded DFS from `root`: list directories, sample files, union the FSTs their
 * replica tables name into arr[start..cap). Stops at the file/dir/FST budgets.
 * Returns the number of distinct FSTs appended (*n advanced by the same count). */
int
doctor_eos_discover_fileinfo(brix_conn *c, const char *root, doctor_ep *arr,
                             int cap, int start, int *n, brix_status *st)
{
    char (*stack)[XRDC_PATH_MAX];
    int   sp = 0, files = 0, dirs = 0, before;

    if (arr == NULL || n == NULL) { return 0; }
    before = *n;
    stack = malloc(sizeof(*stack) * EOS_WALK_STACK);
    if (stack == NULL) { return 0; }

    if (root == NULL || root[0] == '\0') { root = "/"; }
    snprintf(stack[sp++], XRDC_PATH_MAX, "%.*s", XRDC_PATH_MAX - 1, root);

    while (sp > 0 && files < EOS_WALK_FILES && dirs < EOS_WALK_DIRS
           && (*n - start) < EOS_WALK_FSTS && *n < cap) {
        char         dir[XRDC_PATH_MAX];
        brix_dirent *ents = NULL;
        size_t       ne = 0;

        snprintf(dir, sizeof(dir), "%.*s", XRDC_PATH_MAX - 1, stack[--sp]);
        brix_status_clear(st);
        if (brix_dirlist(c, dir, 1, &ents, &ne, st) != 0) { continue; }
        dirs++;
        eos_walk_dir(c, dir, ents, ne, stack, &sp, arr, cap, start, n, &files,
                     st);
        free(ents);
    }
    free(stack);
    return *n - before;
}
