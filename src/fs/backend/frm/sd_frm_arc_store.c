/*
 * sd_frm_arc_store.c — dataset archiver: sidecar index, seal, extract
 * (phase-115 W3.1; the vtable lives in sd_frm_arc.c)
 *
 * WHAT: the three I/O jobs behind the archiver adapter — the per-dataset index
 *       sidecar (`<base>/.arcidx<dataset>.idx`, one "name\tsize\toffset\tcrc"
 *       line per member), sealing a completed dataset into ONE store-only ZIP
 *       under the online buffer and migrating it, and extracting one member
 *       out of a recalled archive into the online buffer.
 *
 * WHY:  raw storage syscalls belong under src/fs/backend/ (invariant 12); the
 *       vtable file stays declarative and this one owns the filesystem walk,
 *       the tmp+rename publishes and the zip streaming.
 *
 * HOW:  seal = recursive lstat walk of `<online><dataset>` (regular files
 *       only, the marker excluded, symlinks never followed) → sorted names →
 *       frm_zip writer into `<archive>.tmp` → fsync+rename → inner migrate →
 *       sidecar tmp+rename → inner migrate(marker). Extract = brix_zip_index
 *       (unsafe names skipped and counted) → brix_zip_extract into
 *       inner->create_online (CRC verified; a failed copy is purged).
 */

#include "sd_frm_arc_internal.h"

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define ARC_WALK_MAX_DEPTH  64u
#define ARC_LINE_MAX        (BRIX_ZIP_NAME_MAX + 96)

/* ---- sidecar ------------------------------------------------------------- */

/* "name\tsize\toffset\tcrc\n" → entry; 0 ok / -1 malformed. */
static int
arc_parse_line(char *line, brix_zip_entry_t *e)
{
    char               *tab = strchr(line, '\t');
    unsigned long long  size, off;
    unsigned            crc;

    if (tab == NULL || tab == line || (size_t) (tab - line) >= sizeof(e->name)) {
        return -1;
    }
    if (sscanf(tab + 1, "%llu\t%llu\t%x", &size, &off, &crc) != 3) {
        return -1;
    }
    memset(e, 0, sizeof(*e));
    memcpy(e->name, line, (size_t) (tab - line));
    e->size = size;
    e->lfh_off = off;
    e->crc = crc;
    return brix_zip_name_ok(e->name) ? 0 : -1;
}

static FILE *
arc_sidecar_open(const arc_ctx_t *c, const char *ds, time_t *mtime_out)
{
    char        path[PATH_MAX];
    struct stat sb;
    FILE       *fp;

    if (arc_sidecar_path(c, ds, path, sizeof(path)) != 0) {
        errno = ENAMETOOLONG;
        return NULL;
    }
    fp = fopen(path, "re");
    if (fp != NULL && mtime_out != NULL) {
        *mtime_out = (fstat(fileno(fp), &sb) == 0) ? sb.st_mtime : 0;
    }
    return fp;
}

int
arc_sidecar_lookup(const arc_ctx_t *c, const char *ds, const char *member,
    brix_zip_entry_t *e, time_t *sealed_at)
{
    FILE *fp = arc_sidecar_open(c, ds, sealed_at);
    char  line[ARC_LINE_MAX];
    int   found = 0;

    if (fp == NULL) {
        return -1;
    }
    while (!found && fgets(line, sizeof(line), fp) != NULL) {
        brix_zip_entry_t cur;

        line[strcspn(line, "\n")] = '\0';
        if (arc_parse_line(line, &cur) == 0 && strcmp(cur.name, member) == 0) {
            *e = cur;
            found = 1;
        }
    }
    fclose(fp);
    return found;
}

int
arc_sidecar_names(const arc_ctx_t *c, const char *ds,
    int (*cb)(void *ud, const char *name), void *ud)
{
    FILE *fp = arc_sidecar_open(c, ds, NULL);
    char  line[ARC_LINE_MAX];
    int   stop = 0;

    if (fp == NULL) {
        return -1;
    }
    while (!stop && fgets(line, sizeof(line), fp) != NULL) {
        brix_zip_entry_t cur;

        line[strcspn(line, "\n")] = '\0';
        if (arc_parse_line(line, &cur) == 0) {
            stop = cb(ud, cur.name);
        }
    }
    fclose(fp);
    return 0;
}

static int
arc_entry_cmp(const void *a, const void *b)
{
    return strcmp(((const brix_zip_entry_t *) a)->name, ((const brix_zip_entry_t *) b)->name);
}

/* Publish the sidecar (sorted so arc_list's dedupe works): tmp + rename. */
int
arc_sidecar_write(const arc_ctx_t *c, const char *ds, brix_zip_entry_t *ents, unsigned n)
{
    char     path[PATH_MAX], tmp[PATH_MAX];
    FILE    *fp;
    unsigned i;
    int      rc = 0;

    if (arc_sidecar_path(c, ds, path, sizeof(path)) != 0
        || snprintf(tmp, sizeof(tmp), "%s.tmp", path) >= (int) sizeof(tmp))
    {
        errno = ENAMETOOLONG;
        return -1;
    }
    qsort(ents, n, sizeof(*ents), arc_entry_cmp);
    frm_mkparents(tmp);
    fp = fopen(tmp, "we");
    if (fp == NULL) {
        return -1;
    }
    for (i = 0; i < n && rc == 0; i++) {
        if (fprintf(fp, "%s\t%" PRIu64 "\t%" PRIu64 "\t%08x\n", ents[i].name, ents[i].size,
                    ents[i].lfh_off, ents[i].crc) < 0)
        {
            rc = -1;
        }
    }
    if (rc == 0 && (fflush(fp) != 0 || fsync(fileno(fp)) != 0)) {
        rc = -1;
    }
    if (fclose(fp) != 0 || rc != 0 || rename(tmp, path) != 0) {
        (void) unlink(tmp);
        return -1;
    }
    return frm_dirsync_parent(path);
}

/* ---- seal (compose) ------------------------------------------------------ */

typedef struct {
    char   **names;             /* dataset-relative member names */
    unsigned n, cap;
    char     path[PATH_MAX];    /* scratch: the directory being walked */
    size_t   root_len;          /* strlen of the dataset's online dir */
} arc_scan_t;

static int
arc_scan_push(arc_scan_t *s, const char *rel)
{
    char     *copy;
    unsigned  index = s->n;

    if (s->n >= BRIX_ZIP_MAX_ENTRIES - 1) {
        errno = EFBIG;
        return -1;
    }
    if (s->n == s->cap) {
        unsigned  ncap = s->cap ? s->cap * 2 : 64;
        char    **grown = realloc(s->names, ncap * sizeof(*grown));

        if (grown == NULL) {
            return -1;
        }
        s->names = grown;
        s->cap = ncap;
    }
    copy = strdup(rel);
    if (copy == NULL) {
        return -1;
    }
    s->names[index] = copy;
    s->n = index + 1;
    return 0;
}

static int arc_scan_dir(arc_scan_t *s, unsigned depth);

static int
arc_scan_entry(arc_scan_t *s, const struct dirent *de, unsigned depth)
{
    struct stat sb;
    size_t      len = strlen(s->path);
    int         rc = 0;

    if (len >= sizeof(s->path)) {
        errno = ENAMETOOLONG;
        return -1;
    }
    if (snprintf(s->path + len, sizeof(s->path) - len, "/%s", de->d_name)
        >= (int) (sizeof(s->path) - len))
    {
        errno = ENAMETOOLONG;
        return -1;
    }
    if (lstat(s->path, &sb) != 0) {
        rc = -1;
    } else if (S_ISDIR(sb.st_mode)) {
        rc = arc_scan_dir(s, depth + 1);
    } else if (S_ISREG(sb.st_mode)) {
        rc = arc_scan_push(s, s->path + s->root_len + 1);
    }
    s->path[len] = '\0';        /* symlinks and specials are not members */
    return rc;
}

static int
arc_scan_dir(arc_scan_t *s, unsigned depth)
{
    DIR           *d;
    struct dirent *de;
    int            rc = 0;

    if (depth > ARC_WALK_MAX_DEPTH) {
        errno = ELOOP;
        return -1;
    }
    d = opendir(s->path);
    if (d == NULL) {
        return -1;
    }
    while (rc == 0 && (de = readdir(d)) != NULL) {
        if (strcmp(de->d_name, ".") == 0 || strcmp(de->d_name, "..") == 0
            || (depth == 0 && strcmp(de->d_name, BRIX_ARC_MARKER) == 0))
        {
            continue;
        }
        rc = arc_scan_entry(s, de, depth);
    }
    closedir(d);
    return rc;
}

static int
arc_name_cmp(const void *a, const void *b)
{
    return strcmp(*(char *const *) a, *(char *const *) b);
}

static void
arc_scan_free(arc_scan_t *s)
{
    unsigned i;

    for (i = 0; i < s->n; i++) {
        free(s->names[i]);
    }
    free(s->names);
}

/* Stream every scanned member into the writer. */
static int
arc_pack(const arc_scan_t *s, brix_zip_writer_t *w)
{
    char     src[PATH_MAX];
    unsigned i;

    for (i = 0; i < s->n; i++) {
        struct stat sb;
        int         fd, rc;

        if (snprintf(src, sizeof(src), "%.*s/%s", (int) s->root_len, s->path, s->names[i])
            >= (int) sizeof(src))
        {
            errno = ENAMETOOLONG;
            return -1;
        }
        fd = open(src, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
        if (fd < 0 || fstat(fd, &sb) != 0) {
            if (fd >= 0) {
                close(fd);
            }
            return -1;
        }
        rc = brix_zip_writer_add(w, s->names[i], fd, (uint64_t) sb.st_size, NULL);
        close(fd);
        if (rc != 0) {
            return -1;
        }
    }
    return 0;
}

/* Write `<archive>.tmp`, fsync it and rename it into place. Returns the
 * finished writer (entries for the sidecar) or NULL with errno. */
static brix_zip_writer_t *
arc_write_archive(const arc_scan_t *s, const char *archive)
{
    char               tmp[PATH_MAX];
    int                fd, rc;
    brix_zip_writer_t *w;

    if (snprintf(tmp, sizeof(tmp), "%s.tmp", archive) >= (int) sizeof(tmp)) {
        errno = ENAMETOOLONG;
        return NULL;
    }
    fd = open(tmp, O_RDWR | O_CREAT | O_TRUNC | O_CLOEXEC | O_NOFOLLOW, 0644);
    if (fd < 0) {
        return NULL;
    }
    w = brix_zip_writer_open(fd);
    rc = (w != NULL) ? arc_pack(s, w) : -1;
    rc = (rc == 0) ? brix_zip_writer_finish(w) : rc;
    rc = (rc == 0 && fsync(fd) != 0) ? -1 : rc;
    close(fd);
    if (rc != 0 || rename(tmp, archive) != 0) {
        int e = errno;

        (void) unlink(tmp);
        brix_zip_writer_close(w);
        errno = e;
        return NULL;
    }
    return w;
}

/* Sidecar entries from the writer (copied, since the writer owns its array). */
static brix_zip_entry_t *
arc_writer_entries(const brix_zip_writer_t *w, unsigned *n_out)
{
    unsigned          n = brix_zip_writer_count(w), i;
    brix_zip_entry_t *ents = calloc(n ? n : 1, sizeof(*ents));

    if (ents == NULL) {
        return NULL;
    }
    for (i = 0; i < n; i++) {
        ents[i] = *brix_zip_writer_entry(w, i);
    }
    *n_out = n;
    return ents;
}

static int
arc_publish(arc_ctx_t *c, const arc_key_t *k, const char *akey, const char *archive,
    brix_zip_writer_t *w)
{
    unsigned          n = 0;
    uint64_t          bytes = 0, i;
    brix_zip_entry_t *ents;

    if (c->inner->migrate(c->ictx, akey) != 0) {
        int e = errno;

        (void) unlink(archive);
        ARC_LOG(c, NGX_LOG_ERR, e, "brix: tape archive \"%s\": migrate failed; dataset left unsealed", k->ds);
        errno = e ? e : EIO;
        return -1;
    }
    ents = arc_writer_entries(w, &n);
    if (ents == NULL || arc_sidecar_write(c, k->ds, ents, n) != 0) {
        int e = errno;

        free(ents);
        ARC_LOG(c, NGX_LOG_ERR, e, "brix: tape archive \"%s\": index sidecar write failed", k->ds);
        errno = e ? e : EIO;
        return -1;
    }
    for (i = 0; i < n; i++) {
        bytes += ents[i].size;
    }
    free(ents);
    if (c->inner->migrate(c->ictx, k->key) != 0) {
        ARC_LOG(c, NGX_LOG_WARN, errno, "brix: tape archive \"%s\": sealed, but the completion "
                "marker did not migrate", k->ds);
        return -1;
    }
    ARC_LOG(c, NGX_LOG_NOTICE, 0, "brix: tape archive \"%s\": sealed %ud member(s), %uL bytes "
            "into \"%s\"", k->ds, n, bytes, akey);
    return 0;
}

int
arc_compose(arc_ctx_t *c, const arc_key_t *k)
{
    arc_scan_t         s;
    char               akey[PATH_MAX], archive[PATH_MAX];
    brix_zip_writer_t *w;
    int                rc;

    if (arc_sealed(c, k->ds)) {
        errno = EEXIST;
        return -1;
    }
    memset(&s, 0, sizeof(s));
    if (arc_archive_key(k, akey, sizeof(akey)) != 0
        || frm_online_path(c->base, akey, archive, sizeof(archive)) != 0
        || frm_online_path(c->base, k->ds, s.path, sizeof(s.path)) != 0)
    {
        errno = ENAMETOOLONG;
        return -1;
    }
    s.root_len = strlen(s.path);
    if (arc_scan_dir(&s, 0) != 0) {
        int e = errno;

        arc_scan_free(&s);
        ARC_LOG(c, NGX_LOG_ERR, e, "brix: tape archive \"%s\": member walk failed", k->ds);
        errno = e;
        return -1;
    }
    qsort(s.names, s.n, sizeof(*s.names), arc_name_cmp);
    w = arc_write_archive(&s, archive);
    arc_scan_free(&s);
    if (w == NULL) {
        ARC_LOG(c, NGX_LOG_ERR, errno, "brix: tape archive \"%s\": writing \"%s\" failed", k->ds, archive);
        return -1;
    }
    rc = arc_publish(c, k, akey, archive, w);
    brix_zip_writer_close(w);
    return rc;
}

/* ---- extract ------------------------------------------------------------- */

typedef struct {
    const char       *want;
    brix_zip_entry_t  e;
    int               found;
    int               rebuild;      /* no sidecar: collect every entry */
    brix_zip_entry_t *all;
    unsigned          n, cap;
} arc_find_t;

static int
arc_find_cb(void *ud, const brix_zip_entry_t *e)
{
    arc_find_t *f = ud;

    if (!f->found && strcmp(e->name, f->want) == 0) {
        f->e = *e;
        f->found = 1;
    }
    if (!f->rebuild) {
        return f->found;                /* stop as soon as the member is known */
    }
    if (f->n == f->cap) {
        unsigned          ncap = f->cap ? f->cap * 2 : 64;
        brix_zip_entry_t *grown = realloc(f->all, ncap * sizeof(*grown));

        if (grown == NULL) {
            f->rebuild = 0;             /* keep serving; just do not rebuild */
            return f->found;
        }
        f->all = grown;
        f->cap = ncap;
    }
    f->all[f->n++] = *e;
    return 0;
}

static int
arc_copy_member(arc_ctx_t *c, const arc_key_t *k, int afd, const brix_zip_entry_t *e)
{
    int dst = c->inner->create_online(c->ictx, k->key, 0644);
    int rc;

    if (dst < 0) {
        return -1;
    }
    rc = brix_zip_extract(afd, e, dst);
    if (close(dst) != 0) {
        rc = -1;
    }
    if (rc != 0) {
        int err = errno;

        (void) c->inner->purge(c->ictx, k->key);
        ARC_LOG(c, NGX_LOG_ERR, err, "brix: tape archive \"%s\": extracting member \"%s\" failed",
                k->ds, k->member);
        errno = err ? err : EIO;
    }
    return rc;
}

int
arc_extract(arc_ctx_t *c, const arc_key_t *k)
{
    char       akey[PATH_MAX], archive[PATH_MAX];
    arc_find_t f;
    unsigned   skipped = 0;
    int        afd, rc;

    if (arc_archive_key(k, akey, sizeof(akey)) != 0
        || frm_online_path(c->base, akey, archive, sizeof(archive)) != 0)
    {
        errno = ENAMETOOLONG;
        return -1;
    }
    afd = open(archive, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (afd < 0) {
        /* The inner adapter said the archive is online, yet its buffer copy is
         * not openable: name it — a silent -1 surfaces as a bare "recall failed". */
        ARC_LOG(c, NGX_LOG_ERR, errno, "brix: tape archive \"%s\": online copy unreadable", k->ds);
        return -1;
    }
    memset(&f, 0, sizeof(f));
    f.want = k->member;
    f.rebuild = !arc_sealed(c, k->ds);
    rc = brix_zip_index(afd, arc_find_cb, &f, &skipped);
    if (rc != 0) {
        ARC_LOG(c, NGX_LOG_ERR, errno, "brix: tape archive \"%s\": not a readable zip container", k->ds);
    }
    if (skipped != 0) {
        ARC_LOG(c, NGX_LOG_WARN, 0, "brix: tape archive \"%s\": skipped %ud unsafe member name(s)",
                k->ds, skipped);
    }
    if (rc == 0 && f.rebuild && f.n > 0 && arc_sidecar_write(c, k->ds, f.all, f.n) != 0) {
        ARC_LOG(c, NGX_LOG_WARN, errno, "brix: tape archive \"%s\": index sidecar rebuild failed", k->ds);
    }
    free(f.all);
    if (rc == 0 && !f.found) {
        errno = ENOENT;
        rc = -1;
    }
    if (rc == 0) {
        rc = arc_copy_member(c, k, afd, &f.e);
    }
    close(afd);
    return rc;
}

/* Durable-publish barrier.  A dataset key has no tape-side entry under its own
 * name: a MEMBER's migrate is deferred to the seal and the MARKER composes the
 * archive object — so the inner barrier, which fsyncs the key's TAPE parent as
 * well as its online parent, answered ENOENT for every member and failed the
 * commit that had just succeeded (phase-115 W3.1).  Lives here, not in sd_frm_arc.c, for the
 * 600-line cap.  Flush what exists: the
 * online-buffer entry for a member; the archive object's entries for a marker. */
int
arc_sync_publish(void *mss, const char *key)
{
    arc_ctx_t *c = mss;
    arc_key_t  k;
    char       path[PATH_MAX];

    if (c->inner->sync_publish == NULL) {
        return 0;
    }
    switch (arc_classify(c, key, &k)) {
    case ARC_KEY_MEMBER:
        if (frm_online_path(c->base, key, path, sizeof(path)) != 0) {
            errno = ENAMETOOLONG;
            return -1;
        }
        return frm_dirsync_parent(path);
    case ARC_KEY_MARKER:
        if (arc_archive_key(&k, path, sizeof(path)) != 0) {
            errno = ENAMETOOLONG;
            return -1;
        }
        return c->inner->sync_publish(c->ictx, path);
    default:
        return c->inner->sync_publish(c->ictx, key);
    }
}
