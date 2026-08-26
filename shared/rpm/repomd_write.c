/* repomd_write.c — repodata emission for `brixrpm createrepo` (phase-104
 * D12.3).
 *
 * WHAT: implement repomd_write.h — per-package XML fragments byte-identical
 *       to the Appendix-X Python generator, gzip'd checksum-named documents,
 *       repomd.xml renamed last.
 * WHY:  see repomd_write.h.
 * HOW:  a small growable string buffer + two escapers (text: &<> · attr:
 *       double-quoted, &<>" plus newline/tab as character references — the
 *       quoteattr rule) — ~80 lines of XML plumbing instead of a library.
 *       gzip via zlib windowBits 15+16; zlib's default header carries
 *       mtime=0, so output bytes are reproducible run-to-run.
 */
#define _POSIX_C_SOURCE 200809L
#include "rpm/repomd_write.h"

#include "oci/digest.h"

#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>
#include <zlib.h>

#define RM_PATH_MAX 4096

typedef struct {
    char  *p;
    size_t len, cap;
} sbuf_t;

struct brix_repomd_s {
    char     repo_dir[RM_PATH_MAX];
    sbuf_t   pri, fil, oth;
    uint32_t npkgs;
};

static int rm_fail(char *err, size_t errlen, const char *fmt, ...) {
    va_list ap;

    va_start(ap, fmt);
    if (err != NULL && errlen > 0)
        vsnprintf(err, errlen, fmt, ap);
    va_end(ap);
    return -1;
}

static int sb_ensure(sbuf_t *b, size_t more) {
    size_t cap = b->cap;
    char  *np;

    if (b->len + more + 1 <= cap)
        return 0;
    cap = cap > 0 ? cap : 4096;
    while (b->len + more + 1 > cap)
        cap *= 2;
    np = realloc(b->p, cap);
    if (np == NULL)
        return -1;
    b->p   = np;
    b->cap = cap;
    return 0;
}

static int sb_put(sbuf_t *b, const char *fmt, ...) {
    va_list ap;
    int     n;

    va_start(ap, fmt);
    n = vsnprintf(NULL, 0, fmt, ap);
    va_end(ap);
    if (n < 0 || sb_ensure(b, (size_t) n) != 0)
        return -1;
    va_start(ap, fmt);
    vsnprintf(b->p + b->len, (size_t) n + 1, fmt, ap);
    va_end(ap);
    b->len += (size_t) n;
    return 0;
}

/* Text escaper: & < > (the xml.sax.saxutils.escape set). NULL → empty. */
static int sb_text(sbuf_t *b, const char *s) {
    if (s == NULL)
        return 0;
    for (; *s != '\0'; s++) {
        const char *rep = *s == '&' ? "&amp;" : *s == '<' ? "&lt;"
                        : *s == '>' ? "&gt;" : NULL;
        if (rep != NULL ? sb_put(b, "%s", rep) != 0
                        : sb_put(b, "%c", *s) != 0)
            return -1;
    }
    return 0;
}

/* Attribute escaper: always double-quoted; & < > " escaped, control
 * whitespace as character references (the quoteattr rule). Length-bounded
 * so version substrings can be quoted without a copy. */
static int sb_attr_n(sbuf_t *b, const char *s, size_t n) {
    size_t i;

    if (sb_put(b, "\"") != 0)
        return -1;
    for (i = 0; i < n && s[i] != '\0'; i++) {
        char        c = s[i];
        const char *rep = c == '&' ? "&amp;" : c == '<' ? "&lt;"
                        : c == '>' ? "&gt;" : c == '"' ? "&quot;"
                        : c == '\n' ? "&#10;" : c == '\r' ? "&#13;"
                        : c == '\t' ? "&#9;" : NULL;
        if (rep != NULL ? sb_put(b, "%s", rep) != 0
                        : sb_put(b, "%c", c) != 0)
            return -1;
    }
    return sb_put(b, "\"");
}

static int sb_attr(sbuf_t *b, const char *s) {
    return sb_attr_n(b, s != NULL ? s : "", s != NULL ? strlen(s) : 0);
}

/* "LT"/"GT"/"EQ"/"LE"/"GE" from the sense bits (empty when none). */
static const char *sense_str(uint32_t flags, char buf[8]) {
    buf[0] = '\0';
    if (flags & BRIX_RPMSENSE_LT)
        strcat(buf, "LT");
    if (flags & BRIX_RPMSENSE_GT)
        strcat(buf, "GT");
    if (flags & BRIX_RPMSENSE_EQ) {
        if (strcmp(buf, "LT") == 0)
            strcpy(buf, "LE");
        else if (strcmp(buf, "GT") == 0)
            strcpy(buf, "GE");
        else
            strcpy(buf, "EQ");
    }
    return buf;
}

/* ' epoch="E" ver="V"[ rel="R"]' from an "[E:]V[-R]" dependency version. */
static int put_evr(sbuf_t *b, const char *version) {
    const char *colon = strchr(version, ':');
    const char *ver   = colon != NULL ? colon + 1 : version;
    const char *dash  = strrchr(ver, '-');
    size_t      vlen  = dash != NULL ? (size_t) (dash - ver) : strlen(ver);

    if (colon != NULL
            ? sb_put(b, " epoch=\"%.*s\" ver=", (int) (colon - version),
                     version) != 0
            : sb_put(b, " epoch=\"0\" ver=") != 0)
        return -1;
    if (sb_attr_n(b, ver, vlen) != 0)
        return -1;
    if (dash != NULL &&
        (sb_put(b, " rel=") != 0 || sb_attr(b, dash + 1) != 0))
        return -1;
    return 0;
}

/* One <rpm:provides>/<rpm:requires> row set. rpmlib() tracking deps are
 * filtered from requires only (createrepo_c behavior). */
static int put_deps(sbuf_t *b, brix_rpm_pkg_t *p, uint32_t names_tag,
                    uint32_t flags_tag, uint32_t vers_tag, int drop_rpmlib) {
    uint32_t n = brix_rpm_count(p, names_tag);
    uint32_t i;

    for (i = 0; i < n; i++) {
        const char *name = brix_rpm_stra(p, names_tag, i);
        const char *version = brix_rpm_stra(p, vers_tag, i);
        uint32_t    flags = 0;
        char        sense[8];

        if (name == NULL)
            return -1;
        (void) brix_rpm_u32(p, flags_tag, i, &flags);
        if (drop_rpmlib && (flags & BRIX_RPMSENSE_RPMLIB))
            continue;
        if (sb_put(b, "    <rpm:entry name=") != 0 ||
            sb_attr(b, name) != 0)
            return -1;
        sense_str(flags, sense);
        if (sense[0] != '\0' && version != NULL && version[0] != '\0' &&
            (sb_put(b, " flags=\"%s\"", sense) != 0 ||
             put_evr(b, version) != 0))
            return -1;
        if (sb_put(b, "/>\n") != 0)
            return -1;
    }
    return 0;
}

/* createrepo's primary filter: under /etc, containing bin/, or sendmail. */
static int primary_file_visible(const char *path) {
    return strncmp(path, "/etc/", 5) == 0 || strstr(path, "bin/") != NULL ||
           strcmp(path, "/usr/lib/sendmail") == 0;
}

static uint32_t pkg_epoch(brix_rpm_pkg_t *p) {
    uint32_t e = 0;

    (void) brix_rpm_u32(p, BRIX_RPMTAG_EPOCH, 0, &e);
    return e;
}

/* <package pkgid=… name=… arch=…> + <version…/> (filelists/other head). */
#include "repomd_render.c"

int brix_repomd_render(brix_rpm_pkg_t *p, const char *href, int64_t mtime,
                       char **primary, char **filelists, char **other,
                       uint32_t *skipped, char *err, size_t errlen) {
    sbuf_t pri = {0}, fil = {0}, oth = {0};

    if (render_primary(&pri, p, href, mtime, skipped) != 0 ||
        render_filelists(&fil, p) != 0 || render_other(&oth, p) != 0) {
        free(pri.p);
        free(fil.p);
        free(oth.p);
        return rm_fail(err, errlen, "fragment render failed for %s "
                       "(malformed file list or out of memory)", href);
    }
    *primary   = pri.p;
    *filelists = fil.p;
    *other     = oth.p;
    return 0;
}

brix_repomd_t *brix_repomd_begin(const char *repo_dir, char *err,
                                 size_t errlen) {
    brix_repomd_t *w = calloc(1, sizeof(*w));

    if (w == NULL) {
        rm_fail(err, errlen, "out of memory");
        return NULL;
    }
    if (snprintf(w->repo_dir, sizeof(w->repo_dir), "%s", repo_dir) >=
        (int) sizeof(w->repo_dir)) {
        rm_fail(err, errlen, "repo dir path too long");
        free(w);
        return NULL;
    }
    return w;
}

int brix_repomd_add_fragments(brix_repomd_t *w, const char *primary,
                              const char *filelists, const char *other,
                              char *err, size_t errlen) {
    if (sb_put(&w->pri, "%s", primary) != 0 ||
        sb_put(&w->fil, "%s", filelists) != 0 ||
        sb_put(&w->oth, "%s", other) != 0)
        return rm_fail(err, errlen, "out of memory");
    w->npkgs++;
    return 0;
}

int brix_repomd_add(brix_repomd_t *w, brix_rpm_pkg_t *p, const char *href,
                    int64_t mtime, uint32_t *skipped, char *err,
                    size_t errlen) {
    char *pri, *fil, *oth;
    int   rc;

    if (brix_repomd_render(p, href, mtime, &pri, &fil, &oth, skipped, err,
                           errlen) != 0)
        return -1;
    rc = brix_repomd_add_fragments(w, pri, fil, oth, err, errlen);
    free(pri);
    free(fil);
    free(oth);
    return rc;
}

/* Whole-buffer gzip (windowBits 15+16, level 9). Malloc'd out. */
static int gz_buf(const void *raw, size_t rawlen, unsigned char **out,
                  size_t *outlen) {
    z_stream zs;
    uLong    bound;

    memset(&zs, 0, sizeof(zs));
    if (deflateInit2(&zs, 9, Z_DEFLATED, 15 + 16, 8,
                     Z_DEFAULT_STRATEGY) != Z_OK)
        return -1;
    bound = deflateBound(&zs, (uLong) rawlen) + 32;
    *out = malloc(bound);
    if (*out == NULL) {
        deflateEnd(&zs);
        return -1;
    }
    zs.next_in   = (Bytef *) (uintptr_t) raw;
    zs.avail_in  = (uInt) rawlen;
    zs.next_out  = *out;
    zs.avail_out = (uInt) bound;
    if (deflate(&zs, Z_FINISH) != Z_STREAM_END) {
        deflateEnd(&zs);
        free(*out);
        *out = NULL;
        return -1;
    }
    *outlen = zs.total_out;
    deflateEnd(&zs);
    return 0;
}

/* Stage <dir>/.<name>.tmp, fsync, rename to <dir>/<name>. */
static int write_staged(const char *dir, const char *name, const void *data,
                        size_t len, char *err, size_t errlen) {
    char    tmp[RM_PATH_MAX], fin[RM_PATH_MAX];
    ssize_t wr;
    size_t  off = 0;
    int     fd;

    if (snprintf(tmp, sizeof(tmp), "%s/.%s.tmp", dir, name) >=
            (int) sizeof(tmp) ||
        snprintf(fin, sizeof(fin), "%s/%s", dir, name) >= (int) sizeof(fin))
        return rm_fail(err, errlen, "repodata path too long");

    fd = open(tmp, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0644);
    if (fd < 0)
        return rm_fail(err, errlen, "create %s: %s", tmp, strerror(errno));
    while (off < len) {
        wr = write(fd, (const char *) data + off, len - off);
        if (wr < 0) {
            if (errno == EINTR)
                continue;
            rm_fail(err, errlen, "write %s: %s", tmp, strerror(errno));
            close(fd);
            unlink(tmp);
            return -1;
        }
        off += (size_t) wr;
    }
    if (fsync(fd) != 0 || close(fd) != 0 || rename(tmp, fin) != 0) {
        rm_fail(err, errlen, "finalize %s: %s", fin, strerror(errno));
        unlink(tmp);
        return -1;
    }
    return 0;
}

/* Emit one document: gz → checksum name → staged write → repomd section. */
static int emit_doc(const char *rd, const char *kind, const char *ns,
                    const char *root, sbuf_t *body, uint32_t npkgs,
                    int64_t now, sbuf_t *sections, char *err, size_t errlen) {
    brix_oci_digest_t raw_d, gz_d;
    sbuf_t            doc = {0};
    unsigned char    *gz = NULL;
    size_t            gzlen = 0;
    char              name[128];
    int               rc = -1;

    if (sb_put(&doc, "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
                     "<%s xmlns=\"http://linux.duke.edu/metadata/%s\"", root,
               ns) != 0 ||
        (strcmp(kind, "primary") == 0 &&
         sb_put(&doc, " xmlns:rpm=\"http://linux.duke.edu/metadata/rpm\"")
             != 0) ||
        sb_put(&doc, " packages=\"%u\">\n", npkgs) != 0 ||
        sb_put(&doc, "%s", body->p != NULL ? body->p : "") != 0 ||
        sb_put(&doc, "</%s>\n", root) != 0) {
        rm_fail(err, errlen, "out of memory");
        free(doc.p);
        return -1;
    }

    if (brix_oci_sha256(doc.p, doc.len, &raw_d) != 0 ||
        gz_buf(doc.p, doc.len, &gz, &gzlen) != 0 ||
        brix_oci_sha256(gz, gzlen, &gz_d) != 0)
        rm_fail(err, errlen, "gzip/sha256 failure for %s", kind);
    else {
        snprintf(name, sizeof(name), "%s-%s.xml.gz", gz_d.hex, kind);
        if (write_staged(rd, name, gz, gzlen, err, errlen) == 0)
            rc = sb_put(sections,
                        "  <data type=\"%s\">\n"
                        "    <checksum type=\"sha256\">%s</checksum>\n"
                        "    <open-checksum type=\"sha256\">%s"
                        "</open-checksum>\n"
                        "    <location href=\"repodata/%s\"/>\n"
                        "    <timestamp>%lld</timestamp>\n"
                        "    <size>%zu</size>\n"
                        "    <open-size>%zu</open-size>\n"
                        "  </data>\n",
                        kind, gz_d.hex, raw_d.hex, name, (long long) now,
                        gzlen, doc.len);
        if (rc != 0 && err != NULL && err[0] == '\0')
            rm_fail(err, errlen, "out of memory");
    }
    free(doc.p);
    free(gz);
    return rc;
}

int brix_repomd_finish(brix_repomd_t *w, char *err, size_t errlen) {
    sbuf_t  sections = {0}, repomd = {0};
    char    rd[RM_PATH_MAX];
    int64_t now = (int64_t) time(NULL);
    int     rc = -1;

    if (err != NULL && errlen > 0)
        err[0] = '\0';
    if (snprintf(rd, sizeof(rd), "%s/repodata", w->repo_dir) >=
        (int) sizeof(rd))
        return rm_fail(err, errlen, "repodata path too long");
    if (mkdir(rd, 0755) != 0 && errno != EEXIST)
        return rm_fail(err, errlen, "mkdir %s: %s", rd, strerror(errno));

    if (emit_doc(rd, "primary", "common", "metadata", &w->pri, w->npkgs, now,
                 &sections, err, errlen) == 0 &&
        emit_doc(rd, "filelists", "filelists", "filelists", &w->fil,
                 w->npkgs, now, &sections, err, errlen) == 0 &&
        emit_doc(rd, "other", "other", "otherdata", &w->oth, w->npkgs, now,
                 &sections, err, errlen) == 0) {
        if (sb_put(&repomd,
                   "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
                   "<repomd xmlns=\"http://linux.duke.edu/metadata/repo\""
                   " xmlns:rpm=\"http://linux.duke.edu/metadata/rpm\">\n"
                   "  <revision>%lld</revision>\n%s</repomd>\n",
                   (long long) now,
                   sections.p != NULL ? sections.p : "") != 0)
            rm_fail(err, errlen, "out of memory");
        else
            /* repomd.xml lands LAST: every file it names already exists. */
            rc = write_staged(rd, "repomd.xml", repomd.p, repomd.len, err,
                              errlen);
    }

    free(sections.p);
    free(repomd.p);
    if (rc == 0)
        brix_repomd_abort(w);    /* success consumes the writer */
    return rc;
}

void brix_repomd_abort(brix_repomd_t *w) {
    if (w == NULL)
        return;
    free(w->pri.p);
    free(w->fil.p);
    free(w->oth.p);
    free(w);
}
