/*
 * copy_zip.c - extracted concern
 * Phase-38 split of copy.c; behavior-identical.
 */
#include "copy_internal.h"


/* phase-42 W3: ?xrdcl.unzip=<member> ZIP-archive member extraction */

ssize_t
zip_remote_pread(void *vctx, uint64_t off, void *buf, size_t len)
{
    zip_remote_ctx *z = vctx;
    return brix_file_read(z->c, z->f, (int64_t) off, buf, len, z->st);
}



int
unzip_sink_write(void *sc, const uint8_t *d, size_t l)
{
    unzip_sink_ctx *s = sc;
    size_t          off = 0;
    while (off < l) {
        ssize_t n = write(s->fd, d + off, l - off);
        if (n < 0) {
            if (errno == EINTR) { continue; }
            return -1;
        }
        off += (size_t) n;
    }
    return 0;
}


/* ---- Open the local destination sink for a ZIP-member extraction ----
 *
 * WHAT: Resolves `du` to a writable fd. For a stdio destination returns
 * STDOUT_FILENO with *use_tmp cleared; for a file destination opens a temp file
 * (path written to `tmp`) and sets *use_tmp so the caller renames on success.
 * Returns the fd, or -1 with `st` populated (destination exists without -f, or
 * temp open failed).
 *
 * WHY: The destination-setup branch (stdout vs. force-check vs. temp-open) is a
 * self-contained decision that inflated copy_unzip past the complexity cap;
 * isolating it keeps the orchestrator a flat sequence and this policy testable.
 *
 * HOW:
 *   1. Clear *use_tmp up front (stdout and error paths leave no temp to clean).
 *   2. For a stdio scheme, return STDOUT_FILENO.
 *   3. Otherwise, unless -f (force) is set, refuse an existing destination.
 *   4. Open the download temp; on failure return -1.
 *   5. Mark *use_tmp and return the temp fd.
 */
static int
copy_unzip_open_dest(const brix_url *du, const brix_copy_opts *o,
                     char *tmp, size_t tmp_sz, int *use_tmp, brix_status *st)
{
    int outfd;

    *use_tmp = 0;
    if (du->scheme == XRDC_SCHEME_STDIO) {
        return STDOUT_FILENO;
    }
    if (!o->force && access(du->path, F_OK) == 0) {
        brix_status_set(st, XRDC_EUSAGE, 0,
                        "destination exists (use -f): %s", du->path);
        return -1;
    }
    outfd = open_download_temp(du->path, tmp, tmp_sz, st);
    if (outfd < 0) {
        return -1;
    }
    *use_tmp = 1;
    return outfd;
}


/* ---- Locate and inflate one member of the remote ZIP archive ----
 *
 * WHAT: Opens the ZIP central directory of the archive of `size` bytes, finds
 * `member`, and inflates it into `outfd` via the streaming sink. Returns 0 on
 * success, or -1 with `st` populated (bad archive, member absent, or extract
 * failure).
 *
 * WHY: The parse/find/extract block owns three failure branches that pushed
 * copy_unzip over the complexity cap; keeping it separate confines the
 * brix_zip_dir lifetime (freed on every exit) to one small function.
 *
 * HOW:
 *   1. Open the directory; on error report "ZIP open failed" and return -1.
 *   2. Find the member; if absent, free the dir and report "member not found".
 *   3. Extract the member into `outfd` through unzip_sink_write.
 *   4. Free the directory unconditionally.
 *   5. Map a non-OK extract result to -1, else return 0.
 */
static int
copy_unzip_extract_member(zip_remote_ctx *zc, uint64_t size,
                          const char *archive_path, const char *member,
                          int outfd, brix_status *st)
{
    brix_zip_dir          dir;
    const brix_zip_entry *e;
    int                   zr;

    zr = brix_zip_open(zip_remote_pread, zc, size, &dir);
    if (zr != XRDC_ZIP_OK) {
        brix_status_set(st, XRDC_EUSAGE, 0,
                        "ZIP open failed (%d) for %s", zr, archive_path);
        return -1;
    }
    e = brix_zip_find(&dir, member);
    if (e == NULL) {
        brix_status_set(st, XRDC_EUSAGE, 0, "ZIP member not found: %s", member);
        brix_zip_dir_free(&dir);
        return -1;
    }
    {
        unzip_sink_ctx sink = { outfd };
        zr = brix_zip_member_extract(zip_remote_pread, zc, e,
                                     unzip_sink_write, &sink);
    }
    brix_zip_dir_free(&dir);
    if (zr != XRDC_ZIP_OK) {
        brix_status_set(st, XRDC_EUSAGE, 0,
                        "ZIP member extract failed (%d): %s", zr, member);
        return -1;
    }
    return 0;
}


/* ---- Commit or discard the temp destination after extraction ----
 *
 * WHAT: When a temp file was used, renames it over `du->path` on success or
 * unlinks it on failure. Returns the final result code (`rc` unchanged, or -1 if
 * the rename failed with `st` populated). A no-op for the stdout path.
 *
 * WHY: The commit step is the mirror of copy_unzip_open_dest and keeps the
 * atomic temp-then-rename policy in one place, so the orchestrator's cleanup
 * stays a single call.
 *
 * HOW:
 *   1. If no temp was used, return `rc` untouched.
 *   2. On a failed extraction, unlink the temp and return `rc`.
 *   3. On success, rename the temp over the destination; if that fails, unlink
 *      and return -1, otherwise return `rc`.
 */
static int
copy_unzip_finalize(int rc, int use_tmp, const char *tmp,
                    const brix_url *du, brix_status *st)
{
    if (!use_tmp) {
        return rc;
    }
    if (rc != 0) {
        unlink(tmp);
        return rc;
    }
    if (rename(tmp, du->path) != 0) {
        brix_status_set(st, XRDC_EUSAGE, errno, "rename to %s", du->path);
        unlink(tmp);
        return -1;
    }
    return rc;
}


/* Extract `member` from the remote ZIP archive at `archive_path` into the local
 * destination du. The server is untouched (serves raw archive bytes); the client
 * parses the directory and inflates the member locally (zlib-only). */
int
copy_unzip(const brix_url *su, const char *archive_path, const char *member,
           const brix_url *du, const brix_copy_opts *o, const brix_opts *co,
           brix_status *st)
{
    brix_conn      c;
    brix_statinfo  si;
    brix_file      f;
    zip_remote_ctx zc;
    int            outfd, use_tmp = 0, rc;
    int            to_stdout = (du->scheme == XRDC_SCHEME_STDIO);
    char           tmp[XRDC_PATH_MAX];

    if (brix_connect(&c, su, co, st) != 0) {
        return -1;
    }
    if (brix_stat(&c, archive_path, &si, st) != 0) {
        brix_close(&c);
        return -1;
    }
    if (brix_file_open_read(&c, archive_path, &f, st) != 0) {
        brix_close(&c);
        return -1;
    }

    outfd = copy_unzip_open_dest(du, o, tmp, sizeof(tmp), &use_tmp, st);
    if (outfd < 0) {
        brix_file_close(&c, &f, st);
        brix_close(&c);
        return -1;
    }

    zc.c = &c; zc.f = &f; zc.st = st;
    rc = copy_unzip_extract_member(&zc, (uint64_t) si.size, archive_path,
                                   member, outfd, st);

    brix_file_close(&c, &f, st);
    if (outfd >= 0 && !to_stdout) {
        close(outfd);
    }
    rc = copy_unzip_finalize(rc, use_tmp, tmp, du, st);
    brix_close(&c);
    return rc;
}


/* If `src` carries the opaque key xrdcl.unzip=<member>, copy `member` into out
 * (caller buffer) and the archive path (opaque stripped) into arch; return 1.
 * Otherwise return 0. */
int
unzip_member_from_src(const char *src, const brix_url *su,
                      char *member, size_t member_sz, char *arch, size_t arch_sz)
{
    const char *q = strstr(src, "xrdcl.unzip=");
    const char *v, *end;
    size_t      n, an;

    if (q == NULL) {
        return 0;
    }
    v   = q + (sizeof("xrdcl.unzip=") - 1);
    end = v;
    while (*end != '\0' && *end != '&') { end++; }
    n = (size_t) (end - v);
    if (n == 0 || n >= member_sz) {
        return 0;
    }
    memcpy(member, v, n);
    member[n] = '\0';

    /* archive path = su->path with any trailing "?opaque" removed. */
    an = strlen(su->path);
    {
        const char *qm = strchr(su->path, '?');
        if (qm != NULL) {
            an = (size_t) (qm - su->path);
        }
    }
    if (an >= arch_sz) {
        return 0;
    }
    memcpy(arch, su->path, an);
    arch[an] = '\0';
    return 1;
}


/* phase-42 W3 write: xrdcp --zip / --zip-append (STORE-only) */
int
zipw_local_write(void *cx, const void *d, size_t n)
{
    zipw_local_sink *s = cx;
    ssize_t          w = pwrite(s->fd, d, n, (off_t) s->off); /* vfs-seam-allow: local zip-archive assembly, not export data */
    if (w < 0 || (size_t) w != n) {
        return -1;
    }
    s->off += n;
    return 0;
}


int
zipw_remote_write(void *cx, const void *d, size_t n)
{
    zipw_remote_sink *s = cx;
    if (brix_file_write(s->c, s->f, (int64_t) s->off, d, n, s->st) != 0) {
        return -1;
    }
    s->off += n;
    return 0;
}


ssize_t
zipw_local_pread(void *cx, uint64_t off, void *buf, size_t len)
{
    return pread(*(int *) cx, buf, len, (off_t) off); /* vfs-seam-allow: local zip-archive assembly, not export data */
}


const char *
zip_member_basename(const char *p)
{
    const char *s = strrchr(p, '/');
    return (s != NULL) ? s + 1 : p;
}


/* Read the existing archive's EOCD + raw central directory for append. Refuses a
 * ZIP64 archive (append-in-place would need 64-bit CD rewrite). Returns 0 with a
 * malloc'd *seed_cd (caller frees), or -1 on error. */
int
zip_read_seed(brix_zip_pread_fn pr, void *ctx, uint64_t size, uint64_t *base,
              uint8_t **seed_cd, size_t *seed_len, size_t *seed_n, brix_status *st)
{
    uint64_t cd_off, cd_size, n;
    int      z64;
    uint8_t *buf;

    if (brix_zip_read_eocd(pr, ctx, size, &cd_off, &cd_size, &n, &z64)
        != XRDC_ZIP_OK)
    {
        brix_status_set(st, XRDC_EUSAGE, 0,
                        "--zip-append: destination is not a valid ZIP archive");
        return -1;
    }
    if (z64) {
        brix_status_set(st, XRDC_EUSAGE, 0,
                        "--zip-append: ZIP64 archives are not supported for append");
        return -1;
    }
    buf = malloc(cd_size ? (size_t) cd_size : 1);
    if (buf == NULL) {
        brix_status_set(st, XRDC_EPROTO, 0, "out of memory");
        return -1;
    }
    if (pr(ctx, cd_off, buf, (size_t) cd_size) != (ssize_t) cd_size) {
        free(buf);
        brix_status_set(st, XRDC_ESOCK, 0, "--zip-append: cannot read central directory");
        return -1;
    }
    *base = cd_off;
    *seed_cd = buf;
    *seed_len = (size_t) cd_size;
    *seed_n = (size_t) n;
    return 0;
}


/* Drive a writer (already created) to add the source member then finish. */
int
zip_emit_member(brix_zip_writer *w, const char *member, int srcfd, brix_status *st)
{
    if (w == NULL) {
        brix_status_set(st, XRDC_EPROTO, 0, "out of memory (zip writer)");
        return -1;
    }
    if (brix_zip_writer_add_fd(w, member, srcfd) != XRDC_ZIP_OK
        || brix_zip_writer_finish(w) != XRDC_ZIP_OK)
    {
        brix_status_set(st, XRDC_ESOCK, 0, "zip write failed");
        return -1;
    }
    return 0;
}


int
copy_zip_store_local(const char *member, int srcfd, const brix_url *du,
                     int append, brix_status *st)
{
    int             flags = append ? (O_RDWR | O_CREAT) : (O_WRONLY | O_CREAT | O_TRUNC);
    int             dfd = open(du->path, flags, 0644);
    uint64_t        base = 0;
    uint8_t        *seed = NULL;
    size_t          seed_len = 0, seed_n = 0;
    zipw_local_sink sink;
    brix_zip_writer *w;
    int             rc;

    if (dfd < 0) {
        brix_status_set(st, XRDC_EUSAGE, errno, "open %s: %s",
                        du->path, strerror(errno));
        return -1;
    }
    if (append) {
        struct stat sb;
        if (fstat(dfd, &sb) == 0 && sb.st_size > 0) {
            if (zip_read_seed(zipw_local_pread, &dfd, (uint64_t) sb.st_size,
                              &base, &seed, &seed_len, &seed_n, st) != 0) {
                close(dfd);
                return -1;
            }
        }
    }
    sink.fd = dfd;
    sink.off = base;
    brix_zip_seed zs = { seed, seed_len, seed_n };
    w = seed ? brix_zip_writer_new_append(zipw_local_write, &sink, base, &zs)
             : brix_zip_writer_new(zipw_local_write, &sink);
    rc = zip_emit_member(w, member, srcfd, st);
    brix_zip_writer_free(w);
    free(seed);
    /* Append always grows the archive (new member + larger CD), and create uses
     * O_TRUNC, so the written length is authoritative — no tail to trim. */
    close(dfd);
    return rc;
}


int
copy_zip_store_remote(const char *member, int srcfd, const brix_url *du,
                      int append, const brix_opts *co, brix_status *st)
{
    brix_conn         c;
    brix_file         f;
    brix_statinfo     si;
    uint64_t          base = 0;
    uint8_t          *seed = NULL;
    size_t            seed_len = 0, seed_n = 0;
    int               existed = 0, rc;
    zipw_remote_sink  sink;
    brix_zip_writer  *w;

    if (brix_connect(&c, du, co, st) != 0) {
        return -1;
    }
    if (append && brix_stat(&c, du->path, &si, st) == 0 && si.size > 0) {
        existed = 1;
    }
    if (existed) {
        if (brix_file_open_update(&c, du->path, 0, &f, st) != 0) {
            brix_close(&c);
            return -1;
        }
        zip_remote_ctx zc = { &c, &f, st };
        if (zip_read_seed(zip_remote_pread, &zc, (uint64_t) si.size,
                          &base, &seed, &seed_len, &seed_n, st) != 0) {
            brix_file_close(&c, &f, st);
            brix_close(&c);
            return -1;
        }
    } else if (brix_file_open_write(&c, du->path, 1 /*truncate*/, 0, &f, st) != 0) {
        brix_close(&c);
        return -1;
    }

    sink.c = &c;
    sink.f = &f;
    sink.off = base;
    sink.st = st;
    brix_zip_seed zs = { seed, seed_len, seed_n };
    w = seed ? brix_zip_writer_new_append(zipw_remote_write, &sink, base, &zs)
             : brix_zip_writer_new(zipw_remote_write, &sink);
    rc = zip_emit_member(w, member, srcfd, st);
    brix_zip_writer_free(w);
    free(seed);

    {
        brix_status tw;
        brix_status_clear(&tw);
        if (brix_file_close(&c, &f, rc == 0 ? st : &tw) != 0 && rc == 0) {
            rc = -1;
        }
    }
    brix_close(&c);
    return rc;
}


/* xrdcp --zip / --zip-append: store the local source as a STORE member of the
 * destination ZIP archive (create, or append to an existing non-ZIP64 archive). */
int
copy_zip_store(const brix_url *su, const brix_url *du, const brix_copy_opts *o,
               const brix_opts *co, brix_status *st)
{
    const char *member;
    int         srcfd, append, dst_remote, rc;

    if (su->scheme == XRDC_SCHEME_STDIO) {
        brix_status_set(st, XRDC_EUSAGE, 0, "--zip requires a regular-file source");
        return -1;
    }
    member = zip_member_basename(su->path);
    srcfd = open(su->path, O_RDONLY);
    if (srcfd < 0) {
        brix_status_set(st, XRDC_EUSAGE, errno, "open %s: %s",
                        su->path, strerror(errno));
        return -1;
    }
    append = (o != NULL && o->zip_append);
    dst_remote = (du->scheme == XRDC_SCHEME_ROOT || du->scheme == XRDC_SCHEME_ROOTS);

    rc = dst_remote
       ? copy_zip_store_remote(member, srcfd, du, append, co, st)
       : copy_zip_store_local(member, srcfd, du, append, st);

    close(srcfd);
    return rc;
}
