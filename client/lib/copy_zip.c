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
    return xrdc_file_read(z->c, z->f, (int64_t) off, buf, len, z->st);
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


/* Extract `member` from the remote ZIP archive at `archive_path` into the local
 * destination du. The server is untouched (serves raw archive bytes); the client
 * parses the directory and inflates the member locally (zlib-only). */
int
copy_unzip(const xrdc_url *su, const char *archive_path, const char *member,
           const xrdc_url *du, const xrdc_copy_opts *o, const xrdc_opts *co,
           xrdc_status *st)
{
    xrdc_conn      c;
    xrdc_statinfo  si;
    xrdc_file      f;
    xrdc_zip_dir   dir;
    zip_remote_ctx zc;
    const xrdc_zip_entry *e;
    int            outfd = -1, to_stdout = (du->scheme == XRDC_SCHEME_STDIO);
    int            use_tmp = 0, rc = -1, zr;
    char           tmp[XRDC_PATH_MAX];

    if (xrdc_connect(&c, su, co, st) != 0) {
        return -1;
    }
    if (xrdc_stat(&c, archive_path, &si, st) != 0) {
        xrdc_close(&c);
        return -1;
    }
    if (xrdc_file_open_read(&c, archive_path, &f, st) != 0) {
        xrdc_close(&c);
        return -1;
    }

    if (to_stdout) {
        outfd = STDOUT_FILENO;
    } else {
        if (!o->force && access(du->path, F_OK) == 0) {
            xrdc_status_set(st, XRDC_EUSAGE, 0,
                            "destination exists (use -f): %s", du->path);
            xrdc_file_close(&c, &f, st); xrdc_close(&c); return -1;
        }
        outfd = open_download_temp(du->path, tmp, sizeof(tmp), st);
        if (outfd < 0) {
            xrdc_file_close(&c, &f, st); xrdc_close(&c); return -1;
        }
        use_tmp = 1;
    }

    zc.c = &c; zc.f = &f; zc.st = st;
    zr = xrdc_zip_open(zip_remote_pread, &zc, (uint64_t) si.size, &dir);
    if (zr != XRDC_ZIP_OK) {
        xrdc_status_set(st, XRDC_EUSAGE, 0,
                        "ZIP open failed (%d) for %s", zr, archive_path);
    } else {
        e = xrdc_zip_find(&dir, member);
        if (e == NULL) {
            xrdc_status_set(st, XRDC_EUSAGE, 0,
                            "ZIP member not found: %s", member);
        } else {
            unzip_sink_ctx sink = { outfd };
            zr = xrdc_zip_member_extract(zip_remote_pread, &zc, e,
                                         unzip_sink_write, &sink);
            if (zr == XRDC_ZIP_OK) {
                rc = 0;
            } else {
                xrdc_status_set(st, XRDC_EUSAGE, 0,
                                "ZIP member extract failed (%d): %s", zr, member);
            }
        }
        xrdc_zip_dir_free(&dir);
    }

    xrdc_file_close(&c, &f, st);
    if (outfd >= 0 && !to_stdout) {
        close(outfd);
    }
    if (use_tmp) {
        if (rc == 0) {
            if (rename(tmp, du->path) != 0) {
                xrdc_status_set(st, XRDC_EUSAGE, errno, "rename to %s", du->path);
                unlink(tmp);
                rc = -1;
            }
        } else {
            unlink(tmp);
        }
    }
    xrdc_close(&c);
    return rc;
}


/* If `src` carries the opaque key xrdcl.unzip=<member>, copy `member` into out
 * (caller buffer) and the archive path (opaque stripped) into arch; return 1.
 * Otherwise return 0. */
int
unzip_member_from_src(const char *src, const xrdc_url *su,
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
    ssize_t          w = pwrite(s->fd, d, n, (off_t) s->off);
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
    if (xrdc_file_write(s->c, s->f, (int64_t) s->off, d, n, s->st) != 0) {
        return -1;
    }
    s->off += n;
    return 0;
}


ssize_t
zipw_local_pread(void *cx, uint64_t off, void *buf, size_t len)
{
    return pread(*(int *) cx, buf, len, (off_t) off);
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
zip_read_seed(xrdc_zip_pread_fn pr, void *ctx, uint64_t size, uint64_t *base,
              uint8_t **seed_cd, size_t *seed_len, size_t *seed_n, xrdc_status *st)
{
    uint64_t cd_off, cd_size, n;
    int      z64;
    uint8_t *buf;

    if (xrdc_zip_read_eocd(pr, ctx, size, &cd_off, &cd_size, &n, &z64)
        != XRDC_ZIP_OK)
    {
        xrdc_status_set(st, XRDC_EUSAGE, 0,
                        "--zip-append: destination is not a valid ZIP archive");
        return -1;
    }
    if (z64) {
        xrdc_status_set(st, XRDC_EUSAGE, 0,
                        "--zip-append: ZIP64 archives are not supported for append");
        return -1;
    }
    buf = malloc(cd_size ? (size_t) cd_size : 1);
    if (buf == NULL) {
        xrdc_status_set(st, XRDC_EPROTO, 0, "out of memory");
        return -1;
    }
    if (pr(ctx, cd_off, buf, (size_t) cd_size) != (ssize_t) cd_size) {
        free(buf);
        xrdc_status_set(st, XRDC_ESOCK, 0, "--zip-append: cannot read central directory");
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
zip_emit_member(xrdc_zip_writer *w, const char *member, int srcfd, xrdc_status *st)
{
    if (w == NULL) {
        xrdc_status_set(st, XRDC_EPROTO, 0, "out of memory (zip writer)");
        return -1;
    }
    if (xrdc_zip_writer_add_fd(w, member, srcfd) != XRDC_ZIP_OK
        || xrdc_zip_writer_finish(w) != XRDC_ZIP_OK)
    {
        xrdc_status_set(st, XRDC_ESOCK, 0, "zip write failed");
        return -1;
    }
    return 0;
}


int
copy_zip_store_local(const char *member, int srcfd, const xrdc_url *du,
                     int append, xrdc_status *st)
{
    int             flags = append ? (O_RDWR | O_CREAT) : (O_WRONLY | O_CREAT | O_TRUNC);
    int             dfd = open(du->path, flags, 0644);
    uint64_t        base = 0;
    uint8_t        *seed = NULL;
    size_t          seed_len = 0, seed_n = 0;
    zipw_local_sink sink;
    xrdc_zip_writer *w;
    int             rc;

    if (dfd < 0) {
        xrdc_status_set(st, XRDC_EUSAGE, errno, "open %s: %s",
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
    w = seed ? xrdc_zip_writer_new_append(zipw_local_write, &sink, base,
                                          seed, seed_len, seed_n)
             : xrdc_zip_writer_new(zipw_local_write, &sink);
    rc = zip_emit_member(w, member, srcfd, st);
    xrdc_zip_writer_free(w);
    free(seed);
    /* Append always grows the archive (new member + larger CD), and create uses
     * O_TRUNC, so the written length is authoritative — no tail to trim. */
    close(dfd);
    return rc;
}


int
copy_zip_store_remote(const char *member, int srcfd, const xrdc_url *du,
                      int append, const xrdc_opts *co, xrdc_status *st)
{
    xrdc_conn         c;
    xrdc_file         f;
    xrdc_statinfo     si;
    uint64_t          base = 0;
    uint8_t          *seed = NULL;
    size_t            seed_len = 0, seed_n = 0;
    int               existed = 0, rc;
    zipw_remote_sink  sink;
    xrdc_zip_writer  *w;

    if (xrdc_connect(&c, du, co, st) != 0) {
        return -1;
    }
    if (append && xrdc_stat(&c, du->path, &si, st) == 0 && si.size > 0) {
        existed = 1;
    }
    if (existed) {
        if (xrdc_file_open_update(&c, du->path, 0, &f, st) != 0) {
            xrdc_close(&c);
            return -1;
        }
        zip_remote_ctx zc = { &c, &f, st };
        if (zip_read_seed(zip_remote_pread, &zc, (uint64_t) si.size,
                          &base, &seed, &seed_len, &seed_n, st) != 0) {
            xrdc_file_close(&c, &f, st);
            xrdc_close(&c);
            return -1;
        }
    } else if (xrdc_file_open_write(&c, du->path, 1 /*truncate*/, 0, &f, st) != 0) {
        xrdc_close(&c);
        return -1;
    }

    sink.c = &c;
    sink.f = &f;
    sink.off = base;
    sink.st = st;
    w = seed ? xrdc_zip_writer_new_append(zipw_remote_write, &sink, base,
                                          seed, seed_len, seed_n)
             : xrdc_zip_writer_new(zipw_remote_write, &sink);
    rc = zip_emit_member(w, member, srcfd, st);
    xrdc_zip_writer_free(w);
    free(seed);

    {
        xrdc_status tw;
        xrdc_status_clear(&tw);
        if (xrdc_file_close(&c, &f, rc == 0 ? st : &tw) != 0 && rc == 0) {
            rc = -1;
        }
    }
    xrdc_close(&c);
    return rc;
}


/* xrdcp --zip / --zip-append: store the local source as a STORE member of the
 * destination ZIP archive (create, or append to an existing non-ZIP64 archive). */
int
copy_zip_store(const xrdc_url *su, const xrdc_url *du, const xrdc_copy_opts *o,
               const xrdc_opts *co, xrdc_status *st)
{
    const char *member;
    int         srcfd, append, dst_remote, rc;

    if (su->scheme == XRDC_SCHEME_STDIO) {
        xrdc_status_set(st, XRDC_EUSAGE, 0, "--zip requires a regular-file source");
        return -1;
    }
    member = zip_member_basename(su->path);
    srcfd = open(su->path, O_RDONLY);
    if (srcfd < 0) {
        xrdc_status_set(st, XRDC_EUSAGE, errno, "open %s: %s",
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
