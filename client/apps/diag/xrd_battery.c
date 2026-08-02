/*
 * xrd_battery.c - extracted concern
 * Phase-38 split of xrd.c; behavior-identical.
 */
#include "xrd_internal.h"


/* endpoint diagnostic report (shared by the verbs below + doctor) */


/* One endpoint's diagnostic facts (filled piecemeal by the gatherers; doctor fills
 * all of it, the standalone verbs fill their own slice). */

/* Defined further down (with the diagnostic verbs); forward-declared so doctor can
 * compose them. */

/* functional method battery (doctor --rw / multi-protocol) */


/* One protocol face's functional results. */

/* Append a result. status: >0 pass, 0 fail, <0 skipped. */
void
bat_add(xrd_battery *b, const char *name, int status, const char *fmt, ...)
{
    xrd_check *c;
    va_list    ap;
    if (b->n >= XRD_MAX_CHECKS) { return; }
    c = &b->checks[b->n++];
    snprintf(c->name, sizeof(c->name), "%s", name);
    c->ok      = (status > 0);
    c->skipped = (status < 0);
    va_start(ap, fmt);
    vsnprintf(c->detail, sizeof(c->detail), fmt, ap);
    va_end(ap);
    if (status < 0)      { b->nskip++; }
    else if (status > 0) { b->npass++; }
    else                 { b->nfail++; }
}


/* Fill `buf` (size n) with a deterministic, position-dependent pattern. */
void
fill_pattern(uint8_t *buf, size_t n)
{
    size_t i;
    for (i = 0; i < n; i++) { buf[i] = (uint8_t) ((i * 7u + 3u) & 0xff); }
}


/* Write `buf` to an anonymous tmpfile and return its fd (rewound), or -1. */
int
tmpfile_with(const uint8_t *buf, size_t n)
{
    FILE *f = tmpfile();
    int   fd;
    if (f == NULL) { return -1; }
    if (n > 0 && fwrite(buf, 1, n, f) != n) { fclose(f); return -1; }
    fflush(f);
    fd = dup(fileno(f));
    fclose(f);
    if (fd >= 0) { lseek(fd, 0, SEEK_SET); }
    return fd;
}


/* fd-backed pull source for brix_http_upload: the battery's body is an anonymous
 * tmpfile (generated diagnostic payload, not export storage), so a plain pread by
 * offset is the source — storage callers pass a VFS-backed source instead. */
ssize_t
bat_upload_src_fd(void *ctx, uint8_t *buf, int64_t off, size_t cap, brix_status *st)
{
    ssize_t r = pread(*(int *) ctx, buf, cap, (off_t) off);  /* vfs-seam-allow: anonymous tmpfile diagnostic payload, not export storage */
    if (r < 0) {
        brix_status_set(st, XRDC_ESOCK, errno, "pread: %s", strerror(errno));
    }
    return r;
}

static void
probe_root_read_suite(brix_conn *c, xrd_battery *b)
{
    brix_status   st;
    brix_statinfo si;
    brix_dirent  *ents = NULL;
    size_t        nents = 0;
    char          reply[1024];

    brix_status_clear(&st);
    if (brix_stat(c, "/", &si, &st) == 0) { bat_add(b, "stat", 1, "/ flags=0x%x", si.flags); }
    else { bat_add(b, "stat", 0, "%s", st.msg); }

    brix_status_clear(&st);
    if (brix_dirlist(c, "/", 0, &ents, &nents, &st) == 0) {
        bat_add(b, "dirlist", 1, "%zu entries", nents);
        free(ents);
    } else { bat_add(b, "dirlist", 0, "%s", st.msg); }

    brix_status_clear(&st);
    if (brix_statvfs(c, "/", reply, sizeof(reply), &st) == 0) { bat_add(b, "statvfs", 1, "ok"); }
    else { bat_add(b, "statvfs", 0, "%s", st.msg); }

    brix_status_clear(&st);
    if (brix_query(c, kXR_Qconfig, "chksum", reply, sizeof(reply), &st) == 0) {
        char *nl = strchr(reply, '\n'); if (nl) { *nl = '\0'; }
        bat_add(b, "query-config", 1, "%s", reply);
    } else { bat_add(b, "query-config", 0, "%s", st.msg); }
}

static void
probe_path_confinement(brix_conn *c, xrd_battery *b)
{
    brix_status   st;
    brix_statinfo si;
    int           rc;

    brix_status_clear(&st);
    rc = brix_stat(c, "/../../../../etc/passwd", &si, &st);
    bat_add(b, "path-confinement", rc != 0 ? 1 : 0,
            rc != 0 ? "escape rejected" : "LEAKED /etc/passwd");
}

static int
write_verify(brix_conn *c, const char *file, const uint8_t *payload, size_t payload_len,
             xrd_battery *b)
{
    brix_status st;
    brix_file   f;
    int         ok = 0;

    brix_status_clear(&st);
    if (brix_file_open_write(c, file, 1, 0, &f, &st) == 0) {
        ok = (brix_file_write(c, &f, 0, payload, payload_len, &st) == 0);
        brix_file_close(c, &f, &st);
    }
    bat_add(b, "write", ok ? 1 : 0, ok ? "%zu bytes" : "%s",
            ok ? payload_len : (size_t) 0, ok ? "" : st.msg);
    return ok;
}

static void
write_readv(brix_conn *c, const char *file, const uint8_t *payload, xrd_battery *b)
{
    brix_status    st;
    brix_file      f;
    brix_readv_seg segs[2];
    int            match = 0;
    uint8_t        s0[64], s1[128];

    segs[0].offset = 0;    segs[0].len = sizeof(s0); segs[0].buf = s0; segs[0].got = 0;
    segs[1].offset = 1000; segs[1].len = sizeof(s1); segs[1].buf = s1; segs[1].got = 0;
    brix_status_clear(&st);
    if (brix_file_open_read(c, file, &f, &st) == 0) {
        if (brix_file_readv(c, &f, segs, 2, &st) >= 0) {
            match = (memcmp(s0, payload, sizeof(s0)) == 0
                     && memcmp(s1, payload + 1000, sizeof(s1)) == 0);
        }
        brix_file_close(c, &f, &st);
    }
    bat_add(b, "readv", match ? 1 : 0, match ? "2 segs verified" : "%s", st.msg);
}

static void
write_checksum(brix_conn *c, const char *file, const uint8_t *payload, size_t payload_len,
               xrd_battery *b)
{
    brix_status st;
    char        srvck[160], locck[160];
    int         fd;
    int         verified = 0;

    fd = tmpfile_with(payload, payload_len);
    brix_status_clear(&st);
    if (fd >= 0
        && brix_cksum_fd(fd, XRDC_CK_ADLER32, locck, sizeof(locck), &st) == 0
        && brix_query_cksum(c, file, "adler32", srvck, sizeof(srvck), &st) == 0) {
        verified = (strcmp(locck, srvck) == 0);
    }
    if (fd >= 0) { close(fd); }
    bat_add(b, "checksum-verify", verified ? 1 : 0,
            verified ? "adler32 %s matches" : "server/local differ or n/a",
            verified ? srvck : "");
}

static void
write_xattr_ops(brix_conn *c, const char *file, xrd_battery *b)
{
    brix_status st;
    char        val[64];
    size_t      vlen = 0;
    int         okset, okget, okdel;

    brix_status_clear(&st);
    okset = (brix_fattr_set(c, file, "doctor", "ok", 2, 0, &st) == 0);
    okget = okset && (brix_fattr_get(c, file, "doctor", val, sizeof(val), &vlen, &st) == 0
                      && vlen == 2 && memcmp(val, "ok", 2) == 0);
    okdel = okget && (brix_fattr_del(c, file, "doctor", &st) == 0);
    bat_add(b, "xattr", okdel ? 1 : (okset ? 0 : -1),
            okdel ? "set/get/del roundtrip" : (okset ? "%s" : "not supported"),
            okdel ? "" : st.msg);
}

static void
write_symlink_ops(brix_conn *c, const char *dir, const char *file, int ext_sl, int ext_rl,
                  int *sym_left, xrd_battery *b)
{
    brix_status st;
    char        lp[200], tgt[256];
    ssize_t     rl;
    int         made;

    if (!ext_sl || !ext_rl) {
        bat_add(b, "symlink+readlink", -1, "server lacks xrdfs.ext");
        return;
    }
    snprintf(lp, sizeof(lp), "%s/probe.link", dir);
    brix_status_clear(&st);
    made = (brix_symlink(c, file, lp, &st) == 0);
    if (made && (rl = brix_readlink(c, lp, tgt, sizeof(tgt), &st)) > 0
        && strcmp(tgt, file) == 0) {
        brix_status rs;
        brix_status_clear(&rs);
        if (brix_rm(c, lp, &rs) != 0) {
            *sym_left = 1;
            bat_add(b, "symlink+readlink", 1,
                    "create+readlink ok; unlink unsupported (rm follows the link)");
        } else {
            bat_add(b, "symlink+readlink", 1, "create/readlink/unlink ok");
        }
    } else {
        bat_add(b, "symlink+readlink", made ? 0 : 0, "%s", st.msg);
        if (made) { brix_status rs; brix_status_clear(&rs);
                    if (brix_rm(c, lp, &rs) != 0) { *sym_left = 1; } }
    }
}

static void
write_rename_truncate_rm(brix_conn *c, const char *dir, const char *file,
                         const char *file2, int sym_left, xrd_battery *b)
{
    brix_status st;
    int         rc;

    brix_status_clear(&st);
    rc = brix_mv(c, file, file2, &st);
    bat_add(b, "rename", rc == 0 ? 1 : 0, "%s", rc == 0 ? "moved" : st.msg);
    brix_status_clear(&st);
    rc = brix_truncate(c, file2, 10, &st);
    bat_add(b, "truncate", rc == 0 ? 1 : 0, "%s", rc == 0 ? "to 10 bytes" : st.msg);
    brix_status_clear(&st);
    rc = brix_rm(c, file2, &st);
    bat_add(b, "rm", rc == 0 ? 1 : 0, "%s", rc == 0 ? "removed" : st.msg);
    if (sym_left) {
        bat_add(b, "rmdir", -1,
                "skipped: temp dir retains a symlink the server cannot unlink");
    } else {
        brix_status_clear(&st);
        rc = brix_rmdir(c, dir, &st);
        bat_add(b, "rmdir", rc == 0 ? 1 : 0, "%s", rc == 0 ? "removed" : st.msg);
    }
}

static void
probe_write_suite(brix_conn *c, int ext_sa, int ext_sl, int ext_rl, xrd_battery *b)
{
    brix_status st;
    char        dir[128], file[200], file2[200];
    uint8_t     payload[8192], rbuf[8192];
    long        pid = (long) getpid();
    int         rc, sym_left = 0;

    snprintf(dir,   sizeof(dir),   "/.xrd_doctor_%ld", pid);
    snprintf(file,  sizeof(file),  "%s/probe.bin", dir);
    snprintf(file2, sizeof(file2), "%s/probe.moved.bin", dir);
    fill_pattern(payload, sizeof(payload));

    brix_status_clear(&st);
    rc = brix_mkdir(c, dir, 0755, 1, &st);
    bat_add(b, "mkdir", rc == 0 ? 1 : 0, "%s", rc == 0 ? dir : st.msg);

    write_verify(c, file, payload, sizeof(payload), b);
    {
        brix_file f;
        ssize_t   got = -1;
        int       match = 0;
        brix_status_clear(&st);
        if (brix_file_open_read(c, file, &f, &st) == 0) {
            got = brix_file_read(c, &f, 0, rbuf, sizeof(rbuf), &st);
            brix_file_close(c, &f, &st);
            match = (got == (ssize_t) sizeof(payload)
                     && memcmp(rbuf, payload, sizeof(payload)) == 0);
        }
        bat_add(b, "read-verify", match ? 1 : 0,
                match ? "byte-exact %zd bytes" : "mismatch/short (%s)",
                match ? got : 0, match ? "" : st.msg);
    }
    write_readv(c, file, payload, b);
    write_checksum(c, file, payload, sizeof(payload), b);
    if (ext_sa) {
        struct timespec ts[2];
        ts[0].tv_sec = ts[1].tv_sec = 0;
        ts[0].tv_nsec = ts[1].tv_nsec = UTIME_NOW;
        brix_status_clear(&st);
        rc = brix_setattr(c, file, 1, ts, 0, (uint32_t) -1, (uint32_t) -1, &st);
        bat_add(b, "setattr-times", rc == 0 ? 1 : 0, "%s", rc == 0 ? "mtime set" : st.msg);
    } else { bat_add(b, "setattr-times", -1, "server lacks xrdfs.ext"); }
    write_xattr_ops(c, file, b);
    write_symlink_ops(c, dir, file, ext_sl, ext_rl, &sym_left, b);
    write_rename_truncate_rm(c, dir, file, file2, sym_left, b);
}


/* The native root:// functional battery: always-safe reads, then (do_write) a full
 * write/read/verify/checksum/metadata cycle under a temp dir that is cleaned up. */
void
battery_root(const brix_url *u, const brix_opts *o, int do_write, xrd_battery *b)
{
    brix_conn     c;
    brix_status   st;
    int           ext_sa = 0, ext_sl = 0, ext_rl = 0, ext_ln = 0;

    snprintf(b->protocol, sizeof(b->protocol), "root");
    brix_status_clear(&st);
    if (brix_connect(&c, u, o, &st) != 0) {
        snprintf(b->err, sizeof(b->err), "%s", st.msg);
        return;
    }
    b->reachable = 1;

    probe_root_read_suite(&c, b);
    probe_path_confinement(&c, b);

    (void) brix_ext_probe(&c, &ext_sa, &ext_sl, &ext_rl, &ext_ln, &st);

    if (!do_write) {
        bat_add(b, "write-suite", -1, "skipped (pass --rw to run write tests)");
        brix_close(&c);
        return;
    }

    probe_write_suite(&c, ext_sa, ext_sl, ext_rl, b);
    brix_close(&c);
}



/* Route an endpoint to the right functional battery (root:// / WebDAV / S3). */
void
xrd_run_battery(const char *endpoint, int do_write, int verify, xrd_battery *b)
{
    memset(b, 0, sizeof(*b));
    snprintf(b->endpoint, sizeof(b->endpoint), "%s", endpoint);

    if (brix_is_web_url(endpoint)) {
        brix_weburl w;
        if (brix_weburl_parse(endpoint, &w) != 0) {
            snprintf(b->protocol, sizeof(b->protocol), "web");
            snprintf(b->err, sizeof(b->err), "unparseable web URL");
            return;
        }
        if (w.is_s3) {
            const char *region = getenv("AWS_DEFAULT_REGION");
            battery_s3(&w, do_write, getenv("AWS_ACCESS_KEY_ID"),
                       getenv("AWS_SECRET_ACCESS_KEY"),
                       region ? region : "us-east-1", verify, b);
        } else {
            char *tok = brix_token_discover();
            battery_web(&w, do_write, tok, verify, b);
            if (tok != NULL) { free(tok); }
        }
        return;
    }
    {
        brix_url    u;
        brix_opts   o;
        brix_status st;
        memset(&o, 0, sizeof(o));
        o.verify_host = verify;
        brix_status_clear(&st);
        snprintf(b->protocol, sizeof(b->protocol), "root");
        if (brix_endpoint_parse(endpoint, &u, &st) != 0) {
            snprintf(b->err, sizeof(b->err), "%s", st.msg);
            return;
        }
        battery_root(&u, &o, do_write, b);
    }
}
