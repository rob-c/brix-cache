/*
 * test_staged_contract_origin.c — the staged_commit OWNERSHIP contract for the
 * ORIGIN-side publishers: sd_http (WebDAV/HTTP PUT), sd_xroot (root:// Mode-A
 * write-through) and the sd_cache decorator's forwarding slots.
 *
 * CONTRACT (src/fs/vfs/vfs_staged.c): driver->staged_commit consumes (frees) the
 * heap handle ONLY on success; a failed commit leaves it valid and the caller
 * releases it with driver->staged_abort. Every caller does exactly that
 * (stage_engine_move, cstb_pump_and_commit, cache fetch.c), so a driver that
 * frees on the failure path turns the mandatory abort into a use-after-free —
 * the family already fixed in sd_remote, sd_posix, sd_stage and sd_frm.
 *
 * These three obey it today; this pins that, per driver, so a later edit cannot
 * regress it silently. Both real drivers are driven hermetically — sd_http over a
 * scripted fake brix_s3_transport_t, sd_xroot over stubbed brix_cache_origin_*
 * wire calls — and everything is built under ASan so a double free or a UAF in
 * the abort that follows a failed commit aborts the run.
 *
 * Arms per driver: success (published, consumed exactly once), error (status /
 * transport / sync failure ⇒ NGX_ERROR with a mapped errno and a handle the
 * abort can still release), and a security-negative (an origin refusal must NOT
 * surface as a successful publish, and a failed commit must not re-issue the
 * upload from abort).
 */
#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <ngx_config.h>
#include <ngx_core.h>

#include "fs/backend/sd.h"
#include "fs/backend/http/sd_http.h"
#include "fs/backend/xroot/sd_xroot.h"
#include "fs/backend/xroot/sd_xroot_internal.h"
#include "fs/backend/cache/sd_cache_internal.h"

static int failures;
#define CHECK(cond, msg) \
    do { if (!(cond)) { \
        fprintf(stderr, "FAIL: %s (errno=%d %s)\n", (msg), errno, strerror(errno)); \
        failures++; \
    } } while (0)

/* ---- ngx / brix link stubs (instances are built log=NULL ⇒ logging inert) -- */

volatile ngx_cycle_t *ngx_cycle = NULL;

void ngx_log_error_core(ngx_uint_t level, ngx_log_t *log, ngx_err_t err,
    const char *fmt, ...) { (void) level; (void) log; (void) err; (void) fmt; }

size_t brix_sanitize_log_string(const char *in, char *out, size_t outsz)
{
    size_t n = 0;

    if (outsz == 0) { return 0; }
    while (in != NULL && in[n] != '\0' && n + 1 < outsz) { out[n] = in[n]; n++; }
    out[n] = '\0';
    return n;
}

ngx_int_t ngx_strncasecmp(u_char *s1, u_char *s2, size_t n)
{
    ngx_uint_t c1, c2;

    while (n) {
        c1 = (ngx_uint_t) *s1++;
        c2 = (ngx_uint_t) *s2++;
        c1 = (c1 >= 'A' && c1 <= 'Z') ? (c1 | 0x20) : c1;
        c2 = (c2 >= 'A' && c2 <= 'Z') ? (c2 | 0x20) : c2;
        if (c1 == c2) {
            if (c1) { n--; continue; }
            return 0;
        }
        return (ngx_int_t) c1 - (ngx_int_t) c2;
    }
    return 0;
}

u_char *ngx_cpystrn(u_char *dst, u_char *src, size_t n)
{
    if (n == 0) { return dst; }
    while (--n) { if ((*dst = *src) == '\0') { return dst; } dst++; src++; }
    *dst = '\0';
    return dst;
}

/* cstore slots sd_cache_forward.o references but the staged path never calls. */
ngx_int_t brix_cstore_cinfo_load(brix_cstore_t *cs, const char *key,
    brix_cache_cinfo_t *out)
{
    (void) cs; (void) key; (void) out;
    return NGX_ERROR;
}
ngx_int_t brix_cstore_evict(brix_cstore_t *cs, const char *key)
{
    (void) cs; (void) key;
    return NGX_ERROR;
}

/* ---- sd_http: scripted fake transport ------------------------------------- */

static long g_status;          /* status the next request replies with        */
static int  g_fail;            /* 1 ⇒ transport-level failure (no status)     */
static int  g_puts;            /* PUT requests actually issued                */

static int
fake_request(void *tctx, const char *host, int port, int tls,
    const char *method, const char *path_and_query, const char *headers,
    const void *body, size_t body_len, int timeout_ms,
    brix_s3_resp_t *resp, char *errbuf, size_t errcap)
{
    (void) tctx; (void) host; (void) port; (void) tls; (void) path_and_query;
    (void) headers; (void) body; (void) body_len; (void) timeout_ms;
    (void) errbuf; (void) errcap;

    if (strcmp(method, "PUT") == 0) { g_puts++; }
    resp->opaque = NULL;
    if (g_fail) { return -1; }
    resp->status = g_status;
    return 0;
}

static int fake_resp_header(const brix_s3_resp_t *resp, const char *name,
    char *out, size_t outcap)
{
    (void) resp; (void) name; (void) out; (void) outcap;
    return -1;
}
static const void *fake_resp_body(const brix_s3_resp_t *resp, size_t *len)
{
    (void) resp;
    if (len) { *len = 0; }
    return NULL;
}
static void fake_resp_free(brix_s3_resp_t *resp) { (void) resp; }

static const brix_s3_transport_t g_fake_transport = {
    .request     = fake_request,
    .resp_header = fake_resp_header,
    .resp_body   = fake_resp_body,
    .resp_free   = fake_resp_free,
};

static brix_sd_instance_t *
http_instance(void)
{
    brix_sd_http_cfg_t cfg;

    memset(&cfg, 0, sizeof(cfg));
    cfg.host       = "127.0.0.1";
    cfg.port       = 9999;
    cfg.base_path  = "/base";
    cfg.transport  = &g_fake_transport;
    cfg.timeout_ms = 2000;
    return brix_sd_http_create(&cfg, NULL);   /* log=NULL ⇒ logging inert */
}

/* Open + fill one staged upload on `inst`; NULL on a refused open. */
static brix_sd_staged_t *
staged_body(brix_sd_instance_t *inst, const char *path, const char *body)
{
    int                err = 0;
    brix_sd_staged_t *h = inst->driver->staged_open(inst, path, 0644, &err);

    if (h != NULL && body != NULL) {
        CHECK(inst->driver->staged_write(h, body, strlen(body), 0)
                  == (ssize_t) strlen(body), "staged_write");
    }
    return h;
}

static void
run_http_arms(void)
{
    brix_sd_instance_t *inst = http_instance();

    CHECK(inst != NULL, "brix_sd_http_create");
    if (inst == NULL) { return; }
    CHECK(inst->driver->staged_commit != NULL && inst->driver->staged_abort != NULL,
          "sd_http wires both staged slots");

    /* A. SUCCESS — every accepted PUT status publishes and consumes the handle
     *    exactly once (no abort may follow; ASan would catch it if one did). */
    {
        const long ok_status[] = { 200, 201, 204 };
        size_t     i;

        for (i = 0; i < sizeof(ok_status) / sizeof(ok_status[0]); i++) {
            brix_sd_staged_t *h = staged_body(inst, "/ok.bin", "hello");

            CHECK(h != NULL, "sd_http staged_open (success)");
            if (h == NULL) { continue; }
            g_status = ok_status[i]; g_fail = 0; g_puts = 0;
            CHECK(inst->driver->staged_commit(h, 0) == NGX_OK,
                  "an accepted PUT status must commit");
            CHECK(g_puts == 1, "exactly one PUT per commit");
        }
    }

    /* B. TRANSPORT FAILURE — no status at all. The commit fails and the handle
     *    stays valid for the caller's abort, which must NOT re-PUT. */
    {
        brix_sd_staged_t *h = staged_body(inst, "/xport.bin", "hello");

        CHECK(h != NULL, "sd_http staged_open (transport-fail)");
        if (h != NULL) {
            g_status = 201; g_fail = 1; g_puts = 0; errno = 0;
            CHECK(inst->driver->staged_commit(h, 0) == NGX_ERROR
                      && errno == EIO,
                  "a transport failure must fail the commit with EIO");
            CHECK(g_puts == 1, "one PUT attempted");
            g_fail = 0;
            inst->driver->staged_abort(h);      /* must not UAF / double free */
            CHECK(g_puts == 1, "SECURITY: abort must not re-issue the upload");
        }
    }

    /* C. ORIGIN REFUSAL (security-negative) — 403 is a denial, so it must map to
     *    EACCES and NEVER be laundered into a successful publish; the handle is
     *    still the caller's to abort. */
    {
        brix_sd_staged_t *h = staged_body(inst, "/denied.bin", "hello");

        CHECK(h != NULL, "sd_http staged_open (403)");
        if (h != NULL) {
            g_status = 403; g_fail = 0; g_puts = 0; errno = 0;
            CHECK(inst->driver->staged_commit(h, 0) == NGX_ERROR
                      && errno == EACCES,
                  "SECURITY: a 403 PUT must fail with EACCES, never succeed");
            inst->driver->staged_abort(h);
            CHECK(g_puts == 1, "SECURITY: the denied upload is not retried");
        }
    }

    /* D. sd_cache forwarding — the decorator's staged slots dispatch on
     *    st->inst->driver (the SOURCE driver stamped on the handle), so a
     *    handle opened on the http instance must reach sd_http's own
     *    commit/abort with the failure contract intact. */
    {
        brix_sd_staged_t *h = staged_body(inst, "/forward.bin", "hello");

        CHECK(h != NULL, "sd_http staged_open (forwarded)");
        if (h != NULL) {
            g_status = 500; g_fail = 0; g_puts = 0; errno = 0;
            CHECK(sd_cache_staged_commit(h, 0) == NGX_ERROR,
                  "forwarded commit reports the driver's failure");
            CHECK(g_puts == 1, "the forwarder issues exactly one PUT");
            sd_cache_staged_abort(h);           /* releases the still-valid handle */
        }
    }
    brix_sd_http_destroy(inst);
}

/* ---- sd_xroot: stubbed origin wire ---------------------------------------- */

static int g_sync_rc;          /* brix_cache_origin_sync result               */
static int g_syncs;
static int g_file_closes;
static int g_conn_closes;

int brix_cache_origin_connect(brix_cache_fill_t *t, brix_cache_origin_conn_t *oc)
{
    (void) t;
    oc->fd = 4242;                       /* never a real socket in this test */
    return 0;
}
int brix_cache_origin_bootstrap(brix_cache_fill_t *t, brix_cache_origin_conn_t *oc)
{
    (void) t; (void) oc;
    return 0;
}
int brix_cache_origin_open_write(brix_cache_fill_t *t,
    brix_cache_origin_conn_t *oc, const char *path, uint16_t mode_bits,
    u_char fhandle[XRD_FHANDLE_LEN])
{
    (void) t; (void) oc; (void) path; (void) mode_bits;
    memset(fhandle, 0x5a, XRD_FHANDLE_LEN);
    return 0;
}
int brix_cache_origin_write_chunk(brix_cache_fill_t *t,
    brix_cache_origin_conn_t *oc, const u_char fhandle[XRD_FHANDLE_LEN],
    uint64_t offset, const u_char *data, size_t len)
{
    (void) t; (void) oc; (void) fhandle; (void) offset; (void) data; (void) len;
    return 0;
}
int brix_cache_origin_sync(brix_cache_fill_t *t, brix_cache_origin_conn_t *oc,
    const u_char fhandle[XRD_FHANDLE_LEN])
{
    (void) oc; (void) fhandle;
    g_syncs++;
    if (g_sync_rc != 0) { t->xrd_error = 3006 /* kXR_IOError */; }
    return g_sync_rc;
}
void brix_cache_origin_close_file(brix_cache_origin_conn_t *oc,
    const u_char fhandle[XRD_FHANDLE_LEN])
{
    (void) oc; (void) fhandle;
    g_file_closes++;
}
void brix_cache_origin_close(brix_cache_origin_conn_t *oc)
{
    oc->fd = -1;
    g_conn_closes++;
}
int sd_xroot_errno(const brix_cache_fill_t *t) { (void) t; return EIO; }
void sd_xroot_copy_cred_into_task(brix_cache_fill_t *t,
    const brix_sd_cred_t *cred) { (void) t; (void) cred; }

static void
run_xroot_arms(void)
{
    ngx_stream_brix_srv_conf_t conf;
    sd_xroot_inst_state          is;
    brix_sd_instance_t         inst;

    memset(&conf, 0, sizeof conf);
    memset(&is, 0, sizeof is);
    memset(&inst, 0, sizeof inst);
    is.conf   = &conf;
    inst.state = &is;

    /* E. SYNC FAILURE — the publish (kXR_sync) did not land, so the commit fails
     *    and leaves the handle valid; the caller's abort tears the origin session
     *    down exactly once. Pre-contract this shape was the double-teardown. */
    {
        int                err = 0;
        brix_sd_staged_t *h;

        g_sync_rc = -1;
        g_syncs = g_file_closes = g_conn_closes = 0;
        h = sd_xroot_staged_open(&inst, "/o_fail.bin", 0644, &err);
        CHECK(h != NULL, "sd_xroot staged_open (sync-fail)");
        if (h != NULL) {
            CHECK(sd_xroot_staged_write(h, "hello", 5, 0) == 5,
                  "sd_xroot staged_write");
            CHECK(sd_xroot_staged_commit(h, 0) == NGX_ERROR,
                  "a failed origin sync must fail the commit");
            CHECK(g_file_closes == 0 && g_conn_closes == 0,
                  "a failed commit must not tear the handle down");
            sd_xroot_staged_abort(h);           /* must not UAF / double free */
            CHECK(g_file_closes == 1 && g_conn_closes == 1,
                  "abort closes the origin file + connection exactly once");
        }
    }

    /* F. SUCCESS — sync lands, the handle is consumed (close_file + close) and
     *    must not be aborted afterwards. */
    {
        int                err = 0;
        brix_sd_staged_t *h;

        g_sync_rc = 0;
        g_syncs = g_file_closes = g_conn_closes = 0;
        h = sd_xroot_staged_open(&inst, "/o_ok.bin", 0644, &err);
        CHECK(h != NULL, "sd_xroot staged_open (ok)");
        if (h != NULL) {
            CHECK(sd_xroot_staged_commit(h, 0) == NGX_OK,
                  "a clean origin sync must commit");
            CHECK(g_syncs == 1 && g_file_closes == 1 && g_conn_closes == 1,
                  "one sync, one file close, one connection close");
        }
    }
}

int main(void)
{
    run_http_arms();
    run_xroot_arms();

    if (failures) { fprintf(stderr, "%d check(s) failed\n", failures); return 1; }
    printf("sd_http + sd_xroot + sd_cache staged-commit ownership contract: PASS\n");
    return 0;
}
