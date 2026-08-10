/*
 * test_tmp_reap.c — unit tests for the POSC crash-orphan reaper policy
 * (src/core/compat/tmp_path.c), parity audit §1.9 (ofs.persist analog).
 *
 * Links against the real compiled tmp_path.o.  That object references three
 * non-libc symbols the reaper path never exercises (brix_sha256 / brix_hex_encode
 * feed only brix_make_resume_path; ngx_log_error_core sits behind a `log != NULL`
 * guard and we pass NULL) — stub them so the link resolves.  The reaper itself
 * uses only libc (nftw/kill/unlink/stat/utimes), so its behaviour is fully
 * exercisable with no running server.
 *
 * Build/run via cmdscripts/c_object_units.py (SPECS["tmp_reap"]), surfaced by
 * tests/test_posc_persist.py.
 */
#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

/* ---- ngx shims + reaper prototypes (mirror src/core/compat/tmp_path.h) ---- */
typedef intptr_t  ngx_int_t;
typedef uintptr_t ngx_uint_t;
typedef struct ngx_log_s ngx_log_t;   /* opaque; we only ever pass NULL */

#define BRIX_POSC_PERSIST_AUTO    0
#define BRIX_POSC_PERSIST_MANUAL  1
#define BRIX_POSC_PERSIST_OFF     2

void       brix_tmp_reap_set_policy(int mode, time_t hold_sec);
void       brix_tmp_reap_register(const char *export_root);
ngx_uint_t brix_tmp_reap_all(ngx_log_t *log);

/* ---- link stubs for symbols tmp_path.o names but this test never drives ---- */
int  brix_sha256(const void *d, size_t n, unsigned char *out)
{ (void) d; (void) n; (void) out; return 0; }
void brix_hex_encode(const unsigned char *in, size_t n, char *out)
{ (void) in; (void) n; if (out) out[0] = '\0'; }
void ngx_log_error_core(ngx_uint_t level, ngx_log_t *log, ...)
{ (void) level; (void) log; }   /* unreachable in-test (guarded by log != NULL) */

/* ---- tiny assertion harness ---- */
static int g_pass, g_fail;
#define CHECK(cond, msg) do {                                               \
        if (cond) { g_pass++; }                                             \
        else { g_fail++; fprintf(stderr, "FAIL: %s (%s:%d)\n",              \
                                  msg, __FILE__, __LINE__); }               \
    } while (0)

static char g_dir[4096];

static void
mkpath(char *out, size_t osz, const char *name)
{
    snprintf(out, osz, "%s/%s", g_dir, name);
}

/* create an empty file at g_dir/name */
static void
touch_file(const char *name)
{
    char path[4200];
    int  fd;

    mkpath(path, sizeof(path), name);
    fd = open(path, O_CREAT | O_WRONLY | O_TRUNC, 0644);
    if (fd >= 0) {
        (void) write(fd, "x", 1);
        close(fd);
    }
}

static int
exists(const char *name)
{
    char path[4200];

    mkpath(path, sizeof(path), name);
    return access(path, F_OK) == 0;
}

static void
rm_file(const char *name)
{
    char path[4200];

    mkpath(path, sizeof(path), name);
    (void) unlink(path);
}

/* backdate a file's mtime by `age` seconds so the hold-age gate sees it stale */
static void
age_file(const char *name, time_t age)
{
    char           path[4200];
    struct timeval tv[2];
    time_t         when = time(NULL) - age;

    mkpath(path, sizeof(path), name);
    tv[0].tv_sec = when; tv[0].tv_usec = 0;
    tv[1].tv_sec = when; tv[1].tv_usec = 0;
    (void) utimes(path, tv);
}

/* A pid guaranteed dead: fork a child that exits at once, reap it — its pid is
 * now free (no reuse across this short single-threaded test). */
static long
dead_pid(void)
{
    pid_t p = fork();
    if (p == 0) {
        _exit(0);
    }
    if (p > 0) {
        int st;
        (void) waitpid(p, &st, 0);
        return (long) p;
    }
    return 999000;   /* fork failed — fall back to an unlikely-live pid */
}

int
main(void)
{
    char  tmpl[] = "/tmp/brix-tmpreap.XXXXXX";
    char  dead_name[128], live_name[128];
    long  dpid = dead_pid();

    if (mkdtemp(tmpl) == NULL) {
        fprintf(stderr, "mkdtemp failed: %s\n", strerror(errno));
        return 2;
    }
    snprintf(g_dir, sizeof(g_dir), "%s", tmpl);
    brix_tmp_reap_register(g_dir);

    snprintf(dead_name, sizeof(dead_name), "up.bin.xrd-tmp.%ld.4242", dpid);
    snprintf(live_name, sizeof(live_name), "up2.bin.xrd-tmp.%ld.7777",
             (long) getpid());

    /* ---- Test 1: AUTO reaps a dead-owner orphan; keeps a live-owner temp and
     * a non-matching data file (the historical default behaviour). ---- */
    touch_file(dead_name);
    touch_file(live_name);
    touch_file("keep.dat");
    brix_tmp_reap_set_policy(BRIX_POSC_PERSIST_AUTO, 0);
    {
        ngx_uint_t n = brix_tmp_reap_all(NULL);
        CHECK(!exists(dead_name), "AUTO: dead-owner orphan reaped");
        CHECK(exists(live_name),  "AUTO: live-owner in-flight temp kept");
        CHECK(exists("keep.dat"), "AUTO: non-.xrd-tmp file untouched");
        CHECK(n == 1,             "AUTO: exactly one temp reaped");
    }

    /* ---- Test 2: MANUAL keeps the dead-owner orphan for recovery. ---- */
    touch_file(dead_name);
    brix_tmp_reap_set_policy(BRIX_POSC_PERSIST_MANUAL, 0);
    {
        ngx_uint_t n = brix_tmp_reap_all(NULL);
        CHECK(exists(dead_name), "MANUAL: dead-owner orphan kept");
        CHECK(n == 0,            "MANUAL: nothing reaped");
    }

    /* ---- Test 3: OFF also keeps it (no automatic recovery). ---- */
    brix_tmp_reap_set_policy(BRIX_POSC_PERSIST_OFF, 0);
    {
        ngx_uint_t n = brix_tmp_reap_all(NULL);
        CHECK(exists(dead_name), "OFF: dead-owner orphan kept");
        CHECK(n == 0,            "OFF: nothing reaped");
    }

    /* ---- Test 4: AUTO + hold — a FRESH orphan is spared by the grace period;
     * once it ages past the hold it is reaped. ---- */
    /* dead_name currently exists with a fresh mtime */
    brix_tmp_reap_set_policy(BRIX_POSC_PERSIST_AUTO, 3600);
    {
        ngx_uint_t n = brix_tmp_reap_all(NULL);
        CHECK(exists(dead_name), "HOLD: fresh orphan spared during grace");
        CHECK(n == 0,            "HOLD: nothing reaped while fresh");
    }
    age_file(dead_name, 7200);   /* 2h old > 1h hold */
    {
        ngx_uint_t n = brix_tmp_reap_all(NULL);
        CHECK(!exists(dead_name), "HOLD: aged-out orphan reaped past grace");
        CHECK(n == 1,             "HOLD: one reaped once aged");
    }

    /* ---- Test 5 (security-neg): the reaper only ever touches ".xrd-tmp."
     * names — a normal data file and a resume partial (.xrdresume.*.part) are
     * NEVER removed, even under AUTO with no grace. ---- */
    rm_file(live_name);
    rm_file("keep.dat");
    touch_file("payload.dat");
    touch_file("upload.xrdresume.abc123.part");
    brix_tmp_reap_set_policy(BRIX_POSC_PERSIST_AUTO, 0);
    {
        (void) brix_tmp_reap_all(NULL);
        CHECK(exists("payload.dat"),
              "SECNEG: a plain data file is never reaped");
        CHECK(exists("upload.xrdresume.abc123.part"),
              "SECNEG: a resume partial is never reaped by the POSC reaper");
    }

    /* restore the policy to the default for hygiene */
    brix_tmp_reap_set_policy(BRIX_POSC_PERSIST_AUTO, 0);

    printf("test_tmp_reap: %d passed, %d failed\n", g_pass, g_fail);
    return g_fail == 0 ? 0 : 1;
}
