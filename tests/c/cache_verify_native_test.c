/* Real staged-file verification and quarantine before cache publication. */
#include "core/ngx_brix_module.h"
#include "fs/cache/cache_internal.h"
#include "fs/cache/verify.h"
#include <assert.h>

typedef struct { unsigned char before; char text[129]; unsigned char after; } guarded_text;

/* WHAT: Dispatch content-addressed verification. WHY: Each key grammar chooses its digest.
 * HOW: Call the production verifier for the explicit family. */
static brix_cache_verify_result_e verify_key(const char *family, const char *path,
    const char *key, ngx_log_t *log, char *algorithm, char *digest)
{
    if (!strcmp(family, "cvmfs")) { return brix_cache_verify_cvmfs_cas(path, key, log, algorithm, digest); }
    if (!strcmp(family, "oci")) { return brix_cache_verify_oci_digest(path, key, log, algorithm, digest); }
    assert(!strcmp(family, "rpm"));
    return brix_cache_verify_rpm_repodata(path, key, log, algorithm, digest);
}

/* WHAT: Verify an origin-advertised digest. WHY: Required integrity may not be bypassed.
 * HOW: Build the finite origin record and inspect the actual fill error fields. */
static brix_cache_verify_result_e verify_origin(const char *path, const char *algorithm,
    const char *hex, int mode, ngx_log_t *log, char *out_alg, char *out_hex)
{
    brix_cache_fill_t task = {0}; ngx_connection_t connection = {0}; connection.log = log;
    task.c = &connection; brix_cache_digest_t origin = {0};
    snprintf(origin.alg, sizeof(origin.alg), "%s", algorithm);
    snprintf(origin.hex, sizeof(origin.hex), "%s", hex);
    const brix_cache_digest_t *digest = !strcmp(algorithm, "null") ? NULL : &origin;
    brix_cache_verify_result_e result = brix_cache_verify_part(&task, path, digest,
        (brix_cache_verify_mode_e) mode, out_alg, out_hex);
    if (result == BRIX_CACHE_VERIFY_ERROR || result == BRIX_CACHE_VERIFY_MISMATCH) {
        assert(task.result == NGX_ERROR && task.err_msg[0]);
        assert(task.xrd_error == kXR_IOError || task.xrd_error == kXR_ChkSumErr);
    } else { assert(task.result == 0 && task.xrd_error == 0); }
    printf("error=%d errno=%d\n", task.xrd_error, task.sys_errno);
    return result;
}

/* WHAT: Exercise quarantine cleanup. WHY: A corrupt part must never remain publishable.
 * HOW: Select a real destination or refusal and check that the original name disappears. */
static void quarantine(const char *path, const char *target, ngx_log_t *log)
{
    char oversized[PATH_MAX + 1]; memset(oversized, 'q', sizeof(oversized) - 1);
    oversized[sizeof(oversized) - 1] = 0;
    const char *directory = !strcmp(target, "null") ? NULL : target;
    if (!strcmp(target, "oversized")) { directory = oversized; }
    brix_cache_quarantine_part(path, directory, log);
    assert(access(path, F_OK) == -1 && errno == ENOENT);
    puts("quarantined");
}

/* WHAT: Run one verifier contract. WHY: Only successful verification may populate outputs.
 * HOW: Guard output buffers, use an owned log fd, and report the real verdict. */
int main(int argc, char **argv)
{
    assert(argc == 10); const char *family = argv[1], *path = argv[2];
    ngx_log_t log = {0}; ngx_open_file_t logfile = {0};
    logfile.fd = open(argv[9], O_WRONLY | O_CREAT | O_EXCL, 0600); assert(logfile.fd >= 0);
    log.file = &logfile; log.log_level = NGX_LOG_DEBUG;
    ngx_cycle_t cycle = {0}; cycle.log = &log; ngx_cycle = &cycle;
    ngx_time_init(); assert(ngx_strerror_init() == NGX_OK); ngx_pid = getpid();
    ngx_log_t *selected_log = atoi(argv[7]) ? &log : NULL;
    if (!strcmp(family, "quarantine")) { quarantine(path, argv[3], selected_log); }
    else {
        guarded_text algorithm, digest; memset(&algorithm, 0x51, sizeof(algorithm));
        memset(&digest, 0x51, sizeof(digest));
        int outputs = atoi(argv[8]);
        char *out_alg = outputs ? algorithm.text : NULL, *out_hex = outputs ? digest.text : NULL;
        brix_cache_verify_result_e result;
        if (!strcmp(family, "part")) {
            result = verify_origin(path, argv[3], argv[4], atoi(argv[5]), selected_log, out_alg, out_hex);
        } else { result = verify_key(family, path, argv[3], selected_log, out_alg, out_hex); }
        assert((int) result == atoi(argv[6]));
        assert(algorithm.before == 0x51 && algorithm.after == 0x51);
        assert(digest.before == 0x51 && digest.after == 0x51);
        if (result == BRIX_CACHE_VERIFY_VERIFIED && outputs) {
            assert(memchr(algorithm.text, 0, 16) && memchr(digest.text, 0, 129));
            printf("algorithm=%s\ndigest=%s\n", algorithm.text, digest.text);
        } else { assert(algorithm.text[0] == 0x51 && digest.text[0] == 0x51); }
        printf("verdict=%d\n", result);
    }
    assert(close(logfile.fd) == 0); return 0;
}
