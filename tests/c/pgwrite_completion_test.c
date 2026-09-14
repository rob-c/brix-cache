/* Exercise the real synchronous pgwrite orchestration and extracted helpers.
 * Only storage completion, logging, bandwidth charging and response transports
 * are replaced here; the Fob, journal and dirty-state accounting stay real.
 * Including the orchestrator keeps its internal entry point private to its TU.
 */
#include "../../src/protocols/root/write/pgwrite.c"
#include <assert.h>

typedef struct {
    ssize_t result;
    int error;
} test_io_t;

typedef struct {
    brix_ctx_t ctx;
    brix_file_t files[3];
    ngx_connection_t connection;
    ngx_stream_brix_srv_conf_t conf;
    ngx_brix_srv_metrics_t metrics;
    pgw_state_t state;
    test_io_t io;
    size_t charged;
    size_t reply_bad_count;
    int64_t reply_offset;
    int error_sent;
    int log_count;
    char detail[64];
} test_case_t;

/* WHAT: Supply the requested storage outcome without real I/O.
 * WHY: Full and failed writes must exercise the same orchestration.
 * HOW: 1. Check job shape. 2. Copy the fixture's result into the job. */
void
brix_vfs_io_execute(brix_vfs_job_t *job)
{
    const test_io_t *io = (const test_io_t *) job->buf;

    assert(job->op == BRIX_VFS_IO_WRITE);
    assert(job->fd == 37 && job->offset == 1024 && job->length == 512);
    job->nio = io->result;
    job->io_errno = io->error;
}

/* WHAT: Capture charged bytes. WHY: Assert accounting exactly once.
 * HOW: 1. Recover the fixture through its first member. 2. Accumulate. */
void
brix_rl_charge_ctx(brix_ctx_t *ctx, size_t nbytes)
{
    test_case_t *test = (test_case_t *) ctx;
    test->charged += nbytes;
}

/* WHAT: Capture access detail. WHY: Assert the error triplet precedes send.
 * HOW: 1. Count the event. 2. Retain the formatted range. */
void
brix_log_access(brix_ctx_t *ctx, ngx_connection_t *connection,
    const char *verb, const char *path, const char *detail, ngx_uint_t ok,
    uint16_t errcode, const char *message, size_t bytes)
{
    test_case_t *test = (test_case_t *) ctx;
    test->log_count++;
    snprintf(test->detail, sizeof(test->detail), "%s", detail);
}

/* WHAT: Observe an error response. WHY: A failed write cannot report success.
 * HOW: 1. Check log and metric ordering. 2. Record the response. */
ngx_int_t
brix_send_error(brix_ctx_t *ctx, ngx_connection_t *connection,
    uint16_t errcode, const char *message)
{
    test_case_t *test = (test_case_t *) ctx;
    assert(test->log_count == 1);
    assert(test->metrics.op_err[BRIX_OP_WRITE] == 1);
    assert(errcode == kXR_IOError && message[0] != '\0');
    test->error_sent++;
    return NGX_DONE;
}

/* WHAT: Capture normal status routing. WHY: The reply must echo request offset.
 * HOW: 1. Record the offset. 2. Return an observable transport status. */
ngx_int_t
brix_send_pgwrite_status(brix_ctx_t *ctx, ngx_connection_t *connection,
    int64_t offset)
{
    test_case_t *test = (test_case_t *) ctx;
    test->reply_offset = offset;
    return NGX_AGAIN;
}

/* WHAT: Capture checksum-error status routing. WHY: Preserve correction data.
 * HOW: 1. Check the original bad-page array. 2. Record count and offset. */
ngx_int_t
brix_send_pgwrite_cse(brix_ctx_t *ctx, ngx_connection_t *connection,
    int64_t offset, const xrdp_pg_bad_t *bad, size_t count)
{
    test_case_t *test = (test_case_t *) ctx;
    assert(bad == test->state.bad_pages);
    test->reply_offset = offset;
    test->reply_bad_count = count;
    return NGX_AGAIN;
}

/* WHAT: Initialize a nonzero-handle retry. WHY: Catch accidental handle-zero use.
 * HOW: 1. Allocate explicit state. 2. Enable real dirty, Fob and journal state. */
static test_case_t *
new_test(void)
{
    test_case_t *test = calloc(1, sizeof(*test));
    assert(test != NULL);
    test->ctx.files = test->files;
    test->ctx.metrics = &test->metrics;
    test->state.rconf = &test->conf;
    test->state.idx = 2;
    test->state.offset = 1024;
    test->state.flat_sz = 512;
    test->state.flat = (u_char *) &test->io;
    test->state.is_retry = 1;
    test->io.result = 512;
    test->ctx.files[2].fd = 37;
    test->ctx.files[2].wt_enabled = 1;
    test->ctx.files[2].wt_dirty_offset = -1;
    brix_pgw_fob_open(&test->ctx.files[2]);
    assert(brix_pgw_fob_add(&test->ctx.files[2], 1024, 512));
    brix_wrts_open(&test->ctx.files[2]);
    return test;
}

/* WHAT: Check a completed clean retry. WHY: Preserve per-handle state and range.
 * HOW: 1. Execute the real orchestrator. 2. Assert accounting and status. */
static void
test_success(void)
{
    test_case_t *test = new_test();
    ngx_int_t rc = NGX_ERROR;
    assert(pgwrite_execute_sync(&test->ctx, &test->connection,
                                &test->state, &rc) == 1);
    assert(rc == NGX_AGAIN && test->error_sent == 0);
    assert(test->ctx.files[0].bytes_written == 0);
    assert(test->ctx.files[2].bytes_written == 512);
    assert(test->ctx.totals.bytes_written == 512 && test->charged == 512);
    assert(test->ctx.files[2].wt_dirty_offset == 1535);
    assert(test->ctx.files[2].wt_bytes_written == 512);
    assert(test->metrics.wt_dirty_handles == 1);
    assert(test->metrics.op_ok[BRIX_OP_WRITE] == 1);
    assert(!brix_pgw_fob_has(&test->ctx.files[2], 1024, 512));
    assert(brix_wrts_is_replay(&test->ctx.files[2], 1024, 512));
    assert(test->reply_offset == 1024 && test->reply_bad_count == 0);
    assert(strcmp(test->detail, "1024+512") == 0);
    free(test);
}

/* WHAT: Check failed and short writes. WHY: Neither may clear integrity state.
 * HOW: 1. Inject the storage result. 2. Assert error ordering and unchanged state. */
static void
test_error(ssize_t written, const char *detail)
{
    test_case_t *test = new_test();
    ngx_int_t rc = NGX_ERROR;
    test->io.result = written;
    test->io.error = EIO;
    assert(pgwrite_execute_sync(&test->ctx, &test->connection,
                                &test->state, &rc) == 1);
    assert(rc == NGX_DONE && test->error_sent == 1);
    assert(test->ctx.totals.bytes_written == 0 && test->charged == 0);
    assert(test->ctx.files[2].wt_dirty_offset == -1);
    assert(test->ctx.files[2].wrts_count == 0);
    assert(brix_pgw_fob_has(&test->ctx.files[2], 1024, 512));
    assert(test->metrics.op_ok[BRIX_OP_WRITE] == 0);
    assert(strcmp(test->detail, detail) == 0);
    free(test);
}

/* WHAT: Retain a still-corrupt retry in the Fob. WHY: Close must remain gated.
 * HOW: 1. Supply a remaining bad-page entry. 2. Assert CSE routing and Fob state. */
static void
test_uncorrected_retry(void)
{
    test_case_t *test = new_test();
    ngx_int_t rc = NGX_ERROR;
    test->state.bad_count = 1;
    test->state.bad_pages[0].off = 1024;
    test->state.bad_pages[0].dlen = 512;
    assert(pgwrite_execute_sync(&test->ctx, &test->connection,
                                &test->state, &rc) == 1);
    assert(rc == NGX_AGAIN && test->error_sent == 0);
    assert(brix_pgw_fob_has(&test->ctx.files[2], 1024, 512));
    assert(test->reply_offset == 1024 && test->reply_bad_count == 1);
    free(test);
}

/* WHAT: Run one regression group. WHY: Expose independent pytest outcomes.
 * HOW: 1. Select the named test. 2. Return success only after assertions pass. */
int
main(int argc, char **argv)
{
    assert(argc == 2);
    if (strcmp(argv[1], "success") == 0) {
        test_success();
        return 0;
    }
    if (strcmp(argv[1], "error") == 0) {
        test_error(-1, "1024+512");
        test_error(128, "1024+128");
        return 0;
    }
    assert(strcmp(argv[1], "uncorrected-retry") == 0);
    test_uncorrected_retry();
    return 0;
}
