/* Durable stage-request contracts over real journal records and file locks. */
#include "fs/xfer/stage_request_registry_internal.h"
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>

typedef struct {
    const char *fault;
    unsigned locks, unlocks;
    brix_stage_registry_t *registry;
    ngx_log_t log;
    char ids[3][BRIX_STAGE_REQID_LEN];
} fixture;

/* WHAT: Retrieve scoped faults. WHY: The registry's real lock and I/O stay in production.
 * HOW: Decode the pointer installed by this process's main. */
static fixture *state(void)
{
    void *pointer = NULL; const char *text = getenv("BRIX_STAGE_REGISTRY_FIXTURE");
    if (text) { assert(sscanf(text, "%p", &pointer) == 1); }
    return pointer;
}

/* WHAT: Select a fault. WHY: Preparation and post-failure verification must use normal operations.
 * HOW: Match the one active boundary label. */
static int fault(const char *name)
{
    fixture *f = state(); return f && f->fault && !strcmp(f->fault, name);
}

ngx_int_t __real_srq_lock(brix_stage_registry_t *, srq_lock_t);
void __real_srq_unlock(brix_stage_registry_t *);
ngx_int_t __real_srq_hdr_read(brix_stage_registry_t *, srq_hdr_t *, ngx_log_t *);
ngx_int_t __real_srq_hdr_write(brix_stage_registry_t *, srq_hdr_t *, ngx_log_t *);
ngx_int_t __real_srq_rec_read(brix_stage_registry_t *, int64_t, srq_rec_t *, ngx_log_t *);
ngx_int_t __real_srq_rec_write(brix_stage_registry_t *, int64_t, srq_rec_t *, ngx_log_t *);
int64_t __real_srq_alloc_slot(brix_stage_registry_t *, ngx_log_t *);

/* WHAT: Acquire or refuse the actual store lock. WHY: Error paths must retain no mutex ownership.
 * HOW: Count only successful production acquisitions. */
ngx_int_t __wrap_srq_lock(brix_stage_registry_t *registry, srq_lock_t kind)
{
    if (fault("lock")) { errno = EACCES; return NGX_ERROR; }
    ngx_int_t rc = __real_srq_lock(registry, kind);
    if (rc == NGX_OK) { state()->locks++; }
    return rc;
}

/* WHAT: Observe store unlock. WHY: Every early return must release its ownership.
 * HOW: Count and execute the real mutex/file unlock. */
void __wrap_srq_unlock(brix_stage_registry_t *registry)
{
    state()->unlocks++; assert(state()->unlocks <= state()->locks);
    __real_srq_unlock(registry);
}

/* WHAT: Refuse header reads. WHY: Sequence allocation cannot continue from an unreadable header.
 * HOW: Return a finite I/O failure before the real CRC-checked reader. */
ngx_int_t __wrap_srq_hdr_read(brix_stage_registry_t *registry, srq_hdr_t *header, ngx_log_t *log)
{
    if (fault("header-read")) { errno = EIO; return NGX_ERROR; }
    return __real_srq_hdr_read(registry, header, log);
}

/* WHAT: Refuse the sequence commit. WHY: A failed durable commit must reach the caller.
 * HOW: Fail before modifying the header, retaining real record writes. */
ngx_int_t __wrap_srq_hdr_write(brix_stage_registry_t *registry, srq_hdr_t *header, ngx_log_t *log)
{
    if (fault("header-write")) { errno = ENOSPC; return NGX_ERROR; }
    return __real_srq_hdr_write(registry, header, log);
}

/* WHAT: Refuse a record read. WHY: Enumerations must unwind their shared locks on I/O failure.
 * HOW: Retain the real reader except at the explicitly armed boundary. */
ngx_int_t __wrap_srq_rec_read(brix_stage_registry_t *registry, int64_t offset,
                             srq_rec_t *record, ngx_log_t *log)
{
    if (fault("record-read")) { errno = EIO; return NGX_ERROR; }
    return __real_srq_rec_read(registry, offset, record, log);
}

/* WHAT: Refuse a record write. WHY: Failed status changes must preserve the old durable record.
 * HOW: Stop before the real CRC update and data sync. */
ngx_int_t __wrap_srq_rec_write(brix_stage_registry_t *registry, int64_t offset,
                              srq_rec_t *record, ngx_log_t *log)
{
    if (fault("record-write")) { errno = ENOSPC; return NGX_ERROR; }
    return __real_srq_rec_write(registry, offset, record, log);
}

/* WHAT: Refuse slot allocation. WHY: A full store cannot silently admit a request.
 * HOW: Keep all other scanning and ownership behavior real. */
int64_t __wrap_srq_alloc_slot(brix_stage_registry_t *registry, ngx_log_t *log)
{
    if (fault("slot")) { errno = ENOSPC; return -1; }
    return __real_srq_alloc_slot(registry, log);
}

/* WHAT: Admit one known request. WHY: Record contents and sequence identity need independent assertions.
 * HOW: Supply every optional field and read its stored public view. */
static void add_request(fixture *f, unsigned index, int64_t expiry)
{
    brix_stage_request_view_t input = {.lfn = "/data/same", .requester_dn = "owner.example",
        .user = "reader", .cs_type = BRIX_STAGE_CS_SHA2, .cs_value = "aabbccdd", .tod_expire = expiry};
    assert(brix_stage_request_add(f->registry, &input, f->ids[index], sizeof(f->ids[index]), &f->log) == NGX_OK);
    brix_stage_request_t output;
    assert(brix_stage_request_get(f->registry, f->ids[index], &output, &f->log) == NGX_OK);
    assert(!strcmp(output.lfn, input.lfn) && !strcmp(output.requester_dn, input.requester_dn));
    assert(output.cs_type == input.cs_type && output.status == BRIX_STAGE_REQ_QUEUED);
    assert(output.tod_expire == expiry);
}

/* WHAT: Invoke one faulted public operation. WHY: Each owner must report its own failure semantics.
 * HOW: Use the real seeded journal, returning the API's status for the caller to verify. */
static ngx_int_t invoke(fixture *f, const char *operation)
{
    brix_stage_registry_t *r = f->registry; char id[BRIX_STAGE_REQID_LEN];
    brix_stage_request_t output; ngx_uint_t cursor = 0;
    if (!strcmp(operation, "mint")) { return brix_stage_request_reqid_generate(r, id, sizeof(id), &f->log); }
    if (!strcmp(operation, "get")) { return brix_stage_request_get(r, f->ids[0], &output, &f->log); }
    if (!strcmp(operation, "find")) { return brix_stage_request_find_by_path(r, "/data/same", id, sizeof(id), &f->log); }
    if (!strcmp(operation, "list")) { return brix_stage_request_list_active(r, &cursor, &output, &f->log); }
    if (!strcmp(operation, "status")) { return brix_stage_request_set_status(r, f->ids[0], BRIX_STAGE_REQ_DONE, &f->log); }
    if (!strcmp(operation, "delete")) { return brix_stage_request_delete(r, f->ids[0], &f->log); }
    if (!strcmp(operation, "reap")) { return (ngx_int_t) brix_stage_request_reap_expired(r, 20, &f->log); }
    assert(!strcmp(operation, "add")); brix_stage_request_view_t input = {.lfn = "/new"};
    return brix_stage_request_add(r, &input, id, sizeof(id), &f->log);
}

/* WHAT: Check failed operation ownership. WHY: Lock leaks and damage to existing records outlive one request.
 * HOW: Inject a boundary, require the documented return and reread the original record. */
static void check_failure(fixture *f, const char *operation, const char *boundary, int expected)
{
    add_request(f, 0, 10); f->fault = boundary;
    assert(invoke(f, operation) == expected); f->fault = NULL;
    assert(f->locks == f->unlocks);
    brix_stage_request_t record;
    assert(brix_stage_request_get(f->registry, f->ids[0], &record, &f->log) == NGX_OK);
    assert(record.status == BRIX_STAGE_REQ_QUEUED && !strcmp(record.lfn, "/data/same"));
}

/* WHAT: Enumerate a known durable set. WHY: Cursor progress and per-id file lists must terminate.
 * HOW: Read every live slot once and compare request identities before terminal transitions. */
static void check_lists(fixture *f)
{
    ngx_uint_t cursor = 0; brix_stage_request_t record;
    for (unsigned i = 0; i < 3; i++) {
        assert(brix_stage_request_list_active(f->registry, &cursor, &record, &f->log) == NGX_OK);
        assert(!strcmp(record.reqid, f->ids[i]));
    }
    assert(brix_stage_request_list_active(f->registry, &cursor, &record, &f->log) == NGX_DONE);
    cursor = 0;
    assert(brix_stage_request_list_files(f->registry, f->ids[0], &cursor, &record, &f->log) == NGX_OK);
    assert(brix_stage_request_list_files(f->registry, f->ids[0], &cursor, &record, &f->log) == NGX_DONE);
}

/* WHAT: Preserve request identity through status, release and expiry.
 * WHY: Reaping must respect exact boundaries and never remove a nonexpiring request.
 * HOW: Exercise sequence minting, owner refusal, cursor queries and durable slot reuse. */
static void check_lifecycle(fixture *f)
{
    char minted[BRIX_STAGE_REQID_LEN], found[BRIX_STAGE_REQID_LEN];
    assert(brix_stage_request_reqid_generate(f->registry, minted, sizeof(minted), &f->log) == NGX_OK);
    for (unsigned i = 0; i < 3; i++) { add_request(f, i, i == 2 ? 0 : 10 + i); }
    assert(strcmp(minted, f->ids[0]) && strcmp(f->ids[0], f->ids[1])); check_lists(f);
    assert(brix_stage_request_find_by_path(f->registry, "/data/same", found, sizeof(found), &f->log) == NGX_OK);
    assert(!strcmp(found, f->ids[2]));
    assert(brix_stage_request_owner_check(f->registry, f->ids[0], "other.example", &f->log) == NGX_DECLINED);
    assert(brix_stage_request_owner_check(f->registry, f->ids[0], "owner.example", &f->log) == NGX_OK);
    assert(brix_stage_request_pin_release(f->registry, "/data/same", &f->log) == NGX_OK);
    assert(brix_stage_request_pin_release(f->registry, "/absent", &f->log) == NGX_DECLINED);
    assert(brix_stage_request_set_status(f->registry, f->ids[0], BRIX_STAGE_REQ_ACTIVE, &f->log) == NGX_OK);
    assert(brix_stage_request_set_status(f->registry, f->ids[0], BRIX_STAGE_REQ_DONE, &f->log) == NGX_OK);
    assert(brix_stage_request_reap_expired(f->registry, 9, &f->log) == 0);
    assert(brix_stage_request_reap_expired(f->registry, 10, &f->log) == 1);
    assert(brix_stage_request_reap_expired(f->registry, 11, &f->log) == 1);
    brix_stage_request_t record;
    assert(brix_stage_request_get(f->registry, f->ids[2], &record, &f->log) == NGX_OK);
    assert(record.status == BRIX_STAGE_REQ_CANCELLED);
    assert(brix_stage_request_delete(f->registry, f->ids[2], &f->log) == NGX_OK);
    assert(brix_stage_request_delete(f->registry, f->ids[2], &f->log) == NGX_OK);
    assert(brix_stage_request_cancel(f->registry, f->ids[2], &f->log) == NGX_OK);
    int64_t previous_size = srq_file_size(f->registry); add_request(f, 0, 0);
    assert(srq_file_size(f->registry) == previous_size);
}

/* WHAT: Reject malformed inputs before locking. WHY: Invalid caller pointers or widths cannot touch storage.
 * HOW: Exercise mint/add/list guards and require unchanged ownership counters. */
static void check_invalid(fixture *f)
{
    char id[BRIX_STAGE_REQID_LEN], long_name[SRQ_LFN_LEN + 1]; brix_stage_request_t output;
    memset(long_name, 'x', sizeof(long_name) - 1); long_name[sizeof(long_name) - 1] = 0;
    brix_stage_request_view_t input = {.lfn = long_name}; unsigned before = f->locks;
    assert(brix_stage_request_reqid_generate(NULL, id, sizeof(id), &f->log) == NGX_ERROR);
    assert(brix_stage_request_reqid_generate(f->registry, id, 1, &f->log) == NGX_ERROR);
    assert(brix_stage_request_add(f->registry, &input, id, sizeof(id), &f->log) == NGX_ERROR);
    assert(brix_stage_request_add(f->registry, NULL, id, sizeof(id), &f->log) == NGX_ERROR);
    assert(brix_stage_request_get(f->registry, NULL, &output, &f->log) == NGX_ERROR);
    assert(brix_stage_request_list_active(f->registry, NULL, &output, &f->log) == NGX_ERROR);
    assert(brix_stage_request_list_files(f->registry, "unused", NULL, &output, &f->log) == NGX_ERROR);
    assert(brix_stage_request_reap_expired(NULL, 1, &f->log) == 0);
    assert(brix_stage_request_pin_release(NULL, "/a", &f->log) == NGX_ERROR);
    assert(f->locks == before);
}

/* WHAT: Run one durable registry scenario. WHY: File-backed state is isolated per process and directory.
 * HOW: Initialize nginx logging, create the real registry, execute and close its owned descriptors. */
int main(int argc, char **argv)
{
    assert(argc == 5); fixture f = {0}; char pointer[64];
    ngx_open_file_t output = {.fd = STDERR_FILENO}; f.log.file = &output;
    ngx_time_init(); assert(ngx_strerror_init() == NGX_OK); ngx_pid = getpid();
    snprintf(pointer, sizeof(pointer), "%p", (void *) &f);
    assert(setenv("BRIX_STAGE_REGISTRY_FIXTURE", pointer, 1) == 0);
    assert(brix_stage_registry_init(argv[1], &f.log) == NGX_OK);
    f.registry = brix_stage_registry_singleton(); assert(f.registry);
    if (!strcmp(argv[2], "lifecycle")) { check_lifecycle(&f); }
    else if (!strcmp(argv[2], "invalid")) { check_invalid(&f); }
    else { check_failure(&f, argv[2], argv[3], atoi(argv[4])); }
    assert(f.locks == f.unlocks); assert(close(f.registry->fd) == 0);
    assert(close(f.registry->lock_fd) == 0); f.registry->fd = f.registry->lock_fd = -1;
    assert(unsetenv("BRIX_STAGE_REGISTRY_FIXTURE") == 0);
    puts("stage registry ownership verified"); return 0;
}
