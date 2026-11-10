/* Live service driver: pytest owns MinIO and independently checks stored bytes. */
#include "fs/backend/s3/sd_s3.h"
#include "core/compat/crypto.h"
#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* These server-side shared verbs are outside the client archive's subset.
 * Compile their real implementations into this finite consumer as well. */
#include "../../../src/fs/backend/s3/sd_s3_batch.c"
#include "../../../src/fs/backend/s3/sd_s3_archive.c"

extern const brix_s3_transport_t brix_s3_http_transport;

static void
require(int okay, const char *error)
{
    if (!okay) { fprintf(stderr, "%s\n", error); abort(); }
}

static void
read_pattern(const sd_s3_open_params *p, size_t size)
{
    char error[512], bytes[65538];
    int64_t actual;
    sd_s3_file *f = sd_s3_open_read(p, error, sizeof(error));
    require(f != NULL, error);
    require(sd_s3_size(f, &actual, error, sizeof(error)) == 0, error);
    assert(actual == (int64_t) size);
    assert(sd_s3_size(f, &actual, error, sizeof(error)) == 0);
    for (size_t offset = 0; offset < size; offset += 65536) {
        size_t want = size - offset < 65536 ? size - offset : 65536;
        memset(bytes, 0x5a, sizeof(bytes));
        require(sd_s3_pread(f, bytes + 1, 65536, offset, error, sizeof(error)) == (ssize_t) want, error);
        assert(bytes[0] == 0x5a && bytes[want + 1] == 0x5a);
        for (size_t i = 0; i < want; i++) { assert((unsigned char) bytes[i + 1] == (offset + i) % 251); }
    }
    assert(sd_s3_pread(f, bytes, sizeof(bytes), size, error, sizeof(error)) == 0);
    assert(sd_s3_pread(f, bytes, 0, 0, error, sizeof(error)) == 0);
    assert(sd_s3_commit(f, error, sizeof(error)) == 0);
    assert(sd_s3_pwrite(f, "x", 1, 0, error, sizeof(error)) == -1);
    assert(sd_s3_set_publish_cond(f, "if-none-match", "*") == -1);
    sd_s3_abort(f);
    sd_s3_close(f);
}

static void
write_pattern(const sd_s3_open_params *p, size_t size, int64_t known, const char *action)
{
    char error[512], bytes[1000003];
    sd_s3_file *f = sd_s3_open_write(p, known, 5 * 1024 * 1024, error, sizeof(error));
    require(f != NULL, error);
    for (size_t offset = 0; offset < size; offset += sizeof(bytes)) {
        size_t n = size - offset < sizeof(bytes) ? size - offset : sizeof(bytes);
        for (size_t i = 0; i < n; i++) { bytes[i] = (char) ((offset + i) % 251); }
        require(sd_s3_pwrite(f, bytes, n, offset, error, sizeof(error)) == 0, error);
        assert(sd_s3_write_size(f) == (int64_t) (offset + n));
    }
    assert(sd_s3_pwrite(f, "x", 1, size + 1, error, sizeof(error)) == -1 && errno == EINVAL);
    assert(sd_s3_write_size(f) == (int64_t) size);
    if (!strcmp(action, "abort")) { sd_s3_abort(f); sd_s3_close(f); return; }
    if (!strcmp(action, "conditional")) {
        assert(sd_s3_set_publish_cond(f, "if-none-match", "*") == 0);
        assert(sd_s3_commit(f, error, sizeof(error)) == -1 && errno == ECANCELED);
        sd_s3_abort(f); sd_s3_close(f); return;
    }
    require(sd_s3_commit(f, error, sizeof(error)) == 0, error);
    sd_s3_close(f);
    read_pattern(p, size);
}

static void
check_metadata(const sd_s3_open_params *p)
{
    char error[512], value[512], names[512];
    sd_s3_meta_buf out = {value, sizeof(value)};
    sd_s3_meta_kv pairs[] = {{"MiXeD", "value"}, {"another", "second"}};
    sd_s3_file *f = sd_s3_open_read(p, error, sizeof(error));
    brix_meta_advisory_t advisory = {0}, actual = {0};
    require(f != NULL, error);
    assert(sd_s3_get_meta(f, "absent", &out, error, sizeof(error)) == 0);
    assert(sd_s3_get_unixattr(f, &actual, error, sizeof(error)) == 0);
    require(sd_s3_set_meta(p, pairs, 2, error, sizeof(error)) == 0, error);
    assert(sd_s3_get_meta(f, "mixed", &out, error, sizeof(error)) == 5);
    assert(!strcmp(value, "value"));
    ssize_t n = sd_s3_list_meta(f, NULL, 0, error, sizeof(error));
    assert(n == (ssize_t) (sizeof("user.mixed") + sizeof("user.another")));
    assert(sd_s3_list_meta(f, names, sizeof(names), error, sizeof(error)) == n);
    assert(sd_s3_list_meta(f, names, 1, error, sizeof(error)) == -1 && errno == ERANGE);
    assert(sd_s3_get_checksum(f, "ETag", &out, error, sizeof(error)) > 0);
    advisory.have_mode = 1; advisory.mode = 0640;
    advisory.have_owner = 1; advisory.uid = 123; advisory.gid = 456;
    require(sd_s3_set_unixattr(p, &advisory, error, sizeof(error)) == 0, error);
    assert(sd_s3_get_unixattr(f, &actual, error, sizeof(error)) == 1);
    assert(actual.have_owner && actual.uid == 123 && actual.gid == 456);
    assert(actual.have_mode && actual.mode == 0640);
    assert(sd_s3_list_meta(f, names, sizeof(names), error, sizeof(error)) == 0);
    sd_s3_close(f);
}

static void
check_archive(const sd_s3_open_params *p)
{
    char error[512], storage[64] = "sentinel", restore[256] = "sentinel", archive[64] = "sentinel";
    sd_s3_meta_buf a = {storage, sizeof(storage)}, b = {restore, sizeof(restore)}, c = {archive, sizeof(archive)};
    sd_s3_archive_buf_t out = {&a, &b, &c};
    sd_s3_file *f = sd_s3_open_read(p, error, sizeof(error));
    require(f != NULL, error);
    require(sd_s3_archive_state(f, &out, error, sizeof(error)) == 0, error);
    assert(!storage[0] && !restore[0] && !archive[0]);
    assert(sd_s3_archive_state(f, NULL, error, sizeof(error)) == -1);
    assert(sd_s3_archive_state(NULL, &out, error, sizeof(error)) == -1);
    assert(sd_s3_restore(NULL, 1, error, sizeof(error)) == -1 && errno == EINVAL);
    assert(sd_s3_restore(p, 0, error, sizeof(error)) == -1);
    sd_s3_close(f);
}

static void
check_batch(const sd_s3_open_params *p, int denied)
{
    const char *keys[] = {"plain", "escaped&<>'\"", "missing"};
    int errors[] = {ECANCELED, ECANCELED, ECANCELED};
    size_t done = 99;
    char error[512];
    assert(sd_s3_delete_many(p, NULL, 0, errors, &done, error, sizeof(error)) == 0 && done == 0);
    int rc = sd_s3_delete_many(p, keys, 3, errors, &done, error, sizeof(error));
    if (denied) {
        assert(rc == -1 && errno == EACCES && done == 0);
        assert(errors[0] == ECANCELED && errors[1] == ECANCELED && errors[2] == ECANCELED);
        return;
    }
    require(rc == 0, error);
    assert(done == 3 && errors[0] == 0 && errors[1] == 0 && errors[2] == 0);
}

static void
check_denied(sd_s3_open_params *p)
{
    char error[512], value[64];
    int64_t size;
    sd_s3_meta_buf out = {value, sizeof(value)};
    p->sk = "deliberately-invalid-fixture-secret";
    sd_s3_file *f = sd_s3_open_read(p, error, sizeof(error));
    require(f != NULL, error);
    assert(sd_s3_size(f, &size, error, sizeof(error)) == -1 && errno == EACCES);
    assert(sd_s3_get_meta(f, "anything", &out, error, sizeof(error)) == -1 && errno == EACCES);
    assert(sd_s3_list_meta(f, value, sizeof(value), error, sizeof(error)) == -1 && errno == EACCES);
    assert(sd_s3_delete(p, error, sizeof(error)) == -1 && errno == EACCES);
    assert(sd_s3_restore(p, 1, error, sizeof(error)) == -1 && errno == EACCES);
    sd_s3_close(f);
}

int
main(int argc, char **argv)
{
    assert(argc == 8);
    assert(brix_crypto_init());
    sd_s3_open_params p = {.host = argv[1], .port = atoi(argv[2]), .key = argv[3],
        .ak = getenv("BRIX_TEST_S3_AK"), .sk = getenv("BRIX_TEST_S3_SK"),
        .region = "us-east-1", .transport = &brix_s3_http_transport,
        .timeout_ms = 10000, .put_checksum = atoi(argv[7])};
    size_t size = (size_t) strtoull(argv[5], NULL, 10);
    if (!strcmp(argv[4], "metadata")) { check_metadata(&p); }
    else if (!strcmp(argv[4], "archive")) { check_archive(&p); }
    else if (!strcmp(argv[4], "batch")) { check_batch(&p, 0); }
    else if (!strcmp(argv[4], "batch-denied")) { p.sk = "invalid-fixture-secret"; check_batch(&p, 1); }
    else if (!strcmp(argv[4], "denied")) { check_denied(&p); }
    else { write_pattern(&p, size, strtoll(argv[6], NULL, 10), argv[4]); }
    puts("S3 native contract: PASS");
    return 0;
}
