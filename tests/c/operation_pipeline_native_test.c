/* Client pipeline limits, failure ordering and allocation rollback. */
#include "ops/opdsl.h"
#include <assert.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>

static int fail_allocate, fail_grow;
void *__real_calloc(size_t, size_t);
void *__real_realloc(void *, size_t);
void *__wrap_calloc(size_t n, size_t size)
{
    if (fail_allocate) { errno = ENOMEM; return NULL; }
    return __real_calloc(n, size);
}
void *__wrap_realloc(void *ptr, size_t size)
{
    if (fail_grow) { errno = ENOMEM; return NULL; }
    return __real_realloc(ptr, size);
}

typedef struct { int id, failure, *trace, *length; } step;
static int execute(brix_conn *connection, void *argument, brix_status *status)
{
    step *s = argument;
    assert(connection == NULL && status != NULL);
    s->trace[(*s->length)++] = s->id;
    return s->failure;
}

int main(int argc, char **argv)
{
    assert(argc == 3);
    int count = atoi(argv[1]), failure = atoi(argv[2]);
    int trace[258] = {0}, length = 0;
    step steps[257]; brix_status status = {0}; size_t ran = 999;
    assert(count >= 0 && count <= 256);
    fail_allocate = 1; assert(brix_opd_new() == NULL); fail_allocate = 0;
    assert(brix_opd_run(NULL, NULL, &status, &ran) == -1 && ran == 999);
    assert(brix_opd_len(NULL) == 0);
    assert(brix_opd_step(NULL, "bad", execute, NULL) == NULL);
    brix_opd_otherwise(NULL, execute, NULL); brix_opd_free(NULL);
    brix_opd_t *pipeline = brix_opd_new(); assert(pipeline);
    assert(brix_opd_step(pipeline, "bad", NULL, NULL) == NULL);
    for (int i = 0; i < count; i++) {
        steps[i] = (step) {i, failure == i, trace, &length};
        /* Initial and later growth failures must leave prior steps usable. */
        if (i == 0 || i == 8 || i == 16 || i == 128) {
            fail_grow = 1;
            assert(brix_opd_step(pipeline, "oom", execute, &steps[i]) == NULL);
            assert(brix_opd_len(pipeline) == (size_t) i);
            fail_grow = 0;
        }
        assert(brix_opd_step(pipeline, "step", execute, &steps[i]) == pipeline);
    }
    if (count == 256) {
        assert(brix_opd_step(pipeline, "excess", execute, &steps[0]) == NULL);
    }
    assert(brix_opd_len(pipeline) == (size_t) count);
    steps[256] = (step) {999, 7, trace, &length};
    for (int otherwise = 0; otherwise < 2; otherwise++) {
        brix_opd_otherwise(pipeline, otherwise ? execute : NULL, &steps[256]);
        for (int report = 0; report < 2; report++) {
            length = 0; ran = 999;
            int failed = failure >= 0 && failure < count;
            assert(brix_opd_run(pipeline, NULL, &status, report ? &ran : NULL) == (failed ? -1 : 0));
            int executed = failed ? failure + 1 : count;
            assert(length == executed + (failed && otherwise));
            for (int i = 0; i < executed; i++) { assert(trace[i] == i); }
            if (failed && otherwise) { assert(trace[executed] == 999); }
            assert(ran == (report ? (size_t) (failed ? failure : count) : 999));
        }
    }
    brix_opd_free(pipeline);
    return 0;
}
