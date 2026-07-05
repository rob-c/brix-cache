/* copy_filter_unit.c — unit tests for --exclude/--include matching and the
 * --sync-check size/mtime comparison policy. */
#include <assert.h>
#include <stdio.h>
#include <string.h>
#include "brix.h"
#include "brix_ops.h"

static void test_no_filters_passes(void)        /* success */
{
    brix_copy_opts o;
    memset(&o, 0, sizeof(o));
    assert(brix_copy_filter_match(&o, "sub/dir/file.txt") == 1);
}

static void test_exclude_and_include(void)
{
    static const char *ex[] = { "*.log" };
    static const char *in[] = { "*.root" };
    brix_copy_opts o;
    memset(&o, 0, sizeof(o));
    o.excludes = ex; o.n_excludes = 1;
    assert(brix_copy_filter_match(&o, "run/job.log") == 0);   /* basename match  */
    assert(brix_copy_filter_match(&o, "run/data.root") == 1);
    o.includes = in; o.n_includes = 1;
    assert(brix_copy_filter_match(&o, "run/data.root") == 1);
    assert(brix_copy_filter_match(&o, "run/notes.txt") == 0); /* include gate    */
}

static void test_exclude_beats_include(void)     /* error/conflict case */
{
    static const char *ex[] = { "secret*" };
    static const char *in[] = { "*" };
    brix_copy_opts o;
    memset(&o, 0, sizeof(o));
    o.excludes = ex; o.n_excludes = 1;
    o.includes = in; o.n_includes = 1;
    assert(brix_copy_filter_match(&o, "secret.txt") == 0);
}

static void test_hostile_rel(void)               /* security-negative */
{
    /* A pathologically long rel must not crash or overflow (no fixed buffers). */
    static const char *ex[] = { "*.log" };
    char big[8192];
    brix_copy_opts o;
    memset(&o, 0, sizeof(o));
    o.excludes = ex; o.n_excludes = 1;
    memset(big, 'a', sizeof(big) - 5);
    memcpy(big + sizeof(big) - 5, ".log", 5);
    assert(brix_copy_filter_match(&o, big) == 0);
    assert(brix_copy_filter_match(&o, "") == 1);
    assert(brix_copy_filter_match(NULL, "x") == 1);
}

static void test_sync_should_skip(void)
{
    assert(brix_sync_should_skip(XRDC_SYNC_SIZE, 10, 0, 10, 0) == 1);
    assert(brix_sync_should_skip(XRDC_SYNC_SIZE, 10, 0, 11, 0) == 0);
    assert(brix_sync_should_skip(XRDC_SYNC_MTIME, 10, 100, 10, 100) == 1);
    assert(brix_sync_should_skip(XRDC_SYNC_MTIME, 10, 200, 10, 100) == 0); /* src newer */
    assert(brix_sync_should_skip(XRDC_SYNC_MTIME, 10, 100, 11, 200) == 0); /* size differs */
}

int main(void)
{
    test_no_filters_passes();
    test_exclude_and_include();
    test_exclude_beats_include();
    test_hostile_rel();
    test_sync_should_skip();
    printf("copy_filter_unit: ALL PASS\n");
    return 0;
}
