/* Test fragment appended after the actual purge candidate push/free bodies. */
static void
ownership_purge_fill(frm_purge_scan_t *scan, size_t count)
{
    struct stat metadata = {.st_size = 81, .st_atime = 11, .st_mtime = 7};
    size_t i;

    for (i = 0; i < count; i++) {
        assert(frm_purge_push(scan, "/member", &metadata) == 0);
    }
}

static void
ownership_success(void)
{
    frm_purge_scan_t scan = {0};

    ownership_purge_fill(&scan, 257);
    assert(scan.n == 257 && scan.cap >= scan.n);
    assert(strcmp(scan.v[0].rel, "/member") == 0);
    assert(scan.v[256].size == 81 && scan.v[256].touched == 11);
    assert(scan.v[256].rule == -1 && scan.v[256].approved == 0);
    frm_purge_scan_free(&scan);
    assert(scan.v == NULL && scan.n == 0 && scan.cap == 0);
}

static void
ownership_allocation_failure(void)
{
    frm_purge_scan_t scan = {0};
    struct stat metadata = {0};

    ownership_fail("realloc");
    assert(frm_purge_push(&scan, "/missing", &metadata) == -1);
    assert(scan.n == 0 && scan.v == NULL && scan.oom == 1);
    ownership_fail(NULL);
    scan.oom = 0;
    ownership_purge_fill(&scan, 1);
    ownership_fail("strdup");
    assert(frm_purge_push(&scan, "/missing", &metadata) == -1);
    assert(scan.n == 1 && scan.oom == 1);
    ownership_fail(NULL);
    scan.oom = 0;
    ownership_purge_fill(&scan, scan.cap - scan.n);
    ownership_fail("realloc");
    assert(frm_purge_push(&scan, "/missing", &metadata) == -1);
    assert(scan.n == scan.cap && scan.oom == 1);
    assert(strcmp(scan.v[0].rel, "/member") == 0);
    frm_purge_scan_free(&scan);
}

static void
ownership_stop_cleanup(void)
{
    frm_purge_scan_t scan = {0};
    struct stat metadata = {0};

    ownership_purge_fill(&scan, FRM_PURGE_MAX_CANDIDATES);
    assert(frm_purge_push(&scan, "/capped", &metadata) == 0);
    assert(scan.n == FRM_PURGE_MAX_CANDIDATES && scan.oom == 0);
    frm_purge_scan_free(&scan);
    frm_purge_scan_free(&scan);
}
