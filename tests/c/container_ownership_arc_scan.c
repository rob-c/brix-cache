/* Test fragment appended after the real arc_scan_t and push/free bodies. */
static void
ownership_scan_fill(arc_scan_t *scan, unsigned count)
{
    unsigned i;

    for (i = 0; i < count; i++) {
        assert(arc_scan_push(scan, "dataset/member") == 0);
    }
}

static void
ownership_success(void)
{
    arc_scan_t scan = {0};
    char member[] = "first";

    assert(arc_scan_push(&scan, member) == 0);
    member[0] = 'X';
    ownership_scan_fill(&scan, 128);
    assert(scan.n == 129 && scan.cap >= scan.n);
    assert(strcmp(scan.names[0], "first") == 0);
    assert(strcmp(scan.names[128], "dataset/member") == 0);
    arc_scan_free(&scan);
}

static void
ownership_allocation_failure(void)
{
    arc_scan_t scan = {0};

    ownership_fail("realloc");
    assert(arc_scan_push(&scan, "entry") == -1);
    assert(scan.n == 0 && scan.names == NULL && errno == ENOMEM);
    ownership_fail(NULL);
    ownership_scan_fill(&scan, 1);
    ownership_fail("strdup");
    assert(arc_scan_push(&scan, "entry") == -1);
    assert(scan.n == 1 && errno == ENOMEM);
    ownership_fail(NULL);
    ownership_scan_fill(&scan, scan.cap - scan.n);
    ownership_fail("realloc");
    assert(arc_scan_push(&scan, "entry") == -1);
    assert(scan.n == scan.cap && errno == ENOMEM);
    assert(strcmp(scan.names[0], "dataset/member") == 0);
    arc_scan_free(&scan);
}

static void
ownership_stop_cleanup(void)
{
    arc_scan_t scan = {0};

    ownership_scan_fill(&scan, BRIX_ZIP_MAX_ENTRIES - 1);
    assert(arc_scan_push(&scan, "refused") == -1);
    assert(errno == EFBIG && scan.n == BRIX_ZIP_MAX_ENTRIES - 1);
    arc_scan_free(&scan);
}
