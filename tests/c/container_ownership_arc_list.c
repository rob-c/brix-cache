/* Test fragment appended after the real arc_list_t and append/free bodies. */
typedef struct {
    unsigned calls;
    int stop;
} ownership_listing_t;

static int
ownership_list_callback(void *data, const char *name, int is_dir)
{
    ownership_listing_t *listing = data;

    assert(name[0] != '\0');
    assert(is_dir == 0);
    listing->calls++;
    return listing->stop;
}

static void
ownership_list_fill(arc_list_t *list, unsigned count)
{
    unsigned i;

    for (i = 0; i < count; i++) {
        assert(arc_list_inner_cb(list, "entry", 0) == 0);
    }
}

static void
ownership_success(void)
{
    ownership_listing_t calls = {0};
    arc_list_t list = {.cb = ownership_list_callback, .ud = &calls};
    char source[] = "entry";

    assert(arc_list_inner_cb(&list, source, 0) == 0);
    source[0] = 'X';
    assert(strcmp(list.seen[0], "entry") == 0);
    ownership_list_fill(&list, 64);
    assert(list.n == 65 && calls.calls == 65);
    assert(list.cap >= list.n);
    arc_list_free(&list);
}

static void
ownership_allocation_failure(void)
{
    ownership_listing_t calls = {0};
    arc_list_t list = {.cb = ownership_list_callback, .ud = &calls};

    ownership_fail("realloc");
    assert(arc_list_inner_cb(&list, "entry", 0) == 1);
    assert(list.n == 0 && list.seen == NULL && calls.calls == 0);
    ownership_fail(NULL);
    ownership_list_fill(&list, 1);
    ownership_fail("strdup");
    assert(arc_list_inner_cb(&list, "unrecorded", 0) == 0);
    assert(list.n == 1 && calls.calls == 2);
    assert(strcmp(list.seen[0], "entry") == 0);
    ownership_fail(NULL);
    ownership_list_fill(&list, list.cap - list.n);
    ownership_fail("realloc");
    assert(arc_list_inner_cb(&list, "entry", 0) == 1);
    assert(list.n == list.cap && calls.calls == list.n + 1);
    arc_list_free(&list);
}

static void
ownership_stop_cleanup(void)
{
    ownership_listing_t calls = {0};
    arc_list_t list = {.cb = ownership_list_callback, .ud = &calls};

    ownership_list_fill(&list, 3);
    calls.stop = 1;
    assert(arc_list_inner_cb(&list, "last", 0) == 1);
    assert(list.stopped == 1 && list.n == 4 && calls.calls == 4);
    assert(strcmp(list.seen[3], "last") == 0);
    arc_list_free(&list);
}
