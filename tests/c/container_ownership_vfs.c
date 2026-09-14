/* The production window uses the real credential dispatcher with this local
 * driver slot. No paths are unlinked; the slot only reports batch outcomes. */
static ngx_int_t
ownership_delete_slot(brix_sd_instance_t *instance, brix_sd_unlink_batch_t *batch)
{
    const int *failure = instance->state;
    size_t i;

    for (i = 0; i < batch->n; i++) {
        assert(batch->errs[i] == ECANCELED);
    }
    if (*failure) {
        batch->done = 1;
        batch->errs[0] = EIO;
        errno = EIO;
        return NGX_ERROR;
    }
    for (i = 0; i < batch->n; i++) {
        batch->errs[i] = 0;
    }
    batch->done = batch->n;
    return NGX_OK;
}

void
brix_metric_vfs_bulk_delete(const char *driver_name, size_t keys)
{
    const char *expected = getenv("BRIX_OWNERSHIP_METRIC_KEYS");

    assert(strcmp(driver_name, "ownership-fixture") == 0);
    assert(expected != NULL);
    assert(keys == strtoul(expected, NULL, 10));
}

static void
ownership_window_fill(brix_vfs_unlink_window_t *window, size_t count)
{
    size_t i;

    for (i = 0; i < count; i++) {
        assert(brix_vfs_unlink_window_add(window, "/member") == NGX_OK);
    }
}

static void
ownership_success(void)
{
    int failure = 0;
    brix_sd_driver_t driver = {.name = "ownership-fixture", .unlink_many = ownership_delete_slot};
    brix_sd_instance_t leaf = {.driver = &driver, .state = &failure};
    brix_vfs_unlink_window_t *window = calloc(1, sizeof(*window));
    char expected[32];

    assert(window != NULL);
    window->leaf = &leaf;
    assert(snprintf(expected, sizeof(expected), "%u", BRIX_SD_BULK_DELETE_WINDOW) > 0);
    assert(setenv("BRIX_OWNERSHIP_METRIC_KEYS", expected, 1) == 0);
    ownership_window_fill(window, BRIX_SD_BULK_DELETE_WINDOW);
    assert(brix_vfs_unlink_window_add(window, "/after-flush") == NGX_OK);
    assert(window->n == 1 && strcmp(window->paths[0], "/after-flush") == 0);
    assert(setenv("BRIX_OWNERSHIP_METRIC_KEYS", "1", 1) == 0);
    assert(brix_vfs_unlink_window_flush(window) == NGX_OK);
    assert(window->n == 0);
    brix_vfs_unlink_window_reset(window);
    free(window);
}

static void
ownership_allocation_failure(void)
{
    brix_vfs_unlink_window_t *window = calloc(1, sizeof(*window));

    assert(window != NULL);
    ownership_fail("strdup");
    assert(brix_vfs_unlink_window_add(window, "/missing") == NGX_ERROR);
    assert(window->n == 0 && errno == ENOMEM);
    ownership_fail(NULL);
    ownership_window_fill(window, 1);
    ownership_fail("strdup");
    assert(brix_vfs_unlink_window_add(window, "/missing") == NGX_ERROR);
    assert(window->n == 1 && errno == ENOMEM);
    assert(strcmp(window->paths[0], "/member") == 0);
    brix_vfs_unlink_window_reset(window);
    assert(window->n == 0);
    free(window);
}

static void
ownership_stop_cleanup(void)
{
    int failure = 1;
    brix_sd_driver_t driver = {.name = "ownership-fixture", .unlink_many = ownership_delete_slot};
    brix_sd_instance_t leaf = {.driver = &driver, .state = &failure};
    brix_vfs_unlink_window_t *window = calloc(1, sizeof(*window));

    assert(window != NULL);
    window->leaf = &leaf;
    assert(setenv("BRIX_OWNERSHIP_METRIC_KEYS", "0", 1) == 0);
    ownership_window_fill(window, 3);
    assert(brix_vfs_unlink_window_flush(window) == NGX_ERROR);
    assert(window->n == 0 && errno == EIO);
    ownership_window_fill(window, BRIX_SD_BULK_DELETE_WINDOW);
    assert(brix_vfs_unlink_window_add(window, "/refused") == NGX_ERROR);
    assert(window->n == 0 && errno == EIO);
    brix_vfs_unlink_window_reset(window);
    free(window);
}
