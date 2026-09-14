/* Test fragment appended after the actual RAM snapshot type and functions. */
static sd_ram_dir_t *
ownership_ram_snapshot(size_t capacity)
{
    sd_ram_dir_t *directory = calloc(1, sizeof(*directory));

    assert(directory != NULL);
    directory->names = calloc(capacity, sizeof(*directory->names));
    directory->types = calloc(capacity, sizeof(*directory->types));
    assert(directory->names != NULL && directory->types != NULL);
    return directory;
}

static void
ownership_success(void)
{
    sd_ram_dir_t *directory = ownership_ram_snapshot(4);
    char name[] = "beta";

    assert(sd_ram_dir_add(directory, "alpha/item", 4) == NGX_OK);
    assert(sd_ram_dir_add(directory, "alpha/second", 4) == NGX_OK);
    assert(sd_ram_dir_add(directory, name, 4) == NGX_OK);
    name[0] = 'X';
    assert(directory->n == 2);
    assert(strcmp(directory->names[0], "alpha") == 0);
    assert(strcmp(directory->names[1], "beta") == 0);
    assert(directory->types[0] == DT_DIR && directory->types[1] == DT_REG);
    sd_ram_dir_free(directory);
}

static void
ownership_allocation_failure(void)
{
    sd_ram_dir_t *directory = ownership_ram_snapshot(3);

    ownership_fail("strndup");
    assert(sd_ram_dir_add(directory, "first", 3) == NGX_ERROR);
    assert(errno == ENOMEM && directory->n == 0);
    ownership_fail(NULL);
    assert(sd_ram_dir_add(directory, "first", 3) == NGX_OK);
    ownership_fail("strndup");
    assert(sd_ram_dir_add(directory, "second", 3) == NGX_ERROR);
    assert(errno == ENOMEM && directory->n == 1);
    assert(strcmp(directory->names[0], "first") == 0);
    sd_ram_dir_free(directory);
}

static void
ownership_stop_cleanup(void)
{
    sd_ram_dir_t *directory = ownership_ram_snapshot(2);

    assert(sd_ram_dir_add(directory, "first", 2) == NGX_OK);
    assert(sd_ram_dir_add(directory, "second", 2) == NGX_OK);
    ownership_fail("strndup");
    assert(sd_ram_dir_add(directory, "out-of-capacity", 2) == NGX_OK);
    assert(directory->n == 2 && errno == 0);
    sd_ram_dir_free(directory);
}
