/* PAX / GNU-long / end-and-truncation test cases
 *
 * Extracted from tar_unittest.c to hold each translation unit under the
 * 600-line file-size cap. Included by tar_unittest.c (one TU); not built
 * standalone. */

static void t_pax(void) {
    ar_t             a = { .len = 0 };
    brix_tar_entry_t e;
    brix_tar_t      *t;
    int              fd;
    static const char rec[] =
        "31 path=override/long-name.bin\n"
        "30 SCHILY.xattr.user.tag=blue\n"
        "23 mtime=1700000000.25\n";

    ar_hdr(&a, "pax-hdr", 'x', (int64_t) (sizeof(rec) - 1), 0644);
    ar_body(&a, rec, sizeof(rec) - 1);
    ar_hdr(&a, "short-name", '0', 2, 0600);
    ar_body(&a, "zz", 2);
    ar_hdr(&a, "plain", '0', 0, 0644);
    ar_end(&a);

    t = ar_open(&a, &fd);
    CHECK(t != NULL && brix_tar_next(t, &e) == 1 &&
          strcmp(e.path, "override/long-name.bin") == 0 &&
          e.mtime == 1700000000 && e.size == 2,
          "pax: path + fractional-mtime overrides applied");
    {
        const char          *key = NULL;
        const unsigned char *val = NULL;
        size_t               keylen = 0, vallen = 0;
        int                  n = cvmfs_xattr_count(
                                     (const unsigned char *) e.xattr,
                                     e.xattr_len);

        CHECK(n == 1 &&
              cvmfs_xattr_unpack((const unsigned char *) e.xattr, e.xattr_len,
                                 0, &key, &keylen, &val, &vallen) == 0 &&
              keylen == 8 && memcmp(key, "user.tag", 8) == 0 &&
              vallen == 4 && memcmp(val, "blue", 4) == 0,
              "pax: SCHILY.xattr packed in changeset wire format");
    }
    CHECK(brix_tar_skip(t) == 0 && brix_tar_next(t, &e) == 1 &&
          strcmp(e.path, "plain") == 0 && e.xattr == NULL,
          "pax: overrides reset after the entry");
    ar_done(t, fd);

    /* malformed record length → refused */
    a.len = 0;
    ar_hdr(&a, "bad-pax", 'x', 9, 0644);
    ar_body(&a, "99 a=b\nxx", 9);
    ar_hdr(&a, "f", '0', 0, 0644);
    ar_end(&a);
    ar_expect_refusal(&a, "pax record length", "pax: lying record length refused");
}

static void t_gnu_long_and_unknown(void) {
    ar_t             a = { .len = 0 };
    brix_tar_entry_t e;
    brix_tar_t      *t;
    char             want[130];
    int              fd;
    size_t           i;

    for (i = 0; i < sizeof(want) - 1; i++)
        want[i] = 'a' + (char) (i % 26);
    want[sizeof(want) - 1] = '\0';

    ar_hdr(&a, "././@LongLink", 'L', (int64_t) strlen(want) + 1, 0644);
    ar_body(&a, want, strlen(want) + 1);
    ar_hdr(&a, "truncated-by-ustar", '0', 0, 0644);
    ar_hdr(&a, "vendor-ext", 'Z', 7, 0644);      /* unknown flag: skipped */
    ar_body(&a, "opaque!", 7);
    ar_hdr(&a, "after", '0', 0, 0644);
    ar_end(&a);

    t = ar_open(&a, &fd);
    CHECK(t != NULL && brix_tar_next(t, &e) == 1 &&
          strcmp(e.path, want) == 0, "gnu: 'L' long name applied");
    CHECK(brix_tar_next(t, &e) == 1 && strcmp(e.path, "after") == 0,
          "gnu: unknown typeflag skipped, stream continues");
    CHECK(brix_tar_next(t, &e) == 0, "gnu: clean EOF");
    ar_done(t, fd);
}

static void t_ends_and_truncation(void) {
    ar_t             a = { .len = 0 };
    brix_tar_entry_t e;
    brix_tar_t      *t;
    int              fd;

    /* single zero block + EOF (sloppy writer) → clean end */
    ar_hdr(&a, "f", '0', 0, 0644);
    memset(a.b + a.len, 0, 512);
    a.len += 512;
    t = ar_open(&a, &fd);
    CHECK(t != NULL && brix_tar_next(t, &e) == 1 &&
          brix_tar_next(t, &e) == 0, "end: single-zero-block+EOF accepted");
    ar_done(t, fd);

    /* data after the end marker → refused */
    a.len = 0;
    ar_hdr(&a, "f", '0', 0, 0644);
    memset(a.b + a.len, 0, 512);
    a.len += 512;
    ar_hdr(&a, "smuggled", '0', 0, 0644);
    t = ar_open(&a, &fd);
    CHECK(t != NULL && brix_tar_next(t, &e) == 1 &&
          brix_tar_next(t, &e) == -1 &&
          strstr(brix_tar_error(t), "end-of-archive") != NULL,
          "end: data after end marker refused");
    ar_done(t, fd);

    /* truncated body → refused */
    a.len = 0;
    ar_hdr(&a, "f", '0', 100, 0644);
    memcpy(a.b + a.len, "short", 5);
    a.len += 5;
    t = ar_open(&a, &fd);
    CHECK(t != NULL && brix_tar_next(t, &e) == 1 && brix_tar_skip(t) == -1 &&
          strstr(brix_tar_error(t), "truncated") != NULL,
          "end: truncated body refused");
    ar_done(t, fd);

    /* truncated header (200 of 512 bytes) → refused */
    a.len = 0;
    ar_hdr(&a, "f", '0', 0, 0644);
    t = ar_open_buf(a.b, 200, &fd);
    CHECK(t != NULL && brix_tar_next(t, &e) == -1 &&
          strstr(brix_tar_error(t), "truncated") != NULL,
          "end: truncated header refused");
    ar_done(t, fd);
}
