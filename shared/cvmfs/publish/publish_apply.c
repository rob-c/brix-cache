/* changeset apply (add/delete/link) + revision finalize
 *
 * Extracted from publish.c to hold each translation unit under the
 * 600-line file-size cap. Included by publish.c (one TU); not built
 * standalone. */
static int pub_apply_delete(pub_ctx_t *px, pub_cat_t *cat, const cvmfs_change_t *c) {
    cvmfs_dirent_t de;
    int found = cvmfs_catwriter_lookup(cat->w, c->path, &de);
    if (found == 1 && (de.flags & CVMFS_FLAG_DIR_NESTED_MOUNT)
        && cvmfs_catwriter_del_nested(cat->w, c->path) != 0)
        return pub_fail(px, "cannot drop nested row for %s", c->path);
    if (cvmfs_catwriter_delete_subtree(cat->w, c->path) < 0)
        return pub_fail(px, "cannot delete %s", c->path);
    size_t plen = strlen(c->path);
    for (pub_cat_t *k = px->cats; k != NULL; k = k->next)   /* orphaned children */
        if (strncmp(k->mount, c->path, plen) == 0
            && (k->mount[plen] == '\0' || k->mount[plen] == '/'))
            k->dropped = 1;
    cat->dirty = 1;
    return 0;
}

static void pub_row_from_change(cvmfs_catrow_t *r, const cvmfs_change_t *c) {
    memset(r, 0, sizeof(*r));
    r->path = c->path;
    r->mode = c->mode;
    r->mtime = c->mtime;
    r->uid = c->uid;
    r->gid = c->gid;
    r->linkcount = c->linkcount != 0 ? c->linkcount : 1;
    r->hardlink_group = c->hardlink_group;
    r->xattr = c->xattr;
    r->xattr_len = c->xattr_len;
}

static int pub_add_dir(pub_ctx_t *px, pub_cat_t *cat, const cvmfs_change_t *c,
                       const pub_dirtab_t *dt) {
    cvmfs_dirent_t de;
    int found = cvmfs_catwriter_lookup(cat->w, c->path, &de);
    if (c->no_clobber && found == 1 && !(de.flags & CVMFS_FLAG_DIR))
        return pub_fail(px, "path exists and is not a directory: %s", c->path);
    if (c->opaque && found == 1
        && cvmfs_catwriter_delete_subtree(cat->w, c->path) < 0)
        return pub_fail(px, "cannot clear opaque dir %s", c->path);
    cvmfs_catrow_t r;
    pub_row_from_change(&r, c);
    r.flags = CVMFS_FLAG_DIR;
    if (found == 1 && (de.flags & CVMFS_FLAG_DIR_NESTED_MOUNT) && !c->opaque) {
        r.flags |= CVMFS_FLAG_DIR_NESTED_MOUNT;      /* attr refresh keeps the mount */
    } else if ((found != 1 || c->opaque) && pub_dirtab_new_nests(dt, c->path)) {
        r.flags |= CVMFS_FLAG_DIR_NESTED_MOUNT;      /* new dir the dirtab nests */
        pub_cat_t *child = pub_cat_fresh(px, c->path, &r);
        if (child == NULL) return -1;
        child->parent = cat;
    }
    cat->dirty = 1;
    return cvmfs_catwriter_upsert(cat->w, &r) == 0
        ? 0 : pub_fail(px, "cannot upsert dir %s", c->path);
}

static int pub_store_chunks(pub_ctx_t *px, pub_cat_t *cat, const cvmfs_change_t *c,
                            int fd, unsigned char *buf) {
    uint64_t off = 0;
    for (;;) {
        ssize_t n = read(fd, buf, (size_t) px->chunk_size);
        if (n < 0) return pub_fail(px, "read error ingesting %s", c->path);
        if (n == 0) break;
        cvmfs_hash_t h;
        if (cvmfs_object_store(&px->store, buf, (size_t) n, 'P', 1, &h, NULL) != 0
            || cvmfs_catwriter_add_chunk(cat->w, c->path, off, (uint64_t) n, &h) != 0)
            return pub_fail(px, "cannot store chunk of %s", c->path);
        off += (uint64_t) n;
    }
    return 0;
}

static int pub_add_file(pub_ctx_t *px, pub_cat_t *cat, const cvmfs_change_t *c) {
    if (cvmfs_catwriter_delete_subtree(cat->w, c->path) < 0)
        return pub_fail(px, "cannot replace %s", c->path);
    int fd = open(c->src, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
    struct stat st;
    if (fd < 0 || fstat(fd, &st) != 0 || !S_ISREG(st.st_mode)) {
        if (fd >= 0) close(fd);
        return pub_fail(px, "upper file vanished or changed type: %s", c->path);
    }
    cvmfs_catrow_t r;
    pub_row_from_change(&r, c);
    r.size = (uint64_t) st.st_size;
    int chunked = st.st_size > px->chunk_size;
    size_t bufsz = (size_t) (chunked ? px->chunk_size : (st.st_size > 0 ? st.st_size : 1));
    unsigned char *buf = malloc(bufsz);
    int rc;
    cvmfs_hash_t h;
    if (buf == NULL) {
        rc = pub_fail(px, "out of memory ingesting %s", c->path);
    } else if (chunked) {
        r.flags = CVMFS_FLAG_FILE | CVMFS_FLAG_FILE_CHUNK;
        rc = pub_store_chunks(px, cat, c, fd, buf);
    } else {
        r.flags = CVMFS_FLAG_FILE;
        ssize_t n = read(fd, buf, bufsz);
        rc = n == st.st_size
             && cvmfs_object_store(&px->store, buf, (size_t) n, 0, 1, &h, NULL) == 0
             ? 0 : pub_fail(px, "cannot store %s", c->path);
        r.hash = &h;
    }
    free(buf);
    close(fd);
    cat->dirty = 1;
    if (rc == 0 && cvmfs_catwriter_upsert(cat->w, &r) != 0)
        rc = pub_fail(px, "cannot upsert file row %s", c->path);
    return rc;
}

static int pub_add_link(pub_ctx_t *px, pub_cat_t *cat, const cvmfs_change_t *c) {
    cvmfs_dirent_t de;
    if (c->no_clobber && cvmfs_catwriter_lookup(cat->w, c->path, &de) == 1
        && (de.flags & CVMFS_FLAG_DIR))
        return pub_fail(px, "refusing to replace directory with symlink: %s",
                        c->path);
    if (cvmfs_catwriter_delete_subtree(cat->w, c->path) < 0)
        return pub_fail(px, "cannot replace %s", c->path);
    cvmfs_catrow_t r;
    pub_row_from_change(&r, c);
    r.flags = CVMFS_FLAG_LINK;
    r.symlink = c->link;
    r.size = strlen(c->link);
    cat->dirty = 1;
    return cvmfs_catwriter_upsert(cat->w, &r) == 0
        ? 0 : pub_fail(px, "cannot upsert symlink %s", c->path);
}

static int pub_apply(pub_ctx_t *px, const cvmfs_changeset_t *cs,
                     const pub_dirtab_t *dt) {
    for (size_t i = 0; i < cs->n; i++) {
        const cvmfs_change_t *c = &cs->v[i];
        pub_cat_t *cat = pub_owner(px, c->path);
        if (cat == NULL) return -1;
        int rc = 0;
        switch (c->op) {
        case CVMFS_CH_DELETE:   rc = pub_apply_delete(px, cat, c); break;
        case CVMFS_CH_ADD_DIR:  rc = pub_add_dir(px, cat, c, dt); break;
        case CVMFS_CH_ADD_FILE: rc = pub_add_file(px, cat, c); break;
        case CVMFS_CH_ADD_LINK: rc = pub_add_link(px, cat, c); break;
        default:                rc = pub_fail(px, "bad change op for %s", c->path);
        }
        if (rc != 0) return -1;
    }
    return 0;
}

/* ---- finalize: bottom-up commit + store + parent nested update ----------- */

static int pub_finalize_one(pub_ctx_t *px, pub_cat_t *c, long new_rev,
                            const char *old_root_hex,
                            cvmfs_hash_t *out_hash, size_t *out_size) {
    char val[32];
    snprintf(val, sizeof(val), "%ld", new_rev);
    int ok = cvmfs_catwriter_set_property(c->w, "revision", val) == 0
          && cvmfs_catwriter_set_property(c->w, "schema", "2.5") == 0
          && cvmfs_catwriter_set_property(c->w, "schema_revision", "2") == 0;
    snprintf(val, sizeof(val), "%ld", (long) time(NULL));
    ok = ok && cvmfs_catwriter_set_property(c->w, "last_modified", val) == 0;
    if (c->mount[0] == '\0')                         /* root extras */
        ok = ok && cvmfs_catwriter_set_property(c->w, "previous_revision",
                                                old_root_hex) == 0;
    else                     /* nested: bind to the mount path (stock rule —
                              * without root_prefix the official client treats
                              * the catalog as rooted at '' and mistranslates) */
        ok = ok && cvmfs_catwriter_set_property(c->w, "root_prefix",
                                                c->mount) == 0;
    if (!ok)
        return pub_fail(px, "cannot set catalog properties for %s",
                        c->mount[0] ? c->mount : "(root)");
    if (cvmfs_catwriter_update_counters(c->w) != 0)
        return pub_fail(px, "cannot update counters for %s", c->mount);
    if (pub_subtree_counters(px, c) != 0)
        return -1;                                   /* err already set */
    if (cvmfs_catwriter_commit(c->w) != 0)
        return pub_fail(px, "cannot commit catalog %s", c->mount);
    c->w = NULL;
    size_t len = 0;
    unsigned char *bytes = pub_slurp(c->db, &len);
    int rc = bytes != NULL
          && cvmfs_object_store(&px->store, bytes, len, 'C', 1, out_hash, NULL) == 0
          ? 0 : pub_fail(px, "cannot store catalog %s", c->mount);
    *out_size = len;
    free(bytes);
    return rc;
}

static int pub_finalize(pub_ctx_t *px, long new_rev, const char *old_root_hex,
                        cvmfs_hash_t *root_hash, size_t *root_size) {
    for (;;) {                       /* deepest dirty mount first; root ends it */
        pub_cat_t *pick = NULL;
        for (pub_cat_t *c = px->cats; c != NULL; c = c->next) {
            if (c->w == NULL) continue;
            if (c->dropped || !c->dirty) {           /* discard untouched/orphaned */
                cvmfs_catwriter_abort(c->w);
                c->w = NULL;
                continue;
            }
            if (pick == NULL || strlen(c->mount) > strlen(pick->mount)) pick = c;
        }
        if (pick == NULL) return pub_fail(px, "nothing to publish%s", "");
        cvmfs_hash_t h;
        size_t sz = 0;
        if (pub_finalize_one(px, pick, new_rev, old_root_hex, &h, &sz) != 0)
            return -1;
        if (pick->mount[0] == '\0') {
            *root_hash = h;
            *root_size = sz;
            return 0;
        }
        char hex[64];
        cvmfs_hash_to_hex(&h, 0, hex, sizeof(hex));
        pub_cat_t *par = pick->parent != NULL ? pick->parent : px->cats;
        if (par->w == NULL
            || cvmfs_catwriter_set_nested(par->w, pick->mount, hex, sz) != 0)
            return pub_fail(px, "cannot update parent nested row for %s", pick->mount);
        par->dirty = 1;
    }
}

