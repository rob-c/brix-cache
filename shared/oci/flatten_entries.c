/* Per-entry materialization: reg/dir/hardlink/whiteout/opaque + entry dispatch
 *
 * Extracted from flatten.c to hold each translation unit under the
 * 600-line file-size cap. Included by flatten.c (one TU); not built
 * standalone. */
static int fl_reg(fl_ctx_t *fx, int parent, const char *name,
                  const brix_tar_entry_t *e) {
    int fd;

    if (fl_rm(fx, parent, name) != 0)      /* dir→file replacement */
        return -1;
    fd = openat(parent, FL_TMP_NAME,
                O_WRONLY | O_CREAT | O_TRUNC | O_NOFOLLOW | O_CLOEXEC, 0600);
    if (fd < 0)
        return fl_fail(fx, "cannot create temp for '%s': %s", name,
                       strerror(errno));
    for (;;) {
        int got = brix_tar_read(fx->tar, fx->copybuf, sizeof(fx->copybuf));

        if (got < 0) {
            close(fd);
            unlinkat(parent, FL_TMP_NAME, 0);
            return fl_fail(fx, "read of '%s' failed: %s", name,
                           brix_tar_error(fx->tar));
        }
        if (got == 0)
            break;
        fx->st->bytes += got;
        if (fx->o->max_total_bytes > 0 &&
            fx->st->bytes > fx->o->max_total_bytes) {
            close(fd);
            unlinkat(parent, FL_TMP_NAME, 0);
            return fl_fail(fx, "byte budget exhausted at '%s'%s", name, "");
        }
        if (write(fd, fx->copybuf, (size_t) got) != (ssize_t) got) {
            close(fd);
            unlinkat(parent, FL_TMP_NAME, 0);
            return fl_fail(fx, "write of '%s' failed: %s", name,
                           strerror(errno));
        }
    }
    if (fchmod(fd, e->mode) != 0 || fl_xattrs(fx, fd, e) != 0) {
        close(fd);
        unlinkat(parent, FL_TMP_NAME, 0);
        return fx->err[0] ? -1
                          : fl_fail(fx, "chmod '%s' failed%s", name, "");
    }
    close(fd);
    if (renameat(parent, FL_TMP_NAME, parent, name) != 0)
        return fl_fail(fx, "rename into '%s' failed: %s", name,
                       strerror(errno));
    fl_meta(fx, parent, name, e);
    fx->st->files++;
    return 0;
}

/* Directory: mkdir-or-merge; later layers win the metadata. */
static int fl_dir(fl_ctx_t *fx, int parent, const char *name,
                  const brix_tar_entry_t *e) {
    struct stat sb;
    int         dfd;

    if (fstatat(parent, name, &sb, AT_SYMLINK_NOFOLLOW) == 0 &&
        !S_ISDIR(sb.st_mode)) {
        if (fl_rm(fx, parent, name) != 0)   /* file→dir replacement */
            return -1;
    }
    if (mkdirat(parent, name, 0755) != 0 && errno != EEXIST)
        return fl_fail(fx, "mkdir '%s' failed: %s", name, strerror(errno));
    dfd = openat(parent, name, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (dfd < 0)
        return fl_fail(fx, "cannot open new dir '%s': %s", name,
                       strerror(errno));
    if (fchmod(dfd, e->mode) != 0 || fl_xattrs(fx, dfd, e) != 0) {
        close(dfd);
        return fx->err[0] ? -1
                          : fl_fail(fx, "chmod dir '%s' failed%s", name, "");
    }
    close(dfd);
    fl_meta(fx, parent, name, e);
    fx->st->dirs++;
    return 0;
}

/*
 * WHAT: Copy a hardlink target when the filesystem refuses linkat.
 * WHY:  Cross-device targets remain representable without leaving partial files.
 * HOW:  Open source before destination, stream bytes, and remove failed output.
 */
static int fl_hardlink_copy(fl_ctx_t *fx, int target_parent,
                            const char *target, int parent, const char *name) {
    int     source = openat(target_parent, target,
                            O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
    int     destination = source < 0 ? -1 :
                          openat(parent, name, O_WRONLY | O_CREAT | O_TRUNC |
                                 O_NOFOLLOW | O_CLOEXEC, 0600);
    int     rc = -1;
    ssize_t got = 0;

    if (source >= 0 && destination >= 0) {
        rc = 0;
        while ((got = read(source, fx->copybuf, sizeof(fx->copybuf))) > 0) {
            if (write(destination, fx->copybuf, (size_t) got) != got) {
                rc = -1;
                break;
            }
            fx->st->bytes += got;
        }
        if (got < 0)
            rc = -1;
    }
    if (source >= 0)
        close(source);
    if (destination >= 0)
        close(destination);
    if (rc != 0 && destination >= 0)
        (void) fl_rm(fx, parent, name);
    return rc;
}

/* Hardlink: resolve the target through the same confined descent, then
 * linkat. A target that cannot be linked degrades to a byte copy. */
static int fl_hardlink(fl_ctx_t *fx, int parent, const char *name,
                       const brix_tar_entry_t *e) {
    char        tbuf[4096];
    const char *tcomps[FL_MAX_COMPS];
    int         tn, tparent;
    int         rc;

    tn = fl_components(fx, e->linkname, tbuf, sizeof(tbuf), tcomps,
                       FL_MAX_COMPS);
    if (tn <= 0)
        return tn == 0 ? fl_fail(fx, "hardlink '%s' targets the root%s",
                                 e->path, "") : -1;
    tparent = fl_descend(fx, tcomps, (size_t) tn - 1);
    if (tparent < 0)
        return -1;
    if (fl_rm(fx, parent, name) != 0) {
        close(tparent);
        return -1;
    }
    rc = linkat(tparent, tcomps[tn - 1], parent, name, 0) == 0 ? 0 :
         fl_hardlink_copy(fx, tparent, tcomps[tn - 1], parent, name);
    if (rc != 0)
        fl_fail(fx, "hardlink '%s' → '%s': target unlinkable and copy failed",
                e->path, e->linkname);
    close(tparent);
    if (rc == 0) {
        int mrc = fchmodat(parent, name, e->mode, 0);
        (void) mrc;                                  /* copy path lands 0600 */
        fl_meta(fx, parent, name, e);
        fx->st->links++;
    }
    return rc;
}

/*
 * WHAT: Materialize a non-whiteout tar entry in its already resolved parent.
 * WHY:  Entry routing and individual filesystem mutations are separate concerns.
 * HOW:  Dispatch regular, directory, symlink, hardlink, and special-file types.
 */
static int fl_materialize(fl_ctx_t *fx, int parent, const char *name,
                          const brix_tar_entry_t *entry) {
    int rc;

    switch (entry->type) {
    case BRIX_TAR_REG:
        return fl_reg(fx, parent, name, entry);
    case BRIX_TAR_DIR:
        return fl_dir(fx, parent, name, entry);
    case BRIX_TAR_SYMLINK:
        rc = fl_rm(fx, parent, name);
        if (rc == 0 && symlinkat(entry->linkname, parent, name) != 0)
            rc = fl_fail(fx, "symlink '%s' failed: %s", name,
                         strerror(errno));
        if (rc == 0) {
            fl_meta(fx, parent, name, entry);
            fx->st->links++;
        }
        return rc;
    case BRIX_TAR_HARDLINK:
        return fl_hardlink(fx, parent, name, entry);
    default:
        if (fx->o->strict)
            return fl_fail(fx, "special file '%s' refused under --strict%s",
                           entry->path, "");
        fx->st->skipped_special++;
        return brix_tar_skip(fx->tar);
    }
}

static int fl_whiteout(fl_ctx_t *fx, int parent, const char *target);
static int fl_opaque(fl_ctx_t *fx, int parent);

/*
 * WHAT: Apply an OCI whiteout, opaque marker, or ordinary materialized entry.
 * WHY:  Overlay control names take precedence over tar entry type semantics.
 * HOW:  Match reserved basenames, skip their bodies, otherwise dispatch type.
 */
static int fl_named_entry(fl_ctx_t *fx, int parent, const char *name,
                          const brix_tar_entry_t *entry) {
    int rc;

    if (strcmp(name, OCI_OPQ_NAME) == 0) {
        rc = fl_opaque(fx, parent);
        return rc == 0 ? brix_tar_skip(fx->tar) : rc;
    }
    if (strncmp(name, OCI_WH_PREFIX, sizeof(OCI_WH_PREFIX) - 1) == 0) {
        rc = fl_whiteout(fx, parent, name + sizeof(OCI_WH_PREFIX) - 1);
        return rc == 0 ? brix_tar_skip(fx->tar) : rc;
    }
    return fl_materialize(fx, parent, name, entry);
}

/* Whiteout: remove the named entry and drop the overlay marker so the
 * DELETE survives into a re-ingest changeset against a published base. */
static int fl_whiteout(fl_ctx_t *fx, int parent, const char *target) {
    char mark[300];
    int  fd, n;

    if (target[0] == '\0' || strcmp(target, ".") == 0 ||
        strcmp(target, "..") == 0 || fl_reserved(target))
        return fl_fail(fx, "refusing whiteout of '%s'%s", target, "");
    n = snprintf(mark, sizeof(mark), FL_WH_PREFIX "%s", target);
    if (n < 0 || (size_t) n >= sizeof(mark) || n > 255)
        return fl_fail(fx, "whiteout marker name too long for '%s'%s",
                       target, "");
    if (fl_rm(fx, parent, target) != 0)
        return -1;
    fd = openat(parent, mark, O_WRONLY | O_CREAT | O_NOFOLLOW | O_CLOEXEC,
                0644);
    if (fd < 0)
        return fl_fail(fx, "cannot drop whiteout marker '%s': %s", mark,
                       strerror(errno));
    close(fd);
    fx->st->whiteouts++;
    return 0;
}

/* Opaque: clear the directory (markers included — the opaque supersedes
 * them) and drop the opaque marker. */
static int fl_opaque(fl_ctx_t *fx, int parent) {
    int            dupfd = dup(parent);
    DIR           *d;
    struct dirent *de;
    int            fd;

    if (dupfd < 0 || (d = fdopendir(dupfd)) == NULL) {
        if (dupfd >= 0)
            close(dupfd);
        return fl_fail(fx, "cannot enumerate opaque dir%s%s", "", "");
    }
    while ((de = readdir(d)) != NULL) {
        if (strcmp(de->d_name, ".") == 0 || strcmp(de->d_name, "..") == 0)
            continue;
        if (fl_rm(fx, dirfd(d), de->d_name) != 0) {
            closedir(d);
            return -1;
        }
    }
    closedir(d);
    fd = openat(parent, FL_OPQ_NAME, O_WRONLY | O_CREAT | O_NOFOLLOW |
                O_CLOEXEC, 0644);
    if (fd < 0)
        return fl_fail(fx, "cannot drop opaque marker: %s%s",
                       strerror(errno), "");
    close(fd);
    fx->st->opaques++;
    return 0;
}

/* One tar entry through the D7.1 translation table. */
static int fl_entry(fl_ctx_t *fx, const brix_tar_entry_t *e) {
    char        buf[4096];
    const char *comps[FL_MAX_COMPS];
    const char *name;
    int         n, parent, rc;

    n = fl_components(fx, e->path, buf, sizeof(buf), comps, FL_MAX_COMPS);
    if (n < 0)
        return -1;
    if (n == 0)             /* the layer root ("./"): nothing to write */
        return brix_tar_skip(fx->tar);

    name = comps[n - 1];
    /* eStargz's own bookkeeping entries, which the format reserves at the
     * archive root only. A lazy-pull snapshotter consumes them and hides
     * them; a publisher that materializes the whole rootfs must drop them,
     * or an eStargz layer flattens to a rootfs its non-stargz original does
     * not have. Dropping them cannot change the layer's diff_id — that is
     * hashed over the decompressed stream before any entry is interpreted.
     * The names come from the TU that WRITES them (stargz.h, D15.8), so the
     * reader and the writer cannot drift on what is reserved. */
    if (n == 1 && brix_stargz_is_meta(name)) {
        fx->st->skipped_toc++;
        return brix_tar_skip(fx->tar);
    }

    parent = fl_descend(fx, comps, (size_t) n - 1);
    if (parent < 0)
        return -1;

    rc = fl_named_entry(fx, parent, name, e);
    close(parent);
    return rc;
}
