/* primary/filelists/other XML renderers
 *
 * Extracted from repomd_write.c to hold each translation unit under the
 * 600-line file-size cap. Included by repomd_write.c (one TU); not built
 * standalone. */
static int put_pkg_head(sbuf_t *b, brix_rpm_pkg_t *p) {
    if (sb_put(b, "<package pkgid=\"%s\" name=", brix_rpm_pkgid(p)) != 0 ||
        sb_attr(b, brix_rpm_str(p, BRIX_RPMTAG_NAME)) != 0 ||
        sb_put(b, " arch=") != 0 ||
        sb_attr(b, brix_rpm_str(p, BRIX_RPMTAG_ARCH)) != 0 ||
        sb_put(b, ">\n  <version epoch=\"%u\" ver=", pkg_epoch(p)) != 0 ||
        sb_attr(b, brix_rpm_str(p, BRIX_RPMTAG_VERSION)) != 0 ||
        sb_put(b, " rel=") != 0 ||
        sb_attr(b, brix_rpm_str(p, BRIX_RPMTAG_RELEASE)) != 0 ||
        sb_put(b, "/>\n") != 0)
        return -1;
    return 0;
}

/* One <tag>escaped text</tag> line at the given indent. */
static int put_text_el(sbuf_t *b, const char *indent, const char *tag,
                       const char *text) {
    if (sb_put(b, "%s<%s>", indent, tag) != 0 || sb_text(b, text) != 0 ||
        sb_put(b, "</%s>\n", tag) != 0)
        return -1;
    return 0;
}

/*
 * WHAT: Emit the identifying fields at the start of a primary package record.
 * WHY:  Identity, version, and package checksum form one XML concern.
 * HOW:  Escape tag text and attributes through the shared string-buffer API.
 */
static int put_primary_identity(sbuf_t *b, brix_rpm_pkg_t *p) {
    if (sb_put(b, "<package type=\"rpm\">\n") != 0 ||
        put_text_el(b, "  ", "name", brix_rpm_str(p, BRIX_RPMTAG_NAME)) != 0 ||
        put_text_el(b, "  ", "arch", brix_rpm_str(p, BRIX_RPMTAG_ARCH)) != 0 ||
        sb_put(b, "  <version epoch=\"%u\" ver=", pkg_epoch(p)) != 0 ||
        sb_attr(b, brix_rpm_str(p, BRIX_RPMTAG_VERSION)) != 0 ||
        sb_put(b, " rel=") != 0 ||
        sb_attr(b, brix_rpm_str(p, BRIX_RPMTAG_RELEASE)) != 0 ||
        sb_put(b, "/>\n  <checksum type=\"sha256\" pkgid=\"YES\">%s"
                  "</checksum>\n", brix_rpm_pkgid(p)) != 0)
        return -1;
    return 0;
}

/*
 * WHAT: Emit human-readable primary package description fields.
 * WHY:  These fields share identical escaped text-element formatting.
 * HOW:  Write summary, description, packager, and URL in schema order.
 */
static int put_primary_description(sbuf_t *b, brix_rpm_pkg_t *p) {
    if (put_text_el(b, "  ", "summary",
                    brix_rpm_str(p, BRIX_RPMTAG_SUMMARY)) != 0 ||
        put_text_el(b, "  ", "description",
                    brix_rpm_str(p, BRIX_RPMTAG_DESCRIPTION)) != 0 ||
        put_text_el(b, "  ", "packager",
                    brix_rpm_str(p, BRIX_RPMTAG_PACKAGER)) != 0 ||
        put_text_el(b, "  ", "url", brix_rpm_str(p, BRIX_RPMTAG_URL)) != 0)
        return -1;
    return 0;
}

/*
 * WHAT: Emit package time, size, location, and format-description metadata.
 * WHY:  These scalar fields bridge the primary package and rpm format blocks.
 * HOW:  Read optional RPM values with zero defaults and serialize in order.
 */
static int put_primary_format_head(sbuf_t *b, brix_rpm_pkg_t *p,
                                   const char *href, int64_t mtime) {
    uint32_t buildtime = 0;
    uint32_t installed = 0;
    uint32_t archive = 0;

    (void) brix_rpm_u32(p, BRIX_RPMTAG_BUILDTIME, 0, &buildtime);
    (void) brix_rpm_u32(p, BRIX_RPMTAG_SIZE, 0, &installed);
    (void) brix_rpm_sig_u32(p, BRIX_RPMSIGTAG_PAYLOADSIZE, &archive);
    if (sb_put(b, "  <time file=\"%lld\" build=\"%u\"/>\n",
               (long long) mtime, buildtime) != 0 ||
        sb_put(b, "  <size package=\"%lld\" installed=\"%u\""
                  " archive=\"%u\"/>\n",
               (long long) brix_rpm_size_bytes(p), installed, archive) != 0 ||
        sb_put(b, "  <location href=") != 0 || sb_attr(b, href) != 0 ||
        sb_put(b, "/>\n  <format>\n") != 0 ||
        put_text_el(b, "    ", "rpm:license",
                    brix_rpm_str(p, BRIX_RPMTAG_LICENSE)) != 0 ||
        put_text_el(b, "    ", "rpm:vendor",
                    brix_rpm_str(p, BRIX_RPMTAG_VENDOR)) != 0 ||
        put_text_el(b, "    ", "rpm:group",
                    brix_rpm_str(p, BRIX_RPMTAG_GROUP)) != 0 ||
        put_text_el(b, "    ", "rpm:buildhost",
                    brix_rpm_str(p, BRIX_RPMTAG_BUILDHOST)) != 0 ||
        put_text_el(b, "    ", "rpm:sourcerpm",
                    brix_rpm_str(p, BRIX_RPMTAG_SOURCERPM)) != 0)
        return -1;
    return 0;
}

/*
 * WHAT: Emit the RPM header range and dependency collections.
 * WHY:  Provides/requires use the same nested XML tail and dependency helper.
 * HOW:  Write the range, render both tagged arrays, and close each collection.
 */
static int put_primary_dependencies(sbuf_t *b, brix_rpm_pkg_t *p) {
    int64_t hs;
    int64_t he;

    brix_rpm_header_range(p, &hs, &he);
    if (sb_put(b, "    <rpm:header-range start=\"%lld\" end=\"%lld\"/>\n",
               (long long) hs, (long long) he) != 0 ||
        sb_put(b, "    <rpm:provides>\n") != 0 ||
        put_deps(b, p, BRIX_RPMTAG_PROVIDENAME, BRIX_RPMTAG_PROVIDEFLAGS,
                 BRIX_RPMTAG_PROVIDEVERSION, 0) != 0 ||
        sb_put(b, "    </rpm:provides>\n    <rpm:requires>\n") != 0 ||
        put_deps(b, p, BRIX_RPMTAG_REQUIRENAME, BRIX_RPMTAG_REQUIREFLAGS,
                 BRIX_RPMTAG_REQUIREVERSION, 1) != 0 ||
        sb_put(b, "    </rpm:requires>\n") != 0)
        return -1;
    return 0;
}

/*
 * WHAT: Emit primary-visible sane files and count rejected package paths.
 * WHY:  createrepo includes only executable/configuration paths in primary XML.
 * HOW:  Validate each RPM path, account for rejects, and render visible rows.
 */
static int put_primary_files(sbuf_t *b, brix_rpm_pkg_t *p,
                             uint32_t *skipped) {
    uint32_t nf = brix_rpm_nfiles(p);
    uint32_t i;

    for (i = 0; i < nf; i++) {
        char path[RM_PATH_MAX];

        if (brix_rpm_file(p, i, path, sizeof(path), NULL, NULL) != 0)
            return -1;
        if (!brix_rpm_path_sane(path)) {
            if (skipped != NULL)
                (*skipped)++;
            continue;
        }
        if (primary_file_visible(path) &&
            put_text_el(b, "    ", "file", path) != 0)
            return -1;
    }
    return 0;
}

/*
 * WHAT: Render one complete package record for primary.xml.
 * WHY:  The schema requires identity, description, format, deps, then files.
 * HOW:  Compose the focused emitters and append the closing XML elements.
 */
static int render_primary(sbuf_t *b, brix_rpm_pkg_t *p, const char *href,
                          int64_t mtime, uint32_t *skipped) {
    if (put_primary_identity(b, p) != 0 ||
        put_primary_description(b, p) != 0 ||
        put_primary_format_head(b, p, href, mtime) != 0 ||
        put_primary_dependencies(b, p) != 0 ||
        put_primary_files(b, p, skipped) != 0)
        return -1;
    return sb_put(b, "  </format>\n</package>\n");
}

static int render_filelists(sbuf_t *b, brix_rpm_pkg_t *p) {
    uint32_t nf = brix_rpm_nfiles(p);
    uint32_t i;

    if (put_pkg_head(b, p) != 0)
        return -1;
    for (i = 0; i < nf; i++) {
        char     path[RM_PATH_MAX];
        uint32_t mode = 0;
        int      ghost = 0;

        if (brix_rpm_file(p, i, path, sizeof(path), &mode, &ghost) != 0)
            return -1;
        if (!brix_rpm_path_sane(path))
            continue;    /* counted once, in render_primary */
        if (sb_put(b, "  <file%s>",
                   S_ISDIR((mode_t) mode) ? " type=\"dir\""
                   : ghost               ? " type=\"ghost\"" : "") != 0 ||
            sb_text(b, path) != 0 || sb_put(b, "</file>\n") != 0)
            return -1;
    }
    return sb_put(b, "</package>\n");
}

static int render_other(sbuf_t *b, brix_rpm_pkg_t *p) {
    uint32_t n = brix_rpm_count(p, BRIX_RPMTAG_CHANGELOGTIME);
    uint32_t i;

    if (put_pkg_head(b, p) != 0)
        return -1;
    for (i = 0; i < n; i++) {
        const char *who  = brix_rpm_stra(p, BRIX_RPMTAG_CHANGELOGNAME, i);
        const char *text = brix_rpm_stra(p, BRIX_RPMTAG_CHANGELOGTEXT, i);
        uint32_t    when = 0;

        if (who == NULL || text == NULL ||
            brix_rpm_u32(p, BRIX_RPMTAG_CHANGELOGTIME, i, &when) != 0)
            break;    /* ragged arrays: stop at the shortest, like zip() */
        if (sb_put(b, "  <changelog author=") != 0 || sb_attr(b, who) != 0 ||
            sb_put(b, " date=\"%u\">", when) != 0 || sb_text(b, text) != 0 ||
            sb_put(b, "</changelog>\n") != 0)
            return -1;
    }
    return sb_put(b, "</package>\n");
}
