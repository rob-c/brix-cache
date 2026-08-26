/* TAR header/field parsing + entry building (the parse layer)
 *
 * Extracted from tar.c to hold each translation unit under the
 * 600-line file-size cap. Included by tar.c (one TU); not built
 * standalone. */
static int tar_discard(brix_tar_t *t, int64_t n) {
    while (n > 0) {
        size_t step = n > (int64_t) sizeof(t->body) ? sizeof(t->body)
                                                    : (size_t) n;
        int rc = brix_tar_fill(t, t->body, step);

        if (rc <= 0)
            return rc < 0 ? -1
                          : brix_tar_fail(t, "truncated archive body");
        n -= (int64_t) step;
    }
    return 0;
}

/* ---- header field parsing ------------------------------------------------ */

/*
 * WHAT: Decode a GNU base-256 signed tar number.
 * WHY:  GNU writers use this representation for values outside octal fields.
 * HOW:  Sign-extend the high byte and reject positive int64 overflow.
 */
static int tar_num_binary(const unsigned char *f, size_t n, int64_t *out) {
    uint64_t v   = f[0] & 0x7f;
    int      neg = (f[0] & 0x40) != 0;
    size_t   i;

    if (neg)
        v |= ~(uint64_t) 0x7f;
    for (i = 1; i < n; i++) {
        if (!neg && v > (uint64_t) INT64_MAX >> 8)
            return -1;
        v = (v << 8) | f[i];
    }
    if (!neg && (int64_t) v < 0)
        return -1;
    *out = (int64_t) v;
    return 0;
}

/*
 * WHAT: Decode a space/NUL-padded POSIX octal tar number.
 * WHY:  Standard tar fields permit leading spaces and two trailing paddings.
 * HOW:  Skip the prefix, accumulate checked octal digits, then validate tail.
 */
static int tar_num_octal(const unsigned char *f, size_t n, int64_t *out) {
    uint64_t v = 0;
    size_t   i = 0;

    while (i < n && f[i] == ' ')
        i++;
    for (; i < n && f[i] >= '0' && f[i] <= '7'; i++) {
        if (v > (uint64_t) INT64_MAX >> 3)
            return -1;
        v = (v << 3) | (uint64_t) (f[i] - '0');
    }
    while (i < n && (f[i] == ' ' || f[i] == '\0'))
        i++;
    if (i != n)
        return -1;
    *out = (int64_t) v;
    return 0;
}

/*
 * WHAT: Decode either standard octal or GNU base-256 header numbers.
 * WHY:  Callers need one strict numeric-field contract for both tar dialects.
 * HOW:  Detect GNU's high-bit marker and delegate to the matching decoder.
 */
static int tar_num(const unsigned char *f, size_t n, int64_t *out) {
    if (n > 0 && (f[0] & 0x80))
        return tar_num_binary(f, n, out);
    return tar_num_octal(f, n, out);
}

/* Verify the header checksum: unsigned byte sum with the chksum field read
 * as spaces; tolerate the historical signed-sum variant. 0 ok / -1. */
static int tar_cksum_ok(const unsigned char *h) {
    unsigned usum = 0;
    long     ssum = 0;
    int64_t  want;
    size_t   i;

    if (tar_num(h + 148, 8, &want) != 0)
        return -1;
    for (i = 0; i < 512; i++) {
        unsigned char c = (i >= 148 && i < 156) ? (unsigned char) ' ' : h[i];

        usum += c;
        ssum += (signed char) c;
    }
    return ((int64_t) usum == want || (int64_t) ssum == want) ? 0 : -1;
}

/* Copy a fixed header text field, stopping at NUL, always terminating. */
static void tar_str(const unsigned char *f, size_t n, char *out, size_t outsz) {
    size_t len = 0;

    while (len < n && f[len] != '\0')
        len++;
    if (len >= outsz)
        len = outsz - 1;
    memcpy(out, f, len);
    out[len] = '\0';
}

static int hdr_is_zero(const unsigned char *h) {
    size_t i;

    for (i = 0; i < 512; i++)
        if (h[i] != 0)
            return 0;
    return 1;
}

/* ---- entry assembly ------------------------------------------------------ */

/* Join ustar prefix+name, honoring pax/GNU overrides (per-file, then global,
 * then the raw header). 0 ok / -1 (too long / empty). */
static int entry_path(brix_tar_t *t, int posix_magic, brix_tar_entry_t *e) {
    if (t->next.have_path) {
        memcpy(e->path, t->next.path, sizeof(e->path));
    } else if (t->glob.have_path) {
        memcpy(e->path, t->glob.path, sizeof(e->path));
    } else {
        char name[101], prefix[156];

        tar_str(t->hdr, 100, name, sizeof(name));
        tar_str(t->hdr + 345, 155, prefix, sizeof(prefix));
        if (posix_magic && prefix[0] != '\0') {
            int n = snprintf(e->path, sizeof(e->path), "%s/%s", prefix, name);

            if (n < 0 || (size_t) n >= sizeof(e->path))
                return brix_tar_fail(t, "entry path exceeds 4095 bytes");
        } else {
            memcpy(e->path, name, sizeof(name));
        }
    }
    if (e->path[0] == '\0')
        return brix_tar_fail(t, "entry with empty path");
    return 0;
}

/*
 * WHAT: Map a supported tar typeflag onto the public entry type.
 * WHY:  Entry assembly should not mix type dispatch with field parsing.
 * HOW:  Translate every POSIX real-entry flag and reject metadata flags.
 */
static int entry_type(brix_tar_t *t, unsigned char typeflag,
                      brix_tar_entry_t *e) {
    switch (typeflag) {
    case '0': case '\0': case '7': e->type = BRIX_TAR_REG;      break;
    case '1':                      e->type = BRIX_TAR_HARDLINK; break;
    case '2':                      e->type = BRIX_TAR_SYMLINK;  break;
    case '3':                      e->type = BRIX_TAR_CHR;      break;
    case '4':                      e->type = BRIX_TAR_BLK;      break;
    case '5':                      e->type = BRIX_TAR_DIR;      break;
    case '6':                      e->type = BRIX_TAR_FIFO;     break;
    default:
        return brix_tar_fail(t, "internal: unmapped typeflag %d", typeflag);
    }
    return 0;
}

/*
 * WHAT: Resolve a link target from per-file, global, or raw-header metadata.
 * WHY:  Pax and GNU overrides have defined precedence over the ustar field.
 * HOW:  Copy the highest-precedence available representation into the entry.
 */
static void entry_link(brix_tar_t *t, brix_tar_entry_t *e) {
    if (t->next.have_link)
        memcpy(e->linkname, t->next.linkname, sizeof(e->linkname));
    else if (t->glob.have_link)
        memcpy(e->linkname, t->glob.linkname, sizeof(e->linkname));
    else
        tar_str(t->hdr + 157, 100, e->linkname, sizeof(e->linkname));
}

/*
 * WHAT: Decode mode, uid, and gid into a tar entry.
 * WHY:  Ownership fields share override precedence but require distinct errors.
 * HOW:  Apply per-file/global values first and parse raw numeric fields last.
 */
static int entry_permissions(brix_tar_t *t, brix_tar_entry_t *e) {
    int64_t v;

    if (tar_num(t->hdr + 100, 8, &v) != 0)
        return brix_tar_fail(t, "bad mode field on %s", e->path);
    e->mode = (mode_t) (v & 07777);

    if (t->next.have_uid)
        e->uid = (uid_t) t->next.uid;
    else if (t->glob.have_uid)
        e->uid = (uid_t) t->glob.uid;
    else if (tar_num(t->hdr + 108, 8, &v) == 0)
        e->uid = (uid_t) v;
    else
        return brix_tar_fail(t, "bad uid field on %s", e->path);

    if (t->next.have_gid)
        e->gid = (gid_t) t->next.gid;
    else if (t->glob.have_gid)
        e->gid = (gid_t) t->glob.gid;
    else if (tar_num(t->hdr + 116, 8, &v) == 0)
        e->gid = (gid_t) v;
    else
        return brix_tar_fail(t, "bad gid field on %s", e->path);
    return 0;
}

/*
 * WHAT: Resolve entry modification time and effective body size.
 * WHY:  Pax overrides and non-regular size semantics must be applied together.
 * HOW:  Resolve fields by precedence, reject negatives, then set body padding.
 */
static int entry_extent(brix_tar_t *t, brix_tar_entry_t *e) {
    int64_t v;

    if (t->next.have_mtime)
        e->mtime = t->next.mtime;
    else if (t->glob.have_mtime)
        e->mtime = t->glob.mtime;
    else if (tar_num(t->hdr + 136, 12, &v) == 0)
        e->mtime = v;
    else
        return brix_tar_fail(t, "bad mtime field on %s", e->path);

    if (t->next.have_size)
        v = t->next.size;
    else if (t->glob.have_size)
        v = t->glob.size;
    else if (tar_num(t->hdr + 124, 12, &v) != 0)
        return brix_tar_fail(t, "bad size field on %s", e->path);
    if (v < 0)
        return brix_tar_fail(t, "negative size on %s", e->path);

    /* POSIX ignores size metadata on non-regular entries. */
    e->size      = (e->type == BRIX_TAR_REG) ? v : 0;
    t->remaining = e->size;
    t->pad       = (size_t) ((512 - (e->size % 512)) % 512);
    return 0;
}

/*
 * WHAT: Decode device numbers for character and block entries.
 * WHY:  Other entry types must ignore device fields that writers may populate.
 * HOW:  Parse major/minor only for device types and combine them with makedev.
 */
static int entry_device(brix_tar_t *t, brix_tar_entry_t *e) {
    int64_t maj;
    int64_t min;

    if (e->type != BRIX_TAR_CHR && e->type != BRIX_TAR_BLK)
        return 0;
    if (tar_num(t->hdr + 329, 8, &maj) != 0 ||
        tar_num(t->hdr + 337, 8, &min) != 0)
        return brix_tar_fail(t, "bad device numbers on %s", e->path);
    e->rdev = makedev((unsigned) maj, (unsigned) min);
    return 0;
}

/*
 * WHAT: Pack accumulated pax extended attributes onto an entry.
 * WHY:  Consumers require one bounded stable blob rather than parser arrays.
 * HOW:  Pack only non-empty sets and expose the resulting internal buffer.
 */
static int entry_xattrs(brix_tar_t *t, brix_tar_entry_t *e) {
    int packed;

    if (t->xcount == 0)
        return 0;
    packed = cvmfs_xattr_pack(t->xkeys, t->xvals, t->xlens, t->xcount,
                              t->xblob, sizeof(t->xblob));
    if (packed < 0)
        return brix_tar_fail(t, "xattr set on %s exceeds pack bounds",
                             e->path);
    e->xattr     = (const char *) t->xblob;
    e->xattr_len = (size_t) packed;
    return 0;
}

/*
 * WHAT: Map one verified real-entry header and its overrides onto an entry.
 * WHY:  Callers need fully resolved metadata before any body bytes are exposed.
 * HOW:  Assemble type, path, link, ownership, extent, device, and xattrs.
 */
static int entry_build(brix_tar_t *t, unsigned char typeflag,
                       brix_tar_entry_t *e) {
    int posix_magic = memcmp(t->hdr + 257, "ustar\0", 6) == 0;

    memset(e, 0, sizeof(*e));
    if (entry_type(t, typeflag, e) != 0)
        return -1;

    if (entry_path(t, posix_magic, e) != 0)
        return -1;
    entry_link(t, e);
    if (entry_permissions(t, e) != 0 || entry_extent(t, e) != 0 ||
        entry_device(t, e) != 0 || entry_xattrs(t, e) != 0)
        return -1;
    return 0;
}

/* Read a metadata body ('x'/'g' pax, 'L'/'K' GNU-long) of claimed `size`
 * into t->pax (with its 512-pad), bounds-checked. 0 ok / -1. */
static int meta_body(brix_tar_t *t, int64_t size, size_t cap) {
    if (size < 0 || (uint64_t) size > cap)
        return brix_tar_fail(t, "oversized metadata entry (%lld bytes)",
                             (long long) size);
    if (size > 0 && brix_tar_fill(t, t->pax, (size_t) size) != 1)
        return -1;
    return tar_discard(t, (int64_t) ((512 - (size % 512)) % 512));
}

/* Take a GNU 'L' (longname) / 'K' (longlink) body into the per-file
 * override. The body is a NUL-padded string. */
static int gnu_long(brix_tar_t *t, int64_t size, int is_link) {
    char  *dst    = is_link ? t->next.linkname : t->next.path;
    size_t dstcap = 4096;
    size_t len;

    if (meta_body(t, size, dstcap + 512) != 0)
        return -1;
    len = (size_t) size;
    while (len > 0 && t->pax[len - 1] == '\0')
        len--;
    if (len >= dstcap)
        return brix_tar_fail(t, "GNU long %s exceeds 4095 bytes",
                             is_link ? "linkname" : "name");
    memcpy(dst, t->pax, len);
    dst[len] = '\0';
    if (is_link) t->next.have_link = 1; else t->next.have_path = 1;
    return 0;
}

/*
 * WHAT: Close the previously returned entry before reading another header.
 * WHY:  The API requires callers to consume bodies while tar padding is ours.
 * HOW:  Reject unread body bytes, discard padding, and clear entry state.
 */
static int entry_finish(brix_tar_t *t) {
    if (t->have_entry && t->remaining > 0)
        return brix_tar_fail(t, "API misuse: current body not fully consumed "
                             "(%lld bytes left)", (long long) t->remaining);
    if (!t->have_entry)
        return 0;
    if (tar_discard(t, (int64_t) t->pad) != 0)
        return -1;
    t->pad        = 0;
    t->have_entry = 0;
    return 0;
}

/*
 * WHAT: Read and validate the next non-terminal 512-byte tar header.
 * WHY:  End markers and checksums must be settled before type dispatch.
 * HOW:  Read one block, validate the optional second zero block, then checksum.
 */
static int header_next(brix_tar_t *t) {
    int rc = brix_tar_fill(t, t->hdr, 512);

    if (rc <= 0)
        return rc;
    if (!hdr_is_zero(t->hdr)) {
        if (tar_cksum_ok(t->hdr) != 0)
            return brix_tar_fail(t, "header checksum mismatch");
        return 1;
    }
    rc = brix_tar_fill(t, t->hdr, 512);
    if (rc < 0)
        return -1;
    if (rc == 0 || hdr_is_zero(t->hdr))
        return 0;
    return brix_tar_fail(t, "data after end-of-archive marker");
}

/*
 * WHAT: Consume and apply a pax per-file or global metadata entry.
 * WHY:  Pax records affect the following real header but are not entries.
 * HOW:  Parse its size, read its padded body, and apply the selected scope.
 */
static int metadata_pax(brix_tar_t *t, unsigned char typeflag) {
    int64_t size;

    if (tar_num(t->hdr + 124, 12, &size) != 0)
        return brix_tar_fail(t, "bad pax header size");
    if (meta_body(t, size, sizeof(t->pax)) != 0)
        return -1;
    return brix_tar_pax_apply(t, (size_t) size, typeflag == 'g');
}

/*
 * WHAT: Consume a GNU long-name or long-link metadata entry.
 * WHY:  GNU tar stores oversized text fields immediately before real entries.
 * HOW:  Parse the body size and install it as the matching per-file override.
 */
static int metadata_gnu_long(brix_tar_t *t, unsigned char typeflag) {
    int64_t size;

    if (tar_num(t->hdr + 124, 12, &size) != 0)
        return brix_tar_fail(t, "bad GNU long-header size");
    return gnu_long(t, size, typeflag == 'K');
}

/*
 * WHAT: Determine whether a typeflag represents a supported real entry.
 * WHY:  Metadata and extension records must never surface as filesystem data.
 * HOW:  Accept the NUL regular-file flag or a POSIX real-entry digit.
 */
static int typeflag_is_entry(unsigned char typeflag) {
    return typeflag == '\0' || strchr("01234567", typeflag) != NULL;
}

/*
 * WHAT: Consume an unsupported extension entry without surfacing it.
 * WHY:  Unknown records may be followed by valid entries and cannot end a walk.
 * HOW:  Validate size, discard body plus padding, and clear per-file overrides.
 */
static int metadata_unknown(brix_tar_t *t, unsigned char typeflag) {
    int64_t size;

    if (tar_num(t->hdr + 124, 12, &size) != 0 || size < 0)
        return brix_tar_fail(t, "bad size on unknown typeflag %d", typeflag);
    if (tar_discard(t, size + (512 - (size % 512)) % 512) != 0)
        return -1;
    brix_tar_pax_reset_next(t);
    return 0;
}
