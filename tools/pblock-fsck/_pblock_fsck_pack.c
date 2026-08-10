/* _pblock_fsck_pack.c — phase-88 W2: the packed small-blob arena legs of
 * pblock-fsck. Do not compile directly; it is #include'd by pblock-fsck.c
 * (the tool's contract stays `cc pblock-fsck.c -lsqlite3`, single file).
 *
 * WHAT: (a) pack_row_len — the probe check_rows uses to recognise a PACKED
 *       blob's resting state (no blob dir is NOT dangling when a pack row
 *       exists); (b) check_pack — verify every pack row's segment record
 *       (header shape always; data crc under --verify-csi), report orphan
 *       rows / dual-layout blobs / orphan records / torn tails, and under
 *       --gc reclaim orphan rows, redundant striped copies and record-less
 *       segments (the runtime reaper's offline twin). Also hosts usage()
 *       (relocated from the main file to keep it inside the size gate).
 *
 * Record layout is single-sourced from shared/cache/cas_pack_format.h (the
 * "BXS1" record both packed stores write); the data crc is zlib's CRC-32,
 * re-implemented bit-by-bit below so the tool keeps its -lsqlite3-only link
 * (same self-containment stance as the local crc32c above).
 */

#include "../../shared/cache/cas_pack_format.h"

/* table_present — opt-in tables (csi, usage, pack) only exist on exports that
 * armed the matching feature; absence is not a finding, just "nothing to
 * verify". (Relocated from the main TU with usage() — size discipline.) */
static int
table_present(sqlite3 *db, const char *name)
{
    sqlite3_stmt *st;
    int           found = 0;

    if (sqlite3_prepare_v2(db,
            "SELECT 1 FROM sqlite_master WHERE type='table' AND name=?1;",
            -1, &st, NULL) != SQLITE_OK) {
        return 0;
    }
    sqlite3_bind_text(st, 1, name, -1, SQLITE_STATIC);
    found = (sqlite3_step(st) == SQLITE_ROW);
    sqlite3_finalize(st);
    return found;
}

/* crc32_ieee — zlib-compatible CRC-32 (reflected, poly 0xEDB88320,
 * init/final 0xFFFFFFFF): must equal crc_of() on the same bytes. */
static uint32_t
crc32_ieee(const unsigned char *p, size_t n)
{
    uint32_t crc = 0xFFFFFFFFu;
    int      k;

    while (n--) {
        crc ^= *p++;
        for (k = 0; k < 8; k++) {
            crc = (crc >> 1) ^ (0xEDB88320u & (uint32_t) -(int) (crc & 1));
        }
    }
    return crc ^ 0xFFFFFFFFu;
}

/* pack_row_len — the pack table's recorded data length for `blob`, or -1 when
 * the blob is not packed (absent table counts as not packed). */
static long long
pack_row_len(sqlite3 *db, const char *blob)
{
    sqlite3_stmt *st;
    long long     len = -1;

    if (!table_present(db, "pack")) {
        return -1;
    }
    if (sqlite3_prepare_v2(db, "SELECT len FROM pack WHERE blob_id = ?1;",
                           -1, &st, NULL) != SQLITE_OK)
    {
        return -1;
    }
    sqlite3_bind_text(st, 1, blob, -1, SQLITE_STATIC);
    if (sqlite3_step(st) == SQLITE_ROW) {
        len = sqlite3_column_int64(st, 0);
    }
    sqlite3_finalize(st);
    return len;
}

/* pack_seg_file — "<root>/pack/seg-<n>.dat" (mirrors pblock_pack.c). */
static void
pack_seg_file(const char *root, long long seg, char *out, size_t cap)
{
    snprintf(out, cap, "%s/pack/seg-%lld.dat", root, seg);
}

/* pack_drop_striped — remove a blob's redundant striped copy (block files +
 * dir) after its packed record was verified present: the --gc action for a
 * dual-layout blob (a crash between the arena append and the block removal). */
static void
pack_drop_striped(const char *root, const char *blob)
{
    char           leaf[PATH_MAX];
    char           sub[PATH_MAX + 264];
    DIR           *d;
    struct dirent *e;

    blob_dir(root, blob, leaf, sizeof(leaf));
    d = opendir(leaf);
    if (d != NULL) {
        while ((e = readdir(d)) != NULL) {
            if (e->d_name[0] == '.') {
                continue;
            }
            if (snprintf(sub, sizeof(sub), "%s/%s", leaf, e->d_name)
                < (int) sizeof(sub))
            {
                unlink(sub);
            }
        }
        closedir(d);
    }
    rmdir(leaf);
}

/* pack_check_rows — pass A: verify each pack row against its segment record.
 * Header shape always; data crc only under --verify-csi (a full read of every
 * packed object, the same opt-in cost class as the csi block re-CRC). */
static int
pack_check_rows(sqlite3 *db, const struct opts *o, const struct blobset *bs)
{
    sqlite3_stmt *st;
    int           rc;

    rc = sqlite3_prepare_v2(db,
        "SELECT blob_id, seg, off, len FROM pack;", -1, &st, NULL);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "pblock-fsck: query pack: %s\n", sqlite3_errmsg(db));
        return 2;
    }
    while ((rc = sqlite3_step(st)) == SQLITE_ROW) {
        const char *blob = (const char *) sqlite3_column_text(st, 0);
        long long   seg  = sqlite3_column_int64(st, 1);
        long long   off  = sqlite3_column_int64(st, 2);
        long long   len  = sqlite3_column_int64(st, 3);
        char        segp[PATH_MAX], leaf[PATH_MAX];
        unsigned char    hdr[SEG_HDR + PACK_KMAX];
        brix_pack_rec_t  rec;
        size_t      klen;
        FILE       *f;
        int         bad = 0;

        if (blob == NULL || blob[0] == '\0') {
            continue;
        }
        klen = strlen(blob);

        /* Orphan row: no live objects/history referrer holds this blob. */
        if (!blobset_has(bs, blob)) {
            printf("PACK-ORPHAN-ROW %s\n", blob);
            g_findings++;
            if (o->gc) {
                char *ds = sqlite3_mprintf(
                    "DELETE FROM pack WHERE blob_id = %Q;", blob);
                sqlite3_exec(db, ds, NULL, NULL, NULL);
                sqlite3_free(ds);
            }
            continue;
        }

        pack_seg_file(o->root, seg, segp, sizeof(segp));
        f = fopen(segp, "rb");
        if (f == NULL) {
            printf("PACK %s seg=%lld missing-segment\n", blob, seg);
            g_findings++;
            continue;               /* data loss — report, never mutate */
        }
        if (klen == 0 || klen > PACK_KMAX
            || fseek(f, (long) off, SEEK_SET) != 0
            || fread(hdr, 1, SEG_HDR + klen, f) != SEG_HDR + klen
            || brix_pack_seg_decode(hdr, &rec) != 0
            || rec.klen != klen
            || rec.fmt != 0
            || rec.stored != rec.raw
            || (long long) rec.raw != len
            || memcmp(hdr + SEG_HDR, blob, klen) != 0)
        {
            printf("PACK %s seg=%lld off=%lld bad-record\n", blob, seg, off);
            g_findings++;
            bad = 1;
        }
        if (!bad && o->verify_csi && rec.stored > 0) {
            unsigned char *data = malloc((size_t) rec.stored);

            if (data != NULL
                && (fread(data, 1, (size_t) rec.stored, f)
                        != (size_t) rec.stored
                    || crc32_ieee(data, (size_t) rec.stored) != rec.crc))
            {
                printf("PACK %s seg=%lld crc\n", blob, seg);
                g_findings++;
            }
            free(data);
        }
        fclose(f);

        /* Dual layout: the striped copy the admit crash left behind. */
        blob_dir(o->root, blob, leaf, sizeof(leaf));
        if (!bad && is_dir(leaf)) {
            printf("PACK %s dual-layout\n", blob);
            g_findings++;
            if (o->gc) {
                pack_drop_striped(o->root, blob);
            }
        }
    }
    sqlite3_finalize(st);
    return rc == SQLITE_DONE ? 0 : 2;
}

/* pack_seg_rows — live pack rows referencing segment `seg`. */
static long long
pack_seg_rows(sqlite3 *db, long long seg)
{
    sqlite3_stmt *st;
    long long     n = -1;

    if (sqlite3_prepare_v2(db,
            "SELECT COUNT(*) FROM pack WHERE seg = ?1;", -1, &st, NULL)
        != SQLITE_OK)
    {
        return -1;
    }
    sqlite3_bind_int64(st, 1, seg);
    if (sqlite3_step(st) == SQLITE_ROW) {
        n = sqlite3_column_int64(st, 0);
    }
    sqlite3_finalize(st);
    return n;
}

/* pack_check_segments — pass B: walk each segment's records front to back.
 * A record no row indexes is crash residue (report; space returns when its
 * whole segment dies); a torn tail is reported; a segment with zero live rows
 * is reclaimed whole under --gc (the runtime reaper's offline twin). */
static int
pack_check_segments(sqlite3 *db, const struct opts *o)
{
    char           dirp[PATH_MAX];
    DIR           *d;
    struct dirent *e;

    snprintf(dirp, sizeof(dirp), "%s/pack", o->root);
    d = opendir(dirp);
    if (d == NULL) {
        return 0;                   /* no arena dir — nothing to walk */
    }
    while ((e = readdir(d)) != NULL) {
        long long seg;
        char      segp[PATH_MAX];
        FILE     *f;
        long long pos = 0, fsz;

        if (sscanf(e->d_name, "seg-%lld.dat", &seg) != 1) {
            continue;
        }
        pack_seg_file(o->root, seg, segp, sizeof(segp));
        f = fopen(segp, "rb");
        if (f == NULL) {
            continue;
        }
        fseek(f, 0, SEEK_END);
        fsz = ftell(f);

        while (pos + (long long) SEG_HDR <= fsz) {
            unsigned char    hdr[SEG_HDR + PACK_KMAX];
            brix_pack_rec_t  rec;
            char             key[PACK_KMAX + 1];
            sqlite3_stmt    *st;
            int              indexed = 0;

            if (fseek(f, (long) pos, SEEK_SET) != 0
                || fread(hdr, 1, SEG_HDR, f) != SEG_HDR
                || brix_pack_seg_decode(hdr, &rec) != 0
                || pos + (long long) (SEG_HDR + rec.klen)
                       + (long long) rec.stored > fsz
                || fread(hdr + SEG_HDR, 1, rec.klen, f) != rec.klen)
            {
                printf("PACK-TORN seg=%lld off=%lld\n", seg, pos);
                g_findings++;
                break;
            }
            memcpy(key, hdr + SEG_HDR, rec.klen);
            key[rec.klen] = '\0';

            if (sqlite3_prepare_v2(db,
                    "SELECT 1 FROM pack WHERE blob_id = ?1 AND seg = ?2"
                    " AND off = ?3;", -1, &st, NULL) == SQLITE_OK)
            {
                sqlite3_bind_text(st, 1, key, -1, SQLITE_STATIC);
                sqlite3_bind_int64(st, 2, seg);
                sqlite3_bind_int64(st, 3, pos);
                indexed = sqlite3_step(st) == SQLITE_ROW;
                sqlite3_finalize(st);
            }
            if (!indexed) {
                printf("PACK-ORPHAN-REC seg=%lld off=%lld bytes=%lld\n",
                       seg, pos,
                       (long long) (SEG_HDR + rec.klen) + (long long) rec.stored);
                g_findings++;
            }
            pos += (long long) (SEG_HDR + rec.klen) + (long long) rec.stored;
        }
        fclose(f);

        if (o->gc && pack_seg_rows(db, seg) == 0) {
            unlink(segp);           /* record-less segment — reclaim whole */
        }
    }
    closedir(d);
    return 0;
}

/* check_pack — the arena consistency pass (no-op on exports without it). */
static int
check_pack(sqlite3 *db, const struct opts *o, const struct blobset *bs)
{
    int rc;

    if (!table_present(db, "pack")) {
        return 0;
    }
    rc = pack_check_rows(db, o, bs);
    if (rc != 0) {
        return rc;
    }
    return pack_check_segments(db, o);
}

/* usage — relocated here verbatim (file-size discipline in the main TU). */
static void
usage(void)
{
    fprintf(stderr,
        "usage: pblock-fsck <export-root> [--gc [--trash-ttl <secs>]] [--repair]"
        " [--verify-csi] [--verify-usage] [--verify-refs]\n"
        "       pblock-fsck <export-root> --snapshot <name> | --restore <name>\n"
        "       pblock-fsck <export-root> --list-versions <path> | --list-trash"
        " | --undelete <path>\n"
        "       pblock-fsck <fresh-export-root> --replay <source-catalog.db>\n"
        "  cross-check catalog.db against the block store + the packed arena,"
        " take/restore an F6 snapshot, inspect/recover F11 versions + trash, or"
        " re-execute a source oplog (F17) against a fresh export and diff the"
        " end-state.\n"
        "  --gc --trash-ttl <secs> also purges trash entries older than <secs>"
        " (0 = all).\n"
        "  exit: 0 clean, 1 findings, 2 error, 3 refused (unknown schema/name)\n");
}
