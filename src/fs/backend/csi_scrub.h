#ifndef BRIX_FS_BACKEND_CSI_SCRUB_H
#define BRIX_FS_BACKEND_CSI_SCRUB_H

#include <stdint.h>
#include <sys/types.h>

/*
 * fs/backend/csi_scrub.h — the paced background CSI scrub (phase-59 W2b).
 *
 * WHAT: An at-rest integrity sweep. brix_csi_scrub_file recomputes every
 *       recorded block CRC of one data file against its bytes on disk;
 *       brix_csi_scrub_walk recurses an export root, scrubbing each regular
 *       data file that carries a checksum record. Both accumulate into a
 *       caller-owned stats block and invoke an optional per-mismatch report.
 *
 * WHY:  CSI's hot read path only verifies the blocks a read FULLY spans, so a
 *       corrupt block in cold data is never noticed until something reads it.
 *       A periodic sweep surfaces at-rest rot proactively (metrics + error.log
 *       DIAG) rather than on the unlucky client's read. This is the deferred
 *       W2b half of the CSI workstream.
 *
 * HOW:  Pure engine — no nginx runtime; libc + fs/meta/xmeta + crc32c only, so
 *       it compiles standalone (see tests/c/test_csi_scrub.c). The pacing is
 *       the CALLER's job: brix_csi_scrub_interval arms a per-server maintenance
 *       timer that runs one walk per interval (never a self-rearming hot poll).
 *       A record's own buffer_size is the granule; a slot of 0 (BRIX_XMETA_
 *       CRC_UNSET) is "not computed" and skipped (fail-open on coverage);
 *       a block whose recorded range is short on disk is skipped, never failed
 *       (fail-closed only on an actual CRC difference).
 */

/* Return codes reuse the engine's (csi_tagstore.h): OK / MISMATCH / NOTAGS /
 * ERR. Included transitively; not redefined here. */

typedef struct {
    uint64_t files_scanned;    /* regular files visited                       */
    uint64_t files_tagged;     /* of those, files with a verifiable record    */
    uint64_t blocks_verified;  /* blocks whose recorded CRC was checked        */
    uint64_t blocks_unset;     /* blocks skipped (slot 0 = not computed)       */
    uint64_t blocks_short;     /* blocks skipped (record longer than the file) */
    uint64_t mismatches;       /* corrupt blocks found                         */
    uint64_t errors;           /* files that could not be read / loaded        */
} brix_csi_scrub_stats_t;

/* Per-mismatch callback (NULL = counters only). Called once per corrupt block
 * with the data path, block index, recorded CRC and the CRC computed now. */
typedef void (*brix_csi_scrub_report_fn)(void *u, const char *path,
    uint64_t block, uint32_t want, uint32_t got);

/*
 * Scrub one data file. Loads its checksum record, reads each recorded block
 * back from disk and compares. Returns BRIX_CSI_OK (all set blocks matched),
 * BRIX_CSI_MISMATCH (>= 1 corrupt block, all reported), BRIX_CSI_NOTAGS (no
 * verifiable record — nothing to check) or BRIX_CSI_ERR (unreadable file /
 * hard record error). *st is accumulated (never zeroed) so a caller can total
 * a whole walk; report/u may be NULL.
 */
int  brix_csi_scrub_file(const char *path, brix_csi_scrub_stats_t *st,
    brix_csi_scrub_report_fn report, void *u);

/*
 * Recursively scrub every regular data file under root (same device as root,
 * sidecars skipped). budget > 0 caps the files scanned this call (the pacing
 * knob); budget <= 0 = unlimited. *st is accumulated. Returns the number of
 * regular files scanned this call (0 when root is absent / not a directory).
 */
long brix_csi_scrub_walk(const char *root, brix_csi_scrub_stats_t *st,
    long budget, brix_csi_scrub_report_fn report, void *u);

#endif /* BRIX_FS_BACKEND_CSI_SCRUB_H */
