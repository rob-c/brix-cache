# xmeta — unified per-file metadata record (stock-cinfo prefix, xattr carrier)

**Date:** 2026-07-02
**Status:** approved (design review with OP; granule + carrier chosen explicitly)

## Problem

A file under cache and/or CSI management today accretes up to four separate
metadata forms on disk:

1. `.cinfo` sidecar — our own `XCI1` v3 format (header + present bitmap +
   dirty extent); **not** byte-compatible with stock XrdPfc.
2. `user.xrd.cinfo` xattr — phase-64 SP2, cache stores only, header-only (no
   bitmap).
3. `.xrdt` CSI tag sidecar — one CRC32C per 4KiB page, under a `/.xrdt`
   prefix tree (per-file sidecars, but perceived as a global checksum list).
4. `user.XrdCks.<alg>` xattr / `.cks` sidecar — whole-file checksum-at-rest.

The OP wants **one form of metadata per file**, stored in an xattr where
possible, whose leading bytes are **byte-compatible with the stock XrdPfc
`.cinfo` format** (`/tmp/xrootd-src/src/XrdPfc/XrdPfcInfo.{hh,cc}`) so stock
tooling can read it, with all of our extra state appended after the stock
payload. CSI checksums move into this per-file record.

## Decisions taken (with OP)

- **CRC granule = cinfo block** (`Store.m_buffer_size`, default 1MiB), not
  4KiB pages. ~4KiB of tags per GiB keeps the whole record inside a 64KiB
  xattr up to ~15GiB files. The per-page `.xrdt` tagstore is retired.
- **Carrier = xattr preferred, sidecar fallback.** One format, two carriers;
  every file has exactly one record. The sidecar fallback is a valid stock
  cinfo file by construction.
- **No migration.** Old `.cinfo`/`.xrdt`/`.cks` are neither read nor written
  after the switch; caches refill, tags regenerate on write/scrub.

## Record format

```
offset 0 — STOCK PREFIX, byte-identical to XrdPfc cinfo v4
  int32   version            (= 4, stock s_defaultVersion)
  Store   POD                (m_buffer_size, m_file_size, m_creationTime,
                              m_noCkSumTime, m_accessCnt, Status, m_astatSize)
                              — written verbatim, native layout, exactly as
                              stock FpHelper::Write(m_store) does
  uint32  crc32c(Store)
  u8[]    present bitmap     (ceil(file_size/buffer_size) bits)
  AStat[] access records     (m_astatSize entries, stock AStat POD)
  uint32  crc32c(bitmap + AStat[])

next byte — EXTENSION, invisible to stock readers (they read sequentially
            and never look past the trailing crc)
  uint32  ext_magic          "XCX1" (0x31584358)
  uint16  ext_version        (= 1)
  uint16  section_count
  section[section_count], each:
    uint16  type
    uint16  reserved         (= 0)
    uint32  payload_len
    u8[payload_len] payload
    uint32  crc32c(type..payload)

section types (ext v1):
  0x0001 STATE     origin_mtime, dirty_lo, dirty_hi, flush_gen, dirty_since,
                   mode, expires_at (the XCI1-v3 fields with no stock slot;
                   origin size/block_size ride the stock Store fields,
                   origin mtime validity lives here)
  0x0002 DIGEST    n × { u16 alg_id, u16 len, u8[len] value } — whole-file
                   checksum(s)-at-rest (replaces .cks / user.XrdCks.*)
  0x0003 BLOCKCRC  uint32 granule (== buffer_size), uint64 nblocks,
                   uint32 crc32c[nblocks]; crc value 0 = "not computed /
                   invalidated" sentinel (paired with stock m_noCkSumTime)
```

Unknown section types are skipped on read (forward compat). Field mapping
from XCI1 v3: `size/block_size` → stock `Store` fields, `mtime` → STATE,
`access_count/bytes_served/last_access` → folded into one merged stock
`AStat` record, present bitmap → stock bitmap, dirty extent/mode/expiry →
STATE.

## Carriers

- **XATTR (preferred):** the record bytes are the value of `user.xrd.cinfo`,
  written below the VFS seam via the SD driver xattr slots (clients cannot
  forge `user.xrd.*` — the VFS maps client attrs to `user.U.*`).
- **SIDECAR (fallback):** identical bytes as the co-located `<file>.cinfo`
  object (staged write). Used when the store lacks xattr capability, or the
  record exceeds the store's effective xattr value cap.
- Effective cap is probed once per store at startup (set/read/remove of a
  probe attr, capped at 64KiB) and cached on the SD instance.
- Exactly one carrier per file. Growth transition: write sidecar first, then
  remove the xattr; readers check xattr first, then sidecar.
- The header-only `cinfo_xattr.c` (SP2) and `.xrdcinfo` sidecar-object mode
  are subsumed by this record and removed.

## CSI on the record (semantic changes — explicit)

- `csi_tagstore`'s read/write-tags engine is re-pointed at the BLOCKCRC
  section with page == block. `.xrdt` files are gone.
- **Read-verify** covers whole blocks only: a read verifies the blocks it
  fully spans; partial-edge blocks are NOT verified on the hot path (covered
  by verify-on-fill and scrub). This is weaker than today's per-page
  verify-every-byte; accepted trade for the xattr-resident record.
- **Writes** immediately zero the touched blocks' CRC slots (+ set
  `m_noCkSumTime` once, stock semantics) and recompute from disk at
  close/flush. The RMW verify-before-partial-write path and the
  strict/`xrootd_csi_loose` distinction collapse and are removed.
- **pgwrite** wire-CRC verification of client 4KiB pages is UNCHANGED
  (INVARIANT 1); stored tags are the folded block CRCs at flush.
- `xrootd_csi_trust_fs` semantics unchanged (skip read-verify; keep tagging).
- New directive `xrootd_csi_block <size>` (default 1m) sets the granule for
  non-cache exports; cache stores use the cache block size so BLOCKCRC and
  the present bitmap share one granule.

## Scope

Everywhere CSI or cache state exists — cache stores get the full record
(bitmap tracks fills); plain origin exports with `xrootd_csi on` (default on)
get the same record with a complete bitmap. One code path.

## Concurrency

Per-file record updates serialize through the existing cache-fill / handle
locks that already serialize block commits; the xattr set is a full-record
last-writer-wins atomic call. The old flock-on-sidecar RMW protocol is
retired with the XCI1 sidecar. Parallel fill workers must merge bitmap +
BLOCKCRC updates under the same lock they already hold for block commit.

## Testing

1. **Format unit test** (standalone, like `csi_unittest.c`): record
   round-trip, unknown-section skip, per-section CRC corruption detection.
2. **Stock cross-check:** a tiny reader built against
   `/tmp/xrootd-src/src/XrdPfc/XrdPfcInfo` parses our record's prefix and
   agrees on version/size/bitmap — proves byte compatibility.
3. **Carrier tests:** xattr round-trip; no-xattr store falls back to sidecar;
   growth past the cap moves xattr → sidecar exactly once; reader precedence.
4. **CSI behavior:** `run_csi_trust.sh` reworked to block granule (stale
   BLOCKCRC fails full-block reads on verify servers, serves under
   trust_fs); write invalidation + flush recompute; pgwrite bad wire-CRC
   still rejected (security-neg).
5. **Cache suite:** partial-fill tests assert exactly one metadata form on
   disk (no `.xrdt`, no `.cks`, no XCI1 `.cinfo`); restart keeps warm state;
   parallel fills lose no bitmap bits.

## Phasing (each lands green)

- **P1** `src/fs/meta/` (new dir — the record spans cache AND CSI, so it
  sits beside `cache/` not inside it): pure-C record codec + carrier layer +
  unit tests + stock cross-check. No consumers yet. New source files ⇒
  `./config` additions + full `./configure` rebuild.
- **P2** Cache switches: cinfo/meta writers+readers → xmeta; XCI1 sidecar,
  SP2 header-xattr, `.xrdcinfo` removed; cache suites green.
- **P3** CSI re-pointed at BLOCKCRC: block-granule verify/invalidate/flush;
  `.xrdt` tagstore, RMW verify, `xrootd_csi_loose` removed;
  `xrootd_csi_block` added; `run_csi_trust.sh` + unittest reworked.
- **P4** DIGEST section: checksum-at-rest (`.cks`/`user.XrdCks`) folded in;
  `xrdcinfo`/`xrdckverify`/scan-engine read the new record; dead code +
  docs sweep.

## Risks / notes

- Stock `Store`/`AStat` PODs are written verbatim (native endian, x86-64
  layout) — same portability contract as stock XrdPfc itself.
- ext4 without `ea_inode` has a ~4KiB total xattr budget: such stores will
  mostly take the sidecar path; that is correct behavior, not an error.
- Block-granule verify is weaker on the read hot path than per-page CSI
  (partial-edge blocks unverified until scrub); verify-on-fill + scrub +
  trust_fs on self-checksumming stores are the compensating controls.
- Files > ~15GiB exceed a 64KiB xattr with 1MiB granule and will ride the
  sidecar carrier; this is expected and invisible to consumers.
