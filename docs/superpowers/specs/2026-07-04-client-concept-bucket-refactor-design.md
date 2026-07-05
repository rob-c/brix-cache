# Design: refactor `client/` into concept buckets like `src/`

**Date:** 2026-07-04
**Status:** IMPLEMENTED 2026-07-04 (working tree; not committed — per OP "without git")
**Type:** behavior-identical structural refactor (file relocation + include/Makefile plumbing)

## Implementation outcome

- Move map recorded in [`docs/refactor/phase-69-client-map.tsv`](../../refactor/phase-69-client-map.tsv) (158 rows).
- `client/lib/` (106 files) → concept buckets; `client/apps/` (52 files) → 7 tool families.
- Includes: 27 cross-bucket `#include` directives rewritten root-relative + 5 stale
  `../` relative includes in the former `sec/` fixed; same-bucket stayed bare.
- Makefile: `LIB_SRCS` regenerated; the five per-app split rules + generic link rule
  collapsed into one `.SECONDEXPANSION` static-pattern rule driven by `<name>_OBJS`
  variables; xrootdfs FUSE rules and `clean` glob repathed.
- Seam guard `tools/ci/check_vfs_seam.sh` CLIENT tier + `vfs_seam_backlog_client.txt`
  repathed to the new `client/lib/fs/...` locations.
- **Deviation from §4:** `xrd_mount.c` stays with the `xrd` family in `apps/diag/`
  (not `apps/fs/`) to keep the Phase-38 split family co-located — it is linked only
  into `xrd`, so splitting it into another dir would fragment one binary's sources.
- **Verification:** from-scratch `make clean && make && make lib` is green (exit 0,
  0 error lines) — `libbrix.{a,so}` + preload + all 19 CLIs + FUSE `xrootdfs`;
  `libbrix.a` is byte-size-identical to pre-refactor (687570) confirming rename-only;
  seam-guard CLIENT tier green; 4/5 client C test consumers link (the 5th,
  `tests/c/aio_mfile.c`, is a **pre-existing** stale-test `brix_mgr_create` arity
  mismatch, unrelated to relocation). The server-tier seam-guard finding
  (`src/protocols/root/read/clone.c`) is likewise **pre-existing** (no `src/` change).

---

## 1. Problem & goal

`client/lib/` is a flat directory of ~80 `.c` files plus a `sec/` subdir and 22
headers — the native `libbrix` XRootD client (root:// + HTTP/S3/WebDAV, libXrdCl-free).
`client/apps/` is a similarly flat directory of ~40 CLI-tool translation units.
Meanwhile `src/` (the server) is organized into seven concept buckets
(`core/ auth/ fs/ net/ observability/ protocols/ tpc/`) with src-rooted includes.

**Goal:** reorganize `client/` to mirror the `src/` concept-bucket philosophy,
so the client reads with the same conceptual map as the server. This is a
**pure relocation** — no logic changes, no function renames, no file splits or
merges. Byte-identical translation units, moved and re-plumbed.

## 2. Scope

- **`client/lib/`** — restructured into concept buckets (the true "src analog"). Primary work.
- **`client/apps/`** — grouped into **tool families** (not lib buckets; these are
  consumers, not library concepts).
- **`client/preload/`, `client/examples/`** — left as-is (already single-purpose).
- **`client/tests/`** — left as-is (test layout is its own convention).

Explicitly out of scope: any behavioral change, function/API rename, file
split/merge, server `src/` changes, `./config` / `./configure` changes.

## 3. Target taxonomy — `client/lib/`

Include root stays `-Ilib`. Buckets mirror `src/` names where they fit; three
client-specific buckets (`xfer/`, `posix/`, `cli/`) cover client-only concerns.

```
client/lib/                         ← include root (-Ilib)
  brix.h  brix_ops.h  brix_net.h  brix_auth.h    ← public API spine stays at root (see §6)
  core/
    aio/     aio.c aio_buffers.c aio_conn.c aio_engine.c aio_io.c aio_mgr.c
             uring.c  (+ aio.h aio_internal.h uring.h)
    config/  xrdrc.c
    types/   status.c  units.c
  net/       conn.c sock.c streams.c pool.c tls.c resilient.c url.c
             netpref.c nettmo.c netdiag.c
  auth/
    auth.c  sigver.c
    cred/    cred.c cred_x509.c cred_bearer.c cred_sss.c cred_krb5.c cred_s3.c
             credinfo.c credrefresh.c  (+ cred.h)
    sec/     sec_gsi.c sec_token.c sec_sss.c sec_krb5.c sec_host.c sec_pwd.c
             sec_unix.c  (+ sec.h)
    gsi/     proxy.c                       ← X.509 RFC-3820 proxy create/info/destroy
    sss/     sss_keytab.c  (+ sss_keytab.h)
  fs/
    vfs.c vfs_posix.c vfs_block.c  (+ vfs.h)
    iobuf.c (+ iobuf.h)  path.c  glob.c  fattr.c
    backend/s3/  vfs_s3.c vfs_s3_io.c vfs_s3_http.c vfs_s3_transport.c
                 (+ vfs_s3_internal.h)
  protocols/
    root/    ops_file.c ops_file_rw.c ops_file_pg.c ops_meta.c ops_fs.c
             ops_ext.c frame.c  (+ ops_internal.h)
    http/    http.c http_req.c http_download.c http_upload.c
             webfile.c webfile_io.c weblist.c  (+ http_internal.h webfile_internal.h)
    s3/      s3.c                            ← AWS SigV4 (path-style) signer
    shared/  zip.c zip_write.c checksum.c cks_verify.c
             (+ zip.h zip_internal.h)
  xfer/      copy.c copy_pump.c copy_local.c copy_remote.c copy_recursive.c
             copy_zip.c copy_block.c  (+ copy_internal.h)
  posix/     fuse_ops.c posix_map.c  (+ fuse_ops.h posix_map.h)
  cli/       cli_cksum.c cli_conn.c cli_cred.c cli_opts.c
  observability/
    trace.c  capture.c
    metabench/  metabench.c metabench_run.c metabench_unittest.c
                (+ metabench.h metabench_run.h)
```

### Rationale for non-obvious placements
- `frame.c` (wire framing) + `status.c` — `frame.c` → `protocols/root` (root:// wire),
  `status.c` → `core/types` (kXR name lookup + shell exit-code mapping is cross-cutting).
- `s3.c` (SigV4 signer) → `protocols/s3`; the S3 **VFS backend** (`vfs_s3*`) →
  `fs/backend/s3`; S3 **credentials** (`cred_s3.c`) → `auth/cred`. This mirrors
  src exactly (protocols/s3/auth does SigV4, fs backend is the store, creds in auth).
- `proxy.c` → `auth/gsi` (it is X.509 GSI proxy-cert management, not a network proxy).
- `iobuf.c` (per-handle read-ahead / write-back) → `fs` (it backs VFS/file-handle I/O).
- `checksum.c` + `cks_verify.c` → `protocols/shared` (checksums span root://, HTTP, S3).
- `cli_*.c` → `cli/` (shared helpers linked by the `apps/` CLIs, not core lib concepts).

## 4. Target grouping — `client/apps/` (tool families)

```
apps/copy/    xrdcp.c xrdcp_transfer.c xrdcp_recursive.c  (+ xrdcp_internal.h)
apps/fs/      xrdfs*.c xrootdfs*.c xrd_mount.c  (+ xrdfs_internal.h xrootdfs_*.h)
apps/cksum/   xrdadler32.c xrdcrc32c.c xrdcrc64.c xrdckverify.c xrdcinfo.c
apps/auth/    xrdgsiproxy.c xrdgsitest.c xrdsssadmin.c
apps/diag/    xrddiag.c diag_*.c xrd.c xrd_battery.c xrd_doctor.c xrd_clockskew.c
              wait41.c xrdqstats.c mpxstats.c xrdmapc.c
              (+ diag_internal.h xrd_internal.h)
apps/scan/    xrdstorascan.c storascan_core.c storascan_unittest.c  (+ storascan_core.h)
apps/prep/    xrdprep.c
```

`preload/`, `examples/`, `tests/` unchanged.

## 5. Include strategy

- Include root stays `-Ilib` (client) + `-I$(SRC)` (server), both already present in `ALL_CFLAGS`.
- **Cross-bucket** includes become root-relative from `lib/`: `#include "auth/cred.h"`,
  `#include "fs/vfs.h"`, `#include "core/aio/aio.h"` — exactly the src convention.
- **Same-bucket** includes stay bare (`#include "aio_internal.h"`).
- `*_internal.h` split-contract headers move alongside their siblings and stay bare.
- Server-header includes (`core/compat/crypto.h`, `protocols/root/protocol/open_flags.h`)
  are resolved via `-I$(SRC)` and are unaffected — note these are src-rooted names that
  now *look* identical to client cross-bucket includes but resolve against the server tree.
  No collision today (no `core/aio/aio.h` etc. in src that would shadow), but the apply
  step must verify no client bucket path shadows a server include path.

## 6. The `brix.h` decision

`brix.h` is included by 44 of 80 lib files and is the **public API spine** (the umbrella
contract, analogous to src's `ngx_brix_module.h`). Decision: the four umbrella headers
(`brix.h`, `brix_ops.h`, `brix_net.h`, `brix_auth.h`) **stay at the `lib/` root**, so
`#include "brix.h"` keeps resolving everywhere with zero churn. Rejected alternative:
moving them into `core/` (→ `#include "core/brix.h"` × 44) — more faithful to src but
high-churn for no functional gain.

## 7. Execution approach (mirrors phase-66/67 precedent)

1. **Map TSV** — `docs/refactor/phase-69-client-map.tsv` (old-path ⟶ new-path), the
   single reviewable source of truth for every move. Authored/reviewed before any move.
2. **Apply script** — per row: `git mv old new` (all client sources verified tracked &
   clean, so no `git mv` abort on untracked WIP — a known phase-67 hazard); then rewrite
   `#include` directives per the map; then regenerate the enumerated source/object path
   lists in `client/Makefile`.
3. **Build governance** — the ONLY build edits are in `client/Makefile`:
   `LIB_SRCS`, `PIC_OBJS` (derived), and the per-app `*_SPLIT` object-path variables
   (`XRDCP_SPLIT`, `XRD_SPLIT`, `XRDFS_SPLIT`, `XRDDIAG_SPLIT`, `STORASCAN_SPLIT`,
   `XROOTDFS_SPLIT`) plus the `apps/xrootdfs*` explicit rules. Source lists are
   enumerated (no wildcards) so every moved file must be re-listed. No server
   `./config` / `./configure` touch.
4. **Verification** — `make -j` full clean build (static `libbrix.a` + shared
   `libbrix.so` + PIC preload + all apps + FUSE driver), then the client C smoke tests
   and the client VFS seam guard (`tools/ci/check_vfs_seam.sh` CLIENT tier) to confirm
   no seam regression. Optionally a spot `nm`/`git diff --stat` to confirm the moves are
   content-identical (rename-only).

## 8. Risks & mitigations

- **`git mv` abort on untracked WIP** — verified `git status --porcelain client/` shows
  no untracked/modified `.c`/`.h` sources; only build artifacts (`.o/.d`) are untracked
  and are not moved via git. Re-check immediately before applying.
- **Stale build artifacts** — `.o/.d/.pic.o/.pic.d` in the old flat layout become orphans;
  the apply step runs `make clean` (or removes stale objects) before the verification build
  to avoid mixed-ABI garbage (a known hazard: configure/build over old objects ⇒ SIGSEGV).
- **Include-path shadowing** — client cross-bucket names (e.g. `core/...`) share a namespace
  shape with server `-I$(SRC)` names; apply step greps for any client new-path that collides
  with an existing server include before finalizing.
- **Client VFS seam guard drift** — `check_vfs_seam.sh` CLIENT tier references file paths;
  update its path list / backlog file to the new locations so the guard stays green.

## 9. Success criteria

- Full `make -j` client build is green (lib, shared, preload, all apps, FUSE).
- Client C smoke tests pass; VFS seam guard (CLIENT tier) green.
- `git log --follow` / `git diff -M` shows every move as a rename (no content delta).
- `client/lib/` and `client/apps/` reflect the taxonomy in §3–§4; includes follow §5.
