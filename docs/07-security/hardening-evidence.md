# Hardening evidence — designed for a better user experience

> Text form of the site's `/evidence` page. The claim: BriX-Cache is
> engineered so that failures — bad networks, bad configs, bad actors,
> crashed workers — cost users as little as possible. The rule: every item
> below cites a file, document, or test in this repository. Nothing here is
> aspirational.

## 1. Designed-in defenses

*What the user feels: the service refuses to start broken, cannot be walked
out of its export, and does not grow new bypasses as the code evolves.*

- **Bad config never takes traffic.** Missing certificates, JWKS files,
  CRLs, or required directories fail `nginx -t` with an explicit `emerg`
  line before a single byte is accepted; reloads drain gracefully.
  ([reload semantics](../09-developer-guide/reload-semantics.md))
- **Path confinement is an invariant, not a habit.** Every wire path goes
  through the canonical resolve helper before any open — no exceptions —
  and confined opens use `openat2` with `RESOLVE_IN_ROOT`, closing
  symlink-escape routes. (`src/fs/path/beneath.h`,
  `src/fs/path/resolve_confined_helpers.c`)
- **One storage seam, mechanically enforced.** All raw file I/O lives in
  `src/fs/backend/` behind the VFS; `tools/ci/check_vfs_seam.py` fails the
  build if a handler reaches around it, so confinement and identity checks
  cannot be bypassed by new code.
- **Hardened builds by default.** `-Werror` with `printf`-format attributes
  (which caught a real header-formatting bug); binaries link with full
  RELRO, immediate binding, and non-executable stacks (`client/Makefile`).
- **Observability that cannot leak or explode.** Wire strings are sanitized
  before logging (`brix_sanitize_log_string`,
  `src/observability/accesslog/access_log.c`); metric labels are fixed and
  low-cardinality.

## 2. Failure-mode engineering, in public

*The strongest evidence is what happened when something broke: hunt the
failure mode, fix it, write it down, pin it with a regression test.*

- **The semaphore stall.** Symptom: multi-worker connection stalls of
  60–450 s on the hot open path. Root cause: a lost POSIX-semaphore wakeup
  inside shared-memory mutexes — a worker slept on a lock that was already
  free. Outcome: a repo-wide spin+yield mutex rule enforced through one
  allocation helper (`src/core/compat/shm_slots.c`) and a published
  postmortem
  ([postmortem](../09-developer-guide/postmortem-shmtx-semaphore-stall.md)).
- **The reboot-lockup audit.** A "stuck after many reboots" report triggered
  a full audit of every lock a dying worker could strand. Four classes
  found and fixed, each pinned by a regression test: dead-holder SHM mutex
  recovery (`tests/test_shm_mutex_recovery.py`), cache-fill lock dead-owner
  reclaim (`tests/test_cache_lock_reclaim.py`), missing origin stall timeout
  (`tests/test_http_origin_stall_timeout.py`), leaked in-use gauges
  (`tests/test_ratelimit_gauge_reset.py`).
- **Absorbing upstream flakiness.** Hardening aimed straight at user
  experience: a stuck origin is detected in seconds (2 s connect / 4 s
  stall defaults, `src/protocols/cvmfs/module.c`), retried against fresh
  connections (force-primary policy), and — when everything upstream fails —
  answered from cache with stale-if-error. A client storm coalesces into a
  single upstream fill. (`tests/run_cvmfs_resilience.sh`)

## 3. Proof by torture

- Full suite **~8,700 tests**; the slow lane — **~1,770 tests** — exists
  specifically to hurt the software: resilience, chaos, fault injection
  (`tests/README.md`).
- A TCP fault-injection proxy (`tests/c/fault_proxy.c`) resets connections
  mid-read and injects stalls and latency while suites assert **byte-exact**
  results and **zero EIO** surfaced to applications
  (`tests/test_xrootdfs_resilience.py`).
- A `netem` network-emulation lab degrades whole links
  (`tests/cvmfs/netem_lab.sh`).
- Conformance is cross-checked, not assumed: the same tests run against
  BriX-Cache and the reference XRootD implementation
  (`TEST_CROSS_BACKEND`).
- Five standing CI guards keep the architecture from eroding between
  releases: `tools/ci/check_vfs_seam.py`, `check_config_coverage.sh`,
  `check_http_helper_reimpl.sh`, `check_file_size.sh`,
  `check_sd_driver_conformance.sh`.

## 4. Integrity, end to end

*What the user feels: the bytes that arrive are the bytes that were
published — provable at every hop.*

- **Per-page CRC32c on the wire** — `kXR_pgread`/`kXR_pgwrite` carry a CRC
  per 4K page (`src/protocols/root/read/pgread.c`).
- **Checksums at rest** — recorded checksums are verifiable on demand
  (`xrdckverify`, `client/apps/README.md`).
- **Verified reads from storage** — CSI integrity verification checks what
  storage returns against the record made at write time
  (`src/fs/backend/csi_verify.c`).
- **Content-addressed trust for CVMFS** — every fetched object is verified
  against its content hash on arrival (`client/apps/fs/brixcvmfs.c`).
- **Byte-exact under fault injection** — the end-to-end check that ties it
  together (`tests/test_xrootdfs_resilience.py`).
