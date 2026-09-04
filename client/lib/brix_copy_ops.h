/*
 * brix_copy_ops.h - copy.c decls (brix_copy_opts + the copy engine surface)
 * Split from the 647-line brix_ops.h at phase-103; #included by brix_ops.h at
 * the exact position the block occupied, so declaration order is identical.
 * Do not include this directly — go through brix.h.
 */
#pragma once

/* ---- copy.c ---- */
/* Progress callback: invoked during a transfer with bytes-so-far and the total
 * (total < 0 = unknown, e.g. stdin); done==total signals completion. NULL = off. */
typedef void (*brix_progress_cb)(void *arg, long long done, long long total);
typedef struct {
    int         force;    /* -f: overwrite existing destination */
    int         posc;     /* -P: persist-on-successful-close (upload) */
    int         silent;   /* -s: suppress progress/info */
    int         verbose;  /* -v/-d */
    int         pgrw;     /* --pgrw: use kXR_pgread/pgwrite (per-page CRC32c) */
    const char *cksum;    /* --cksum <type>[:source|:print|:<value>], or NULL */
    const char *compress; /* --compress <codec>: phase-42 W4 root:// inline read
                           * compression — request "?xrootd.compress=<codec>" on
                           * the read open; NULL = plaintext (default). */
    int         zip;      /* --zip: phase-42 W3 — store the local source as a
                           * STORE member of the destination ZIP archive. */
    int         zip_append; /* --zip-append: like --zip but append to an existing
                           * (non-ZIP64) archive instead of overwriting. */
    int         streams;  /* -S/--streams N: attach N-1 kXR_bind secondaries */
    int         parallel; /* --parallel: TRUE concurrent striped download — one
                           * thread per bound connection, each pwrites its disjoint
                           * byte range into the destination (real multi-stream
                           * throughput, hides RTT on high-latency links).  Opt-in:
                           * the parallel path is fail-closed (no single-link
                           * resilient ride-out), so it is OFF by default and the
                           * serial resilient fan-out stays the default.  Applies
                           * only to a local-file download of a known-size plain
                           * (non-compressed, non-pgrw) object; every other case
                           * falls back to the serial pump. */
    int         sources;  /* --sources N (phase-100 extreme copy): download from
                           * up to N replicas concurrently with block stealing.
                           * Replicas come from the metalink mirror list, else a
                           * kXR_locate on the source, else the single source
                           * duplicated. 0/1 = off (single-source paths). */
    int         metalink_off; /* --no-metalink: treat .meta4/.metalink sources
                           * as plain files. Also forced on internally for the
                           * metalink document fetch + per-mirror dispatch so
                           * resolution can never recurse. */
    int         xattr_preserve; /* --xattr (§7.13): after a successful
                           * root://↔local copy, mirror USER-namespace
                           * extended attributes (best-effort, warnings only;
                           * system./security./trusted. names never cross). */
    int         coerce;   /* -F/--coerce (§7.13): stock "ignore file locking
                           * semantics" — the kXR_force bit rides every remote
                           * destination open. BriX's server has no mandatory
                           * usage-locking to override, so it accepts the bit;
                           * the flag exists for drop-in scripts and for stock
                           * destinations that DO enforce usage rules. */
    int         rm_bad_cksum;  /* --rm-bad-cksum: stock's opt-IN unlink of a
                           * cksum-mismatched destination. BriX unlinks on
                           * mismatch unconditionally (fail-closed), so the
                           * flag is an accepted no-op alias of the default. */
    int64_t     xrate_bps;     /* --xrate: cap the serial-pump transfer rate
                           * (bytes/sec; 0 = unlimited). Engines that bypass
                           * the pump (--parallel/--sources) are parse-time
                           * exclusive with it. */
    int64_t     xrate_min_bps; /* --xrate-threshold: fail the transfer when the
                           * average rate drops below this (bytes/sec, 0 = off;
                           * 3 s grace so connection setup never trips it). */
    int         cont;     /* --continue (§7.6 byte-offset resume): a download
                           * writes the DESTINATION file directly (no atomic
                           * temp) and, when it already exists, resumes at its
                           * size. Partial destinations survive failures so a
                           * later --continue can pick them up; a completed
                           * copy that then fails --cksum is still dropped
                           * (fail-closed on COMPLETED integrity verdicts).
                           * Parse-time exclusive with --force/--resume/
                           * --journal/--pgrw/--compress/--zip*. */
    /* Internal (resolver-owned, never set by CLI): the ranked root-family
     * mirror list a metalink resolved to, threaded to the extreme-copy engine.
     * Pointers borrow the resolver's storage for the dispatch call. */
    const char *const *xcp_mirrors;
    size_t             xcp_n_mirrors;
    int         tpc_mode; /* --tpc: 0=off, 1=first (fallback), 2=only, 3=delegate */
    const char *tpc_token_mode;  /* --tpc delegate token_mode value (optional) */
    int         recursive;/* -r: copy a directory tree (dirlist walk + mkdir + per-file) */
    /* davs/http(s) + s3 transfer auth (web schemes). NULL fields fall back to the
     * environment (BEARER_TOKEN / AWS_ACCESS_KEY_ID / AWS_SECRET_ACCESS_KEY /
     * AWS_DEFAULT_REGION). s3_region defaults to "us-east-1". */
    const char *bearer;    /* -T/--token: WebDAV/HTTP Authorization: Bearer <jwt> */
    const char *s3_access; /* --s3-access: SigV4 access key id */
    const char *s3_secret; /* --s3-secret: SigV4 secret key */
    const char *s3_region; /* --s3-region: SigV4 region (default us-east-1) */
    int         max_stall_ms;  /* download resilience: per-read patience window for
                                * reconnect+reopen+resume on a flaky/lossy link
                                * (0 = default 60000). The read size adapts down to
                                * survive loss; see pump_src_remote. */
    int         no_retry;      /* 1 ⇒ resilience off: every bounded copy loop uses a
                                * zero-stall deadline and fails on the first transport
                                * fault (--no-retry / --retry 0 / --max-stall 0).
                                * Distinguishes "fail fast" from max_stall_ms==0
                                * meaning "use the default". See copy_stall_ms(). */
    int         retry_count;   /* outer retry budget for each leaf of a recursive
                                * web/S3 copy and each leg of a web-to-web relay.
                                * Zero preserves the fail-fast library default. */
    brix_progress_cb progress;  /* periodic transfer progress, or NULL */
    void            *progress_arg;
    int         io_uring;  /* phase-44 --io-uring: 0=auto, 1=on, 2=off. Selects
                            * the local-disk io_uring overlap ring in copy.c.
                            * auto = use it iff brix_uring_available(); on with no
                            * liburing = clean CLI error; off = classic read/write. */
    int         io_uring_direct; /* --io-uring-direct: 1 ⇒ engage the O_DIRECT tier
                            * on the local-disk ring (page-cache bypass, block-aligned
                            * slab). Ignored unless the ring is active. A filesystem
                            * that rejects O_DIRECT makes an AUTO ring fall back to the
                            * buffered tier; an ON ring surfaces a clean error. */
    /* --- 2026-07-05 transfer-policy extensions (zero-init = legacy) --- */
    const char *const *excludes;   /* fnmatch(3) patterns; a match skips the file */
    size_t             n_excludes;
    const char *const *includes;   /* when non-empty, a file must match one       */
    size_t             n_includes;
    int  dry_run;                  /* print decisions, transfer nothing            */
    int  remove_source;            /* delete source after verified success         */
    int  sync;                     /* --sync honored inside recursive walkers      */
    int  sync_cmp;                 /* XRDC_SYNC_SIZE | _MTIME | _CKSUM             */
    const char *sync_cksum_algo;   /* algo for XRDC_SYNC_CKSUM (default adler32)   */
    int  sync_delete;              /* recursive sync: delete dst entries not in src */
} brix_copy_opts;

/* brix_copy_opts.io_uring tri-state values (match the server enum spelling). */
#define XRDC_IO_URING_AUTO  0
#define XRDC_IO_URING_ON    1
#define XRDC_IO_URING_OFF   2

/* --tpc mode values for brix_copy_opts.tpc_mode. */
#define XRDC_TPC_OFF      0
#define XRDC_TPC_FIRST    1   /* try TPC, fall back to client-mediated on failure */
#define XRDC_TPC_ONLY     2   /* TPC or hard fail */
#define XRDC_TPC_DELEGATE 3   /* TPC with credential delegation (tpc.token_mode) */

#define XRDC_SYNC_SIZE  0   /* skip when sizes match (legacy --sync)            */
#define XRDC_SYNC_MTIME 1   /* sizes match AND dst mtime >= src mtime           */
#define XRDC_SYNC_CKSUM 2   /* sizes match AND checksums match (caller does I/O) */

int brix_copy_filter_match(const brix_copy_opts *o, const char *rel);
/* brix_sync_should_skip: for XRDC_SYNC_CKSUM, this is only the size gate; the
 * caller performs the checksum comparison itself if sizes match. */
int brix_sync_should_skip(int cmp, long long ssz, long long smt,
                          long long dsz, long long dmt);

/* Copy between a root://[s] URL and a local path (or "-"). Direction is inferred
 * from the schemes: remote→local download, local→remote upload. `co` carries the
 * connection (auth/TLS) options; may be NULL. */
int brix_copy(const char *src, const char *dst, const brix_copy_opts *o,
              const brix_opts *co, brix_status *st);

/* Phase 40 (a): install cooperative SIGINT/SIGTERM handlers so an interrupted
 * transfer drops its partial local destination instead of leaving a corrupt
 * file. The handler only sets a flag (async-signal-safe); the transfer loops
 * poll brix_copy_quit_requested() and abort, and the normal teardown unlinks the
 * temp. Call once from main() before any transfer. */
void brix_copy_install_signal_handlers(void);
int  brix_copy_quit_requested(void);
