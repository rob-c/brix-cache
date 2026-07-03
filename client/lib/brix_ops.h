/*
 * brix_ops.h - metadata + file op, resilient, checksum, copy decls
 * Phase-38 umbrella split of brix.h; included via brix.h (relies on the
 * core types declared there first).  Do not include this directly.
 */
#ifndef XRDC_OPS_H
#define XRDC_OPS_H

/* ---- ops_meta.c ---- */
int brix_stat(brix_conn *c, const char *path, brix_statinfo *out, brix_status *st);
/* lstat — do not follow a final symlink (kXR_statNoFollow). A symlink reports the
 * kXR_other flag with size = target length; against a server without the vendor
 * extension the option is ignored and this behaves like brix_stat. */
int brix_lstat(brix_conn *c, const char *path, brix_statinfo *out, brix_status *st);
int brix_dirlist(brix_conn *c, const char *path, int want_stat,
                 brix_dirent **ents, size_t *count, brix_status *st);

/* ---- ops_file.c ---- */
typedef struct {
    uint8_t fhandle[XRDC_FHANDLE_LEN];
    /* phase-42 W4: inline read-compression codec negotiated at open (the codec
     * ordinal from the kXR_open reply cptype[0]).  0 = plaintext (the default);
     * non-zero means kXR_read responses are codec frames the client inflates.
     * Only set when this client opened with "?xrootd.compress=" against a server
     * that confirmed support; stays 0 for stock servers / plain opens. */
    uint8_t read_codec;
    /* phase-42 W5: inline write-compression codec negotiated at open (write opens
     * only).  0 = plaintext; non-zero means brix_file_write compresses each
     * payload as a self-contained frame the server decompresses on ingest. */
    uint8_t write_codec;
} brix_file;

int brix_file_open_read(brix_conn *c, const char *path, brix_file *f,
                        brix_status *st);
/* force → truncate-on-open (overwrite); posc → persist-on-successful-close. */
int brix_file_open_write(brix_conn *c, const char *path, int force, int posc,
                         brix_file *f, brix_status *st);
/* Open an EXISTING file for read+write IN PLACE (no truncate, no create) — enables
 * random writes over existing content (kXR_open_updt only). posc as above. */
int brix_file_open_update(brix_conn *c, const char *path, int posc,
                          brix_file *f, brix_status *st);
/* Read up to len bytes at offset; returns bytes read (0 = EOF) or -1. Accumulates
 * any kXR_oksofar partial frames into buf. */
/* phase-42 W4: inflate one inline-compressed kXR_read frame (codec ordinal from
 * the open reply cptype[0]).  Shared by the sync (ops_file.c) and async
 * (aio_mgr.c) read paths.  Returns plaintext length, or -1 on a corrupt/oversized
 * frame.  out_cap bounds the plaintext (it cannot exceed the requested length). */
ssize_t brix_inflate_frame(uint8_t codec, const uint8_t *comp, size_t comp_len,
                           void *out, size_t out_cap, brix_status *st);

/* phase-42 W5: compress one inline-write frame (codec ordinal from the open reply
 * cptype[0]).  Shared by the sync (ops_file.c) and async (aio_mgr.c) write paths.
 * Returns a malloc'd buffer (caller frees) + sets *out_len, or NULL on failure. */
uint8_t *brix_deflate_frame(uint8_t codec, const void *in, size_t in_len,
                            size_t *out_len, brix_status *st);

ssize_t brix_file_read(brix_conn *c, brix_file *f, int64_t offset,
                       void *buf, size_t len, brix_status *st);
int brix_file_write(brix_conn *c, brix_file *f, int64_t offset,
                    const void *buf, size_t len, brix_status *st);
int brix_file_close(brix_conn *c, brix_file *f, brix_status *st);

/* Scatter-gather read/write (kXR_readv 3025 / kXR_writev 3031). Each segment names
 * an offset+length on the open file f; readv fills seg.buf, writev sends seg.data.
 * Up to XRDC_VEC_MAXSEGS segments per call. */
#define XRDC_VEC_MAXSEGS 1024
#define XRDC_VEC_MAXBYTES (256u << 20)   /* aggregate readv/writev payload cap */
typedef struct {
    int64_t offset;
    size_t  len;
    void   *buf;          /* caller-supplied, >= len bytes */
    size_t  got;          /* OUT: bytes actually delivered for this segment */
} brix_readv_seg;
typedef struct {
    int64_t     offset;
    size_t      len;
    const void *data;     /* caller-supplied, len bytes */
} brix_writev_seg;
/* readv: issue one kXR_readv for all segs; fills each seg.buf and sets seg.got to
 * the bytes actually delivered for that segment (which may be < seg.len on a short
 * read past EOF). Returns total bytes read across segments, or -1. */
ssize_t brix_file_readv(brix_conn *c, brix_file *f, brix_readv_seg *segs,
                        size_t nseg, brix_status *st);
/* writev: issue one kXR_writev for all segs (do_sync → fsync after). 0 / -1. */
int brix_file_writev(brix_conn *c, brix_file *f, const brix_writev_seg *segs,
                     size_t nseg, int do_sync, brix_status *st);

/* Open with an opaque "?key=val&…" suffix (for TPC tpc.* params). write selects
 * read vs write-create semantics (force/posc as in open_write). Redirect-aware. */
int brix_file_open_opaque(brix_conn *c, const char *path, const char *opaque,
                          int write, int force, int posc, brix_file *f,
                          brix_status *st);
/* kXR_sync the handle (also the TPC arm/trigger on a destination handle). Uses a
 * plain send+recv (no redirect follow); the caller may raise c->io.timeout_ms
 * before the trigger sync, whose reply is deferred until the pull completes. */
int brix_file_sync(brix_conn *c, brix_file *f, brix_status *st);

/* Paged I/O with per-page CRC32c integrity (kXR_pgread/kXR_pgwrite). pgread reads
 * up to len bytes at offset and verifies every page's CRC32c before returning the
 * decoded bytes (returns bytes read, 0=EOF, -1=error incl. CRC mismatch). pgwrite
 * frames buf into [crc][data] page units and fails (-1) if the server rejects any
 * page's checksum. Both are file-offset aligned (short first/last page). */
ssize_t brix_file_pgread(brix_conn *c, brix_file *f, int64_t offset,
                         void *buf, size_t len, brix_status *st);
int     brix_file_pgwrite(brix_conn *c, brix_file *f, int64_t offset,
                          const void *buf, size_t len, brix_status *st);

/* ---- resilient.c — network resilience for the synchronous tools ----
 *
 * Brings xrootdfs-style recovery (reconnect + full re-auth + handle reopen +
 * offset resume + bounded backoff) to one-shot CLI flows, lifted from the proven
 * xrdcp pump (copy.c) and the async mfile layer (aio_mgr.c). Two seams:
 *   - brix_with_resilience(): wrap any stateless op (stat/ls/query/...) so it is
 *     re-issued after a sever, gated by an idempotency class.
 *   - brix_rfile: a synchronous file handle that reopens + resumes mid-transfer.
 * Both are no-ops (single attempt) when the window is 0, so --no-retry restores
 * the exact legacy fail-fast path. Raw ops (and copy.c) are untouched. */

/* Idempotency class for brix_with_resilience — governs re-issue after a sever. */
typedef enum {
    XRDC_OP_READONLY,           /* stat/ls/locate/query/statvfs: retry freely */
    XRDC_OP_IDEMPOTENT,         /* chmod: re-apply is harmless — retry freely */
    XRDC_OP_MUTATION_NORMALIZE, /* mkdir/rm/rmdir/mv/prepare: re-issue ONCE, then
                                 * treat benign_errno (EEXIST/ENOENT) as success */
    XRDC_OP_UNSAFE              /* never auto-retry */
} brix_op_class;

/* A single logical operation over a connection, re-invocable after a reconnect.
 * Returns 0 on success, -1 with *st set on failure. */
typedef int (*brix_op_fn)(brix_conn *c, void *arg, brix_status *st);

/* Effective resilience window for c (ms): 0 when disabled (opts.no_retry), else
 * opts.max_stall_ms, else XRDC_DEFAULT_MAX_STALL_MS. */
int brix_resilient_window_ms(const brix_conn *c);

/* Reconnect c to its home endpoint (manager if known, else the current host) with
 * a full re-handshake + re-auth. 0 / -1 (st set). */
int brix_reconnect_home(brix_conn *c, brix_status *st);

/* Like brix_connect, but retries the (multi-RTT, loss-fragile) connect+handshake+
 * login within the resilience window with backoff, so a one-shot tool can bring a
 * session up over a lossy link instead of failing on the first severed handshake.
 * A refused connection (nothing listening) still fails fast. Window from o /
 * $XRDC_MAX_STALL_MS; 0 ⇒ a single attempt (legacy). 0 / -1 (st set). */
int brix_connect_resilient(brix_conn *c, const brix_url *u, const brix_opts *o,
                           brix_status *st);

/* Run op(c,arg,st); on a retryable transport fault, reconnect to home and re-run,
 * bounded by max_stall_ms with backoff. cls governs mutation re-issue; benign_errno
 * (e.g. EEXIST/ENOENT) becomes success for MUTATION_NORMALIZE. max_stall_ms<=0 ⇒ a
 * single attempt (legacy). Returns op's last result; 0 on success. */
int brix_with_resilience(brix_conn *c, int max_stall_ms, brix_op_class cls,
                         int benign_errno, brix_op_fn op, void *arg, brix_status *st);

/* Resilient single-frame roundtrip: like brix_roundtrip (re-sending the same
 * hdr24/payload, which gets a fresh streamid each send) but with reconnect+retry
 * on a transport sever, gated by cls/benign_errno. The window is taken from c
 * (brix_resilient_window_ms); 0 ⇒ a single attempt. This is the seam the
 * high-level metadata/fs ops route through, so every tool inherits resilience. */
int brix_roundtrip_resilient(brix_conn *c, void *hdr24, const void *payload,
                             uint32_t plen, brix_op_class cls, int benign_errno,
                             uint16_t *status, uint8_t **body, uint32_t *blen,
                             brix_status *st);

/* Resilient synchronous file: the handle plus the state needed to reopen + resume
 * after a sever (path/flags), with an adaptive read size that halves under loss. */
typedef struct {
    brix_conn *c;
    brix_file  f;
    char       path[XRDC_PATH_MAX];
    char       opaque[256];     /* "?key=val&…" suffix for read opens, or "" */
    int        writable;        /* 1 ⇒ reopen in place (update, no truncate) */
    int        posc;            /* persist-on-successful-close (write opens) */
    int        pgrw;            /* 1 ⇒ paged I/O + per-page CRC (kXR_pgread/pgwrite) */
    int        max_stall_ms;
    size_t     cur_chunk;       /* adaptive read size; halves on each sever to a floor */
    int      (*cancel)(void);   /* optional abort predicate (e.g. SIGINT); NULL = none */
} brix_rfile;

/* opaque may be NULL. pgrw selects paged CRC I/O. max_stall_ms<=0 ⇒ pull the
 * window from c (brix_resilient_window_ms). The open itself is resilient. 0/-1. */
int     brix_rfile_open_read (brix_conn *c, const char *path, const char *opaque,
                              int pgrw, int max_stall_ms, brix_rfile *rf, brix_status *st);
int     brix_rfile_open_write(brix_conn *c, const char *path, int force, int posc,
                              int pgrw, int max_stall_ms, brix_rfile *rf, brix_status *st);
/* Read/write at an absolute offset, transparently riding out severs within the
 * window (reconnect + reopen + re-issue at the same offset — idempotent). pread
 * returns bytes read (0=EOF) or -1; pwrite returns 0/-1. */
ssize_t brix_rfile_pread (brix_rfile *rf, int64_t off, void *buf, size_t len, brix_status *st);
int     brix_rfile_pwrite(brix_rfile *rf, int64_t off, const void *buf, size_t len, brix_status *st);
int     brix_rfile_close (brix_rfile *rf, brix_status *st);

/* ---- checksum.c ---- */
typedef enum {
    XRDC_CK_ADLER32 = 0,
    XRDC_CK_CRC32C,
    XRDC_CK_MD5,
    XRDC_CK_CRC64,      /* CRC-64/XZ   */
    XRDC_CK_CRC64NVME,  /* CRC-64/NVME */
    XRDC_CK_ZCRC32      /* zlib CRC-32 — XRootD "zcrc32" (8 hex) */
} brix_cksum_algo;

/* Map an algorithm name ("adler32"/"crc32c"/"md5") to the enum. 0 / -1. */
int brix_cksum_algo_parse(const char *name, brix_cksum_algo *out);
/* Streaming local checksum over a file descriptor; writes a lowercase hex digest
 * (NUL-terminated) into hex[hexsz] (need ≥33 for md5). 0 / -1. */
int brix_cksum_fd(int fd, brix_cksum_algo algo, char *hex, size_t hexsz,
                  brix_status *st);
/* Ask the server for a file's checksum via kXR_query/kXR_Qcksum (redirect-aware).
 * On success writes the server's hex digest into hex[hexsz]. 0 / -1. */
int brix_query_cksum(brix_conn *c, const char *path, const char *algo_name,
                     char *hex, size_t hexsz, brix_status *st);

/* ---- cks_verify.c (verify a file on disk against its recorded checksum) ---- */
#define XRDC_CKV_HEX_MAX 129

/* Which recorded-checksum sources to consult. */
typedef enum {
    XRDC_CKV_AUTO = 0,   /* cache sidecars (.cinfo/.meta) AND storage (xattr/.cks) */
    XRDC_CKV_CACHE,      /* proxy cache only: <file>.cinfo / <file>.meta cks fields */
    XRDC_CKV_STORAGE     /* storage only: user.XrdCks.<alg> xattr + <file>.cks sidecar */
} brix_ckv_mode;

/* Outcome of a verification. */
typedef enum {
    XRDC_CKV_OK = 0,        /* a recorded checksum was found and matches */
    XRDC_CKV_MISMATCH,      /* recorded != recomputed (corruption) */
    XRDC_CKV_NO_RECORD,     /* no recorded checksum found for this file/algo */
    XRDC_CKV_UNSUPPORTED,   /* recorded with an algorithm this engine cannot compute */
    XRDC_CKV_ERROR          /* I/O / access error */
} brix_ckv_result;

/* Filled with the decisive record (the match, or the mismatch). */
typedef struct {
    char source[16];                 /* "xattr" | "cks" | "cinfo" | "meta" */
    char algo[16];
    char recorded[XRDC_CKV_HEX_MAX];
    char computed[XRDC_CKV_HEX_MAX];
} brix_ckv_report;

/* Recompute `path`'s checksum and compare it to the value recorded on disk.
 * want_algo NULL ⇒ verify every recorded checksum; non-NULL ⇒ only that algo.
 * `rep` (may be NULL) receives the decisive record. See cks_verify.c. */
brix_ckv_result brix_cks_verify_file(const char *path, const char *want_algo,
    brix_ckv_mode mode, brix_ckv_report *rep, brix_status *st);

/* ---- cli_cksum.c (shared checksum-tool front-end) ---- */
/* Process-exit conventions shared by the front-end tools (phase-49):
 *   USAGE — bad arguments / URL parse / local open  (was the bare `return 50`)
 *   IO    — runtime I/O failure
 *   AUTH  — authentication/authorization failure
 * Runtime failures prefer brix_shellcode(st), which maps a status to a stable
 * code; these are for the cases that never produced a status. */
#define XRDC_EXIT_USAGE  50
#define XRDC_EXIT_IO     51
#define XRDC_EXIT_AUTH   53

/* The whole body of xrdcrc32c / xrdcrc64 / xrdadler32: checksum a LOCAL file or a
 * root:// file with `algo` (local enum) / `algo_name` (wire name) and print
 * "<hex> <path>". Returns the process exit code. `arg` is the single CLI argument
 * (NULL ⇒ usage). `err_exit` is the tool's process exit code for ANY failure to
 * produce a checksum (connect/query/open/digest), chosen to match the stock tool
 * byte-for-byte: xrdadler32 → 1, xrdcrc32c → 3, xrdcrc64 → 1. Argument/URL-parse
 * errors still return XRDC_EXIT_USAGE. */
int brix_cli_cksum_main(const char *prog, const char *algo_name,
                        brix_cksum_algo algo, const char *arg, int err_exit);

/* ---- cli_opts.c / cli_conn.c (shared front-end scaffold) ---- */
/* Zero-init connection options to the canonical defaults (verify_host on). */
void brix_opts_init(brix_opts *o);

/* ---- cli_cred.c — CLI→credential-store builder ---- */
/* Map per-tool CLI values into an brix_cred_config and return a live store.
 * NULL/empty arguments fall back to per-handler env/default discovery, preserving
 * today's per-protocol precedence exactly.  Returns NULL only on OOM.
 * Callers free the result with brix_cred_store_free. */
struct brix_cred_store *
brix_cli_cred_store_build(const char *proxy, const char *bearer,
                           const char *bearer_file, const char *s3_access,
                           const char *s3_secret, const char *oidc_account,
                           int auto_refresh);
/* Release a credential store (matches brix_cred_store_new / brix_cli_cred_store_build).
 * No-op when s is NULL. */
void brix_cred_store_free(struct brix_cred_store *s);
/* Consume one common connection/trace flag at argv[*i] (--tls/--notlsok/
 * --noverifyhost/--auth <p>/--wire-trace[=N]/--timing/--redirect-trace/--capture
 * <p>), advancing *i past any value. Returns 1 if it recognised the flag (caller
 * should `continue`), 0 if not (caller handles its own flags). */
int  brix_opts_parse_arg(brix_opts *o, int argc, char **argv, int *i);
/* endpoint_parse → connect with the standard "prog: <msg>" / "prog: connect:
 * <msg>" stderr on failure. Returns 0 (connected, c live) or a process exit code
 * (XRDC_EXIT_USAGE on parse error, brix_shellcode(st) on connect failure). */
int  brix_cli_connect(const char *endpoint, const brix_opts *o, brix_conn *c,
                      const char *prog, brix_status *st);
/* Emit "tool: op path: msg" + a credential hint and return brix_shellcode(st):
 * the per-operation failure idiom shared across the namespace tools. */
int  brix_report_err(FILE *out, const char *tool, const char *op,
                     const char *path, const brix_status *st, int want_write);

/* ---- path.c / units.c (shared path + byte-count helpers) ---- */
/* Canonicalise `arg` against `cwd` into an absolute server path in out[outsz],
 * collapsing "."/".."/dup-slashes (the xrdfs shell's build_path). */
void    brix_path_resolve(const char *cwd, const char *arg, char *out, size_t outsz);
/* Open a credential file safely (O_NOFOLLOW, regular + owned by euid, no
 * group/other write; `secret` also rejects group/other read). Returns an fd the
 * caller closes, or -1; `st` may be NULL for silent probing. See path.c. */
int     brix_open_credfile(const char *path, int secret, brix_status *st);
/* Open a credential file as an OpenSSL BIO with brix_open_credfile's safety
 * checks (no symlink, owned by euid, secret=1 → 0600). NULL on a missing/unsafe
 * file; the caller surfaces its own "no proxy" message. Defined in proxy.c; the
 * opaque forward-decl keeps OpenSSL out of this header. */
struct bio_st;
struct bio_st *brix_credfile_bio(const char *path, int secret);
/* Render a byte count: raw decimal, or human ("1.5G") when human!=0. */
void    brix_fmt_size(int64_t n, char *out, size_t sz, int human);
/* Parse "4096" / "1.5G" (K/M/G/T suffix) → bytes, or -1 if malformed. */
int64_t brix_parse_bytes(const char *s);
/* Token-bucket pacing: sleep off any surplus so the average stays ≤ `rate` B/s
 * (rate ≤ 0 disables). `start` is the transfer's CLOCK_MONOTONIC start. */
struct timespec;
void    brix_rate_pace(const struct timespec *start, int64_t sent, double rate);

/* ---- ops_fs.c (xrdfs subcommands) ---- */
/* Mutating namespace ops: 0 / -1 (st set). All are redirect-aware. */
int brix_mkdir(brix_conn *c, const char *path, int mode, int parents,
               brix_status *st);
int brix_rm(brix_conn *c, const char *path, brix_status *st);
int brix_rmdir(brix_conn *c, const char *path, brix_status *st);
int brix_mv(brix_conn *c, const char *src, const char *dst, brix_status *st);
int brix_chmod(brix_conn *c, const char *path, int mode, brix_status *st);
int brix_truncate(brix_conn *c, const char *path, int64_t size, brix_status *st);

/* ---- ops_ext.c — vendor POSIX-completeness ops (kXR_setattr/symlink/readlink/
 * link). Only emit these against a server that advertises them: brix_ext_probe
 * queries kXR_Qconfig "xrdfs.ext" and sets the four flags (0 = unsupported). All
 * are redirect-aware; 0 / -1 (st set). ---- */
int brix_ext_probe(brix_conn *c, int *has_setattr, int *has_symlink,
                   int *has_readlink, int *has_link, brix_status *st);
/* set_times applies times[2] (atime,mtime; per-field UTIME_OMIT/UTIME_NOW honoured
 * server-side via utimensat); set_owner applies uid/gid. mode is NOT handled here
 * (use brix_chmod). */
int brix_setattr(brix_conn *c, const char *path, int set_times,
                 const struct timespec times[2], int set_owner,
                 uint32_t uid, uint32_t gid, brix_status *st);
int brix_symlink(brix_conn *c, const char *target, const char *linkpath,
                 brix_status *st);
int brix_link(brix_conn *c, const char *oldpath, const char *newpath,
              brix_status *st);
/* Read a symlink target into out[outsz] (NUL-terminated). Returns the target
 * length (bytes, may exceed outsz-1 if truncated) or -1 (st set). */
ssize_t brix_readlink(brix_conn *c, const char *path, char *out, size_t outsz,
                      brix_status *st);

/* ---- fattr.c — extended attributes (kXR_fattr), path-based, one attr at a time.
 * The per-attribute kXR status is reported via st->kxr (e.g. kXR_AttrNotFound →
 * map with brix_kxr_to_errno). 0 / -1. ---- */
/* Get: copies up to bufsz bytes of the value into value[]; *out_vlen (may be NULL)
 * gets the true value length (pass value=NULL/bufsz=0 to query the size). */
int brix_fattr_get(brix_conn *c, const char *path, const char *name,
                   void *value, size_t bufsz, size_t *out_vlen, brix_status *st);
/* Set: create_only != 0 → fail if the attribute already exists (kXR_fa_isNew). */
int brix_fattr_set(brix_conn *c, const char *path, const char *name,
                   const void *value, size_t vlen, int create_only,
                   brix_status *st);
int brix_fattr_del(brix_conn *c, const char *path, const char *name,
                   brix_status *st);
/* List: copies up to bufsz bytes of the NUL-separated name list into out[];
 * *out_len (may be NULL) gets the true total length. */
int brix_fattr_list(brix_conn *c, const char *path, char *out, size_t bufsz,
                    size_t *out_len, brix_status *st);
/* Text-reply ops: copy the server's reply into out[outsz] (NUL-terminated). */
int brix_query(brix_conn *c, int infotype, const char *args, char *out,
               size_t outsz, brix_status *st);
int brix_statvfs(brix_conn *c, const char *path, char *out, size_t outsz,
                 brix_status *st);
int brix_locate(brix_conn *c, const char *path, char *out, size_t outsz,
                brix_status *st);
/* options = kXR_stage/cancel/wmode/fresh… (byte); optionX = extended flags
 * (kXR_evict…, uint16); prty = request priority 0-3. */
int brix_prepare(brix_conn *c, const char *const *paths, int npaths, int options,
                 int optionX, int prty, char *out, size_t outsz, brix_status *st);

/* ---- proxy.c (xrdgsiproxy: RFC-3820 X.509 proxy create/info/destroy) ---- */
typedef struct {
    const char *user_cert;   /* NULL ⇒ $X509_USER_CERT else ~/.globus/usercert.pem */
    const char *user_key;    /* NULL ⇒ $X509_USER_KEY  else ~/.globus/userkey.pem  */
    const char *out_path;    /* NULL ⇒ $X509_USER_PROXY else /tmp/x509up_u<uid>    */
    int         valid_hours; /* lifetime; ≤0 ⇒ 12h */
    int         bits;        /* ephemeral RSA size; ≤0 ⇒ 2048 */
} brix_proxy_opts;
/* Create an RFC-3820 proxy (proxyCertInfo OID 1.3.6.1.5.5.7.1.14, id-ppl-inheritAll)
 * signed by the user cert/key, written as cert+chain+key (mode 0400). 0 / -1. */
int brix_proxy_create(const brix_proxy_opts *o, brix_status *st);
/* Print subject/issuer/validity of the proxy at `path` (NULL ⇒ default). 0 / -1. */
int brix_proxy_info(const char *path, FILE *out, brix_status *st);
/* Shred + unlink the proxy at `path` (NULL ⇒ default). 0 / -1. */
int brix_proxy_destroy(const char *path, brix_status *st);
/* Resolve the default proxy path ($X509_USER_PROXY else /tmp/x509up_u<uid>). */
void brix_proxy_default_path(char *out, size_t outsz);
/* Phase 40 (c): seconds of proxy validity remaining (negative if expired) into
 * *secs_left.  0 on success, -1 if no/unparseable proxy at `path` (NULL=default). */
int brix_proxy_remaining(const char *path, long *secs_left);

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
    brix_progress_cb progress;  /* periodic transfer progress, or NULL */
    void            *progress_arg;
    int         io_uring;  /* phase-44 --io-uring: 0=auto, 1=on, 2=off. Selects
                            * the local-disk io_uring overlap ring in copy.c.
                            * auto = use it iff brix_uring_available(); on with no
                            * liburing = clean CLI error; off = classic read/write. */
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

#endif /* XRDC_OPS_H */
