/* shared_conf_fields_policy.h — cache tiers, write/security/auth/token/TPC
 * policy and runtime-DNS fields of brix_shared_conf_t.  Second fragment of
 * the shared-conf struct: included inside shared_conf_types.h right after
 * shared_conf_fields.h (see the note there). */
    /* ---- phase-64 composable tier grammar (additive over storage_backend) ----
     * Raw directive values parsed + registered at finalisation (the legacy cache
     * directives that share a name — brix_cache, _verify, _slice, _dirty_max_age
     * — are NOT re-used here; the new cache tier uses the non-colliding names and
     * sensible defaults until the P2 legacy-removal big-bang). */
    ngx_str_t           cache_store;        /* brix_cache_store URL ("" = none)   */
    ngx_array_t        *cache_store_args;   /* its credential=/block_size= tokens    */
    ngx_str_t           cache_root;         /* [brix_cache_root <path>] (phase-101 W8):
                                             * legacy read-through cache root; was the
                                             * webdav+s3 twins brix_{webdav,s3}_cache_
                                             * root. "" = disabled. The stream plane's
                                             * fd-based cache (brix_cache_export) is a
                                             * separate mechanism, left as-is. */
    char                cache_root_canon[PATH_MAX]; /* realpath of cache_root; "" =
                                             * disabled. Derived per-protocol at merge
                                             * (after adopt), not adopted. */
    ngx_str_t           cache_cold_store;   /* brix_cache_cold_store URL ("" = none)
                                             * — phase-85 F7 cold tier: eviction
                                             * victims demote here; a miss promotes
                                             * (verified) from here before origin. */
    ngx_array_t        *cache_cold_store_args;
    ngx_array_t        *cache_peers;        /* brix_cache_peers tokens (ngx_str_t[])
                                             * — phase-85 F8 sibling mesh: the
                                             * ring member list, one "host:port"
                                             * per sibling with this node's own
                                             * slot written "self=host:port".
                                             * NULL = no mesh.                    */
    ngx_flag_t          stage_enable;       /* brix_stage on|off                  */
    ngx_str_t           stage_store;        /* brix_stage_store URL               */
    ngx_array_t        *stage_store_args;
    ngx_uint_t          stage_flush_async;  /* brix_stage_flush: 0 sync, 1 async   */
    ngx_flag_t          backend_async;      /* brix_backend_async on|off: route     */
                                            /* namespace mutations through the      */
                                            /* durable coalescing queue (park until */
                                            /* the batch flushes)                   */
    ngx_uint_t          backend_async_batch; /* brix_backend_async_batch: size flush */
    ngx_msec_t          backend_async_wait; /* brix_backend_async_wait: time flush   */
    off_t               cache_max_object;   /* brix_cache_max_object (0 = no cap)  */
    ngx_uint_t          cache_evict_at;     /* brix_cache_evict_at  (percent)      */
    ngx_uint_t          cache_evict_to;     /* brix_cache_evict_to  (percent)      */
    ngx_uint_t          cache_meta_mode;    /* brix_cache_meta  (0 auto..3 sidecar)*/
    ngx_uint_t          cache_verify_mode;  /* brix_cache_verify_mode_e for the
                                             * composed cache tier (phase-68);
                                             * 0/UNSET = off. Registered today by
                                             * the cvmfs protocol only.           */
    ngx_str_t           cache_verify_digest; /* brix_cache_verify_digest <alg>: the
                                             * digest a NON-xroot origin is asked
                                             * for (HTTP/Pelican Want-Digest, an
                                             * object store's stored checksum) so
                                             * best-effort/require have something
                                             * to compare the filled bytes with.
                                             * Empty = ask for nothing (root://
                                             * still offers kXR_Qcksum in band). */
    ngx_flag_t          cache_global_cas;   /* phase-87 G13: hardlink-dedup
                                             * cvmfs-cas-verified CAS objects
                                             * across repos in the local posix
                                             * cache store (default off).        */
    ngx_flag_t          cache_only_if_cached; /* brix_cache_only_if_cached (audit
                                             * §4.4, upstream pfc.onlyifcached):
                                             * serve only what is already cached
                                             * — a read MISS returns ENOENT
                                             * instead of filling from the
                                             * origin, so the client fails over
                                             * to another replica rather than
                                             * making this node pull the object.
                                             * Writes always pass through
                                             * (default off).                    */
    ngx_flag_t          cache_passthrough;  /* phase-92 brix_cache_passthrough:
                                             * store-then-evict an admission-
                                             * declined remote object so the
                                             * coalesced HTTP waiters are served
                                             * a transient hit, then it is
                                             * evicted (default off).            */
    off_t               cache_passthrough_max; /* brix_cache_passthrough_max: the
                                             * spool cap for a passthrough fill;
                                             * 0 = fall back to cache_max_object. */
    ngx_str_t           cache_quarantine_dir; /* verify-mismatch evidence dir;
                                             * "" = unlink the failed part.       */
    ngx_str_t           cache_cvmfs_master_key; /* phase-85 F1: path to the repo
                                             * master public key PEM (may hold
                                             * several concatenated keys). "" =
                                             * no manifest signature verify.     */
    time_t              cache_manifest_ttl; /* phase-68 cvmfs: TTL stamped on
                                             * MANIFEST-class cache fills (secs;
                                             * 0 = no expiry stamping).           */
    time_t              cache_offline_ttl;  /* phase-85 F10 cvmfs: through a
                                             * total origin outage keep serving
                                             * the last verified manifest this
                                             * long past its fill; extends the
                                             * 10x-TTL stale window (0 = off).   */
    time_t              cache_uvkeep;       /* brix_cache_uvkeep (audit §4.3,
                                             * pfc.uvkeep): age out a never-
                                             * verified cache entry past this
                                             * many secs from its fill so the
                                             * next open revalidates (0 = off). */
    time_t              cache_serve_while_filling; /* brix_cache_serve_while_filling
                                             * (audit §4.5, pfc serve-while-
                                             * filling): follow an in-flight
                                             * whole-file fill instead of
                                             * waiting for it, giving up if the
                                             * fill frontier stops advancing for
                                             * this long (0 = off).             */
    time_t              cache_client_hold;  /* phase-68 T20: keep retrying a
                                             * failing fill this long while a
                                             * client waits, then 504+Retry-After
                                             * on a kept-alive conn. 0 = today's
                                             * single-pass fill.                  */
    time_t              cache_fill_max_life; /* T20: detached-fill retry budget
                                             * once every client has gone.       */
    ngx_uint_t          cache_batch_cinfo;  /* brix_cache_batch_cinfo (0 off/1 on/2 auto) */
    size_t              cache_index_cache;  /* brix_cache_index_cache (L1 entries) */
    size_t              cache_slice_size;   /* brix_cache_slice_size (0 = whole-file) */
    ngx_int_t           cache_prefetch;     /* brix_cache_prefetch: max in-flight
                                             * background block-prefetch jobs per
                                             * worker (0 = off)                    */
    size_t              cache_prefetch_window; /* brix_cache_prefetch_window: max
                                             * bytes one WILLNEED hint may queue
                                             * for background fill                 */
    brix_cache_urlcgi_conf_t cache_urlcgi;  /* brix_cache_urlcgi (2.0 F5): the
                                             * per-open pfc.* hint clamps; a
                                             * *_max sentinel = not set here      */
    /* Read-cache admission (deny/allow prefix + include regex).  The directives
     * live on the stream srv conf (they are stream-only and share the matcher
     * with write-through); the protocol finaliser bridges the already-merged
     * pointers here so the protocol-agnostic tier registration can build the
     * composable sd_cache policy from them — read-fill parity with write-through
     * and the legacy cache_origin admit (brix_cache_admit).  NULL when unset. */
    ngx_array_t        *cache_deny_prefixes;  /* brix_wt_prefix_entry_t[] — blacklist */
    ngx_array_t        *cache_allow_prefixes; /* brix_wt_prefix_entry_t[] — whitelist */
    regex_t            *cache_include_re;      /* compiled include filter, or NULL     */
    ngx_flag_t          allow_write;        /* write permission flag               */
    ngx_flag_t          durable_commit;     /* brix_durable_commit on|off: fsync the
                                             * staged upload's data before the commit
                                             * rename publishes it (phase-51 C1
                                             * torn-object guard). ON by default; off
                                             * matches stock XRootD close semantics
                                             * (no per-close fsync — a host crash in
                                             * the writeback window can lose the tail
                                             * of a just-closed upload, but a clean
                                             * close never publishes torn data since
                                             * the rename still orders after the
                                             * writes).                            */
    ngx_flag_t          verify_write;       /* brix_verify_write: fold a self-computed
                                             * read-back CRC check into whole-object
                                             * writes routed through brix_vfs_writer
                                             * (root:// staged, WebDAV/S3 PUT). Off by
                                             * default; never applies to partial/
                                             * ranged (REST/Content-Range) writes.  */
    ngx_flag_t          require_pgwrite;    /* brix_require_pgwrite on|off: refuse a
                                             * cleartext kXR_write / kXR_writev that
                                             * carries data on a writable root:// file
                                             * handle (kXR_Unsupported), forcing clients
                                             * onto the per-page-CRC32c kXR_pgwrite path
                                             * so a hostile-network bit-flip is caught
                                             * on the wire (plain write has no CRC).
                                             * Off by default (plain write is the stock
                                             * upload op); SSI accumulation and
                                             * zero-length no-ops are exempt.          */
    ngx_flag_t          data_substreams;    /* brix_data_substreams on|off (root://):
                                             * accept kXR_bind so a client may open
                                             * secondary data connections (parallel
                                             * reads).  ON by default.  When OFF, bind
                                             * is refused with kXR_Unsupported, so a
                                             * client falls back to sending every
                                             * request (and its data) inline on the
                                             * primary connection (pathid 0) — the
                                             * correct, spec-endorsed fallback.  BriX
                                             * does not yet service a cross-connection
                                             * WRITE data-path, so a deployment fronting
                                             * clients that stream write payloads on a
                                             * substream (e.g. go-hep WithSubStreams)
                                             * turns this off to force the streaming
                                             * inline write path.                       */
    ngx_flag_t          read_only;          /* hard read-only switch: when on, the
                                             * finaliser forces allow_write off so
                                             * EVERY write op is rejected at the
                                             * protocol edge (root:// require_write,
                                             * WebDAV/S3 method gate, write-open)
                                             * before the VFS - and before token
                                             * scope, so a write token cannot bypass
                                             * it. Overrides allow_write on.        */
    ngx_flag_t          read_only_public;   /* [brix_read_only_public on|off] — the
                                             * public-gateway posture: implies
                                             * read_only (the finaliser turns it on),
                                             * and additionally refuses the kXR_query
                                             * infotypes that describe the SERVER
                                             * rather than a path the client may
                                             * already read (QStats, Qspace, Qconfig,
                                             * QFSinfo, Qvisa). Listing, stat, read,
                                             * checksum and per-path xattr are
                                             * untouched, so an anonymous client can
                                             * still browse and stream data.        */
    ngx_flag_t          compress;           /* phase-42: outbound GET compression
                                             * (Accept-Encoding negotiated). Off by
                                             * default; bypasses sendfile when used. */
    ngx_uint_t          tls_require;        /* [brix_tls_require <caps...>] —
                                             * BRIX_TLSREQ_* capability mask
                                             * (vfs_secgate.h): ops exercising a
                                             * masked capability are refused on
                                             * cleartext transports. 0 = off. */
    ngx_flag_t          strict_security;    /* [brix_strict_security on|off] (E-1)
                                             * — refuse valid-but-dangerous configs
                                             * at nginx -t instead of only warning:
                                             * anonymous S3 (no SigV4/token verify),
                                             * WebDAV writes without auth, anonymous
                                             * dashboard, etc. Off by default (warn
                                             * only); see brix_shared_security_gate. */
    ngx_str_t           access_log;         /* HTTP-plane brix_access_log path.
                                             * Empty/off disables sesslog emission
                                             * for HTTP protocols. Stream keeps its
                                             * legacy srv_conf access_log owner. */
    ngx_open_file_t    *access_log_file;    /* nginx-managed HTTP log handle. */
    ngx_flag_t          session_log;        /* brix_session_log on|off; controls
                                             * correlated SESS lifecycle records.
                                             * Default ON wherever an access-log fd
                                             * exists. */
    ngx_flag_t          ktls;               /* [brix_ktls on|off] SSL_OP_ENABLE_KTLS
                                             * on this server's TLS context so HTTPS
                                             * GET sendfiles over kernel-TLS (and PUT
                                             * decrypts in-kernel). Default OFF
                                             * (phase-33 P5: opt-in, HW-offload-only;
                                             * software kTLS regresses). No-op when
                                             * the cipher/kernel cannot offload. See
                                             * docs/.../ktls.md.                     */
    ngx_flag_t          cache_store_endpoint; /* [brix_cache_store_endpoint on|off]
                                             * default OFF. Marks this location as a
                                             * trusted remote cache-STORE surface (a
                                             * cache node's origin-facing endpoint),
                                             * where internal sidecar names (.cinfo /
                                             * .meta / stage markers) are legitimate
                                             * request targets and so must be allowed
                                             * for both read and create. Every normal
                                             * client location leaves it OFF, keeping
                                             * the reserved-name 404 guard in force
                                             * (default-deny). Read at the WebDAV/S3
                                             * path resolver and forwarded to
                                             * brix_http_resolve_path_ex().           */
    ngx_str_t           thread_pool_name;   /* async I/O thread pool name          */
    ngx_thread_pool_t  *thread_pool;        /* resolved pool handle (runtime only) */
    int                 rootfd;             /* O_PATH fd on root_canon for openat2
                                             * RESOLVE_BENEATH confinement; -1 until
                                             * opened per worker at init_process.
                                             * Runtime only — never merged.        */
    brix_pmark_conf_t pmark;              /* SciTags packet-marking config — see
                                             * src/pmark/pmark.h. Shared by every
                                             * protocol; init/merge below.          */
    brix_acc_http_t   acc;                /* XrdAcc engine settings + per-worker
                                             * state (phase-101 W2): promoted from the
                                             * webdav/s3 loc-confs so brix_authdb* /
                                             * brix_acc_* register ONCE on the common
                                             * module and every HTTP protocol (incl.
                                             * cvmfs) inherits via adopt. The tables/
                                             * timer tail is per-worker, NEVER merged. */
    ngx_flag_t        zip_access;         /* [brix_zip_access on|off] (phase-101 W4):
                                             * serve a member of a stored ZIP via a
                                             * ?zip=member query. Was brix_webdav_zip_
                                             * access / brix_s3_zip_access. */
    size_t            zip_cd_max_bytes;   /* [brix_zip_cd_max_bytes] central-directory
                                             * scan cap; was the webdav/s3 twins. */
    ngx_str_t         pwd_file;           /* [brix_pwd_file <file>] (phase-101 W4):
                                             * HTTP basic-auth password db; was
                                             * brix_webdav_pwd_file. Bare on the stream
                                             * plane already. "" = off. */
    ngx_flag_t        upload_resume;      /* [brix_upload_resume on|off] (phase-101
                                             * W4): resumable Content-Range PUT;
                                             * was brix_webdav_upload_resume. Default
                                             * ON (applied in the shared merge). */
    ngx_str_t         token_macaroon_secret;     /* [brix_macaroon_secret <hex>]
                                             * (phase-101 W4): was
                                             * brix_webdav_macaroon_secret. */
    ngx_str_t         token_macaroon_secret_old; /* [brix_macaroon_secret_old <hex>]
                                             * grace-period rotation key. */
    ngx_str_t         upload_stage_dir;    /* [brix_stage_dir <path>] (phase-101 W4):
                                             * optional fast-cache staging device;
                                             * was brix_webdav_stage_dir. The derived
                                             * *_canon buffer stays protocol-local. */
    ngx_str_t         vfs_spill_path;      /* [brix_vfs_spill_path <path>]
                                             * (phase-107 C1): writer reorder-spill
                                             * scratch root; validated absolute and
                                             * outside every export root at nginx -t.
                                             * Empty = fall back to brix_stage_dir,
                                             * else reordered uploads are refused. */
    size_t            vfs_spill_max;       /* [brix_vfs_spill_max <size>]
                                             * (phase-107 C1): cap one spill's span;
                                             * 0 = the filesystem decides. */
    ngx_flag_t        durable_publish;     /* [brix_durable_publish on|off]
                                             * (phase-107 C3): fsync the published
                                             * name's parent directory at every
                                             * publish. Default on — off trades a
                                             * crash-lost name for one dirfsync
                                             * per publish (cache-store use). */
    ngx_uint_t        lock_enforcement;    /* [brix_lock_enforcement
                                             * strict|advisory|off] (phase-107 C7):
                                             * does a live foreign WebDAV lock
                                             * refuse mutations on EVERY plane
                                             * (strict, 0 — the default),
                                             * log-and-allow outside WebDAV
                                             * (advisory, 1), or bind WebDAV-only
                                             * as before C7 (off, 2). Values are
                                             * brix_vfs_lock_enforcement_t. */
    ngx_uint_t        authz_backstop;      /* [brix_authz_backstop
                                             * off|observe|enforce], default
                                             * observe; brix_authz_backstop_mode_t */
    ngx_str_t         crl;                 /* [brix_crl <dir>] (phase-101 W4): CRL PEM
                                             * directory; was brix_webdav_crl. */
    ngx_uint_t        signing_policy_mode; /* [brix_signing_policy] BRIX_SP_MODE_*;
                                             * was brix_webdav_signing_policy. */
    ngx_uint_t        crl_mode;            /* [brix_crl_mode] BRIX_CRL_MODE_*;
                                             * was brix_webdav_crl_mode. */
    ngx_uint_t        legacy_proxy_mode;   /* [brix_gsi_legacy_proxy off|on|full-only]
                                             * BRIX_LEGACY_PROXY_*; default on. */
    ngx_uint_t        crl_scope;           /* [brix_crl_scope all|last] (2.0 F19)
                                             * BRIX_CRL_SCOPE_*; default ALL.
                                             * Narrows the CRL check to the
                                             * certificate's own issuer, as stock
                                             * xrd.tlsca `crlcheck last` does.
                                             * Reach, not strictness: a revoked
                                             * leaf is refused under both. */
    ngx_uint_t        tls_verify_log;      /* [brix_tls_verify_log
                                             * off|failure|all] (2.0 F19)
                                             * BRIX_TLS_VERIFY_LOG_*; default OFF.
                                             * Subject DNs only — never key
                                             * material, never PEM. */
    ngx_str_t         vomsdir;             /* [brix_vomsdir <dir>] (phase-101 W4):
                                             * VOMS *.lsc trust dir; was
                                             * brix_webdav_vomsdir. */
    ngx_str_t         voms_cert_dir;       /* [brix_voms_cert_dir <dir>]: VOMS CA dir;
                                             * was brix_webdav_voms_cert_dir. */
    ngx_array_t      *vo_rules;            /* brix_vo_rule_t[] from [brix_require_vo
                                             * <path> <vo>] (phase-101 W4): per-path VO
                                             * ACL; was the webdav-local brix_webdav_
                                             * require_vo. Honored on webdav/root/gridftp
                                             * (VOMS); parsed-but-inert on s3 (SigV4). */
    ngx_array_t      *authdb_rules;        /* brix_authdb_rule_t[] from [brix_authdb
                                             * <file>] (phase-101 W5.2): native u/g/p/h
                                             * READ ACL; moved here from the webdav-local
                                             * field so brix_authdb registers once on
                                             * http_common (all HTTP planes) into the shared
                                             * preamble.  ENFORCED in the webdav AND s3 access
                                             * phases (+ root:// on stream) — each deep-copies
                                             * this and finalizes the copy against its own
                                             * root (brix_authdb_rules_finalize_copy) so a
                                             * sibling plane's finalize can't mis-resolve it.
                                             * cvmfs is NOT gated: its read-through/CAS path
                                             * model has no local realpath to match. */
    ngx_array_t      *protbind;            /* brix_protbind_rule_t[] from [brix_protbind
                                             * <tpl> none|[only] <proto>...] (phase-101
                                             * W4): per-host credential-source binding
                                             * (XRootD sec.protbind); was brix_webdav_
                                             * protbind. NULL = no rules; shared engine
                                             * in src/auth/protbind/. */
    /* HTTP/stream TPC policy. */
    ngx_flag_t        tpc_allow_local;     /* 0: reject loopback+link-local targets */
    ngx_flag_t        tpc_allow_private;   /* default 1: allow RFC-1918/ULA targets */
    ngx_flag_t        tpc_source_guard;    /* 0: off; on = pull only from an
                                             * authority on tpc_source_allow */
    ngx_array_t      *tpc_source_allow;    /* ngx_str_t[]: exact host or leading-'.'
                                             * domain suffix (NULL = none) */
    /* TPC identity matrix (2.0 F18 — BriX's `ofs.tpc allow|require|restrict|
     * oids`).  The INNER plane: the host verdict above stays the outer gate and
     * these can only narrow it.  Element types are the pure structs from
     * src/tpc/common/identity_matrix.h, stored directly (conf tokens are
     * NUL-terminated and live for the cycle), so no per-request conversion. */
    ngx_array_t      *tpc_allow_identity;  /* brix_tpc_allow_rule_t[]: AND within
                                             * a rule, OR across rules (NULL =
                                             * no identity constraint) */
    ngx_array_t      *tpc_require;         /* brix_tpc_require_rule_t[]: the auth
                                             * method demanded of client / dest /
                                             * all (NULL = none) */
    ngx_array_t      *tpc_restrict;        /* ngx_str_t[]: cleaned LOGICAL path
                                             * prefixes a TPC may touch (NULL =
                                             * unrestricted) */
    ngx_flag_t        tpc_oids;            /* 0 (default, and stock's default):
                                             * refuse a '*'-prefixed object-id
                                             * TPC path outright.  BriX exports
                                             * no object-id namespace, so `on`
                                             * only stops the refusal — it does
                                             * not create one. */
    ngx_flag_t        tpc_require_source_size; /* 0: pull a length-less source anyway;
                                                 * on = refuse it as unverifiable */
    ngx_str_t         tpc_verify_checksum; /* [brix_tpc_verify_checksum on|off|<alg>]
                                             * (phase-101 W4): unified post-copy TPC
                                             * integrity. Normalized at parse: "" =
                                             * off; a canonical checksum alg name
                                             * otherwise ("on" => "adler32", the
                                             * XRootD/WLCG default). The native
                                             * (root) TPC reads it as a boolean gate
                                             * (kXR_Qcksum negotiates its own alg);
                                             * the webdav curl-COPY uses the alg for
                                             * Want-Digest + recompute. Was the flag
                                             * brix_tpc_verify_checksum (stream) and
                                             * the <alg> brix_webdav_tpc_verify_
                                             * checksum (webdav) — now one grammar. */
    ngx_flag_t        tpc_outbound_tls;       /* native TPC source TLS */
    ngx_flag_t        tpc_outbound_passthrough; /* forward inbound bearer */
    ngx_str_t         tpc_outbound_bearer_file; /* static source bearer */
    ngx_str_t         tpc_outbound_token_endpoint; /* RFC 8693 endpoint */
    ngx_str_t         tpc_outbound_client_id;
    ngx_str_t         tpc_outbound_client_secret;
    ngx_str_t         tpc_outbound_scope;
    time_t            tpc_outbound_renew_lead;  /* renew a delegated cred
                                                 * this long before it
                                                 * expires; 0 = never */
    ngx_flag_t        tpc_outbound_renew_strict; /* refuse the rest of a
                                                  * pull whose credential
                                                  * expired and could not
                                                  * be re-minted */
    ngx_str_t         token_jwks;          /* [brix_token_jwks <file>] (phase-101 W4):
                                             * JWKS pubkey file; collapsed webdav+s3
                                             * twins. Per-worker jwks_keys[] stays
                                             * protocol-local. */
    /* [brix_token_jwks_refresh_interval] mtime poll; 0 disables. */
    ngx_msec_t        token_jwks_refresh_interval;
    ngx_str_t         token_issuer;        /* [brix_token_issuer] required "iss". */
    ngx_str_t         token_audience;      /* [brix_token_audience] required "aud". */
    time_t            token_clock_skew;    /* [brix_token_clock_skew] exp/nbf grace;
                                             * sec_slot since phase-105 W8 (suffixes
                                             * legal; the 300s security clamp in the
                                             * shared merge still rejects loudly).
                                             * Unified default 30 (was 30 on webdav,
                                             * 60 on s3 — stricter wins). */
    ngx_str_t         token_config;        /* [brix_token_config <scitokens.cfg>]
                                             * (phase-101 W4): multi-issuer registry
                                             * file; overrides the single-issuer
                                             * jwks/issuer/audience when set. Was the
                                             * webdav-local brix_webdav_token_config;
                                             * bare on the stream plane already. The
                                             * built token_registry stays protocol-
                                             * local. */
    /* OIDC token introspection / revocation (phase-105 W4.1 — were the
     * brix_webdav_token_introspect_* quad; 101 Table 1 planned the bare
     * names). Consulted by the GLOBAL introspection access handler
     * (webdav/introspect.c) for any brix request carrying a Bearer token —
     * the verdict cache (brix_webdav_revoke_cache) stays webdav-scoped. */
    ngx_str_t         introspect_url;      /* [brix_token_introspect_url] display/doc */
    ngx_str_t         introspect_loc;      /* [brix_token_introspect_loc] internal URI
                                             * that proxy_passes to the IdP; enables
                                             * the check ("" = off) */
    time_t            introspect_ttl;      /* [brix_token_introspect_ttl] verdict TTL;
                                             * sec_slot since the move (was num) */
    ngx_flag_t        introspect_fail_open; /* [brix_token_introspect_fail_open] */
    ngx_str_t         certificate;      /* stream GSI/TLS certificate PEM */
    ngx_str_t         certificate_key;  /* stream GSI/TLS private-key PEM */
    ngx_str_t         trusted_ca;         /* [brix_trusted_ca <file>] (phase-105 W2):
                                             * auth-layer verify-source CA bundle for
                                             * the GSI/VOMS chain (101-W6 role name).
                                             * Consumed by webdav cert-auth today;
                                             * scope documented in directives.md. */
    ngx_str_t         trusted_ca_dir;     /* [brix_trusted_ca_dir <dir>] verify-source
                                             * CA directory — file/dir forms of ONE
                                             * source; distinct from client_ca_store
                                             * (front-leg SSL_CTX) and backend_ca_dir
                                             * (proxy back leg) — the 101-W6 four-
                                             * mechanism distinction holds. */
    ngx_uint_t        verify_depth;       /* [brix_verify_depth <n>] (phase-105 W3.5):
                                             * cap on the accepted client proxy-chain
                                             * depth in the auth path (VOMS proxies +
                                             * delegation re-verify). One spelling with
                                             * the stream plane; per-plane defaults
                                             * KEEP (HTTP 10; stream 0=unlimited). */
    ngx_str_t         tcp_congestion;     /* [brix_tcp_congestion <alg>] (phase-105
                                             * W2): sender-side congestion alg applied
                                             * by the SHARED file-serve path — one
                                             * site covers webdav GET, S3 GetObject
                                             * and cvmfs; was webdav-owned while the
                                             * engine was already cross-protocol. */
    brix_mirror_conf_t mirror;            /* [brix_mirror_url/_methods/_sample/
                                             * _strip_auth/_writes/_log_diverge/
                                             * _timeout/_token] (phase-105 W2):
                                             * traffic-mirror SETTINGS — were
                                             * webdav-owned; the engine plumbing
                                             * (upstream conf, TLS ctx, request ctx)
                                             * stays on the webdav conf, which the
                                             * globally-registered phase handlers
                                             * fetch (documented residual, same
                                             * shape as ratelimit_http.c). The
                                             * stream plane keeps its own flat
                                             * copy. */
    ngx_flag_t        delegation_endpoint; /* [brix_delegation_endpoint on|off]
                                             * (phase-105 W2): opt-in GSI proxy-upload
                                             * delegation well-known endpoint. Consumed
                                             * by the webdav dispatch today (HTTP-TPC
                                             * delegation is a webdav COPY mechanism);
                                             * documented webdav-scoped in
                                             * directives.md. Was webdav-owned. */
    ngx_str_t         client_ca_store;    /* [brix_client_ca_store <dir>] (phase-105
                                             * W2): hashed CA dir loaded into the
                                             * SERVER SSL_CTX client-verify store at
                                             * postconfiguration — the listener ctx is
                                             * shared by every protocol on the server,
                                             * so behavior was already server-wide;
                                             * only ownership moved. Hook stays in
                                             * webdav postconfig (documented residual). */
    time_t            max_delay;          /* [brix_max_delay <time>] (phase-105 W3):
                                             * the xrootd maxdelay analog — CAP on the
                                             * client wait/Retry-After seconds a
                                             * response may advertise. Was
                                             * brix_webdav_maxdelay; the stream plane
                                             * spells it brix_max_delay already (its
                                             * flat field + default 60 stay per-plane;
                                             * HTTP default 0 = off). */
    brix_kv_t        *token_cache_kv;     /* [brix_token_cache zone=] (phase-105 W1):
                                             * verified-token KV cache; was the
                                             * webdav-local field, so the bare name
                                             * parsed-but-was-inert on s3/cvmfs
                                             * (first-module-wins routed it to
                                             * webdav's conf). NULL = off. */
    brix_rate_limit_conf_t rate_limit;    /* [brix_rate_limit zone= rate= burst=
                                             * key=dn|ip] (phase-105 W1): token-
                                             * bucket admission; engine in
                                             * core/shm/rate_limit.c. kv==NULL = off
                                             * (the UNSET sentinel — zeroed init). */
    ngx_array_t      *rl_rules;           /* brix_rl_rule_t[] from [brix_rate_limit_
                                             * rule / brix_bandwidth_limit /
                                             * brix_concurrency_limit] (phase-105
                                             * W1): traffic-shaping rules, engine in
                                             * net/ratelimit/. NULL = none; inherited
                                             * WHOLE at merge (like vo_rules) — was
                                             * location-exact on webdav, so server-
                                             * scope rules are new capability. */
    ngx_uint_t        seccomp;            /* brix_seccomp mode (off/audit/enforce)
                                             * for HTTP (WebDAV/S3/cvmfs) servers;
                                             * a record only — the effective mode is
                                             * the process-global brix_seccomp_worker_mode
                                             * (strictest across ALL brix servers,
                                             * incl. stream), 0=OFF via pcalloc.     */
    brix_dns_conf_t   dns;                /* phase-116: [brix_resolver auto|off …]
                                             * policy + [brix_dns_retry] backoff +
                                             * [brix_dns_cache_max] +
                                             * [brix_dns_status_zone]; adopted
                                             * parent -> child like every other
                                             * preamble field (brix_dns_conf_adopt). */
