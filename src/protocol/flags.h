#ifndef XROOTD_PROTOCOL_FLAGS_H
#define XROOTD_PROTOCOL_FLAGS_H

/* ------------------------------------------------------------------ */
/* Open option flags (ClientOpenRequest.options, uint16)               */
/* ------------------------------------------------------------------ */
/*
 * Multiple flags can be OR'd together.  The most common combinations:
 *   read-only:      kXR_open_read
 *   create-write:   kXR_open_updt | kXR_new
 *   overwrite:      kXR_open_updt | kXR_delete
 *   append:         kXR_open_apnd
 *   retstat-open:   kXR_open_read | kXR_retstat  (saves a separate kXR_stat)
 */

#define kXR_compress    0x0001  /* serve compressed copy if available;
                                   not implemented — treated as 0 */
#define kXR_delete      0x0002  /* open for write, truncating to zero first
                                   (equivalent to O_TRUNC | O_WRONLY) */
#define kXR_force       0x0004  /* override "file is offline" status;
                                   attempt access even if storage unavailable */
#define kXR_new         0x0008  /* fail with kXR_ItExists if the file
                                   already exists (O_EXCL behaviour) */
#define kXR_open_read   0x0010  /* open for reading (O_RDONLY) */
#define kXR_open_updt   0x0020  /* open for reading and writing (O_RDWR) */
#define kXR_async       0x0040  /* hint: client prefers async I/O (advisory) */
#define kXR_refresh     0x0080  /* bypass any local cache for this open */
#define kXR_mkpath      0x0100  /* create parent directories if needed;
                                   equivalent to mkdir -p before the open */
#define kXR_open_apnd   0x0200  /* open in append mode (O_APPEND) */
#define kXR_retstat     0x0400  /* include file stat info in the kXR_ok
                                   open response body (avoids a separate
                                   kXR_stat round-trip after open) */
#define kXR_replica     0x0800  /* open a replica / mirror copy */
#define kXR_posc        0x1000  /* persist-on-successful-close: file is
                                   treated as temporary until kXR_close;
                                   abandoned opens are cleaned up */
#define kXR_nowait      0x2000  /* return kXR_wait immediately rather than
                                   blocking if the resource is busy */
#define kXR_seqio       0x4000  /* hint: access will be sequential (advisory;
                                   server may enable readahead) */
#define kXR_open_wrto   0x8000  /* open for write, without read permission;
                                   used by xrdcp source-side staging */

/* ------------------------------------------------------------------ */
/* Stat response flags  (combined into <flags> in the ASCII stat body) */
/* ------------------------------------------------------------------ */
/*
 * The on-wire stat body is a space-separated ASCII string:
 *   "<id> <size> <flags> <mtime>"
 *
 * <flags> is a decimal integer formed by OR-ing the kXR_* values below.
 * kXR_file (0) is the default; set only the bits that apply.
 *
 * FIELD ORDER WARNING: <size> comes BEFORE <flags> in the wire format.
 * Swapping them causes the client to misread kXR_isDir (2) or kXR_readable
 * (16) as the file size, producing confusing "file size = 16" bugs.
 */
#define kXR_file        0    /* plain regular file (no flag bit) */
#define kXR_xset        1    /* executable (x bit set) or searchable dir */
#define kXR_isDir       2    /* path is a directory */
#define kXR_other       4    /* special file — not a regular file or dir */
#define kXR_offline     8    /* file data is not currently online/cached */
#define kXR_readable    16   /* caller has read permission */
#define kXR_writable    32   /* caller has write permission */
#define kXR_poscpend    64   /* POSC (persist-on-close) file, not yet closed */
#define kXR_bkpexist    128  /* a backup copy exists at this site */
#define kXR_statAttrCache  256  /* per-file stat hint: xattr metadata is cached locally;
                                    server can satisfy kXR_fattr without a round-trip.
                                    Local extension — not part of upstream protocol spec.
                                    Named kXR_statAttrCache to avoid collision with the
                                    protocol-level kXR_attrCache (0x80) flag below. */
#define kXR_cachersp    512  /* file is served from a local read-through cache
                               (xcache node); set when conf->cache is on and
                               the file exists in the local cache_root.
                               XRootD clients use this to distinguish a cache
                               server from a plain data server. */

/* ------------------------------------------------------------------ */
/* Protocol request flags  (ClientProtocolRequest.flags, uint8)        */
/* ------------------------------------------------------------------ */
/*
 * Sent by the client in kXR_protocol to advertise its TLS capabilities.
 * The server echoes its own capabilities back in ServerProtocolBody.flags.
 */
#define kXR_secreqs  0x01u  /* client wants the server's security-protocol
                               list (auth mechanism names) */
#define kXR_ableTLS  0x02u  /* client supports in-protocol TLS upgrade;
                               server may respond with kXR_gotoTLS */
#define kXR_wantTLS  0x04u  /* client requires TLS — abort if unavailable */

/* ClientProtocolRequest.expect — what the client will send next. The only value
 * used in practice is kXR_ExpLogin, which tells the server a kXR_login follows the
 * protocol negotiation. Single source of truth so both the module's bootstrap
 * packers and the native client reference the name, not a bare 0x03. */
#define kXR_ExpLogin 0x03

/* ------------------------------------------------------------------ */
/* Protocol response flags  (ServerProtocolBody.flags, uint32)         */
/* ------------------------------------------------------------------ */
/*
 * Lower bits identify the server role; upper bits control TLS negotiation.
 */
#define kXR_isServer      0x00000001u  /* we are a data server (can serve files) */
#define kXR_isManager     0x00000002u  /* we are a manager / redirector */
#define kXR_attrCache     0x00000080u  /* this node is a read-through cache (XCache);
                                          set when xrootd_cache_root is configured.
                                          Distinct from kXR_statAttrCache (stat hint). */
#define kXR_attrMeta      0x00000100u  /* metadata-only: namespace ops only, no file
                                          data; kXR_open redirected or rejected.
                                          Set when xrootd_metadata_only is on. */
#define kXR_attrProxy     0x00000200u  /* this node is a proxy; all file I/O is
                                          forwarded to a backend XRootD server.
                                          Set when xrootd_proxy is on. */
#define kXR_attrSuper     0x00000400u  /* supervisor role: top-tier manager in a
                                          three-level CMS hierarchy; implies
                                          kXR_isManager. Set when xrootd_supervisor. */
#define kXR_attrVirtRdr   0x00000800u  /* virtual redirector: translates logical paths
                                          via static map, not CMS protocol.
                                          Set when xrootd_virtual_redirector is on. */
#define kXR_recoverWrts   0x00001000u  /* server can recover partial writes; requires
                                          kXR_attn async notification (Phase 3). */
#define kXR_collapseRedir 0x00002000u  /* server caches recent redirect targets;
                                          subsequent identical requests skip CMS.
                                          Set when xrootd_collapse_redir is on. */
#define kXR_ecRedir       0x00004000u  /* redirect to erasure-coded storage shards;
                                          out of scope — requires EC storage backend;
                                          defined for completeness, never set. */
#define kXR_supposc       0x00100000u  /* server supports persist-on-successful-close
                                          (kXR_posc open flag); always set. */
#define kXR_suppgrw       0x00200000u  /* server supports kXR_pgread and kXR_pgwrite
                                          with per-page CRC32c integrity; always set. */
#define kXR_supgpf        0x00400000u  /* server supports Grouped Parallel Fetch
                                          (kXR_gpfile opcode 3005, retired in v5);
                                          defined for completeness, never set —
                                          requires gpfile dispatch + src/query/gpfile.c */
#define kXR_anongpf       0x00800000u  /* GPF available to anonymous clients;
                                          defined for completeness, never set —
                                          requires kXR_supgpf to be implemented first */
#define kXR_haveTLS       0x80000000u  /* server can accept an in-protocol TLS
                                          upgrade (kXR_ableTLS) */
#define kXR_gotoTLS       0x40000000u  /* client must upgrade to TLS immediately
                                          before any further requests */
#define kXR_tlsLogin      0x04000000u  /* the kXR_login exchange specifically
                                          requires TLS protection */

/* ------------------------------------------------------------------ */
/* Protocol security requirement options                               */
/* ------------------------------------------------------------------ */

#define kXR_secOData  0x01u  /* signed requests include write payload data */
#define kXR_secOFrce  0x02u  /* allow unencrypted hash signatures */

/* ------------------------------------------------------------------ */
/* Login capver / ability flags  (ClientLoginRequest.capver, uint8)    */
/* ------------------------------------------------------------------ */
/*
 * capver encodes both a version number and an async-capable flag:
 *   capver = (version & kXR_vermask) | kXR_asyncap
 */
#define kXR_asyncap  0x80  /* client can handle asynchronous responses */
#define kXR_vermask  0x3F  /* mask to extract the version bits */
#define kXR_ver003   3     /* XRootD v3 client — base feature set */
#define kXR_ver005   5     /* XRootD v5 client — TLS and kXR_sigver capable */

/* ServerResponseBody_Status.resptype — whether a kXR_status frame is the last for
 * its request (Final) or one of several (Partial, more follow). Single source of
 * truth so the module's pgread/pgwrite framing and the native client reference the
 * names, not bare 0/1. */
#define kXR_FinalResult   0
#define kXR_PartialResult 1

/* ------------------------------------------------------------------ */
/* Per-request option flags                                             */
/* ------------------------------------------------------------------ */

/* kXR_stat — options byte */
#define kXR_vfs  1  /* stat the virtual filesystem (statvfs), not the file;
                       response is "total_space used_space free_space nfs_largefiles" */
#define kXR_statNoFollow 0x40  /* VENDOR (nginx-xrootd local): lstat — do NOT follow
                                  a final symlink, so the reply describes the link
                                  itself (kXR_other flag + target-length size). The
                                  FUSE getattr sets this so symlinks present as
                                  S_IFLNK; stock servers ignore the unknown bit and
                                  follow as before (no interop change). */

/* kXR_dirlist — options byte */
#define kXR_dstat   0x02  /* include per-entry stat (id, size, flags, mtime)
                             after each filename; triggers the 10-byte ".\n0 0 0 0\n"
                             lead-in that the client uses to detect dStat mode */
#define kXR_dcksm   0x04  /* include per-entry checksums; implies dStat */
#define kXR_online  0x01  /* omit entries whose data is not currently online */

/* kXR_prepare — options byte (can be combined) */
#define kXR_cancel  0x01  /* cancel an earlier prepare request */
#define kXR_notify  0x02  /* send a notification when staging finishes */
#define kXR_noerrs  0x04  /* suppress per-path "file not found" errors;
                             the whole request still succeeds if any path fails */
#define kXR_stage   0x08  /* stage files from tape / nearline to online disk */
#define kXR_wmode   0x10  /* prepare for write access */
#define kXR_coloc   0x20  /* request that replicas be placed on the same node */
#define kXR_fresh   0x40  /* require a freshly-fetched (not cached) copy */
#define kXR_usetcp  0x80  /* notification callback uses TCP (not UDP) */

/* kXR_prepare — optionX (extended flags, uint16) */
#define kXR_evict   0x0001  /* evict (remove) cached data after use */

/* kXR_mkdir — options[0] byte */
#define kXR_mkdirpath  0x01  /* create parent directories (mkdir -p behaviour) */

/* ------------------------------------------------------------------ */
/* kXR_writev — vector write options and sizing                        */
/* ------------------------------------------------------------------ */

#define kXR_wv_doSync       0x01  /* fsync the file after all segments written */
#define XROOTD_WRITEV_SEGSIZE   16    /* bytes per write_list struct */
#define XROOTD_WRITEV_MAXSEGS   1024  /* max segments per kXR_writev request */

/* ------------------------------------------------------------------ */
/* kXR_readv — vector read sizing                                      */
/* ------------------------------------------------------------------ */

#define XROOTD_READV_SEGSIZE  16    /* bytes per readahead_list struct */
#define XROOTD_READV_MAXSEGS  1024  /* max segments per kXR_readv request */

/* ------------------------------------------------------------------ */
/* kXR_pgwrite — paged write with CRC32 integrity                      */
/* ------------------------------------------------------------------ */
/*
 * Each page fragment in a pgwrite payload starts with a 4-byte big-endian
 * CRC32c checksum followed by up to XRD_PGWRITE_PAGESZ bytes of data:
 *   [crc32c_be[4]][data[0..4095]] [crc32c_be[4]][data[0..4095]] ...
 * The first and last fragments may be smaller when the file offset is
 * unaligned or the write ends mid-page.
 * Total payload = (full_pages * 4100) + (last_page_size + 4) if partial.
 */
#define XRD_PGWRITE_PAGESZ   4096  /* bytes of data per page */
#define XRD_PGWRITE_CKSZ     4     /* bytes of CRC32c before each page */
#define XRD_PGWRITE_UNITSZ   (XRD_PGWRITE_PAGESZ + XRD_PGWRITE_CKSZ)  /* 4100 */

/* ------------------------------------------------------------------ */
/* kXR_pgread — paged read with CRC32c integrity                       */
/* ------------------------------------------------------------------ */
/*
 * The server response body interleaves data and checksums as
 * [data[4096]][crc32c_be[4]] per page fragment. This is intentionally the
 * inverse order of the client-to-server kXR_pgwrite payload.
 *
 * kXR_pgPageSZ   — page size in bytes
 * kXR_pgPageBL   — log2(page size) = 12, used to convert byte offsets
 *                  to page indices: page_index = byte_offset >> kXR_pgPageBL
 * kXR_pgUnitSZ   — total bytes per page unit (data + checksum)
 * kXR_pgRetry    — reqflags bit: server should retry any failed pages
 * kXR_AnyPath    — pathid value meaning "server chooses the path"
 */
#define kXR_pgPageSZ  4096                          /* bytes per data page */
#define kXR_pgPageBL  12                            /* bits: log2(4096)    */
#define kXR_pgUnitSZ  (kXR_pgPageSZ + 4)           /* 4100 bytes          */
#define kXR_pgRetry   0x01                          /* retry bad pages     */
#define kXR_AnyPath   0xff                          /* let server choose   */

/* CSE (checksum-error) retransmit caps — mirror stock XProtocol limits.
 * kXR_pgMaxEpr: max corrupt pages reportable in ONE pgwrite request (over →
 *   kXR_TooManyErrs). kXR_pgMaxEos: max uncorrected pages outstanding per open
 *   file (the Fob capacity; over → kXR_TooManyErrs). */
#define kXR_pgMaxEpr  128                           /* max errs per request */
#define kXR_pgMaxEos  256                           /* max errs outstanding */

/* ------------------------------------------------------------------ */
/* kXR_sigver — request signing (HMAC-SHA256)                          */
/* ------------------------------------------------------------------ */
/*
 * Each signed request is preceded by a kXR_sigver frame carrying an HMAC
 * over the next request's header (and optionally its payload).
 * The HMAC key is SHA-256(DH-shared-secret) negotiated during GSI auth.
 */
#define kXR_SHA256_sig    0x01  /* HMAC algorithm is HMAC-SHA256 */
#define kXR_HashMask_sig  0x0f  /* mask to extract the hash algorithm ID */
#define kXR_rsaKey_sig    0x80  /* signing key is RSA-based (not DH-derived) */
#define kXR_nodata_sig    0x01  /* payload bytes were NOT included in the HMAC
                                   (only the 24-byte request header was signed) */

/* ------------------------------------------------------------------ */
/* kXR_set — modifier byte values                                      */
/* ------------------------------------------------------------------ */
/*
 * The modifier byte in ClientSetRequest selects what the client is setting.
 * Servers that do not recognise a modifier MUST return kXR_ok (the spec
 * treats all kXR_set payloads as advisory hints).
 */
#define kXR_set_appid  0x00  /* set the application-ID string for this session;
                                payload is an arbitrary NUL-terminated label used
                                for server-side monitoring and logging */
#define kXR_set_clttl  0x01  /* set client time-to-live (session keep-alive hint);
                                payload is a decimal number of seconds as ASCII */

/* ------------------------------------------------------------------ */
/* kXR_chkpoint — checkpoint sub-operation codes and size limit        */
/* ------------------------------------------------------------------ */

#define kXR_ckpBegin     0   /* save current file state to checkpoint */
#define kXR_ckpCommit    1   /* discard checkpoint, make writes permanent */
#define kXR_ckpQuery     2   /* query checkpoint size / capacity */
#define kXR_ckpRollback  3   /* restore file from checkpoint */
#define kXR_ckpXeq       4   /* execute a write sub-op under checkpoint protection */

/* Maximum checkpoint file size (100 MiB + 4 bytes, matching the XRootD reference). */
#define kXR_ckpMinMax    104857604

/* ------------------------------------------------------------------ */
/* kXR_fattr — extended attribute limits and option bits               */
/* ------------------------------------------------------------------ */

#define kXR_faMaxVars  16      /* max attributes per request */
#define kXR_faMaxNlen  248     /* max attribute name length in bytes */
#define kXR_faMaxVlen  65536   /* max attribute value length in bytes */

#define kXR_fa_isNew   0x01    /* (set) fail if the attribute already exists */
#define kXR_fa_aData   0x10    /* (list) include attribute values in response,
                                   not just names */
#define kXR_fa_recurse 0x20    /* (list) LOCAL EXTENSION — recurse into
                                   subdirectories; response entries are
                                   "<relpath>:<U.name>\0" pairs */

#endif /* XROOTD_PROTOCOL_FLAGS_H */
