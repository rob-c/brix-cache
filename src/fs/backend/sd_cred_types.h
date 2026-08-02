/*
 * sd_cred_types.h — per-open backend credential types for the Storage Driver
 *                   seam.
 *
 * A verbatim relocation of the credential POD types out of sd.h (pure textual
 * split to keep every SD header < 600 LOC): the accepted-kind bitmap
 * (brix_sd_cred_kind_t), the acquisition-mode enum (brix_cred_mode), and the
 * per-open credential record (brix_sd_cred_t). Self-contained C types with no
 * nginx dependency — valid in both the nginx build and the ngx-free
 * XRDPROTO_NO_NGX client build. Do NOT include this header directly — include
 * "sd.h".
 */
#ifndef BRIX_SD_CRED_TYPES_H
#define BRIX_SD_CRED_TYPES_H

/* Delegation credential kinds a backend can consume (phase-71). A backend ORs
 * the kinds it accepts into brix_sd_driver_s.cred_accept; the VFS denies (EACCES)
 * before touching the origin when the live credential kind is not accepted. */
typedef enum {
    BRIX_SD_CRED_NONE      = 0,
    BRIX_SD_CRED_BEARER    = 1u << 0,  /* raw JWT bearer text        */
    BRIX_SD_CRED_PROXY_PEM = 1u << 1,  /* full x509 proxy PEM        */
    /* Local identity: the backend consumes only WHO the client is (principal +
     * VO list) for its own ownership/enforcement model — no forwardable secret
     * is required or minted, so no credential directory needs configuring.
     * pblock's catalog-internal ownership registry is the consumer. */
    BRIX_SD_CRED_IDENTITY  = 1u << 2,
    /* SSS identity injection (phase-70 §5.6 / P90-70.3): the backend re-issues
     * an XrdSecsss credential to its origin ASSERTING the inbound caller's
     * principal, signed with a gateway-held shared keytab. No forwardable
     * secret comes from the client; the keytab is the export's
     * (brix_backend_sss_keytab). sd_xroot is the consumer. */
    BRIX_SD_CRED_SSS       = 1u << 3,
    /* S3 STS EXCHANGE (phase-70 §5.5): the backend signs the origin leg with a
     * short-lived SigV4 keypair + session token the gate obtained by trading the
     * node's S3 service credential for one scoped to the inbound principal
     * (AssumeRole / GetSessionToken). sd_remote/S3 is the consumer — it reads
     * s3_ak/s3_sk/s3_region and, when set, s3_session (X-Amz-Security-Token). */
    BRIX_SD_CRED_S3        = 1u << 4,
    /* krb5 GSSAPI EXCHANGE (phase-70 §5.7): the backend authenticates its origin
     * leg AS the inbound user by forwarding the user's delegated TGT through a
     * multi-leg GSSAPI negotiation (brix_cache_origin_auth_krb5). The forwardable
     * TGT is carried async-safely as a 0600 FILE ccache PATH (krb5_ccache) — a
     * live gss_cred_id_t is request-scoped and cannot ride the async fill task —
     * plus the origin service principal (krb5_princ). A root:// origin that
     * advertises krb5 is the consumer; the origin leg re-imports the cred from
     * the ccache path via brix_krb5_cred_from_ccache. */
    BRIX_SD_CRED_GSS_KRB5  = 1u << 5
} brix_sd_cred_kind_t;

/* Per-open user credential passed from the protocol handler to the storage
 * driver so a remote backend can authenticate AS the client user (Phase 1:
 * x509 proxy; Phase 2 T2: WLCG bearer token).  Extended with the fields needed
 * to re-resolve the credential for async/deferred flushes.
 *
 * WHAT: Borrowed pointers valid for the duration of the open() / staged_open()
 *       call. Drivers that defer the open (thread-pool) MUST copy the strings
 *       internally before returning — the caller's buffers may be freed once
 *       the vtable function returns.
 *
 * WHY:  A per-open cred lets the VFS pass identity down to the driver without
 *       threading it through every intermediate layer; the driver is the only
 *       entity that knows how to present it to a specific remote protocol.
 *       The extra fields (key, cred_dir, fallback_deny) let decorator layers
 *       (sd_stage, sd_cache) embed a re-resolvable identity into their durable
 *       state so an async flush — possibly after a crash and restart — can
 *       re-authenticate as the original user rather than the service account.
 *
 * HOW:  The gate fills exactly ONE credential kind: {x509_proxy}, {bearer},
 *       {s3_ak + s3_sk (+ s3_region)}, or {ceph_keyring + ceph_user}
 *       depending on the kind selected by ucred_select; the other kinds'
 *       fields are NULL.  Drivers check the kind they support (sd_xroot:
 *       x509_proxy then bearer; sd_remote/S3: s3_ak; sd_ceph: ceph_keyring) —
 *       only one kind is ever set for a given open.
 *       A NULL cred or a driver with no open_cred slot falls back to the plain
 *       open slot (service credential / anonymous).
 *       sd_xroot reads x509_proxy OR bearer + principal; sd_remote reads
 *       s3_ak/s3_sk/s3_region (phase-3 T3) to re-init its SigV4 signer per
 *       open instead of the export's static access_key/secret_key/region;
 *       sd_ceph reads ceph_keyring/ceph_user (ceph-peruser item) to open a
 *       per-user librados connection instead of the export's static
 *       user/keyring.
 *       The extra fields (key, cred_dir, fallback_deny) are consumed by
 *       sd_stage / sd_cache and are not required by sd_xroot, sd_remote, or
 *       sd_ceph. */

/* How the per-open credential in brix_sd_cred_t was obtained — the strategy the
 * VFS gate resolved for the backend leg (phase-70 §4). SELECT (the default, 0)
 * is the pre-phase-70 directory-lookup behaviour, so every existing caller that
 * leaves the struct zeroed keeps the same meaning. The other modes are set by
 * the delegation gate (vfs_deleg.c) when the front door captured a forwardable
 * credential:
 *   PASSTHROUGH — replay the exact credential the user presented (bearer bytes;
 *                 a user-supplied full x509 proxy incl. private key);
 *   EXCHANGE    — trade the inbound credential for a backend-valid one (RFC 8693
 *                 token-exchange; S3 STS; GSSAPI krb5 forwarding);
 *   DELEGATE    — obtain a fresh short-lived proxy via a GridSite handshake;
 *   MINT        — mint a fresh short-lived proxy from a local CA;
 *   AUTO        — dispatch by id->auth_method (§2 matrix).
 * The field is advisory metadata for audit/metrics and for the async re-acquire
 * record; the cred's byte/path fields still say WHICH credential to present. */
enum brix_cred_mode {
    BRIX_CRED_SELECT      = 0,
    BRIX_CRED_PASSTHROUGH,
    BRIX_CRED_EXCHANGE,
    BRIX_CRED_DELEGATE,
    BRIX_CRED_MINT,
    BRIX_CRED_AUTO
};

typedef struct {
    const char *x509_proxy;      /* path to per-user proxy PEM (NULL unless x509 cred) */
    const char *bearer;          /* WLCG bearer token text (NULL unless bearer cred)   */
    const char *s3_ak;           /* S3 access key id (NULL unless s3 cred)             */
    const char *s3_sk;           /* S3 secret key (NULL unless s3 cred; never log)     */
    const char *s3_region;       /* S3 region (NULL unless s3 cred)                    */
    const char *s3_session;      /* STS session token → X-Amz-Security-Token (NULL for */
                                  /* a static keypair; set only for EXCHANGE; never log)*/
    const char *ceph_keyring;    /* CephX keyring PATH (NULL unless ceph cred; never   */
                                  /* log its contents)                                  */
    const char *ceph_user;       /* bare CephX user id, e.g. "bob" (NULL unless ceph   */
                                  /* cred)                                              */
    const char *sss_keytab;      /* SSS identity-injection keytab PATH (NULL unless the
                                  * delegation gate resolved SSS injection; the driver
                                  * then asserts `principal` to the origin via SSS,
                                  * signed with this keytab — phase-70 §5.6)           */
    const char *krb5_ccache;     /* krb5 forwarded-TGT FILE ccache PATH (NULL unless the
                                  * gate resolved krb5 GSSAPI EXCHANGE; the origin leg
                                  * re-imports the delegated cred from it and negotiates
                                  * AS the caller — phase-70 §5.7; never log)          */
    const char *krb5_princ;      /* origin service principal for the krb5 leg, e.g.
                                  * host/<backend-fqdn>@REALM (NULL unless krb5 cred)  */
    const char *key;             /* credential-dir lookup key (audit + flush re-resolve) */
    const char *principal;       /* authenticated principal (audit/ledger; may be NULL) */
    const char *vos;             /* comma-separated VO/group names of the principal      */
                                  /* (NULL or "" when none; consumed by IDENTITY drivers) */
    const char *cred_dir;        /* export credential directory (flush re-resolve)      */
    enum brix_cred_mode mode;    /* how this cred was obtained (phase-70; 0 = SELECT)   */
    unsigned    fallback_deny:1; /* 1 = service-credential fallback forbidden           */
} brix_sd_cred_t;

#endif /* BRIX_SD_CRED_TYPES_H */
