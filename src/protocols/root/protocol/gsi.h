#ifndef XROOTD_PROTOCOL_GSI_H
#define XROOTD_PROTOCOL_GSI_H

/*
 * GSI (x509) authentication wire constants.
 * Source: xrootd/xrootd src/XrdSecgsi/XrdSecProtocolgsi.hh
 *         and src/XrdSut/XrdSutBuffer.hh
 */

/* ------------------------------------------------------------------ */
/* GSI handshake step numbers                                           */
/* ------------------------------------------------------------------ */

/*
 * Server sends steps in the kXGS_* range; client in the kXGC_* range.
 * Steps are carried as the first 4-byte big-endian field in every
 * XrdSutBuffer after the null-terminated protocol name ("gsi\0").
 */
#define kXGS_init       2000    /* server → client: initial exchange    */
#define kXGS_cert       2001    /* server → client: server cert + DH    */
#define kXGS_pxyreq     2002    /* server → client: proxy request       */
#define kXGC_certreq    1000    /* client → server: cert request        */
#define kXGC_cert       1001    /* client → server: client cert + DH    */
#define kXGC_sigpxy     1002    /* client → server: signed proxy        */

/* ------------------------------------------------------------------ */
/* XrdSutBucket type codes (kXRS_*)                                     */
/* ------------------------------------------------------------------ */

/*
 * Every bucket on the wire is [type:4B BE][len:4B BE][data:len].
 * A bucket with type=kXRS_none signals end-of-message.
 * Parsing runs as a length-delimited loop until the terminator is seen
 * or the enclosing auth payload is exhausted.
 */
#define kXRS_none           0       /* terminator bucket                 */
#define kXRS_inactive       1       /* skipped during serialisation      */
#define kXRS_cryptomod   3000       /* crypto module name ("ssl")        */
#define kXRS_main        3001       /* inner/encrypted main buffer       */
#define kXRS_puk         3004       /* server DH public key blob         */
#define kXRS_cipher      3005       /* DH public params / ciphertext     */
#define kXRS_rtag        3006       /* random challenge tag              */
#define kXRS_signed_rtag 3007       /* signed random tag                 */
#define kXRS_user        3008       /* username string                   */
#define kXRS_creds       3010       /* credential bytes (XrdSecpwd)      */
#define kXRS_version     3014       /* protocol version (int32)          */
#define kXRS_status      3015       /* pwdStatus_t word (XrdSecpwd)      */
#define kXRS_clnt_opts   3019       /* client option flags (int32)       */
#define kXRS_x509        3022       /* X.509 certificate (PEM text)      */
#define kXRS_issuer_hash 3023       /* CA subject name hash (uint32)     */
#define kXRS_x509_req    3024       /* X.509 certificate request (proxy delegation) */
#define kXRS_cipher_alg  3025       /* supported cipher algorithms       */
#define kXRS_md_alg      3026       /* supported digest algorithms       */

/* GSI protocol version sent in kXRS_version bucket. 20100 = 2.01.00 */
#define kXGSI_VERSION    20100

#endif /* XROOTD_PROTOCOL_GSI_H */
