#ifndef XROOTD_VOMS_INTERNAL_H
#define XROOTD_VOMS_INTERNAL_H

#include "../ngx_xrootd_module.h"

#include <openssl/x509.h>

/*
 * ABI-compatible struct definitions for voms-2.1.3 / EL9.
 *
 * We dlopen() libvoms at runtime (to avoid a hard dependency) and call its
 * VOMS_Retrieve() / VOMS_Destroy() functions through function pointers.
 * These struct layouts match the libvoms ABI; only fields we dereference are
 * given meaningful types.  The rest are opaque placeholders so the byte offsets
 * stay correct across minor library versions.
 *
 * DO NOT change field order or add/remove fields — that would break the dlopen
 * ABI contract.
 */

/*
 * One VOMS attribute item: a group/role/capability triple from one AC.
 *   group: VOMS group name, e.g. "/cms/Production"
 *   role:  role name, e.g. "pilot" (may be NULL for group-only membership)
 *   cap:   capability string (rarely used; usually NULL)
 */
struct voms_data_item {
    char *group;
    char *role;
    char *cap;
};

/*
 * One VOMS attribute certificate (AC) entry: metadata about one VO's AC
 * embedded in the X.509 proxy.
 *   voname: the VO name, e.g. "cms"
 *   fqan:   NULL-terminated array of fully-qualified attribute names, e.g.
 *             ["/cms/Production/Role=pilot/Capability=NULL", NULL]
 *   std:    NULL-terminated array of voms_data_item pointers (structured fqan)
 */
struct voms_entry {
    int    siglen;        /* length of signature bytes */
    char  *signature;     /* AC signature (opaque) */
    char  *user;          /* subject DN of the proxy holder */
    char  *userca;        /* issuer DN of the holder's CA */
    char  *server;        /* VOMS server DN */
    char  *serverca;      /* VOMS server CA DN */
    char  *voname;        /* VO name (primary key for attribute lookups) */
    char  *uri;           /* VOMS server URI */
    char  *date1;         /* AC validity start (ISO 8601) */
    char  *date2;         /* AC validity end */
    int    type;          /* AC type (opaque) */
    struct voms_data_item **std; /* structured attribute list, NULL-terminated */
    char  *custom;        /* custom attribute data (opaque) */
    int    datalen;       /* byte count of custom data */
    int    version;       /* AC version number */
    char **fqan;          /* FQANs as strings, NULL-terminated */
    char  *serial;        /* AC serial number */
    void  *ac;            /* raw OpenSSL AC pointer (opaque) */
    void  *holder;        /* AC holder certificate pointer (opaque) */
};

/*
 * Top-level VOMS data container returned by VOMS_Init().
 *   data:   NULL-terminated array of voms_entry pointers (one per VO AC found)
 *   volen:  number of entries in data[]
 *   real:   internal VOMS library state (opaque; do not access)
 */
struct voms_data {
    char  *cdir;          /* configured VOMS certificates directory (opaque) */
    char  *vdir;          /* configured VOMS server dir (opaque) */
    struct voms_entry **data; /* VO AC entries, NULL-terminated */
    char  *workvo;        /* working VO name (opaque) */
    char  *extra_data;    /* extra data pointer (opaque) */
    int    volen;         /* number of VO AC entries */
    int    extralen;      /* byte count of extra_data */
    void  *real;          /* internal library state; do not free directly */
};

#define VOMS_VERR_NOEXT   5
#define VOMS_VERR_NODATA  11
#define VOMS_RECURSE_CHAIN 0

typedef struct voms_data *(*xrootd_voms_init_pt)(char *voms, char *cert);
typedef int (*xrootd_voms_retrieve_pt)(X509 *cert, STACK_OF(X509) *chain,
    int how, struct voms_data *vd, int *error);
typedef void (*xrootd_voms_destroy_pt)(struct voms_data *vd);
typedef char *(*xrootd_voms_error_message_pt)(struct voms_data *vd,
    int error, char *buf, int len);

typedef struct {
    void                         *handle;
    xrootd_voms_init_pt          init;
    xrootd_voms_retrieve_pt      retrieve;
    xrootd_voms_destroy_pt       destroy;
    xrootd_voms_error_message_pt error_message;
} xrootd_voms_api_t;

extern xrootd_voms_api_t xrootd_voms_api;
extern ngx_flag_t        xrootd_voms_loaded;

ngx_int_t xrootd_collect_voms_vos(struct voms_data *vd,
    char *primary_vo, size_t primary_vo_sz,
    char *vo_list, size_t vo_list_sz);

#endif /* XROOTD_VOMS_INTERNAL_H */
