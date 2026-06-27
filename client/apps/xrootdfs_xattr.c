/*
 * xrootdfs_xattr.c - extracted concern
 * Phase-38 split of xrootdfs.c; behavior-identical.
 */
#include "xrootdfs_internal.h"


int op_qspace(xrdc_conn *c, void *v, xrdc_status *st)
{ struct ctx_qspace *a = v; return xrdc_query(c, kXR_Qspace, a->path, a->out, a->outsz, st); }


/* extended attributes (opt-in --xattr) — sync pool                    */

const char *
xfs_xattr_to_fattr(const char *name)
{
    if (strncmp(name, "user.", 5) == 0 && name[5] != '\0') {
        return name + 5;
    }
    return NULL;
}


int op_cks(xrdc_conn *c, void *v, xrdc_status *st)
{ struct ctx_cks *a = v; return xrdc_query_cksum(c, a->path, a->algo, a->hex, a->hexsz, st); }


int op_faget(xrdc_conn *c, void *v, xrdc_status *st)
{ struct ctx_faget *a = v; return xrdc_fattr_get(c, a->path, a->name, a->val, a->bufsz, a->vlen, st); }


int
xfs_getxattr(const char *path, const char *name, char *value, size_t size)
{
    if (g_web) return -ENOTSUP;
    xrdc_status st;
    int         rc;
    size_t      vlen = 0;
    const char *fname;

    if (!g_xattr) {
        return -ENOTSUP;
    }
    xrdc_status_clear(&st);
    char pbuf[XRDC_PATH_MAX];
    path = srv_path(path, pbuf, sizeof(pbuf));

    if (strncmp(name, XFS_CKS_XATTR_PFX, sizeof(XFS_CKS_XATTR_PFX) - 1) == 0) {
        const char *algo = name + sizeof(XFS_CKS_XATTR_PFX) - 1;
        char        hex[160];
        if (algo[0] == '\0') {
            return -ENODATA;
        }
        struct ctx_cks a = { path, algo, hex, sizeof(hex) };
        rc = xfs_meta(op_cks, &a, &st);
        if (rc != 0) {
            return rc;
        }
        vlen = strlen(hex);
        if (size == 0) {
            return (int) vlen;
        }
        if (vlen > size) {
            return -ERANGE;
        }
        memcpy(value, hex, vlen);
        return (int) vlen;
    }

    fname = xfs_xattr_to_fattr(name);
    if (fname == NULL) {
        return -ENODATA;
    }
    struct ctx_faget a = { path, fname, value, size, &vlen };
    rc = xfs_meta(op_faget, &a, &st);
    if (rc != 0) {
        return rc;
    }
    if (size == 0) {
        return (int) vlen;
    }
    if (vlen > size) {
        return -ERANGE;
    }
    return (int) vlen;
}


int op_faset(xrdc_conn *c, void *v, xrdc_status *st)
{ struct ctx_faset *a = v;
  return xrdc_fattr_set(c, a->path, a->name, a->val, a->vlen, a->create_only, st); }

int
xfs_setxattr(const char *path, const char *name, const char *value,
             size_t size, int flags)
{
    if (g_web) return -EROFS;
    xrdc_status st;
    const char *fname;
    if (!g_xattr) {
        return -ENOTSUP;
    }
    if (strncmp(name, XFS_CKS_XATTR_PFX, sizeof(XFS_CKS_XATTR_PFX) - 1) == 0) {
        return -EACCES;
    }
    fname = xfs_xattr_to_fattr(name);
    if (fname == NULL) {
        return -ENOTSUP;
    }
    xrdc_status_clear(&st);
    char pbuf[XRDC_PATH_MAX];
    struct ctx_faset a = { srv_path(path, pbuf, sizeof(pbuf)), fname, value, size,
                           (flags & XATTR_CREATE) ? 1 : 0 };
    return xfs_meta(op_faset, &a, &st);
}


int op_fadel(xrdc_conn *c, void *v, xrdc_status *st)
{ struct ctx_fadel *a = v; return xrdc_fattr_del(c, a->path, a->name, st); }


int
xfs_removexattr(const char *path, const char *name)
{
    if (g_web) return -EROFS;
    xrdc_status st;
    const char *fname;
    if (!g_xattr) {
        return -ENOTSUP;
    }
    if (strncmp(name, XFS_CKS_XATTR_PFX, sizeof(XFS_CKS_XATTR_PFX) - 1) == 0) {
        return -EACCES;
    }
    fname = xfs_xattr_to_fattr(name);
    if (fname == NULL) {
        return -ENODATA;
    }
    xrdc_status_clear(&st);
    char pbuf[XRDC_PATH_MAX];
    struct ctx_fadel a = { srv_path(path, pbuf, sizeof(pbuf)), fname };
    return xfs_meta(op_fadel, &a, &st);
}


int op_falist(xrdc_conn *c, void *v, xrdc_status *st)
{ struct ctx_falist *a = v; return xrdc_fattr_list(c, a->path, a->raw, a->rawsz, a->rawlen, st); }


int
xfs_listxattr(const char *path, char *list, size_t size)
{
    if (g_web) return -ENOTSUP;
    xrdc_status st;
    char        raw[16384];
    size_t      rawlen = 0;

    if (!g_xattr) {
        return -ENOTSUP;
    }
    xrdc_status_clear(&st);
    char pbuf[XRDC_PATH_MAX];
    struct ctx_falist a = { srv_path(path, pbuf, sizeof(pbuf)), raw, sizeof(raw),
                            &rawlen };
    int rc = xfs_meta(op_falist, &a, &st);
    if (rc != 0) {
        return rc;
    }
    if (rawlen > sizeof(raw)) {
        rawlen = sizeof(raw);
    }
    /* Convert each server name "U.<x>" → the FUSE name "user.<x>". */
    return xrdc_fattr_listxattr_xlate(raw, rawlen, list, size);
}
