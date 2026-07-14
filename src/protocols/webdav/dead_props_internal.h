/*
 * dead_props_internal.h - shared surface between dead_props.c and its
 * dead_props_keys.c sibling.
 *
 * Holds the xattr key-space constants and the key encode/decode/validate
 * helpers that dead_props_keys.c defines and dead_props.c consumes.  Symbols
 * used in only one translation unit stay static in that unit and are absent
 * here.
 */

#ifndef _NGX_HTTP_BRIX_WEBDAV_DEAD_PROPS_INTERNAL_H_INCLUDED_
#define _NGX_HTTP_BRIX_WEBDAV_DEAD_PROPS_INTERNAL_H_INCLUDED_

#include "webdav.h"

#ifndef ENOATTR
#define ENOATTR ENODATA
#endif

/*
 * xattr naming scheme: an xattr key is
 *   "user.nginx_xrootd.webdav." <hex(namespace-URI)> "." <hex(local-name)>
 * Both the XML namespace URI and the local element name are lowercase-hex
 * encoded so that arbitrary URI bytes (':', '/', '.', etc.) survive the
 * "user." flat keyspace, and the single literal '.' separator is unambiguous
 * (real dots inside the URI/name become "2e", never a bare '.').
 * NAME_MAX 255 is the Linux xattr-key limit; VALUE_MAX/LIST_MAX cap how much
 * we will read back so a hostile filesystem cannot force unbounded allocs.
 */
#define WEBDAV_DEAD_PROP_PREFIX      "user.nginx_xrootd.webdav."
#define WEBDAV_DEAD_PROP_PREFIX_LEN  (sizeof(WEBDAV_DEAD_PROP_PREFIX) - 1)
#define WEBDAV_DEAD_PROP_NAME_MAX    255
#define WEBDAV_DEAD_PROP_VALUE_MAX   16384
#define WEBDAV_DEAD_PROP_LIST_MAX    65536

/*
 * Validate that a decoded local name is a safe XML element name before it is
 * spliced back into a PROPFIND response (defined in dead_props_keys.c).
 */
ngx_flag_t webdav_dead_prop_xml_name_ok(const char *name);

/*
 * Encode (namespace URI, local name) into the flat xattr key
 * (defined in dead_props_keys.c).
 */
ngx_int_t webdav_dead_prop_attr_name(const char *ns, const char *local,
    char *out, size_t outsz);

/*
 * Parse one listxattr entry back into (namespace, local name)
 * (defined in dead_props_keys.c).
 */
ngx_int_t webdav_dead_prop_decode_attr(ngx_pool_t *pool, const char *attr,
    char **ns_out, char **local_out);

#endif /* _NGX_HTTP_BRIX_WEBDAV_DEAD_PROPS_INTERNAL_H_INCLUDED_ */
