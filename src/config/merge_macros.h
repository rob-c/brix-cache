#ifndef XROOTD_CONFIG_MERGE_MACROS_H
#define XROOTD_CONFIG_MERGE_MACROS_H
/*
 * merge_macros.h — config merge helpers for patterns nginx's built-ins don't cover.
 *
 * nginx provides ngx_conf_merge_{value,str_value,uint_value,msec_value,...}
 * for scalar fields.  These macros handle the three remaining patterns that
 * appear across the module's merge functions:
 *
 *   XROOTD_MERGE_PTR      — NULL-sentinel pointer (no default; just inherit)
 *   XROOTD_MERGE_HOSTPORT — paired ngx_str_t host + port (inherit together)
 *   XROOTD_MERGE_ENUM     — custom enum with an explicit UNSET sentinel
 *
 * Naming mirrors nginx's ngx_conf_merge_* convention.
 */

/* NULL-sentinel pointer: copy from parent if child is unset (NULL). */
#define XROOTD_MERGE_PTR(conf, prev, field)                         \
    if ((conf)->field == NULL) { (conf)->field = (prev)->field; }

/*
 * Paired host+port fields where len==0 is the "unset" sentinel.
 * Both fields are inherited together or not at all.
 */
#define XROOTD_MERGE_HOSTPORT(conf, prev, host, port)               \
    if ((conf)->host.len == 0 && (prev)->host.len > 0) {            \
        (conf)->host = (prev)->host;                                 \
        (conf)->port = (prev)->port;                                 \
    }

/*
 * Custom enum field with an explicit UNSET sentinel value.
 * If child is UNSET, inherit parent or apply def.
 */
#define XROOTD_MERGE_ENUM(conf, prev, field, unset, def)            \
    if ((conf)->field == (unset)) {                                  \
        (conf)->field = ((prev)->field != (unset))                   \
                        ? (prev)->field : (def);                     \
    }

#endif /* XROOTD_CONFIG_MERGE_MACROS_H */
