/*
 * stream_mirror_config.c — Phase 24 XRootD stream mirror: configuration-time
 * directive setters (see stream_mirror.h).
 *
 * WHAT: Owns the three brix_stream_mirror_* directive setters and their private
 *       parse helpers: brix_stream_mirror_url (resolve + append a shadow target),
 *       and the opcode allowlist / exclude setters plus the opcode-name -> bit
 *       table they share.
 * WHY:  split out (phase-79 file-size cap) from the request-path code in
 *       stream_mirror.c / stream_mirror_launch.c so each file stays under the
 *       500-line cap.  This file runs ONLY at configuration time (getaddrinfo,
 *       token parsing) and shares nothing with the event-loop engine beyond the
 *       public conf struct — so it needs neither stream_mirror_internal.h nor the
 *       shadow-connection primitives.
 * HOW:  the setters are declared in stream_mirror.h and registered in the stream
 *       module's directive table; each populates fields on conf->mirror.  Opcode
 *       tokens are mapped through a NULL-terminated name/bit table, keeping the
 *       parse loop a flat data walk.
 */
#include "stream_mirror.h"


/* directive setters */
/*
 * brix_stream_mirror_url host:port — append one shadow target, resolved at
 * configuration time so request handlers never call getaddrinfo on the event
 * loop.  Up to BRIX_MIRROR_MAX_TARGETS may be configured.
 */
char *
brix_stream_mirror_set_url(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_stream_brix_srv_conf_t *xcf = conf;
    ngx_str_t                    *value = cf->args->elts;
    brix_mirror_target_t       *t;
    ngx_url_t                     u;
    u_char                       *colon;
    ngx_str_t                     hostport = value[1];

    (void) cmd;

    if (xcf->mirror.targets == NULL) {
        xcf->mirror.targets = ngx_array_create(cf->pool,
            BRIX_MIRROR_MAX_TARGETS, sizeof(brix_mirror_target_t));
        if (xcf->mirror.targets == NULL) {
            return NGX_CONF_ERROR;
        }
    }
    if (xcf->mirror.targets->nelts >= BRIX_MIRROR_MAX_TARGETS) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
            "brix_stream_mirror_url: at most %d targets supported",
            BRIX_MIRROR_MAX_TARGETS);
        return NGX_CONF_ERROR;
    }

    if (hostport.len == 0
        || ngx_strlchr(hostport.data, hostport.data + hostport.len, ':')
           == NULL)
    {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
            "brix_stream_mirror_url: expected host:port, got \"%V\"",
            &hostport);
        return NGX_CONF_ERROR;
    }

    ngx_memzero(&u, sizeof(ngx_url_t));
    u.url          = hostport;
    u.default_port = 1094;
    if (ngx_parse_url(cf->pool, &u) != NGX_OK || u.naddrs == 0) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
            "brix_stream_mirror_url: cannot resolve \"%V\"%s%s", &hostport,
            u.err ? ": " : "", u.err ? u.err : "");
        return NGX_CONF_ERROR;
    }

    t = ngx_array_push(xcf->mirror.targets);
    if (t == NULL) {
        return NGX_CONF_ERROR;
    }
    ngx_memzero(t, sizeof(*t));
    t->url  = hostport;
    t->host = u.host;
    t->port = u.port;
    if (u.addrs[0].socklen > sizeof(t->sockaddr)) {
        return NGX_CONF_ERROR;
    }
    ngx_memcpy(&t->sockaddr, u.addrs[0].sockaddr, u.addrs[0].socklen);
    t->socklen = u.addrs[0].socklen;

    /* keep the host:port colon split out of the host label for logging */
    colon = ngx_strlchr(hostport.data, hostport.data + hostport.len, ':');
    if (colon != NULL && t->host.len == 0) {
        t->host.data = hostport.data;
        t->host.len  = (size_t) (colon - hostport.data);
    }

    ngx_conf_log_error(NGX_LOG_NOTICE, cf, 0,
        "brix: stream mirror target %V", &hostport);
    return NGX_CONF_OK;
}

/*
 * Opcode-name → bitmask table.
 *
 * WHAT: static lookup pairing each accepted brix_mirror_opcodes token with the
 *       BRIX_MIRROR_OP_* bit(s) it selects.  "all" expands to the full set.
 * WHY:  a data table replaces a 16-arm if/else ladder, keeping the parse loop
 *       branch-flat and making the accepted vocabulary a single edit point.
 * HOW:  terminated by a NULL name; brix_mirror_opcode_name_bit() scans it.
 */
typedef struct {
    const char  *name;
    ngx_uint_t   bit;
} brix_mirror_opcode_name_t;

static const brix_mirror_opcode_name_t  brix_mirror_opcode_names[] = {
    { "all",      BRIX_MIRROR_OP_ALL      },
    { "stat",     BRIX_MIRROR_OP_STAT     },
    { "locate",   BRIX_MIRROR_OP_LOCATE   },
    { "open",     BRIX_MIRROR_OP_OPEN     },
    { "read",     BRIX_MIRROR_OP_READ     },
    { "readv",    BRIX_MIRROR_OP_READV    },
    { "dirlist",  BRIX_MIRROR_OP_DIRLIST  },
    { "statx",    BRIX_MIRROR_OP_STATX    },
    { "query",    BRIX_MIRROR_OP_QUERY    },
    /* Write/mutation opcodes (require brix_mirror_writes on). */
    { "mkdir",    BRIX_MIRROR_OP_MKDIR    },
    { "rm",       BRIX_MIRROR_OP_RM       },
    { "rmdir",    BRIX_MIRROR_OP_RMDIR    },
    { "mv",       BRIX_MIRROR_OP_MV       },
    { "truncate", BRIX_MIRROR_OP_TRUNCATE },
    { "chmod",    BRIX_MIRROR_OP_CHMOD    },
    { "write",    BRIX_MIRROR_OP_WRITE    },
    { NULL,       0                       },
};

/*
 * Map one opcode-name token to its bitmask.
 *
 * WHAT: return the BRIX_MIRROR_OP_* bit(s) for @name, or 0 if unrecognised.
 * WHY:  isolates the table scan so the parse loop stays a flat data walk.
 * HOW:  linear scan of brix_mirror_opcode_names (small, config-time only).
 */
static ngx_uint_t
brix_mirror_opcode_name_bit(const u_char *name)
{
    const brix_mirror_opcode_name_t *e;

    for (e = brix_mirror_opcode_names; e->name != NULL; e++) {
        if (ngx_strcmp(name, e->name) == 0) {
            return e->bit;
        }
    }
    return 0;
}

/*
 * Parse opcode name args (cf->args[1..]) into a bitmask.  "all" expands to
 * BRIX_MIRROR_OP_ALL.  Shared by the allowlist and exclude setters.
 */
static char *
brix_mirror_parse_opcode_args(ngx_conf_t *cf, const char *directive,
    ngx_uint_t *mask_out)
{
    ngx_str_t  *value = cf->args->elts;
    ngx_uint_t  i, mask = 0;

    for (i = 1; i < cf->args->nelts; i++) {
        ngx_str_t  *v   = &value[i];
        ngx_uint_t  bit = brix_mirror_opcode_name_bit(v->data);

        if (bit == 0) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                "%s: unknown opcode \"%V\" (expected one of"
                " all stat locate open read readv dirlist statx query"
                " mkdir rm rmdir mv truncate chmod write)",
                directive, v);
            return NGX_CONF_ERROR;
        }
        mask |= bit;
    }
    *mask_out = mask;
    return NGX_CONF_OK;
}

/*
 * brix_mirror_opcodes stat locate open ...  — RESTRICT mirroring to exactly
 * the named opcodes (allowlist; overrides the default-all).  Most operators
 * want the default (mirror everything) or brix_mirror_exclude_opcodes instead.
 */
char *
brix_stream_mirror_set_opcodes(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_stream_brix_srv_conf_t *xcf = conf;
    (void) cmd;
    return brix_mirror_parse_opcode_args(cf, "brix_mirror_opcodes",
                                           &xcf->mirror.opcode_mask);
}

/*
 * brix_mirror_exclude_opcodes read query ...  — DE-SELECT opcodes from the
 * mirrored set.  Mirroring defaults to ALL ops, so this is the normal way to
 * turn specific ops off without listing everything you want to keep.
 */
char *
brix_stream_mirror_set_exclude_opcodes(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf)
{
    ngx_stream_brix_srv_conf_t *xcf = conf;
    (void) cmd;
    return brix_mirror_parse_opcode_args(cf, "brix_mirror_exclude_opcodes",
                                           &xcf->mirror.opcode_exclude_mask);
}
