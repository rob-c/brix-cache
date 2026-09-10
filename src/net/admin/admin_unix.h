#ifndef BRIX_NET_ADMIN_UNIX_H
#define BRIX_NET_ADMIN_UNIX_H

/*
 * admin_unix.h — the verb-agnostic unix-domain admin transport.
 *
 * WHAT: a per-worker unix-socket line server. A caller supplies a table of
 *       verbs and an opaque `ud`; this TU owns everything else — the socket,
 *       the per-worker path, the accept/read/write event handlers, the
 *       one-command-per-line framing, and the reply arena.
 *
 * WHY: §1.16's ROOT admin socket (`brix_admin_socket`) and §2.x's CMS admin
 *      socket (`brix_cms_admin_socket`) are the SAME transport carrying
 *      different verbs. The transport half — accept, wire the I/O vtable a
 *      bare ngx_get_connection() leaves NULL, accumulate to a newline, refuse
 *      an oversized line, flush a reply with NGX_AGAIN handling, name the
 *      per-worker path — is ~200 lines of event-loop detail that must not be
 *      written twice; a second copy is a second place for a partial-write or
 *      a missing-vtable bug to live. CLAUDE.md: never reimplement HELPERS.
 *
 * HOW: `brix_admin_unix_listen()` creates worker 0's socket at <path> and
 *      worker n's at "<path>.<n>", then dispatches each complete line against
 *      the verb table by exact-name (bare verbs) or name-plus-space (verbs
 *      taking operands). A handler receives ONLY its operand text, so no verb
 *      re-derives the offset of its own arguments. Unknown lines answer
 *      "err unknown-command\n" here, uniformly, rather than in each table.
 *
 * SECURITY: the socket is chmod 0600 (owner-only) and carries NO in-band auth
 *      — filesystem permission on the path IS the privilege boundary, exactly
 *      like stock's adminpath. Every verb table inherits that model, so a verb
 *      added to any table is reachable by exactly the users who can open the
 *      path and no others. A caller must not place a socket where that is not
 *      the boundary it wants.
 */

#include "core/ngx_brix_module.h"

/* Reply arena caps. A command line longer than CMD_MAX closes the connection
 * rather than truncating — a truncated command could parse as a DIFFERENT,
 * valid command. */
#define BRIX_ADMIN_REPLY_MAX  (64 * 1024)
#define BRIX_ADMIN_CMD_MAX    512

/*
 * A verb's reply. `buf`/`cap` are the pool-allocated arena; `out`/`len` are
 * what is actually sent. They are separate so a verb that builds a long body
 * can reserve header room in front of it and repoint `out` backwards instead
 * of memmoving the body (see the ROOT "list" verb).
 */
typedef struct {
    u_char *buf;
    size_t  cap;
    u_char *out;
    size_t  len;
} brix_admin_reply_t;

/*
 * One verb. `args`/`alen` are the operand text: the line with the verb and its
 * one separating space already removed, EOL already stripped. For a bare verb
 * they are NULL/0.
 */
typedef void (*brix_admin_verb_pt)(void *ud, u_char *args, size_t alen,
    brix_admin_reply_t *rep);

typedef struct {
    const char          *name;
    size_t               nlen;
    brix_admin_verb_pt   handler;
    unsigned             wants_args:1;   /* 1 = "<verb> <operands>" */
} brix_admin_verb_t;

/* Static table entry; nlen is derived so a rename cannot desynchronise it. */
#define BRIX_ADMIN_VERB(n, h, a)   { (n), sizeof(n) - 1, (h), (a) }

/*
 * A server: one verb table plus the opaque pointer its handlers receive.
 * `label` prefixes this socket's log lines ("admin", "cms admin") so two
 * sockets in one worker are told apart in the error log.
 */
typedef struct {
    const char              *label;
    const brix_admin_verb_t *verbs;
    ngx_uint_t               nverbs;
    void                    *ud;
} brix_admin_unix_t;

/*
 * Create + listen on this worker's socket for `srv`. `path` is worker 0's
 * path; worker n serves "<path>.<n>". A no-op when `path` is NULL or empty.
 * `srv` must outlive the cycle (a static in the caller's TU). Failures are
 * logged and leave the socket absent — never fatal to worker start, because an
 * admin socket that cannot bind must not take the data plane down with it.
 */
void brix_admin_unix_listen(ngx_cycle_t *cycle, const char *path,
    const brix_admin_unix_t *srv);

/* Set `rep` to a complete one-shot reply (callers include the trailing \n). */
void brix_admin_reply_set(brix_admin_reply_t *rep, const char *msg);

#endif /* BRIX_NET_ADMIN_UNIX_H */
