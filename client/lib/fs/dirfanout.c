/*
 * fs/dirfanout.c — cluster-wide directory enumeration (W7.2b).
 *
 * WHAT: brix_dirlist_all() — the union of one directory's entries across every
 *       data server a CMS manager names for that path, deduplicated by name.
 *
 * WHY:  A manager answers kXR_dirlist by REDIRECTING to a single registered
 *       data server (src/protocols/root/dirlist/handler.c), so a plain dirlist
 *       against a manager enumerates ONE node's view of the directory, not the
 *       cluster's.  Every file whose only replica lives elsewhere is invisible.
 *       Stock XRootD solves this client-side in XrdFfsPosix_readdirall; this is
 *       the same contract for the brix client, so a FUSE mount over a manager
 *       lists what the cluster holds rather than what one node happens to hold.
 *
 * HOW:  kXR_locate the directory on the manager connection → keep the 'S'/'s'
 *       data-server tokens (manager 'M'/'m' entries are skipped: dialing a
 *       manager would just re-locate) → dial each one with the manager
 *       connection's own opts → brix_dirlist → concatenate → sort by name and
 *       drop adjacent duplicates (a replicated file is named by several nodes).
 *
 *       Failure policy, deliberately asymmetric:
 *         * a node that answers "not found" contributes nothing and is fine —
 *           a directory need not exist on every server;
 *         * ANY other per-node failure (connect, auth, protocol) fails the
 *           whole call.  A silently short listing is worse than an error: the
 *           caller cannot tell a partial answer from a complete one, and
 *           "file missing" is exactly the bug this function exists to fix.
 */

#include "brix.h"
#include "brix_ops.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* A locate reply is bounded by the server's own frame; 64 holders is far past
 * any realistic replication factor and keeps the node table a stack local. */
#define DIRFAN_MAX_NODES   64
#define DIRFAN_REPLY_MAX   8192

typedef struct {
    char host[256];
    int  port;
} dirfan_node;

/* The node table's host field is the SAME width as the URL host it is copied
 * into, so that copy is a fixed-size memcpy rather than a bounded string copy
 * the optimizer cannot prove terminates.  Pinned here so a later widening of
 * either side is a build error and not a silent truncation to the wrong host. */
_Static_assert(sizeof(((dirfan_node *) 0)->host)
               == sizeof(((brix_url *) 0)->host),
               "dirfan_node.host must match brix_url.host");

/* Accumulator: the growing union plus the query it is being built from.  Passed
 * as one argument so the per-node worker stays inside the parameter budget. */
typedef struct {
    brix_dirent *ents;
    size_t       n;
    size_t       cap;
    const char  *path;
    int          want_stat;
} dirfan_acc;


/* ---- Is this locate token a data server we should ask? ----
 *
 * WHAT: 1 for a "S<r|w><host>:<port>" / "s..." token with a non-empty body.
 *
 * WHY:  'M'/'m' are managers — asking one re-enters the same redirect we are
 *       working around.  Anything else is a token shape we do not model.
 *
 * HOW:  Leading byte class plus a length check for the two-byte prefix.
 */
static int
dirfan_is_server(const char *token)
{
    return (token[0] == 'S' || token[0] == 's')
           && token[1] != '\0' && token[2] != '\0';
}


/* ---- Have we already recorded this endpoint? ----
 *
 * WHAT: 1 when host:port is already in the node table.
 *
 * WHY:  A locate can name the same server twice (read and write entries for
 *       the same holder).  Listing it twice would double every name and make
 *       the dedup pass do work that never needed doing.
 *
 * HOW:  Linear scan — the table is at most DIRFAN_MAX_NODES.
 */
static int
dirfan_seen(const dirfan_node *nodes, size_t n, const brix_url *u)
{
    size_t i;

    for (i = 0; i < n; i++) {
        if (nodes[i].port == u->port
            && strcmp(nodes[i].host, u->host) == 0) {
            return 1;
        }
    }
    return 0;
}


/* ---- Data servers named by a locate reply ----
 *
 * WHAT: Fill `nodes` with the distinct data-server endpoints in `reply`.
 *       Returns the count.
 *
 * WHY:  The union is taken over exactly these; everything downstream is a
 *       loop over this table.
 *
 * HOW:  Whitespace-split, keep server tokens, and reuse brix_url_parse for the
 *       host:port split so bracketed IPv6 literals are handled by the one
 *       parser that already knows their shape — never a second hand-rolled
 *       splitter (a token like "Sr[::1]:1094" has colons inside the host).
 */
static size_t
dirfan_nodes_from_locate(char *reply, dirfan_node *nodes, size_t max)
{
    char       *cursor = reply, *token, *save = NULL;
    size_t      n = 0;

    while (n < max && (token = strtok_r(cursor, " \t\r\n", &save)) != NULL) {
        char        url[512];
        brix_url    u;
        brix_status ust;

        cursor = NULL;
        if (!dirfan_is_server(token)) {
            continue;
        }
        if ((size_t) snprintf(url, sizeof(url), "root://%s//", token + 2)
            >= sizeof(url)) {
            continue;
        }
        brix_status_clear(&ust);
        if (brix_url_parse(url, &u, &ust) != 0 || u.host[0] == '\0') {
            continue;
        }
        if (dirfan_seen(nodes, n, &u)) {
            continue;
        }
        snprintf(nodes[n].host, sizeof(nodes[n].host), "%s", u.host);
        nodes[n].port = u.port;
        n++;
    }
    return n;
}


/* ---- Append one node's listing to the union ----
 *
 * WHAT: Grow the accumulator and copy `add` entries in. 0 / -1 (st set).
 *
 * WHY:  The union's size is not known until the last node has answered, so the
 *       array doubles rather than being sized from a guess.
 *
 * HOW:  realloc to the next power-of-two-ish capacity, then memcpy.
 */
static int
dirfan_append(dirfan_acc *acc, const brix_dirent *add, size_t n_add,
              brix_status *st)
{
    size_t       want = acc->n + n_add;
    brix_dirent *grown;

    if (n_add == 0) {
        return 0;
    }
    if (want > acc->cap) {
        size_t cap = (acc->cap == 0) ? 64 : acc->cap;

        while (cap < want) {
            cap *= 2;
        }
        grown = realloc(acc->ents, cap * sizeof(*grown));
        if (grown == NULL) {
            brix_status_set(st, XRDC_EIO, errno,
                            "dirlist-all: out of memory for %zu entries", cap);
            return -1;
        }
        acc->ents = grown;
        acc->cap = cap;
    }
    memcpy(acc->ents + acc->n, add, n_add * sizeof(*add));
    acc->n = want;
    return 0;
}


/* ---- Did this node simply not have the directory? ----
 *
 * WHAT: 1 for a not-found-class failure.
 *
 * WHY:  A data server that holds no part of a directory is a normal member of
 *       a cluster, not an error — its absence must not fail the enumeration.
 *
 * HOW:  Same predicate the CLI hint layer uses (cli_hint.c): the wire code or
 *       a locally-mapped ENOENT.
 */
static int
dirfan_not_found(const brix_status *st)
{
    return st->kxr == kXR_NotFound || st->sys_errno == ENOENT;
}


/* ---- List one data server and fold it into the union ----
 *
 * WHAT: Dial `nd`, dirlist acc->path, append. 0 on success or a clean miss,
 *       -1 on any other failure (st carries it).
 *
 * WHY:  Each holder is asked directly, so the manager's single-node redirect
 *       is bypassed entirely.
 *
 * HOW:  Compose a URL for the endpoint, connect with the manager connection's
 *       stored opts (same credentials, same TLS posture), dirlist, close.  The
 *       connection is closed on every path — a listing must not leak a socket
 *       per node per readdir.
 */
static int
dirfan_one(const brix_conn *mgr, const dirfan_node *nd, dirfan_acc *acc,
           brix_status *st)
{
    brix_conn    c;
    brix_url     u;
    brix_dirent *ents = NULL;
    size_t       n = 0;
    int          rc;

    memset(&u, 0, sizeof(u));
    u.scheme = mgr->tls_strict ? XRDC_SCHEME_ROOTS : XRDC_SCHEME_ROOT;
    memcpy(u.host, nd->host, sizeof(u.host));   /* equal widths, see the assert */
    u.port = nd->port;
    snprintf(u.path, sizeof(u.path), "%s", acc->path);

    if (brix_connect(&c, &u, &mgr->opts, st) != 0) {
        return -1;
    }
    rc = brix_dirlist(&c, acc->path, acc->want_stat, &ents, &n, st);
    brix_close(&c);
    if (rc != 0) {
        if (dirfan_not_found(st)) {
            brix_status_clear(st);
            return 0;
        }
        return -1;
    }
    rc = dirfan_append(acc, ents, n, st);
    free(ents);
    return rc;
}


/* ---- Order two entries by name ---- */
static int
dirfan_cmp(const void *a, const void *b)
{
    return strcmp(((const brix_dirent *) a)->name,
                  ((const brix_dirent *) b)->name);
}


/* ---- Collapse duplicate names in place ----
 *
 * WHAT: Sort the union and drop adjacent equal names. Returns the kept count.
 *
 * WHY:  A replicated file is named by every node holding it; a caller that saw
 *       it twice would render it twice.  The FIRST occurrence is kept, so a
 *       stat-bearing entry is never replaced by a later stat-less one from a
 *       node that answered a want_stat=1 dirlist with only names.
 *
 * HOW:  qsort by name (stable enough for this purpose — duplicates are equal
 *       records to the caller) then a single compaction sweep.
 */
static size_t
dirfan_dedup(brix_dirent *ents, size_t n)
{
    size_t i, keep = 0;

    if (n < 2) {
        return n;
    }
    qsort(ents, n, sizeof(*ents), dirfan_cmp);
    for (i = 1; i < n; i++) {
        if (strcmp(ents[keep].name, ents[i].name) == 0) {
            continue;
        }
        keep++;
        if (keep != i) {
            ents[keep] = ents[i];
        }
    }
    return keep + 1;
}


int
brix_dirlist_all(brix_conn *c, const char *path, int want_stat,
                 brix_dirent **ents, size_t *count, brix_status *st)
{
    char        reply[DIRFAN_REPLY_MAX];
    dirfan_node nodes[DIRFAN_MAX_NODES];
    dirfan_acc  acc;
    size_t      n_nodes, i;

    *ents = NULL;
    *count = 0;

    /* No locate support, or a locate that names nobody: this endpoint is not a
     * manager fronting other holders, so its own listing IS the answer. */
    if (brix_locate(c, path, reply, sizeof(reply), st) != 0) {
        brix_status_clear(st);
        return brix_dirlist(c, path, want_stat, ents, count, st);
    }
    n_nodes = dirfan_nodes_from_locate(reply, nodes, DIRFAN_MAX_NODES);
    if (n_nodes == 0) {
        return brix_dirlist(c, path, want_stat, ents, count, st);
    }

    memset(&acc, 0, sizeof(acc));
    acc.path = path;
    acc.want_stat = want_stat;

    for (i = 0; i < n_nodes; i++) {
        if (dirfan_one(c, &nodes[i], &acc, st) != 0) {
            free(acc.ents);
            return -1;
        }
    }

    *ents = acc.ents;
    *count = dirfan_dedup(acc.ents, acc.n);
    return 0;
}
