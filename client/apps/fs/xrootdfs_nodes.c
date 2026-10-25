/* Mount-owned inode/alias registry, independent of libfuse and transport.
 * Hash indexes bound lookup cost; explicit forget/open references bound lifetime.
 * Namespace allocations happen before server mutations, never afterward.
 */
#include "xrootdfs_nodes.h"
#include "brix.h"
#include <errno.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

struct xfs_rename_change {
    xfs_alias *alias;
    char *replacement;
    xfs_rename_change *next;
};

/* WHAT: Hash a namespace key. WHY: Share one deterministic candidate/index hash.
 * HOW: 1. Fold every byte. 2. Return the full-width value. */
static uint64_t
xfs_path_hash(const char *path)
{
    uint64_t hash = UINT64_C(14695981039346656037);
    for (; *path; path++) {
        hash = (hash ^ (unsigned char) *path) * UINT64_C(1099511628211);
    }
    return hash;
}

/* WHAT: Select a pathname bucket. WHY: Keep full identity hashes independent
 * of index sizing. HOW: 1. Hash the key. 2. Bound the index. */
static size_t
xfs_path_bucket(const char *path)
{
    return xfs_path_hash(path) % XFS_NODE_BUCKETS;
}

/* WHAT: Find a live kernel inode or NULL. WHY: Never confuse recycled paths.
 * HOW: 1. Select its bucket. 2. Compare exact never-reused node ids. */
xfs_node *
xfs_nodes_find(xfs_nodes *table, uint64_t ino)
{
    for (xfs_node *node = table->ids[ino % XFS_NODE_BUCKETS]; node;
         node = node->id_next) {
        if (node->ino == ino) {
            return node;
        }
    }
    return NULL;
}

/* WHAT: Find an exact alias or NULL. WHY: A name is not an inode identity.
 * HOW: 1. Hash the path. 2. Compare full strings. */
xfs_alias *
xfs_nodes_alias(xfs_nodes *table, const char *path)
{
    for (xfs_alias *alias = table->paths[xfs_path_bucket(path)]; alias;
         alias = alias->hash_next) {
        if (strcmp(alias->path, path) == 0) {
            return alias;
        }
    }
    return NULL;
}

/* WHAT: Get a surviving name, or NULL after unlink. WHY: Handles outlive names.
 * HOW: 1. Inspect the alias head without fabricating a fallback path. */
const char *
xfs_node_path(const xfs_node *node)
{
    return node && node->aliases ? node->aliases->path : NULL;
}

/* WHAT: Remove one alias from its path index. WHY: Rename changes hash keys.
 * HOW: 1. Find the exact owned pointer. 2. Unchain it. */
static void
xfs_alias_unhash(xfs_nodes *table, xfs_alias *alias)
{
    xfs_alias **cursor = &table->paths[xfs_path_bucket(alias->path)];
    while (*cursor && *cursor != alias) {
        cursor = &(*cursor)->hash_next;
    }
    if (*cursor) {
        *cursor = alias->hash_next;
    }
}

/* WHAT: Publish an alias key. WHY: Keep its index coherent across rename.
 * HOW: 1. Select the new bucket. 2. Insert at its head. */
static void
xfs_alias_hash(xfs_nodes *table, xfs_alias *alias)
{
    size_t bucket = xfs_path_bucket(alias->path);
    alias->hash_next = table->paths[bucket];
    table->paths[bucket] = alias;
}

/* WHAT: Free an unpublished alias. WHY: Account every reserved path byte.
 * HOW: 1. Debit limits. 2. Release string and owner. */
static void
xfs_alias_free(xfs_nodes *table, xfs_alias *alias)
{
    table->alias_bytes -= strlen(alias->path) + 1;
    table->aliases--;
    free(alias->path);
    free(alias);
}

/* WHAT: Remove a published alias. WHY: Unlink must not delete its open inode.
 * HOW: 1. Unhash. 2. Unchain from the inode. 3. Free the owned name. */
static void
xfs_alias_remove(xfs_nodes *table, xfs_alias *alias)
{
    xfs_alias_unhash(table, alias);
    xfs_alias **cursor = &alias->node->aliases;
    while (*cursor && *cursor != alias) {
        cursor = &(*cursor)->node_next;
    }
    if (*cursor) {
        *cursor = alias->node_next;
    }
    xfs_alias_free(table, alias);
}

/* WHAT: Forget one namespace alias. WHY: Its sibling hard links stay valid.
 * HOW: 1. Find the exact name. 2. Remove only that alias. */
void
xfs_nodes_unlink(xfs_nodes *table, const char *path)
{
    xfs_alias *alias = xfs_nodes_alias(table, path);
    if (alias) {
        xfs_alias_remove(table, alias);
    }
}

/* WHAT: Reserve a node and alias, returning negative errno on exhaustion.
 * WHY: A successful remote create/link must never lose local bookkeeping.
 * HOW: 1. Check hard limits. 2. Allocate all memory. 3. Charge the reservation. */
int
xfs_nodes_prepare(xfs_nodes *table, const char *path, xfs_node_ticket *ticket)
{
    size_t bytes = strlen(path) + 1;
    memset(ticket, 0, sizeof(*ticket));
    if (bytes > XRDC_PATH_MAX) {
        return -ENAMETOOLONG;
    }
    while (table->next_ino != UINT64_MAX && xfs_nodes_find(table, table->next_ino)) {
        table->next_ino++;
    }
    if (table->nodes >= XFS_NODE_LIMIT || table->aliases >= XFS_ALIAS_LIMIT
        || bytes > XFS_ALIAS_BYTES - table->alias_bytes
        || table->next_ino == UINT64_MAX) {
        return -ENOSPC;
    }
    ticket->node = calloc(1, sizeof(*ticket->node));
    ticket->alias = calloc(1, sizeof(*ticket->alias));
    if (ticket->alias) {
        ticket->alias->path = strdup(path);
    }
    if (!ticket->node || !ticket->alias || !ticket->alias->path) {
        if (ticket->alias) {
            free(ticket->alias->path);
        }
        free(ticket->alias);
        free(ticket->node);
        memset(ticket, 0, sizeof(*ticket));
        return -ENOMEM;
    }
    ticket->node->ino = table->next_ino++;
    ticket->node->generation = ticket->node->ino;
    table->nodes++;
    table->aliases++;
    table->alias_bytes += bytes;
    return 0;
}

/* WHAT: Release unused reservations. WHY: Error paths must conserve capacity.
 * HOW: 1. Free optional owners. 2. Clear the ticket. */
void
xfs_nodes_cancel(xfs_nodes *table, xfs_node_ticket *ticket)
{
    if (ticket->alias) {
        xfs_alias_free(table, ticket->alias);
    }
    if (ticket->node) {
        table->nodes--;
        free(ticket->node);
    }
    memset(ticket, 0, sizeof(*ticket));
}

/* WHAT: Find a nonzero server identity. WHY: All hard links share a node id.
 * HOW: 1. Ignore unavailable identity zero. 2. Search the identity bucket. */
static xfs_node *
xfs_backend_find(xfs_nodes *table, uint64_t backend)
{
    if (!backend) {
        return NULL;
    }
    for (xfs_node *node = table->backends[backend % XFS_NODE_BUCKETS]; node;
         node = node->backend_next) {
        if (node->backend == backend) {
            return node;
        }
    }
    return NULL;
}

/* WHAT: Suggest a stable directory inode, or zero when a collision is unknown.
 * WHY: readdir's advisory inode should agree with a later lookup/stat. Unknown
 * WebDAV identities derive from exact paths but are NEVER merged by hash.
 * HOW: 1. Prefer known server/path owners. 2. Select server id or path hash.
 *      3. Refuse occupied candidate ids rather than aliasing unrelated objects. */
uint64_t
xfs_nodes_ino_hint(xfs_nodes *table, const char *path, uint64_t backend)
{
    xfs_node *node = xfs_backend_find(table, backend);
    if (node) {
        return node->ino;
    }
    xfs_alias *alias = xfs_nodes_alias(table, path);
    if (alias && (!backend || !alias->node->backend || alias->node->backend == backend)) {
        return alias->node->ino;
    }
    uint64_t candidate = backend > 1 ? backend : xfs_path_hash(path) | (UINT64_C(1) << 63);
    return xfs_nodes_find(table, candidate) ? 0 : candidate;
}

/* WHAT: Attach a newly learned server identity. WHY: Staged creates start at zero.
 * HOW: 1. Preserve an existing identity. 2. Index a newly known one. */
static void
xfs_backend_attach(xfs_nodes *table, xfs_node *node, uint64_t backend)
{
    if (!node->backend && backend && !xfs_backend_find(table, backend)) {
        node->backend = backend;
        node->backend_next = table->backends[backend % XFS_NODE_BUCKETS];
        table->backends[backend % XFS_NODE_BUCKETS] = node;
    }
}

/* WHAT: Publish a prepared name without allocating. WHY: Preserve hard-link ids.
 * HOW: 1. Prefer the linked node or matching identity. 2. Reconcile the alias.
 *      3. Publish a fresh node only when necessary. 4. Return unused capacity. */
xfs_node *
xfs_nodes_bind(xfs_nodes *table, xfs_node_ticket *ticket, uint64_t backend,
               xfs_node *preferred)
{
    xfs_alias *existing = xfs_nodes_alias(table, ticket->alias->path);
    xfs_node *node = preferred ? preferred : xfs_backend_find(table, backend);
    if (!node && existing && (!backend || !existing->node->backend
                              || existing->node->backend == backend)) {
        node = existing->node;
    }
    if (!node) {
        node = ticket->node;
        ticket->node = NULL;
        uint64_t candidate = xfs_nodes_ino_hint(table, ticket->alias->path, backend);
        if (table->nodes == 1 && strcmp(ticket->alias->path, "/") == 0) {
            candidate = 1; /* the permanent root is the only reserved node id */
        }
        if (candidate) {
            node->ino = candidate;
        }
        size_t bucket = node->ino % XFS_NODE_BUCKETS;
        node->id_next = table->ids[bucket];
        table->ids[bucket] = node;
    }
    xfs_backend_attach(table, node, backend);
    if (existing && existing->node != node) {
        xfs_alias_remove(table, existing);
        existing = NULL;
    }
    if (!existing) {
        xfs_alias *alias = ticket->alias;
        ticket->alias = NULL;
        alias->node = node;
        alias->node_next = node->aliases;
        node->aliases = alias;
        xfs_alias_hash(table, alias);
    }
    xfs_nodes_cancel(table, ticket);
    return node;
}

/* WHAT: Reclaim a node with no kernel/handle owners. WHY: Bound mount memory.
 * HOW: 1. Retain root and referenced nodes. 2. Drop indexes and aliases. 3. Free. */
static void
xfs_node_collect(xfs_nodes *table, xfs_node *node)
{
    if (node->ino == 1 || node->lookups || node->opens) {
        return;
    }
    xfs_node **cursor = &table->ids[node->ino % XFS_NODE_BUCKETS];
    while (*cursor != node) {
        cursor = &(*cursor)->id_next;
    }
    *cursor = node->id_next;
    if (node->backend) {
        cursor = &table->backends[node->backend % XFS_NODE_BUCKETS];
        while (*cursor != node) {
            cursor = &(*cursor)->backend_next;
        }
        *cursor = node->backend_next;
    }
    while (node->aliases) {
        xfs_alias_remove(table, node->aliases);
    }
    table->nodes--;
    free(node);
}

/* WHAT: Drop kernel lookup owners. WHY: Forget is independent of unlink.
 * HOW: 1. Saturate defensively. 2. Collect only unowned nodes. */
void
xfs_nodes_forget(xfs_nodes *table, xfs_node *node, uint64_t count)
{
    node->lookups -= count < node->lookups ? count : node->lookups;
    xfs_node_collect(table, node);
}

/* WHAT: Drop an open owner. WHY: An unlinked open file must keep its identity.
 * HOW: 1. Decrement an existing owner. 2. Collect if now unowned. */
void
xfs_nodes_close(xfs_nodes *table, xfs_node *node)
{
    if (node->opens) {
        node->opens--;
    }
    xfs_node_collect(table, node);
}

/* WHAT: Initialize a root identity. WHY: FUSE reserves node one for the mount.
 * HOW: 1. Clear indexes. 2. Reserve root. 3. Publish its permanent owner. */
int
xfs_nodes_init(xfs_nodes *table)
{
    memset(table, 0, sizeof(*table));
    table->next_ino = 1;
    xfs_node_ticket ticket;
    int rc = xfs_nodes_prepare(table, "/", &ticket);
    if (rc != 0) {
        return rc;
    }
    xfs_nodes_bind(table, &ticket, 0, NULL)->lookups = 1;
    return 0;
}

/* WHAT: Free a stopped mount's registry. WHY: Kernel forgets are not guaranteed.
 * HOW: 1. Walk every id bucket. 2. Free names and nodes. 3. Clear counters. */
void
xfs_nodes_destroy(xfs_nodes *table)
{
    for (size_t bucket = 0; bucket < XFS_NODE_BUCKETS; bucket++) {
        xfs_node *node = table->ids[bucket];
        while (node) {
            xfs_node *next = node->id_next;
            while (node->aliases) {
                xfs_alias_remove(table, node->aliases);
            }
            free(node);
            node = next;
        }
    }
    memset(table, 0, sizeof(*table));
}

/* WHAT: Recognize a renamed subtree member. WHY: Prefixes need a slash boundary.
 * HOW: 1. Compare prefix bytes. 2. Require exact name or child separator. */
static int
xfs_path_inside(const char *path, const char *root)
{
    size_t length = strlen(root);
    return strncmp(path, root, length) == 0
           && (path[length] == '\0' || path[length] == '/');
}

/* WHAT: Prepare one renamed path. WHY: Never allocate after successful rename.
 * HOW: 1. Check path/budget bounds. 2. Allocate replacement and record. */
static int
xfs_rename_add(xfs_nodes *table, xfs_alias *alias, const char *from,
                const char *to, xfs_rename_change **changes)
{
    size_t length = strlen(to) + strlen(alias->path + strlen(from)) + 1;
    if (length > XRDC_PATH_MAX) {
        return -ENAMETOOLONG;
    }
    if (length > XFS_ALIAS_BYTES - table->alias_bytes) {
        return -ENOSPC;
    }
    xfs_rename_change *change = calloc(1, sizeof(*change));
    if (!change) {
        return -ENOMEM;
    }
    change->replacement = malloc(length);
    if (!change->replacement) {
        free(change);
        return -ENOMEM;
    }
    snprintf(change->replacement, length, "%s%s", to, alias->path + strlen(from));
    table->alias_bytes += length;
    change->alias = alias;
    change->next = *changes;
    *changes = change;
    return 0;
}

/* WHAT: Reserve all subtree rename keys. WHY: Open descendants survive rename.
 * HOW: 1. Scan names with a boundary check. 2. Reserve each new path. 3. Roll back
 *      all reservations on error; the namespace has not yet changed. */
int
xfs_nodes_rename_prepare(xfs_nodes *table, const char *from, const char *to,
                          xfs_rename_change **changes)
{
    *changes = NULL;
    for (size_t bucket = 0; bucket < XFS_NODE_BUCKETS; bucket++) {
        for (xfs_alias *alias = table->paths[bucket]; alias; alias = alias->hash_next) {
            if (!xfs_path_inside(alias->path, from)) {
                continue;
            }
            int rc = xfs_rename_add(table, alias, from, to, changes);
            if (rc != 0) {
                xfs_nodes_rename_finish(table, *changes, to, 0);
                *changes = NULL;
                return rc;
            }
        }
    }
    return 0;
}

/* WHAT: Commit or cancel reserved rename keys. WHY: Mirror only server success.
 * HOW: 1. Remove an overwritten destination. 2. Swap prepared keys on commit.
 *      3. Return all old or cancelled string capacity. */
void
xfs_nodes_rename_finish(xfs_nodes *table, xfs_rename_change *changes,
                         const char *to, int commit)
{
    if (commit) {
        xfs_nodes_unlink(table, to);
    }
    while (changes) {
        xfs_rename_change *next = changes->next;
        if (commit) {
            xfs_alias *alias = changes->alias;
            xfs_alias_unhash(table, alias);
            char *old = alias->path;
            alias->path = changes->replacement;
            changes->replacement = old;
            xfs_alias_hash(table, alias);
        }
        table->alias_bytes -= strlen(changes->replacement) + 1;
        free(changes->replacement);
        free(changes);
        changes = next;
    }
}
