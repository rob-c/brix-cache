/* Mount-local inode identities and namespace aliases.
 * Requires: standard integer, size and POSIX types (included below).
 * One server identity owns every hard-link alias; lookup/open references keep
 * it alive independently of names. All calls require the session mutex.
 */
#pragma once
#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

#define XFS_NODE_BUCKETS 4096
#define XFS_NODE_LIMIT 65536
#define XFS_ALIAS_LIMIT 262144
#define XFS_ALIAS_BYTES (64U * 1024U * 1024U)

typedef struct xfs_node xfs_node;
typedef struct xfs_alias xfs_alias;
typedef struct xfs_rename_change xfs_rename_change;

struct xfs_node {
    uint64_t ino, generation, backend, lookups, opens;
    xfs_node *id_next, *backend_next;
    xfs_alias *aliases;
    struct afh *open_handles; /* adapter-owned list; registry never dereferences */
};
struct xfs_alias {
    char *path;
    xfs_node *node;
    xfs_alias *hash_next, *node_next;
};
typedef struct {
    xfs_node *ids[XFS_NODE_BUCKETS], *backends[XFS_NODE_BUCKETS];
    xfs_alias *paths[XFS_NODE_BUCKETS];
    uint64_t next_ino;
    size_t nodes, aliases, alias_bytes;
} xfs_nodes;
typedef struct {
    xfs_node *node;
    xfs_alias *alias;
} xfs_node_ticket;

int xfs_nodes_init(xfs_nodes *table);
void xfs_nodes_destroy(xfs_nodes *table);
xfs_node *xfs_nodes_find(xfs_nodes *table, uint64_t ino);
xfs_alias *xfs_nodes_alias(xfs_nodes *table, const char *path);
uint64_t xfs_nodes_ino_hint(xfs_nodes *table, const char *path, uint64_t backend);
const char *xfs_node_path(const xfs_node *node);
int xfs_nodes_prepare(xfs_nodes *table, const char *path, xfs_node_ticket *ticket);
void xfs_nodes_cancel(xfs_nodes *table, xfs_node_ticket *ticket);
xfs_node *xfs_nodes_bind(xfs_nodes *table, xfs_node_ticket *ticket,
                         uint64_t backend, xfs_node *preferred);
void xfs_nodes_forget(xfs_nodes *table, xfs_node *node, uint64_t count);
void xfs_nodes_close(xfs_nodes *table, xfs_node *node);
void xfs_nodes_unlink(xfs_nodes *table, const char *path);
int xfs_nodes_rename_prepare(xfs_nodes *table, const char *from, const char *to,
                             xfs_rename_change **changes);
void xfs_nodes_rename_finish(xfs_nodes *table, xfs_rename_change *changes,
                             const char *to, int commit);
