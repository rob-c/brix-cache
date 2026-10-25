/* Sanitized registry lifetime and namespace contract, without a FUSE kernel. */
#include "xrootdfs_nodes.h"
#include <assert.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>

/* WHAT: Publish a referenced name. WHY: Exercise production reservation paths.
 * HOW: 1. Reserve. 2. Bind server identity. 3. Add a kernel lookup owner. */
static xfs_node *
publish(xfs_nodes *table, const char *path, uint64_t backend, xfs_node *preferred)
{
    xfs_node_ticket ticket;
    assert(xfs_nodes_prepare(table, path, &ticket) == 0);
    xfs_node *node = xfs_nodes_bind(table, &ticket, backend, preferred);
    node->lookups++;
    return node;
}

/* WHAT: Verify aliases and unknown identities. WHY: Zero never aliases all files.
 * HOW: 1. Bind equal ids. 2. Bind zero ids. 3. Check explicit link identity. */
static void
check_links(xfs_nodes *table)
{
    xfs_node *source = publish(table, "/source", 345, NULL);
    xfs_node *linked = publish(table, "/linked", 345, NULL);
    assert(source == linked && source->lookups == 2);
    assert(publish(table, "/third", 345, source) == source);
    xfs_node *first = publish(table, "/unknown-a", 0, NULL);
    xfs_node *second = publish(table, "/unknown-b", 0, NULL);
    assert(first != second && first->ino != second->ino);
    assert(publish(table, "/unknown-a", 900, NULL) == first);
    assert(publish(table, "/learned-link", 900, NULL) == first);
    assert(xfs_nodes_alias(table, "/source")->node == linked);
}

/* WHAT: Verify forget/unlink/open ordering. WHY: No freed live-handle identity.
 * HOW: 1. Keep an open owner. 2. Unlink/forget. 3. Close and check collection. */
static void
check_lifetime(xfs_nodes *table)
{
    xfs_node *node = publish(table, "/gone", 76, NULL);
    uint64_t ino = node->ino;
    uint64_t generation = node->generation;
    node->opens++;
    xfs_nodes_unlink(table, "/gone");
    assert(!xfs_node_path(node));
    xfs_nodes_forget(table, node, 100);
    assert(xfs_nodes_find(table, ino) == node && node->lookups == 0);
    xfs_nodes_close(table, node);
    assert(!xfs_nodes_find(table, ino));
    xfs_node *replacement = publish(table, "/gone", 76, NULL);
    assert(replacement->ino == ino && replacement->generation > generation);
    xfs_nodes_forget(table, replacement, 1);
    assert(!xfs_nodes_alias(table, "/gone"));
    xfs_nodes_forget(table, xfs_nodes_find(table, 1), UINT64_MAX);
    assert(xfs_nodes_find(table, 1) && table->nodes == 1);
}

/* WHAT: Verify rename transactions. WHY: Descendants and overwritten opens survive.
 * HOW: 1. Populate boundary neighbors. 2. Cancel once. 3. Commit and inspect ids. */
static void
check_rename(xfs_nodes *table)
{
    xfs_node *directory = publish(table, "/old", 80, NULL);
    xfs_node *child = publish(table, "/old/child", 81, NULL);
    xfs_node *neighbor = publish(table, "/old-neighbor", 82, NULL);
    xfs_node *overwritten = publish(table, "/new", 83, NULL);
    xfs_rename_change *changes;
    size_t bytes = table->alias_bytes;
    assert(xfs_nodes_rename_prepare(table, "/old", "/new", &changes) == 0);
    xfs_nodes_rename_finish(table, changes, "/new", 0);
    assert(table->alias_bytes == bytes && xfs_nodes_alias(table, "/old"));
    assert(xfs_nodes_rename_prepare(table, "/old", "/new", &changes) == 0);
    xfs_nodes_rename_finish(table, changes, "/new", 1);
    assert(!xfs_nodes_alias(table, "/old"));
    assert(!xfs_nodes_alias(table, "/old/child"));
    assert(xfs_nodes_alias(table, "/new")->node == directory);
    assert(xfs_nodes_alias(table, "/new/child")->node == child);
    assert(xfs_nodes_alias(table, "/old-neighbor")->node == neighbor);
    assert(xfs_nodes_find(table, overwritten->ino) == overwritten);
    assert(!xfs_node_path(overwritten));
}

/* WHAT: Verify refusal budgets preserve existing names. WHY: Fail before mutation.
 * HOW: 1. Pin each limit. 2. Require empty tickets. 3. Check cancellation balance. */
static void
check_limits(xfs_nodes *table)
{
    xfs_node_ticket ticket;
    size_t saved = table->nodes;
    table->nodes = XFS_NODE_LIMIT;
    assert(xfs_nodes_prepare(table, "/no", &ticket) == -ENOSPC);
    assert(!ticket.node && !ticket.alias);
    table->nodes = saved;
    saved = table->alias_bytes;
    table->alias_bytes = XFS_ALIAS_BYTES;
    assert(xfs_nodes_prepare(table, "/no", &ticket) == -ENOSPC);
    table->alias_bytes = saved;
    assert(xfs_nodes_prepare(table, "/cancel", &ticket) == 0);
    xfs_nodes_cancel(table, &ticket);
    assert(table->nodes == 1 && table->aliases == 1 && table->alias_bytes == saved);
    char longpath[8192];
    memset(longpath, 'a', sizeof(longpath) - 1);
    longpath[sizeof(longpath) - 1] = '\0';
    assert(xfs_nodes_prepare(table, longpath, &ticket) == -ENAMETOOLONG);
    assert(xfs_nodes_alias(table, "/") && !xfs_nodes_alias(table, "/no"));
}

/* WHAT: Verify replaced names do not recycle referenced identities.
 * WHY: A remote delete/recreate must not make a live descriptor name a new file.
 * HOW: 1. Keep original lookup. 2. Replace server id. 3. Inspect both lifetimes. */
static void
check_replacement(xfs_nodes *table)
{
    xfs_node *original = publish(table, "/same", 100, NULL);
    xfs_node *replacement = publish(table, "/same", 101, NULL);
    assert(original != replacement && original->ino != replacement->ino);
    assert(!xfs_node_path(original));
    assert(xfs_nodes_alias(table, "/same")->node == replacement);
    uint64_t ino = original->ino;
    xfs_nodes_forget(table, original, 1);
    assert(!xfs_nodes_find(table, ino));
    assert(xfs_nodes_alias(table, "/same")->node == replacement);
}

/* WHAT: Reject inode-hint collisions as alias identity.
 * WHY: A path hash is an allocation candidate, never proof of a hard link.
 * HOW: 1. Occupy its candidate with another server object. 2. Require unknown
 * hint. 3. Publish a distinct owner without changing the occupied inode. */
static void
check_collision(xfs_nodes *table)
{
    uint64_t candidate = xfs_nodes_ino_hint(table, "/collision", 0);
    assert(candidate > 1);
    xfs_node *occupied = publish(table, "/occupied", candidate, NULL);
    assert(occupied->ino == candidate);
    assert(xfs_nodes_ino_hint(table, "/collision", 0) == 0);
    xfs_node *separate = publish(table, "/collision", 0, NULL);
    assert(separate != occupied && separate->ino != occupied->ino);
    assert(xfs_nodes_ino_hint(table, "/collision", 0) == separate->ino);
    assert(xfs_nodes_alias(table, "/occupied")->node == occupied);
}

/* WHAT: Execute one independent contract. WHY: Sanitizers see real ownership paths.
 * HOW: 1. Initialize heap-owned mount state. 2. Dispatch case. 3. Destroy all. */
int
main(int argc, char **argv)
{
    assert(argc == 2);
    xfs_nodes *table = calloc(1, sizeof(*table));
    assert(table && xfs_nodes_init(table) == 0);
    if (strcmp(argv[1], "links") == 0) { check_links(table); }
    else if (strcmp(argv[1], "lifetime") == 0) { check_lifetime(table); }
    else if (strcmp(argv[1], "rename") == 0) { check_rename(table); }
    else if (strcmp(argv[1], "limits") == 0) { check_limits(table); }
    else if (strcmp(argv[1], "replacement") == 0) { check_replacement(table); }
    else if (strcmp(argv[1], "collision") == 0) { check_collision(table); }
    else { assert(0); }
    xfs_nodes_destroy(table);
    assert(table->nodes == 0 && table->alias_bytes == 0);
    free(table);
    return 0;
}
