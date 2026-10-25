/* Exact request-helper bodies are appended by pytest; only libfuse's public
 * caller-context accessor is injected. No production auth decision is copied.
 */
#include "brix.h"
#include "xrootdfs_nodes.h"
#include <assert.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>

typedef uint64_t fuse_ino_t;
typedef struct { uid_t uid; } *fuse_req_t;
typedef struct afh { uid_t caller_uid; struct afh *node_next; } afh;
typedef struct { xfs_nodes nodes; char base[XRDC_PATH_MAX]; } xfs_session;
/* Model the existing option's read through a test-owned session value. */
#define g_base (session->base)
uid_t xfs_req_uid(fuse_req_t req);
int xfs_req_path(xfs_session *session, fuse_ino_t ino, char *out);
int xfs_req_child(xfs_session *session, fuse_ino_t parent, const char *name, char *out);
static afh *xfs_ll_caller_handle(fuse_req_t req, xfs_node *node);

/* WHAT: Supply a controlled kernel context. WHY: Test uid propagation exactly.
 * HOW: 1. Return this request's injected immutable context. */
static fuse_req_t
fuse_req_ctx(fuse_req_t req)
{
    return req;
}

/* WHAT: Verify explicit caller identity. WHY: Never collapse root/non-owner uid.
 * HOW: 1. Provide distinct contexts. 2. Assert each exact uid, including zero. */
static void
check_caller(void)
{
    fuse_req_t first = calloc(1, sizeof(*first));
    fuse_req_t second = calloc(1, sizeof(*second));
    assert(first && second);
    first->uid = 0;
    second->uid = 2101;
    assert(xfs_req_uid(first) == 0 && xfs_req_uid(second) == 2101);
    second->uid = (uid_t) 65534;
    assert(xfs_req_uid(second) == 65534 && xfs_req_uid(first) == 0);
    free(first);
    free(second);
}

/* WHAT: Verify missing/traversing names fail without alias changes.
 * WHY: Never substitute root when an inode is stale or a component malformed.
 * HOW: 1. Resolve valid child. 2. Reject stale/empty/dot/slash names. 3. Check root. */
static void
check_paths(xfs_session *session)
{
    char path[XRDC_PATH_MAX];
    assert(xfs_req_child(session, 1, "child", path) == 0);
    assert(strcmp(path, "/child") == 0);
    assert(xfs_req_child(session, 999, "child", path) == -ESTALE);
    const char *invalid[] = {"", ".", "..", "../escape", "a/b", "/absolute"};
    for (size_t index = 0; index < sizeof(invalid) / sizeof(invalid[0]); index++) {
        assert(xfs_req_child(session, 1, invalid[index], path) == -EINVAL);
    }
    assert(session->nodes.nodes == 1 && session->nodes.aliases == 1);
    assert(xfs_req_path(session, 1, path) == 0 && strcmp(path, "/") == 0);
}

/* WHAT: Verify full export-relative path bounds. WHY: Overflow must not map to root.
 * HOW: 1. Fill export base. 2. Admit exact bound. 3. Refuse one byte over bound. */
static void
check_boundaries(xfs_session *session)
{
    char path[XRDC_PATH_MAX];
    memset(session->base, 'a', sizeof(session->base) - 8);
    session->base[sizeof(session->base) - 8] = '\0';
    assert(xfs_req_child(session, 1, "123456", path) == 0);
    assert(xfs_req_child(session, 1, "1234567", path) == -ENAMETOOLONG);
    assert(!xfs_nodes_alias(&session->nodes, "/1234567"));
}

/* WHAT: Verify omitted-fh GETATTR never borrows another caller's handle.
 * WHY: Open metadata cannot lend mount-owner authority to another uid.
 * HOW: 1. Create two identity owners. 2. Refuse an unknown uid. 3. Match exact uids. */
static void
check_handle_caller(void)
{
    afh first = {.caller_uid = 0}, second = {.caller_uid = 2102};
    first.node_next = &second;
    xfs_node node = {.open_handles = &first};
    fuse_req_t request = calloc(1, sizeof(*request));
    assert(request);
    request->uid = 2101;
    assert(!xfs_ll_caller_handle(request, &node));
    request->uid = 2102;
    assert(xfs_ll_caller_handle(request, &node) == &second);
    request->uid = 0;
    assert(xfs_ll_caller_handle(request, &node) == &first);
    node.open_handles = NULL;
    assert(!xfs_ll_caller_handle(request, &node));
    free(request);
}

/* WHAT: Execute one isolated request contract. WHY: Keep all state disposable.
 * HOW: 1. Initialize nodes. 2. Dispatch. 3. Destroy all memory under sanitizers. */
int
main(int argc, char **argv)
{
    assert(argc == 2);
    xfs_session *session = calloc(1, sizeof(*session));
    assert(session && xfs_nodes_init(&session->nodes) == 0);
    if (strcmp(argv[1], "caller") == 0) { check_caller(); }
    else if (strcmp(argv[1], "paths") == 0) { check_paths(session); }
    else if (strcmp(argv[1], "boundaries") == 0) { check_boundaries(session); }
    else if (strcmp(argv[1], "handle-caller") == 0) { check_handle_caller(); }
    else { assert(0); }
    xfs_nodes_destroy(&session->nodes);
    free(session);
    return 0;
}
