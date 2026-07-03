/*
 * router_unittest.c — standalone unit test for the CMS opcode router.
 *
 *   gcc -Wall -Wextra -Werror -I src -o /tmp/cms_router_ut \
 *       src/cms/router_unittest.c src/cms/router.c && /tmp/cms_router_ut
 *
 * Exit 0 = all checks pass. No nginx dependency (router.c is pure C).
 */

#include "router.h"

#include <stdio.h>
#include <string.h>

#define K_LOCATE   2
#define K_MKDIR    3
#define K_MV       5
#define K_PREPDEL  7
#define K_PING    17
#define K_AVAIL   12
#define K_UPDATE  25

static int g_fail;
#define CHECK(cond) do { \
    if (!(cond)) { printf("FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond); \
                   g_fail++; } \
} while (0)

static void
test_manager_forwardable_mkdir(void)
{
    const brix_cms_route_t *r = brix_cms_route_lookup(XRDCMS_ROLE_MANAGER,
                                                          K_MKDIR);
    CHECK(r != NULL);
    if (r) {
        CHECK(strcmp(r->name, "mkdir") == 0);
        CHECK(r->flags & XRDCMS_RF_FORWARD);
        CHECK(r->flags & XRDCMS_RF_REPLIABLE);
        CHECK(r->flags & XRDCMS_RF_DELAYABLE);
    }
}

static void
test_manager_locate_not_forwarded(void)
{
    /* locate is repliable/delayable but NOT a Forward op (manager resolves it) */
    const brix_cms_route_t *r = brix_cms_route_lookup(XRDCMS_ROLE_MANAGER,
                                                          K_LOCATE);
    CHECK(r != NULL);
    if (r) {
        CHECK(r->flags & XRDCMS_RF_REPLIABLE);
        CHECK((r->flags & XRDCMS_RF_FORWARD) == 0);
    }
}

static void
test_manager_ping_sync_noargs(void)
{
    const brix_cms_route_t *r = brix_cms_route_lookup(XRDCMS_ROLE_MANAGER,
                                                          K_PING);
    CHECK(r != NULL);
    if (r) {
        CHECK(strcmp(r->name, "ping") == 0);
        CHECK(r->flags & XRDCMS_RF_SYNC);
        CHECK(r->flags & XRDCMS_RF_NOARGS);
        CHECK((r->flags & XRDCMS_RF_FORWARD) == 0);
    }
}

static void
test_node_executes_forwarded_mkdir_without_reforward(void)
{
    /* a data node accepts a forwarded mkdir but does NOT re-forward it */
    const brix_cms_route_t *r = brix_cms_route_lookup(XRDCMS_ROLE_NODE,
                                                          K_MKDIR);
    CHECK(r != NULL);
    if (r) {
        CHECK((r->flags & XRDCMS_RF_FORWARD) == 0);
    }
}

static void
test_node_rejects_node_status_opcode(void)
{
    /* avail is a node->manager status frame; a node does not accept it */
    const brix_cms_route_t *r = brix_cms_route_lookup(XRDCMS_ROLE_NODE,
                                                          K_AVAIL);
    CHECK(r == NULL);
}

static void
test_update_routed_both_roles(void)
{
    CHECK(brix_cms_route_lookup(XRDCMS_ROLE_MANAGER, K_UPDATE) != NULL);
    CHECK(brix_cms_route_lookup(XRDCMS_ROLE_NODE,    K_UPDATE) != NULL);
}

static void
test_unknown_opcode_rejected(void)
{
    CHECK(brix_cms_route_lookup(XRDCMS_ROLE_MANAGER, 99) == NULL);
    CHECK(brix_cms_route_lookup(XRDCMS_ROLE_NODE,    99) == NULL);
}

int
main(void)
{
    test_manager_forwardable_mkdir();
    test_manager_locate_not_forwarded();
    test_manager_ping_sync_noargs();
    test_node_executes_forwarded_mkdir_without_reforward();
    test_node_rejects_node_status_opcode();
    test_update_routed_both_roles();
    test_unknown_opcode_rejected();

    if (g_fail) { printf("%d check(s) FAILED\n", g_fail); return 1; }
    printf("all router checks passed\n");
    return 0;
}
