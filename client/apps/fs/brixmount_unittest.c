/*
 * brixmount_unittest.c — unit tests for the brixMount dispatch core (mock drivers).
 *
 * gcc -Wall -Wextra -Werror -I shared -DBRIXMOUNT_NO_MAIN \
 *     -o /tmp/brixmount_ut client/apps/fs/brixmount_unittest.c \
 *     client/apps/fs/brixmount.c && /tmp/brixmount_ut
 */
#include <stdio.h>
#include <string.h>

typedef int (*brix_driver_fn)(int, char **);
typedef struct { const char *type; const char *brand; brix_driver_fn fn; } brix_driver_t;
int brixmount_dispatch(int argc, char **argv, const brix_driver_t *drv, size_t ndrv);
int brixmount_overlay_route(int argc, char **argv,
                            int (*list_fn)(const char *, FILE *),
                            int (*reset_fn)(const char *));

static int g_checks, g_failed;
#define CHECK(c,n) do{ g_checks++; if(c){printf("  ok   %s\n",n);} \
    else{printf("  FAIL %s (line %d)\n",n,__LINE__); g_failed++;} }while(0)

/* mock drivers record what they were called with */
static char g_last_brand[64], g_last_ep[128], g_last_mnt[128];
static int  g_last_argc, g_last_opt_seen;
static int  mock_ok(int argc, char **argv) {
    g_last_argc = argc;
    snprintf(g_last_brand, sizeof(g_last_brand), "%s", argv[0]);
    snprintf(g_last_ep,   sizeof(g_last_ep),   "%s", argc > 1 ? argv[1] : "");
    snprintf(g_last_mnt,  sizeof(g_last_mnt),  "%s", argc > 2 ? argv[2] : "");
    g_last_opt_seen = 0;
    for (int i = 3; i < argc; i++) if (!strcmp(argv[i], "-o")) g_last_opt_seen = 1;
    return 42;
}

/* mock overlay subcommand cores */
static char g_cli_dir[128];
static char g_cli_which;
static int  mock_list(const char *dir, FILE *out) {
    (void) out;
    snprintf(g_cli_dir, sizeof(g_cli_dir), "%s", dir);
    g_cli_which = 'l';
    return 7;
}
static int mock_reset(const char *dir) {
    snprintf(g_cli_dir, sizeof(g_cli_dir), "%s", dir);
    g_cli_which = 'r';
    return 8;
}

int main(void) {
    static const brix_driver_t drv[] = {
        { "cvmfs", "CVMFS-brix",    mock_ok },
        { "eos",   "XRootDFS-brix", mock_ok },
        { "s3",    "S3-brix",       NULL    },  /* unavailable */
    };
    size_t n = sizeof(drv)/sizeof(drv[0]);

    char *a1[] = { "brixMount", "cvmfs", "atlas.cern.ch", "/mnt/atlas", NULL };
    int rc = brixmount_dispatch(4, a1, drv, n);
    CHECK(rc == 42 && !strcmp(g_last_brand, "CVMFS-brix")
          && !strcmp(g_last_ep, "atlas.cern.ch") && !strcmp(g_last_mnt, "/mnt/atlas"),
          "cvmfs dispatch → CVMFS-brix with endpoint+mount");

    char *a2[] = { "brixMount", "eos", "root://eoslhcb.cern.ch", "/mnt/eos", "-o", "ro", NULL };
    rc = brixmount_dispatch(6, a2, drv, n);
    CHECK(rc == 42 && !strcmp(g_last_brand, "XRootDFS-brix")
          && !strcmp(g_last_ep, "root://eoslhcb.cern.ch") && g_last_opt_seen,
          "eos dispatch → XRootDFS-brix, fuse-opts passed through");

    char *a3[] = { "brixMount", "nope", "x", "/mnt", NULL };
    CHECK(brixmount_dispatch(4, a3, drv, n) == 2, "unknown type → usage error");

    char *a4[] = { "brixMount", "s3", "x", "/mnt", NULL };
    CHECK(brixmount_dispatch(4, a4, drv, n) == 2, "unavailable driver → error");

    char *a5[] = { "brixMount", "cvmfs", NULL };
    CHECK(brixmount_dispatch(2, a5, drv, n) == 2, "too few args → usage");  /* neg */

    /* cvmfs-rw is its own table row with its own brand */
    static const brix_driver_t drv_rw[] = {
        { "cvmfs",    "CVMFS-brix",    mock_ok },
        { "cvmfs-rw", "CVMFS-brix-rw", mock_ok },
    };
    char *a6[] = { "brixMount", "cvmfs-rw", "atlas.cern.ch", "/mnt/atlas", NULL };
    rc = brixmount_dispatch(4, a6, drv_rw, 2);
    CHECK(rc == 42 && !strcmp(g_last_brand, "CVMFS-brix-rw"),
          "cvmfs-rw dispatch → CVMFS-brix-rw");

    /* overlay subcommand router */
    char *r1[] = { "brixMount", "--overlay-list", "/mnt/x", NULL };
    CHECK(brixmount_overlay_route(3, r1, mock_list, mock_reset) == 7
          && !strcmp(g_cli_dir, "/mnt/x") && g_cli_which == 'l',
          "--overlay-list routed with mountdir");
    char *r2[] = { "brixMount", "--overlay-reset", "/mnt/y", NULL };
    CHECK(brixmount_overlay_route(3, r2, mock_list, mock_reset) == 8
          && !strcmp(g_cli_dir, "/mnt/y") && g_cli_which == 'r',
          "--overlay-reset routed with mountdir");
    char *r3[] = { "brixMount", "--overlay-list", NULL };
    CHECK(brixmount_overlay_route(2, r3, mock_list, mock_reset) == 2,
          "--overlay-list without mountdir → 2");  /* neg */
    char *r4[] = { "brixMount", "cvmfs", "a", "/m", NULL };
    CHECK(brixmount_overlay_route(4, r4, mock_list, mock_reset) == -1,
          "mount args fall through the router");

    printf("%d checks, %d failed\n", g_checks, g_failed);
    return g_failed ? 1 : 0;
}
