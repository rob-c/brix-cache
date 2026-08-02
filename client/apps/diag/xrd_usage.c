/*
 * xrd_usage.c - xrd(1) usage/help text.
 * Phase-38 split of xrd.c; behavior-identical.
 */
#include "xrd_internal.h"
#include "core/version.h"
#include "core/progname.h"

/*
 * usage_fp — print xrd usage to the given stream.
 * WHY: --help (WS-2) goes to stdout; no-arg / unknown-command goes to stderr.
 */
void
usage_fp(FILE *out, const char *prog)
{
    fprintf(out,
        "usage: %s <command> [args]\n"
        "  the unified XRootD/WLCG toolkit front-end (~/.xrdrc aliases work everywhere)\n\n"
        "  transfer:\n"
        "    xrd cp [opts] <src>... <dst>     copy (-> xrdcp; supports -r -j --sync --from ...)\n"
        "    xrd get <url> [localdst]         download a file (default dst: cwd)\n"
        "    xrd put <localfile> <url>        upload a file\n"
        "    xrd upload   [rate=R] <localfile|-> <url>  rate-limited upload (bs=/-f)\n"
        "    xrd download [rate=R] <url> [localdst|-]   rate-limited download (bs=/-f)\n"
        "    xrd sync <srcdir> <dstdir>       recursive mirror (-> xrdcp -r --sync)\n\n"
        "  filesystem (-> xrdfs <endpoint> <verb>):\n"
        "    xrd ls|stat|du|df|tree|find|mkdir|rm|rmdir|mv|truncate <endpoint> [args]\n"
        "    xrd cat|head|tail|wc|grep|hexdump|dd|cmp|cksum|xattr <endpoint> [args]\n"
        "    xrd touch|chmod|ln|readlink|stage|evict <endpoint> [args]\n"
        "    xrd locate|query|statvfs|prepare|explain <endpoint> [args]\n"
        "      (ls/du/df -h; head/tail -c/-n; tail -f follows; grep -i/-n; ln [-s];\n"
        "       dd bs=/skip=/count=/rate=; upload bs=/rate=/-f)\n\n"
        "  diagnostics:\n"
        "    xrd diag <subcommand> [args]      (-> xrddiag: check/bench/watch/srr/tape/...)\n"
        "    xrd ping [-c N] <endpoint>       liveness + RTT probe\n"
        "    xrd certinfo <endpoint>          server host-cert validity + expiry\n"
        "    xrd clockskew <endpoint>         client<->server clock offset (token/GSI sanity)\n"
        "    xrd whoami <endpoint>            negotiated auth + presented identity\n"
        "    xrd caps <endpoint>              server role + kXR_Qconfig capability matrix\n"
        "    xrd replicas <url>               cluster holder + space map (-> xrdmapc)\n"
        "    xrd doctor [endpoint] [--rw] [--also URL]... [--insecure] [--json]\n"
        "       full endpoint health: creds/TLS/cert/clock/caps + a functional method\n"
        "       battery (--rw adds write tests; --also adds protocols; --json dumps all)\n"
        "    xrd login [--oidc-account N] [--read]  acquire/refresh a token and/or GSI proxy\n\n"
        "  backend storage (-> xrdstorascan; lists/verifies what the backend physically holds,\n"
        "                    incl. the Ceph/RADOS object catalog over librados):\n"
        "    xrd inventory <url> [--stats] [-o objs.tsv]   dump backend object paths (+ sizes)\n"
        "    xrd verify <url> [--wire]                     recompute + compare checksums\n"
        "    xrd drift <url>                               reconcile namespace vs catalog (orphans)\n"
        "    xrd inspect <url>                             one object's backend facts (key/type)\n\n"
        "  FUSE mount (needs the libfuse3-built driver):\n"
        "    xrd mount [--legacy] <endpoint> <mountpoint> [fuse-opts]   mount via xrootdfs (--legacy: simple driver)\n"
        "    xrd mount | xrd mounts            list active XRootD FUSE mounts\n"
        "    xrd unmount [-z] <mountpoint>     unmount (fusermount3/fusermount/umount)\n\n"
        "    xrd version | help\n",
        brix_prog_base(prog));
    brix_usage_footer(out, prog);
}

void
usage(const char *prog)
{
    usage_fp(stderr, prog);
}
