/*
 * xrootdfs_usage.c — xrootdfs command-line usage/help text.
 *
 * WHAT: usage_fp() renders the full help screen; usage() sends it to stderr.
 * WHY:  Phase-38 split of xrootdfs.c to keep each TU under the 600-line cap;
 *       the (long, static) help text is one self-contained concept.
 * HOW:  behavior-identical extraction; usage() is declared in
 *       xrootdfs_internal.h and called from the arg parser exactly as before.
 */
#include "xrootdfs_internal.h"
#include "core/version.h"

void
usage_fp(FILE *out)
{
    fprintf(out,
        "usage: xrootdfs [opts] <endpoint> <mountpoint> [fuse-opts]\n"
        "  endpoint:   root[s]://host[:port][/base]      (binary XRootD; read-write)\n"
        "              http|https|dav|davs://host[:port][/base]\n"
        "                                (WebDAV/XrdHttp; READ-ONLY, ranged GET)\n"
        "              a /base path component roots the mount at that subtree\n"
        "  web-opts:   --token TOK       bearer token for http(s)  ($BEARER_TOKEN)\n"
        "              --noverifyhost    skip TLS server-cert check (self-signed beds)\n"
        "  conn-opts:  --tls --notlsok --noverifyhost --auth <gsi|ztn|unix>\n"
        "              --max-conns N    metadata connection pool size (default 8)\n"
        "              --version        print version and exit\n"
        "  resilience: --streams N      async data connections (default 4)\n"
        "              --lazy-streams   open 1 stream at mount, the rest on first\n"
        "                               I/O (lowest mount latency; first read warms up)\n"
        "              --max-stall MS   reconnect patience for a dropped link\n"
        "                               (default 60000; 0 = fail fast, no reconnect)\n"
        "              --keepalive MS   heartbeat after this idle time (default 15000)\n"
        "              --max-retries N  transient-error retries (default 5)\n"
        "              --connect-timeout MS  cap on connect+handshake+login\n"
        "                               (default 15000; tighten on a flaky firewall)\n"
        "              --io-timeout MS  steady-state read/write cap (default 30000)\n"
        "  cache-opts: --attr-timeout S --entry-timeout S --kernel-cache\n"
        "              --compress C     inline read compression (gzip|deflate|zstd|\n"
        "                               br|xz|bzip2); server opt-in, transparently\n"
        "                               inflated; ignored if the server declines\n"
        "              --readahead N    per-handle read-ahead bytes (default 1048576)\n"
        "              --writeback N    per-handle write-back bytes (default 1048576)\n"
        "              --xattr          enable extended attributes (kXR_fattr)\n"
        "  identity:   --sss-identity   authenticate each caller as THEMSELVES over\n"
        "                               sss, instead of as the mount owner.  Needed\n"
        "                               for any multi-user mount (-o allow_other):\n"
        "                               one connection set per uid, since a login\n"
        "                               identity cannot change mid-connection.  The\n"
        "                               server's keytab still decides: a key with a\n"
        "                               fixed user= ignores the name we propose.\n"
        "              --max-identities N  distinct uids one mount serves (default\n"
        "                               64).  Past it, further users are REFUSED,\n"
        "                               never served as the mount owner.\n"
        "              --identity-conns N   per-identity meta pool (default 2)\n"
        "              --identity-streams N per-identity data streams (default 1)\n"
        "  cluster:    --cluster-readdir  list a directory by asking EVERY holder\n"
        "                               the manager names, not the one it would\n"
        "                               redirect us to.  Without it a mount over a\n"
        "                               CMS manager shows one node's share of each\n"
        "                               directory.  Costs a locate plus one dirlist\n"
        "                               per holder; a node that fails is an error,\n"
        "                               never a silently short listing.\n"
        "  fuse-opts:  -f -d -s -o <opt>  (e.g. -o ro -o allow_other)\n"
        "  notes: open files survive a connection drop / server restart transparently\n"
        "         (reopen + resume at the same offset, byte-exact). utimens/chown and\n"
        "         symlink/readlink/link use the vendor kXR_setattr/link extensions when\n"
        "         the server advertises them (BriX does); ENOTSUP otherwise.\n"
        BRIX_USAGE_FOOTER("xrootdfs"));
}

void
usage(void)
{
    usage_fp(stderr);
}
