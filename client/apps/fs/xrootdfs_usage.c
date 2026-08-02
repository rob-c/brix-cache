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
        "  fuse-opts:  -f -d -s -o <opt>  (e.g. -o ro -o allow_other)\n"
        "  notes: open files survive a connection drop / server restart transparently\n"
        "         (reopen + resume at the same offset, byte-exact). utimens/chown are\n"
        "         no-ops (no XRootD wire op); symlinks are unsupported.\n"
        BRIX_USAGE_FOOTER("xrootdfs"));
}

void
usage(void)
{
    usage_fp(stderr);
}
