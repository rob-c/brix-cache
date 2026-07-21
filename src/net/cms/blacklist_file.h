#ifndef BRIX_CMS_BLACKLIST_FILE_H
#define BRIX_CMS_BLACKLIST_FILE_H

/*
 * cms/blacklist_file.h — file-driven server blacklist (Phase-89 W6′).
 *
 * WHAT: the manager re-reads an operator-maintained blacklist file (one entry
 * per line: `host`, `host:port`, or IPv4 `a.b.c.d/n` CIDR) whenever its mtime
 * changes, and on every poll re-asserts a registry blacklist against each
 * currently-registered data server that matches an entry.
 *
 * WHY: cmsd parity (phase-61 W6′) — operators expect a cms.blacklist-style
 * file that wins over transient state.  Re-asserting every poll (rather than
 * only on mtime change) is what makes the file authoritative: an admin-API
 * `undrain` and the blacklist-clear inside brix_srv_register() are both
 * re-covered within one poll period.  Removing a line lifts the ban once the
 * last re-asserted duration expires (3x the poll interval).
 *
 * HOW: state lives in the owning CMS-server srv conf (one per srv block, no
 * globals).  brix_cms_blfile_poll() is called from the per-connection ping
 * tick and immediately after each node registration; it self-rate-limits the
 * stat() to once per second, so per-node ping fan-in stays cheap.  Matching
 * is exact host text (covers IPv6 literals), optional exact port, or IPv4
 * CIDR against the registry snapshot.  Malformed lines are logged and
 * skipped — a bad file never crashes the manager or drops the good lines.
 */

#include <ngx_config.h>
#include <ngx_core.h>

#define BRIX_CMS_BLFILE_MAX_ENTRIES  128
#define BRIX_CMS_BLFILE_MAX_BYTES    65536   /* re-read cap: admin file, tiny */
#define BRIX_CMS_BLFILE_POLL_MS      1000    /* min gap between stat() polls  */

typedef struct {
    char        host[256];   /* exact-match host text ("" when is_cidr)      */
    uint32_t    net;         /* IPv4 network (host byte order) when is_cidr  */
    uint32_t    mask;        /* IPv4 netmask (host byte order) when is_cidr  */
    uint16_t    port;        /* 0 = every port of the host                   */
    unsigned    is_cidr:1;
} brix_cms_blfile_entry_t;

typedef struct {
    brix_cms_blfile_entry_t entries[BRIX_CMS_BLFILE_MAX_ENTRIES];
    ngx_uint_t   nentries;
    time_t       mtime;      /* last-parsed file mtime (0 = never read)      */
    ngx_msec_t   next_poll;  /* ngx_current_msec gate for the stat() poll    */
} brix_cms_blfile_t;

/*
 * Parse one file line (no trailing newline; len bytes) into *out.
 * Accepts `host`, `host:port` (port 1-65535), or `a.b.c.d/n` (n 0-32).
 * `#` comments and blank lines are the CALLER's job to skip.  Pure (no I/O,
 * no nginx state).  Returns 0 on success, -1 on a malformed line.
 */
int brix_cms_blfile_parse_line(const char *line, size_t len,
    brix_cms_blfile_entry_t *out);

/*
 * Does entry e cover the registered server host:port?  Exact host text
 * (case-sensitive — registry hosts are numeric IP text) with port 0 = any,
 * or CIDR containment for IPv4 hosts.  Pure.  Returns 1 = match.
 */
int brix_cms_blfile_entry_matches(const brix_cms_blfile_entry_t *e,
    const char *host, uint16_t port);

/*
 * Poll the blacklist file and enforce it against the live registry.
 * path empty/NULL = feature off (returns immediately).  Rate-limited to one
 * stat() per BRIX_CMS_BLFILE_POLL_MS unless force is set (used right after a
 * node registration, whose brix_srv_register cleared any prior blacklist).
 * Each matching registered server is blacklisted for blacklist_ms.
 */
void brix_cms_blfile_poll(brix_cms_blfile_t *bl, const ngx_str_t *path,
    ngx_msec_t blacklist_ms, ngx_uint_t force, ngx_log_t *log);

#endif /* BRIX_CMS_BLACKLIST_FILE_H */
