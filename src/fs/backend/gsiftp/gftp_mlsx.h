#ifndef BRIX_GSIFTP_MLSX_H
#define BRIX_GSIFTP_MLSX_H

/*
 * gftp_mlsx.h — client-role MLSD/MLST fact-line parser (RFC 3659 §7) for the
 * outbound gsiftp:// storage driver.
 *
 * WHAT: invert one "facts SP pathname" line into the size/type/mtime/name the
 * SD namespace layer maps onto brix_sd_stat_t / brix_sd_dirent_t.
 *
 * WHY: the phase-82 gateway only *emits* MLSx (ev_list_fill); a client must
 * reverse the fact grammar (`type=;size=;modify=;perm=;unix.mode=;`). Directory
 * listings from a remote origin are attacker-influenced, so the parser is
 * defensive: unknown facts are ignored, a name carrying NUL/CR/LF or a path
 * separator is rejected (the SD layer re-confines the survivor), and numeric
 * facts reject overflow. Pure (no nginx types) so it is exhaustively testable.
 *
 * HOW: `gftp_mlsx_parse` splits the leading facts blob at the first space,
 * walks the `;`-separated `key=value` facts case-insensitively, and returns the
 * name as a pointer/length into the caller's line buffer (no copies).
 */

#include <stddef.h>

typedef struct {
    const char         *name;      /* into the caller's buffer (not NUL-term)  */
    size_t              name_len;
    int                 is_dir;    /* type=dir/cdir/pdir                        */
    int                 has_size;
    unsigned long long  size;      /* valid iff has_size                        */
    int                 has_mtime;
    long long           mtime;     /* UTC epoch from modify=; valid iff has_mtime */
} gftp_mlsx_ent_t;

/*
 * Parse one MLSD/MLST fact line (CR/LF already stripped, no trailing newline).
 * Returns 0 on success (out filled), -1 if there is no facts/name separator,
 * the name is empty, or the name contains NUL, CR, LF, or '/'.
 */
int gftp_mlsx_parse(const char *line, size_t len, gftp_mlsx_ent_t *out);

#endif /* BRIX_GSIFTP_MLSX_H */
