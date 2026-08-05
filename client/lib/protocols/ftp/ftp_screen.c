/*
 * ftp_screen.c — data-channel address policy for the GridFTP client.
 *
 * WHAT: decide whether the address a passive-mode reply nominated may be dialled.
 * WHY:  a 227/229 reply is attacker-controlled input the moment the control peer
 *       is hostile or compromised: FTP's classic bounce attack is a server that
 *       answers PASV with someone else's address and port, turning the client into
 *       a connector to arbitrary hosts (an SSRF primitive against whatever the
 *       client can reach — link-local metadata services, internal admin ports).
 *       Every serious FTP client therefore ignores the advertised address; curl
 *       calls this --ftp-skip-pasv-ip and has made it the default.
 * HOW:  a pure predicate — no sockets, no DNS — so the rule is exhaustively
 *       unit-testable: the data address must equal the control peer's, and the
 *       port must be unprivileged (a passive data port never legitimately lands
 *       below 1024, whereas 22/25/6379 are exactly what a bounce targets).
 */
#include "ftp_client.h"

#include <string.h>

int
brix_ftp_data_addr_ok(const char *ctl_ip, const char *data_ip, unsigned port,
                      int allow_offpeer)
{
    if (port == 0 || port > 65535 || port < 1024) {
        return 0;
    }
    if (allow_offpeer) {
        return 1;
    }
    if (ctl_ip == NULL || ctl_ip[0] == '\0' || data_ip == NULL
        || data_ip[0] == '\0') {
        return 0;
    }
    return strcmp(ctl_ip, data_ip) == 0;
}
