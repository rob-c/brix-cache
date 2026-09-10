/* GridFTP striped passive data channels — see gftp_spas.h. */

#include "gftp_spas.h"
#include "gftp_feat.h"
#include "gftp_reply.h"

#include <stdio.h>
#include <string.h>

/* The stripe ports kept from one SPAS reply.  Only the PORTS survive the parse:
 * every stripe's address has to be the control channel's peer to be kept at
 * all, so carrying the addresses forward would just be carrying that same
 * string N times — and would give a later reader the impression there was a
 * choice of address here.  There is not (see gftp_spas.h). */
typedef struct {
    unsigned ports[GFTP_STREAMS_MAX];
    unsigned n;
} gftp_spas_list_t;


/* Is this stripe's address the control channel's own peer? */
static int
gftp_spas_same_peer(const gftp_session_t *session, const unsigned char ip[4])
{
    char text[16];
    int  n;

    n = snprintf(text, sizeof(text), "%u.%u.%u.%u", ip[0], ip[1], ip[2], ip[3]);
    if (n <= 0 || n >= (int) sizeof(text)) {
        return 0;
    }
    return strcmp(text, session->peer_ip) == 0;
}


/* Take one continuation line of the 229 reply.  Returns 0 when the line was a
 * usable stripe or an empty separator, -1 when the whole reply must be
 * abandoned — an unreadable line, a stripe pointing somewhere other than the
 * control peer, or more stripes than one transfer may hold. */
static int
gftp_spas_line(const gftp_session_t *session, gftp_spas_list_t *out,
    const char *line, size_t len)
{
    unsigned char ip[4];
    unsigned      port;
    size_t        i;

    for (i = 0; i < len; i++) {
        if (line[i] != ' ' && line[i] != '\t' && line[i] != '\r') {
            break;
        }
    }
    if (i == len) {
        return 0;                        /* blank separator line */
    }
    if (gftp_reply_parse_pasv(line, len, ip, &port) != 0
        || !gftp_spas_same_peer(session, ip)
        || out->n == GFTP_STREAMS_MAX)
    {
        return -1;
    }
    out->ports[out->n++] = port;
    return 0;
}


/* Parse every stripe out of the session's continuation buffer.  Returns 0 with
 * out->n >= 1, or -1 when the reply cannot be used as a whole. */
static int
gftp_spas_parse(const gftp_session_t *session, gftp_spas_list_t *out)
{
    const char *line = session->cont;

    /* A truncated continuation buffer would silently DROP stripes, and a
     * transfer connected to a subset of them waits for EOD blocks that arrive
     * on sockets nobody opened.  Refuse the reply rather than the transfer. */
    if (session->cont_truncated) {
        return -1;
    }
    out->n = 0;
    while (line != NULL && *line != '\0') {
        const char *end = strchr(line, '\n');
        size_t      len = (end != NULL) ? (size_t) (end - line) : strlen(line);

        if (gftp_spas_line(session, out, line, len) != 0) {
            return -1;
        }
        line = (end != NULL) ? end + 1 : NULL;
    }
    return (out->n >= 1) ? 0 : -1;
}


/* Would a striped channel be used at all?  Three independent reasons not to
 * ask, none of them a failure: the operator did not budget for it, the wire is
 * not carrying offsets (only MODE E blocks can be reassembled out of order
 * across connections at all), or the origin never advertised SPAS. */
static int
gftp_spas_wanted(gftp_session_t *session)
{
    if (session->want_streams < 2 || session->mode != GFTP_DMODE_E) {
        return 0;
    }
    return (gftp_feat(session) & GFTP_FEAT_SPAS) != 0;
}


/* Ask for the stripe list.  Returns 0 with `out` filled, or -1 to fall back. */
static int
gftp_spas_request(gftp_session_t *session, gftp_spas_list_t *out)
{
    if (gftp_command(session, "SPAS") != 0) {
        return -1;
    }
    if (session->code != 229 || gftp_spas_parse(session, out) != 0
        || out->n > session->want_streams)
    {
        /* Advertised then unusable.  Clear the bit so the rest of the session
         * spends no more round trips discovering the same thing — the same
         * ask-once rule the ERET fallback follows. */
        session->feat &= ~GFTP_FEAT_SPAS;
        return -1;
    }
    return 0;
}


void
gftp_dc_group_close(gftp_dc_group_t *group)
{
    unsigned i;

    for (i = 0; i < group->n; i++) {
        gftp_dc_close(&group->conns[i]);
    }
    group->n = 0;
}


/* Dial every stripe.  Returns 0, or -1 with the group already closed. */
static int
gftp_spas_dial(gftp_session_t *session, gftp_dc_group_t *group,
    const gftp_spas_list_t *list)
{
    unsigned i;

    for (i = 0; i < list->n; i++) {
        if (gftp_dc_open_at(session, &group->conns[i], session->peer_ip,
                            list->ports[i]) != 0)
        {
            gftp_dc_group_close(group);
            return -1;
        }
        group->n = i + 1;
    }
    return 0;
}


int
gftp_dc_group_secure(gftp_session_t *session, gftp_dc_group_t *group)
{
    unsigned i;

    for (i = 0; i < group->n; i++) {
        if (gftp_dc_secure(session, &group->conns[i]) != 0) {
            gftp_dc_group_close(group);
            return -1;
        }
    }
    return 0;
}


int
gftp_dc_group_open(gftp_session_t *session, gftp_dc_group_t *group)
{
    gftp_spas_list_t list;

    group->n = 0;
    if (gftp_spas_wanted(session)
        && gftp_spas_request(session, &list) == 0
        && gftp_spas_dial(session, group, &list) == 0)
    {
        return 0;
    }
    /* Every way of not striping ends here, at the connection this driver has
     * always opened: one EPSV/PASV to the pinned control peer. */
    if (gftp_dc_open(session, &group->conns[0]) != 0) {
        return -1;
    }
    group->n = 1;
    return 0;
}
