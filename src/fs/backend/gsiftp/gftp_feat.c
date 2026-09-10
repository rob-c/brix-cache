/* RFC 2389 FEAT capability probe — see gftp_feat.h. */

#include "gftp_feat.h"

#include <strings.h>
#include <string.h>

/* One advertised feature name and the bit it lights.  A FEAT line is a bare
 * verb optionally followed by parameters (RFC 2389 §3.2), so the match is on
 * the leading token of a trimmed line and never on a substring of the reply —
 * "ERET" must not be found inside a door's banner or inside "SITE ERETSTAT". */
static const struct {
    const char *name;
    size_t      len;
    unsigned    bit;
} gftp_feat_names[] = {
    { "ERET", 4, GFTP_FEAT_ERET },
    { "SPAS", 4, GFTP_FEAT_SPAS },
};


/* True when `line` (already trimmed of its leading space) begins with the
 * feature `name` as a whole token.
 *
 * The line terminator is a token boundary, and saying so is the whole point of
 * this helper: FEAT lines arrive CRLF-terminated (RFC 2389 §3.2 over RFC 959's
 * control channel), so a boundary set of only ' ' / '\t' / NUL matched NOTHING
 * on a conforming origin — every advertised name is followed by the CR.  The
 * mask came back empty every time, ERET and SPAS were never once issued, and
 * nothing said so: the driver simply fell back to REST+RETR and single-stream
 * transfers and worked, slower and unbounded. */
static int
gftp_feat_line_is(const char *line, const char *name, size_t len)
{
    char after;

    if (strncasecmp(line, name, len) != 0) {
        return 0;
    }
    after = line[len];

    return after == '\0' || after == ' ' || after == '\t'
        || after == '\r' || after == '\n';
}


/* Parse one FEAT reply body into a mask. */
static unsigned
gftp_feat_parse(const char *text)
{
    unsigned    mask = 0;
    const char *line = text;

    while (line != NULL && *line != '\0') {
        const char *end = strchr(line, '\n');
        size_t      i;

        while (*line == ' ' || *line == '\t' || *line == '\r') {
            line++;
        }
        for (i = 0; i < sizeof(gftp_feat_names) / sizeof(*gftp_feat_names);
             i++)
        {
            if (gftp_feat_line_is(line, gftp_feat_names[i].name,
                                  gftp_feat_names[i].len))
            {
                mask |= gftp_feat_names[i].bit;
            }
        }
        line = (end != NULL) ? end + 1 : NULL;
    }
    return mask;
}


unsigned
gftp_feat(gftp_session_t *session)
{
    if (session->feat_probed) {
        return session->feat;
    }
    /* Probed exactly once whatever the outcome: an origin that answers FEAT
     * with 500 is telling us something permanent about itself, and re-asking on
     * every bounded read would spend a round trip to be told the same thing. */
    session->feat_probed = 1;
    session->feat = 0;
    if (gftp_command(session, "FEAT") != 0) {
        return 0;
    }
    if (session->code != 211) {
        return 0;
    }
    /* The features are in the CONTINUATION lines: a FEAT reply's final line is
     * a bare "End", so parsing session->text would find nothing, every time. */
    session->feat = gftp_feat_parse(session->cont);
    return session->feat;
}
