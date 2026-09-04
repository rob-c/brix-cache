/* RFC 959 anonymous login and RFC 2228 GSI ADAT negotiation. */

#include "gftp_client.h"
#include "gftp_gsi.h"

#include <errno.h>
#include <stdlib.h>
#include <string.h>

static char *
gftp_adat_argument(const char *text)
{
    const char *start = strstr(text, "ADAT=");
    const char *end;
    char       *copy;
    size_t      len;

    if (start == NULL) {
        return NULL;
    }
    start += sizeof("ADAT=") - 1;
    for (end = start; *end != '\0' && *end != ' ' && *end != '\r'
         && *end != '\n'; end++) {
        /* scan token */
    }
    len = (size_t) (end - start);
    if (len == 0) {
        return NULL;
    }
    copy = malloc(len + 1);
    if (copy != NULL) {
        memcpy(copy, start, len);
        copy[len] = '\0';
    }
    return copy;
}

static int
gftp_adat_input(gftp_session_t *session, uint8_t **input, size_t *input_len)
{
    char *encoded;

    *input = NULL;
    *input_len = 0;
    encoded = gftp_adat_argument(session->text);
    if (encoded == NULL) {
        return 0;
    }
    *input = gftp_base64_decode(encoded, input_len);
    free(encoded);
    if (*input == NULL) {
        gftp_set_error(session, EPROTO, "GridFTP ADAT token is not base64");
        return -1;
    }
    return 0;
}

static int
gftp_adat_send(gftp_session_t *session, const uint8_t *token, size_t token_len)
{
    char *encoded = gftp_base64_encode(token, token_len);
    char *line;
    size_t encoded_len;
    int   rc;

    if (encoded == NULL) {
        gftp_set_error(session, ENOMEM, "cannot encode GridFTP ADAT token");
        return -1;
    }
    encoded_len = strlen(encoded);
    if (encoded_len + sizeof("ADAT \r\n") > GFTP_ADAT_LINE_CAP) {
        free(encoded);
        gftp_set_error(session, EOVERFLOW, "GridFTP ADAT token exceeds limit");
        return -1;
    }
    line = malloc(encoded_len + sizeof("ADAT \r\n"));
    if (line == NULL) {
        free(encoded);
        gftp_set_error(session, ENOMEM, "cannot allocate GridFTP ADAT command");
        return -1;
    }
    memcpy(line, "ADAT ", sizeof("ADAT ") - 1);
    memcpy(line + sizeof("ADAT ") - 1, encoded, encoded_len);
    memcpy(line + sizeof("ADAT ") - 1 + encoded_len, "\r\n",
           sizeof("\r\n"));
    free(encoded);
    rc = gftp_socket_write_all(session, session->fd, line, encoded_len + 7);
    free(line);
    if (rc == 0) {
        rc = gftp_read_reply(session);
    }
    return rc;
}

static int
gftp_gsi_loop(gftp_session_t *session)
{
    uint8_t *output = NULL;
    size_t   output_len = 0;
    int      round;
    int      more;

    more = gftp_gsi_step(session->gsi, NULL, 0, &output, &output_len, session);
    if (more < 0) {
        return -1;
    }
    for (round = 0; round < 16; round++) {
        uint8_t *input = NULL;
        size_t   input_len = 0;

        if (output_len == 0 || gftp_adat_send(session, output, output_len) != 0) {
            free(output);
            return -1;
        }
        free(output);
        output = NULL;
        output_len = 0;
        if (session->code == 235) {
            session->secure = 1;
            return 0;
        }
        if (session->code != 335
            || gftp_adat_input(session, &input, &input_len) != 0) {
            free(input);
            gftp_set_error(session, EACCES, "GridFTP GSI authentication refused");
            return -1;
        }
        more = gftp_gsi_step(session->gsi, input, input_len,
                             &output, &output_len, session);
        free(input);
        if (more < 0) {
            free(output);
            return -1;
        }
    }
    free(output);
    gftp_set_error(session, ELOOP, "GridFTP GSI handshake did not converge");
    return -1;
}

static int
gftp_user_pass(gftp_session_t *session, const char *user, const char *password)
{
    if (gftp_command(session, "USER %s", user) != 0) {
        return -1;
    }
    if (session->code >= 300 && session->code < 400
        && gftp_command(session, "PASS %s", password) != 0) {
        return -1;
    }
    if (session->code < 200 || session->code > 299) {
        gftp_set_error(session, EACCES, "GridFTP identity is not authorized");
        return -1;
    }
    return 0;
}

static int
gftp_gsi_login(gftp_session_t *session, const gftp_session_cfg_t *cfg)
{
    if (cfg->proxy_path == NULL || cfg->proxy_path[0] == '\0') {
        gftp_set_error(session, EACCES, "gsiftp origin requires an X.509 proxy");
        return -1;
    }
    if (gftp_command(session, "AUTH GSSAPI") != 0 || session->code != 334) {
        gftp_set_error(session, EACCES, "GridFTP origin refused AUTH GSSAPI");
        return -1;
    }
    session->gsi = gftp_gsi_create(cfg->proxy_path, cfg->ca_dir, session);
    if (session->gsi == NULL || gftp_gsi_loop(session) != 0) {
        return -1;
    }
    return gftp_user_pass(session, ":globus-mapping:", "dummy");
}

int
gftp_authenticate(gftp_session_t *session, const gftp_session_cfg_t *cfg)
{
    if (cfg->require_gsi) {
        if (gftp_gsi_login(session, cfg) != 0) {
            return -1;
        }
        /* The data leg remains clear but is bound to the authenticated control
         * peer. A PROT-P engine can replace these policy commands later without
         * changing the storage-driver API. */
        (void) gftp_command(session, "PBSZ 0");
        (void) gftp_command(session, "PROT C");
        (void) gftp_command(session, "DCAU N");
    } else if (gftp_user_pass(session, "anonymous", "brix@") != 0) {
        return -1;
    }
    return gftp_expect(session, 200, 299, "TYPE I");
}
