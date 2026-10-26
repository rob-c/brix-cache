/*
 * gridftp_control_integrity_probe_unit.c — live GridFTP GSS command-integrity
 * regression probe.
 *
 * WHAT: Opens a native gsiftp session, bypasses the client's normal command
 * wrapper for two raw commands, and verifies the server refuses them while
 * continuing to accept correctly protected commands.
 *
 * WHY: The ordinary client deliberately wraps every command after ADAT, so a
 * black-box transfer cannot prove that the server rejects an attacker who
 * writes plaintext directly to the authenticated control socket.
 *
 * HOW: Use the private client session API to complete a real GSI login; write
 * raw PWD and DELE lines to its fd; unwrap their protected 533 replies; send a
 * nested ENC and a legitimate PWD through the normal protected command path;
 * finally verify raw QUIT remains the sole compatibility exception.
 */

#include "protocols/ftp/ftp_client.h"

#include <stdio.h>
#include <string.h>
#include <unistd.h>


/* ---- Report one failed probe step ----
 *
 * WHAT: Prints the failed step, observed reply/status, and returns one.
 *
 * WHY: Pytest needs a bounded diagnostic that distinguishes transport failure
 * from an unexpected server verdict without exposing credential material.
 *
 * HOW: Read only the public status text and last reply fields.
 */
static int
probe_fail(const char *step, const brix_ftp_sess *session,
           const brix_status *status)
{
    fprintf(stderr, "%s failed: reply=%d text=%s status=%s\n",
            step, session->code, session->text, status->msg);
    return 1;
}


/* ---- Send an intentionally unprotected command and require one reply ----
 *
 * WHAT: Writes `line` directly to the control fd, unwraps the reply, and
 * returns zero only when its code equals `expected`.
 *
 * WHY: `brix_ftp_cmd()` correctly protects post-GSS commands; bypassing it is
 * necessary to exercise the server's raw-socket integrity gate.
 *
 * HOW: Perform a bounded full write, use the session's normal protected-reply
 * reader, then compare the decoded reply code.
 */
static int
probe_raw_expect(brix_ftp_sess *session, const char *line, int expected,
                 brix_status *status)
{
    size_t length = strlen(line);

    brix_status_clear(status);
    if (brix_ftp_io_write_all(session->fd, line, length,
                              session->timeout_ms, status) != 0)
    {
        return -1;
    }
    if (brix_ftp_read_reply(session, status) != 0) {
        return -1;
    }
    return session->code == expected ? 0 : -1;
}


/* ---- Send a normally protected command and require one reply ----
 *
 * WHAT: Sends `command` through the client wrapper and returns zero only for
 * the expected decoded reply code.
 *
 * WHY: Every malicious rejection must be paired with a legitimate control on
 * the identical established GSS session.
 *
 * HOW: Invoke the normal command API, then compare its stored reply code.
 */
static int
probe_protected_expect(brix_ftp_sess *session, const char *command,
                       int expected, brix_status *status)
{
    brix_status_clear(status);
    if (brix_ftp_cmd(session, status, "%s", command) != 0) {
        return -1;
    }
    return session->code == expected ? 0 : -1;
}


/* ---- Exercise the live post-GSS command-integrity contract ----
 *
 * WHAT: Returns zero only when raw ordinary commands and nested wrappers are
 * refused, a protected ordinary command succeeds, and raw QUIT remains valid.
 *
 * WHY: This is the end-to-end regression for the dispatcher provenance split.
 *
 * HOW: Parse the supplied gsiftp URL, establish a real proxy-authenticated
 * session, run the malicious/control sequence, and release all session state on
 * every outcome.
 */
int
main(int argc, char **argv)
{
    brix_ftp_sess session;
    brix_ftpurl   url;
    brix_opts     options;
    brix_status   status = { 0 };

    if (argc != 3) {
        fprintf(stderr, "usage: %s gsiftp://host:port/ ca-directory\n",
                argv[0]);
        return 2;
    }
    if (brix_ftpurl_parse(argv[1], &url) != 0 || !url.gsi) {
        fprintf(stderr, "probe requires a gsiftp URL\n");
        return 2;
    }

    brix_opts_init(&options);
    options.ca_dir = argv[2];
    if (brix_ftp_session_open(&session, &url, &options, &status) != 0) {
        return probe_fail("GSI session open", &session, &status);
    }

    if (probe_raw_expect(&session, "PWD\r\n", 533, &status) != 0) {
        int result = probe_fail("raw PWD", &session, &status);

        brix_ftp_close(&session);
        return result;
    }
    if (probe_raw_expect(&session, "DELE /raw-command-target.bin\r\n",
                         533, &status) != 0)
    {
        int result = probe_fail("raw DELE", &session, &status);

        brix_ftp_close(&session);
        return result;
    }
    if (probe_protected_expect(&session, "ENC AAAA", 533, &status) != 0) {
        int result = probe_fail("nested ENC", &session, &status);

        brix_ftp_close(&session);
        return result;
    }
    if (probe_protected_expect(&session, "PWD", 257, &status) != 0) {
        int result = probe_fail("protected PWD", &session, &status);

        brix_ftp_close(&session);
        return result;
    }
    if (probe_raw_expect(&session, "QUIT\r\n", 221, &status) != 0) {
        int result = probe_fail("raw QUIT", &session, &status);

        brix_ftp_close(&session);
        return result;
    }

    close(session.fd);
    session.fd = -1;
    brix_ftp_close(&session);
    puts("gridftp control integrity: PASS");
    return 0;
}
