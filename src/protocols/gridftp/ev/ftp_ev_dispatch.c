#include "ftp_ev.h"

#include <strings.h>   /* strcasecmp / strncasecmp */
#include <string.h>    /* strcasestr, strrchr */
#include <stdlib.h>    /* atoi, strtoll */
#include <unistd.h>    /* close() for ABOR's dangling listener */

/*
 * ftp_ev_dispatch.c — the command dispatcher and the small stateless verbs.
 *
 * WHAT: brix_ftp_ev_dispatch() frames a single command line into verb+arg,
 * enforces the pre-auth gate, and routes to the right handler; the transfer-
 * parameter and session verbs whose entire implementation is a single reply
 * (TYPE/MODE/STRU/ALLO/PWD/CDUP/NOOP/SYST/OPTS/REST/ABOR/SITE/PBSZ/PROT/DCAU/
 * USER/PASS/QUIT/FEAT) are handled inline here; the heavier namespace, security,
 * and transfer verbs delegate to their own files.
 *
 * WHY: this mirrors the sync engine's ftp_dispatch() one-to-one so the two engines
 * accept exactly the same grammar and emit the same reply codes — the invariant
 * the transition depends on.  Keeping the one-line verbs here (rather than one
 * trivial function each) keeps the dispatcher readable without inflating the file
 * count with near-empty handlers.
 *
 * HOW: each handler queues its reply via brix_ftp_ev_reply() and returns NGX_OK
 * to continue, NGX_DONE on QUIT (flush then close), or NGX_ERROR on a fatal reply
 * failure.  The dispatcher never performs I/O itself — the engine flushes.
 */


/* Verbs accepted before the client has authenticated: the login verbs, the RFC
 * 2228 security handshake (which sets ->authed once ADAT completes), and
 * stateless capability probes.  Everything else is gated behind login. */
static int
ev_verb_preauth(const char *verb)
{
    static const char *const ok[] = {
        "USER", "PASS", "AUTH", "ADAT", "PBSZ", "PROT",
        "MIC",  "CONF", "ENC",  "QUIT", "FEAT", "SYST",
        "NOOP", "HELP", "OPTS", NULL
    };
    int i;

    for (i = 0; ok[i] != NULL; i++) {
        if (strcasecmp(verb, ok[i]) == 0) {
            return 1;
        }
    }
    return 0;
}


/* FEAT: advertise supported extensions; the GSI mechanisms only when a security
 * context is configured. */
static ngx_int_t
ev_cmd_feat(ftp_ev_t *fc)
{
    if (fc->conf->gsi && fc->conf->tls_ctx != NULL) {
        return brix_ftp_ev_reply(fc,
            "211-Features:\r\n SIZE\r\n MDTM\r\n REST STREAM\r\n PASV\r\n"
            " EPSV\r\n EPRT\r\n TYPE\r\n MLSD\r\n MLST type*;size*;modify*;perm*;\r\n"
            " CKSM\r\n AUTH GSSAPI\r\n PBSZ\r\n PROT\r\n DCAU\r\n211 End\r\n");
    }
    return brix_ftp_ev_reply(fc,
        "211-Features:\r\n SIZE\r\n MDTM\r\n REST STREAM\r\n PASV\r\n"
        " EPSV\r\n EPRT\r\n TYPE\r\n MLSD\r\n MLST type*;size*;modify*;perm*;\r\n"
        " CKSM\r\n211 End\r\n");
}


/* Handle one framed command line. */
ngx_int_t
brix_ftp_ev_dispatch(ftp_ev_t *fc, char *line)
{
    char *verb;
    char *arg = brix_ftp_ev_split(line, &verb);

    /* Pre-auth gate: reject file/namespace/transfer verbs until login. */
    if (!fc->authed && !ev_verb_preauth(verb)) {
        return brix_ftp_ev_reply(fc, "530 Please login with USER and PASS\r\n");
    }

    /* ---- RFC 2228 GSI security handshake (ftp_ev_sec.c) ---- */
    if (strcasecmp(verb, "AUTH") == 0) {
        return brix_ftp_ev_cmd_auth(fc, arg);
    } else if (strcasecmp(verb, "ADAT") == 0) {
        return brix_ftp_ev_cmd_adat(fc, arg);
    } else if (strcasecmp(verb, "MIC") == 0) {
        return brix_ftp_ev_cmd_protected(fc, "631", arg);
    } else if (strcasecmp(verb, "CONF") == 0) {
        return brix_ftp_ev_cmd_protected(fc, "632", arg);
    } else if (strcasecmp(verb, "ENC") == 0) {
        return brix_ftp_ev_cmd_protected(fc, "633", arg);

    /* ---- login ---- */
    } else if (strcasecmp(verb, "USER") == 0) {
        if (fc->sec_active) {                        /* GSI already logged in  */
            fc->authed = 1;
            return brix_ftp_ev_reply(fc, "230 GSI user %s logged in\r\n", arg);
        }
        return brix_ftp_ev_reply(fc, "331 Please specify the password\r\n");
    } else if (strcasecmp(verb, "PASS") == 0) {
        fc->authed = 1;
        return brix_ftp_ev_reply(fc, "230 Login successful\r\n");

    /* ---- data-channel protection negotiation ---- */
    } else if (strcasecmp(verb, "PBSZ") == 0) {
        return brix_ftp_ev_reply(fc, "200 PBSZ=0\r\n");
    } else if (strcasecmp(verb, "PROT") == 0) {
        if (arg[0] == 'C' || arg[0] == 'c' || arg[0] == '\0') {
            fc->prot = 'C';
            return brix_ftp_ev_reply(fc, "200 Protection level set to Clear\r\n");
        }
        if ((arg[0] == 'P' || arg[0] == 'p') && fc->sec_active) {
            fc->prot = 'P';
            return brix_ftp_ev_reply(fc, "200 Protection level set to Private\r\n");
        }
        return brix_ftp_ev_reply(fc,
            "536 Only PROT C supported; retry with -nodcau\r\n");
    } else if (strcasecmp(verb, "DCAU") == 0) {
        if (arg[0] == 'N' || arg[0] == 'n') {
            fc->dcau_a = 0;
            return brix_ftp_ev_reply(fc, "200 DCAU N\r\n");
        }
        if ((arg[0] == 'A' || arg[0] == 'a') && fc->sec_active) {
            fc->dcau_a = 1;
            return brix_ftp_ev_reply(fc, "200 DCAU A\r\n");
        }
        return brix_ftp_ev_reply(fc,
            "504 Data channel authentication unsupported; use -nodcau\r\n");

    /* ---- capability / session probes ---- */
    } else if (strcasecmp(verb, "SITE") == 0) {
        return brix_ftp_ev_reply(fc, "200 OK\r\n");
    } else if (strcasecmp(verb, "SYST") == 0) {
        return brix_ftp_ev_reply(fc, "215 UNIX Type: L8\r\n");
    } else if (strcasecmp(verb, "FEAT") == 0) {
        return ev_cmd_feat(fc);
    } else if (strcasecmp(verb, "NOOP") == 0) {
        return brix_ftp_ev_reply(fc, "200 NOOP ok\r\n");
    } else if (strcasecmp(verb, "OPTS") == 0) {
        const char *par = strcasestr(arg, "Parallelism=");
        if (par != NULL) {
            int n = atoi(par + 12);
            if (n < 1)  { n = 1; }
            if (n > 64) { n = 64; }
            fc->parallelism = n;
        }
        return brix_ftp_ev_reply(fc, "200 OK\r\n");

    /* ---- transfer parameters ---- */
    } else if (strcasecmp(verb, "TYPE") == 0) {
        fc->type_binary = (arg[0] == 'I' || arg[0] == 'i');
        return brix_ftp_ev_reply(fc, "200 Type set to %s\r\n",
                                 fc->type_binary ? "I" : "A");
    } else if (strcasecmp(verb, "MODE") == 0) {
        if (arg[0] == 'S' || arg[0] == 's') {
            fc->mode_e = 0;
            return brix_ftp_ev_reply(fc, "200 Mode set to Stream\r\n");
        }
        if (arg[0] == 'E' || arg[0] == 'e') {
            fc->mode_e = 1;
            return brix_ftp_ev_reply(fc, "200 Mode set to Extended-block\r\n");
        }
        return brix_ftp_ev_reply(fc, "504 Only stream (S) and extended-block (E) "
                                     "modes supported\r\n");
    } else if (strcasecmp(verb, "STRU") == 0) {
        if (arg[0] == 'F' || arg[0] == 'f') {
            return brix_ftp_ev_reply(fc, "200 Structure set to File\r\n");
        }
        return brix_ftp_ev_reply(fc,
            "504 Only file structure (STRU F) supported\r\n");
    } else if (strcasecmp(verb, "ALLO") == 0) {
        return brix_ftp_ev_reply(fc, "200 ALLO ok\r\n");
    } else if (strcasecmp(verb, "REST") == 0) {
        char      *endp = NULL;
        long long  off  = strtoll(arg, &endp, 10);
        if (arg[0] == '\0' || endp == arg || off < 0) {
            return brix_ftp_ev_reply(fc, "501 Bad restart offset\r\n");
        }
        fc->rest_off = (off_t) off;
        return brix_ftp_ev_reply(fc, "350 Restart position accepted (%lld)\r\n",
                                 off);

    /* ---- navigation ---- */
    } else if (strcasecmp(verb, "PWD") == 0 || strcasecmp(verb, "XPWD") == 0) {
        return brix_ftp_ev_reply(fc,
            "257 \"%s\" is the current directory\r\n", fc->cwd);
    } else if (strcasecmp(verb, "CWD") == 0 || strcasecmp(verb, "XCWD") == 0) {
        return brix_ftp_ev_cmd_cwd(fc, arg);
    } else if (strcasecmp(verb, "CDUP") == 0 || strcasecmp(verb, "XCUP") == 0) {
        char *slash = strrchr(fc->cwd, '/');
        if (slash != NULL && slash != fc->cwd) {
            *slash = '\0';
        } else {
            fc->cwd[0] = '/'; fc->cwd[1] = '\0';
        }
        return brix_ftp_ev_reply(fc, "250 Directory changed to %s\r\n", fc->cwd);

    /* ---- namespace metadata (ftp_ev_cmd.c) ---- */
    } else if (strcasecmp(verb, "SIZE") == 0) {
        return brix_ftp_ev_cmd_size(fc, arg);
    } else if (strcasecmp(verb, "MKD") == 0 || strcasecmp(verb, "XMKD") == 0) {
        return brix_ftp_ev_cmd_mkd(fc, arg);
    } else if (strcasecmp(verb, "DELE") == 0) {
        return brix_ftp_ev_cmd_dele(fc, arg);
    } else if (strcasecmp(verb, "RMD") == 0 || strcasecmp(verb, "XRMD") == 0) {
        return brix_ftp_ev_cmd_rmd(fc, arg);
    } else if (strcasecmp(verb, "MDTM") == 0) {
        return brix_ftp_ev_cmd_mdtm(fc, arg);
    } else if (strcasecmp(verb, "MLST") == 0) {
        return brix_ftp_ev_cmd_mlst(fc, arg);
    } else if (strcasecmp(verb, "STAT") == 0) {
        return brix_ftp_ev_cmd_stat(fc, arg);
    } else if (strcasecmp(verb, "CKSM") == 0) {
        return brix_ftp_ev_cmd_cksm(fc, arg);
    } else if (strcasecmp(verb, "RNFR") == 0) {
        return brix_ftp_ev_cmd_rnfr(fc, arg);
    } else if (strcasecmp(verb, "RNTO") == 0) {
        return brix_ftp_ev_cmd_rnto(fc, arg);

    /* ---- data transfers (ftp_ev_xfer.c — P82.2 event pump) ---- */
    } else if (strcasecmp(verb, "PASV") == 0) {
        return brix_ftp_ev_do_transfer(fc, -1 /* PASV setup */, arg);
    } else if (strcasecmp(verb, "EPSV") == 0) {
        return brix_ftp_ev_do_transfer(fc, -2 /* EPSV setup */, arg);
    } else if (strcasecmp(verb, "PORT") == 0) {
        return brix_ftp_ev_do_transfer(fc, -3 /* PORT setup */, arg);
    } else if (strcasecmp(verb, "EPRT") == 0) {
        return brix_ftp_ev_do_transfer(fc, -4 /* EPRT setup */, arg);
    } else if (strcasecmp(verb, "RETR") == 0) {
        return brix_ftp_ev_do_transfer(fc, FTP_EV_OP_RETR, arg);
    } else if (strcasecmp(verb, "STOR") == 0) {
        return brix_ftp_ev_do_transfer(fc, FTP_EV_OP_STOR, arg);
    } else if (strcasecmp(verb, "APPE") == 0) {
        return brix_ftp_ev_do_transfer(fc, FTP_EV_OP_APPE, arg);
    } else if (strcasecmp(verb, "LIST") == 0) {
        return brix_ftp_ev_do_transfer(fc, FTP_EV_OP_LIST, arg);
    } else if (strcasecmp(verb, "NLST") == 0) {
        return brix_ftp_ev_do_transfer(fc, FTP_EV_OP_NLST, arg);
    } else if (strcasecmp(verb, "MLSD") == 0) {
        return brix_ftp_ev_do_transfer(fc, FTP_EV_OP_MLSD, arg);

    /* ---- abort / quit ---- */
    } else if (strcasecmp(verb, "ABOR") == 0) {
        if (fc->pasv_fd >= 0) { (void) close(fc->pasv_fd); fc->pasv_fd = -1; }
        fc->active = 0;
        return brix_ftp_ev_reply(fc, "226 ABOR: no transfer in progress\r\n");
    } else if (strcasecmp(verb, "QUIT") == 0) {
        (void) brix_ftp_ev_reply(fc, "221 Goodbye\r\n");
        return NGX_DONE;
    }

    return brix_ftp_ev_reply(fc, "500 Unknown command\r\n");
}
