/*
 * diag_topology.c - extracted concern
 * Phase-38 split of xrddiag.c; behavior-identical.
 */
#include "diag_internal.h"


/* Choose a remote regular file to operate on: if the URL carried an explicit
 * path (not "/") use it; otherwise list "/" and pick the largest regular file.
 * Fills target[tsz] with the absolute path and *sti with its stat. 0 / -1. */
int
resolve_target(brix_conn *c, const brix_url *u, char *target, size_t tsz,
               brix_statinfo *sti, brix_status *st)
{
    brix_dirent *ents = NULL;
    size_t       n = 0, i;
    int64_t      best = -1;
    int          found = 0;

    if (u->path[0] != '\0' && strcmp(u->path, "/") != 0) {
        if (brix_stat(c, u->path, sti, st) != 0) {
            return -1;
        }
        if (sti->flags & kXR_isDir) {
            brix_status_set(st, XRDC_EUSAGE, 0, "%s is a directory", u->path);
            return -1;
        }
        snprintf(target, tsz, "%s", u->path);
        return 0;
    }

    if (brix_dirlist(c, "/", 1, &ents, &n, st) != 0) {
        return -1;
    }
    for (i = 0; i < n; i++) {
        if (!ents[i].have_stat || (ents[i].st.flags & kXR_isDir)) {
            continue;
        }
        if (ents[i].st.size > best) {
            best = ents[i].st.size;
            snprintf(target, tsz, "/%s", ents[i].name);
            *sti = ents[i].st;
            found = 1;
        }
    }
    free(ents);
    if (!found) {
        brix_status_set(st, XRDC_EUSAGE, 0,
                        "no regular file under / to test (pass a file URL)");
        return -1;
    }
    return 0;
}


/* topology — locate + redirect-loop convergence (+ optional /cluster) */

int
do_topology(const diag_args *a)
{
    brix_url    u;
    brix_conn   c;
    brix_status st;
    char        loc[4096];
    const char *qpath;

    brix_status_clear(&st);
    if (brix_endpoint_parse(a->url, &u, &st) != 0) {
        fprintf(stderr, "xrddiag: %s\n", st.msg);
        return 50;
    }
    if (brix_connect(&c, &u, &a->conn, &st) != 0) {
        fprintf(stderr, "xrddiag: connect %s:%d: %s\n", u.host, u.port, st.msg);
        return brix_shellcode(&st);
    }

    qpath = (u.path[0] != '\0') ? u.path : "/";
    printf("Topology of %s:%d\n", u.host, u.port);

    if (brix_locate(&c, qpath, loc, sizeof(loc), &st) == 0) {
        probe("locate", loc[0] != '\0', "%s -> %s", qpath, loc[0] ? loc : "(empty)");
    } else {
        probe("locate", 0, "%s", st.msg);
    }

    /* redirect-loop convergence: a nonexistent path must resolve to NotFound,
     * not exhaust the redirect budget (the cluster loop-guard regression test). */
    {
        brix_statinfo s;
        brix_status   nst;
        int           rc;
        brix_status_clear(&nst);
        rc = brix_stat(&c, "/nonexistent-xrddiag-probe-path", &s, &nst);
        probe("redirect-convergence", rc != 0 && nst.kxr == kXR_NotFound,
              "nonexistent path -> %s", rc != 0 ? brix_kxr_name(nst.kxr) : "SERVED?!");
    }

    if (a->cluster_url != NULL) {
        brix_url    cu;
        brix_status cst;
        char       *body = malloc(1u << 20);
        int         http = 0;
        brix_status_clear(&cst);
        if (body != NULL && brix_endpoint_parse(a->cluster_url, &cu, &cst) == 0 &&
            brix_http_get(cu.host, cu.port, cu.path[0] ? cu.path : "/", 5000,
                          &http, body, 1u << 20, NULL, &cst) == 0) {
            printf("  /cluster (HTTP %d):\n%s\n", http, body);
        } else {
            note("cluster-json", "unavailable: %s", cst.msg);
        }
        free(body);
    } else {
        note("cluster-json", "pass --cluster-url http://host:port/brix/api/v1/cluster");
    }

    brix_close(&c);
    return g_fails ? 1 : 0;
}


/* Parse a "[http://]host[:port][/...]" WebDAV endpoint into host + port (8080). */
void
parse_http_hostport(const char *s, char *host, size_t hsz, int *port)
{
    const char *p = s, *e;
    *port = 8080;
    if (strncmp(p, "http://", 7) == 0) {
        p += 7;
    }
    e = p;
    while (*e != '\0' && *e != ':' && *e != '/') {
        e++;
    }
    {
        size_t n = (size_t) (e - p);
        if (n >= hsz) { n = hsz - 1; }
        memcpy(host, p, n);
        host[n] = '\0';
    }
    if (*e == ':') {
        *port = atoi(e + 1);
    }
}


/* probe-robustness — gated adversarial auditor (§15.8)                */

/*
 * Resolve host ONCE to a numeric IP and classify whether it is loopback. The
 * probe then connects to this SAME numeric IP (getaddrinfo on a literal address
 * is deterministic), so a DNS-rebind / localhost.attacker.com cannot slip a
 * non-loopback target past the gate between the check and the connect. 0 / -1.
 */
int
resolve_once(const char *host, int port, char *ip, size_t ipsz, int *is_loop,
             brix_status *st)
{
    struct addrinfo  hints, *res = NULL;
    char             portstr[16];
    int              gai;

    memset(&hints, 0, sizeof(hints));
    /* Honor a session-wide IPv6→IPv4 demotion (netpref.c) for consistency with
     * every other connect path: AF_UNSPEC normally, AF_INET once this process
     * has fallen back to IPv4-only. */
    hints.ai_family   = brix_netpref_family();
    hints.ai_socktype = SOCK_STREAM;
    snprintf(portstr, sizeof(portstr), "%d", port);

    gai = getaddrinfo(host, portstr, &hints, &res);
    if (gai != 0 || res == NULL) {
        brix_status_set(st, XRDC_ESOCK, 0, "resolve %s: %s", host,
                        gai_strerror(gai));
        return -1;
    }
    *is_loop = 0;
    if (res->ai_family == AF_INET) {
        struct sockaddr_in *s4 = (struct sockaddr_in *) res->ai_addr;
        *is_loop = ((ntohl(s4->sin_addr.s_addr) >> 24) == 127);   /* 127.0.0.0/8 */
    } else if (res->ai_family == AF_INET6) {
        struct sockaddr_in6 *s6 = (struct sockaddr_in6 *) res->ai_addr;
        *is_loop = IN6_IS_ADDR_LOOPBACK(&s6->sin6_addr);
    }
    getnameinfo(res->ai_addr, res->ai_addrlen, ip, (socklen_t) ipsz, NULL, 0,
                NI_NUMERICHOST);
    freeaddrinfo(res);
    return 0;
}


/* Connect a fresh session to the (numeric) probe target, with a bounded per-probe
 * deadline so a wedged/abusive exchange can never hang the auditor. 0 / -1. */
int
probe_open(brix_conn *c, const char *urlbuf, const diag_args *a, int tmo,
           brix_status *st)
{
    brix_url cu;
    if (brix_endpoint_parse(urlbuf, &cu, st) != 0) {
        return -1;
    }
    if (brix_connect(c, &cu, &a->conn, st) != 0) {
        return -1;
    }
    c->io.timeout_ms = tmo;
    return 0;
}


/*
 * Write a (possibly malformed) 24-byte header + body bytes straight onto the wire
 * — bypassing brix_send so we can lie about dlen / use a bad opcode — then read
 * one response. Returns 1 if the server REJECTED the abuse (kXR_error, an
 * unexpected status, or a closed/timed-out connection), 0 if it SERVED it
 * (kXR_ok/oksofar — a bug), -1 on our own write failure.
 */
int
raw_send_expect_reject(brix_conn *c, const uint8_t hdr24[24],
                       const uint8_t *body, uint32_t bodylen,
                       int lie_dlen, uint32_t fake_dlen)
{
    uint8_t     hdr[24];
    brix_status st;
    uint16_t    status = 0;
    uint8_t    *rb = NULL;
    uint32_t    rl = 0, wire_dlen;
    int         rc;

    memcpy(hdr, hdr24, 24);
    hdr[0] = 0x7e; hdr[1] = 0x01;   /* arbitrary streamid (recv accepts any) */
    wire_dlen = lie_dlen ? fake_dlen : bodylen;
    hdr[20] = (uint8_t) (wire_dlen >> 24);
    hdr[21] = (uint8_t) (wire_dlen >> 16);
    hdr[22] = (uint8_t) (wire_dlen >> 8);
    hdr[23] = (uint8_t) wire_dlen;

    brix_status_clear(&st);
    if (brix_write_full(&c->io, hdr, 24, &st) != 0) {
        return -1;
    }
    if (bodylen > 0 && body != NULL) {
        if (brix_write_full(&c->io, body, bodylen, &st) != 0) {
            return -1;
        }
    }
    rc = brix_recv(c, 0xffff, &status, &rb, &rl, &st);
    free(rb);
    if (rc != 0) {
        return 1;   /* kXR_error / closed / timeout → rejected cleanly */
    }
    return (status == kXR_ok || status == kXR_oksofar) ? 0 : 1;
}
