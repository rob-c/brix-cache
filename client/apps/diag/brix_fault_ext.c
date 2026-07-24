/*
 * brix_fault_ext.c — pure stream-mutation + PROXY-protocol forgery helpers.
 * See brix_fault_ext.h.  No globals, no I/O: safe to unit-test and to call from
 * the relay hot path after the caller has snapshotted its locked config.
 */
#include "brix_fault_ext.h"

#include <arpa/inet.h>
#include <ctype.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int
fp_ext_mut_active(const fp_ext_mut *m)
{
    return m->find_len > 0 || m->inject_len > 0 ||
           m->drop_ppm > 0 || m->repeat_ppm > 0;
}

/* Append one byte to out[*o] if room; returns 1 on write, 0 if full. */
static int
emit(unsigned char *out, size_t outcap, size_t *o, unsigned char b)
{
    if (*o >= outcap) {
        return 0;
    }
    out[(*o)++] = b;
    return 1;
}

size_t
fp_ext_mutate(const unsigned char *in, size_t n,
              unsigned char *out, size_t outcap,
              const fp_ext_mut *m, unsigned *seed, fp_ext_stats *st)
{
    size_t o = 0;

    /* One-shot inject: splice the payload in front of this buffer. */
    for (size_t k = 0; k < m->inject_len; k++) {
        if (emit(out, outcap, &o, m->inject[k])) {
            st->injected++;
        }
    }

    for (size_t i = 0; i < n; ) {
        /* Substring rewrite (non-overlapping, greedy left-to-right). */
        if (m->find_len > 0 && i + m->find_len <= n &&
            memcmp(in + i, m->find, m->find_len) == 0) {
            for (size_t k = 0; k < m->repl_len; k++) {
                emit(out, outcap, &o, m->repl[k]);
            }
            st->replaced++;
            i += m->find_len;
            continue;
        }
        /* Probabilistic delete (framing desync — length shrinks). */
        if (m->drop_ppm > 0 && (int) (rand_r(seed) % 1000000u) < m->drop_ppm) {
            st->dropped++;
            i++;
            continue;
        }
        emit(out, outcap, &o, in[i]);
        /* Probabilistic duplicate (length inflates). */
        if (m->repeat_ppm > 0 && (int) (rand_r(seed) % 1000000u) < m->repeat_ppm) {
            if (emit(out, outcap, &o, in[i])) {
                st->repeated++;
            }
        }
        i++;
    }
    return o;
}

/* Decode two hex nibbles at s into a byte; returns -1 on a non-hex digit. */
static int
hexbyte(const char *s)
{
    int hi = 0, lo = 0;
    for (int pass = 0; pass < 2; pass++) {
        char c = s[pass];
        int  v;
        if (c >= '0' && c <= '9')      v = c - '0';
        else if (c >= 'a' && c <= 'f') v = c - 'a' + 10;
        else if (c >= 'A' && c <= 'F') v = c - 'A' + 10;
        else return -1;
        if (pass == 0) hi = v; else lo = v;
    }
    return (hi << 4) | lo;
}

static int
parse_hex(const char *p, unsigned char *out, size_t cap)
{
    size_t len = strlen(p);
    if (len % 2 != 0) {
        return -1;
    }
    size_t o = 0;
    for (size_t i = 0; i < len; i += 2) {
        int b = hexbyte(p + i);
        if (b < 0 || o >= cap) {
            return -1;
        }
        out[o++] = (unsigned char) b;
    }
    return (int) o;
}

/* Decode a literal token honouring \r \n \t \0 \xNN \\ escapes. */
static int
parse_literal(const char *p, unsigned char *out, size_t cap)
{
    size_t o = 0;
    for (size_t i = 0; p[i] != '\0'; i++) {
        unsigned char c = (unsigned char) p[i];
        if (c == '\\' && p[i + 1] != '\0') {
            char e = p[++i];
            switch (e) {
            case 'r': c = '\r'; break;
            case 'n': c = '\n'; break;
            case 't': c = '\t'; break;
            case '0': c = '\0'; break;
            case '\\': c = '\\'; break;
            case 'x': {
                int b = hexbyte(p + i + 1);
                if (b < 0) {
                    return -1;
                }
                c = (unsigned char) b;
                i += 2;
                break;
            }
            default: c = (unsigned char) e; break;
            }
        }
        if (o >= cap) {
            return -1;
        }
        out[o++] = c;
    }
    return (int) o;
}

int
fp_ext_parse_payload(const char *tok, unsigned char *out, size_t cap)
{
    if (tok == NULL) {
        return -1;
    }
    if (strncmp(tok, "hex:", 4) == 0) {
        return parse_hex(tok + 4, out, cap);
    }
    if (strncmp(tok, "str:", 4) == 0) {
        return parse_literal(tok + 4, out, cap);
    }
    return parse_literal(tok, out, cap);
}

/* Split "ip:port" (IPv4 dotted or IPv6 in [..]) into ip / port. Returns family
 * AF_INET/AF_INET6 or -1. */
static int
split_hostport(const char *hp, char *ip, size_t ipcap, int *port)
{
    if (hp == NULL) {
        return -1;
    }
    const char *colon;
    int         fam;
    if (hp[0] == '[') {                       /* [v6]:port */
        const char *close = strchr(hp, ']');
        if (close == NULL || close[1] != ':') {
            return -1;
        }
        size_t n = (size_t) (close - hp - 1);
        if (n == 0 || n >= ipcap) {
            return -1;
        }
        memcpy(ip, hp + 1, n);
        ip[n] = '\0';
        colon = close + 1;
        fam = AF_INET6;
    } else {
        colon = strrchr(hp, ':');
        if (colon == NULL) {
            return -1;
        }
        size_t n = (size_t) (colon - hp);
        if (n == 0 || n >= ipcap) {
            return -1;
        }
        memcpy(ip, hp, n);
        ip[n] = '\0';
        fam = strchr(ip, ':') ? AF_INET6 : AF_INET;
    }
    char *end;
    long  p = strtol(colon + 1, &end, 10);
    if (end == colon + 1 || p <= 0 || p > 65535) {
        return -1;
    }
    *port = (int) p;
    /* Validate the literal really parses in the claimed family. */
    unsigned char tmp[16];
    if (inet_pton(fam, ip, tmp) != 1) {
        return -1;
    }
    return fam;
}

/* A parsed src/dst endpoint pair sharing one address family. */
typedef struct {
    char sip[64], dip[64];
    int  sport, dport, fam;
} fp_hostpair;

/* Parse both "ip:port" endpoints and require a common family.  Returns 0 on
 * success (fields of *hp filled), or -1 on a parse error / family mismatch. */
static int
parse_pair(const char *src, const char *dst, fp_hostpair *hp)
{
    int sf = split_hostport(src, hp->sip, sizeof(hp->sip), &hp->sport);
    int df = split_hostport(dst, hp->dip, sizeof(hp->dip), &hp->dport);
    if (sf < 0 || df < 0 || sf != df) {
        return -1;
    }
    hp->fam = sf;
    return 0;
}

int
fp_ext_proxy_v1(char *out, size_t cap, const char *src, const char *dst)
{
    fp_hostpair hp;
    if (parse_pair(src, dst, &hp) < 0) {
        return -1;
    }
    const char *proto = (hp.fam == AF_INET) ? "TCP4" : "TCP6";
    int n = snprintf(out, cap, "PROXY %s %s %s %d %d\r\n",
                     proto, hp.sip, hp.dip, hp.sport, hp.dport);
    if (n < 0 || (size_t) n >= cap) {
        return -1;
    }
    return n;
}

int
fp_ext_proxy_v2(unsigned char *out, size_t cap, const char *src, const char *dst)
{
    fp_hostpair hp;
    if (parse_pair(src, dst, &hp) < 0) {
        return -1;
    }
    static const unsigned char sig[12] = {
        0x0D, 0x0A, 0x0D, 0x0A, 0x00, 0x0D, 0x0A, 0x51, 0x55, 0x49, 0x54, 0x0A
    };
    size_t addrlen = (hp.fam == AF_INET) ? 12 : 36;
    size_t total   = 16 + addrlen;
    if (cap < total) {
        return -1;
    }
    memcpy(out, sig, 12);
    out[12] = 0x21;                                   /* version 2, PROXY */
    out[13] = (hp.fam == AF_INET) ? 0x11 : 0x21;      /* AF_INET/6 + STREAM */
    out[14] = (unsigned char) (addrlen >> 8);
    out[15] = (unsigned char) (addrlen & 0xFF);
    /* addrlen is 2*iplen + 4 port bytes; write both IPs then the port pair,
     * family-agnostic (iplen 4 for v4, 16 for v6). */
    size_t         iplen = (hp.fam == AF_INET) ? 4 : 16;
    unsigned char *a     = out + 16;
    inet_pton(hp.fam, hp.sip, a);
    inet_pton(hp.fam, hp.dip, a + iplen);
    unsigned char *p = a + 2 * iplen;
    p[0] = (unsigned char) (hp.sport >> 8); p[1] = (unsigned char) hp.sport;
    p[2] = (unsigned char) (hp.dport >> 8); p[3] = (unsigned char) hp.dport;
    return (int) total;
}
