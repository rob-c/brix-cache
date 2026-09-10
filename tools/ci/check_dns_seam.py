#!/usr/bin/env python3
#
# check_dns_seam.py — enforce "one DNS path" (phase-116 W4.4 / Appendix A).
#
# WHAT: Fails (exit 1) when any file under src/, client/ or shared/ resolves
#       a name outside the two resolver seams:
#         server   src/net/dns/resolve_thread.c (forward) + reverse.c (PTR)
#         client   client/lib/net/resolve.c
#       Symbol rules — allowed ONLY in the listed files:
#         forward   getaddrinfo / getaddrinfo_a / gethostbyname(2)(_r) /
#                   gethostbyaddr(_r) / res_(n)query / res_(n)search
#         reverse   getnameinfo
#         nginx     ngx_inet_resolve_host — nowhere (blocking, config-time)
#         include   <netdb.h> — the three seam files only
#         OpenSSL   BIO_new_connect / BIO_set_conn_hostname — the OCSP
#                   transport only (its hostport is numeric, pinned upstream)
#         libcurl   CURLOPT_FOLLOWLOCATION — nowhere (a hidden per-hop resolve;
#                   redirects are walked by the pin helpers)
#         libcurl   CURLOPT_CONNECT_TO / DOH_URL / DNS_SERVERS / DNS_LOCAL_IP*
#                   / DNS_INTERFACE — nowhere: each is libcurl resolving on its
#                   own terms (a name, DoH, or c-ares) behind the seam
#         c-ares    ares_*( — nowhere; brix links no second resolver
#       Companion rules — a file that uses one thing must also carry another:
#         ngx_parse_url(  ⇒  no_resolve = 1   (the parse never resolves)
#         CURLOPT_PROXY   ⇒  the same pin call: libcurl resolves the PROXY
#                            host as well as the URL host
#         CURLOPT_URL     ⇒  a pin call (brix_dns_curl_pin /
#                            brix_dns_curl_perform_pinned / tpc_curl_secure /
#                            cvmfs_curl_perform_pinned) so libcurl gets
#                            CURLOPT_RESOLVE entries instead of resolving
#
# WHY:  A name that libc cannot resolve stalls the caller for the resolver
#       timeout: on the event loop a worker goes dark, at startup nginx refuses
#       to start, in a client a tool hangs.  Phase 116 routed every resolution
#       through brix_dns_resolve() (server) or brix_resolve() (client), the
#       hidden resolvers (libcurl, OpenSSL) through address pins, and reverse
#       lookups through the PTR cache.  There is deliberately NO waiver marker
#       and NO backlog: a new call site is a regression, full stop.
#
# HOW:  walk *.c / *.h, drop comment lines and trailing comments, apply the
#       symbol rules per line and the companion rules per file.  --root points
#       the scan at another tree (the guard's own negative tests use a
#       damaged tmp_path copy; the real tree is never edited by a test).
#
# USAGE:
#   tools/ci/check_dns_seam.py                 # exit 1 on any bypass
#   tools/ci/check_dns_seam.py --root <dir>    # scan another checkout

import argparse
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
# Every tree that holds non-test C.  tools/ is here for tools/pblock-fsck,
# a standalone consistency oracle with its own install target
# (tools/pblock-fsck/Makefile:14-15) -- shipped code, so the one-DNS-path
# guarantee covers it like any other.  contrib/ is here for the site
# checksum plugins (contrib/checksum-plugins/README.md): shared objects the
# worker dlopen()s, so a resolver there runs inside the server process.
# What is left outside is test C only (tests/, k8s-tests/, brixtest/),
# which uses libc deliberately.
SCAN_DIRS = ("src", "client", "shared", "tools", "contrib")

# Every suffix these trees compile.  C++ belongs here: client/apps/ceph
# compiles four .cpp sources into two shipped programs (client/Makefile
# :587-601) and installs a fifth as the pymigrate shim (:812-813), and a
# guard reading only .c/.h left all of them outside the one-DNS-path
# guarantee -- a backlog by file extension, which this phase does not allow.
SOURCE_SUFFIXES = (".c", ".h", ".cc", ".cpp", ".cxx", ".hh", ".hpp")

SERVER_FORWARD = "src/net/dns/resolve_thread.c"
SERVER_REVERSE = "src/net/dns/reverse.c"
CLIENT_SEAM = "client/lib/net/resolve.c"

# (label, regex, files the symbol may appear in)
SYMBOL_RULES = (
    ("libc forward resolver",
     re.compile(r"\b(getaddrinfo(_a)?|gethostbyname2?(_r)?|gethostbyaddr(_r)?"
                r"|res_n?(query|search))\s*\("),
     frozenset({SERVER_FORWARD, CLIENT_SEAM})),
    ("libc reverse resolver",
     re.compile(r"\bgetnameinfo\s*\("),
     frozenset({SERVER_REVERSE})),
    ("nginx blocking resolver",
     re.compile(r"\bngx_inet_resolve_host\s*\("),
     frozenset()),
    ("<netdb.h> include",
     re.compile(r"#\s*include\s*<netdb\.h>"),
     frozenset({SERVER_FORWARD, SERVER_REVERSE, CLIENT_SEAM})),
    ("OpenSSL connect BIO",
     re.compile(r"\bBIO_(new_connect|set_conn_hostname)\s*\("),
     frozenset({"src/auth/crypto/ocsp_transport.c"})),
    ("libcurl redirect follow",
     re.compile(r"\bCURLOPT_FOLLOWLOCATION\b"),
     frozenset()),
    ("libcurl alternate resolver",
     re.compile(r"\bCURLOPT_(CONNECT_TO|DOH_URL|DNS_SERVERS|DNS_LOCAL_IP4"
                r"|DNS_LOCAL_IP6|DNS_INTERFACE)\b"),
     frozenset()),
    ("c-ares resolver",
     re.compile(r"\bares_[a-z_]+\s*\("),
     frozenset()),
)

# (label, trigger regex, required regex, hint)
COMPANION_RULES = (
    ("ngx_parse_url without no_resolve",
     re.compile(r"\bngx_parse_url\s*\("),
     re.compile(r"\bno_resolve\s*=\s*1\b"),
     "set u.no_resolve = 1 and resolve through brix_dns_* at runtime"),
    ("CURLOPT_PROXY without an address pin",
     re.compile(r"\bCURLOPT_PROXY\b"),
     re.compile(r"\b(brix_dns_curl_pin|brix_dns_curl_perform_pinned"
                r"|tpc_curl_secure|cvmfs_curl_perform_pinned)\s*\("),
     "libcurl resolves the proxy host too: pin it with the same helper"),
    ("CURLOPT_URL without an address pin",
     re.compile(r"\bCURLOPT_URL\b"),
     re.compile(r"\b(brix_dns_curl_pin|brix_dns_curl_perform_pinned"
                r"|tpc_curl_secure|cvmfs_curl_perform_pinned)\s*\("),
     "pin the host with brix_dns_curl_pin()/cvmfs_curl_perform_pinned()"),
)

COMMENT_LINE_RE = re.compile(r"^\s*(\*|//|/\*)")
TRAILING_COMMENT_RE = re.compile(r"/\*.*?\*/|//.*$")


def _code_lines(path):
    """Yield (lineno, code) with comment lines and trailing comments removed."""
    for i, text in enumerate(path.read_text(errors="replace").splitlines(), 1):
        if COMMENT_LINE_RE.match(text):
            continue
        yield i, TRAILING_COMMENT_RE.sub("", text)


def _symbol_hits(rel, lines):
    for lineno, code in lines:
        for label, pattern, allowed in SYMBOL_RULES:
            if pattern.search(code) and rel not in allowed:
                yield f"{rel}:{lineno}: {label}: {code.strip()}"


def _companion_hits(rel, lines):
    body = "\n".join(code for _, code in lines)
    for label, trigger, required, hint in COMPANION_RULES:
        if trigger.search(body) and not required.search(body):
            yield f"{rel}: {label} ({hint})"


def _source_files(root):
    for sub in SCAN_DIRS:
        for path in sorted((root / sub).rglob("*")):
            if path.suffix in SOURCE_SUFFIXES and path.is_file():
                yield path


def scan(root):
    """Return (hits, files_scanned) for the tree at root."""
    hits, count = [], 0
    for path in _source_files(root):
        rel = path.relative_to(root).as_posix()
        lines = list(_code_lines(path))
        hits.extend(_symbol_hits(rel, lines))
        hits.extend(_companion_hits(rel, lines))
        count += 1
    return hits, count


def main(argv):
    ap = argparse.ArgumentParser(description="phase-116 one-DNS-path guard")
    ap.add_argument("--root", type=Path, default=ROOT)
    args = ap.parse_args(argv)
    hits, count = scan(args.root.resolve())
    if hits:
        print("check_dns_seam: name resolution outside the DNS seam "
              "(src/net/dns/, client/lib/net/resolve.c):", file=sys.stderr)
        for hit in hits:
            print(f"  {hit}", file=sys.stderr)
        print("  Route it through brix_dns_resolve()/brix_dns_resolve_sync() "
              "(server) or brix_resolve() (client); no waiver exists.",
              file=sys.stderr)
        return 1
    print(f"check_dns_seam: OK ({count} files scanned)")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
