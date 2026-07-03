"""
endpoints — the client-conformance server matrix.

WHAT
    Defines the set of servers a client test can target and, for each, the
    *auth environment* a client needs to talk to it.  Holding the server
    constant and swapping only the client binary makes any divergence provably
    client-side.

WHY
    Client tools authenticate the same way regardless of which endpoint they
    hit, but the *credentials* differ per endpoint (none / X509 proxy / proxy+TLS
    / bearer token).  Centralizing this here keeps every case table free of auth
    plumbing — a case declares which endpoints it applies to and nothing more.

HOW
    ``ENDPOINTS`` is the ordered list.  ``Endpoint.auth_env()`` returns the env
    overlay for that endpoint; ``Endpoint.url()`` builds the ``root://host:port``
    authority.  ``healthy()`` probes the endpoint with the stock client so a
    fixture can SKIP (never fail) when a server or its credentials are down —
    exactly the kind of transient seen with short-TTL tokens.
"""

import os
import shutil
import subprocess

from settings import (
    CA_DIR,
    HOST,
    NGINX_ANON_PORT,
    NGINX_GSI_PORT,
    NGINX_GSI_TLS_PORT,
    NGINX_TOKEN_PORT,
    PROXY_STD,
    REF_BRIX_PORT,
    TOKENS_DIR,
    url_host,
)

# The bearer token the token tier is provisioned with (see test_native_*).
TOKEN_FILE = os.path.join(TOKENS_DIR, "upstream.jwt")

# Every auth-bearing env var we must SCRUB before injecting a known-clean set,
# so a client can never silently pick up an ambient credential (e.g. our xrdcp
# auto-discovering /tmp/x509up_u<uid> and emitting an EXPIRED-proxy warning).
SCRUB_VARS = (
    "X509_USER_PROXY",
    "X509_USER_CERT",
    "X509_USER_KEY",
    "X509_CERT_DIR",
    "X509_CERT_FILE",
    "BEARER_TOKEN",
    "BEARER_TOKEN_FILE",
    "XDG_RUNTIME_DIR",
    "XrdSecPROTOCOL",
    "XrdSecGSIDELEGPROXY",
)


class Endpoint:
    """One target server plus the credentials a client uses to reach it."""

    def __init__(self, key, host, port, *, caps=(), auth=None, scheme="root"):
        self.key = key                  # short label used in test ids
        self.host = host
        self.port = port
        self.caps = frozenset(caps)     # {"proxy","tls","token"} — what it needs
        self._auth = auth or {}         # extra env overlay
        self.scheme = scheme

    # -- url ----------------------------------------------------------------
    def url(self, path=""):
        """``root://host:port`` (+ ``//path`` when a path is given)."""
        base = "%s://%s:%d" % (self.scheme, url_host(self.host), self.port)
        if not path:
            return base
        return "%s//%s" % (base, path.lstrip("/"))

    # -- auth env -----------------------------------------------------------
    def base_env(self):
        """A copy of the process env with every auth var scrubbed out."""
        env = dict(os.environ)
        for var in SCRUB_VARS:
            env.pop(var, None)
        return env

    def auth_env(self):
        """Full env to run a client against THIS endpoint (scrubbed + overlay)."""
        env = self.base_env()
        env.update(self._auth)
        return env

    # -- health -------------------------------------------------------------
    def healthy(self, stock_xrdfs, probe="/", timeout=15):
        """True when the stock client can reach the endpoint with its creds.

        Used by fixtures to SKIP cleanly when a server/credential is transiently
        down — never to fail a client-parity test for an infra reason.
        """
        if not stock_xrdfs:
            return False
        try:
            proc = subprocess.run(
                [stock_xrdfs, self.url(), "stat", probe],
                env=self.auth_env(),
                capture_output=True, text=True, timeout=timeout,
            )
        except (OSError, subprocess.TimeoutExpired):
            return False
        # stat of "/" should resolve (rc 0) on a healthy export; some servers
        # forbid stat of the bare root but answer "ls", so accept either signal.
        if proc.returncode == 0:
            return True
        try:
            ls = subprocess.run(
                [stock_xrdfs, self.url(), "ls", "/"],
                env=self.auth_env(),
                capture_output=True, text=True, timeout=timeout,
            )
            return ls.returncode == 0
        except (OSError, subprocess.TimeoutExpired):
            return False

    def __repr__(self):
        return "<Endpoint %s %s:%d caps=%s>" % (
            self.key, self.host, self.port, ",".join(sorted(self.caps)) or "-")


# --------------------------------------------------------------------------- #
# The matrix.  Auth overlays mirror the conventions used across the existing   #
# client tests (X509_USER_PROXY/X509_CERT_DIR for GSI, BEARER_TOKEN_FILE for   #
# the token tier).                                                             #
# --------------------------------------------------------------------------- #
_GSI_ENV = {"X509_USER_PROXY": PROXY_STD, "X509_CERT_DIR": CA_DIR}
_TOKEN_ENV = {"BEARER_TOKEN_FILE": TOKEN_FILE}

ANON = Endpoint("anon", HOST, NGINX_ANON_PORT)
GSI = Endpoint("gsi", HOST, NGINX_GSI_PORT, caps=("proxy",), auth=_GSI_ENV)
TLS = Endpoint("tls", HOST, NGINX_GSI_TLS_PORT, caps=("proxy", "tls"), auth=_GSI_ENV)
TOKEN = Endpoint("token", HOST, NGINX_TOKEN_PORT, caps=("token",), auth=_TOKEN_ENV)
REF = Endpoint("ref", HOST, REF_BRIX_PORT)

ENDPOINTS = [ANON, GSI, TLS, TOKEN, REF]
BY_KEY = {e.key: e for e in ENDPOINTS}

# Convenient endpoint-set labels for case tables.
ALL_KEYS = frozenset(BY_KEY)
ANON_LIKE = frozenset({"anon", "ref"})       # no auth required
AUTH_KEYS = frozenset({"gsi", "tls", "token"})
NGINX_KEYS = frozenset({"anon", "gsi", "tls", "token"})
WRITABLE = frozenset({"anon", "gsi", "tls", "token", "ref"})


def select(keys):
    """Resolve a set/iterable of endpoint keys to Endpoint objects (in order)."""
    keys = set(keys)
    return [e for e in ENDPOINTS if e.key in keys]


def stock_xrdfs():
    """Path to the stock xrdfs, or None."""
    return shutil.which("xrdfs")
