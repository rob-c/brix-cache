"""Process-wide environment defaults the stock XRootD stack needs on this host.

``install()`` is called once by the pytest session (``tests/conftest.py``) and
by the fleet CLI (``cmdscripts.manage_test_servers``); every child — stock
``xrootd``/``cmsd`` members, ``xrdfs``/``xrdcp`` probes, the isolated pyxrootd
worker — inherits the result.  ``setdefault`` keeps an operator's own value.
"""
import os
import sys


#: Homebrew's MIT krb5 is keg-only: its .pc files are invisible to pkg-config
#: unless the keg's pkgconfig dir is on PKG_CONFIG_PATH.  Both the module's
#: configure and the client Makefile gate Kerberos on `pkg-config --exists
#: krb5`, so a harness-driven `make -C client` would otherwise silently build a
#: client with no krb5 protocol at all (Apple's Heimdal ships no .pc file).
_KRB5_PKGCONFIG_DIRS = ("/usr/local/opt/krb5/lib/pkgconfig",
                        "/opt/homebrew/opt/krb5/lib/pkgconfig")
_OPENSSL_PREFIXES = ("/usr/local/opt/openssl@3",
                     "/opt/homebrew/opt/openssl@3")
_HOMEBREW_PREFIXES = ("/usr/local", "/opt/homebrew")


def _installed_kegs() -> list[str]:
    return [d for d in _KRB5_PKGCONFIG_DIRS if os.path.isdir(d)]


def _path_entries(value: str) -> list[str]:
    return [p for p in value.split(os.pathsep) if p]


def _with_krb5_pkgconfig(current: str) -> str:
    """``current`` with every installed keg dir prepended once."""
    parts = _path_entries(current)
    missing = [d for d in _installed_kegs() if d not in parts]
    return os.pathsep.join(missing + parts)


def _prepend_existing(current: str, candidates: list[str]) -> str:
    parts = _path_entries(current)
    missing = [path for path in candidates
               if os.path.isdir(path) and path not in parts]
    return os.pathsep.join(missing + parts)


def install() -> None:
    if sys.platform == "darwin":
        pkgconfig = _with_krb5_pkgconfig(os.environ.get("PKG_CONFIG_PATH", ""))
        pkgconfig = _prepend_existing(
            pkgconfig,
            [os.path.join(prefix, "lib", "pkgconfig")
             for prefix in _OPENSSL_PREFIXES],
        )
        os.environ["PKG_CONFIG_PATH"] = pkgconfig
        os.environ["CPATH"] = _prepend_existing(
            os.environ.get("CPATH", ""),
            [os.path.join(prefix, "include")
             for prefix in (*_OPENSSL_PREFIXES, *_HOMEBREW_PREFIXES)],
        )
        os.environ["LIBRARY_PATH"] = _prepend_existing(
            os.environ.get("LIBRARY_PATH", ""),
            [os.path.join(prefix, "lib")
             for prefix in (*_OPENSSL_PREFIXES, *_HOMEBREW_PREFIXES)],
        )
        # libXrdUtils resolves the host's identity in a static initialiser
        # (XrdNetIdentity: reverse lookup of the primary interface address).
        # A LAN address without a PTR record costs the full 30 s resolver
        # timeout on macOS, once per process — every stock tool start, every
        # bindings import, every fleet member boot.  XRDNET_IDENTITY is
        # XRootD's own short-circuit; the fleet binds 127.0.0.1, so
        # "localhost" is also the name its cmsd members should advertise.
        os.environ.setdefault("XRDNET_IDENTITY", "localhost")  # net-literal-allow: the name this process ADVERTISES for itself, never dialled
