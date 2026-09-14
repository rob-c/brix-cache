"""Python ports for object-linked C regression shell runners — DNS shard.

Continuation of ``c_regression_units.py`` (loaded before ``part3``, whose
``RUNNERS`` table names these two functions).  The phase-116 units live here
because part3 had reached the 600-line cap; nothing else changed.
"""

from __future__ import annotations

from pathlib import Path
import os

from cmdscripts.compile_run import REPO_ROOT


DEFAULT_NGX_SRC = Path(os.environ.get(
    "NGX_SRC",
    "/tmp/nginx-1.28.3" if Path("/tmp/nginx-1.28.3/src/core/ngx_config.h").exists()
    else "/tmp/nginx-1.24.0",
))
TEST_C = REPO_ROOT / "tests" / "c"
SRC_DNS = REPO_ROOT / "src" / "net" / "dns"
CLIENT = REPO_ROOT / "client"


def dns_resolv_conf(base: Path, ngx_src: Path = DEFAULT_NGX_SRC) -> tuple[bool, str]:
    # resolv.conf parser (phase-116 W1.1): pure C over libc, no ngx runtime.
    # Keyword grammar (nameserver/search/domain/options), the glibc caps
    # (3 nameservers, 6 search suffixes, ndots/timeout/attempts clamps),
    # $LOCALDOMAIN / $RES_OPTIONS precedence, and the malformed-line and
    # missing-file behaviours that must never fail a server start.
    return _compile_and_run(
        base / "resolv_conf_unittest",
        [
            "-O",
            "-Wall",
            "-Wextra",
            "-Werror",
            "-I",
            str(SRC_DNS),
            "-I",
            str(REPO_ROOT / "src"),
            str(SRC_DNS / "resolv_conf_unittest.c"),
            str(SRC_DNS / "resolv_conf.c"),
        ],
    )


def client_resolve(base: Path, ngx_src: Path = DEFAULT_NGX_SRC) -> tuple[bool, str]:
    # The client's one DNS seam (phase-116): brix_resolve() over an interposed
    # getaddrinfo(), so the answer cache, the flag mapping and the never-cached
    # classes are checked with an exact libc call count and no resolver.  The
    # binary is also run a second time with XRDC_RESOLVE_CACHE_S=0 by
    # tests/test_phase116_client_resolve.py (cache-off arm).
    return _compile_and_run(
        base / "client_resolve_test",
        [
            "-O",
            "-Wall",
            "-Wextra",
            "-Werror",
            "-I",
            str(CLIENT / "lib"),
            str(TEST_C / "client_resolve_test.c"),
            str(CLIENT / "lib" / "net" / "resolve.c"),
            "-pthread",
        ],
    )


def _curl_pin_budget(base: Path, ngx_src: Path, default_ms: int | None
                     ) -> tuple[bool, str]:
    # The pinned transfer loop is time-bounded (phase-116 amendment 14).  The
    # unit compiles src/net/dns/curl_pin.c itself and stubs the five brix
    # symbols it calls, so it needs the nginx HEADERS but none of its objects
    # and no built binary.  -D_GNU_SOURCE because curl_pin.h includes
    # <curl/curl.h> before the nginx headers get to define it.
    name = "curl_pin_budget" + ("" if default_ms is None else f"_d{default_ms}")
    define = ([] if default_ms is None
              else [f"-DBRIX_DNS_CURL_TIMEOUT_MS_DEFAULT={default_ms}"])
    return _compile_and_run(
        base / name,
        [
            "-O",
            "-Wall",
            "-Wextra",
            "-Werror",
            "-D_GNU_SOURCE",
            *define,
            *_nginx_includes(ngx_src, http=True, stream=True),
            str(TEST_C / "curl_pin_budget_test.c"),
            str(SRC_DNS / "curl_pin.c"),
            "-lcurl",
            "-pthread",
        ],
    )


def dns_curl_pin_budget(base: Path, ngx_src: Path = DEFAULT_NGX_SRC
                        ) -> tuple[bool, str]:
    # As shipped: a black-holed endpoint ends the transfer, a redirect into one
    # spends the SAME budget rather than a second copy of it, and a prompt
    # answer is untouched.
    return _curl_pin_budget(base, ngx_src, None)


def dns_curl_pin_budget_default(base: Path, ngx_src: Path = DEFAULT_NGX_SRC
                                ) -> tuple[bool, str]:
    # The arm where the caller names no budget at all.  Built with a 400 ms
    # BRIX_DNS_CURL_TIMEOUT_MS_DEFAULT so the fallback can be proven in under a
    # second instead of the shipped minute; the shipped value is pinned by
    # tests/test_phase116_curl_pin_budget.py.
    return _curl_pin_budget(base, ngx_src, 400)
