"""Compile the outbound-target grammar and pin parser-policy edge cases."""

from __future__ import annotations

import os
from pathlib import Path
import shlex
import subprocess

import pytest


REPO_ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture(scope="module")
def net_target_probe(tmp_path_factory):
    """Build the real zero-copy parser against a minimal nginx type surface."""
    build = tmp_path_factory.mktemp("net-target-parser")
    include = build / "include"
    include.mkdir()
    (include / "ngx_http.h").write_text(_NGX_STUB)
    source = build / "probe.c"
    source.write_text(_PROBE)
    executable = build / "probe"
    compiler = shlex.split(os.environ.get("CC", "cc"))
    command = [
        *compiler,
        "-std=c11",
        "-Wall",
        "-Wextra",
        "-Werror",
        "-I" + str(include),
        "-I" + str(REPO_ROOT / "src"),
        str(source),
        str(REPO_ROOT / "src/core/compat/net_target_parse.c"),
        str(REPO_ROOT / "src/core/compat/net_target_policy.c"),
        "-o",
        str(executable),
    ]
    result = subprocess.run(command, capture_output=True, text=True, timeout=30)
    assert result.returncode == 0, result.stdout + result.stderr
    return executable


def _run(probe, mode, url, *policy):
    """Run one parser contract and return its bounded diagnostic output."""
    return subprocess.run(
        [str(probe), mode, url, *map(str, policy)],
        capture_output=True,
        text=True,
        timeout=5,
        check=False,
    )


@pytest.mark.parametrize(
    "url,expected",
    [
        ("https://Example.COM:8443/a?b#c", "https|Example.COM|8443|1|/a?b#c"),
        ("https://example.org?x=1", "https|example.org|0|0|?x=1"),
        ("https://example.org#part", "https|example.org|0|0|#part"),
        ("https://[2001:db8::1]:443/#part", "https|2001:db8::1|443|1|/#part"),
        ("HTTPS://example.org./", "HTTPS|example.org.|0|0|/"),
        ("https://127.0.0.1/", "https|127.0.0.1|0|0|/"),
    ],
)
def test_valid_targets_have_one_unambiguous_authority(net_target_probe, url, expected):
    """Accept normal HTTP targets and split query/fragment outside authority."""
    result = _run(net_target_probe, "parse", url)
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == expected


@pytest.mark.parametrize(
    "url",
    [
        "https://[2001:db8::1]@127.0.0.1/private",
        "https://user@example.org/private",
        "https://[2001:db8::1]evil/private",
        "https://[example.org]/private",
        "https://2001:db8::1/private",
        "https://example.org:/private",
        "https://example.org:0/private",
        "https://example.org:65536/private",
        "https://example.org:12x/private",
        "https://example..org/private",
        "https://-example.org/private",
        "https://example-.org/private",
        "https://exam%70le.org/private",
        "https://example.org\\@127.0.0.1/private",
        "https://example.org/unsafe path",
        "https://example.org/unsafe\tpath",
        "1https://example.org/private",
        "https://0177.0.0.1/private",
        "https://0x7f000001/private",
        "https://2130706433/private",
        "https://127.1/private",
        "https://127.0.0.1./private",
    ],
)
def test_ambiguous_or_malformed_targets_fail_before_resolution(net_target_probe, url):
    """Reject userinfo, bracket suffixes, bad ports and parser-smuggling bytes."""
    result = _run(net_target_probe, "reject", url)
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip(), "a rejection must retain an operator diagnostic"


@pytest.mark.parametrize(
    "url,require_https,allow_root,accepted",
    [
        ("HTTPS://example.org/", 1, 0, 1),
        ("http://example.org/", 0, 0, 1),
        ("http://example.org/", 1, 0, 0),
        ("root://example.org/data", 0, 1, 1),
        ("root://example.org/data", 0, 0, 0),
        ("root://example.org/data", 1, 1, 0),
        ("ftp://example.org/data", 0, 1, 0),
        ("httpsx://example.org/data", 0, 1, 0),
    ],
)
def test_scheme_policy_is_an_enforced_exact_match(
    net_target_probe, url, require_https, allow_root, accepted
):
    """Treat policy fields as gates, never as mere default-port hints."""
    result = _run(
        net_target_probe, "policy", url, require_https, allow_root, accepted
    )
    assert result.returncode == 0, result.stderr


@pytest.mark.parametrize(
    "url,require_https,allow_root,expected_port",
    [
        ("https://example.org/data", 1, 0, 9443),
        ("http://example.org/data", 0, 0, 80),
        ("root://example.org/data", 0, 1, 1194),
        ("https://example.org:444/data", 1, 0, 444),
    ],
)
def test_dns_pin_and_connection_share_one_effective_port(
    net_target_probe, url, require_https, allow_root, expected_port
):
    """Select an explicit or scheme-specific port once at the trust boundary."""
    result = _run(
        net_target_probe, "port", url, require_https, allow_root, expected_port
    )
    assert result.returncode == 0, result.stderr


@pytest.mark.parametrize("require_https,accepted", [(0, 1), (1, 0)])
def test_bare_native_target_cannot_bypass_https_policy(
    net_target_probe, require_https, accepted
):
    """Keep native bare-host checks compatible while fail-closing TLS policy."""
    result = _run(
        net_target_probe, "bare-policy", "example.org", require_https, 0, accepted
    )
    assert result.returncode == 0, result.stderr


@pytest.mark.parametrize(
    "initial,next_url,allow_cross_origin,accepted",
    [
        ("https://example.org/a", "https://example.org/b", 0, 1),
        ("https://example.org/a", "https://example.org:443/b", 0, 1),
        ("https://example.org/a", "http://example.org/b", 1, 0),
        ("https://example.org/a", "https://other.example/b", 0, 0),
        ("https://example.org/a", "https://other.example/b", 1, 1),
        ("http://example.org/a", "http://other.example/b", 0, 0),
    ],
)
def test_redirects_preserve_tls_and_authority_by_default(
    net_target_probe, initial, next_url, allow_cross_origin, accepted
):
    """Refuse downgrade and credential replay; cross-origin is explicit."""
    result = _run(
        net_target_probe,
        "redirect",
        initial,
        next_url,
        allow_cross_origin,
        accepted,
    )
    assert result.returncode == 0, result.stderr


_NGX_STUB = r"""
#pragma once
#include <stdint.h>
#include <stddef.h>
#include <string.h>
typedef unsigned char u_char;
typedef intptr_t ngx_int_t;
typedef uintptr_t ngx_uint_t;
typedef intptr_t ngx_flag_t;
typedef struct ngx_pool_s ngx_pool_t;
typedef struct { size_t len; u_char *data; } ngx_str_t;
#define NGX_OK 0
#define NGX_ERROR -1
#define ngx_memzero(buffer, size) memset((buffer), 0, (size))
#define ngx_memcpy(destination, source, size) memcpy((destination), (source), (size))
void *ngx_pnalloc(ngx_pool_t *pool, size_t size);
ngx_int_t ngx_strncasecmp(u_char *first, u_char *second, size_t length);
"""


_PROBE = r"""
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include "core/compat/net_target.h"

ngx_int_t ngx_strncasecmp(u_char *first, u_char *second, size_t length) {
    return (ngx_int_t) strncasecmp((char *) first, (char *) second, length);
}

static int parse_target(const char *text, brix_net_target_t *target,
                        char *error, size_t error_size) {
    ngx_str_t url = { strlen(text), (u_char *) text };
    return brix_net_target_parse(NULL, &url, target, error, error_size);
}

int main(int argc, char **argv) {
    brix_net_target_t target;
    brix_net_target_policy_t policy;
    char error[160] = "";
    int result;

    if (argc < 3) return 90;
    if (strcmp(argv[1], "bare-policy") == 0) {
        memset(&target, 0, sizeof(target));
        target.host.data = (u_char *) argv[2];
        target.host.len = strlen(argv[2]);
    } else {
        result = parse_target(argv[2], &target, error, sizeof(error));
        if (strcmp(argv[1], "reject") == 0) {
            if (result == NGX_ERROR && error[0] != '\0') {
                puts(error);
                return 0;
            }
            return 91;
        }
        if (result != NGX_OK) {
            fprintf(stderr, "%s\n", error);
            return 92;
        }
    }

    if (strcmp(argv[1], "redirect") == 0 && argc == 6) {
        brix_net_target_t next;

        result = parse_target(argv[3], &next, error, sizeof(error));
        if (result != NGX_OK) return 96;
        result = brix_net_target_check_redirect(
            &target, &next, atoi(argv[4]), error, sizeof(error));
        return (result == NGX_OK) == atoi(argv[5]) ? 0 : 97;
    }
    if (strcmp(argv[1], "parse") == 0) {
        printf("%.*s|%.*s|%u|%ld|%.*s\n",
               (int) target.scheme.len, target.scheme.data,
               (int) target.host.len, target.host.data,
               (unsigned) target.port, (long) target.has_port,
               (int) target.path.len, target.path.data);
        return 0;
    }

    if ((strcmp(argv[1], "policy") == 0
         || strcmp(argv[1], "bare-policy") == 0) && argc == 6) {
        memset(&policy, 0, sizeof(policy));
        policy.require_https = atoi(argv[3]);
        policy.allow_root_scheme = atoi(argv[4]);
        result = brix_net_target_check_scheme(&target, &policy,
                                              error, sizeof(error));
        return (result == NGX_OK) == atoi(argv[5]) ? 0 : 93;
    }
    if (strcmp(argv[1], "port") == 0 && argc == 6) {
        uint16_t port = 0;
        memset(&policy, 0, sizeof(policy));
        policy.require_https = atoi(argv[3]);
        policy.allow_root_scheme = atoi(argv[4]);
        policy.default_https_port = 9443;
        policy.default_root_port = 1194;
        result = brix_net_target_effective_port(&target, &policy, &port,
                                                error, sizeof(error));
        return result == NGX_OK && port == (uint16_t) atoi(argv[5]) ? 0 : 95;
    }
    return 94;
}
"""
