"""Real OpenSSL verification through the standalone client's actual trust body."""

from pathlib import Path
import os
import re
import subprocess

import pytest

from cmdscripts.compile_run import openssl_compile_args


def _body(source, name):
    match = re.search(r"(?:static )?(?:int|const char \*)\n" + name
                      + r"\([^{}]+\n\{.*?\n\}", source, re.S)
    assert match, name
    return match[0]


def _run(arguments, **kwargs):
    return subprocess.run(arguments, capture_output=True, text=True, check=True,
                          timeout=30, **kwargs)


@pytest.fixture(scope="module")
def trust_driver(tmp_path_factory):
    root = Path(__file__).resolve().parents[1]
    directory = tmp_path_factory.mktemp("standalone-tls-trust")
    program = directory / "trust.c"
    resolve = (root / "client/lib/net/conn.c").read_text()
    tls = (root / "client/lib/net/tls.c").read_text()
    program.write_text(_PREAMBLE + _body(resolve, "brix_resolve_ca_dir")
                       + _body(tls, "tls_prepare_ctx") + _MAIN)
    binary = directory / "trust"
    _run(["cc", "-std=c11", "-Wall", "-Wextra", "-Werror",
          *openssl_compile_args([str(program), "-lssl", "-lcrypto"]),
          "-o", str(binary)])
    trusted = directory / "trusted"
    trusted.mkdir()
    certificate = trusted / "ca.pem"
    _run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
          "-subj", "/CN=BriXStandaloneTrust", "-days", "1",
          "-keyout", str(directory / "key.pem"), "-out", str(certificate)])
    digest = _run(["openssl", "x509", "-in", str(certificate),
                   "-noout", "-subject_hash"]).stdout.strip()
    (trusted / f"{digest}.0").symlink_to("ca.pem")
    empty = directory / "empty"
    empty.mkdir()
    return binary, certificate, trusted, empty


@pytest.mark.parametrize("explicit,environment,expected,identity", [
    ("-", "trusted", 1, "-"),
    ("trusted", "empty", 1, "-"),
    ("empty", "trusted", 0, "-"),
    ("-", "empty", 0, "-"),
    ("-", "trusted", -1, "missing-client.pem"),
], ids=["grid-env", "explicit-overrides-env", "no-trust-fallback",
        "untrusted-refused", "broken-identity-refused"])
def test_standalone_tls_trust_is_selected_and_verified(trust_driver, explicit,
                                                      environment, expected, identity):
    binary, certificate, trusted, empty = trust_driver
    paths = {"trusted": trusted, "empty": empty, "-": "-"}
    _run([str(binary), str(paths[explicit]), str(certificate), str(expected), identity],
         env={**os.environ, "X509_CERT_DIR": str(paths[environment])})


_PREAMBLE = r'''
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <openssl/ssl.h>
#include <openssl/pem.h>
#define XRDC_GRID_CA_DIR "/etc/grid-security/certificates"
#define XRDC_EAUTH 53
typedef struct { int error; } brix_status;
static void brix_tls_err(brix_status *status, int code, const char *message) {
    assert(message != NULL);
    status->error = code;
}
'''

_MAIN = r'''
int main(int argc, char **argv) {
    assert(argc == 5);
    brix_status status = {0};
    SSL_CTX *context = SSL_CTX_new(TLS_client_method());
    assert(context != NULL);
    const char *explicit = strcmp(argv[1], "-") == 0 ? NULL : argv[1];
    const char *identity = strcmp(argv[4], "-") == 0 ? NULL : argv[4];
    int expected = atoi(argv[3]);
    int result = tls_prepare_ctx(context, 1, explicit, identity, &status);
    assert(SSL_CTX_get_verify_mode(context) == SSL_VERIFY_PEER || expected == -1);
    if (expected == -1) {
        assert(result == -1 && status.error == XRDC_EAUTH);
        SSL_CTX_free(context);
        return 0;
    }
    assert(result == 0);
    FILE *input = fopen(argv[2], "r");
    assert(input != NULL);
    X509 *certificate = PEM_read_X509(input, NULL, NULL, NULL);
    fclose(input);
    assert(certificate != NULL);
    X509_STORE_CTX *chain = X509_STORE_CTX_new();
    assert(chain != NULL);
    assert(X509_STORE_CTX_init(chain, SSL_CTX_get_cert_store(context), certificate, NULL) == 1);
    assert(X509_verify_cert(chain) == expected);
    X509_STORE_CTX_free(chain);
    X509_free(certificate);
    SSL_CTX_free(context);
    return 0;
}
'''
