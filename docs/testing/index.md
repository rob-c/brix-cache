# Testing guide

This document explains how to run, understand, and extend the nginx-xrootd test suite. It covers the full lifecycle: how the test environment is bootstrapped, how each credential type (GSI proxy, VOMS proxy, bearer token) is generated, how per-test nginx instances are managed, and how to write new tests.

For the manual step-by-step PKI walkthrough (CA, proxy, VOMS from scratch with `openssl` commands), see [test-pki.md](test-pki.md). For token details, see [test-tokens.md](test-tokens.md). For the PKI trust model and wire formats, see [pki.md](pki.md).

---

## Test Philosophy and Requirements

To maintain a high level of reliability and security in `nginx-xrootd`, all tests must adhere to these three core principles:

### 1. Determinism
ALL tests must be deterministic. A test should produce exactly one predictable outcome every time it is run against a given server state. Flaky tests that rely on race conditions, wall-clock timing without sufficient buffers, or non-deterministic external state are not permitted.

### 2. Full Integration Coverage
New features must be accompanied by tests that cover their full integration with the rest of the module. Unit tests for isolated helpers are encouraged, but the primary validation must happen via end-to-end integration tests that exercise the actual protocol handlers (native XRootD, WebDAV, S3).

### 3. Liberal Security Policy
We apply a **liberal security policy** to testing. Any modification that touches:
- Authentication or Authorization (GSI, JWT, VOMS, S3 SigV4)
- TLS or transport encryption
- Path resolution and confinement (root resolution, symlink checks)
- Data-exposing logic (read/write handlers)

is considered **security-sensitive**. These changes require mandatory negative tests, including:
- **Traversal attempts**: Trying to escape `xrootd_root` via `..` or symlinks.
- **Missing/Invalid Auth**: Verifying that requests fail without credentials or with expired/revoked tokens.
- **Wrong Scopes**: Verifying that tokens with `storage.read` cannot perform `storage.write`.
- **Malformed Input**: Verifying that truncated or garbage protocol frames do not cause worker crashes or memory leaks.

---

## Quick start

```bash
# 1. Build nginx with the module
cd /tmp/nginx-1.28.3
./configure --add-module=/path/to/nginx-xrootd ...
make -j$(nproc)

# 2. Install Python test dependencies
pip install pytest xrootd pytest-timeout cryptography requests urllib3

# 3. Run the full suite (session setup is automatic)
cd /path/to/nginx-xrootd
pytest tests/ -v

# 4. Run a specific file
pytest tests/test_xrootd.py -v

# 5. Run a specific test
pytest tests/test_conformance.py::test_stat -v
```

The first `pytest` run generates the PKI from scratch, starts all test servers, and tears them down when the session ends. No manual setup is required.

---

## Test directory layout

Everything lives under `TEST_ROOT` (default `/tmp/xrd-test`, overridden by the `TEST_ROOT` environment variable):

```
/tmp/xrd-test/
├── conf/                    main nginx config (from tests/configs/nginx_shared.conf)
├── data/                    test files served by all servers
│   ├── test.txt             5-byte ASCII seed file
│   ├── random.bin           5 MiB random data (re-generated each session)
│   └── large200.bin         200 MiB random data (seeded, MD5 exported as LARGE_FILE_MD5)
├── logs/                    nginx and xrootd log files
│   ├── nginx.pid            main nginx instance PID
│   ├── error.log            main nginx error log
│   └── xrootd_access*.log   per-listener access logs
├── pki/                     test PKI (auto-generated each session)
│   ├── ca/
│   │   ├── ca.pem           CA certificate
│   │   ├── ca.key           CA private key (mode 0400)
│   │   ├── <hash>.0         subject-hash symlink → ca.pem (new OpenSSL format)
│   │   ├── <oldhash>.0      subject-hash symlink → ca.pem (old OpenSSL format)
│   │   ├── <hash>.signing_policy
│   │   └── <oldhash>.signing_policy
│   ├── server/
│   │   ├── hostcert.pem     server TLS certificate (signed by CA)
│   │   └── hostkey.pem      server private key (mode 0400)
│   ├── user/
│   │   ├── usercert.pem     user end-entity certificate (signed by CA)
│   │   ├── userkey.pem      user private key (mode 0400)
│   │   ├── proxy_std.pem    plain GSI proxy (cert + key + chain)
│   │   ├── proxy_cms.pem    VOMS proxy for the /cms VO
│   │   └── proxy_atlas.pem  VOMS proxy for the /atlas VO
│   ├── voms/
│   │   ├── vomscert.pem     VOMS signing certificate (signed by CA)
│   │   └── vomskey.pem      VOMS signing key (mode 0400)
│   └── vomsdir/
│       ├── cms/
│       │   └── voms.test.local.lsc
│       └── atlas/
│           └── voms.test.local.lsc
├── tokens/
│   ├── signing_key.pem      JWT signing key (RSA-2048, mode 0400)
│   └── jwks.json            matching public key in JWKS format (loaded by nginx)
├── tmp/                     scratch space for test artifacts
└── instances/               per-test nginx instances (auto-cleaned after each test)
    └── nginx-<uuid>/
        ├── conf/nginx.conf
        ├── logs/
        └── tmp/
```

---

## Testing sub-pages

- [Infrastructure](infrastructure.md) — session lifecycle, PKI generation, token infrastructure, per-test nginx fixtures, port table, test categories
- [Writing tests and debugging](writing-tests.md) — new test guide, environment variables, debugging failures, troubleshooting, infrastructure files
- [Test PKI walkthrough](../test-pki.md) — manual CA, host cert, user cert, proxy, VOMS, CRL setup with openssl
- [Test tokens](../test-tokens.md) — JWT signing authority, WLCG token generation, negative test tokens

---
