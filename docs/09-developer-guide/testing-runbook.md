# Testing guide

How to run, understand, and extend the BriX-Cache test suite — from environment bootstrap through credential generation (GSI proxy, VOMS proxy, bearer token) through per-test nginx instance management and writing new tests.

For the manual step-by-step PKI walkthrough (CA, proxy, VOMS from scratch with `openssl` commands), see [test-pki.md](../06-authentication/test-pki-setup.md). For token details, see [test-tokens.md](../06-authentication/test-token-generation.md). For the PKI trust model and wire formats, see [pki.md](../06-authentication/pki-config.md).

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
- **Traversal attempts**: Trying to escape `brix_export` via `..` or symlinks.
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

# 3. Run the full suite (persistent session setup is automatic)
cd /path/to/nginx-xrootd
pytest tests/ -v
```

The `pytest` session automatically manages the test infrastructure: it generates PKI, launches all required dedicated nginx and xrootd instances at startup, and performs a centralized cleanup only after the final test completes. Manual server setup is no longer required and should be avoided to prevent port conflicts and race conditions.


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
│   └── brix_access*.log   per-listener access logs
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

- [Infrastructure](testing-infrastructure.md) — session lifecycle, PKI generation, token infrastructure, per-test nginx fixtures, port table, test categories
- [Writing tests and debugging](writing-tests.md) — new test guide, environment variables, debugging failures, troubleshooting, infrastructure files
- [Test PKI walkthrough](../06-authentication/test-pki-setup.md) — manual CA, host cert, user cert, proxy, VOMS, CRL setup with openssl
- [Test tokens](../06-authentication/test-token-generation.md) — JWT signing authority, WLCG token generation, negative test tokens

---

## XrdHttp/davs:// Conformance Tests

Starting in **May 2026**, the suite includes **XrdHttp conformance tests** that verify BriX-Cache's WebDAV HTTPS interface operates identically to the official xrootd daemon running the `XrdHttp` module. These tests compare operation outcomes byte-for-byte or by HTTP status code equivalence.

### Test Files

| File | Scope | Key Tests |
|------|-------|-----------|
| `tests/test_xrdhttp_webdav.py` | WebDAV operations over HTTPS vs XrdHttp | OPTIONS, HEAD, GET (with Range), PUT, MKCOL, DELETE, PROPFIND, non-existent path errors |
| `tests/test_xrdhttp_tpc.py` | HTTP-TPC transfer protocols | TPC pull (Source header), TPC push (Credential header), marker streaming, SSRF policy enforcement |
| `tests/test_xrdhttp_auth.py` | Authentication consistency over HTTPS | GSI proxy cert auth, bearer token auth, dual-auth cache, missing credential handling |

### How They Work

```
                    +------------------+
  davs://:8443      |  nginx-xrootd    |   davs://:11113
  ────────────────> │  (WebDAV module) | <─────────────────
                    │                  │     XrdHttp
  xrdcp --allow-http│                  │     module
  aws s3 cp         +------------------+
```

Both endpoints serve `/tmp/xrd-test/data` — the tests verify **semantic equivalence**: same HTTP status codes, identical response bodies (byte-for-byte or MD5-verified), and agreeing on error outcomes.

### Running XrdHttp Tests

```bash
# Start both nginx-xrootd AND reference XrdHttp server
tests/manage_test_servers.sh start all

# Run just the new XrdHttp tests
pytest tests/test_xrdhttp_*.py -v

# Cross-compatibility: run against BOTH backends (via env var)
TEST_CROSS_BACKEND=nginx pytest tests/test_xrdhttp_webdav.py -v
TEST_CROSS_BACKEND=xrootd pytest tests/test_xrdhttp_webdav.py -v

# Full cross-compatible suite (includes XrdHttp tests now)
tests/run_cross_compatible_tests.sh
```

### Prerequisites

The reference xrootd daemon must have the `XrdHttp` module compiled and enabled. The port **11113** is reserved for this purpose by default (`TEST_XRDHTTP_HTTPS_PORT`). If your site uses a different port, set the environment variable:

```bash
export TEST_XRDHTTP_HTTPS_PORT=9443
pytest tests/test_xrdhttp_webdav.py -v
```

---
