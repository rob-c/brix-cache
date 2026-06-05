# Test Data Lifecycle Audit

## Overview

This document audits every piece of test data in the `tests/` module — PKI certificates, tokens, dummy files, configurations, and server state — and determines what is already regenerated on each `pytest` run versus what persists across runs. It also identifies gaps in teardown completeness and proposes a "brutal tear down" script to clean everything after test execution.

**Goal:** Every test run starts with fresh data (PKI certs + tokens + dummy files + configs) and ends with a complete cleanup of all generated artifacts, leaving `/tmp/xrd-test/` empty or reset to defaults.

---

## Current Session Lifecycle Flow

```
pytest session start
    │
    ▼
conftest.py: pytest_sessionstart()
    │
    ├── shutil.rmtree(DATA_ROOT)           # wipe test data dir
    ├── shutil.rmtree(PKI_DIR)             # wipe PKI dir
    ├── generate test.txt + random.bin     # fresh dummy files each session
    ├── pki_helpers.blitz_test_pki()       # rebuild full PKI from scratch
    │
    ▼
tests/manage_test_servers.sh: start_all_dedicated (via start-all_dedicated)
    │
    ├── substitute_config()                # write fresh nginx configs via sed
    ├── create tokens dir + init JWKS      # signing authority if-not-exists
    ├── create upstream.jwt placeholder    # if-not-exists stub token
    ├── create dedicated server dirs       # cluster, proxy, cache, etc.
    ├── start nginx instances              # ~80 ports across roles
    ├── start ref xrootd                   # ~15 ports
    │
    ▼
pytest tests run...
    │
    └── individual test fixtures generate tokens per-test via TokenIssuer class
    │
    ▼
conftest.py: pytest_sessionfinish()
    │
    ├── manage_test_servers.sh stop-all  # kill nginx + ref servers
    │
    ▼
pytest session end
```

---

## What Is Already Regenerated Every Run (✅)

### PKI Full Stack — `tests/pki_helpers.py::blitz_test_pki()`

| Artifact | Tool | Details | Regenerated? |
|----------|------|---------|--------------|
| CA key (`ca.key`) | openssl genrsa 4096 | Private RSA-4096, mode 0400 | ✅ Yes |
| CA cert (`ca.pem`) | openssl req -x509 -sha256 -days 3650 | `/DC=test/DC=xrootd/CN=Test XRootD CA`, CA:TRUE | ✅ Yes |
| Server hostcert + hostkey | openssl genrsa 2048 → req/x509 | `/DC=test/DC=xrootd/CN=localhost` | ✅ Yes |
| User usercert + userkey | openssl genrsa 2048 → req/x509 | `/DC=test/DC=xrootd/CN=Test User/CN=12345` | ✅ Yes |
| Proxy certs (proxy_std.pem, proxy.pem, proxykey.pem) | `utils/make_proxy.py` CLI | RFC 3820 proxyCertInfo extension, ephemeral RSA-2048 proxy key | ✅ Yes |

**Invocation:** Called by `conftest.py::pytest_sessionstart()` before any servers start. PKI_DIR is wiped first (`shutil.rmtree(PKI_DIR)`), then rebuilt from scratch via `blitz_test_pki()`.

### Test Data Files — `tests/conftest.py::_setup_session()`

| Artifact | Details | Regenerated? |
|----------|---------|--------------|
| DATA_ROOT directory | Wiped via `shutil.rmtree(DATA_ROOT)` then recreated | ✅ Yes |
| test.txt | Fresh content written each session | ✅ Yes |
| random.bin | 200 bytes of fresh random data generated each session | ✅ Yes |

### Configuration Templates — `manage_test_servers.sh::substitute_config()`

| Artifact | Tool | Regenerated? |
|----------|------|--------------|
| All nginx.conf templates in tests/configs/ | sed substitution with port/dir variables | ✅ Yes (fresh per start) |

### Server Lifecycle — `manage_test_servers.sh`

| Artifact | Cleanup Action | Completeness? |
|----------|----------------|---------------|
| nginx instances (~80 ports) | PID file kill + port-based kill across ~80 ports | ✅ Yes |
| reference xrootd instances (~15 ports) | PID file kill + port-based kill across ~15 ports | ✅ Yes |

---

## What Is NOT Fully Regenerated Every Run (⚠️ Gaps)

### Token Signing Authority — `manage_test_servers.sh::start_all_dedicated()`

| Artifact | Current Behavior | Gap |
|----------|------------------|-----|
| TOKENS_DIR (`/tmp/xrd-test/tokens`) | Created if-not-exists each session | ⚠️ Directory created but contents may persist |
| signing_key.pem + jwks.json (jwks-refresh dir) | `make_token.py init` called only if-not-exists | ⚠️ JWKS signing key persists across sessions — not regenerated |
| upstream.jwt placeholder | Written as stub (`eyJhbGci...`) only if-not-exists | ⚠️ Stub token persists; tests may overwrite it but no guaranteed fresh generation |

**Impact:** Tests that use `TokenIssuer` class (imported from `utils/make_token.py`) generate tokens on-demand per-test using the persistent signing key. Token signatures are deterministic across runs (same issuer, same kid). If a test modifies the upstream.jwt file during its run, that modification persists to the next session.

**Fix needed:** Add explicit `make_token.py init --overwrite` flag in conftest or start_all_dedicated so JWKS is regenerated each session.

### Per-Test Token Generation — Individual Test Modules

| Module | Token Generation Pattern | Gap |
|--------|--------------------------|-----|
| `test_token_auth.py` | `TokenIssuer(TOKEN_DIR).generate()` per-test fixture | ✅ Fresh tokens per test (uses persistent JWKS) |
| `test_https_webdav_token_status_codes.py` | `_ISSUER = TokenIssuer(token_dir)` session-level | ⚠️ Issuer persists across tests within same session |
| `test_token_security.py` | `TokenIssuer(TOKEN_DIR).generate()` per-test + expired variants | ✅ Fresh tokens per test (uses persistent JWKS) |
| `test_macaroon_discharge.py` | Token generation via make_token.py gen commands | ⚠️ Tokens generated on-demand, not tracked for cleanup |
| `test_tpc_token_mode.py` | Token generation via make_token.py gen commands | ⚠️ Same pattern — on-demand, no teardown tracking |

**Impact:** No centralized registry of all tokens generated during a session. Individual test fixtures create tokens that may persist after the test completes within the same session.

### Dedicated Server Data Directories — Not Wiped Between Sessions

| Directory | Current Behavior | Gap |
|-----------|------------------|-----|
| `/tmp/xrd-test/dedicated/cluster/data` | Created if-not-exists in start_all_dedicated | ⚠️ Seed files persist across sessions |
| `/tmp/xrd-test/dedicated/proxy/data` | Created if-not-exists | ⚠️ Proxy test data persists |
| `/tmp/xrd-test/dedicated/upstream/data` | Created if-not-exists | ⚠️ Upstream test data persists |
| `/tmp/xrd-test/dedicated/cache/data` | Created if-not-exists | ⚠️ Cache test data persists |
| `/tmp/xrd-test/dedicated/wt/data` (write-through) | Created if-not-exists | ⚠️ WT test data persists |

**Impact:** Test-created files (PUT results, multipart uploads, etc.) in dedicated server directories persist between sessions. A test that creates a file in the data directory will see it on subsequent runs unless explicitly deleted.

---

## Current Teardown — `conftest.py::pytest_sessionfinish()` + `manage_test_servers.sh stop-all`

### What Is Cleaned Up (✅)

| Artifact | Cleanup Action | Completeness? |
|----------|----------------|---------------|
| nginx processes | PID file kill + port-based kill across ~80 ports | ✅ Yes |
| reference xrootd processes | PID file kill + port-based kill across ~15 ports | ✅ Yes |

### What Is NOT Cleaned Up After Teardown (⚠️ Gaps — "Brutal Tear Down" Needed)

| Artifact | Current Behavior | Gap |
|----------|------------------|-----|
| DATA_ROOT (`/tmp/xrd-test/data`) | Wiped at session START but NOT wiped at session END | ⚠️ Test-created files persist across sessions |
| PKI_DIR (`/tmp/xrd-test/pki`) | Wiped at session START but NOT wiped at session END | ⚠️ Certs, proxies, CRL persist |
| TOKENS_DIR (`/tmp/xrd-test/tokens`) | Created if-not-exists at start; NOT wiped at end | ⚠️ Generated tokens + JWKS persist |
| Dedicated server dirs (`/tmp/xrd-test/dedicated/*`) | Created if-not-exists at start; NOT wiped at end | ⚠️ All sub-data directories persist |
| PID files (nginx.pid, ref_pid_file, etc.) | Written each start; NOT removed at teardown | ⚠️ Stale PIDs persist |

---

## Proposed "Brutal Tear Down" Script

### `tests/brutal_teardown.sh` (New — Needs Implementation)

```bash
#!/usr/bin/env bash
set -euo pipefail

TEST_ROOT="${TEST_ROOT:-/tmp/xrd-test}"

echo "=== BRUTAL TEAR DOWN ==="
echo "Target: ${TEST_ROOT}"

# Kill all remaining servers (belt and suspenders)
echo "[1/4] Killing remaining servers..."
tests/manage_test_servers.sh force-stop all || true

# Remove all generated directories
echo "[2/4] Removing data directories..."
for dir in data pki tokens dedicated; do
    if [[ -d "${TEST_ROOT}/${dir}" ]]; then
        rm -rf "${TEST_ROOT}/${dir}/"
        echo "  Removed ${TEST_ROOT}/${dir}/"
    else
        echo "  ${TEST_ROOT}/${dir}/ already absent"
    fi
done

# Remove PID files scattered across TEST_ROOT
echo "[3/4] Removing stale PID files..."
find "${TEST_ROOT}" -name "*.pid" -type f -delete || true
echo "  Removed all .pid files"

# Recreate clean directory structure (optional — leave empty or pre-create)
echo ""
echo "=== CLEAN ==="
echo "Test root is now empty. Run 'tests/manage_test_servers.sh start-all' to rebuild."
```

### Integration Options

| Option | Description | Recommended? |
|--------|-------------|--------------|
| **A.** Add `brutal_teardown.sh` as standalone script + instructions in testing-runbook.md | Users run it manually after tests or via CI cleanup step | ✅ Yes — simplest, most explicit |
| **B.** Add pytest_unconfigure hook in conftest.py that calls stop-all then rm -rf /tmp/xrd-test/* | Automatic teardown at end of every session | ⚠️ Risky — may remove files tests want to inspect post-run |
| **C.** Hybrid: conftest adds soft cleanup (stop servers + wipe DATA_ROOT) + standalone brutal script for full reset | Best of both worlds | ✅ Yes — recommended approach |

**Recommended implementation:** Option C. Add `shutil.rmtree(DATA_ROOT)` in `conftest.py::pytest_sessionfinish()` for automatic data cleanup, and provide the standalone `brutal_teardown.sh` script for complete resets (PKI + tokens + dedicated dirs).

---

## What Needs to Be Done (Implementation Checklist)

### Priority 1 — Token Regeneration Fix

| Task | File | Details |
|------|------|---------|
| Add `make_token.py init --overwrite` in conftest or start_all_dedicated | `tests/conftest.py` or `tests/manage_test_servers.sh` | Ensure JWKS signing key is regenerated each session, not just if-not-exists |
| Force upstream.jwt regeneration at session start | `tests/manage_test_servers.sh::start_all_dedicated()` | Replace the "if-not-exists" stub with fresh generation via `make_token.py gen --scope storage.read:/` |

### Priority 2 — Teardown Data Cleanup

| Task | File | Details |
|------|------|---------|
| Add `brutal_teardown.sh` script | `tests/brutal_teardown.sh` (new) | Implement the full teardown script shown above |
| Add DATA_ROOT wipe in conftest::pytest_sessionfinish() | `tests/conftest.py` | Add `shutil.rmtree(DATA_ROOT)` after stop-all to prevent cross-session file persistence |

### Priority 3 — Dedicated Server Data Cleanup

| Task | File | Details |
|------|------|---------|
| Wipe dedicated server data dirs at session end | `tests/conftest.py::pytest_sessionfinish()` or `brutal_teardown.sh` | Add removal of `/tmp/xrd-test/dedicated/*/data/` subdirectories |

---

## File Inventory Summary

### PKI Generation Files

| File | Function | Role |
|------|----------|------|
| `tests/pki_helpers.py::blitz_test_pki()` | Full PKI regeneration | CA, server cert, user cert, proxy certs — called at session start after PKI wipe |
| `utils/make_proxy.py` CLI | Proxy cert generation (RFC 3820) | Called by blitz_test_pki for proxy_cert_std.pem and proxy_cert.pem |

### Token Generation Files

| File | Function | Role |
|------|----------|------|
| `utils/make_token.py::TokenIssuer` class | JWT token generation per-test | Used directly in test fixtures — generates tokens using persistent JWKS signing key |
| `manage_test_servers.sh::start_all_dedicated()` | Token init (if-not-exists) | Creates TOKENS_DIR + calls make_token.py init only if jwks-refresh dir is needed |

### Test Data Setup Files

| File | Function | Role |
|------|----------|------|
| `tests/conftest.py::pytest_sessionstart()` | Session lifecycle start | Wipes DATA_ROOT/PKI, generates test.txt/random.bin, calls blitz_test_pki, starts servers |
| `tests/conftest.py::pytest_sessionfinish()` | Session lifecycle end | Calls manage_test_servers.sh stop-all — kills processes but does not wipe data dirs |

### Existing Test Data Docs (for reference)

| File | Content |
|------|---------|
| `docs/09-developer-guide/testing-infrastructure.md` | Session lifecycle flow diagram, PKI setup details, per-test nginx instances, fixture patterns |
| `docs/06-authentication/test-pki-setup.md` | Automated and manual PKI generation guide — exact openssl commands and Python proxy steps |

### New Document (this file)

| File | Content |
|------|---------|
| `docs/09-developer-guide/test-data-lifecycle.md` | **This document** — audit of all test data regeneration + teardown gaps + brutal tear down proposal |

---

## Verification Notes

- PKI regeneration confirmed: conftest.py calls shutil.rmtree(PKI_DIR) then pki_helpers.blitz_test_pki() at session start.
- Data regeneration confirmed: conftest.py wipes DATA_ROOT and generates test.txt + random.bin each session.
- Token JWKS not fully regenerated: manage_test_servers.sh creates upstream.jwt only if-not-exists; make_token.py init called only when needed but does not overwrite existing keys.
- Teardown stops servers but not data: conftest.py::pytest_sessionfinish() calls stop-all which kills processes on ports + PID files, but no shutil.rmtree or rm -rf of data directories in teardown.

---

*Last updated: 2026-05-27 — Initial audit of test data lifecycle.*
