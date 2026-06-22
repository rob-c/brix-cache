# Dedicated Server Instance Recommendations [2026-05-24]

## Current State

All dedicated instances are managed by `manage_test_servers.sh start-all` at session startup. The test infrastructure now utilizes a persistent session-level lifecycle, ensuring all required instances are launched once and available for the duration of the test run.

### Permanent shared instance (`nginx_shared.conf`) — always running

| Port | Protocol | Auth | Purpose |
|---|---|---|---|
| 11094 | XRootD stream | anonymous | Default stream access |
| 11095 | XRootD stream | GSI (optional_no_ca) | GSI authentication |
| 11096 | XRootD stream | GSI+TLS (ssl) | TLS-encrypted GSI |
| 11097 | XRootD stream | token (bearer) | JWT bearer auth |
| 8443 | WebDAV HTTP | optional cert + token | `davs://` with either GSI cert or Bearer token |
| 8444 | WebDAV HTTP | required GSI cert | `davs://` strict GSI-only |
| 8080 | WebDAV HTTP (proxy) | proxy to dav-backend | HTTP WebDAV proxying |
| 9001 | S3 REST | anonymous | S3 without SigV4 auth |
| 9100 | Prometheus metrics | none | `/metrics` endpoint |

### Dedicated instance instances (Started via `manage_test_servers.sh start-all`)

| Port | Config | Purpose |
|---|---|---|
| 11103 | `vo_acl.conf` | VO ACL enforcement (`cms`, `atlas`) with GSI auth |
| 11116 | `nginx_krb5.conf` | XRootD stream Kerberos 5 (`xrootd_auth krb5`). **Conditional** — `start_krb5_tier` starts it only when the MIT KDC tooling (`krb5-server`) is installed *and* the nginx binary is linked against libkrb5; otherwise skipped cleanly. The realm/keytab/client-ccache are provisioned under `TEST_ROOT/krb5` by `kdc_helpers.py` (throwaway KDC on 11117). Drives `tests/test_krb5_auth.py`, gated by the `requires_krb5` fixture. |
| 11211 | `nginx_ha_instance1.conf` | HA Cluster Nginx 1 |
| 11212 | `nginx_ha_instance2.conf` | HA Cluster Nginx 2 |
...

## Gap Analysis: Config Templates that Exist but are NOT Permanently Started

### 1. Manager mode — **HIGH priority**

**Config:** `tests/configs/nginx_manager.conf`
**What it does:** Two nginx instances acting as manager + worker nodes in a cluster. Manager sends heartbeat (`/manager/heartbeat`) and redirects clients to workers via `/manager/locate`. Workers serve actual data behind the manager's proxy.
**Why dedicated:** Multiple tests exercise cluster redirect logic, heartbeat monitoring, and locate responses. On-demand start/stop is fragile — tests need stable reference ports for cross-instance communication (manager→worker).
**Recommended port:** `11120`

### 2. Read-only mode — **MEDIUM priority**

**Config:** `tests/configs/nginx_readonly.conf`
**What it does:** XRootD stream with `xrootd_stream_allow_write off`. All write ops (write, pgwrite, sync, mkdir, rm, rename) return kXR_NotAuthorized. Read/open/stat/dirlist/locate work normally.
**Why dedicated:** Tests need a stable read-only server to verify write denial across all write opcodes. The shared instance allows writes on 11094–11097, so read-only behavior can't be tested there without toggling config mid-test.
**Recommended port:** `11121`

### 3. CRL reload — **MEDIUM priority**

**Config:** `tests/configs/nginx_crl.conf`
**What it does:** GSI TLS with explicit CRL file (`xrootd_stream_crl_file`). Tests the CRL reload mechanism — cert revoked in CRL should be rejected, new CRL added should re-accept. Requires server restart between reload cycles.
**Why dedicated:** CRL reload requires stopping/starting the nginx instance to load a new CRL file. Can't do this on the shared instance without disrupting other ports. Needs stable port across restart cycles.
**Recommended port:** `11122`

### 4. Root TPC — **HIGH priority**

**Config:** `tests/configs/nginx_root_tpc.conf`
**What it does:** XRootD stream with `xrootd_stream_allow_write on` and root directory set to a writable temp dir. Tests native TPC (`kXR_locate2`) transfers from the root directory — source and destination are both xrootd servers, transfer via shared memory key registry (`src/tpc/key_registry.c`).
**Why dedicated:** Native TPC requires two stable server ports (source + dest) communicating via SHM. Tests need consistent ports across multiple TPC scenarios (same-server, cross-server, partial failure). The shared instance's root is `/tmp/xrd-test/data` which may not be writable for all tests.
**Recommended ports:** `11123` (source), `11124` (dest)

### 5. WebDAV TPC — **HIGH priority**

**Config:** `tests/configs/nginx_webdav_tpc.conf`
**What it does:** Six server blocks covering WebDAV HTTP-TPC credential passing: source required auth, source open auth, dest via CA file, dest via CA directory, dest without service cert, dest with TPC disabled, dest read-only. Each tests different TPC credential propagation paths through curl COPY requests.
**Why dedicated:** 6 server blocks = 6 ports. Tests need all of them running simultaneously for multi-hop TPC scenarios. Can't fit on shared instance (already at max ports). Requires stable HTTPS+GSI across all blocks.
**Recommended ports:** `11125`–`11131`

### 6. Auth cache — **LOW priority**

**Config:** not yet created (needs to be written)
**What it does:** WebDAV with token/GSI auth caching — cached validation results for repeated requests to avoid re-validating tokens/certs on every request.
**Why dedicated:** Tests measure cache hit/miss rates and stale entry behavior. Needs stable port across cache lifecycle tests.
**Recommended port:** `11132` (when config is written)

## Port Allocation Summary

| Config | Recommended Ports | Priority | Notes |
|---|---|---|---|
| manager mode | 11120 | HIGH | 2 nginx instances on same port (manager+worker) |
| read-only | 11121 | MEDIUM | Single stream port |
| CRL reload | 11122 | MEDIUM | Single GSI+TLS port, needs restart cycles |
| root TPC | 11123–11124 | HIGH | Source + dest pair |
| WebDAV TPC | 11125–11131 | HIGH | 6 server blocks (7 ports) |
| auth cache | 11132 | LOW | Pending config creation |

**Total new ports needed:** 14 ports in the `11120–11132` range.
**Existing allocated range:** `11098–11113` (conformance) + `11103` (vo_acl already started).

## Implementation Plan

### Step 1: Add to `nginx_shared.conf`

Append server blocks for the stable-on-demand configs. Unlike vo_acl/manager which use `manage_test_servers.sh`, these should be permanent additions to the shared config so they're always available.

**Changes:**
- Append manager mode block (port 11120) — two location blocks on same port acting as manager+worker
- Append read-only stream block (port 11121)
- Append CRL reload GSI+TLS block (port 11122)
- Append root TPC source + dest blocks (ports 11123, 11124)

### Step 2: Create standalone instance for WebDAV TPC

WebDAV TPC has 6 server blocks and is too large to append to the shared config. Create a new `nginx_webdav_tpc_shared.conf` in `tests/configs/` and start it via `manage_test_servers.sh`.

**Changes:**
- Copy `nginx_webdav_tpc.conf` template → rename to `nginx_webdav_tpc_shared.conf`
- Replace `{SOURCE_REQUIRED_PORT}` etc. with concrete ports (11125–11131)
- Add entry in `manage_test_servers.sh` for `start-webdav-tpc-shared`

### Step 3: Create auth_cache config (future)

When auth caching is implemented, create `nginx_auth_cache.conf` and add port 11132.

## Commands to Start New Instances

```bash
# After adding to nginx_shared.conf:
./configure --with-stream --with-http_ssl_module --with-threads --add-module=$REPO && make -j$(nproc)

# Restart shared instance with new ports
tests/manage_test_servers.sh restart-shared

# WebDAV TPC standalone (if created as separate config):
tests/manage_test_servers.sh start-webdav-tpc-shared

# Verify all ports listening:
ss -tlnp | grep -E '(1109[4-7]|844[34]|8080|9001|9100|1112[0-4]|11125-11131)'
```

## Verification Tests (after starting)

Each new port should pass a quick smoke test:

```bash
# Manager mode — heartbeat check
curl -s http://localhost:11120/manager/heartbeat | jq .

# Read-only — write denied
xrdcp root://localhost:11121//dummy /tmp/out 2>&1 | grep "NotAuthorized"

# CRL reload — cert accepted (before revocation)
curl -sk https://localhost:11122/ --cert tests/certs/client.pem --key tests/certs/client.key

# Root TPC — locate response
XRD_LOGLEVEL=Debug xrdcp root://localhost:11123//file /tmp/out 2>&1 | grep "locate"

# WebDAV TPC — credential header present
curl -sk https://localhost:11125/ -H "Destination: https://localhost:11126/" -H "Credential: ..."
```
