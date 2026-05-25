# Security Hardening Guide

> **Audience:** Operators who want their deployment secure by default, not just "working."
>
> **Prerequisites:** Sections 01-02 (Getting Started and Concepts). Know what nginx-xrootd does before hardening it.
>
> **Time:** 30 minutes

---

A default nginx-xrootd install is functional, not hardened. This guide closes the gap: network exposure, auth policy, path confinement, TLS posture, and the settings that are too easy to leave at their insecure defaults.

## Overview

nginx-xrootd includes multiple layers of security controls. This guide explains each layer, how to configure it, and the default behavior — so you know what's protected out-of-the-box and what needs explicit configuration.

### The Layers (Bottom-Up)

```
Layer 4: Transport Security    ← TLS encryption in transit
Layer 3: Authentication       ← Who can connect (certs, tokens, anonymous)
Layer 2: Authorization        ← What they're allowed to do (scopes, ACLs)
Layer 1: Path Confinement     ← Where they can access on disk
```

Each layer is independent — enabling one doesn't automatically enable the others. Configure all four.

---

## Layer 1: Path Confinement

**What it protects against:** Path traversal attacks (e.g., `../../../../etc/passwd`).

### How It Works

All file operations go through **confined open helpers**. These functions canonicalize paths and verify they stay within the configured root directory before performing any operation.

```
Request:  /../../../etc/shadow
         ↓
Confined resolve: Rejects — escapes root boundary
Result:           HTTP 403 Forbidden (or XRootD equivalent)
```

### Configuration

No configuration needed for basic confinement — it's always enabled. However, verify these settings are correct:

| Directive | Value | Notes |
|---|---|---|
| `xrootd_root` | Absolute path only | Must be an absolute path like `/data/storage`. Relative paths bypass confinement. |
| `xrootd_webdav_root` | Absolute path only | Same constraint for WebDAV operations. |

### What it protects

- ✅ Symlink escapes under write-side path resolution
- ✅ Path traversal via `../` sequences
- ✅ NUL-byte injection in paths (stops string parsing attacks)
- ✅ Cross-root filesystem access attempts

### Verification test

```bash
# This should FAIL on a correctly configured server:
xrdcp root://localhost:1094///../../../etc/passwd /tmp/test.txt
# Expected: "Access denied" or similar error — NEVER succeeds
```

---

## Layer 2: Authorization (what users can do)

**What it protects against:** Authenticated users performing operations outside their intended scope.

### Write Gate (`xrootd_allow_write`)

This is a **server-wide write gate** — independent of token scopes or authentication method. Even with a valid `storage.write` token, writes fail if the gate is off.

```nginx
stream {
    server {
        listen 1094;
        xrootd on;
        xrootd_root /data;
        
        # CRITICAL: Disable by default unless you need writes!
        # xrootd_allow_write on;   ← Enable only when required
    }
}
```

**Default:** Off (read-only). This is the safest configuration.

### Token Scope Enforcement

WLCG/JWT tokens carry **scopes** that control access:

| Scope | Permission | Typical Use |
|---|---|---|
| `storage.read` | Read files, list directories | Analysis workers |
| `storage.write` | Write/upload files | Data ingestion |
| `storage.create` | Create directories | Directory management |

Scopes are enforced per-location in your nginx config. Check the token claims against the configured scope requirements.

### VO/FQAN ACLs

Optional access control based on Virtual Organization membership:

```nginx
# Only allow ATLAS VO members to write
xrootd_require_vo atlas
```

### Verification checklist

- [ ] Write gate is **off** unless explicitly needed
- [ ] Token scopes match user roles (read-only users can't write)
- [ ] VO restrictions are configured if your site requires them
- [ ] No wildcard scope grants (`*`) in production configs

---

## Layer 3: Authentication (who can connect)

### Auth methods ranked by security

| Method | Security Level | When to Use |
|---|---|---|
| **Anonymous** | Lowest | Development, public read-only mirrors |
| **JWT/Bearer Token** | High | WLCG workloads, long-lived sessions |
| **SSS (Shared Secret)** | Medium | Internal tooling, short-lived access |
| **GSI/x509 Certificates** | Highest | Grid computing, physics workloads |

### GSI certificate validation

When using GSI authentication:

1. **Certificate chain validation** — verifies the cert was signed by a trusted CA
2. **CRL checking** — rejects revoked certificates (see Layer 4)
3. **VOMS attribute verification** — optional VO membership check
4. **Subject DN matching** — optional identity constraint

```nginx
http {
    server {
        listen 8443 ssl;
        
        # Verify client certificates against trusted CAs
        ssl_verify_client optional_no_ca;
        
        location / {
            xrootd_webdav      on;
            xrootd_webdav_root /data;
            
            # Path to CA certificates for verification
            xrootd_webdav_cadir /etc/grid-security/certificates;
            
            # Require proxy certificate (stronger than host cert)
            xrootd_webdav_proxy_certs on;
        }
    }
}
```

### Token authentication

JWT tokens are validated locally — **no network calls to identity providers during request processing**. This means:

- ✅ No latency impact from IdP downtime
- ✅ Predictable performance under load
- ⚠️ Token revocation requires short TTL + rotation

Configure JWKS endpoints for key discovery:

```nginx
# Load signing keys from local file (cached)
xrootd_token_jwks /etc/nginx/jwks.json;
```

### Verification checklist

- [ ] Production uses **at minimum** token or GSI auth, never anonymous
- [ ] Token TTL is short enough to limit exposure window (< 1 hour recommended)
- [ ] JWKS files are accessible and not world-readable
- [ ] CRLs are updated regularly (automated if possible)

---

## Layer 4: Transport security (encryption in transit)

### TLS options ranked by safety

```
Option A: roots:// (TLS from byte 0)     ← Strongest, no downgrade possible
Option B: root:// + xrootd_tls on        ← In-protocol upgrade (kXR_wantTLS/kXR_ableTLS)
Option C: root:// (raw TCP)              ← Plaintext — NEVER in production with sensitive data
```

### Option A: `roots://` (Recommended for Production)

TLS is established immediately after the TCP handshake — before any protocol negotiation happens.

```nginx
stream {
    server {
        listen 1095 ssl;           # Different port from plaintext
        xrootd on;
        xrootd_root /data;
        
        # TLS configuration for roots:// mode
        ssl_certificate     /etc/ssl/xrdcert.pem;
        ssl_certificate_key /etc/ssl/xrdkey.pem;
    }
}
```

**Advantage:** No possibility of "downgrade attack" — the client cannot request plaintext.

### Option B: In-Protocol TLS Upgrade (`xrootd_tls on`)

The connection starts as raw TCP, then negotiates TLS through XRootD protocol opcodes. Useful when you want a single port for both modes or need to support legacy clients.

```nginx
stream {
    server {
        listen 1094;               # Same port as plaintext
        xrootd on;
        xrootd_root /data;
        xrootd_tls on;             ← Enable in-protocol TLS upgrade
        
        ssl_certificate     /etc/ssl/xrdcert.pem;
        ssl_certificate_key /etc/ssl/xrdkey.pem;
    }
}
```

**Warning:** Cleartext reads use nginx file-backed sendfile paths. **TLS paths require memory-backed responses.** Mixing these causes silent data corruption. This is handled automatically by the module, but worth understanding for debugging.

### WebDAV HTTPS

WebDAV always uses HTTPS — there's no plaintext equivalent. Ensure your TLS configuration follows security best practices:

```nginx
ssl_protocols TLSv1.2 TLSv1.3;
ssl_ciphers HIGH:!aNULL:!MD5:!3DES;
ssl_prefer_server_ciphers on;
ssl_session_timeout 1d;
ssl_stapling on;                 # OCSP stapling for faster verification
```

### Verification Checklist

- [ ] Production uses **TLSv1.2 or higher** (no SSLv3, TLSv1.0, TLSv1.1)
- [ ] Weak cipher suites are excluded (`MD5`, `DES`, `RC4`)
- [ ] OCSP stapling is enabled for certificate verification performance
- [ ] Certificate expiration is monitored (set up alerts 30 days before expiry)

---

## Additional Security Controls

### CRL (Certificate Revocation List) Handling

Revoked certificates are rejected at the authentication layer. Configure CRL loading:

```nginx
# Load CRL for certificate revocation checking
ssl_crl /etc/grid-security/crl.pem;
```

CRL files should be updated automatically — manually maintained lists go stale quickly.

### Privilege Escalation Prevention

nginx-xrootd runs with specific security constraints:

1. **Dropping privileges** — worker processes run as an unprivileged user after accepting connections
2. **File descriptor limiting** — prevents resource exhaustion attacks
3. **Request rate limits** — configurable via nginx `limit_req_zone`

```nginx
# Rate limit authentication attempts (prevents brute force)
limit_req_zone $binary_remote_addr zone=auth_limit:10m rate=10r/m;

stream {
    server {
        listen 1094;
        
        # Apply auth-specific rate limiting
        if ($request_uri ~* "kXR_auth") {
            limit_req zone=auth_limit burst=5 nodelay;
        }
    }
}
```

4. **PROPFIND `Depth: infinity` rate limiting** — a single `PROPFIND` with `Depth: infinity` on a large tree can hold a worker connection for tens of seconds while directory entries are enumerated.  nginx-xrootd caps the result set at 10 000 entries, but without a per-IP rate limit an attacker can open many simultaneous requests.  Add a dedicated zone in the `http` block:

```nginx
http {
    # Allow at most 2 recursive PROPFIND requests/second per IP.
    # Burst of 4 absorbs momentary spikes from legitimate DAV clients (e.g. Finder, Nautilus).
    limit_req_zone $binary_remote_addr zone=propfind_limit:10m rate=2r/s;

    server {
        listen 8443 ssl;

        location / {
            # Apply only to PROPFIND so other methods are not affected.
            limit_req zone=propfind_limit burst=4 nodelay;
        }
    }
}
```

If you want to restrict only `PROPFIND` and not other WebDAV methods, use a `map` on `$request_method` to set the zone key to an empty string for non-PROPFIND requests (an empty key bypasses `limit_req`).

### Security Headers (WebDAV)

Always include security headers for WebDAV responses:

```nginx
add_header X-Content-Type-Options "nosniff" always;
add_header X-Frame-Options "DENY" always;
add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
```

---

## Hardening Checklist

### Before Going Production

| # | Check | Severity |
|---|---|---|
| 1 | Write gate is **disabled** unless explicitly needed | Critical |
| 2 | Authentication method is **not anonymous** | Critical |
| 3 | TLS version is **1.2 or higher** | Critical |
| 4 | Path confinement root uses an **absolute path** | Critical |
| 5 | Certificate files are **not world-readable** (mode 600) | High |
| 6 | CRL lists are **current and loaded** | High |
| 7 | Token TTL is **short enough** for your threat model | Medium |
| 8 | Security headers are present on WebDAV responses | Medium |
| 9 | Access logs include full request details (for audit) | Low |
| 10 | Prometheus metrics don't expose sensitive information (e.g., paths, usernames) | Medium |

### Ongoing Maintenance

- [ ] Rotate signing keys periodically (JWT JWKS files)
- [ ] Update CRL lists (automate this!)
- [ ] Monitor certificate expiration (set alerts at 30/14/7 days before expiry)
- [ ] Review access logs for anomalous patterns
- [ ] Run security tests regularly: `pytest tests/test_security_hardening.py -v`

---

## Quick Reference: Security vs. Concurrency Trade-offs

| Feature | Security Impact | Performance Cost | Recommendation |
|---|---|---|---|
| OCSP stapling | Higher (live verification) | Negligible | Enable if possible |
| Strict TLS ciphers | Higher | Minor (~1-3%) | Use recommended ciphers |
| Rate limiting auth | Prevents brute force | Low | Set reasonable burst limits |
| CRL checking | Blocks revoked certs | Very low (cached) | Always enable in production |

---

## Related Documentation

| Topic | Document |
|---|---|
| GSI certificate setup | [PKI Configuration](../06-authentication/pki-config.md) |
| Token authentication | [Auth Overview](../06-authentication/auth-overview.md) |
| TLS modes | [TLS Configuration](../03-configuration/tls-config.md) |
| Security tests | `tests/test_security_hardening.py` |
| Privilege escalation tests | `tests/test_privilege_escalation.py` |

---

*This document covers the security controls available in nginx-xrootd. When in doubt, **default to more restrictive** — it's easier to add permissions than to remove them.*
