# Deployment Modes

There are three ways to run BriX-Cache, and they solve three different problems. Pick the one that matches where BriX-Cache sits in your stack — you can always combine modes later.

---

## Quick Decision Guide

Answer these questions to find your mode:

```text
              ┌──────────────────────────────────────┐
              │ Where do the bytes you serve live?    │
              └───────────────────┬──────────────────┘
            local disk on          │          behind an existing
            this machine           │          server you keep
                  │                │                │
                  ▼                │                ▼
        ┌──────────────────┐       │      what protocol do
        │ MODE 1 Standalone│       │      external clients speak?
        │ nginx IS the     │       │        ┌──────────┴──────────┐
        │ XRootD server,   │       │      root://            HTTP/davs://
        │ serves /data     │       │        │                     │
        └──────────────────┘       │        ▼                     ▼
                                   │  ┌──────────────┐   ┌──────────────────┐
                                   │  │ MODE 2 Proxy │   │ MODE 3 WebDAV    │
                                   │  │ relay root://│   │ perimeter proxy  │
                                   │  │ to a backend │   │ HTTPS+token →    │
                                   │  │ xrootd daemon│   │ internal WebDAV  │
                                   │  └──────────────┘   └──────────────────┘
                                   └─ (modes combine in one process — see below)
```

| Question | Yes → | No → |
|---|---|---|
| Do you already have an `xrootd` daemon running? | **Proxy Mode** (Mode 2) | Continue... |
| Do you need HTTPS/WebDAV access for non-XRootD clients? | **WebDAV Proxy** (Mode 3) | Continue... |
| Is this a new installation with direct filesystem access? | **Standalone** (Mode 1) | — |

---

## Mode 1: Standalone Server

```
┌─────────────┐         ┌──────────────────┐         ┌─────────────┐
│  xrdcp      │────────>│  nginx-xrootd    │────────>│  Local File- │
│  client     │  root://│  (port 1094)     │  POSIX  │  system     │
│             │         │                  │         │  /data/...   │
└─────────────┘         └──────────────────┘         └─────────────┘
                           │
                    Auth/TLS/metrics here
```

### What it does

BriX-Cache *is* the XRootD server. It directly serves files from your local filesystem using the native XRootD protocol.

### When to use this mode

- ✅ You're setting up a **new** file server (not replacing existing infrastructure)
- ✅ Your data lives on **local disks** attached to this machine
- ✅ You want **one service** instead of running `xrootd` daemon separately
- ✅ You need nginx features: TLS termination, request limiting, unified logging

### Configuration example

```nginx
stream {
    server {
        listen 1094;          # XRootD default port
        brix_root on;            # Enable the module
        brix_export /data;    # Root directory to serve
        brix_allow_write on;# Allow writes (optional)
        
        # Authentication options:
        # brix_auth none;           # Anonymous access
        # brix_auth gsi;            # GSI/x509 certificates
        # brix_auth token;          # JWT bearer tokens
    }
}
```

### Pros and Cons

| Pros | Cons |
|---|---|
| Simple — one service to manage | Only serves local filesystem (no remote backends) |
| Full control over auth, TLS, metrics | Limited by nginx worker capacity vs xrootd daemon threads |
| Can combine with WebDAV and S3 in same process | Does not implement XrdMon UDP monitoring (by design — will never be added; use Prometheus) |

---

## Mode 2: Transparent XRootD Proxy

```
┌─────────────┐         ┌──────────────────┐         ┌─────────────┐
│  xrdcp      │────────>│  nginx-xrootd    │────────>│  Backend     │
│  client     │  root://│  (port 1094)     │  root://│  daemon      │
│             │         │                  │────────>│  :1094       │
└─────────────┘         └──────────────────┘         └─────────────┘
                           │                              (invisible to client)
                    Auth/TLS/metrics here
```

### What it does

BriX-Cache sits **in front of** an existing XRootD server. Clients connect to nginx; nginx authenticates, then transparently forwards requests to the backend. The client never sees the backend server.

### When to use this mode

- ✅ You have an **existing xrootd daemon** you don't want to change
- ✅ You need to add **TLS termination** or **token auth** without touching the backend
- ✅ You want **metrics and access logs** at the edge, not on every backend server
- ✅ You're adding a **security perimeter** in front of internal infrastructure

### Configuration example

```nginx
stream {
    server {
        listen 1094;
        brix_root on;
        brix_proxy on;                    # Enable proxy mode
        brix_proxy_upstream ceph-xrootd:1094;  # Backend address
        
        # Auth options at the edge:
        brix_auth token;                  # JWT tokens instead of GSI
    }
}
```

### How it works (simplified)

1. Client connects and authenticates to nginx
2. First XRootD opcode after login triggers a **lazy connection** to backend
3. nginx translates file handles between client and backend
4. All opcodes relay byte-for-byte — nginx doesn't understand the data, just forwards it
5. Metrics and access logs capture everything at the edge

### Pros and Cons

| Pros | Cons |
|---|---|
| Protect existing infrastructure investment | Adds network hop (slight latency increase) |
| Centralize auth/TLS across multiple backends | File-handle translation adds complexity |
| Single point for metrics/logging | Can't do local file operations (relays everything) |

---

## Mode 3: WebDAV Perimeter Proxy

```
┌─────────────┐         ┌──────────────────┐         ┌─────────────┐
│  HTTP/      │────────>│  nginx-xrootd    │────────>│  Internal    │
│  davs://    │  HTTPS  │  (port 8443)     │  HTTP   │  WebDAV      │
│  client     │         │                  │────────>│  server      │
└─────────────┘         └──────────────────┘         └─────────────┘
                           │
                    HTTPS + WLCG token auth here
```

### What it does

BriX-Cache terminates **HTTPS** and enforces **WLCG JWT bearer token authentication**, then forwards plain HTTP requests to an internal WebDAV server. External clients never see the internal infrastructure.

### When to use this mode

- ✅ You have a **plain HTTP WebDAV server** internally that you want to expose externally
- ✅ You need HTTPS and token-based auth at the perimeter
- ✅ Your external clients prefer WebDAV over XRootD (browsers, rucio, etc.)
- ✅ Security policy requires terminating TLS outside your network

### Configuration example

```nginx
http {
    server {
        listen 8443 ssl;              # HTTPS port
        
        ssl_certificate     /etc/ssl/hostcert.pem;
        ssl_certificate_key /etc/ssl/hostkey.pem;
        
        location / {
            brix_webdav_proxy on;                   # Enable proxy mode
            brix_webdav_proxy_upstream http://internal-dav:8080;
            
            # Auth enforcement at the perimeter:
            brix_webdav_auth required;                # Require valid token/cert
        }
    }
}
```

### Pros and Cons

| Pros | Cons |
|---|---|
| Terminate TLS outside your network | Only works for WebDAV-compatible clients |
| Enforce WLCG tokens at the edge | Can't use native XRootD protocol through this path |
| Protect internal infrastructure | Higher overhead than direct XRootD access |

---

## Can I Run Multiple Modes Together?

**Yes.** A single nginx process can run all three modes simultaneously:

```nginx
# Stream block — Mode 1 (standalone) + Mode 2 (proxy)
stream {
    # Standalone server serving local files
    server {
        listen 1094;
        brix_root on;
        brix_export /data/local-store;
    }
    
    # Proxy for backend storage
    server {
        listen 1095;
        brix_root on;
        brix_proxy on;
        brix_proxy_upstream ceph-xrootd:1094;
    }
}

# HTTP block — Mode 3 (WebDAV proxy) + S3 endpoint
http {
    # WebDAV perimeter proxy
    server {
        listen 8443 ssl;
        location / {
            brix_webdav_proxy on;
            brix_webdav_proxy_upstream http://internal-dav:8080;
        }
    }
    
    # S3-compatible endpoint
    server {
        listen 9000;
        location / {
            brix_s3 on;
            brix_export /data/s3-bucket;
        }
    }
}
```

---

## Summary — Which Mode?

| Your Situation | Recommended Mode |
|---|---|
| New server, local files | **Mode 1: Standalone** |
| Replacing xrootd daemon on storage node | **Mode 1: Standalone** |
| Adding TLS/auth to existing XRootD server | **Mode 2: Transparent Proxy** |
| Centralizing metrics across multiple backends | **Mode 2: Transparent Proxy** |
| Exposing internal WebDAV externally | **Mode 3: WebDAV Proxy** |
| Browser/rucio access needed | **Mode 3: WebDAV Proxy** |

---

## Related Reading

- [XRootD Basics](xrootd-basics.md) — Understanding the protocol
- [Configuration Reference](../03-configuration/) — All available directives
- [TLS Configuration](../03-configuration/tls-config.md) — Setting up encryption
