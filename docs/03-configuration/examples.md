# Complete configuration examples

Copy-paste-ready configs for every common deployment pattern. Each example is self-contained and tested.

[← Configuration overview](config-reference.md)

## Complete examples

### Minimal read-only server

```nginx
worker_processes auto;
thread_pool default threads=4 max_queue=65536;

events { worker_connections 1024; }

stream {
    server {
        listen 1094;
        brix_root on;
        brix_export /data/public;
    }
}
```

### Read-write server with access log

```nginx
worker_processes auto;
thread_pool default threads=4 max_queue=65536;

events { worker_connections 1024; }

stream {
    server {
        listen 1094;
        brix_root on;
        brix_export /data/upload;
        brix_allow_write on;
        brix_access_log /var/log/nginx/brix_access.log;
    }
}
```

### Read-through XCache-style server

```nginx
worker_processes auto;
thread_pool brix_cache_io threads=8 max_queue=65536;

events { worker_connections 4096; }

stream {
    server {
        listen 1094;
        brix_root on;
        brix_export /;
        brix_cache on;
        brix_cache_export /srv/xcache;
        brix_cache_origin root://origin.example.org:1094;
        brix_cache_lock_timeout 300s;
        brix_cache_eviction_threshold 90%;
        brix_access_log /var/log/nginx/brix_cache.log;
        brix_thread_pool brix_cache_io;
    }
}
```

Requests for `/store/...` are opened from `/srv/xcache/store/...` if present. A miss is filled once across all workers, then future clients read the local cached file.

```text
  client ── root://cache//store/a.root ──▶ ┌─────────────────────────┐
                                           │  nginx-xrootd (XCache)   │
                                           │  brix_cache_export       │
                                           └───────────┬─────────────┘
                  ┌────────────────────────────────────┴───────────┐
                  ▼ HIT: /srv/xcache/store/a.root exists            ▼ MISS
            serve local copy                              fill once (shared
            (no origin traffic)                           lock, all workers
                  ▲                                        wait on one fetch)
                  │                                                 │
                  │                          root://origin//store/a.root
                  │                                                 ▼
                  └──── cached for next client ◀── stream from ── origin
                        (eviction at 90% via                     data server
                         brix_cache_eviction_threshold)
```

---

### VO-restricted storage with group inheritance (CephFS-style)

```nginx
worker_processes auto;
thread_pool default threads=8 max_queue=65536;

events { worker_connections 1024; }

stream {
    server {
        listen 1095;
        brix_root on;
        brix_auth          gsi;
        brix_allow_write   on;
        brix_export          /ceph/store;

        brix_certificate     /etc/grid-security/hostcert.pem;
        brix_certificate_key /etc/grid-security/hostkey.pem;
        brix_trusted_ca      /etc/grid-security/ca.pem;

        # VOMS: where to find VO membership information
        brix_vomsdir         /etc/voms;
        brix_voms_cert_dir   /etc/grid-security/certificates;

        # Restrict /atlas and /cms sub-trees to their respective VOs
        brix_require_vo /atlas atlas;
        brix_require_vo /cms   cms;

        # Keep group ownership consistent for all new files/dirs
        brix_inherit_parent_group /atlas;
        brix_inherit_parent_group /cms;

        brix_access_log /var/log/nginx/brix_gsi.log;
        brix_thread_pool default;
    }
}
```

With `setgid` on the top-level directories (set once with `chmod g+s /ceph/store/atlas /ceph/store/cms`), all files written through nginx will automatically inherit the correct GID and group permissions.

---

### Token-authenticated stream listener

```nginx
worker_processes auto;
thread_pool default threads=4 max_queue=65536;

events { worker_connections 1024; }

stream {
    server {
        listen 1096;
        brix_root on;
        brix_export /data/token;
        brix_auth token;
        brix_allow_write on;

        brix_token_jwks     /etc/tokens/jwks.json;
        brix_token_issuer   "https://idp.example.com";
        brix_token_audience "my-storage";

        brix_access_log /var/log/nginx/brix_token.log;
    }
}
```

Native stream token auth validates the JWT and stores the `sub`, `scope`, and
`wlcg.groups` claims. Path-resolving operations enforce storage scopes:
`storage.read` is required for read opens and metadata operations, while
`storage.write` or `storage.create` is required for write opens and namespace
mutation. Handle-based I/O inherits the decision made when the handle was
opened. `brix_allow_write` remains an additional server-wide write gate, and
`brix_require_vo` can still use token `wlcg.groups` for path ACLs.

---

### Two ports: read-only anonymous + read-write GSI-authenticated

```text
                        ┌──────────────────────────────────────┐
   anonymous reader ──▶ │ :1094  brix_export /data/public      │ read-only
                        │        (no auth, no write)            │
                        ├──────────────────────────────────────┤
   GSI cert holder  ──▶ │ :1095  brix_auth gsi                │ read-write
                        │        brix_allow_write on          │ (cert + CA)
                        │        brix_export /data/upload       │
                        ├──────────────────────────────────────┤
   Prometheus       ──▶ │ :9100  http /metrics                  │ scrape
                        └──────────────────────────────────────┘
   one nginx process · separate listeners · independent auth + root per port
```

```nginx
worker_processes auto;
thread_pool default threads=4 max_queue=65536;

events { worker_connections 1024; }

stream {
    # Public read-only endpoint
    server {
        listen 1094;
        brix_root on;
        brix_export /data/public;
        brix_access_log /var/log/nginx/brix_public.log;
    }

    # Authenticated read-write endpoint
    server {
        listen 1095;
        brix_root on;
        brix_auth gsi;
        brix_allow_write on;
        brix_export /data/upload;
        brix_certificate     /etc/grid-security/hostcert.pem;
        brix_certificate_key /etc/grid-security/hostkey.pem;
        brix_trusted_ca      /etc/grid-security/ca.pem;
        brix_access_log /var/log/nginx/brix_gsi.log;
    }
}

# Prometheus metrics on a separate port
http {
    server {
        listen 9100;
        location /metrics {
            brix_metrics on;
        }
    }
}
```

---
