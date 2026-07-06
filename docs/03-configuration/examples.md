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

### CVMFS site cache — minimal (forward-proxy mode)

Three directives are sufficient for a production-grade CVMFS site cache. All
other knobs are at their tested defaults: manifest TTL 61 s, negative TTL 10 s,
client hold 25 s, fill max-life 300 s, up to 8 concurrent fills per origin, CAS
verify on, RTT-based origin selection, eviction at 90% → target 80%.

```nginx
worker_processes auto;
thread_pool default threads=16 max_queue=65536;
events { worker_connections 4096; }

http {
    server {
        listen 3128;
        location / {
            brix_cvmfs on;
            brix_cache_store posix:/srv/cvmfs-cache;
            brix_cvmfs_upstream_allow cvmfs-stratum-one.cern.ch
                                      cvmfs-s1fnal.opensciencegrid.org;
        }
    }
}
```

On the worker nodes:

```
CVMFS_HTTP_PROXY="http://cache.site:3128"
CVMFS_TIMEOUT=30      # must exceed brix_cvmfs_client_hold (25s default)
```

### CVMFS site cache — tuned production (forward-proxy mode)

Show only the non-default knobs, each with a comment stating what the default
already does and why you would change it.

```nginx
worker_processes auto;
thread_pool default threads=16 max_queue=65536;
events { worker_connections 4096; }

http {
    log_format cvmfs '$remote_addr [$time_local] "$request" $status '
                     '$body_bytes_sent $request_time '
                     'class=$cvmfs_class cache=$cvmfs_cache origin=$cvmfs_origin';
    access_log /var/log/nginx/cvmfs_access.log cvmfs;

    # Keep WN connections alive — prevents spurious proxy-failure marks
    keepalive_timeout  3600s;
    keepalive_requests 1000000;

    server {
        listen 3128 so_keepalive=60s:10s:6 backlog=2048;
        location / {
            brix_cvmfs on;
            brix_cache_store posix:/srv/cvmfs-cache;

            # --- non-default: turn verify off for testing only ---
            # Default is cvmfs-cas (verify every fill against SHA-1).
            # Only disable if you are debugging fill performance.
            # brix_cache_verify off;

            # --- non-default: geo-based origin selection ---
            # Default is rtt (probe connect latency, prefer fastest).
            # Switch to geo when RTT probes are unreliable (e.g. firewalled).
            # brix_cvmfs_origin_select geo;
            # brix_cvmfs_here 55.95:-3.19;   # this cache (Edinburgh)
            # brix_cvmfs_origin_coords cvmfs-stratum-one.cern.ch 46.23:6.05;
            # brix_cvmfs_origin_coords cvmfs-s1fnal.opensciencegrid.org 41.85:-88.31;

            # --- non-default: raise eviction watermarks ---
            # Defaults are evict_at=90 evict_to=80 (percent of volume).
            # Lower evict_at to keep more headroom on a busy cache.
            brix_cache_evict_at 85;          # default: 90
            brix_cache_evict_to 70;          # default: 80

            # Quarantine directory for CAS verify failures (evidence, not cache)
            brix_cvmfs_quarantine_dir /srv/cvmfs-quarantine;

            # All Stratum-1 hosts your experiments use
            brix_cvmfs_upstream_allow cvmfs-stratum-one.cern.ch
                                      cvmfs-s1fnal.opensciencegrid.org
                                      cvmfs-stratum-one.ihep.ac.cn;
        }
    }

    server {
        listen 9100;
        location /metrics { brix_metrics on; }
        location /healthz  { brix_health on; }
    }
}
```

### CVMFS site cache — reverse-proxy mode

In reverse mode the cache acts as an HTTP origin for CVMFS clients (they point
`CVMFS_SERVER_URL` directly at the cache, not at Stratum-1s). Replace the
`upstream_allow` allowlist with a pipe-separated `brix_storage_backend` origin
set; the cache handles failover internally.

```nginx
http {
    server {
        listen 8000;
        location / {
            brix_cvmfs on;
            brix_cache_store posix:/srv/cvmfs-cache;
            brix_storage_backend "http://s1a.example.org:8000|http://s1b.example.org:8000";
        }
    }
}
```

Worker-node CVMFS configuration for reverse mode:

```
CVMFS_SERVER_URL="http://cache.site:8000/cvmfs/@fqrn@"
CVMFS_HTTP_PROXY=DIRECT
CVMFS_TIMEOUT=30
```

---
