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
        xrootd on;
        xrootd_root /data/public;
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
        xrootd on;
        xrootd_root /data/upload;
        xrootd_allow_write on;
        xrootd_access_log /var/log/nginx/xrootd_access.log;
    }
}
```

### Read-through XCache-style server

```nginx
worker_processes auto;
thread_pool xrootd_cache_io threads=8 max_queue=65536;

events { worker_connections 4096; }

stream {
    server {
        listen 1094;
        xrootd on;
        xrootd_root /;
        xrootd_cache on;
        xrootd_cache_root /srv/xcache;
        xrootd_cache_origin root://origin.example.org:1094;
        xrootd_cache_lock_timeout 300s;
        xrootd_cache_eviction_threshold 90%;
        xrootd_access_log /var/log/nginx/xrootd_cache.log;
        xrootd_thread_pool xrootd_cache_io;
    }
}
```

Requests for `/store/...` are opened from `/srv/xcache/store/...` if present. A miss is filled once across all workers, then future clients read the local cached file.

---

### VO-restricted storage with group inheritance (CephFS-style)

```nginx
worker_processes auto;
thread_pool default threads=8 max_queue=65536;

events { worker_connections 1024; }

stream {
    server {
        listen 1095;
        xrootd on;
        xrootd_auth          gsi;
        xrootd_allow_write   on;
        xrootd_root          /ceph/store;

        xrootd_certificate     /etc/grid-security/hostcert.pem;
        xrootd_certificate_key /etc/grid-security/hostkey.pem;
        xrootd_trusted_ca      /etc/grid-security/ca.pem;

        # VOMS: where to find VO membership information
        xrootd_vomsdir         /etc/voms;
        xrootd_voms_cert_dir   /etc/grid-security/certificates;

        # Restrict /atlas and /cms sub-trees to their respective VOs
        xrootd_require_vo /atlas atlas;
        xrootd_require_vo /cms   cms;

        # Keep group ownership consistent for all new files/dirs
        xrootd_inherit_parent_group /atlas;
        xrootd_inherit_parent_group /cms;

        xrootd_access_log /var/log/nginx/xrootd_gsi.log;
        xrootd_thread_pool default;
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
        xrootd on;
        xrootd_root /data/token;
        xrootd_auth token;
        xrootd_allow_write on;

        xrootd_token_jwks     /etc/tokens/jwks.json;
        xrootd_token_issuer   "https://idp.example.com";
        xrootd_token_audience "my-storage";

        xrootd_access_log /var/log/nginx/xrootd_token.log;
    }
}
```

Native stream token auth validates the JWT and stores the `sub`, `scope`, and
`wlcg.groups` claims. Path-resolving operations enforce storage scopes:
`storage.read` is required for read opens and metadata operations, while
`storage.write` or `storage.create` is required for write opens and namespace
mutation. Handle-based I/O inherits the decision made when the handle was
opened. `xrootd_allow_write` remains an additional server-wide write gate, and
`xrootd_require_vo` can still use token `wlcg.groups` for path ACLs.

---

### Two ports: read-only anonymous + read-write GSI-authenticated

```nginx
worker_processes auto;
thread_pool default threads=4 max_queue=65536;

events { worker_connections 1024; }

stream {
    # Public read-only endpoint
    server {
        listen 1094;
        xrootd on;
        xrootd_root /data/public;
        xrootd_access_log /var/log/nginx/xrootd_public.log;
    }

    # Authenticated read-write endpoint
    server {
        listen 1095;
        xrootd on;
        xrootd_auth gsi;
        xrootd_allow_write on;
        xrootd_root /data/upload;
        xrootd_certificate     /etc/grid-security/hostcert.pem;
        xrootd_certificate_key /etc/grid-security/hostkey.pem;
        xrootd_trusted_ca      /etc/grid-security/ca.pem;
        xrootd_access_log /var/log/nginx/xrootd_gsi.log;
    }
}

# Prometheus metrics on a separate port
http {
    server {
        listen 9100;
        location /metrics {
            xrootd_metrics on;
        }
    }
}
```

---
