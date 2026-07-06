# BriX-Cache Quick-Start Guide

**One container → root:// + https:// + S3 → xrdcp transfers → Prometheus monitoring → CURL with JWT or x509 auth.**

All paths reference `/tmp/xrd-test/` — the same PKI and tokens used by the test suite.

---

## 1. Prerequisites

```bash
# Build tools
yum install gcc make nginx-mod-devel openssl-devel pcre2-devel zlib-devel \
            libxml2-devel jansson-devel curl voms-libs   # AlmaLinux/RHEL
apt install build-essential nginx-dev libssl-dev libpcre2-dev zlib1g-dev \
            libxml2-dev libjansson-dev curl libvoms-dev  # Debian/Ubuntu

# Docker or Podman for the container image
docker --version || podman --version

# Python helper scripts (for tokens)
pip install cryptography

# XRootD client tools (on your machine to connect to the server)
yum install xrootd-client   # AlmaLinux/RHEL
apt install xrootd-client   # Debian/Ubuntu
```

---

## 2. Build the RPM

### Option A — Local build

```bash
cd /home/rcurrie/HEP-x/nginx-xrootd
./packaging/rpm/build-rpm.sh [version]
# Output: RPM in ~/rpmbuild/RPMS/x86_64/
```

### Option B — Container-based build (recommended for reproducibility)

```bash
cd /home/rcurrie/HEP-x/nginx-xrootd
./packaging/rpm/build-rpm-container.sh \
    -v 1.0.0 \
    -d alma9 \
    -o ./rpm-output
# Output: RPM in ./rpm-output/
```

This uses `packaging/rpm/Dockerfile.alma9` which builds on AlmaLinux 9 with EPEL installed. The spec file is at `packaging/rpm/nginx-mod-brix-cache.spec`.

---

## 3. Install the Module into nginx

```bash
# Place the RPM-installed module where nginx can find it
rpm -ivh ./rpm-output/nginx-mod-brix-cache-*.rpm

# Or manually copy if you built from source:
cp objs/ngx_stream_brix_module.so /usr/lib64/nginx/modules/
cp objs/ngx_http_brix_webdav_module.so /usr/lib64/nginx/modules/
```

---

## 4. Generate the PKI (certificates)

The test suite regenerates this from scratch each run via `blitz_test_pki()`. To do it manually:

```bash
cd /home/rcurrie/HEP-x/nginx-xrootd
# blitz_test_pki() takes no arguments; it reads the target path (PKI_DIR) from
# tests/settings.py, which defaults to $TEST_ROOT/pki (TEST_ROOT=/tmp/xrd-test).
# Override the location by exporting TEST_ROOT before invoking.
PYTHONPATH=tests python3 -c 'from pki_helpers import blitz_test_pki; blitz_test_pki()'
```

This creates the full hierarchy under `/tmp/xrd-test/pki/`:

| Path | Contents | Purpose |
|---|---|---|
| `ca/ca.key` + `ca/ca.pem` | CA private key and certificate | Root trust for GSI auth |
| `server/hostcert.pem` + `server/hostkey.pem` | Server TLS cert/key | SSL termination on https:// ports |
| `user/usercert.pem` + `useruserkey.pem` | User cert/key | Generate proxy certs from this |
| `user/proxy_cms.pem` | CMS VOMS proxy certificate | GSI auth with /cms VO |
| `user/proxy_atlas.pem` | ATLAS VOMS proxy certificate | GSI auth with /atlas VO |
| `user/proxy_std.pem` | Standard proxy (no VOMS) | GSI auth without VO membership |
| `vomsdir/cms/lsc` + `vomsdir/atlas/lsc` | VOMS server descriptors | VOMS attribute validation |

### Generate a fresh user proxy certificate

```bash
# Create a 12-hour proxy from your user cert/key
openssl x509 -req -in /tmp/xrd-test/pki/user/usercert.pem \
    -CA /tmp/xrd-test/pki/ca/ca.pem -CAkey /tmp/xrd-test/pki/ca/ca.key \
    -extfile /tmp/xrd-test/pki/vomsdir/cms/lsc \
    -out /tmp/xrd-test/pki/user/proxy_new.pem \
    -days 0.5   # half a day = ~12 hours
export X509_USER_PROXY=/tmp/xrd-test/pki/user/proxy_new.pem
```

---

## 5. Generate JWT Tokens

```bash
cd /home/rcurrie/HEP-x/nginx-xrootd

# Initialize the signing authority (one-time)
python3 utils/make_token.py init /tmp/xrd-test/tokens

# Create a read-only token
export BEARER_TOKEN=$(python3 utils/make_token.py gen \
    --scope "storage.read:/" /tmp/xrd-test/tokens)

# Create a read-write token (for uploads)
export BEARER_TOKEN=$(python3 utils/make_token.py gen \
    --scope "storage.read:/ storage.write:/" /tmp/xrd-test/tokens)
```

The signing authority consists of two files under `/tmp/xrd-test/tokens/`:
- `signing_key.pem` — RSA-2048 private key (used to sign tokens)
- `jwks.json` — Public key in JWKS format (loaded by nginx for verification)

Inspect a token:
```bash
python3 utils/make_token.py gen --scope "storage.read:/" /tmp/xrd-test/tokens \
    | python3 utils/inspect_token.py -
```

---

## 6. Configure nginx

Create `/tmp/xrd-test/conf/nginx.conf` from this template (adjust paths as needed):

```nginx
worker_processes 1;
error_log /tmp/xrd-test/logs/error.log info;
pid /tmp/xrd-test/logs/nginx.pid;

load_module /usr/lib64/nginx/modules/ngx_stream_brix_module.so;
load_module /usr/lib64/nginx/modules/ngx_http_brix_webdav_module.so;

stream {
    # Anonymous XRootD (no auth) — port 11094
    server {
        listen 11094;
        brix_root on;
        brix_export /tmp/xrd-test/data;
        brix_access_log /tmp/xrd-test/logs/brix_access_anon.log;
    }

    # GSI auth (x509 proxy certificate) — port 11095
    server {
        listen 11095;
        brix_root on;
        brix_export /tmp/xrd-test/data;
        brix_certificate     /tmp/xrd-test/pki/server/hostcert.pem;
        brix_certificate_key /tmp/xrd-test/pki/server/hostkey.pem;
        brix_trusted_ca      /tmp/xrd-test/pki/ca/ca.pem;
        brix_access_log /tmp/xrd-test/logs/brix_access_gsi.log;
    }

    # GSI + TLS (encrypted channel with proxy cert) — port 11096
    server {
        listen 11096 ssl;
        brix_root on;
        brix_export /tmp/xrd-test/data;
        brix_certificate     /tmp/xrd-test/pki/server/hostcert.pem;
        brix_certificate_key /tmp/xrd-test/pki/server/hostkey.pem;
        brix_trusted_ca      /tmp/xrd-test/pki/ca/ca.pem;
        ssl_certificate        /tmp/xrd-test/pki/server/hostcert.pem;
        ssl_certificate_key    /tmp/xrd-test/pki/server/hostkey.pem;
        brix_access_log /tmp/xrd-test/logs/brix_access_gsi_tls.log;
    }

    # JWT token auth — port 11097
    server {
        listen 11097;
        brix_root on;
        brix_export /tmp/xrd-test/data;
        brix_auth token;
        brix_allow_write on;
        brix_token_jwks     /tmp/xrd-test/tokens/jwks.json;
        brix_token_issuer   "https://test.example.com";
        brix_token_audience "nginx-xrootd";
        brix_access_log /tmp/xrd-test/logs/brix_access_token.log;
    }
}

http {
    # WebDAV/HTTPS — port 8443
    server {
        listen 8443 ssl;
        server_name localhost;

        ssl_certificate     /tmp/xrd-test/pki/server/hostcert.pem;
        ssl_certificate_key /tmp/xrd-test/pki/server/hostkey.pem;

        location / {
            brix_webdav         on;
            brix_export    /tmp/xrd-test/data;
            brix_webdav_auth    optional;
            brix_allow_write on;

            brix_webdav_token_jwks     /tmp/xrd-test/tokens/jwks.json;
            brix_webdav_token_issuer   "https://test.example.com";
            brix_webdav_token_audience "nginx-xrootd";
        }
    }

    # S3 REST API — port 9001
    server {
        listen 9001;
        server_name localhost;

        location / {
            brix_s3         on;
            brix_export    /tmp/xrd-test/s3-data;
            brix_s3_bucket  test-bucket;
        }
    }

    # Prometheus metrics — port 9100
    server {
        listen 9100;
        server_name localhost;

        location /metrics {
            brix_metrics on;
        }
    }
}
```

---

## 7. Start the Server

```bash
# Create required directories
mkdir -p /tmp/xrd-test/data /tmp/xrd-test/s3-data /tmp/xrd-test/logs

# Seed some test files
echo "hello from root://" > /tmp/xrd-test/data/test.txt
echo "hello from webdav" > /tmp/xrd-test/data/webdav_test.txt

# Validate the config
/tmp/nginx-1.28.3/objs/nginx -t -c /tmp/xrd-test/conf/nginx.conf

# Start nginx
/tmp/nginx-1.28.3/objs/nginx -c /tmp/xrd-test/conf/nginx.conf
```

---

## 8. Connect with xrdcp and Monitor Transfers

### XRootD stream — anonymous (no auth)

```bash
xrdcp root://localhost:11094//test.txt /tmp/downloaded.txt
cat /tmp/downloaded.txt   # hello from root://
```

### XRootD stream — GSI proxy cert

```bash
export X509_USER_PROXY=/tmp/xrd-test/pki/user/proxy_cms.pem
xrdcp root://localhost:11095//test.txt /tmp/downloaded_gsi.txt
cat /tmp/downloaded_gsi.txt   # hello from root://
```

### XRootD stream — JWT token

```bash
export BEARER_TOKEN=$(python3 utils/make_token.py gen \
    --scope "storage.read:/" /tmp/xrd-test/tokens)
xrdcp root://localhost:11097//test.txt /tmp/downloaded_token.txt
cat /tmp/downloaded_token.txt   # hello from root://
```

### Upload a file (token auth with write scope)

```bash
export BEARER_TOKEN=$(python3 utils/make_token.py gen \
    --scope "storage.read:/ storage.write:/" /tmp/xrd-test/tokens)
echo "uploaded via xrdcp" > /tmp/upload_test.txt
xrdcp /tmp/upload_test.txt root://localhost:11097//upload_test.txt

# Verify it uploaded
xrdcp root://localhost:11097//upload_test.txt -   # prints content to stdout
```

### Monitor transfers via Prometheus metrics

The server exposes Prometheus metrics at `http://localhost:9100/metrics`:

```bash
curl http://localhost:9100/metrics | grep xrootd
```

You will see counters like:
- `brix_requests_total{op="stat",status="OK"}` — stat operations completed successfully
- `brix_bytes_sent_total{proto="stream"}` — bytes transferred over XRootD stream
- `brix_bytes_received_total{proto="stream"}` — bytes uploaded via XRootD stream

For HTTPS dashboard access: configure SSL on port 9100 with the same host cert/key.

---

## 9. Connect with CURL (WebDAV/HTTPS)

### WebDAV — JWT token auth

```bash
TOKEN=$(python3 utils/make_token.py gen --scope "storage.read:/" /tmp/xrd-test/tokens)

# GET a file
curl -k -H "Authorization: Bearer $TOKEN" \
    https://localhost:8443/test.txt   # hello from webdav

# PROPFIND (directory listing)
curl -k -X PROPFIND -H "Depth: 1" \
    -H "Authorization: Bearer $TOKEN" \
    https://localhost:8443/   # XML listing of files

# HEAD (file metadata)
curl -k -I -H "Authorization: Bearer $TOKEN" \
    https://localhost:8443/test.txt   # HTTP 200 with Content-Length

# PUT a file (requires write scope)
TOKEN=$(python3 utils/make_token.py gen \
    --scope "storage.read:/ storage.write:/" /tmp/xrd-test/tokens)
curl -k -X PUT \
    -H "Authorization: Bearer $TOKEN" \
    -d "uploaded via webdav" \
    https://localhost:8443/webdav_upload.txt

# Verify upload
curl -k -H "Authorization: Bearer $TOKEN" \
    https://localhost:8443/webdav_upload.txt   # uploaded via webdav
```

### WebDAV — GSI proxy cert (mutual TLS)

```bash
export X509_USER_PROXY=/tmp/xrd-test/pki/user/proxy_cms.pem

# GET with mutual TLS (client cert + server cert)
curl -k --cert /tmp/xrd-test/pki/user/proxy_cms.pem \
    --key /tmp/xrd-test/pki/user/proxykey.pem \
    https://localhost:8443/test.txt   # hello from webdav

# PUT with mutual TLS + write scope token on same port (both auth)
curl -k --cert /tmp/xrd-test/pki/user/proxy_cms.pem \
    --key /tmp/xrd-test/pki/user/proxykey.pem \
    https://localhost:8443/webdav_upload2.txt   # hello from webdav
```

### S3 — curl examples (port 9001)

```bash
# List buckets
curl http://localhost:9001/

# Put an object
curl -X PUT -d "s3 content" \
    http://localhost:9001/test-bucket/myfile.txt

# Get an object
curl http://localhost:9001/test-bucket/myfile.txt   # s3 content

# List objects in a bucket
curl http://localhost:9001/test-bucket/
```

---

## 10. Troubleshooting

| Symptom | Fix |
|---|---|
| `xrdcp` says "authentication failure" on token port | Ensure `BEARER_TOKEN` env var is set; verify token scope includes the path you're accessing |
| `xrdcp` says "authentication failure" on GSI port | Ensure `X509_USER_PROXY` points to a valid proxy cert within its lifetime; check it was signed by the CA at `/tmp/xrd-test/pki/ca/ca.pem` |
| curl returns 401/403 on HTTPS | Token missing or expired; use `--scope "storage.read:/"` for GET, `"storage.write:/"` for PUT. Check token expiry with `utils/inspect_token.py` |
| nginx won't start | Verify all cert/key paths exist and JWKS file exists (`python3 utils/make_token.py init /tmp/xrd-test/tokens`) |
| Write denied even with valid token | Server must have `brix_allow_write on` (stream) or `brix_allow_write on` (WebDAV); token scope must include `storage.write:PATH` |
| Metrics endpoint empty | Port 9100 must be listening; check `ss -tlnp \| grep 9100` |

---

## Quick Reference — Ports

| Protocol | Auth Mode | Port |
|---|---|---|
| root:// (XRootD stream) | Anonymous | **11094** |
| root:// (XRootD stream) | GSI proxy cert | **11095** |
| root:// (XRootD stream) | GSI + TLS | **11096** |
| root:// (XRootD stream) | JWT token | **11097** |
| https:// (WebDAV/HTTPS) | Token or anonymous | **8443** |
| S3 REST API | Anonymous | **9001** |
| Prometheus metrics | No auth | **9100** |

---

## Quick Reference — Auth Environment Variables

| Auth Mode | Env Var | Example Value |
|---|---|---|
| JWT token | `BEARER_TOKEN` | `eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVC...` (JWT string) |
| GSI proxy cert | `X509_USER_PROXY` | `/tmp/xrd-test/pki/user/proxy_cms.pem` (proxy cert path) |

---

## Full Test Suite

To run all tests including token auth, GSI auth, WebDAV, S3, and metrics:

```bash
cd /home/rcurrie/HEP-x/nginx-xrootd
source .venv/bin/activate
tests/manage_test_servers.sh start
PYTHONPATH=tests pytest tests/ -v --tb=short
tests/manage_test_servers.sh stop
```
