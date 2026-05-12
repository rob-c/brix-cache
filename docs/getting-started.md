# Getting started

This guide walks you from zero to a working XRootD server in nginx. It takes about 10 minutes.

## Prerequisites

- Linux (tested on RHEL 8/9, Ubuntu 22.04+)
- A C compiler (`gcc` or `clang`)
- nginx source (we build from source because we add a module)
- `xrdcp` installed for testing — install via `yum install xrootd-client` or `apt install xrootd-client`

> GSI authentication also needs an x509 host certificate. If you only want anonymous access (no certificates), you can skip that entirely.

---

## Step 1: Get the nginx source

We compile nginx from source to add this module. Use the current stable release:

```bash
curl -O https://nginx.org/download/nginx-1.28.3.tar.gz
tar xzf nginx-1.28.3.tar.gz
cd nginx-1.28.3
```

---

## Step 2: Configure and build

Clone this module alongside the nginx source tree, then configure:

```bash
git clone https://github.com/rob-c/nginx-xrootd.git /opt/nginx-xrootd

./configure \
    --with-stream \
    --with-threads \
    --add-module=/opt/nginx-xrootd
make -j$(nproc)
sudo make install
```

The key flags:
- `--with-stream` — enables nginx's raw TCP handling (required)
- `--with-threads` — enables async file I/O (strongly recommended; without this, slow disk I/O blocks all connections on the worker)
- `--add-module` — points to this repository

nginx is installed to `/usr/local/nginx` by default. The binary is at `/usr/local/nginx/sbin/nginx`.

**Verifying the build:**

```bash
/usr/local/nginx/sbin/nginx -V 2>&1 | grep xrootd
# Should show: --add-module=.../nginx-xrootd
```

---

## Step 3: Write a minimal nginx.conf

Create `/usr/local/nginx/conf/nginx.conf`:

```nginx
# Required: tell nginx how many workers to run
worker_processes auto;

# Required: enable async file I/O thread pool
# (match the thread count to your disk I/O capacity)
thread_pool default threads=4 max_queue=65536;

events {
    worker_connections 1024;
}

stream {
    server {
        listen 1094;           # standard XRootD port
        xrootd on;
        xrootd_root /data;     # serve files from /data
        xrootd_allow_write on; # allow uploads
        xrootd_access_log /var/log/nginx/xrootd_access.log;
    }
}
```

Make the data directory:

```bash
mkdir -p /data
```

---

## Step 4: Start nginx

```bash
sudo /usr/local/nginx/sbin/nginx
```

If you rebuild nginx with a modified version of this module, do a full stop/start of the rebuilt binary. A plain `nginx -s reload` only reloads configuration for the already-running master process; it does not switch the process over to a newly rebuilt executable.

Check the error log if anything goes wrong:

```bash
tail -f /usr/local/nginx/logs/error.log
```

---

## Step 5: Test with xrdcp

```bash
# Upload a file
echo "hello xrootd" > /tmp/test.txt
xrdcp /tmp/test.txt root://localhost:1094//test.txt

# Download it back
xrdcp root://localhost:1094//test.txt /tmp/downloaded.txt
cat /tmp/downloaded.txt  # should print: hello xrootd

# List the directory
xrdfs localhost:1094 ls /

# Stat a file
xrdfs localhost:1094 stat /test.txt
```

If your local `xrdfs` build does not support `ping`, use `xrdfs ... ls /` as the simplest readiness check. That is the case for the 5.9.2 client packages used in this repository's test environment.

If `xrdcp` exits with status 0 and prints no errors, you have a working XRootD server.

---

## Step 6: Test with the Python client (optional)

Install the Python XRootD client:

```bash
pip install xrootd
```

Run the Python smoke-test helper from the repository root:

```bash
python3 utils/xrd_python_smoke.py --url root://localhost:1094 --path /test.txt
```

The helper lists `/`, reads `/test.txt`, and exits non-zero if either operation fails.

---

## Step 7: Add HTTPS and WebDAV (davs://)

WebDAV lets the same files be accessible over `davs://` URLs — used by `xrdcp --allow-http`,
FTS3/FTS4, Rucio, GFAL2, and standard HTTP tools. This requires a TLS certificate and key.

### 7a: Get a certificate

For testing, create a self-signed certificate:

```bash
openssl req -x509 -newkey rsa:4096 -keyout /etc/nginx/server.key \
    -out /etc/nginx/server.crt -days 365 -nodes \
    -subj "/CN=localhost"
```

For production, use a certificate from your site CA or Let's Encrypt.

### 7b: Update nginx.conf

Add an `http {}` block alongside the existing `stream {}` block:

```nginx
worker_processes auto;
thread_pool default threads=4 max_queue=65536;

events {
    worker_connections 1024;
}

# Native XRootD (root://)
stream {
    server {
        listen 1094;
        xrootd on;
        xrootd_root /data;
        xrootd_allow_write on;
    }
}

# WebDAV over HTTPS (davs://)
http {
    server {
        listen 8443 ssl;
        ssl_certificate     /etc/nginx/server.crt;
        ssl_certificate_key /etc/nginx/server.key;

        location / {
            xrootd_webdav             on;
            xrootd_webdav_root        /data;    # same backing storage
            xrootd_webdav_allow_write on;
        }
    }
}
```

Reload nginx:

```bash
sudo /usr/local/nginx/sbin/nginx -s stop
sudo /usr/local/nginx/sbin/nginx
```

### 7c: Test WebDAV

```bash
# Upload via curl
curl -k -T /tmp/test.txt https://localhost:8443//test-webdav.txt

# Download via curl
curl -k https://localhost:8443//test-webdav.txt -o /tmp/downloaded-webdav.txt

# List directory via curl (PROPFIND)
curl -k -X PROPFIND https://localhost:8443/ -H "Depth: 1"

# Upload via xrdcp (using WebDAV instead of native XRootD)
xrdcp -f --allow-http /tmp/test.txt davs://localhost:8443//test-xrdcp.txt

# Download via xrdcp WebDAV
xrdcp --allow-http davs://localhost:8443//test-xrdcp.txt /tmp/out-webdav.txt
```

The `-k` flag skips certificate verification for self-signed certs. In production with a real
certificate, omit it.

---

## Step 8: Add the S3-compatible endpoint (optional)

The S3 endpoint exposes the same data through the AWS S3 REST API subset used by
XrdClS3-backed `xrdcp` and FTS.

### 8a: Update nginx.conf

Add an S3 location in the http block:

```nginx
http {
    server {
        listen 9001;

        location / {
            xrootd_s3          on;
            xrootd_s3_root     /data;       # same backing storage
            xrootd_s3_bucket   mybucket;    # bucket name clients will use
            # xrootd_s3_access_key  mykey;  # optional SigV4 auth
            # xrootd_s3_secret_key  mysecret;
        }
    }
}
```

### 8b: Test S3

```bash
# Upload via curl (path-style)
curl -T /tmp/test.txt http://localhost:9001/mybucket/test.txt

# Download
curl http://localhost:9001/mybucket/test.txt -o /tmp/s3-download.txt

# List bucket (ListObjectsV2)
curl "http://localhost:9001/mybucket/?list-type=2"

# With AWS CLI (configure with any key/secret if auth is not set)
export AWS_ACCESS_KEY_ID=test
export AWS_SECRET_ACCESS_KEY=test
aws --endpoint-url http://localhost:9001 s3 ls s3://mybucket/
aws --endpoint-url http://localhost:9001 s3 cp /tmp/test.txt s3://mybucket/test.txt
aws --endpoint-url http://localhost:9001 s3 cp s3://mybucket/test.txt /tmp/s3-out.txt
```

### Multipart upload (for files > 5 GiB)

The S3 endpoint supports the full multipart lifecycle. AWS SDK clients use this
automatically for large files. To test manually:

```bash
# Initiate
curl -X POST "http://localhost:9001/mybucket/bigfile.dat?uploads" \
     -o /tmp/init.xml
# Extract UploadId from XML response

UPLOAD_ID="<from init response>"

# Upload parts (minimum part size is 5 MiB except the last)
dd if=/dev/urandom bs=6M count=1 | \
    curl -T - "http://localhost:9001/mybucket/bigfile.dat?partNumber=1&uploadId=$UPLOAD_ID" \
         -o /tmp/part1.xml

# Complete (include ETag from each part response)
curl -X POST "http://localhost:9001/mybucket/bigfile.dat?uploadId=$UPLOAD_ID" \
     -H "Content-Type: application/xml" \
     -d '<CompleteMultipartUpload><Part><PartNumber>1</PartNumber><ETag>"..."</ETag></Part></CompleteMultipartUpload>'
```

---

## Step 9: Enable Prometheus metrics (optional)

```nginx
http {
    server {
        listen 9100;
        location /metrics {
            xrootd_metrics on;
        }
    }
}
```

```bash
# Scrape metrics
curl http://localhost:9100/metrics

# Example output:
# xrootd_native_ops_total{port="1094",op="open",status="ok"} 42
# xrootd_webdav_requests_total{port="8443",method="GET",status="200"} 17
# xrootd_s3_requests_total{port="9001",method="GET",status="200"} 5
```

Add to your `prometheus.yml`:

```yaml
scrape_configs:
  - job_name: 'nginx-xrootd'
    static_configs:
      - targets: ['localhost:9100']
```

---

## What's next?

- **Add GSI authentication** — [docs/authentication.md](authentication.md)
- **Add token (JWT/WLCG) authentication** — [docs/authentication.md](authentication.md#token--jwt-wlcg-bearer-token-authentication)
- **Set up a test PKI from scratch** — [docs/test-pki.md](test-pki.md)
- **Set up test tokens from scratch** — [docs/test-tokens.md](test-tokens.md)
- **All configuration options** — [docs/configuration.md](configuration.md)
- **Prometheus metrics** — [docs/metrics-and-logging.md](metrics-and-logging.md)
- **Understand all supported operations** — [docs/operations.md](operations.md)
- **Enable WebDAV over HTTPS** — [docs/webdav.md](webdav.md)
- **Set up HTTP-TPC (FTS3/FTS4 transfers)** — [docs/webdav.md#http-tpc](webdav.md)
- **Enable S3-compatible endpoint** — [docs/configuration.md](configuration.md)
- **Understand the comparison with official xrootd** — [docs/comparison-with-xrootd.md](comparison-with-xrootd.md)
- **Run the full test suite** — [docs/testing.md](testing.md)

---

## Troubleshooting

**`xrdcp` hangs after connecting:**
Check the nginx error log. The most common cause is a firewall blocking port 1094.

**`xrdcp` prints "No space left on device":**
The upload landed in the right place but the filesystem is full.

**`xrdcp` prints "Permission denied":**
Either the nginx worker process does not have read/write permission to `xrootd_root`, or `xrootd_allow_write` is not set to `on`.

**`xrdcp` exits with status 1 and no useful message:**
Run with `--debug` for verbose output:
```bash
xrdcp --debug 2 /tmp/test.txt root://localhost:1094//test.txt
```

When repeating upload tests against the same destination path, prefer `xrdcp -f` so the client overwrites the target instead of failing early on an already-existing file.

**Error log shows "xrootd: thread pool 'default' not found":**
Add `thread_pool default threads=4 max_queue=65536;` at the top level of `nginx.conf` (outside `stream {}`), or compile with `--with-threads`.

**WebDAV `curl -k https://localhost:8443//file` returns 403:**
Either `xrootd_webdav_auth` is set to `required` and no certificate/token was provided,
or `xrootd_webdav_allow_write` is off and the client tried a write operation.
Check the nginx error log: `tail -f /usr/local/nginx/logs/error.log`.

**WebDAV `xrdcp davs://` fails with SSL handshake error:**
The server certificate may not be trusted by the XRootD client. Either use a
CA-signed cert, or set `XRD_REQUESTTIMEOUT=60` and pass `--cacert /etc/nginx/server.crt`
to configure trust. For testing, `curl -k` skips verification; xrdcp does not
have an equivalent flag so use a real certificate for davs:// testing.

**S3 `curl` returns 404 on a key that exists:**
Check that the bucket name in the URL matches `xrootd_s3_bucket` in the config.
The S3 module uses path-style routing: `http://host/BUCKET/key`.

**S3 `aws s3` returns `SignatureDoesNotMatch`:**
The access key and secret key in the environment must match `xrootd_s3_access_key`
and `xrootd_s3_secret_key` in the nginx config. If S3 auth is disabled (no key
configured), any credentials work.

**nginx fails to start with "unknown directive xrootd_webdav":**
The module must be compiled with `--with-http_ssl_module` for WebDAV over HTTPS.
Re-run `./configure --with-stream --with-http_ssl_module --with-threads --add-module=...`.
