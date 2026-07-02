# First Server: verify your installation

> Verify all three protocol paths work before adding authentication or deploying to production.

---

## What you'll test

| Protocol | URL format | Client tool | Status |
|---|---|---|---|
| XRootD (TCP) | `root://localhost:1094//path` | `xrdcp`, `xrdfs` | ✅ Basic connectivity |
| XRootD (TLS) | `roots://localhost:1095//path` | `xrdcp --allow-tls` | ⏭️ Optional — requires TLS config |
| WebDAV (HTTP) | `http://localhost:8443/path` | `curl`, `xrdcp --allow-http` | ⏭️ Optional — requires HTTP module |

---

## Prerequisites

You should have already completed the [Quick Install](quick-install.md). Your server must be running with at least the XRootD (`root://`) protocol enabled.

---

## Test 1: Verify nginx is running

```bash
# Check if nginx process exists
ps aux | grep nginx

# Check listening ports
sudo ss -tlnp | grep -E '1094|1095|8443|9100'
```

Expected output should show nginx processes and port 1094 (XRootD) listening.

---

## Test 2: XRootD file upload (write test)

```bash
# Create a test file locally
echo "This is a test file for verification" > /tmp/verify-test.txt

# Upload to the server using xrdcp
xrdcp /tmp/verify-test.txt root://localhost:1094//data/publications/verify-uploaded.txt
```

If successful, you'll see output like:
```
transferred 39 bytes in 0.0 seconds (0.8 kbytes/s)
```

---

## Test 3: XRootD file download (read test)

```bash
# Download the file back from the server
xrdcp root://localhost:1094//data/publications/verify-uploaded.txt /tmp/verify-downloaded.txt

# Compare the files — they should be identical
diff /tmp/verify-test.txt /tmp/verify-downloaded.txt && echo "Files match!"
```

---

## Test 4: XRootD directory listing (browse test)

```bash
# List files on the server using xrdfs
xrdfs localhost ls /data/publications/
```

Expected output includes `verify-uploaded.txt`.

---

## Test 5: Metrics endpoint (observability test)

```bash
# Query the Prometheus metrics endpoint
curl -s http://localhost:9100/metrics | grep xrootd_requests_total

# Expected output should show request counters incrementing as you use the server
```

Example output:
```
xrootd_requests_total{proto="root",op="read",status="ok"} 2
xrootd_requests_total{proto="root",op="write",status="ok"} 1
xrootd_requests_total{proto="root",op="dirlist",status="ok"} 1
```

---

## Test 6: File operations (basic filesystem tests)

### Create a directory
```bash
xrdfs localhost mkdir /data/publications/test-dir
xrdfs localhost ls /data/publications/ | grep test-dir
```

### Remove a directory
```bash
xrdfs localhost rmdir /data/publications/test-dir
```

---

## Summary checklist

| Test | Command | Pass criteria |
|---|---|---|
| nginx running | `ps aux \| grep nginx` | Process exists, listening on 1094 |
| Upload file | `xrdcp ... root://localhost:1094//...` | Transfer completes without error |
| Download file | `xrdcp root://localhost:1094//... /local/path` | File received and matches source |
| Directory listing | `xrdfs localhost ls /path` | Shows uploaded files |
| Metrics available | `curl http://localhost:9100/metrics` | Returns Prometheus format data |

---

## If everything passes

You have a working gnuBall server. Before putting it in production, you should:

1. **Add authentication** — See [Authentication Overview](../06-authentication/)
2. **Enable TLS/HTTPS** — See [TLS Configuration](../03-configuration/tls-config.md) for `roots://` support
3. **Set up monitoring** — Configure Prometheus to scrape your `/metrics` endpoint

## If something fails

Check the nginx error log:
```bash
sudo tail -f /usr/local/nginx/logs/error.log
```

Common issues and fixes are in the [Troubleshooting](getting-started-full.md) section of the quick install guide.
