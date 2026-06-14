# RPM Package Build

Building and distributing nginx-xrootd as an RPM for RHEL/AlmaLinux — for sites that deploy everything through a package manager. For general build instructions, see [Build Guide](build-guide.md).

From a fresh AlmaLinux host to a running `root://` server that authenticates clients via x509 proxy certificate (GSI) and serves files from a local POSIX directory — packaged as an RPM.

**What you will have at the end:**

- An nginx process listening on port 1094 (`root://`) and port 1095 (`root://` + GSI)
- A self-signed test CA, a host certificate, a user certificate, and a proxy
  credential — enough to test end-to-end without an external grid CA
- A data directory readable and writable by authenticated clients
- Verification with `xrdcp` and `xrdfs`

If you already have real grid certificates (from your institution's grid CA)
and a real proxy from `voms-proxy-init`, skip §2 and §3 and plug the real
paths into §4.

---

## 0. Prerequisites

- AlmaLinux 8, 9, 10, or 11 (adjust repo steps as noted)
- `docker` or `podman` for the container RPM build (§1)
- Network access from the build host to download packages

---

## 1. Build the RPM

The RPM is built inside a container so the host needs no RPM build toolchain.
The only requirement is a working container engine.

```bash
# AlmaLinux 9 (default)
packaging/rpm/build-rpm-container.sh -v 0.1.0

# AlmaLinux 8
packaging/rpm/build-rpm-container.sh -d alma8 -v 0.1.0

# AlmaLinux 10
packaging/rpm/build-rpm-container.sh -d alma10 -v 0.1.0

# AlmaLinux 11 (once almalinux:11 is published)
packaging/rpm/build-rpm-container.sh -d alma11 -v 0.1.0
```

Built RPMs appear in `dist/`.  The `nginx-mod-xrootd-*.rpm` is the installable
module package; the `.src.rpm` is the source package.

```
dist/
  nginx-mod-xrootd-0.1.0-1.el9.x86_64.rpm   ← install this
  nginx-mod-xrootd-0.1.0-1.el9.src.rpm
```

---

## 2. Install on the target host

### 2.1 Enable required repositories

```bash
# EPEL (nginx-mod-stream, pcre2, openssl-libs)
sudo dnf install -y epel-release

# WLCG repository — provides voms-libs (required runtime dependency)
# AlmaLinux 8:
sudo dnf install -y https://linuxsoft.cern.ch/wlcg/el8/x86_64/wlcg-repo-1.0.0-1.el8.noarch.rpm
# AlmaLinux 9:
sudo dnf install -y https://linuxsoft.cern.ch/wlcg/el9/x86_64/wlcg-repo-1.0.0-1.el9.noarch.rpm
# AlmaLinux 10+ — monitor https://linuxsoft.cern.ch/wlcg/ for availability.
# Until the EL10 repo is published, use --nodeps and install voms-libs separately.
```

### 2.2 Install the RPM

```bash
sudo dnf install -y dist/nginx-mod-xrootd-0.1.0-1.el9.x86_64.rpm
```

This pulls in `nginx-mod-stream`, `openssl-libs`, `voms-libs`, and `curl`
as declared runtime dependencies, and drops a module loader snippet under
`/etc/nginx/modules-enabled/` (or the equivalent `nginx_modconfdir` for your
distribution).

Verify the modules are present:

```bash
ls /usr/lib64/nginx/modules/ngx_stream_xrootd_module.so
ls /usr/lib64/nginx/modules/ngx_http_xrootd_webdav_module.so
```

---

## 3. Create a test PKI (skip if you have real grid certificates)

This section creates a self-signed CA, a host certificate for nginx, a user
certificate, and a short-lived proxy credential.  Everything is self-signed and
local — no external CA is involved.

### 3.1 Set up the working directory

```bash
PKI=/etc/grid-security/test-pki

sudo mkdir -p $PKI/{ca,server,user}
```

### 3.2 Create the test CA

```bash
sudo bash -c "cd $PKI/ca && \
    openssl genrsa -out ca.key 4096 && \
    chmod 400 ca.key && \
    openssl req -new -x509 \
        -key ca.key \
        -out ca.pem \
        -days 3650 \
        -subj '/DC=test/DC=example/CN=Test Grid CA' \
        -addext 'basicConstraints=critical,CA:TRUE' \
        -addext 'subjectKeyIdentifier=hash' \
        -addext 'keyUsage=critical,keyCertSign,cRLSign'"

# Create hash symlinks so OpenSSL and XRootD can find the CA by subject hash
sudo bash -c "cd $PKI/ca && \
    NEW_HASH=\$(openssl x509 -in ca.pem -noout -subject_hash) && \
    OLD_HASH=\$(openssl x509 -in ca.pem -noout -subject_hash_old) && \
    ln -sf ca.pem \${NEW_HASH}.0 && \
    ln -sf ca.pem \${OLD_HASH}.0 && \
    CA_DN='/DC=test/DC=example/CN=Test Grid CA' && \
    for HASH in \$NEW_HASH \$OLD_HASH; do
        printf 'access_id_CA    X509    \"%s\"\npos_rights      globus  CA:sign\ncond_subjects   globus  \"/DC=test/DC=example/*\"\n' \
            \"\$CA_DN\" > \${HASH}.signing_policy
    done"
```

### 3.3 Create the host certificate

The Common Name must match the hostname that clients will use in `root://hostname/`.

```bash
sudo bash -c "cd $PKI/server && \
    openssl genrsa -out hostkey.pem 2048 && \
    chmod 400 hostkey.pem && \
    openssl req -new \
        -key hostkey.pem \
        -out host.csr \
        -subj '/DC=test/DC=example/CN=$(hostname -f)' && \
    openssl x509 -req \
        -in host.csr \
        -CA $PKI/ca/ca.pem \
        -CAkey $PKI/ca/ca.key \
        -CAcreateserial \
        -out hostcert.pem \
        -days 365"

# nginx workers run as the nginx user and must read the host key
sudo chmod 440 $PKI/server/hostkey.pem
sudo chgrp nginx $PKI/server/hostkey.pem
```

Verify:

```bash
openssl verify -CAfile $PKI/ca/ca.pem $PKI/server/hostcert.pem
# hostcert.pem: OK
```

### 3.4 Create a user certificate

```bash
sudo bash -c "cd $PKI/user && \
    openssl genrsa -out userkey.pem 2048 && \
    chmod 400 userkey.pem && \
    openssl req -new \
        -key userkey.pem \
        -out user.csr \
        -subj '/DC=test/DC=example/CN=Test User/CN=12345' && \
    openssl x509 -req \
        -in user.csr \
        -CA $PKI/ca/ca.pem \
        -CAkey $PKI/ca/ca.key \
        -CAcreateserial \
        -out usercert.pem \
        -days 365"
```

### 3.5 Create an RFC 3820 proxy certificate

XRootD's GSI layer requires a proxy certificate (a short-lived credential
derived from the user certificate, with a `proxyCertInfo` extension).  The
`make_proxy.py` helper in this repository generates a conformant proxy:

```bash
# Install the cryptography library if not already present
pip3 install cryptography

python3 utils/make_proxy.py "$PKI"
# Writes: $PKI/user/proxy_std.pem  (proxy cert + user cert + proxy key, mode 0400)
```

Verify the proxy chain:

```bash
openssl x509 -in $PKI/user/proxy_std.pem -noout -subject -dates
openssl verify -CAfile $PKI/ca/ca.pem \
    -untrusted $PKI/user/usercert.pem \
    $PKI/user/proxy_std.pem
```

---

## 4. Create the data directory

```bash
sudo mkdir -p /srv/xrootd/data
sudo chown nginx:nginx /srv/xrootd/data
sudo chmod 750 /srv/xrootd/data

# Seed a test file
echo "hello from nginx-xrootd" | sudo tee /srv/xrootd/data/hello.txt > /dev/null
```

---

## 5. Write the nginx configuration

Create `/etc/nginx/conf.d/xrootd.conf`:

```nginx
# nginx-xrootd: anonymous root:// + GSI-authenticated root://
# Serves files from /srv/xrootd/data on both listeners.

stream {
    # Thread pool for async file I/O.
    # Without this, a slow disk read blocks all connections on the worker.
    thread_pool xrootd_pool threads=8 max_queue=4096;

    # ── Port 1094: anonymous access (no credentials required) ──────────────
    server {
        listen 1094;
        xrootd on;
        xrootd_root /srv/xrootd/data;
        xrootd_thread_pool xrootd_pool;
        xrootd_access_log /var/log/nginx/xrootd_anon.log;
    }

    # ── Port 1095: GSI / x509 proxy-certificate authentication ─────────────
    server {
        listen 1095;
        xrootd on;
        xrootd_auth gsi;
        xrootd_allow_write on;
        xrootd_root /srv/xrootd/data;
        xrootd_thread_pool xrootd_pool;

        # Server identity presented to clients during the GSI DH exchange
        xrootd_certificate     /etc/grid-security/test-pki/server/hostcert.pem;
        xrootd_certificate_key /etc/grid-security/test-pki/server/hostkey.pem;

        # CA(s) trusted to vouch for client proxy certificates.
        # Point at the directory that contains the hash symlinks (§3.2).
        xrootd_trusted_ca      /etc/grid-security/test-pki/ca/ca.pem;

        xrootd_access_log /var/log/nginx/xrootd_gsi.log;
    }
}
```

> **Using real grid certificates?**
> Replace the `xrootd_certificate*` and `xrootd_trusted_ca` paths with your
> real host certificate, key, and the IGTF CA bundle (usually
> `/etc/grid-security/certificates/`).  Point `xrootd_trusted_ca` at the
> directory if it contains hash-named symlinks, or at a bundle `.pem` file.

### 5.1 Check the configuration

```bash
# The stream block must be at the top level, not inside http {}.
# nginx-mod-stream must be loaded.  Confirm the loader snippet is present:
ls /etc/nginx/modules-enabled/mod-xrootd.conf

sudo nginx -t
# nginx: the configuration file /etc/nginx/nginx.conf syntax is ok
# nginx: configuration file /etc/nginx/nginx.conf test is successful
```

If `nginx -t` reports `unknown directive "xrootd"`, the module is not loaded.
Check that `/etc/nginx/nginx.conf` includes files from `modules-enabled/` or
add `include /etc/nginx/modules-enabled/*.conf;` at the top of `nginx.conf`.

---

## 6. Open firewall ports

```bash
sudo firewall-cmd --permanent --add-port=1094/tcp
sudo firewall-cmd --permanent --add-port=1095/tcp
sudo firewall-cmd --reload
```

---

## 7. Start nginx

```bash
sudo systemctl enable --now nginx
# or, if nginx is already running:
sudo systemctl reload nginx
```

Check that both ports are listening:

```bash
ss -tlnp | grep -E '1094|1095'
# LISTEN  0  128  0.0.0.0:1094  ...
# LISTEN  0  128  0.0.0.0:1095  ...
```

---

## 8. Test

Install the XRootD client tools if not already present:

```bash
sudo dnf install -y xrootd-client   # also installs xrdcp, xrdfs
```

### 8.1 Anonymous access (port 1094)

No credentials needed.

```bash
# List root directory
xrdfs root://localhost:1094 ls /

# Download the seeded file
xrdcp root://localhost:1094//hello.txt /tmp/hello_anon.txt
cat /tmp/hello_anon.txt
# hello from nginx-xrootd

# Upload a file
echo "anonymous upload" > /tmp/anon_upload.txt
xrdcp /tmp/anon_upload.txt root://localhost:1094//anon_upload.txt
```

> Anonymous upload only succeeds if the listener has `xrootd_allow_write on`.
> The port-1094 server in the example config above does **not** — add it if
> you want anonymous writes.

### 8.2 GSI-authenticated access (port 1095)

```bash
# Point the client at the proxy and CA bundle
export X509_USER_PROXY=/etc/grid-security/test-pki/user/proxy_std.pem
export X509_CERT_DIR=/etc/grid-security/test-pki/ca

# List the root
xrdfs root://localhost:1095 ls /

# Upload a file (allowed because xrootd_allow_write on)
echo "gsi upload" > /tmp/gsi_upload.txt
xrdcp /tmp/gsi_upload.txt root://localhost:1095//gsi_upload.txt

# Download it back
xrdcp root://localhost:1095//gsi_upload.txt /tmp/gsi_upload_back.txt
diff /tmp/gsi_upload.txt /tmp/gsi_upload_back.txt
# (no output = identical)

# Confirm the authenticated DN in the access log
sudo tail -5 /var/log/nginx/xrootd_gsi.log
```

The GSI access log line looks like:

```
127.0.0.1 gsi "/DC=test/DC=example/CN=Test User/CN=12345/CN=12346" \
    [14/Apr/2026:10:23:44 +0000] "OPEN /gsi_upload.txt" OK 0 12ms
```

### 8.3 Reject without a proxy (sanity check)

```bash
unset X509_USER_PROXY
xrdfs root://localhost:1095 ls /
# [ERROR] Server responded with an error: [3010] kXR_NotAuthorized ...
```

---

## 9. Troubleshooting

| Symptom | Check |
|---|---|
| `unknown directive "xrootd"` | Module loader snippet not included in `nginx.conf` |
| `nginx -t` passes but port not open | SELinux or firewall blocking; check `ausearch -m AVC` and `firewall-cmd --list-all` |
| GSI: `kXR_NotAuthorized` | CA hash symlinks missing (§3.2), or `xrootd_trusted_ca` points at wrong path |
| GSI: `server cert not trusted` | Client does not trust the server's CA; set `X509_CERT_DIR` to the CA directory |
| GSI: `proxy certificate rejected` | Proxy not RFC 3820 — regenerate with `utils/make_proxy.py` |
| `Permission denied` on data directory | `nginx` user cannot read/write `/srv/xrootd/data`; fix ownership (§4) |
| `hostkey.pem: permission denied` | `nginx` group cannot read the key; fix with `chmod 440 / chgrp nginx` (§3.3) |
| SELinux denying nginx reading the key | `sudo semanage fcontext -a -t cert_t '/etc/grid-security(/.*)?'` + `restorecon -Rv /etc/grid-security` |

### Reading nginx error logs

```bash
sudo journalctl -u nginx -f
# or
sudo tail -f /var/log/nginx/error.log
```

The module logs GSI errors at `[error]` level and diagnostic notices at
`[notice]` level in the nginx error log.

---

## 10. Next steps

| Goal | Where to look |
|---|---|
| TLS-encrypted `root://` (protect file data in transit) | [docs/tls.md](tls-config.md) — `xrootd_tls on` or `roots://` |
| WebDAV (`davs://`) over HTTPS | [WebDAV overview](../04-protocols/webdav-overview.md) |
| Token (JWT/WLCG bearer) authentication | [docs/authentication.md](../06-authentication/auth-overview.md) §Token |
| VO / FQAN ACLs with VOMS | [docs/authentication.md](../06-authentication/auth-overview.md) §VOMS, `xrootd_require_vo` |
| S3-compatible endpoint | [docs/configuration/directives.md](directives.md) `xrootd_s3` |
| Prometheus metrics | [docs/metrics-and-logging.md](../08-metrics-monitoring/monitoring-guide.md) |
| CRL checking | [docs/configuration/directives.md](directives.md) `xrootd_crl` |
| Production PKI (real IGTF/grid CA) | [PKI setup](../06-authentication/test-pki-setup.md) |
