# Deployment Configuration Reference

This page gives side-by-side, commented deployment snippets for common
BriX-Cache and vanilla XRootD roles. The examples intentionally use
placeholder hostnames and filesystem paths, and they include no private keys,
tokens, proxy contents, passwords, or shared secrets.

Assumptions used by every section:

- Data is exported from `/srv/brix/export`.
- Cache data lives under `/srv/brix/cache`.
- Host certificates are installed at `/etc/grid-security/hostcert.pem` and
  `/etc/grid-security/hostkey.pem`.
- Grid trust anchors are installed in `/etc/grid-security/certificates`.
- Token examples use issuer `https://idp.example.com`, audience `my-storage`,
  and a public JWKS file at `/etc/tokens/storage-jwks.json`.
- Grid-mapfile examples use `/etc/grid-security/grid-mapfile` and placeholder
  local pool accounts such as `alice` and `bob`.
- Packet-marking examples report Fireflies to `flowd.example.org:10514` and use
  a local SciTags registry file at `/etc/brix/scitags.json`.
- Example cache origins use `origin.example.org:1094`.
- CERN EOS cache examples use `eoslhcb.cern.ch:1094` and `/eos/lhcb` as a
  concrete EOS door and namespace; replace both with the experiment EOS service
  and prefix for the site.
- The service account running nginx or XRootD can read the host certificate,
  host key, CA directory, token JWKS file, and any configured proxy credential
  path.
- Vanilla XRootD token examples assume the `ztn` security protocol and
  `libXrdAccSciTokens.so` authorization plugin are installed.

For GSI cache-origin examples, the proxy file path is only a reference to a
short-lived credential managed outside this document. The file itself contains a
private key and must not be committed, pasted into config management, or made
world-readable.

## 1. Insecure Read-Write root:// Fileserver

No client credential is required. Use only on an isolated network or for data
where anonymous read-write access is intentional.

<table>
<thead>
<tr>
<th>nginx + xrootd module</th>
<th>Vanilla XRootD</th>
</tr>
</thead>
<tbody>
<tr>
<td>
<pre><code class="language-nginx"># /etc/nginx/nginx.conf
&#32;
worker_processes auto;
thread_pool default threads=8 max_queue=65536;
&#32;
events {
    worker_connections 4096;
}
&#32;
stream {
    server {
        # Clients use root://host.example.org:1094//path.
        listen 1094;
&#32;
        # Enable the native XRootD stream protocol.
        brix_root on;
&#32;
        # Map client path "/" to this local directory.
        brix_export /srv/brix/export;
&#32;
        # Explicitly document anonymous access.
        # This is also the module default.
        brix_auth none;
&#32;
        # Allow write and namespace-changing operations.
        # Without this, the server is read-only.
        brix_allow_write on;
&#32;
        # Keep blocking filesystem work off the event loop.
        brix_thread_pool default;
    }
}
</code></pre>
</td>
<td>
<pre><code class="language-text"># /etc/brix/brix.cfg
&#32;
# Native XRootD listener for root://.
xrd.port 1094
&#32;
# Runtime and IPC locations for the daemon.
all.adminpath /var/spool/brix
all.pidpath /run/brix
&#32;
# Export the whole logical namespace and allow writes.
all.export / rw
&#32;
# Map exported paths below "/" onto local storage.
oss.localroot /srv/brix/export
&#32;
# No xrootd.seclib, sec.protocol, or sec.protbind lines:
# clients are anonymous.
</code></pre>
</td>
</tr>
</tbody>
</table>

## 2. Insecure Read-Write http:// Fileserver

No client credential is required. The nginx example exposes WebDAV over cleartext
HTTP. The XRootD example exposes the XrdHttp plugin over cleartext HTTP.

<table>
<thead>
<tr>
<th>nginx + xrootd module</th>
<th>Vanilla XRootD</th>
</tr>
</thead>
<tbody>
<tr>
<td>
<pre><code class="language-nginx"># /etc/nginx/nginx.conf
&#32;
worker_processes auto;
&#32;
events {
    worker_connections 4096;
}
&#32;
http {
    server {
        # Clients use http://host.example.org:8080/path.
        listen 8080;
&#32;
        # Large PUTs need a body limit above the expected object size.
        client_max_body_size 0;
&#32;
        location / {
            # Enable the WebDAV data-plane handler.
            brix_webdav on;
&#32;
            # Map URL path "/" to this local directory.
            brix_export /srv/brix/export;
&#32;
            # Explicit anonymous HTTP/WebDAV access.
            brix_webdav_auth none;
&#32;
            # Allow PUT, DELETE, MKCOL, and writable COPY paths.
            brix_allow_write on;
        }
    }
}
</code></pre>
</td>
<td>
<pre><code class="language-text"># /etc/brix/brix.cfg
&#32;
# Keep a native root:// port available for tools that expect it.
xrd.port 1094
&#32;
# Add cleartext HTTP on port 8080 using XrdHttp.
xrd.protocol XrdHttp:8080 libXrdHttp.so
&#32;
all.adminpath /var/spool/brix
all.pidpath /run/brix
&#32;
# Export the full namespace with write permission.
all.export / rw
&#32;
# Local filesystem root for exported paths.
oss.localroot /srv/brix/export
&#32;
# No sec.protocol binding is configured, so HTTP clients are anonymous.
</code></pre>
</td>
</tr>
</tbody>
</table>

## 3. root:// Fileserver With Token Support

Clients authenticate with a WLCG/JWT bearer token during the native XRootD
`ztn` security exchange. The token contains the storage scopes that authorize
reads, writes, and namespace operations.

<table>
<thead>
<tr>
<th>nginx + xrootd module</th>
<th>Vanilla XRootD</th>
</tr>
</thead>
<tbody>
<tr>
<td>
<pre><code class="language-nginx"># /etc/nginx/nginx.conf
&#32;
worker_processes auto;
thread_pool default threads=8 max_queue=65536;
&#32;
events {
    worker_connections 4096;
}
&#32;
stream {
    server {
        # Clients use root://host.example.org:1094//path and provide a
        # bearer token through the XRootD ztn security protocol.
        listen 1094;
&#32;
        brix_root on;
        brix_export /srv/brix/export;
&#32;
        # Require a valid bearer token for every native XRootD session.
        brix_auth token;
&#32;
        # Write operations still need both this server-wide gate and an
        # appropriate storage.write or storage.create token scope.
        brix_allow_write on;
&#32;
        # Public signing keys trusted for token validation.
        brix_token_jwks /etc/tokens/storage-jwks.json;
&#32;
        # Reject tokens from other issuers or for other audiences.
        brix_token_issuer   "https://idp.example.com";
        brix_token_audience "my-storage";
&#32;
        brix_thread_pool default;
    }
}
</code></pre>
</td>
<td>
<pre><code class="language-text"># /etc/brix/brix.cfg
&#32;
xrd.port 1094
all.adminpath /var/spool/brix
all.pidpath /run/brix
&#32;
# Export the full namespace with write permission. SciTokens scopes
# decide which authenticated token holders may actually use it.
all.export / rw
oss.localroot /srv/brix/export
&#32;
# Load XRootD security plugins and require ztn bearer-token auth.
xrootd.seclib libXrdSec.so
sec.protocol ztn
sec.protbind * only ztn
&#32;
# Enforce token scopes with the SciTokens authorization plugin.
ofs.authorize 1
ofs.authlib libXrdAccSciTokens.so config=/etc/brix/scitokens.cfg
&#32;
# /etc/brix/scitokens.cfg
&#32;
[Global]
# Must match the token aud claim.
audience = my-storage
&#32;
# Token-only server: missing or unauthorized tokens fail closed.
onmissing = deny
&#32;
[Issuer Example]
# Must match the token iss claim.
issuer = https://idp.example.com
&#32;
# Token storage scopes are interpreted relative to this local namespace.
base_path = /
&#32;
# Authorize token access from explicit storage.* scopes.
authorization_strategy = capability
</code></pre>
</td>
</tr>
</tbody>
</table>

## 4. Anonymous root:// + http:// Fileserver

Both native `root://` and cleartext HTTP/WebDAV clients are anonymous. This is a
single-host version of the first two sections and is appropriate only when
anonymous read-write access is intentional.

<table>
<thead>
<tr>
<th>nginx + xrootd module</th>
<th>Vanilla XRootD</th>
</tr>
</thead>
<tbody>
<tr>
<td>
<pre><code class="language-nginx"># /etc/nginx/nginx.conf
&#32;
worker_processes auto;
thread_pool default threads=8 max_queue=65536;
&#32;
events {
    worker_connections 4096;
}
&#32;
stream {
    server {
        # Clients use root://host.example.org:1094//path.
        listen 1094;
&#32;
        brix_root on;
        brix_export /srv/brix/export;
&#32;
        # Anonymous native XRootD access.
        brix_auth none;
        brix_allow_write on;
&#32;
        brix_thread_pool default;
    }
}
&#32;
http {
    server {
        # Clients use http://host.example.org:8080/path.
        listen 8080;
&#32;
        client_max_body_size 0;
&#32;
        location / {
            brix_webdav on;
            brix_export /srv/brix/export;
&#32;
            # Anonymous HTTP/WebDAV access.
            brix_webdav_auth none;
            brix_allow_write on;
        }
    }
}
</code></pre>
</td>
<td>
<pre><code class="language-text"># /etc/brix/brix.cfg
&#32;
# Native root:// listener.
xrd.port 1094
&#32;
# Cleartext HTTP listener using XrdHttp.
xrd.protocol XrdHttp:8080 libXrdHttp.so
&#32;
all.adminpath /var/spool/brix
all.pidpath /run/brix
&#32;
# Export one shared namespace for both protocols with write permission.
all.export / rw
oss.localroot /srv/brix/export
&#32;
# No xrootd.seclib, sec.protocol, or sec.protbind lines:
# both root:// and http:// clients are anonymous.
</code></pre>
</td>
</tr>
</tbody>
</table>

## 5. root:// Fileserver With Firefly Packet Marking And No Auth

Clients are anonymous, but data flows are reported to a SciTags/Firefly
collector. These examples intentionally keep only the Firefly path enabled for
parity; BriX-Cache can also stamp IPv6 flow labels by setting
`brix_pmark_flowlabel on`.

<table>
<thead>
<tr>
<th>nginx + xrootd module</th>
<th>Vanilla XRootD</th>
</tr>
</thead>
<tbody>
<tr>
<td>
<pre><code class="language-nginx"># /etc/nginx/nginx.conf
&#32;
worker_processes auto;
thread_pool default threads=8 max_queue=65536;
&#32;
events {
    worker_connections 4096;
}
&#32;
stream {
    server {
        # Clients use root://host.example.org:1094//path.
        listen 1094;
&#32;
        brix_root on;
        brix_export /srv/brix/export;
&#32;
        # Anonymous root:// access; packet marking is accounting only.
        brix_auth none;
&#32;
        # Keep this example read-only even though it is anonymous.
        brix_allow_write off;
&#32;
        # Enable SciTags packet marking for root:// transfers.
        brix_pmark on;
        brix_pmark_firefly on;
        brix_pmark_scitag_cgi on;
&#32;
        # Firefly-only parity with stock XRootD. Set this on if the
        # deployment wants BriX-Cache's IPv6 flow-label marking too.
        brix_pmark_flowlabel off;
&#32;
        # UDP collector for RFC5424-wrapped Firefly JSON datagrams.
        brix_pmark_firefly_dest flowd.example.org:10514;
&#32;
        # Local SciTags experiment/activity registry.
        brix_pmark_defsfile /etc/brix/scitags.json;
&#32;
        # Default tag used when the client sends no scitag.flow opaque value.
        brix_pmark_map_experiment default example;
        brix_pmark_map_activity   example default default;
&#32;
        brix_thread_pool default;
    }
}
&#32;
# /etc/brix/scitags.json
&#32;
{
  "modified": "2026-06-22",
  "experiments": [
    {
      "expName": "example",
      "expId": 1,
      "activities": [
        { "activityName": "default", "activityId": 1 },
        { "activityName": "read",    "activityId": 2 }
      ]
    }
  ]
}
</code></pre>
</td>
<td>
<pre><code class="language-text"># /etc/brix/brix.cfg
&#32;
xrd.port 1094
all.adminpath /var/spool/brix
all.pidpath /run/brix
&#32;
# Anonymous read-only export.
all.export / r/o
oss.localroot /srv/brix/export
&#32;
# Enable Firefly packet marking. Stock XRootD emits Firefly UDP reports;
# flow-label parsing exists in config but is not the deployed data path.
pmark use noflowlabel firefly scitag
pmark domain remote
pmark ffdest flowd.example.org:10514
&#32;
# Local SciTags registry. nofail keeps the data server up if the file is
# temporarily unavailable; marking then simply does not resolve named tags.
pmark defsfile nofail /etc/brix/scitags.json
&#32;
# Default tag used when the client sends no scitag.flow opaque value.
pmark map2exp default example
pmark map2act example default default
&#32;
# /etc/brix/scitags.json
&#32;
{
  "modified": "2026-06-22",
  "experiments": [
    {
      "expName": "example",
      "expId": 1,
      "activities": [
        { "activityName": "default", "activityId": 1 },
        { "activityName": "read",    "activityId": 2 }
      ]
    }
  ]
}
</code></pre>
</td>
</tr>
</tbody>
</table>

## 6. root:// Fileserver With GSI Enabled

Clients authenticate with the XRootD GSI exchange. The data channel remains
native `root://`; use `roots://` or HTTPS when transport encryption is also
required.

<table>
<thead>
<tr>
<th>nginx + xrootd module</th>
<th>Vanilla XRootD</th>
</tr>
</thead>
<tbody>
<tr>
<td>
<pre><code class="language-nginx"># /etc/nginx/nginx.conf
&#32;
worker_processes auto;
thread_pool default threads=8 max_queue=65536;
&#32;
events {
    worker_connections 4096;
}
&#32;
stream {
    server {
        # Clients use root://host.example.org:1094//path.
        listen 1094;
&#32;
        brix_root on;
        brix_export /srv/brix/export;
&#32;
        # Require GSI during the native XRootD login/auth flow.
        brix_auth gsi;
&#32;
        # Allow authenticated clients to perform writes.
        brix_allow_write on;
&#32;
        # Host credential presented by the server.
        brix_certificate     /etc/grid-security/hostcert.pem;
        brix_certificate_key /etc/grid-security/hostkey.pem;
&#32;
        # Trust anchor used to verify client proxy chains.
        brix_trusted_ca /etc/grid-security/certificates;
&#32;
        brix_thread_pool default;
    }
}
</code></pre>
</td>
<td>
<pre><code class="language-text"># /etc/brix/brix.cfg
&#32;
xrd.port 1094
all.adminpath /var/spool/brix
all.pidpath /run/brix
&#32;
# Export the full namespace with write permission.
all.export / rw
oss.localroot /srv/brix/export
&#32;
# Load the XRootD security plugin collection.
xrootd.seclib libXrdSec.so
&#32;
# Configure GSI server identity and trusted CA directory.
# -gmapopt:10 accepts authenticated DNs without requiring a grid-mapfile.
# -dlgpxy:0 disables delegated-proxy creation on this storage server.
sec.protocol gsi -certdir:/etc/grid-security/certificates -cert:/etc/grid-security/hostcert.pem -key:/etc/grid-security/hostkey.pem -gmapopt:10 -dlgpxy:0
&#32;
# Require GSI for every client connection.
sec.protbind * only gsi
</code></pre>
</td>
</tr>
</tbody>
</table>

## 7. root:// GSI Fileserver With Explicit User Mapping

Both examples authenticate clients with GSI and use a grid-mapfile, but the files
mean different things. BriX-Cache uses `brix_gridmap` for optional
per-request UNIX impersonation; its authdb still matches the GSI DN. Vanilla
XRootD's GSI grid-mapfile maps the client DN to the local name that `acc.authdb`
then authorizes.

<table>
<thead>
<tr>
<th>nginx + xrootd module</th>
<th>Vanilla XRootD</th>
</tr>
</thead>
<tbody>
<tr>
<td>
<pre><code class="language-nginx"># /etc/nginx/nginx.conf
&#32;
# The master must start as root in map mode so it can spawn the small
# identity broker. Workers still run as an unprivileged service account.
user xrootd;
worker_processes auto;
thread_pool default threads=8 max_queue=65536;
&#32;
events {
    worker_connections 4096;
}
&#32;
stream {
    # Process-global broker settings. These can be placed in stream{}
    # because the broker is shared by the nginx instance.
    brix_impersonation map;
    brix_impersonation_socket /run/brix/impersonate.sock;
    brix_impersonation_export /srv/brix/export;
    brix_impersonation_broker_user xrootd-broker;
&#32;
    # DN to local account mapping used only by the impersonation broker.
    brix_gridmap /etc/grid-security/grid-mapfile;
&#32;
    # Fail closed for unmapped DNs by omitting brix_idmap_default_user.
    brix_idmap_min_uid 1000;
    brix_idmap_cache_ttl 600;
&#32;
    server {
        listen 1094;
&#32;
        brix_root on;
        brix_export /srv/brix/export;
        brix_auth gsi;
        brix_allow_write on;
&#32;
        brix_certificate     /etc/grid-security/hostcert.pem;
        brix_certificate_key /etc/grid-security/hostkey.pem;
        brix_trusted_ca      /etc/grid-security/certificates;
&#32;
        # Authorization is separate from impersonation. The authdb sees
        # the GSI DN, not the local account from the grid-mapfile.
        brix_authdb_format xrdacc;
        brix_authdb /etc/brix/authdb;
        brix_authdb_refresh 60;
        brix_authdb_audit deny;
&#32;
        brix_thread_pool default;
    }
}
&#32;
# /etc/grid-security/grid-mapfile
&#32;
"/DC=org/DC=example/CN=Alice Example" alice
"/DC=org/DC=example/CN=Bob Example" bob
&#32;
# /etc/brix/authdb
&#32;
# BriX-Cache authdb grants are keyed by the authenticated DN.
# The grid-mapfile controls the local uid/gid used for filesystem opens.
u /DC=org/DC=example/CN=Alice Example /users/alice a
u /DC=org/DC=example/CN=Bob Example   /users/bob   a
</code></pre>
</td>
<td>
<pre><code class="language-text"># /etc/brix/brix.cfg
&#32;
xrd.port 1094
all.adminpath /var/spool/brix
all.pidpath /run/brix
&#32;
all.export / rw
oss.localroot /srv/brix/export
&#32;
xrootd.seclib libXrdSec.so
&#32;
# GSI authenticates the client and maps a DN to a local name through
# /etc/grid-security/grid-mapfile. usedn keeps the DN when no mapping
# exists; remove usedn if unmapped users must fail at authentication.
sec.protparm gsi -ca:verify -certdir:/etc/grid-security/certificates
sec.protparm gsi -cert:/etc/grid-security/hostcert.pem
sec.protparm gsi -key:/etc/grid-security/hostkey.pem
sec.protparm gsi -gridmap:/etc/grid-security/grid-mapfile
sec.protparm gsi -gmapopt:trymap,usedn
sec.protparm gsi -dlgpxy:0
sec.protocol gsi
sec.protbind * only gsi
&#32;
# XRootD authdb sees the mapped local names alice and bob.
ofs.authorize 1
acc.authdb /etc/brix/authdb
&#32;
# /etc/grid-security/grid-mapfile
&#32;
"/DC=org/DC=example/CN=Alice Example" alice
"/DC=org/DC=example/CN=Bob Example" bob
&#32;
# /etc/brix/authdb
&#32;
u alice /users/alice a
u bob   /users/bob   a
</code></pre>
</td>
</tr>
</tbody>
</table>

## 8. root:// Fileserver With GSI Or Token Support

Clients may authenticate with either a GSI proxy certificate or a bearer token
on the same native `root://` listener. This is useful while a site is migrating
from GSI to token-based access.

<table>
<thead>
<tr>
<th>nginx + xrootd module</th>
<th>Vanilla XRootD</th>
</tr>
</thead>
<tbody>
<tr>
<td>
<pre><code class="language-nginx"># /etc/nginx/nginx.conf
&#32;
worker_processes auto;
thread_pool default threads=8 max_queue=65536;
&#32;
events {
    worker_connections 4096;
}
&#32;
stream {
    server {
        # Clients use root://host.example.org:1094//path.
        listen 1094;
&#32;
        brix_root on;
        brix_export /srv/brix/export;
&#32;
        # Accept either GSI or ztn bearer-token authentication.
        brix_auth both;
&#32;
        # Write requests still require brix_allow_write plus either
        # token storage scopes or the site's GSI authorization policy.
        brix_allow_write on;
&#32;
        # GSI server credential and client trust anchors.
        brix_certificate     /etc/grid-security/hostcert.pem;
        brix_certificate_key /etc/grid-security/hostkey.pem;
        brix_trusted_ca      /etc/grid-security/certificates;
&#32;
        # Token validation inputs. The JWKS file contains public keys only.
        brix_token_jwks /etc/tokens/storage-jwks.json;
        brix_token_issuer   "https://idp.example.com";
        brix_token_audience "my-storage";
&#32;
        brix_thread_pool default;
    }
}
</code></pre>
</td>
<td>
<pre><code class="language-text"># /etc/brix/brix.cfg
&#32;
xrd.port 1094
all.adminpath /var/spool/brix
all.pidpath /run/brix
&#32;
all.export / rw
oss.localroot /srv/brix/export
&#32;
# Load security plugins and advertise both token and GSI auth.
xrootd.seclib libXrdSec.so
sec.protocol ztn
sec.protocol gsi -certdir:/etc/grid-security/certificates -cert:/etc/grid-security/hostcert.pem -key:/etc/grid-security/hostkey.pem -gmapopt:10 -dlgpxy:0
sec.protbind * only ztn gsi
&#32;
# SciTokens authorizes scoped tokens first. The ++ chain lets GSI
# sessions, which normally have no bearer token, fall through to authdb.
ofs.authorize 1
ofs.authlib ++ libXrdAccSciTokens.so config=/etc/brix/scitokens.cfg
acc.authdb /etc/brix/authdb
&#32;
# /etc/brix/scitokens.cfg
&#32;
[Global]
audience = my-storage
&#32;
# Mixed GSI+token server: pass no-token GSI sessions to acc.authdb.
# Keep authdb rules specific to GSI identities or groups.
onmissing = passthrough
&#32;
[Issuer Example]
issuer = https://idp.example.com
base_path = /
&#32;
# Authorize token access from explicit storage.* scopes.
authorization_strategy = capability
&#32;
# /etc/brix/authdb
&#32;
# Example GSI DN grant. Replace this placeholder with site-approved
# GSI DNs, VO groups, roles, or compound XrdAcc rules.
u /DC=org/DC=example/CN=storage-user / a
</code></pre>
</td>
</tr>
</tbody>
</table>

## 9. https:// Fileserver With GSI Enabled

The nginx example is HTTPS WebDAV with RFC 3820 proxy-certificate verification
performed by the module. The XRootD example is XrdHttp over HTTPS with GSI
bound as the required security protocol.

<table>
<thead>
<tr>
<th>nginx + xrootd module</th>
<th>Vanilla XRootD</th>
</tr>
</thead>
<tbody>
<tr>
<td>
<pre><code class="language-nginx"># /etc/nginx/nginx.conf
&#32;
worker_processes auto;
&#32;
events {
    worker_connections 4096;
}
&#32;
http {
    server {
        # Clients use https://host.example.org:8443/path.
        listen 8443 ssl;
        server_name host.example.org;
&#32;
        # Host credential for the TLS server side.
        ssl_certificate     /etc/grid-security/hostcert.pem;
        ssl_certificate_key /etc/grid-security/hostkey.pem;
&#32;
        # Request the client certificate chain but do not let nginx reject
        # RFC 3820 proxy certificates before the module can verify them.
        ssl_verify_client optional_no_ca;
        ssl_verify_depth 10;
&#32;
        # Allow the module's WebDAV verifier to accept proxy certificates.
        brix_webdav_proxy_certs on;
&#32;
        client_max_body_size 0;
&#32;
        location / {
            brix_webdav on;
            brix_export /srv/brix/export;
&#32;
            # Require a valid TLS client proxy certificate.
            brix_webdav_auth required;
&#32;
            # CA directory used by the module for proxy-chain verification.
            brix_webdav_cadir /etc/grid-security/certificates;
&#32;
            # Allow writes only after authentication succeeds.
            brix_allow_write on;
        }
    }
}
</code></pre>
</td>
<td>
<pre><code class="language-text"># /etc/brix/brix.cfg
&#32;
# Keep the native port available for root:// clients if desired.
xrd.port 1094
&#32;
# Serve HTTPS through XrdHttp on port 8443.
xrd.protocol https:8443 libXrdHttp.so
&#32;
all.adminpath /var/spool/brix
all.pidpath /run/brix
&#32;
all.export / rw
oss.localroot /srv/brix/export
&#32;
# TLS host credential and CA trust for HTTPS.
xrd.tls /etc/grid-security/hostcert.pem /etc/grid-security/hostkey.pem
xrd.tlsca certdir /etc/grid-security/certificates
&#32;
# Load and configure GSI.
xrootd.seclib libXrdSec.so
sec.protocol gsi -certdir:/etc/grid-security/certificates -cert:/etc/grid-security/hostcert.pem -key:/etc/grid-security/hostkey.pem -gmapopt:10 -dlgpxy:0
&#32;
# Require GSI for clients reaching this XrdHttp endpoint.
sec.protbind * only gsi
</code></pre>
</td>
</tr>
</tbody>
</table>

## 10. https:// Fileserver With GSI And Grid-Mapfile

Clients use HTTPS/WebDAV and present GSI proxy certificates. The grid-mapfile
maps certificate DNs to local account names for per-user ownership or authdb
policy. The nginx grid-mapfile path belongs to the optional impersonation broker;
the XRootD path belongs to XrdHttp's client-certificate mapping.

<table>
<thead>
<tr>
<th>nginx + xrootd module</th>
<th>Vanilla XRootD</th>
</tr>
</thead>
<tbody>
<tr>
<td>
<pre><code class="language-nginx"># /etc/nginx/nginx.conf
&#32;
user xrootd;
worker_processes auto;
&#32;
events {
    worker_connections 4096;
}
&#32;
stream {
    # Global broker settings used by HTTP/WebDAV filesystem opens too.
    # Omit this block if the deployment only needs DN-based authdb
    # authorization and not per-user UNIX ownership.
    brix_impersonation map;
    brix_impersonation_socket /run/brix/impersonate.sock;
    brix_impersonation_export /srv/brix/export;
    brix_impersonation_broker_user xrootd-broker;
    brix_gridmap /etc/grid-security/grid-mapfile;
    brix_idmap_min_uid 1000;
}
&#32;
http {
    server {
        # Clients use https://host.example.org:8443/path.
        listen 8443 ssl;
        server_name host.example.org;
&#32;
        ssl_certificate     /etc/grid-security/hostcert.pem;
        ssl_certificate_key /etc/grid-security/hostkey.pem;
        ssl_verify_client optional_no_ca;
        ssl_verify_depth 10;
&#32;
        # Let the module verify RFC 3820 proxy chains.
        brix_webdav_proxy_certs on;
&#32;
        client_max_body_size 0;
&#32;
        location / {
            brix_webdav on;
            brix_export /srv/brix/export;
            brix_webdav_auth required;
            brix_webdav_cadir /etc/grid-security/certificates;
            brix_allow_write on;
&#32;
            # WebDAV authorization still matches the authenticated DN.
            # The grid-mapfile above controls the local user for I/O.
            brix_authdb_format xrdacc;
            brix_authdb /etc/brix/webdav-authdb;
            brix_authdb_refresh 60;
            brix_authdb_audit deny;
        }
    }
}
&#32;
# /etc/grid-security/grid-mapfile
&#32;
"/DC=org/DC=example/CN=Alice Example" alice
"/DC=org/DC=example/CN=Bob Example" bob
&#32;
# /etc/brix/webdav-authdb
&#32;
u /DC=org/DC=example/CN=Alice Example /users/alice a
u /DC=org/DC=example/CN=Bob Example   /users/bob   a
</code></pre>
</td>
<td>
<pre><code class="language-text"># /etc/brix/brix.cfg
&#32;
# Optional native root:// port for tools that expect a data-server port.
xrd.port 1094
&#32;
# HTTPS/WebDAV endpoint.
xrd.protocol XrdHttp:8443 libXrdHttp.so
&#32;
all.adminpath /var/spool/brix
all.pidpath /run/brix
&#32;
all.export / rw
oss.localroot /srv/brix/export
&#32;
# XrdHttp TLS identity and CA trust for client certificates.
http.cert  /etc/grid-security/hostcert.pem
http.key   /etc/grid-security/hostkey.pem
http.cadir /etc/grid-security/certificates
&#32;
# Extract the client X.509/GSI identity from the TLS connection.
# The library path may need the distribution-specific absolute path.
http.secxtractor required libXrdHttpVOMS.so
&#32;
# Require the DN to appear in the grid-mapfile and map it to a local name.
http.gridmap required /etc/grid-security/grid-mapfile
http.desthttps yes
&#32;
# Authorize the mapped local names from the grid-mapfile.
ofs.authorize 1
acc.authdb /etc/brix/authdb
&#32;
# /etc/grid-security/grid-mapfile
&#32;
"/DC=org/DC=example/CN=Alice Example" alice
"/DC=org/DC=example/CN=Bob Example" bob
&#32;
# /etc/brix/authdb
&#32;
u alice /users/alice a
u bob   /users/bob   a
</code></pre>
</td>
</tr>
</tbody>
</table>

## 11. XCache With Anonymous Clients And GSI Upstream

Clients do not authenticate to the cache. Cache misses authenticate from the
cache to the origin using a service proxy credential. The cache is read-only to
clients; it fills local files from the origin.

<table>
<thead>
<tr>
<th>nginx + xrootd module</th>
<th>Vanilla XRootD</th>
</tr>
</thead>
<tbody>
<tr>
<td>
<pre><code class="language-nginx"># /etc/nginx/nginx.conf
&#32;
worker_processes auto;
thread_pool brix_cache_io threads=8 max_queue=65536;
&#32;
events {
    worker_connections 4096;
}
&#32;
stream {
    server {
        # Clients use root://cache.example.org:1094//path.
        listen 1094;
&#32;
        brix_root on;
&#32;
        # Anonymous clients are allowed to read through the cache.
        brix_auth none;
&#32;
        # Cache mode is read-only; writes must stay disabled.
        brix_allow_write off;
&#32;
        # Namespace root used for path handling. In cache mode, hits are
        # served from brix_cache_export below.
        brix_export /srv/brix/cache;
&#32;
        # Enable read-through cache fills.
        brix_cache on;
        brix_cache_export /srv/brix/cache;
&#32;
        # Origin data server. Use roots:// here if the origin requires TLS.
        brix_cache_origin root://origin.example.org:1094;
&#32;
        # Service proxy used only for outbound origin fetches.
        # The file must be created and renewed outside nginx.
        brix_cache_origin_proxy /run/brix/cache-fetcher.proxy;
        brix_cache_origin_cadir /etc/grid-security/certificates;
        brix_cache_origin_client /usr/bin/xrdcp;
&#32;
        # Operational cache policy.
        brix_cache_lock_timeout 300s;
        brix_cache_eviction_threshold 90%;
        brix_cache_max_file_size 100g;
&#32;
        brix_thread_pool brix_cache_io;
    }
}
</code></pre>
</td>
<td>
<pre><code class="language-text"># /etc/brix/brix.cfg
&#32;
# Client-facing cache listener.
xrd.port 1094
&#32;
all.adminpath /var/spool/brix
all.pidpath /run/brix
&#32;
# Anonymous clients can read the cached namespace.
# Cache fill writes are internal to PFC, so the client export stays read-only.
all.export / r/o
&#32;
# PSS proxies reads to the origin; PFC stores cached data locally.
ofs.osslib libXrdPss.so
pss.cachelib libXrdPfc.so
&#32;
# Origin contacted on cache misses.
pss.origin root://origin.example.org:1094
&#32;
# The cache's local namespace and cache storage.
oss.localroot /srv/brix/cache/namespace
pfc.spaces data meta
oss.space data /srv/brix/cache/data
oss.space meta /srv/brix/cache/meta
&#32;
# Basic PFC policy.
pfc.ram 16g
pfc.diskusage 0.90 0.95 purgeinterval 300s
&#32;
# Load XRootD security plugins for the cache-to-origin GSI client.
xrootd.seclib libXrdSec.so
&#32;
# Outbound origin GSI credential. This sets process environment for
# the XRootD client code used by PSS; it does not contain the proxy.
setenv X509_USER_PROXY = /run/brix/cache-fetcher.proxy
setenv X509_CERT_DIR = /etc/grid-security/certificates
setenv XrdSecPROTOCOL = gsi
</code></pre>
</td>
</tr>
</tbody>
</table>

## 12. XCache With GSI Authentication Everywhere

Clients must authenticate to the cache with GSI. Cache misses authenticate from
the cache to the origin using a service proxy credential. This is the normal
shape for a cache that protects both its client-facing surface and its upstream
origin access.

<table>
<thead>
<tr>
<th>nginx + xrootd module</th>
<th>Vanilla XRootD</th>
</tr>
</thead>
<tbody>
<tr>
<td>
<pre><code class="language-nginx"># /etc/nginx/nginx.conf
&#32;
worker_processes auto;
thread_pool brix_cache_io threads=8 max_queue=65536;
&#32;
events {
    worker_connections 4096;
}
&#32;
stream {
    server {
        # Clients use root://cache.example.org:1094//path.
        listen 1094;
&#32;
        brix_root on;
&#32;
        # Require client-side GSI before serving cache reads.
        brix_auth gsi;
        brix_certificate     /etc/grid-security/hostcert.pem;
        brix_certificate_key /etc/grid-security/hostkey.pem;
        brix_trusted_ca      /etc/grid-security/certificates;
&#32;
        # Cache mode is read-only; writes must stay disabled.
        brix_allow_write off;
&#32;
        brix_export /srv/brix/cache;
&#32;
        # Enable read-through cache fills.
        brix_cache on;
        brix_cache_export /srv/brix/cache;
&#32;
        # Origin data server. Use roots:// if the origin requires TLS.
        brix_cache_origin root://origin.example.org:1094;
&#32;
        # Service proxy for authenticated origin fetches.
        # Managed and renewed outside nginx.
        brix_cache_origin_proxy /run/brix/cache-fetcher.proxy;
        brix_cache_origin_cadir /etc/grid-security/certificates;
        brix_cache_origin_client /usr/bin/xrdcp;
&#32;
        brix_cache_lock_timeout 300s;
        brix_cache_eviction_threshold 90%;
        brix_cache_max_file_size 100g;
&#32;
        brix_thread_pool brix_cache_io;
    }
}
</code></pre>
</td>
<td>
<pre><code class="language-text"># /etc/brix/brix.cfg
&#32;
xrd.port 1094
all.adminpath /var/spool/brix
all.pidpath /run/brix
&#32;
# Export the cache namespace read-only to clients. Cache fill writes are
# internal to PFC.
all.export / r/o
&#32;
# PSS proxies reads to the origin; PFC stores cached data locally.
ofs.osslib libXrdPss.so
pss.cachelib libXrdPfc.so
pss.origin root://origin.example.org:1094
&#32;
oss.localroot /srv/brix/cache/namespace
pfc.spaces data meta
oss.space data /srv/brix/cache/data
oss.space meta /srv/brix/cache/meta
&#32;
pfc.ram 16g
pfc.diskusage 0.90 0.95 purgeinterval 300s
&#32;
# Require GSI from cache clients.
xrootd.seclib libXrdSec.so
sec.protocol gsi -certdir:/etc/grid-security/certificates -cert:/etc/grid-security/hostcert.pem -key:/etc/grid-security/hostkey.pem -gmapopt:10 -dlgpxy:0
sec.protbind * only gsi
&#32;
# Use a separate service proxy for cache-to-origin GSI.
# The proxy file is not shown here and must be renewed externally.
setenv X509_USER_PROXY = /run/brix/cache-fetcher.proxy
setenv X509_CERT_DIR = /etc/grid-security/certificates
setenv XrdSecPROTOCOL = gsi
</code></pre>
</td>
</tr>
</tbody>
</table>

## 13. Secure Multi-User GSI XCache In Front Of CERN EOS

Clients authenticate to the cache with GSI and are authorized per user. Cache
misses fetch from CERN EOS over `root://` using a service proxy credential that
has read access to the configured EOS namespace. The proxy file is referenced
only by path and must be created and renewed outside these configs.

<table>
<thead>
<tr>
<th>nginx + xrootd module</th>
<th>Vanilla XRootD</th>
</tr>
</thead>
<tbody>
<tr>
<td>
<pre><code class="language-nginx"># /etc/nginx/nginx.conf
&#32;
worker_processes auto;
thread_pool brix_cache_io threads=8 max_queue=65536;
&#32;
events {
    worker_connections 4096;
}
&#32;
stream {
    server {
        # Clients use root://cache.example.org:1094//eos/lhcb/...
        listen 1094;
&#32;
        brix_root on;
&#32;
        # Client-facing GSI authentication.
        brix_auth gsi;
        brix_certificate     /etc/grid-security/hostcert.pem;
        brix_certificate_key /etc/grid-security/hostkey.pem;
        brix_trusted_ca      /etc/grid-security/certificates;
&#32;
        # Multi-user authorization at the cache edge. The authdb sees the
        # authenticated DN; grant only the EOS prefixes each user may read.
        brix_authdb_format xrdacc;
        brix_authdb /etc/brix/cache-authdb;
        brix_authdb_refresh 60;
        brix_authdb_audit deny;
&#32;
        # XCache is client read-only. Cache fills write internally.
        brix_allow_write off;
        brix_export /srv/brix/cache;
&#32;
        # Read-through cache storage.
        brix_cache on;
        brix_cache_export /srv/brix/cache;
&#32;
        # CERN EOS root:// door. Replace eoslhcb.cern.ch and /eos/lhcb
        # policy below with the experiment's EOS endpoint and namespace.
        brix_cache_origin root://eoslhcb.cern.ch:1094;
&#32;
        # Service proxy used only for cache-to-EOS fetches.
        brix_cache_origin_proxy /run/brix/eos-cache-fetcher.proxy;
        brix_cache_origin_cadir /etc/grid-security/certificates;
        brix_cache_origin_client /usr/bin/xrdcp;
&#32;
        # Operational cache policy.
        brix_cache_lock_timeout 300s;
        brix_cache_eviction_threshold 90%;
        brix_cache_max_file_size 100g;
&#32;
        brix_thread_pool brix_cache_io;
    }
}
&#32;
# /etc/brix/cache-authdb
&#32;
# Alice may read the experiment namespace.
u /DC=org/DC=example/CN=Alice Example /eos/lhcb rl
&#32;
# Bob may read only his user area.
u /DC=org/DC=example/CN=Bob Example /eos/lhcb/user/b/bob rl
</code></pre>
</td>
<td>
<pre><code class="language-text"># /etc/brix/brix.cfg
&#32;
# Client-facing cache listener.
xrd.port 1094
&#32;
all.adminpath /var/spool/brix
all.pidpath /run/brix
&#32;
# Cache namespace is read-only to clients.
all.export / r/o
&#32;
# PSS proxies cache misses to EOS; PFC stores cached data locally.
ofs.osslib libXrdPss.so
pss.cachelib libXrdPfc.so
&#32;
# CERN EOS origin. Replace eoslhcb.cern.ch and /eos/lhcb policy below
# with the experiment's EOS endpoint and namespace.
pss.origin root://eoslhcb.cern.ch:1094
&#32;
oss.localroot /srv/brix/cache/namespace
pfc.spaces data meta
oss.space data /srv/brix/cache/data
oss.space meta /srv/brix/cache/meta
pfc.ram 16g
pfc.diskusage 0.90 0.95 purgeinterval 300s
&#32;
# Require GSI from cache clients and map DNs to local names.
xrootd.seclib libXrdSec.so
sec.protparm gsi -ca:verify -certdir:/etc/grid-security/certificates
sec.protparm gsi -cert:/etc/grid-security/hostcert.pem
sec.protparm gsi -key:/etc/grid-security/hostkey.pem
sec.protparm gsi -gridmap:/etc/grid-security/grid-mapfile
sec.protparm gsi -gmapopt:trymap,usedn
sec.protparm gsi -dlgpxy:0
sec.protocol gsi
sec.protbind * only gsi
&#32;
# Authorize the mapped users at the cache edge.
ofs.authorize 1
acc.authdb /etc/brix/cache-authdb
&#32;
# Service proxy for cache-to-EOS GSI. The proxy file itself is a
# secret-bearing short-lived credential and is not shown here.
setenv X509_USER_PROXY = /run/brix/eos-cache-fetcher.proxy
setenv X509_CERT_DIR = /etc/grid-security/certificates
setenv XrdSecPROTOCOL = gsi
&#32;
# /etc/grid-security/grid-mapfile
&#32;
"/DC=org/DC=example/CN=Alice Example" alice
"/DC=org/DC=example/CN=Bob Example" bob
&#32;
# /etc/brix/cache-authdb
&#32;
u alice /eos/lhcb rl
u bob   /eos/lhcb/user/b/bob rl
</code></pre>
</td>
</tr>
</tbody>
</table>

## 14. One Host Serving root://, http://, S3, Metrics, And Health

This pattern is useful for a small testbed or edge node that wants one daemon to
serve the same POSIX namespace through multiple protocols. The nginx module keeps
the protocol faces in one `nginx.conf`. Vanilla XRootD can serve native XRootD
and XrdHttp in one daemon; S3 and Prometheus-style metrics require extra plugins
or adjacent services.

<table>
<thead>
<tr>
<th>nginx + xrootd module</th>
<th>Vanilla XRootD</th>
</tr>
</thead>
<tbody>
<tr>
<td>
<pre><code class="language-nginx"># /etc/nginx/nginx.conf
&#32;
worker_processes auto;
thread_pool storage_io threads=8 max_queue=65536;
&#32;
events {
    worker_connections 8192;
}
&#32;
stream {
    server {
        # Native XRootD clients use root://edge.example.org:1094//path.
        listen 1094;
&#32;
        brix_root on;
        brix_export /srv/brix/export;
        brix_auth none;
        brix_allow_write on;
        brix_thread_pool storage_io;
    }
}
&#32;
http {
    server {
        # WebDAV and XrdHttp clients use http://edge.example.org:8080/path.
        listen 8080;
        client_max_body_size 0;
&#32;
        location / {
            brix_webdav on;
            brix_export /srv/brix/export;
            brix_webdav_auth none;
            brix_allow_write on;
            brix_thread_pool storage_io;
        }
    }
&#32;
    server {
        # S3 clients use http://edge.example.org:9001/data-bucket/key.
        listen 9001;
        client_max_body_size 0;
&#32;
        location / {
            brix_s3 on;
            brix_export /srv/brix/export;
            brix_s3_bucket data-bucket;
&#32;
            # Anonymous S3 is deliberate for this example. Add SigV4 keys
            # through local config management when authenticated S3 is needed.
            brix_allow_write on;
            brix_s3_list_cache on;
            brix_s3_list_cache_ttl 30s;
            brix_thread_pool storage_io;
        }
    }
&#32;
    server {
        # Prometheus and load-balancer endpoints.
        listen 9100;
&#32;
        location /metrics {
            brix_metrics on;
        }
&#32;
        location /healthz {
            brix_health on;
        }
    }
}
</code></pre>
</td>
<td>
<pre><code class="language-text"># /etc/brix/brix.cfg
&#32;
# Native root:// endpoint.
xrd.port 1094
&#32;
# XrdHttp endpoint for http:// and davs:// style access.
xrd.protocol XrdHttp:8080 libXrdHttp.so
&#32;
all.adminpath /var/spool/brix
all.pidpath /run/brix
&#32;
# Export one local namespace through both native XRootD and XrdHttp.
all.export / rw
oss.localroot /srv/brix/export
&#32;
# No security protocol lines: anonymous by design.
&#32;
# Vanilla XRootD does not expose an S3 front end or Prometheus endpoint
# from this config alone. Sites normally add an S3 gateway/plugin and
# a monitoring bridge beside the XRootD daemon when those surfaces are
# required.
</code></pre>
</td>
</tr>
</tbody>
</table>

## 15. Operator Console With Prometheus, Health, And Live Transfers

This setup exposes a scrape endpoint, a cheap health probe, and an HTTPS
operator dashboard. The nginx example uses a password-file reference only; the
hash file contents are intentionally not shown.

<table>
<thead>
<tr>
<th>nginx + xrootd module</th>
<th>Vanilla XRootD</th>
</tr>
</thead>
<tbody>
<tr>
<td>
<pre><code class="language-nginx"># /etc/nginx/nginx.conf
&#32;
worker_processes auto;
thread_pool default threads=8 max_queue=65536;
&#32;
events {
    worker_connections 4096;
}
&#32;
stream {
    server {
        listen 1094;
        brix_root on;
        brix_export /srv/brix/export;
        brix_auth none;
        brix_thread_pool default;
        brix_access_log /var/log/nginx/root_access.json;
    }
}
&#32;
http {
    server {
        # Keep Prometheus and load balancers on an internal network.
        listen 9100;
&#32;
        location /metrics {
            brix_metrics on;
        }
&#32;
        location /healthz {
            brix_health on;
        }
    }
&#32;
    server {
        # Browser dashboard for operators.
        listen 9443 ssl;
        server_name ops.example.org;
&#32;
        ssl_certificate     /etc/grid-security/hostcert.pem;
        ssl_certificate_key /etc/grid-security/hostkey.pem;
&#32;
        location /brix/ {
            brix_dashboard on;
&#32;
            # htpasswd-style user:hash file. Hash contents are not shown.
            brix_dashboard_users /etc/nginx/brix-dashboard.htpasswd;
            brix_dashboard_session_ttl 8h;
            brix_dashboard_idle_threshold 5s;
            brix_dashboard_stalled_threshold 60s;
            brix_dashboard_cluster_stale_after 90s;
&#32;
            # Restrict dashboard access to an operations network.
            allow 192.0.2.0/24;
            deny all;
        }
    }
}
</code></pre>
</td>
<td>
<pre><code class="language-text"># /etc/brix/brix.cfg
&#32;
xrd.port 1094
xrd.protocol XrdHttp:8080 libXrdHttp.so
&#32;
all.adminpath /var/spool/brix
all.pidpath /run/brix
all.export / r/o
oss.localroot /srv/brix/export
&#32;
# XRootD has native monitoring streams and logs, but not the same
# embedded Prometheus /healthz / browser-dashboard endpoints. Deploy
# an XRootD monitoring collector and any Prometheus bridge as adjacent
# services, then protect them with the site's normal HTTP stack.
</code></pre>
</td>
</tr>
</tbody>
</table>

## 16. HTTP-TPC Transfer Node With Performance Markers

This pattern is for FTS/Rucio-style third-party copies over HTTPS. The nginx
example keeps curl off the event loop, emits WLCG performance markers, and limits
SSRF exposure. The XRootD example uses the native `ofs.tpc` controls for the
XrdHttp plugin.

<table>
<thead>
<tr>
<th>nginx + xrootd module</th>
<th>Vanilla XRootD</th>
</tr>
</thead>
<tbody>
<tr>
<td>
<pre><code class="language-nginx"># /etc/nginx/nginx.conf
&#32;
worker_processes auto;
thread_pool tpc_io threads=8 max_queue=65536;
&#32;
events {
    worker_connections 8192;
}
&#32;
http {
    server {
        listen 8443 ssl;
        server_name tpc.example.org;
&#32;
        ssl_certificate     /etc/grid-security/hostcert.pem;
        ssl_certificate_key /etc/grid-security/hostkey.pem;
        ssl_client_certificate /etc/grid-security/certificates/ca-bundle.pem;
        ssl_verify_client optional;
&#32;
        client_max_body_size 0;
&#32;
        location / {
            brix_webdav on;
            brix_export /srv/brix/export;
            brix_allow_write on;
&#32;
            # Accept either a verified proxy cert or an anonymous request
            # that carries a valid bearer token.
            brix_webdav_auth optional;
            brix_webdav_cadir /etc/grid-security/certificates;
            brix_webdav_token_jwks /etc/tokens/storage-jwks.json;
            brix_webdav_token_issuer https://idp.example.com;
            brix_webdav_token_audience my-storage;
&#32;
            # Enable HTTP-TPC COPY Source:/Destination: handling.
            brix_webdav_tpc on;
            brix_webdav_tpc_curl /usr/bin/curl;
            brix_webdav_tpc_cadir /etc/grid-security/certificates;
&#32;
            # Use site-managed outbound credentials by path only.
            brix_webdav_tpc_cert /etc/grid-security/hostcert.pem;
            brix_webdav_tpc_key  /etc/grid-security/hostkey.pem;
&#32;
            # Operational limits and WLCG perf-marker streaming.
            brix_webdav_tpc_timeout 7200;
            brix_webdav_tpc_marker_interval 30;
            brix_webdav_tpc_max_streams 4;
            brix_webdav_tpc_low_speed_bytes 1024;
            brix_webdav_tpc_low_speed_secs 300;
&#32;
            # Block loopback/link-local SSRF. RFC1918 peers are allowed
            # because many HEP transfer nodes sit on private fabrics.
            brix_webdav_tpc_allow_local off;
            brix_webdav_tpc_allow_private on;
&#32;
            brix_thread_pool tpc_io;
        }
    }
}
</code></pre>
</td>
<td>
<pre><code class="language-text"># /etc/brix/brix.cfg
&#32;
xrd.port 1094
xrd.protocol XrdHttp:8443 libXrdHttp.so
&#32;
all.adminpath /var/spool/brix
all.pidpath /run/brix
all.export / rw
oss.localroot /srv/brix/export
&#32;
http.cert /etc/grid-security/hostcert.pem
http.key  /etc/grid-security/hostkey.pem
http.cadir /etc/grid-security/certificates
http.secxtractor libXrdHttpVOMS.so
&#32;
# Enable third-party copy in the OFS layer.
# The proxy credential material is created at runtime under fcpath.
ofs.tpc ttl 600 3600
ofs.tpc xfr 16
ofs.tpc streams 4,8
ofs.tpc restrict /
ofs.tpc fcreds ?gsi =X509_USER_PROXY
ofs.tpc fcpath /var/spool/brix/tpccreds
&#32;
# Optional external transfer program. Keep program arguments site-local.
# ofs.tpc pgm /usr/bin/xrdcp
</code></pre>
</td>
</tr>
</tbody>
</table>

## 17. root:// Token Edge In Front Of An Anonymous Legacy Origin

This is a perimeter gateway pattern: require tokens from clients at the edge,
then forward accepted native XRootD traffic to an older anonymous backend. Use it
only when the backend is on a trusted internal network.

<table>
<thead>
<tr>
<th>nginx + xrootd module</th>
<th>Vanilla XRootD</th>
</tr>
</thead>
<tbody>
<tr>
<td>
<pre><code class="language-nginx"># /etc/nginx/nginx.conf
&#32;
worker_processes auto;
&#32;
events {
    worker_connections 4096;
}
&#32;
stream {
    server {
        # Public token-protected root:// endpoint.
        listen 1094;
&#32;
        brix_root on;
        brix_tap_proxy on;
&#32;
        # Client-facing token authentication and scope enforcement.
        brix_tap_proxy_auth token;
        brix_auth token;
        brix_token_jwks /etc/tokens/storage-jwks.json;
        brix_token_issuer https://idp.example.com;
        brix_token_audience my-storage;
&#32;
        # Backend is an internal anonymous XRootD data server.
        brix_tap_proxy_upstream legacy-origin.internal.example.org:1094;
        brix_tap_proxy_login_user edge-token-gateway;
&#32;
        # Audit the security-domain bridge.
        brix_tap_proxy_audit_log /var/log/nginx/root_proxy_audit.json;
&#32;
        # The backend owns storage; the edge does not need a local root.
        brix_export /srv/brix/export;
        brix_allow_write off;
    }
}
</code></pre>
</td>
<td>
<pre><code class="language-text"># /etc/brix/brix.cfg
&#32;
# Closest vanilla pattern: use PSS as a read-through proxy/cache layer.
# It does not provide the same full native root:// transparent proxy
# behavior for every opcode.
&#32;
xrd.port 1094
all.adminpath /var/spool/brix
all.pidpath /run/brix
all.export / r/o
&#32;
ofs.osslib libXrdPss.so
pss.origin root://legacy-origin.internal.example.org:1094
&#32;
oss.localroot /srv/brix/cache/namespace
&#32;
# Token enforcement still happens with the normal XRootD security stack.
xrootd.seclib libXrdSec.so
sec.protocol ztn
sec.protbind * only ztn
ofs.authorize 1
acc.authdb /etc/brix/authdb
</code></pre>
</td>
</tr>
</tbody>
</table>

## 18. Dynamic WebDAV Origin Pool With Admin Drain

This configuration turns nginx into an authenticated WebDAV front end for a pool
of HTTP origins. Operators can add, drain, and remove dynamic backends through
the dashboard admin API without editing `nginx.conf`. The admin secret is a file
path only; the token value is not shown.

<table>
<thead>
<tr>
<th>nginx + xrootd module</th>
<th>Vanilla XRootD</th>
</tr>
</thead>
<tbody>
<tr>
<td>
<pre><code class="language-nginx"># /etc/nginx/nginx.conf
&#32;
worker_processes auto;
&#32;
events {
    worker_connections 8192;
}
&#32;
http {
    server {
        listen 8443 ssl;
        server_name dav.example.org;
&#32;
        ssl_certificate     /etc/grid-security/hostcert.pem;
        ssl_certificate_key /etc/grid-security/hostkey.pem;
&#32;
        location / {
            brix_webdav on;
            brix_export /srv/brix/export;
&#32;
            # Authenticate clients at the edge.
            brix_webdav_auth required;
            brix_webdav_cadir /etc/grid-security/certificates;
&#32;
            # NOTE: the dedicated WebDAV reverse-proxy directives
            # (brix_webdav_proxy*) were removed. The edge serves WebDAV
            # directly from shared or remote storage; for plain HTTP
            # relaying to an origin pool use nginx stock proxy_pass
            # with an upstream{} block instead.
        }
&#32;
        location /brix/ {
            brix_dashboard on;
            brix_dashboard_users /etc/nginx/brix-dashboard.htpasswd;
&#32;
            # Admin API controls the dynamic backend pool.
            brix_admin_allow 192.0.2.0/24;
            brix_admin_secret /run/nginx/brix-admin.bearer;
            brix_admin_require_both on;
            brix_admin_proxy_allow be1.example.org be2.example.org;
        }
    }
}
</code></pre>
</td>
<td>
<pre><code class="language-text"># /etc/brix/brix.cfg
&#32;
# XrdHttp can expose the local namespace, but vanilla XRootD does not
# provide this nginx-style runtime HTTP upstream pool and drain API.
# Use DNS, an external load balancer, or a site-specific proxy layer for
# dynamic backend management.
&#32;
xrd.port 1094
xrd.protocol XrdHttp:8443 libXrdHttp.so
&#32;
all.adminpath /var/spool/brix
all.pidpath /run/brix
all.export / r/o
oss.localroot /srv/brix/export
&#32;
http.cert /etc/grid-security/hostcert.pem
http.key  /etc/grid-security/hostkey.pem
http.cadir /etc/grid-security/certificates
http.secxtractor libXrdHttpVOMS.so
http.gridmap required /etc/grid-security/grid-mapfile
</code></pre>
</td>
</tr>
</tbody>
</table>

## 19. Cross-Protocol Rate, Bandwidth, And Concurrency Guardrails

Use this when a shared endpoint needs identity-aware throttles across native
XRootD and HTTP/WebDAV. The same shared-memory rate-limit zone can be referenced
from both `stream {}` and `http {}` blocks.

<table>
<thead>
<tr>
<th>nginx + xrootd module</th>
<th>Vanilla XRootD</th>
</tr>
</thead>
<tbody>
<tr>
<td>
<pre><code class="language-nginx"># /etc/nginx/nginx.conf
&#32;
worker_processes auto;
&#32;
events {
    worker_connections 8192;
}
&#32;
stream {
    # Shared leaky-bucket state for root:// requests.
    brix_rate_limit_zone zone=stream_limits:10m;
&#32;
    server {
        listen 1094;
        brix_root on;
        brix_export /srv/brix/export;
        brix_auth gsi;
        brix_certificate     /etc/grid-security/hostcert.pem;
        brix_certificate_key /etc/grid-security/hostkey.pem;
        brix_trusted_ca      /etc/grid-security/certificates;
&#32;
        # Bound abusive request rates, tape bandwidth, and active sessions.
        brix_rate_limit_rule zone=stream_limits key=vo rate=500r/s burst=800;
        brix_bandwidth_limit zone=stream_limits key=volume:/store/tape rate=50m/s burst=200m;
        brix_concurrency_limit zone=stream_limits key=dn limit=16;
    }
}
&#32;
http {
    # Separate HTTP zone, same policy shape.
    brix_rate_limit_zone zone=http_limits:10m;
&#32;
    server {
        listen 8443 ssl;
        ssl_certificate     /etc/grid-security/hostcert.pem;
        ssl_certificate_key /etc/grid-security/hostkey.pem;
&#32;
        location / {
            brix_webdav on;
            brix_export /srv/brix/export;
            brix_webdav_auth required;
            brix_webdav_cadir /etc/grid-security/certificates;
&#32;
            brix_rate_limit_rule zone=http_limits key=vo rate=500r/s burst=800;
            brix_bandwidth_limit zone=http_limits key=volume:/store/tape rate=50m/s burst=200m;
            brix_concurrency_limit zone=http_limits key=dn limit=16;
        }
    }
}
</code></pre>
</td>
<td>
<pre><code class="language-text"># /etc/brix/brix.cfg
&#32;
xrd.port 1094
xrd.protocol XrdHttp:8443 libXrdHttp.so
&#32;
all.adminpath /var/spool/brix
all.pidpath /run/brix
all.export / r/o
oss.localroot /srv/brix/export
&#32;
xrootd.seclib libXrdSec.so
sec.protocol gsi -certdir:/etc/grid-security/certificates -cert:/etc/grid-security/hostcert.pem -key:/etc/grid-security/hostkey.pem
sec.protbind * only gsi
&#32;
http.cert /etc/grid-security/hostcert.pem
http.key  /etc/grid-security/hostkey.pem
http.cadir /etc/grid-security/certificates
http.secxtractor libXrdHttpVOMS.so
&#32;
# Vanilla deployments commonly use XrdThrottle and XrdBwm plugins for
# throttling. Their exact policy files are plugin/site specific, so they
# are not equivalent to the single cross-protocol nginx SHM zone shown
# on the left.
</code></pre>
</td>
</tr>
</tbody>
</table>

## 20. Native root:// Shadow Mirroring For Canary Validation

Mirror a sample of read-only native XRootD operations to a shadow server and log
divergence without changing the client response. This is useful during backend
migrations and module upgrades.

<table>
<thead>
<tr>
<th>nginx + xrootd module</th>
<th>Vanilla XRootD</th>
</tr>
</thead>
<tbody>
<tr>
<td>
<pre><code class="language-nginx"># /etc/nginx/nginx.conf
&#32;
worker_processes auto;
&#32;
events {
    worker_connections 4096;
}
&#32;
stream {
    server {
        listen 1094;
        brix_root on;
        brix_export /srv/brix/export;
        brix_auth none;
&#32;
        # Shadow read-path operations to a separate validation server.
        # Do not point the shadow at the same writable storage root.
        brix_stream_mirror_url shadow-xrd.example.org:21094;
        brix_mirror_opcodes protocol login stat locate open dirlist;
        brix_mirror_sample 10;
        brix_mirror_strip_auth on;
        brix_mirror_log_diverge on;
        brix_mirror_timeout 2000;
&#32;
        # Writes are intentionally not mirrored in a canary read check.
        brix_mirror_writes off;
    }
}
</code></pre>
</td>
<td>
<pre><code class="language-text"># /etc/brix/brix.cfg
&#32;
xrd.port 1094
all.adminpath /var/spool/brix
all.pidpath /run/brix
all.export / r/o
oss.localroot /srv/brix/export
&#32;
# Vanilla XRootD does not include a transparent per-request shadow replay
# directive with divergence accounting. Run a separate validation client,
# redirect selected users, or place an external proxy in front when this
# canary style is required.
</code></pre>
</td>
</tr>
</tbody>
</table>

## 21. WebDAV Shadow Mirroring For HTTP Migration

This mirrors a controlled subset of HTTP methods to a shadow WebDAV endpoint.
Authorization is stripped before the mirror request unless the shadow is in the
same trust domain.

<table>
<thead>
<tr>
<th>nginx + xrootd module</th>
<th>Vanilla XRootD</th>
</tr>
</thead>
<tbody>
<tr>
<td>
<pre><code class="language-nginx"># /etc/nginx/nginx.conf
&#32;
worker_processes auto;
&#32;
events {
    worker_connections 4096;
}
&#32;
http {
    server {
        listen 8443 ssl;
        server_name dav.example.org;
&#32;
        ssl_certificate     /etc/grid-security/hostcert.pem;
        ssl_certificate_key /etc/grid-security/hostkey.pem;
&#32;
        location / {
            brix_webdav on;
            brix_export /srv/brix/export;
            brix_webdav_auth optional;
            brix_webdav_cadir /etc/grid-security/certificates;
&#32;
            # Mirror only safe read/list methods while validating the shadow.
            brix_mirror_url https://shadow-dav.example.org:8443;
            brix_mirror_methods GET HEAD PROPFIND OPTIONS;
            brix_mirror_sample 25;
            brix_mirror_strip_auth on;
            brix_mirror_log_diverge on;
            brix_mirror_timeout 2000;
&#32;
            # Write mirroring is off unless the shadow namespace is isolated.
            brix_mirror_writes off;
        }
    }
}
</code></pre>
</td>
<td>
<pre><code class="language-text"># /etc/brix/brix.cfg
&#32;
xrd.port 1094
xrd.protocol XrdHttp:8443 libXrdHttp.so
&#32;
all.adminpath /var/spool/brix
all.pidpath /run/brix
all.export / r/o
oss.localroot /srv/brix/export
&#32;
http.cert /etc/grid-security/hostcert.pem
http.key  /etc/grid-security/hostkey.pem
http.cadir /etc/grid-security/certificates
&#32;
# XrdHttp serves the HTTP/WebDAV surface, but vanilla XRootD does not
# shadow HTTP requests to another origin from config. Use an external
# HTTP proxy or traffic-replay pipeline for this migration pattern.
</code></pre>
</td>
</tr>
</tbody>
</table>

## 22. Tape-Aware Gateway With Durable FRM Queue

This pattern accepts `kXR_prepare`/stage requests, records them durably, and runs
site-provided stage/residency commands. The commands are paths only; their
contents and any backend credentials are managed outside the config.

<table>
<thead>
<tr>
<th>nginx + xrootd module</th>
<th>Vanilla XRootD</th>
</tr>
</thead>
<tbody>
<tr>
<td>
<pre><code class="language-nginx"># /etc/nginx/nginx.conf
&#32;
worker_processes auto;
thread_pool tape_io threads=4 max_queue=1024;
&#32;
events {
    worker_connections 4096;
}
&#32;
stream {
    server {
        listen 1094;
        brix_root on;
        brix_export /srv/brix/export;
        brix_auth gsi;
        brix_certificate     /etc/grid-security/hostcert.pem;
        brix_certificate_key /etc/grid-security/hostkey.pem;
        brix_trusted_ca      /etc/grid-security/certificates;
&#32;
        # Durable file-residency manager queue.
        brix_frm on;
        brix_frm_queue_path /var/spool/nginx-xrootd/frm.queue;
        brix_frm_max_inflight 64;
        brix_frm_max_per_source 4;
        brix_frm_stagecmd /usr/local/libexec/brix-stage-in;
        brix_frm_residency_cmd /usr/local/libexec/brix-residency;
        brix_frm_stage_ttl 600s;
        brix_frm_xfrhold 30s;
        brix_frm_fail_backoff 60s;
        brix_frm_fail_retries 3;
&#32;
        # Optional disk purge hooks for tape-backed cache space.
        brix_frm_purge_watermark 95% 85%;
        brix_frm_purge_interval 300s;
&#32;
        brix_thread_pool tape_io;
    }
}
&#32;
http {
    server {
        listen 8443 ssl;
        ssl_certificate     /etc/grid-security/hostcert.pem;
        ssl_certificate_key /etc/grid-security/hostkey.pem;
&#32;
        location / {
            brix_webdav on;
            brix_export /srv/brix/export;
            brix_webdav_auth required;
            brix_webdav_cadir /etc/grid-security/certificates;
&#32;
            # Expose the HTTP Tape REST facade on the same namespace.
            brix_webdav_tape_rest on;
        }
    }
}
</code></pre>
</td>
<td>
<pre><code class="language-text"># /etc/brix/brix.cfg
&#32;
xrd.port 1094
xrd.protocol XrdHttp:8443 libXrdHttp.so
&#32;
all.adminpath /var/spool/brix
all.pidpath /run/brix
&#32;
# Mark exported data as stage-capable and read-only to clients.
all.export / stage r/o
oss.localroot /srv/brix/export
&#32;
xrootd.seclib libXrdSec.so
sec.protocol gsi -certdir:/etc/grid-security/certificates -cert:/etc/grid-security/hostcert.pem -key:/etc/grid-security/hostkey.pem
sec.protbind * only gsi
&#32;
http.cert /etc/grid-security/hostcert.pem
http.key  /etc/grid-security/hostkey.pem
http.cadir /etc/grid-security/certificates
http.secxtractor libXrdHttpVOMS.so
&#32;
# Site-specific FRM/MSS stage command. The helper script owns backend auth.
frm.xfr.copycmd /usr/local/libexec/brix-stage-in /dev/null $PFN
</code></pre>
</td>
</tr>
</tbody>
</table>

## 23. Write-Through Edge Ingest With Local Reads

Use this when an edge site accepts writes locally for low latency, then mirrors
selected prefixes back to an origin. The nginx example can keep local reads
available while async close flushes proceed.

<table>
<thead>
<tr>
<th>nginx + xrootd module</th>
<th>Vanilla XRootD</th>
</tr>
</thead>
<tbody>
<tr>
<td>
<pre><code class="language-nginx"># /etc/nginx/nginx.conf
&#32;
worker_processes auto;
thread_pool edge_io threads=8 max_queue=65536;
&#32;
events {
    worker_connections 8192;
}
&#32;
stream {
    server {
        listen 1094;
        brix_root on;
        brix_export /srv/brix/export;
        brix_auth token;
        brix_token_jwks /etc/tokens/storage-jwks.json;
        brix_token_issuer https://idp.example.com;
        brix_token_audience my-storage;
        brix_allow_write on;
&#32;
        # Read-through fills for cold files.
        brix_cache on;
        brix_cache_export /srv/brix/cache;
        brix_cache_origin root://origin.example.org:1094;
        brix_cache_lock_timeout 300s;
        brix_cache_eviction_threshold 90%;
&#32;
        # Write-through mirrors only selected project prefixes.
        brix_write_through on;
        brix_wt_mode async;
        brix_wt_origin root://origin.example.org:1094;
        brix_wt_allow_prefix /projects/atlas;
        brix_wt_allow_prefix /projects/cms;
        brix_wt_deny_prefix /scratch;
&#32;
        brix_thread_pool edge_io;
    }
}
</code></pre>
</td>
<td>
<pre><code class="language-text"># /etc/brix/brix.cfg
&#32;
xrd.port 1094
&#32;
all.adminpath /var/spool/brix
all.pidpath /run/brix
all.export / rw
&#32;
# PSS/PFC cache in front of the same origin.
ofs.osslib libXrdPss.so
pss.cachelib libXrdPfc.so
pss.origin root://origin.example.org:1094
&#32;
oss.localroot /srv/brix/cache/namespace
pfc.spaces data meta
oss.space data /srv/brix/cache/data
oss.space meta /srv/brix/cache/meta
pfc.ram 16g
pfc.diskusage 0.90 0.95 purgeinterval 300s
&#32;
# Enable PFC write-through and bound its queue.
pfc.writethrough on
pfc.writequeue 64 4
&#32;
# Client auth and write policy still belong in the normal security and
# authorization stack.
xrootd.seclib libXrdSec.so
sec.protocol ztn
sec.protbind * only ztn
ofs.authorize 1
acc.authdb /etc/brix/write-authdb
</code></pre>
</td>
</tr>
</tbody>
</table>

## 24. Browser-Friendly WebDAV With CORS, Locks, And Cached Metadata

This setup is for notebooks, portals, and browser clients that need preflight
requests, RFC 4918 locks, and fast repeated metadata lookups.

<table>
<thead>
<tr>
<th>nginx + xrootd module</th>
<th>Vanilla XRootD</th>
</tr>
</thead>
<tbody>
<tr>
<td>
<pre><code class="language-nginx"># /etc/nginx/nginx.conf
&#32;
worker_processes auto;
thread_pool webdav_io threads=8 max_queue=65536;
&#32;
events {
    worker_connections 4096;
}
&#32;
http {
    server {
        listen 8443 ssl;
        server_name portal-storage.example.org;
&#32;
        ssl_certificate     /etc/grid-security/hostcert.pem;
        ssl_certificate_key /etc/grid-security/hostkey.pem;
&#32;
        client_max_body_size 0;
&#32;
        location / {
            brix_webdav on;
            brix_export /srv/brix/export;
            brix_webdav_auth optional;
            brix_webdav_cadir /etc/grid-security/certificates;
            brix_allow_write on;
&#32;
            # Explicit browser origins. Avoid "*" when credentials are used.
            brix_webdav_cors_origin https://notebooks.example.org;
            brix_webdav_cors_origin https://portal.example.org;
            brix_webdav_cors_credentials on;
            brix_webdav_cors_max_age 86400;
&#32;
            # Lock records are xattrs under the export root.
            brix_webdav_lock_timeout 600;
            brix_webdav_lock_startup_sweep off;
&#32;
            # Cache stat/open metadata but keep errors out of cache.
            brix_webdav_open_file_cache max=10000 inactive=30s;
            brix_webdav_open_file_cache_valid 60s;
            brix_webdav_open_file_cache_min_uses 2;
            brix_webdav_open_file_cache_errors off;
            brix_webdav_open_file_cache_events on;
&#32;
            brix_thread_pool webdav_io;
        }
    }
}
</code></pre>
</td>
<td>
<pre><code class="language-text"># /etc/brix/brix.cfg
&#32;
xrd.port 1094
xrd.protocol XrdHttp:8443 libXrdHttp.so
&#32;
all.adminpath /var/spool/brix
all.pidpath /run/brix
all.export / rw
oss.localroot /srv/brix/export
&#32;
http.cert /etc/grid-security/hostcert.pem
http.key  /etc/grid-security/hostkey.pem
http.cadir /etc/grid-security/certificates
http.secxtractor libXrdHttpVOMS.so
http.gridmap /etc/grid-security/grid-mapfile
&#32;
# XrdHttp covers HTTP/WebDAV-style access. Browser-specific CORS,
# lock persistence policy, and nginx open-file-cache tuning are not
# represented by these vanilla XRootD directives.
</code></pre>
</td>
</tr>
</tbody>
</table>
