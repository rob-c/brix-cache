# Certificate, CRL & Token-Key Rotation

How to roll the credentials an BriX-Cache gateway depends on **without dropping
in-flight requests**. The key fact: the token-signing keys (JWKS), CRLs, and the
authorization DB are **hot-reloaded in place** — you do *not* need to restart, and
for those three you usually do not even need `nginx -s reload`.

## What reloads automatically (no restart)

| Credential | Directive | Mechanism |
|---|---|---|
| Token signing keys (JWKS) | `brix_token_jwks` / `brix_webdav_token_jwks`, interval `brix_token_jwks_refresh_interval` | A per-worker timer polls the JWKS file's mtime and reloads keys in place. Old keys are freed only **after** a successful reload, so in-flight token validations never see an empty key set. |
| CRLs | `brix_crl` / `brix_webdav_crl`, reload via `brix_crl_reload` | The X509 store is rebuilt and swapped atomically; active TLS sessions are unaffected. |
| Authorization DB | `brix_authdb`, `brix_authdb_refresh` | The authz table is re-read and swapped on change. |

**To roll a token key:** publish the new JWKS (containing both old and new keys
during the overlap window) to the configured path, atomically (write-temp +
`rename`). The next poll picks it up. Once all issued tokens signed by the old key
have expired, drop the old key from the JWKS.

**To refresh CRLs:** update the CRL files in place (e.g. via `fetch-crl`), atomically.
The store rebuild picks them up on the next reload tick / `brix_crl_reload` cadence.

## What needs `nginx -s reload` (the host cert/key)

The TLS **host certificate** (`ssl_certificate` / `ssl_certificate_key`, and the
root:// `brix_certificate` / `brix_certificate_key`) is read by nginx at
configuration load. To roll it:

1. Install the new cert+key at the configured paths (atomically).
2. Validate: `nginx -t`.
3. Apply with a **graceful** reload: `nginx -s reload` (or `systemctl reload nginx`).
   nginx starts new workers with the new cert and drains the old ones — established
   connections finish on the old workers, new connections use the new cert. No drop.

> The GSI/token validation paths are written so in-flight tokens **survive**
> `nginx -s reload` during key rotation — a reload mid-rotation will not mass-reject
> active sessions.

### Watching expiry before it bites

- `GET /healthz?verbose` is the cheap liveness/readiness probe (see
  [Troubleshooting](troubleshooting.md)).
- Check the host cert manually:
  `openssl x509 -in /etc/grid-security/hostcert.pem -noout -enddate`.
- Watch the auth-rejection metric for the tell-tale of a missed roll:
  `rate(brix_webdav_auth_total{result="rejected"}[5m])` (and the S3 equivalent)
  jumping at the moment a cert/CRL/key expired. The
  [alert rules](../../contrib/prometheus-alerts.yml) include `XrootdAuthRejectionSpike`.

## Rotation checklist

1. Stage the new material **atomically** (write to a temp path, then `rename`) so a
   poller never reads a half-written file.
2. For JWKS/CRL/authdb: nothing else to do — wait for the poll/reload tick and
   confirm via metrics that rejections stay flat.
3. For the host cert/key: `nginx -t` → `nginx -s reload`.
4. Confirm with `/healthz?verbose` and the auth metrics that the gateway is healthy.
5. Remove superseded keys/certs only **after** the overlap window (all tokens/sessions
   signed by the old key have expired).

See also: [Troubleshooting](troubleshooting.md) ·
[Authentication overview](../06-authentication/auth-overview.md) ·
[Upgrade Procedure](upgrade-procedure.md)
