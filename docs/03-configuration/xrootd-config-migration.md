# Migrating an XRootD configuration

`brix-config-migrate` is a standalone, offline assistant that turns one XRootD
configuration into a reviewable BriX-Cache nginx configuration. It is intended
to shorten an operator migration, not to claim that two independently designed
servers have identical semantics.

```bash
brix-config-migrate \
  --strict \
  --report migration-decisions.json \
  /etc/xrootd/xrootd.cfg > brix-cache.conf

# Resolve every REVIEW comment, then validate the real installed modules.
nginx -t -c "$PWD/brix-cache.conf"
```

Without `--strict`, a syntactically valid suggestion exits 0 even when it has
review items. With `--strict`, review or unsupported items produce exit status
3. Invalid input and I/O errors produce status 2.

## What it recognizes

| XRootD surface | Suggested BriX-Cache surface | Important review point |
|---|---|---|
| `xrd.port`, `all.export`, `oss.localroot` | listener, export, POSIX backend and write policy | confirm export ownership and nginx worker permissions |
| `xrd.timeout read`, `xrd.network keepalive` | bounded client-read time and TCP keepalive | only exact forms are automatic; compound policies remain review items |
| `sec.protocol gsi`, `sec.protbind` | GSI/VOMS trust, certificates, CRL policy, identity mapping and protocol binding | certificate directory and CA-bundle concepts are not interchangeable; populate the converted CRL path |
| `sec.protocol ztn` | token authentication | issuer, audiences, JWKS and path scopes normally require site input |
| `acc.authdb`, `acc.audit`, `acc.authrefresh` | XrdAcc authorization engine and policy | convert an explicitly named companion authdb and validate deny/default behavior |
| `ofs.osslib libXrdPss`, `pss.origin` | remote `root://` storage backend | confirm failover and DNS policy separately |
| common `pfc.*` controls | cache store, slice/prefetch, watermarks, reap/age and write-through | arbitrary decision plugins have no automatic equivalent |
| `ofs.osslib libXrdCeph`, common `ceph.*` | native `ceph:` librados backend | pool, config, key prefix and name-to-name mapping must be explicit |
| `xrd.protocol XrdHttp`, common `http.*` | basic WebDAV listener | review TLS, authorization and client-certificate policy |
| `all.manager`, `ofs.tpc streams` | CMS membership and TPC stream limit | validate topology and transfer authorization |

For XrdCeph configurations, values that cannot be inferred safely are supplied
on the command line rather than guessed:

```bash
brix-config-migrate \
  --ceph-pool atlas \
  --ceph-conf /etc/ceph/ceph.conf \
  --ceph-key-prefix /store/ \
  --n2n-scheme cephfs_path \
  --n2n-prefix /store/ \
  xrootd-ceph.cfg > brix-cache.conf
```

VOMS path policy is similarly explicit and repeatable:

```bash
brix-config-migrate \
  --vomsdir /etc/grid-security/vomsdir \
  --voms-cert-dir /etc/grid-security/certificates \
  --require-vo /atlas=atlas \
  --require-vo /cms=cms \
  xrootd.cfg > brix-cache.conf
```

Some deployed XrdAcc authdb files spell identity selectors as `o:`, `r:`, or
`g:` while BriX's XrdAcc reader uses the unpunctuated tokens. Convert a
companion file explicitly and make the generated configuration reference it:

```bash
brix-config-migrate \
  --authdb-input /etc/xrootd/authdb \
  --authdb-output /etc/brix-cache/authdb \
  xrootd.cfg > brix-cache.conf
```

The pair is all-or-nothing. The assistant never follows the `acc.authdb` path
from source text. Conversion changes only unquoted selector slots in `=`
identity-definition records; access rules, values, comments, and layout are
preserved.

## Deliberate safety limits

The tool reads only the named configuration file and an authdb explicitly
named with `--authdb-input`. It does not follow `include` directives or the
source configuration's authdb path,
load `osslib`, `seclib`, decision, or name-mapping plugins, expand environment
variables, inspect secrets, resolve names, or contact a manager/origin. Those
inputs remain visible as `REVIEW` or unsupported findings. Directive arguments
are quoted when rendered so source text cannot inject an nginx directive.

The JSON report records directive names, line numbers, outcomes, and reasons;
it intentionally does not copy the original arguments, which may contain site
paths or credentials. Keep the report with the reviewed configuration as an
upgrade/audit artifact.

XRootD can multiplex XrdHttp and root:// on one socket. When both source
protocols name the same numeric port, the assistant preserves it as the only
public `stream {}` listener, adds `brix_http_handoff`, and binds WebDAV to the
next port on `127.0.0.1`. Use `--http-port PORT` to override that private
loopback port. The generated handoff has explicit 5-second connect and
75-second idle deadlines; override them with `--http-connect-timeout` and
`--http-idle-timeout`. Separate source ports remain separate public listeners.

## External Lancaster validation

On 2026-10-12 the public Lancaster configuration repository
[`mdoidge/lancsxroot`](https://github.com/mdoidge/lancsxroot) was downloaded to
a temporary directory and tested as external input; no Lancaster file or
site-specific test fixture is vendored here. All six endpoint configurations
(`stor002-cluster`, `xroot-server`, `xrootd-cluster`, `xrootd-min`,
`xrootd-redirector`, and `xrootd-server`) converted and passed `nginx -t` with
the real Darwin ARM64 BriX modules. The derived `xrootd-cluster` configuration
also sustained a real worker; the shared-port form now uses the public root
listener plus a private loopback HTTPS handoff.

That exercise added support for Lancaster's deployed aliases, non-ASCII
continuation indentation, shared XrdHttp/root port handoff, SciTokens and
macaroon plugin paths, GSI CRL policy, and explicit companion-authdb
conversion. It deliberately did not claim equivalence for monitoring,
SciTags, conditional host logic, notification hooks, handler plugins, or the
Lancaster cluster manager's availability: those remain visible review items.
The Lancaster SciTokens `onmissing = passthrough` setting is also reported by
BriX as unsupported and must be resolved rather than silently assumed.

## Required operator validation

1. Resolve every `REVIEW` comment and any `REVIEW_*` placeholder.
2. Compare export read/write behavior and authorization defaults with the old
   endpoint, including an explicitly denied identity.
3. Validate certificates, VOMS trust, token issuers/audiences, and revocation.
4. Exercise a cache miss and hit for PFC replacements, or object/path mapping
   for librados replacements.
5. Run `nginx -t` using the packaged nginx and modules, then run the relevant
   root://, WebDAV, TPC, CMS, and storage integration tests before cutover.

See the [configuration reference](config-reference.md), [complete
examples](examples.md), and [production deployment guide](production-deployment.md)
for the BriX-specific choices that cannot be inferred from an XRootD file.
