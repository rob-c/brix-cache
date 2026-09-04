# Running an OCI pull-through registry mirror

**Status: source-verified 2026-08-18.** The executable forms of this page are
`deploy/oci-mirror/nginx.conf.example` and the lanes
`tests/test_oci_mirror_classify.py`, `test_oci_mirror_authdance.py`,
`test_oci_mirror_cachepolicy.py` (block 14100) and
`test_oci_mirror_podman_pull.py` (block 14120).

Companion pages: [oci.md](../04-protocols/oci.md) — the wire contract ·
[oci-registry.md](oci-registry.md) — pushing to your own registry ·
[container-ingest.md](container-ingest.md) — the same images as a filesystem ·
[rpm-mirror.md](rpm-mirror.md) — the same idea for dnf.

---

## 1. What it is

A location that carries `brix_oci_mirror <upstream>` **is** the `/v2/`
endpoint of a caching mirror. The first client to pull a blob pulls it
across the WAN; everyone after that gets it from local disk. There is no
sync job, no mirror list to maintain, and no "is the mirror behind?" — a tag
that moves upstream moves here within `brix_oci_manifest_ttl`.

It is not `proxy_cache` with a registry-shaped `location`, and the
differences are the reason it exists:

| | stock `proxy_cache` | `brix_oci_mirror` |
|---|---|---|
| Upstream 401 + `WWW-Authenticate` | relayed to the client | performed by the mirror; the bearer is cached per (upstream, scope) |
| Blob integrity | whatever the origin sent | hashed against the digest in its own name before publication |
| Tag vs blob freshness | two regex locations that must keep agreeing | one directive; the cache key tells the tiers which is which |
| Writes | pass through | 405 + a `signal=ocipush` guard line |

---

## 2. Minimal configuration

```nginx
http {
    brix_oci_token_zone oci_tokens 1m;   # optional; this is also the default

    server {
        listen 5000;
        client_max_body_size 1m;         # nothing here is an upload

        location /v2/ {
            brix_oci_mirror       https://registry-1.docker.io;
            brix_cache_store      posix:/var/cache/brix/oci;
            brix_cache_verify     oci-digest;
            brix_oci_manifest_ttl 60s;
        }

        location / { return 404; }
    }
}
```

`brix_oci_mirror` takes the upstream **root** (`scheme://host`), not its
`/v2/` endpoint. The location prefix is free: mount it at `/v2/` for clients
that treat the host as a registry, or at `/mirror/v2/` alongside other
surfaces — the classifier finds the `/v2/` segment wherever it sits.

### Directives

| Directive | Context | Notes |
|---|---|---|
| `brix_oci_mirror <base-url>` | location | marks the mirror **and** installs the handler |
| `brix_cache_store posix:<dir>` | location | where cached objects live |
| `brix_cache_verify oci-digest` | location | hash-before-publish; see §4 |
| `brix_oci_manifest_ttl <time>` | http/server/location | freshness of **tag**-addressed manifests only |
| `brix_oci_token_zone <name> <size>` | http/server/location | bearer cache; default `oci_tokens 1m` |
| `brix_oci_mirror_auth <user> <pw-file>` | location | credential for the upstream **token realm** |
| `brix_oci_upstream_namespace <ns>` | location | prefix for single-component names |
| `brix_oci_upstream_auth_realm <host>` | http/server/location | one extra host a token realm may live on; repeatable — see §5.1 |
| `brix_oci_mirror_insecure on` | location | permits a cleartext `http://` upstream base — test fixtures |
| `brix_oci_mirror_delegate on` | location | pulls carry the **client's** credential; authorize-on-hit — see §5.2 |
| `brix_oci_delegate_realm <name>` | http/server/location | the Basic realm challenged downstream; default `brix-oci` |
| `brix_oci_delegate_proof_ttl <time>` | http/server/location | how long a per-(credential, repo) grant is remembered; default 300s |
| `brix_oci_delegate_insecure on` | location | waives the delegate-mode TLS mandate — test fixtures |

---

## 3. Cache policy: two classes, one rule

The cache key *is* the route (`/v2/<name>/(manifests|blobs)/<ref>`), and the
tiers read the reference back off it:

- **`blobs/sha256:…`** and **`manifests/sha256:…`** — content-addressed,
  therefore immutable. Cached until evicted; no revalidation is meaningful,
  because a different object would have a different URL.
- **`manifests/<tag>`** — the only mutable mapping in the API. Governed by
  `brix_oci_manifest_ttl`. 60 s is a good default: short enough that
  `:latest` moves within a minute of upstream, long enough that a CI herd
  does not re-run the token dance per job.

Beside each cached object sits an **`.ocimeta` sidecar** — one `key=value`
line per field: the media type to echo, the content digest to advertise, the
upstream ETag, the fetch time, and whether the fill was digest-verified.
Podman and docker both branch on a manifest's `Content-Type` (an OCI index
and a Docker manifest list are the same shape and different objects) and
both read `Docker-Content-Digest`; neither is recoverable from a
tag-addressed cache path, and re-deriving them per hit would hash the
manifest on the event loop. The sidecar is a **cache of a pure function of
the bytes**: if it is missing or unparsable, the answer is re-derived, never
wrong.

The sidecar lives in the cache store's directory beside the body. It is not
served, and clients never see it.

---

## 4. Verification, and what happens when it fails

`brix_cache_verify oci-digest` hashes the filled bytes and compares against
the digest in the request's own URL **before** the object is published to
the cache. On mismatch:

- nothing is admitted to the cache — the partial is discarded;
- the client gets a **502** with an `UNAVAILABLE` envelope;
- `brix_oci_verify_fail_total` increments;
- one guard line is written with `signal=oci_tamper`, naming the
  **upstream** as the host (a fill is detached — there is no client to
  blame).

The matching fail2ban jail ships **disabled** (`deploy/fail2ban/jail.d/
xrootd-guard.conf`). Banning here removes the mirror's upstream for
everybody, and the corruption was already refused; enable it only when the
offender is one edge of a set you can afford to lose.

Run without `brix_cache_verify` and you have a generic HTTP cache with a
registry-shaped URL. There is no reason to.

---

## 5. Talking to a private or rate-limited upstream

```nginx
brix_oci_mirror_auth robot@example.org /etc/brix/oci-upstream.pw;
```

TAKE2: a username and a **file** holding the password, read once at config
load. The password never appears in the configuration, and the credential is
presented to the **token realm only** — never to a redirect target, and
never to the CDN the realm hands back. That distinction is load-bearing:
registries routinely redirect blob GETs to a signed CDN URL, and forwarding
an `Authorization` header there would leak the credential to a third party
(and, on some CDNs, break the signature).

### 5.1 When the token service is on another domain

A `realm=` in a `WWW-Authenticate` header is an instruction to go hand a
credential to a host the *upstream* named, so the mirror only follows one it
can tie back to the upstream: the same host, its registrable parent domain, or
a sibling under that parent. That covers every registry that runs its own
token service — `registry-1.docker.io` → `auth.docker.io` is the shape — and
the refusal is logged with `signal=oci_realm_refused`.

A registry that delegates to an unrelated identity host has no spelling of
that shape, and would otherwise be unmirrorable. Name the host:

```nginx
brix_oci_upstream_auth_realm sso.identity.example;
```

Repeatable, up to eight entries, and each is **one exact host**. There is no
pattern form: a `*.example` entry is how one line silently re-admits every
host under a domain you do not run. An entry with a scheme, a port, a
wildcard, or a duplicate is refused at `nginx -t` — the port in particular,
because the trust rule compares hosts, so accepting `auth.example:8443` would
read as pinning a port that nothing checks.

Each dance that uses the widened boundary logs one INFO line naming the host,
so "which realm did we actually trust" is answerable from the log rather than
from the config.

### 5.2 Delegated pull: the client's own credential (D16)

`brix_oci_mirror_auth` gives the mirror **one** service identity. When the
upstream holds private repositories with per-user visibility, that is the
wrong shape: either the service account can see everything (and the mirror
becomes a leak) or it can see nothing. Delegate mode makes the mirror carry
the *client's* credential instead:

```nginx
brix_oci_mirror_delegate on;
# brix_oci_delegate_realm  brix-oci;   # the Basic realm shown downstream
# brix_oci_delegate_proof_ttl 300s;    # how long a grant is remembered
```

`docker login mirror.example.org` stores the user's own upstream credential;
the client presents it as `Basic` on every pull. The mirror replays it to
**the allowlisted token endpoint only** — never to the data plane, never to a
CDN redirect — mints a bearer, and then *verifies* the grant with a HEAD of
the requested object (a token endpoint of DockerHub's shape answers a denied
scope with a 200 and an empty grant, so "the mint worked" proves nothing).
The result is a per-(credential, repository) **proof**, cached in the token
zone for `brix_oci_delegate_proof_ttl` (default 300 s).

The properties that follow:

- **Authorize-on-hit.** The proof is demanded on every request against the
  gated routes — cache hit or miss, manifests, blobs, tags and referrers
  alike. A warm cache is not a bypass: a user whose upstream access was
  revoked loses the mirror within one proof TTL.
- **No stored secrets.** The credential exists in request memory for the
  duration of the token leg; what persists in SHM is a sha256 digest used
  purely as a cache key, and the minted bearer under that key.
- **One uniform refusal.** Wrong password, unknown account, valid account
  without access, repository that does not exist upstream: all are the same
  `401 DENIED` with the same `WWW-Authenticate: Basic` challenge. The mirror
  is not an oracle for account or repository existence.
- **Anonymous stays open.** A request without a credential mints an
  anonymous proof, exactly as docker itself would — public repositories keep
  serving without a login wall.

**TLS is mandatory.** A delegated credential on cleartext is already
compromised, so `brix_oci_mirror_delegate on` in a server block with no TLS
certificate is refused at `nginx -t`. `brix_oci_delegate_insecure on` states
a test fixture and nothing else.

`brix_oci_delegate_total{outcome=cached|granted|denied|error}` is the
observability: `denied` climbing tracks probing or revocation; `cached`
dwarfing `granted` means the proof TTL is doing its job.

Bearer tokens are cached in the SHM zone named by `brix_oci_token_zone`
(default `oci_tokens 1m`, roughly 125 live tokens — i.e. ~125 concurrently
pulled repositories per TTL window). Exhaustion costs a re-dance, never
correctness. `brix_oci_token_fetch_total{outcome=...}` tells you whether the
zone is doing its job: a `fetched` rate that tracks the pull rate means the
zone is too small or the tokens are short-lived.

---

## 6. Pointing clients at it

Per-invocation, treating the mirror as a registry:

```console
$ podman pull --tls-verify=false mirror.example.org:5000/library/alpine:3.19
```

Site-wide, as a mirror of an upstream (`/etc/containers/registries.conf`):

```toml
[[registry]]
prefix = "docker.io"
location = "docker.io"

[[registry.mirror]]
location = "mirror.example.org:5000"
```

With `brix_oci_upstream_namespace library`, a single-component name pulls
through the shorthand every client applies implicitly: `pull
mirror.example.org/alpine:3.19` reaches `<upstream>/v2/library/alpine`.
Multi-component names are already fully qualified and are passed through
untouched.

**Give the mirror a real certificate.** `--tls-verify=false` is a lab
setting; the lanes use it because podman is the only runtime that can be
told to trust a cleartext registry per invocation (docker needs
`insecure-registries` in `daemon.json` and an engine restart, which is not
something a test may do).

---

## 7. Observing it

Access log variables: `$oci_class` (api\|manifest\|blob\|upload\|tags\|bad)
and `$brix_cache_status` (`HIT`\|`MISS`\|`NEGHIT`\|`-`), the one
cross-plane cache vocabulary. Phase 112 removed the plane-local
`$oci_cache`: its `hit`/`fill`/`local` map onto `HIT`/`MISS`/`HIT`, and
`refused`/`error` — which were never cache dispositions — report `-`. The
refusal and the error are not lost: they are the `outcome` label on
`brix_oci_requests_total{surface,class,outcome}`.

```nginx
log_format oci '$remote_addr $status $body_bytes_sent '
               '$oci_class $brix_cache_status "$request"';
```

`local` is the `GET /v2/` liveness probe, answered without touching the
upstream. `wait`, `reval` and `stale` are deliberately *not* separate values:
a coalesced waiter and a revalidation both end as the fill that satisfied
them, and staleness is reported by the RFC 9111 `Warning` header on the
response instead.

The four numbers worth alerting on:

| Symptom | Metric |
|---|---|
| the cache is not absorbing traffic | `brix_oci_requests_total{outcome="hit"}` vs `{outcome="fill"}`, per `class` |
| the WAN bill | `brix_oci_fill_bytes_total` |
| the token dance is failing | `brix_oci_token_fetch_total{outcome="failed"}` |
| something served bytes that were not what they claimed | `brix_oci_verify_fail_total` |

Compute the hit ratio **per class**. Blobs and manifests have genuinely
different ratios and averaging them hides the interesting one.

---

## 8. Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| `[emerg] brix_oci_mirror "http://…": a cleartext upstream would hand every pulled token to the network` | `http://` base without the opt-in | give the upstream TLS, or `brix_oci_mirror_insecure on` for a fixture |
| every pull re-authenticates | token zone too small, or an upstream issuing very short tokens | raise `brix_oci_token_zone`; check `token_fetch_total{outcome="fetched"}` |
| `:latest` is stale for minutes | `brix_oci_manifest_ttl` too long | lower it; digest-pinned pulls are unaffected either way |
| client reports "unauthorized" from *our* mirror | an upstream 401 that survived the dance is remapped to **403** on purpose | fix `brix_oci_mirror_auth`, not the client |
| `429` with `Retry-After: 5` | the upstream throttled us | that hold-off is ours, not the upstream's — it reflects when *our* next attempt is worth making |
| `podman push` to the mirror "fails" | it is supposed to: 405 + `signal=ocipush` | push to a `brix_oci_registry` location instead ([oci-registry.md](oci-registry.md)) |
