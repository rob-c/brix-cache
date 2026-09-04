# Running an RPM/dnf pull-through mirror

**Status: source-verified 2026-08-19.** The executable form of this page is
`tests/test_rpm_mirror_native.py` (block 14170) and
`tests/test_rpm_mirror_dnf.py` (block 14160), over
`deploy/rpm-mirror/brix.conf.example` and
`deploy/rpm-mirror/nginx.conf.example` respectively.

**Two ways to run this mirror, and §7 is the one to read first.** Sections
1–6 describe the *stock nginx* recipe — no brix directives, so it runs in
front of any nginx build. [§7](#7-the-native-surface-brix_rpm_mirror) is the
same mirror as this server's own surface, which is the default answer here
because it can verify a checksum and refuse a write; the wire contract is
[../04-protocols/rpm.md](../04-protocols/rpm.md).

Companion pages:
[rpm-on-cvmfs.md](rpm-on-cvmfs.md) — the *other* RPM plane: publishing your
own repository rather than caching someone else's ·
[cvmfs-stratum0.md](cvmfs-stratum0.md).

---

## 1. What this is, and why it is so small

A pull-through mirror caches an upstream RPM repository on first request and
serves every later request locally. There is no synchronisation job, no
`reposync` cron, no "is the mirror behind?" — the first client to ask for a
package pulls it, and everyone after that gets it from disk.

It is small because an RPM repository has exactly two classes of object:

| Class | Examples | Mutable? | Policy |
|---|---|---|---|
| freshness root | `repodata/repomd.xml`, `.asc`, `.key` | yes | short TTL |
| content | `repodata/<sha256>-primary.xml.gz`, `Packages/*.rpm` | no | cache ~forever |

The metadata files are **digest-named**: their checksum is their filename, so
new content is always a new URL and a cached copy can never be wrong. The
packages are immutable in practice and are verified client-side anyway. Only
`repomd.xml` — the one document that says what the repository currently
contains — has to expire.

That split is the entire configuration. It is the same rule the CVMFS site
cache applies to `.cvmfspublished` versus `data/`
(`deploy/cvmfs/nginx-proxy-cache.conf`), and the same rule an OCI mirror
applies to tags versus blobs.

---

## 2. Deploying it

Copy `deploy/rpm-mirror/nginx.conf.example`, substitute the three
placeholders, and start nginx:

| Placeholder | Meaning |
|---|---|
| `@PORT@` | port the mirror listens on |
| `@CACHEDIR@` | writable directory for the cache store, logs and pid |
| `@ORIGIN@` | `host:port` of the upstream repository |

```sh
# nginx creates only the last component of a *_temp_path, so make the parents
install -d /var/cache/brix-rpm-mirror/{store,tmp}
sed -e 's|@PORT@|8080|' \
    -e 's|@CACHEDIR@|/var/cache/brix-rpm-mirror|' \
    -e 's|@ORIGIN@|mirror.example.org:80|' \
    deploy/rpm-mirror/nginx.conf.example > /etc/nginx/rpm-mirror.conf
nginx -t -c /etc/nginx/rpm-mirror.conf
nginx    -c /etc/nginx/rpm-mirror.conf
```

Stock nginx grammar throughout — `proxy_pass` + `proxy_cache` — so this runs
on the brix build or on a distribution nginx. No brix directives are involved
and nothing needs to be enabled.

### 2.1 Client side

```ini
# /etc/yum.repos.d/upstream-via-mirror.repo
[baseos]
name=BaseOS via the local mirror
baseurl=http://mirror.internal:8080/9/BaseOS/x86_64/os
enabled=1
gpgcheck=1
repo_gpgcheck=1
gpgkey=file:///etc/pki/rpm-gpg/RPM-GPG-KEY-redhat-release
```

Point `baseurl=` at the mirror and change nothing else. In particular **keep
`gpgcheck=1`** — see §4.

---

## 3. The policy, and why each line is the way it is

### 3.1 Short TTL on `repomd.xml`, and no stale serving

```nginx
location ~ ^/.*/repodata/repomd\.xml(\.asc|\.key)?$ {
    proxy_cache_valid 200 60s;
    proxy_cache_use_stale off;
    proxy_cache_revalidate on;
}
```

dnf sends `Cache-Control: no-cache` on this request specifically — it wants
the current one. nginx does not honour client `no-cache` for cache lookups
unless `proxy_cache_bypass` tells it to, and the example config does not, so
the 60 s TTL is what bounds staleness. That is deliberate: honouring every
client's `no-cache` would mean every `dnf install` on every node reaching
upstream, which is the stampede the mirror exists to prevent.

`proxy_cache_use_stale off` is the load-bearing choice. Everywhere else,
serving stale content when the upstream is unreachable is good availability
engineering. Here it is not: `repomd.xml` is the document that says what the
repository contains, and serving an expired one because upstream is down is
how a mirror starts quietly concealing a security update. It fails loudly
instead, and §5 covers what that looks like.

`proxy_cache_revalidate on` makes the refresh cheap — a conditional request,
`304`, no re-transfer — so the short TTL costs a round trip, not a download.

### 3.2 Cache-forever on everything else

```nginx
location ~ ^/.*/repodata/ { proxy_cache_valid 200 720h; }
location ~ \.(rpm|drpm)$  { proxy_cache_valid 200 720h; }
```

Safe because the names are digests. A 30-day TTL rather than a literal
infinity only so that `inactive=90d` eviction has something to work with.

### 3.3 Ignoring upstream cache headers

```nginx
proxy_ignore_headers Cache-Control Expires Set-Cookie X-Accel-Expires;
```

Public mirrors send caching headers tuned for browsers and CDNs. The policy
here is derived from the repository *format*, which we know more about than
their CDN config does, so theirs is discarded.

### 3.4 Bounded timeouts

```nginx
proxy_connect_timeout 5s;
proxy_read_timeout 20s;
```

This is what makes an unreachable upstream a prompt `502` that dnf reports,
instead of a hang.

### 3.5 Read-only

```nginx
if ($request_method !~ ^(GET|HEAD)$) { return 405; }
```

A mirror has no write surface. Anything else is a bug or an attack.

---

## 4. The mirror is not part of your trust chain

This is the most important operational property, and it is worth being
precise about: **the mirror never weakens RPM's trust chain, and it never
strengthens it either.**

dnf verifies, client-side:

1. the detached GPG signature on `repomd.xml` (`repo_gpgcheck=1`),
2. every metadata file against the checksum `repomd.xml` gives for it,
3. every package against the checksum `primary.xml` gives for it, and
4. the package's own GPG signature (`gpgcheck=1`).

All four are computed on the bytes dnf received. A mirror that corrupted or
substituted anything is caught by the client, not by the mirror. Which means:

- You do **not** need to trust the mirror host with repository integrity.
- You do need it to pass bytes through unmodified — which is what the
  configuration above does, and what the third lane of
  `tests/test_rpm_mirror_dnf.py` proves by re-signing a fixture repository
  with the wrong key and confirming dnf refuses it *through* the mirror.
- Turning off `gpgcheck` because "it is only our internal mirror" removes the
  protection and gains nothing. Keep it on.

---

## 5. Failure modes

| Symptom | Cause | What to do |
|---|---|---|
| dnf: "Failed to download metadata" right after upstream goes down | expired `repomd.xml`, `use_stale off` (§3.1) | intended behaviour — the mirror is refusing to guess. Restore upstream, or repoint `baseurl` |
| dnf installs work fine with upstream down | packages and digest-named metadata are cached, and dnf's own metadata cache is still inside `metadata_expire` | also intended — this is the mirror doing its job |
| new package upstream not visible for up to a minute | 60 s `repomd.xml` TTL | wait it out, or lower the TTL and accept more upstream traffic |
| every request is a `MISS` | cache dir not writable, or the response is not matching a cacheable location | check `X-Brix-Cache` on the response and the error log; unknown URL shapes fall through to the uncached `location /` by design |
| `405` from the mirror | something tried to write | a mirror is read-only (§3.5) |
| disk filling | `max_size=50g` too high for the volume | lower it; nginx evicts least-recently-used |

`X-Brix-Cache` carries `$upstream_cache_status` (`HIT`/`MISS`/`EXPIRED`/
`REVALIDATED`/`STALE`) on every classified response, so `curl -sI` is the
fastest way to see which policy a URL landed in.

---

## 6. Mirroring several repositories

The example config mirrors one upstream. For several, the cheapest approach
is one `server` block per upstream on its own port, sharing the
`proxy_cache_path` zone — the cache key is `$uri`, so give each upstream a
distinct path prefix or a distinct `keys_zone` to avoid collisions between
repositories that use the same paths.

---

## 7. The native surface (`brix_rpm_mirror`)

Everything above is a policy expressed in `location` regexes. This server can
express it as a route instead:

```nginx
location / {
    brix_rpm_mirror       https://mirror.example.org/el9;
    brix_cache_store      posix:/var/cache/brix-rpm-mirror/store;
    brix_cache_verify     rpm-repodata;
    brix_rpm_metadata_ttl 60s;
}
```

That is the whole configuration — `deploy/rpm-mirror/brix.conf.example` is the
same thing with the surrounding `http {}` and the reasoning in comments. One
location covers the repository because the classifier reads the route from the
path, so there are no blocks to keep in sync.

**What you get that the recipe cannot give you.**

| | recipe (§1–6) | `brix_rpm_mirror` |
|---|---|---|
| TTL split | two `location ~` blocks | the classifier's verdict |
| digest-named metadata | cached by pattern | **hashed and checked** against the digest in its own name, before it is published |
| write attempt | `405` from an `if` | `405` at the gate + `signal=rpmwrite` for fail2ban |
| tampered upstream | cached and served | `502`, nothing stored, `signal=rpm_tamper` |
| which route did this request take | infer from the URL | `$rpm_class` / `$brix_cache_status`, and `brix_rpm_requests_total{class,outcome}` |
| upstream flapping | `502` from `proxy_next_upstream` | held to the fill deadline, then `504` + `Retry-After` |

**Two things it refuses to start with**, both deliberate: any
`brix_cache_verify` value other than `rpm-repodata` (a mirror that does not
check the one proof the repository hands it for free is a mirror whose config
is lying), and an `http://` upstream without `brix_rpm_mirror_insecure on`.

**The client side is unchanged** — §2.1's `.repo` stanza works against either,
and so does §4: the mirror is still not part of your trust chain. Verifying at
the edge is a second, independent check that the metadata arrived intact; dnf's
GPG verification is the one that decides whether you trust the repository, and
this surface goes out of its way not to touch the bytes it checks.

**Warming the next two fetches.** Add `brix_rpm_prefetch on;` and a new
`repomd.xml` — one that was actually fetched, not a TTL re-read — makes the
mirror pull the `primary` and `filelists` it names, on the thread pool, before
the client asks for them. That is the whole of what dnf does next, so the first
`dnf makecache` after an upstream push stops paying for two serial round trips.
It is off by default because it spends upstream bandwidth for a client that may
never arrive; on a mirror, that trade is usually already made. It cannot be
steered by an attacker who controls the index: every href is re-read through
the classifier and warmed only if it is digest-named metadata, which then
verifies against its own name like any other fill. Watch
`brix_rpm_prefetch_total` and `brix_rpm_prefetch_fail_total` — warm failures
are invisible to clients by design, so that counter is where they surface.

**Several repositories** are one `location` each — a prefix per upstream in one
`server` — rather than §6's port per upstream, because the cache key is the
request URI and the store mirrors the URI tree.
