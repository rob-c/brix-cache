# CVMFS site-cache demo container (CentOS Stream 9)

One container, **one nginx config**, proving the whole phase-68 stack
coexists in a single process:

| Port | Surface |
|---|---|
| **3128** | `cvmfs://` site cache, forward-proxy mode (`CVMFS_HTTP_PROXY` target), CAS verify-on-fill, never-drop semantics, **bad-actor guard** active on the listener |
| **3129** | built-in operator dashboard (`/xrootd/`) |
| **3130** | Prometheus `/metrics` + `/healthz` |
| (internal) | loopback `root://` stream endpoint on 127.0.0.1:1094 — registers the dashboard SHM zones and proves the stream plane shares the config |

**fail2ban runs inside the container**, consuming two independent bad-actor
signals: the guard audit log (`xrootd-guard-*` jails, phase-65) and the
`cvmfs-reject:` classifier lines in the nginx error log
(`nginx-xrootd-cvmfs` jail, phase-68). With `--cap-add=NET_ADMIN` the bans
are real nftables rules; without it fail2ban still detects and counts
(no-op ban action), visible via `fail2ban-client status`.

## Build & run

From the **repo root** (the `.dockerignore` whitelists `config` + `src`):

```bash
docker build -t nginx-xrootd-cvmfs -f deploy/cvmfs/docker/Dockerfile .

docker run -d --name cvmfs-demo --cap-add=NET_ADMIN \
    -p 3128:3128 -p 3129:3129 -p 3130:3130 \
    nginx-xrootd-cvmfs
```

Env knobs (`docker run -e …`):

| Var | Default | Meaning |
|---|---|---|
| `DASH_PASSWORD` | `cvmfs-demo` | dashboard password |
| `UPSTREAM_ALLOW` | CERN + RAL + BNL + FNAL + OSG Stratum-1s | space-separated hosts a client may proxy to |
| `MOCK_STRATUM1=1` | off | offline mode: bundled mock Stratum-1 on container-local `127.0.0.1:8000`, auto-allowlisted |

## Automated proof

```bash
deploy/cvmfs/docker/smoke.sh          # real Stratum-1s (needs internet)
deploy/cvmfs/docker/smoke.sh --mock   # fully offline
deploy/cvmfs/docker/smoke.sh --keep   # leave it running afterwards
```

Checks: cold fill + byte-exact warm hit through 3128, cvmfs Prometheus
counters on 3130, dashboard on 3129, classifier reject → 403 +
`cvmfs-reject:` log line, a 25-request reject storm **actually banned** by
the `nginx-xrootd-cvmfs` jail (and really blocked when NET_ADMIN is
present), and a `wp-login.php` scanner probe instant-banned by the
`xrootd-guard-signature` jail.

## Pointing an official CVMFS client at it

On the client machine (with `cvmfs` + `cvmfs-config-default` installed):

```bash
# /etc/cvmfs/default.local
CVMFS_CLIENT_PROFILE=single
CVMFS_HTTP_PROXY="http://<docker-host>:3128"
# IMPORTANT: keep CVMFS_TIMEOUT above the cache's client-hold (25 s), so the
# cache's 504+Retry-After never-drop answers are retried, not failed over:
CVMFS_TIMEOUT=30
CVMFS_TIMEOUT_DIRECT=10

cvmfs_config setup
cvmfs_config probe cvmfs-config.cern.ch
ls /cvmfs/sft.cern.ch
```

The default `UPSTREAM_ALLOW` covers the standard `CVMFS_SERVER_URL` hosts
for CERN-distributed repositories. If your repo's Stratum-1 is elsewhere,
add its hostname: `-e UPSTREAM_ALLOW="… my-stratum1.example.org"`.

Then watch it work:

- **Dashboard:** `http://<docker-host>:3129/xrootd/` (password above) —
  live transfers, per-protocol counters (`cvmfs` identity), events.
- **Prometheus:** `curl http://<docker-host>:3130/metrics | grep cvmfs_` —
  request classes, fills, verify failures, origin failovers, the
  hit/fill byte split (`xrootd_cvmfs_bytes_served_total`) vs WAN-in
  (`xrootd_cvmfs_origin_bytes_total`).
- **Health:** `curl http://<docker-host>:3130/healthz` — includes
  per-origin fail scores.
- **Bans:** `docker exec cvmfs-demo fail2ban-client status
  nginx-xrootd-cvmfs` (and `xrootd-guard-signature` etc.). Trigger one
  yourself: `for i in $(seq 25); do curl -s -x http://<docker-host>:3128
  http://cvmfs-stratum-one.cern.ch/cvmfs/x/junk-$i.txt -o /dev/null; done`

## Notes

- The dashboard is **admin-only by design** (it shows client IPs and
  paths): firewall 3129/3130 in any real deployment; the demo only
  password-protects it.
- The cache store is a volume (`/var/cache/nginx-cvmfs`); quarantined
  CAS-verify mismatches land in `/var/cache/nginx-cvmfs-quarantine`.
- Logs: `docker exec cvmfs-demo ls /var/log/nginx-xrootd/` —
  `cvmfs_access.log` uses the `$cvmfs_class`/`$cvmfs_cache`/`$cvmfs_origin`
  identity format, `error.log` carries `cvmfs-reject:` lines,
  `guard-audit.log` feeds the guard jails.
- Protocol reference: [docs/04-protocols/cvmfs.md](../../../docs/04-protocols/cvmfs.md).
