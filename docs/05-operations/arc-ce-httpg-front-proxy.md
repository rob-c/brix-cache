# brix as an httpg forwarding proxy for ARC-CE

**Status: source- and lab-verified 2026-07-16** against NorduGrid ARC 7
(`nordugrid/arc-ce-image:rocky9-arc7-atlas`) with the ARC 7 client tools.
The executable form of everything on this page is
`tests/test_arc_httpg_proxy.py` + `tests/configs/nginx_arc_httpg_proxy.conf`.

Companion reference:
[credential-tiers-t-numbers.md](../10-reference/credential-tiers-t-numbers.md)
— what the delegated credentials are, how they are stored, T8 vs T4.

---

## 1. What problem this solves

ARC-CE's REST interface (`org.nordugrid.arcrest`, `/arex/rest/1.0/...`)
speaks **httpg**: ordinary HTTPS whose *client* authentication is an
**RFC 3820 proxy certificate** (`arcproxy` / `voms-proxy-init` output). Two
things break when you put a stock nginx in front of it:

1. **Stock nginx rejects proxy certificates.** OpenSSL refuses RFC 3820
   chains unless `X509_V_FLAG_ALLOW_PROXY_CERTS` is set on the verify
   context, and nginx never sets it — every grid client gets
   `400 Bad Request ("proxy certificates not allowed")`, even under
   `ssl_verify_client optional_no_ca`. The brix directive
   **`brix_webdav_proxy_certs on`** sets the flag on the listener's SSL_CTX
   (`src/protocols/webdav/postconfig.c`), making nginx verify grid proxies
   like any grid service.
2. **TLS client identity cannot be "forwarded".** The user's private key
   never leaves the user, so the proxy cannot replay the client's TLS auth on
   the back leg. The honest solution is **delegation**: each user deposits a
   short-lived proxy credential with the gateway (see §4), and the back leg
   presents *that user's own delegated credential* to the ARC-CE per request.
   The ARC-CE therefore authenticates, authorizes, and account-maps every
   request as the real submitting user — the gateway adds no identity of its
   own and holds no blanket super-credential.

## 2. Architecture

```
              front leg (httpg)                         back leg (httpg)
   ══════════════════════════════════════   ═══════════════════════════════════════
                                          │
 ┌──────────┐  TLS, client cert =         │            ┌──────────────────────────┐
 │  alice   │  alice's RFC3820 proxy      │            │                          │
 │ arcsub/  ├────────────────────────┐    │            │        ARC-CE            │
 │ arcstat/ │                        ▼    │            │  (A-REX + arcrest on     │
 │ arcget   │            ┌──────────────────────┐      │   :443, httpg)           │
 └──────────┘            │   nginx + brix       │      │                          │
                         │ ┌──────────────────┐ │ mTLS,│  authenticates each      │
 ┌──────────┐            │ │ ssl_verify_client│ │ cert=│  request as the REAL     │
 │   bob    │  TLS,      │ │ on  (FAIL-CLOSED)│ │ that │  user:                   │
 │ (his own ├───────────►│ │ + proxy certs OK │ ├─────►│   alice -> alice's jobs  │
 │  proxy)  │            │ └──────────────────┘ │user's│   bob   -> bob's jobs    │
 └──────────┘            │ ┌──────────────────┐ │deleg.│                          │
                         │ │ brix_guard (444  │ │proxy │  enforces ownership:     │
 ┌──────────┐            │ │ junk-path drop)  │ │      │  bob GET alice's session │
 │ scanner/ │  no cert / │ └──────────────────┘ │      │  -> 404                  │
 │ anonymous│  bad cert  │ ┌──────────────────┐ │      └──────────────────────────┘
 └────┬─────┘            │ │ delegation       │ │
      │                  │ │ endpoint (T8/T4) │ │      ┌──────────────────────────┐
      └───────X 400/     │ └──────────────────┘ │      │ credential store         │
        handshake fail   │                      │◄────►│ x5h-<sha256(DN)>.pem     │
        AT NGINX,        └──────────────────────┘ read │ (per-user delegated      │
        never proxied                             per  │  proxy, incl. KEY)       │
                                                  req. └──────────────────────────┘
```

Identity plumbing on the back leg — stock nginx, no custom code:

```
    verified front-leg leaf DN                       per-user credential file
 $ssl_client_s_dn_legacy                                     │
    │                                                        ▼
    │   map $ssl_client_s_dn_legacy $arc_cred {
    │       default "";                                  # no match -> NO cred
    └────►  "~^/DC=org/.../CN=alice(/CN=[0-9]+)*$"  /creds/x5h-3f1c….pem;
            "~^/DC=org/.../CN=bob(/CN=[0-9]+)*$"    /creds/x5h-77ab….pem;
        }
        proxy_ssl_certificate     $arc_cred;   # same combined PEM serves
        proxy_ssl_certificate_key $arc_cred;   # cert+chain AND key
```

The `(/CN=[0-9]+)*` tail matters: the front leg authenticates with a *proxy*,
whose leaf DN is the user DN plus one `/CN=<serial>` level per delegation
hop, and brix's GSI auth exposes that full leaf DN.

## 3. Fail-closed semantics (what fails where)

The design goal: **a failing handshake fails at nginx; a correctly
authenticating user's requests go through to the ARC-CE, and ARC-level
failures come back to the client as ARC's own answers.**

```
 client connects
      │
      ▼
 ┌─────────────────────────────┐   no cert presented, or cert does not
 │ TLS handshake +             │   chain to the grid CA, or proxy chain
 │ ssl_verify_client on        ├──────────► REJECTED AT NGINX (TLS alert /
 │ (+ brix_webdav_proxy_certs) │            400).  Nothing is proxied; the
 └──────────────┬──────────────┘            ARC-CE never sees the request.
                │ verified grid identity
                ▼
 ┌─────────────────────────────┐   junk path (scanner signature, e.g.
 │ brix_guard  profile=arc     ├──────────► /wp-login.php): 444 connection
 └──────────────┬──────────────┘            drop + audit log line, even for
                │ legitimate ARC path       an authenticated client.
                ▼
 ┌─────────────────────────────┐   identity has no delegated credential:
 │ map -> $arc_cred            │   back leg connects with NO client cert
 │ proxy_pass https://ARC      ├──────────► ARC refuses (its own 4xx/5xx)
 └──────────────┬──────────────┘            and THAT answer is relayed
                │ delegated credential      verbatim to the client.
                ▼
     request runs at ARC as the user; every ARC outcome — success,
     unknown job 404, someone else's session 404, queue errors —
     is ARC's own response, delivered unmodified to the client.
```

Design choices that make it fail closed rather than fail quiet:

| Choice | Effect |
|---|---|
| `ssl_verify_client on` (not `optional`) | anonymous/untrusted clients die at nginx — the ARC-CE's attack surface is only ever exposed to CA-verified grid identities |
| `map ... default ""` | **no static fallback credential exists in the config**; an un-delegated identity cannot ride anyone else's credential (an empty `proxy_ssl_certificate` sends no client cert at all) |
| `proxy_ssl_verify on` + `proxy_ssl_trusted_certificate` | the gateway refuses to hand user credentials to an impostor backend |
| `brix_guard` before `proxy_pass` | scanner junk never consumes an ARC connection |

## 4. Delegation: how a user's credential gets to the gateway

The lab uses the **T8 proxy-upload** form (simplest client-side); the
**T4 GridSite two-step** form is equivalent and avoids sending the proxy key
over the wire — both are documented in depth in
[credential-tiers-t-numbers.md](../10-reference/credential-tiers-t-numbers.md).

```
 alice (has EEC + fresh arcproxy)                 gateway
    │                                                │
    │ PUT /.well-known/brix-delegation               │ PKIX-verify chain vs grid CA
    │   TLS client cert = EEC  (NOT the proxy!)      │ EEC DN must == authenticated DN
    │   body = userproxy.pem (cert+key+chain)        │ store verbatim ->
    ├───────────────────────────────────────────────►│ creds/x5h-<sha256(DN)>.pem
    │ 201 Created                                    │
    │◄───────────────────────────────────────────────┤
```

Notes that bite in practice:
- **Authenticate the upload with the EEC**, not the proxy: the delegation
  endpoint's strict DN check compares the uploaded chain's EEC subject with
  the authenticated DN; a proxy-authenticated upload has the extra
  `/CN=<serial>` level and is refused 403 (by design).
- The delegated proxy's lifetime bounds the exposure: when it expires, the
  stored file is dead weight and the user re-delegates.
- Users re-delegate whenever they refresh their proxy (`arcproxy` again →
  new serial, same DN → same store file, overwritten).

## 5. Complete example configuration (fail-closed)

Rendered template used by the automated lab:
`tests/configs/nginx_arc_httpg_proxy.conf`. Standalone version with concrete
paths — adjust ports/paths/DNs:

```nginx
worker_processes 1;
pid /var/run/brix-arc/nginx.pid;
error_log /var/log/brix-arc/error.log info;

events { worker_connections 1024; }

http {
    access_log /var/log/brix-arc/access.log;
    client_body_temp_path /var/run/brix-arc/tmp;
    proxy_temp_path       /var/run/brix-arc/tmp;

    # Verified front-leg identity (proxy leaf DN, oneline form) -> that
    # user's delegated credential.  default "" = FAIL CLOSED: no match
    # means the back leg carries no credential and ARC refuses.
    map $ssl_client_s_dn_legacy $arc_cred {
        default "";
        "~^/DC=org/DC=nordugrid/DC=ARC/O=TestCA/CN=alice(/CN=[0-9]+)*$"
            /dev/shm/brix-creds/x5h-3f1c9a...(alice-hash).pem;
        "~^/DC=org/DC=nordugrid/DC=ARC/O=TestCA/CN=bob(/CN=[0-9]+)*$"
            /dev/shm/brix-creds/x5h-77ab02...(bob-hash).pem;
    }

    server {
        # ── front leg: httpg, FAIL-CLOSED ────────────────────────────────
        listen 8443 ssl;
        ssl_certificate        /etc/grid-security/hostcert.pem;
        ssl_certificate_key    /etc/grid-security/hostkey.pem;
        ssl_client_certificate /etc/grid-security/certificates/grid-ca.pem;
        ssl_verify_client      on;          # no cert / untrusted cert
        ssl_verify_depth       10;          #   -> rejected here, never proxied
        brix_webdav_proxy_certs on;         # accept RFC 3820 proxy chains
        client_max_body_size   256m;

        # ── self-service delegation (T8 upload + T4 two-step) ───────────
        location /.well-known/brix-delegation {
            brix_webdav on;
            brix_export /var/lib/brix-arc/export;
            brix_allow_write on;            # REQUIRED: read-only 403s the PUT
            brix_webdav_cafile /etc/grid-security/certificates/grid-ca.pem;
            brix_webdav_auth required;
            # Optional: defaults to /dev/shm/brix-creds — a RAM-backed
            # (tmpfs) store created 0700 at config time, so delegated
            # private keys never persist across reboots or touch real
            # disk.  Set it only to override; "" disables the store.
            brix_storage_credential_dir /dev/shm/brix-creds;
            brix_delegation_endpoint on;
        }

        # ── everything else: guarded forward to the ARC-CE ───────────────
        location / {
            brix_guard on;
            brix_guard_profile arc;
            brix_guard_audit_log /var/log/brix-arc/guard-audit.log;

            proxy_pass https://arc-ce.internal:443;
            proxy_http_version 1.1;
            proxy_set_header Connection "";
            proxy_set_header Host $http_host;   # A-REX builds session hrefs
                                                # from Host; arcget breaks
                                                # without this
            # back leg presents THE USER'S delegated credential:
            proxy_ssl_certificate         $arc_cred;
            proxy_ssl_certificate_key     $arc_cred;
            proxy_ssl_trusted_certificate /etc/grid-security/certificates/grid-ca.pem;
            proxy_ssl_verify on;                # never leak creds to an
            proxy_ssl_name arc-ce.internal;     # impostor backend
            proxy_ssl_server_name on;
        }
    }
}
```

Map entries are mechanical to generate — for each user, escape the DN for
regex and derive the store filename:

```python
import hashlib, re
dn = "/DC=org/DC=nordugrid/DC=ARC/O=TestCA/CN=alice"
key = "x5h-" + hashlib.sha256(dn.encode()).hexdigest()[:32]
print(f'"~^{re.escape(dn)}(/CN=[0-9]+)*$" /dev/shm/brix-creds/{key}.pem;')
```

## 6. Building the test cluster from scratch

Everything below is what `tests/test_arc_httpg_proxy.py` automates; run it
manually to get a poke-able cluster. Host prerequisites: `docker`, the
`nordugrid-arc7-client` package (`arcproxy`/`arcsub`/`arcstat`/`arcget`), and
a brix nginx build (`objs/nginx`).

```
   host                                     docker
 ┌─────────────────────────────────┐     ┌──────────────────────────────────┐
 │ brix nginx        :18443 (front)│     │ arc-ce-image  (--hostname        │
 │ arc client tools                │     │  localhost, sleep infinity)      │
 │ alice/, bob/ user credentials   │     │  A-REX + arcrest  :443 ──────────┼──► published to
 │ creds/ delegated store          │     │  fork queue (runs jobs in-place) │    127.0.0.1:18444
 │ certificates/ (ARC test CA)     │     │  test-CA + host/user certs       │
 └─────────────────────────────────┘     └──────────────────────────────────┘
```

### 6.1 Start the ARC-CE container

```bash
docker pull nordugrid/arc-ce-image:rocky9-arc7-atlas
docker run -d --name brix-arc --hostname localhost \
    -p 127.0.0.1:18444:443 \
    nordugrid/arc-ce-image:rocky9-arc7-atlas sleep infinity
```

`--hostname localhost` matters: the image's host certificate must match the
name the gateway's `proxy_ssl_name`/`proxy_ssl_verify` checks.

### 6.2 Regenerate the test PKI inside the container (the baked-in one is expired)

```bash
docker exec brix-arc arcctl test-ca init -f
docker exec brix-arc arcctl test-ca hostcert -f
docker exec brix-arc arcctl test-ca usercert -t -n alice -f
docker exec brix-arc arcctl test-ca usercert -t -n bob   -f
```

### 6.3 Start A-REX and the REST (WS) interface — the image has no systemd

```bash
docker exec brix-arc /usr/share/arc/arc-arex-start
docker exec brix-arc /usr/share/arc/arc-arex-ws-start
```

### 6.4 Copy the trust anchors and user bundles out

```bash
mkdir -p lab && cd lab
docker cp brix-arc:/etc/grid-security/testCA-hostcert.pem .   # gateway host cert
docker cp brix-arc:/etc/grid-security/testCA-hostkey.pem  .   # gateway host key
docker cp brix-arc:/usercert-alice.tar.gz .
docker cp brix-arc:/usercert-bob.tar.gz   .
mkdir alice bob && tar -C alice -xf usercert-alice.tar.gz \
                && tar -C bob   -xf usercert-bob.tar.gz
# Trust anchor for BOTH legs = the ARC test CA only (NOT the IGTF bundle):
CA=$(ls alice/arc-testca-usercert/certificates/ARC-TestCA-*.pem | head -1)
```

### 6.5 Make each user a proxy

```bash
for u in alice bob; do
  cred=$PWD/$u/arc-testca-usercert
  X509_USER_CERT=$cred/usercert.pem  X509_USER_KEY=$cred/userkey.pem \
  X509_USER_PROXY=$cred/userproxy.pem X509_CERT_DIR=$cred/certificates \
    arcproxy
done
```

### 6.6 Configure and start the gateway

Render §5's config with front port 18443, backend port
18444, host cert/key from 6.4, `ssl_client_certificate`/cafile/trusted = the
`$CA` file, and one map entry per user
(DN = `/DC=org/DC=nordugrid/DC=ARC/O=TestCA/CN=<user>`; filename from the
snippet in §5). Then:

```bash
objs/nginx -t -c $PWD/nginx.conf && objs/nginx -c $PWD/nginx.conf
```

The credential store itself needs no setup: config parse creates
`/dev/shm/brix-creds` mode-0700 (chown'd to the worker user when the master
runs as root). If the path is unusable — not creatable, wrong owner,
group/other-accessible — `nginx -t` prints a `[warn]` telling you delegation
will not work until `brix_storage_credential_dir` is fixed, but never refuses
to start.

### 6.7 Each user delegates a credential to the gateway (T8)

```bash
for u in alice bob; do
  cred=$PWD/$u/arc-testca-usercert
  curl -sk --cert $cred/usercert.pem --key $cred/userkey.pem \
       -T $cred/userproxy.pem \
       https://127.0.0.1:18443/.well-known/brix-delegation
done
ls /dev/shm/brix-creds/   # -> x5h-<hash-alice>.pem  x5h-<hash-bob>.pem
```

(EEC cert/key on the curl — see §4. Expect `OK`, HTTP 201, and one complete
`.pem` per user in the store.)

### 6.8 Submit / query / retrieve a hello-world job — through the gateway

`hello.xrsl` (the fork queue runs it in the container):

```
&( executable = "/bin/sh" )
 ( arguments = "-c" "echo hello-from-arc; id -un" )
 ( jobname = "brix-hello" )
 ( stdout = "stdout.txt" )( stderr = "stderr.txt" )
 ( queue = "fork" )
```

As alice (same env vars as 6.5, plus point the tools at the FRONT port):

```bash
export X509_USER_PROXY=$PWD/alice/arc-testca-usercert/userproxy.pem
export X509_CERT_DIR=$PWD/alice/arc-testca-usercert/certificates

arcsub  -C https://localhost:18443/arex -T arcrest -Q NONE \
        -j jobs.dat hello.xrsl
# Job submitted with jobid:
#   https://localhost:18443/arex/rest/1.0/jobs/<id>
#                     ^^^^^ the job id EMBEDS the gateway URL, so every
#                           later arcstat/arcget automatically routes
#                           through the front proxy.

arcstat -j jobs.dat -a            # poll until Finished
arcstat -j jobs.dat -a -l         # long form; the identity proof:
# Job: https://localhost:18443/arex/rest/1.0/jobs/<id>
#  Name: brix-hello
#  State: Finished
#  Exit code: 0
#  Owner: /DC=org/DC=nordugrid/DC=ARC/O=TestCA/CN=alice   <== the ARC-CE
#         authenticated the forwarded request as ALICE, not as a gateway
#         service identity.  Submit as bob and Owner: is ...CN=bob.

arcget -j jobs.dat -a -D out -k
cat out/*/stdout.txt
# hello-from-arc
# <container uid the fork queue mapped alice to>
```

### 6.9 Verify the fail-closed properties by hand

```bash
# anonymous -> refused AT NGINX (400, never proxied):
curl -sk -o /dev/null -w '%{http_code}\n' \
     https://127.0.0.1:18443/arex/rest/1.0/jobs            # -> 400

# untrusted (self-signed) client cert -> refused at nginx:
openssl req -x509 -newkey rsa:2048 -nodes -subj "/DC=org/DC=evil/CN=mallory" \
        -keyout evil.key -out evil.pem -days 1
curl -sk --cert evil.pem --key evil.key -o /dev/null -w '%{http_code}\n' \
     https://127.0.0.1:18443/arex/rest/1.0/jobs            # -> 400

# authenticated but junk path -> guard drops the connection (curl exit 52):
curl -sk --cert alice/.../userproxy.pem --key alice/.../userproxy.pem \
     https://127.0.0.1:18443/wp-login.php ; echo "exit=$?" # -> exit=52 (444)

# authenticated, delegated, cross-user isolation enforced BY ARC:
#   bob GET alice's session file -> ARC's own 404, relayed to bob.
```

### 6.10 Teardown

```bash
objs/nginx -c $PWD/nginx.conf -s stop
docker rm -f brix-arc
```

## 7. Request lifecycles (sequence detail)

Job submission, the full path:

```
 alice            nginx front              cred store         ARC-CE (A-REX)
   │ TLS: alice's     │                        │                   │
   │ proxy chain      │                        │                   │
   ├─────────────────►│ verify vs grid CA      │                   │
   │                  │ (proxy certs allowed)  │                   │
   │ POST /arex/rest/ │                        │                   │
   │ 1.0/jobs (xRSL)  │                        │                   │
   ├─────────────────►│ guard: path OK         │                   │
   │                  │ map: alice's DN ──────►│ x5h-<alice>.pem   │
   │                  │                        │ (cert+chain+KEY)  │
   │                  │ mTLS to ARC, client cert = alice's         │
   │                  │ delegated proxy; Host preserved            │
   │                  ├───────────────────────────────────────────►│
   │                  │                        │     authn: ALICE  │
   │                  │                        │     create job,   │
   │                  │ 201 + jobid (URL embeds the gateway host:  │
   │                  │ port because A-REX honours Host)           │
   │◄─────────────────┼◄───────────────────────────────────────────┤
   │ jobs.dat now routes all arcstat/arcget through the gateway    │
```

The three failure lanes, side by side:

```
 lane A: bad handshake          lane B: authed, junk path    lane C: authed, ARC-level failure
 ──────────────────────         ─────────────────────────    ─────────────────────────────────
 client ──X                     client ────► nginx           client ────► nginx ────► ARC
   TLS alert / 400                │ guard signature             │            │  e.g. bob asks
   at nginx;                      ▼ match                      │            │  for alice's file
   ARC never touched            444: connection                │            ▼
                                dropped, audit line          ◄─┴── ARC's own 404/4xx/5xx
                                written; ARC never                 relayed unmodified
                                touched                            to the client
```

## 8. Troubleshooting

| Symptom | Cause / fix |
|---|---|
| every grid client gets `400 ... proxy certificates not allowed` | `brix_webdav_proxy_certs on` missing on the front server block |
| delegation PUT → 403, nginx error page, no delegation log line | delegation location lacks `brix_allow_write on` (read-only export refuses the PUT before delegation dispatch) |
| delegation PUT → 403 with a `GSI auth OK dn=".../CN=<serial>"` log line | upload was authenticated with the **proxy**; use the EEC cert/key (§4) |
| arcsub OK but arcget/arcstat hit the backend directly or 404 | `proxy_set_header Host $http_host` missing — A-REX builds session hrefs from Host |
| back leg 502/SSL errors | `proxy_ssl_name`/`proxy_ssl_trusted_certificate` don't match the ARC host cert (with the docker image: run it `--hostname localhost` and trust the regenerated test CA, **not** the IGTF bundle) |
| everything on the container 40x's after a while | the image's baked-in test CA was expired at first start and you skipped §6.2, or the regenerated certs expired — rerun `arcctl test-ca ...` |
| authenticated user's ARC requests fail with no credential | that user never delegated (or the delegated proxy expired) — check `creds/x5h-*.pem` exists, is fresh, and the map regex matches the *full leaf* DN including `(/CN=[0-9]+)*` |
| `docker run -p` fails with a `/forwards/expose` 500 (WSL2) | transient WSL port-forward flake — pick another host port |

## 9. Limits and honest caveats

- **Delegation is explicit.** A user who has not delegated can authenticate
  to the gateway but achieves nothing at ARC. That is the intended
  fail-closed behaviour, not a bug — but it means client onboarding includes
  the one-time (per-proxy-lifetime) delegation step from §6.7.
- **The map is static config.** Adding a user means adding a map entry and
  reloading nginx (`nginx -s reload` is hitless). Auto-discovery of the
  credential dir would need dynamic config generation around nginx.
- **T8 sends the proxy's private key over the (EEC-authenticated, encrypted)
  front leg.** Where that is unacceptable, use the T4 two-step form — same
  endpoint, GridSite-shaped, key never crosses the wire; see the
  [credential reference](../10-reference/credential-tiers-t-numbers.md).
- The gateway host must be trusted to hold delegated user proxies — same
  posture as any FTS/myproxy-style delegation holder. The default store
  (`/dev/shm/brix-creds`, tmpfs, auto-created 0700) already keeps keys off
  real disk and wipes them on reboot; the residual exposures are a live
  compromise of the service uid (or root) and tmpfs pages reaching swap —
  use encrypted swap (or none) on the gateway. Users re-delegate after a
  reboot, exactly as they do when a proxy expires.
