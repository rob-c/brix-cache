# Running the real pytest suite against the cluster (REMOTE mode)

The project's `tests/conftest.py` already supports a **REMOTE mode** built for
exactly this: set `TEST_SERVER_HOST` and it will *not* start a local fleet
(`manage_test_servers.sh start-all` is skipped), connecting instead to the server
at that host. Tests marked `requires_local_server` auto-skip; **378 of the 390
test files are remote-capable.**

## Why a single "mono" server (not one-pod-per-role)

REMOTE mode reaches every auth tier at **one** `SERVER_HOST` on **different ports**
(`:11094` anon, `:11095` gsi, `:11096` tls, `:11097` token, `:9100` metrics).
So the suite wants one server exposing all those ports — the shape of the repo's
`tests/configs/nginx_shared.conf`. That is `charts/topology-role/configs/fleet-mono.conf`:
one nginx-xrootd pod with a `server{}` block per auth tier, consuming the #1
authority plane (CA + host cert mounted; JWKS fetched over HTTP).

(The `main-fleet` chart's one-pod-per-role split is the right shape for topology
/ isolation testing; the mono server is the right shape for running the suite.)

## Recipe (verified)

```bash
NS=brix-suite
kubectl create namespace "$NS"
kubectl label ns "$NS" pod-security.kubernetes.io/enforce=baseline --overwrite

# 1. authority plane (release "auth" -> auth-ca-bundle / auth-pki / auth-jwks / auth-token-issuer)
helm upgrade --install auth charts/auth-authority -n "$NS" \
  --set services.ca=true,services.token=true,services.voms=false,services.krb5=false --wait

# 2. the mono fleet server (all auth ports in one pod), consuming the authorities
helm upgrade --install srv charts/topology-role -n "$NS" \
  --set role.name=mono,role.configKey=fleet-mono \
  --set role.ports[0].name=anon,role.ports[0].port=11094 \
  --set role.ports[1].name=gsi,role.ports[1].port=11095 \
  --set role.ports[2].name=tls,role.ports[2].port=11096 \
  --set role.ports[3].name=token,role.ports[3].port=11097 \
  --set role.ports[4].name=metrics,role.ports[4].port=9100 \
  --set role.auth.caBundle=auth-ca-bundle \
  --set role.auth.hostCertSecret=auth-pki \
  --set role.auth.jwksUrl=http://auth-token-issuer:8080/certs/jwks.json --wait

# 3. run remote-capable tests against the cluster fleet (REMOTE mode)
kubectl -n "$NS" run suite --rm -i --restart=Never \
  --image=brix-test-runner:dev --image-pull-policy=Never \
  --env=TEST_SERVER_HOST=srv-mono --env=TEST_ROOT=/tmp/tr --command -- \
  bash -lc 'mkdir -p /tmp/tr/data && cd /opt/brix && \
            pytest tests/ -m "not requires_local_server and not slow and not serial" -p no:xdist -q'
```

## Status & remaining wiring

- **Proven:** REMOTE mode skips the local-fleet start and connects to the cluster;
  a real `test_file_api.py` test **passes** against the mono server in-cluster.
- **Client-side scratch:** the runner needs `$TEST_ROOT/data` to exist (some
  otherwise-remote-capable fixtures `os.listdir(DATA_DIR)` locally) — the recipe
  `mkdir -p`s it.
- **Auth tests (gsi/token/voms):** need the *client* PKI tree laid out where
  `settings.py` expects it (`$TEST_ROOT/pki/{ca,user}`, `$TEST_ROOT/tokens/`).
  The `auth-pki` Secret + `auth-ca-bundle`/`auth-jwks` ConfigMaps carry the
  material; an init step must place `usercert.pem`/`userkey.pem`/`userproxy.pem`
  and mint tokens from `signing_key.pem`. This is the last piece to run the full
  auth surface; anon + metadata tests run today.
- **This sandbox only:** most `test_*` fixtures drive a Python `_xrdcl_proxy`
  worker that is **dead in this WSL2 sandbox** (pre-existing, unrelated to k8s) —
  those error identically on a local run. On a host with a working XrdCl, the
  378 remote-capable files run against the cluster fleet.

## Client-PKI init (for gsi/token tests) — implemented

The runner ships `/opt/brix/client-pki-init.sh` (tested by
`pytests/test_images.py::test_client_pki_init_lays_out_the_suite_pki`). To run the auth surface, mount the
authority Secret/ConfigMap into the runner and lay out the client PKI before
pytest:

```bash
# in the runner pod, with the auth-pki Secret at /auth/pki and auth-jwks CM at /auth/jwks:
TEST_ROOT=/tmp/tr PKI_SRC=/auth/pki JWKS_SRC=/auth/jwks/jwks.json \
  bash /opt/brix/client-pki-init.sh
# -> $TEST_ROOT/pki/{ca/ca.pem(+hash.0), user/{usercert,userkey,proxy_std}.pem,
#    server/host*}, $TEST_ROOT/tokens/{jwks.json,signing_key.pem}
pytest tests/ -m "not requires_local_server and not slow and not serial" -p no:xdist
```

Wire it into a Job by adding a projected volume from the `<rel>-pki` Secret and
`<rel>-jwks` ConfigMap, then an init step running the script. The layout is
verified; the only host-dependent gate left is a working XrdCl (dead in this
sandbox) to execute the proxy-driven tests.
