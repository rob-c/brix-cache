# Compose stacks — one directory per deployment mode

The files described here remain in [`deploy/compose/`](../../../../deploy/compose/).
Directory listings below refer to that source location; command working
directories are unchanged by this guide’s relocation.

Each stack is a self-contained `docker compose` demo of one thing the module
does, built from the published image and a throwaway PKI. They are the
runnable twins of the deployment modes described in
`docs/02-concepts/deployment-modes.md`; every `nginx*.conf` here is validated
with `nginx -t` on every push by `tools/ci/check_example_configs.py`, and
`tests/test_phase115_example_configs.py` boots each stack on a developer host
(ports remapped, hostnames aliased) and runs its `smoke.sh` against it.

```sh
cd deploy/compose/standalone
docker compose up -d                         # pki → server (healthy on /healthz)
docker compose --profile smoke run --rm client   # writes + reads through every door
docker compose down -v
```

| Stack | Doors | What the smoke proves |
|---|---|---|
| `standalone/` | root:// 1094 · davs 8443 · metrics 9100 | one POSIX export, byte-exact across protocols |
| `xrootd-proxy/` | root:// 1094 → origin 1095 | transparent frame relay; bytes land on the origin |
| `webdav-edge/` | davs 8443, x509 / RFC 3820 proxy certs | anonymous PUT refused, certificate round trip |
| `gridftp-gateway/` | gsiftp:// 2811 (GSI) · ftp:// 2121 (anonymous) | both doors, cross-door read |
| `httpg-proxy/` | httpg 8443 → x509 WebDAV backend 8444 | delegation, forwarding *as the caller*, no-cert refused |
| `cms-cluster/` | redirector 1094 + cms 1213, two data servers | redirect round trip, data lives on a data server |
| `s3-frontend/` | S3 SigV4 9000 · davs 8443 | bad secret refused, PUT/GET/List, same object over WebDAV |
| `xcache/` | root:// 1094 read-through cache → origin 1095 | cold fill + warm hit, cache is read-only |
| `cvmfs/` | forward proxy 3128 · dashboard 3129 · metrics 3130 | CVMFS site cache with its bundled mock Stratum-1 |

## Conventions

* **Image** `${BRIX_IMAGE:-ghcr.io/rob-c/brix-cache:latest}` — built by
  `.github/workflows/image.yml` from `deploy/docker/Dockerfile`. Set
  `BRIX_IMAGE` to a local tag to run a stack against a working-tree build.
* **PKI** a one-shot `pki` service runs `brix-pki-init`
  (`common/pki-init.sh`) into the `pki` volume: demo CA, a host certificate
  whose SAN covers every service name, a user certificate and a proxy. Every
  server waits for it (`service_completed_successfully`). Demo material only.
* **Paths inside the image** config at `/etc/brix/nginx.conf`, PKI under
  `/etc/brix/pki`, data under `/data`, cache under `/var/cache/brix`.
* **Health** every server exposes `/healthz` + `/metrics` on 9100 (plain HTTP,
  internal); compose waits on it before starting dependants and the client.
* **`smoke.sh`** takes every endpoint from the environment (`BRIX_HOST`,
  `*_PORT`, `XRDCP`, `BRIX_PKI_DIR`) so the same script runs inside the
  `client` service and from the test suite against a local nginx. Each ends
  with `SMOKE OK: <stack>`; a security negative (unauthenticated write, bad
  secret, client write to a cache) runs before the positive path where the
  stack has one.
