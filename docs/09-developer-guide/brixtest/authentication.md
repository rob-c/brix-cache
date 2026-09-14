# Managed credentials and authentication recipes

BriXTest treats credentials and authentication infrastructure as immutable case
declarations. Nothing is generated during collection: the supervised helper
creates the resources immediately before servers start, gives each process role
only its declared subset, records hashes and metadata, and removes the run-owned
services and files during teardown.

## Custom credentials

```python
from brixtest import case, checksum_credential, noise, signed_credential

payload = noise("payload", size=100_000_000, seed=4)
checksum = checksum_credential(
    "payload_checksum", payload,
    destination="checksums/payload.sha256",
    env="PAYLOAD_CHECKSUM_FILE",
    targets=("test", "client"),
)
proof = signed_credential(
    "request_proof", "read:/data", secret="test-only-key",
    env="REQUEST_PROOF", targets=("test",),
)


@case(artifacts=[payload], credentials=[checksum, proof])
def test_request(run):
    assert run.credential(checksum).path.is_file()
```

`credential()` accepts text or a source file. `checksum_credential()` hashes a
declared, materialized artifact. `signed_credential()` produces a compact
base64url payload plus HMAC signature. Destinations are confined relative paths;
file modes cannot be group/world writable. `targets` selects `test`, `server`,
and/or `client`, while `env_value="path"|"content"` controls environment exposure.

## Token recipe

```python
tokens = token_auth(
    issuer="https://issuer.auth.test",
    audience="storage.example",
    scopes=("storage.read:/",),
)

@case(auth=[tokens])
def test_token(run):
    stack = run.auth(tokens)
    claims = verify_token(
        stack.path("token").read_text(),
        secret=stack.path("secret").read_text(),
        issuer=tokens.issuer,
        audience=tokens.audience,
    )
```

The client/test receives `BEARER_TOKEN` and `BEARER_TOKEN_FILE`. Servers receive
the verification-key path, issuer, audience, and algorithm, never the bearer
credential. HS256 is the dependency-free default for isolated infrastructure.

Set `algorithm="ES256"` or `algorithm="RS256"` (with the `brixtest[crypto]`
extra) for a case-owned asymmetric authority. BriXTest creates a mode-0600
private key, public PEM, public-only JWKS, OIDC discovery document, and signed
token; only the public verification material reaches servers:

```python
tokens = token_auth(algorithm="ES256", key_id="rotation-1")

@case(auth=[tokens])
def test_es256(run):
    stack = run.auth(tokens)
    claims = verify_token(
        stack.path("token").read_text(),
        public_key=stack.path("public_key").read_bytes(),
        algorithms=("ES256",),
    )
    assert claims["sub"] == tokens.subject
```

Verification defaults to accepting only HS256. Asymmetric callers must allow
their exact algorithm, preventing algorithm-confusion fallback. Supplying an
HS256 shared secret to an asymmetric recipe is rejected rather than ignored.

For a live discovery surface, set `managed=True`. BriXTest starts a supervised
loopback authority helper, publishes exact OIDC discovery and public-only JWKS
routes, exports their URLs to every approved role, retains its request log, and
stops the helper during normal or failed teardown:

```python
tokens = token_auth(
    algorithm="ES256", managed=True, rotate_on_restart=True,
)

@case(auth=[tokens])
def test_jwks_recovery(run):
    authority = run.auth(tokens)
    discovery_url = authority.environment()["BRIXTEST_TOKEN_DISCOVERY_URL"]
    authority.stop()
    assert not authority.available()
    authority.start()  # same URL; a new public key is now in the JWKS
    assert authority.available() and discovery_url == authority.metadata["discovery_url"]
```

`rotate_on_restart=True` requires `managed=True`. It performs a deterministic
key rollover before a stopped authority is restarted while retaining the same
allocated endpoint. The HTTP helper serves only `/healthz`,
`/.well-known/openid-configuration`, and (for asymmetric algorithms)
`/jwks.json`; private keys, shared secrets, issuance, and mutation are never
HTTP-accessible. Tests use `issue()` and `rotate()` for those controlled actions.

## TLS CA, CRL, and host certificate

```python
tls = tls_auth(
    hostname="origin.auth.test",
    aliases=("alias.auth.test",),
)

@case(auth=[tls])
def test_tls(run):
    assert run.auth(tls).path("crl").is_file()
```

Each case gets a new OpenSSL CA key/certificate, hashed trust directory, CRL,
SAN-bearing host certificate/key, and client certificate/key. The host private
key is server-only; client processes receive the CA/trust paths and client key.
This is disposable test PKI, not a production CA.

## VOMS/GSI PKI recipe

```python
voms = voms_auth(vo="atlas", hostname="voms.auth.test")

@case(auth=[voms])
def test_gsi(run):
    proxy = run.auth(voms).path("proxy")
    assert proxy.is_file()
```

The recipe creates its own CA/CRL, host, user, and VOMS identities, hashed CA
directory, `.lsc` trust file, `vomses` file, and a real RFC VOMS proxy generated
by `voms-proxy-fake`. Servers receive host trust and host identity; clients get
the user proxy and user identity. OpenSSL and the VOMS command-line tools must be
installed on the helper image/host.

## Kerberos realm recipe

```python
realm = kerberos_auth(
    realm="BRIXTEST.AUTH.TEST",
    domain="auth.test",
    hostname="kdc.auth.test",
    service="host/origin.auth.test",
)

@case(auth=[realm], timeout=30)
def test_kerberos(run):
    stack = run.auth(realm)
    assert stack.path("keytab").is_file()
    assert stack.path("cache").is_file()
```

BriXTest writes confined `krb5.conf`/`kdc.conf`, creates and stashes a new realm
database, adds user and service principals, exports the service keytab, starts a
loopback KDC on an allocated port, obtains a user ticket cache, and stops the KDC.
Servers get `KRB5_KTNAME`; clients/tests get `KRB5CCNAME`. Multiple named realms
can be declared across tests. A case that activates conflicting standard
Kerberos environment names fails before its body rather than silently selecting
one realm.

On `backend="minikube"`, the same declaration additionally creates a
namespace-owned KDC Deployment and Service on that allocated port for both TCP
and UDP. BriXTest captures `krb5kdc`, its ELF dependencies, KDB/event plugins,
and the initialized database into a content-addressed image and a dedicated
seed Secret. An init container copies that seed into a writable private realm
volume before the KDC starts. Server/client environments transparently select
the Service-DNS `krb5.conf`; the controller-side test keeps its loopback
configuration. `available()`, `stop()`, and `start()` coordinate both instances
so failure-injection tests retain one backend-neutral API. KDC output, Pod
status, namespace events, object UIDs, image inputs, and checksums are archived.
The KDC seed contains neither the client ticket cache nor the service keytab,
and ordinary server Secrets never contain the client cache.

## Live issuance, rotation, and revocation

The object returned by `run.auth(...)` controls the already materialized
authority; tests do not launch helper daemons or invoke OpenSSL themselves:

```python
tokens = run.auth("tokens")
rotation = tokens.rotate(key_id="rollover-2")
fresh_token = tokens.issue(
    subject="alice", scopes=("storage.read:/dataset",),
)

tls = run.auth("tls")
updated_crl = tls.revoke("client_cert")

kdc = run.auth("kerberos")
kdc.stop()
assert not kdc.available()
kdc.start()
assert kdc.available()
```

HS256 rotation replaces the managed verification secret. ES256/RS256 rotation
replaces the private/public key pair and publishes a public-only JWKS using the
new key ID. `issue()` always signs from the current recorded version. TLS and
VOMS/GSI revocation accepts only issued leaf-certificate roles, regenerates the
CRL through the case-owned CA database, and atomically refreshes the hashed
trust directory. Consumers keep the same declared file paths, allowing servers
that reload JWKS/CRLs to observe the change without configuration rewrites.

`authority-state.json`, issued token files, and `authority-events.jsonl` remain
under the case auth root. Events include action, time, version/key ID, and
public/token/certificate checksums; token values, shared secrets, and private
key content are never written to event records or summaries.

`start()`, `stop()`, and `available()` apply only to recipes that own a managed
service process: managed token authorities and the Kerberos KDC. Stopping
preserves state, credentials, configuration, and the allocated endpoint;
restarting uses that retained state. Static file authorities reject availability
control rather than pretending that a file rotation stopped a service.
Start/stop transitions are recorded in the same redacted authority journal.

## Hostname and reverse-DNS mappings

```python
auth_host = host_mapping(
    "origin", "origin.auth.test", address="127.0.0.77",
    aliases=("alias.auth.test",),
    libc=True,
)

@case(hosts=[auth_host])
def test_names(run):
    assert run.resolve("alias.auth.test") == "127.0.0.77"
    assert run.reverse("127.0.0.77") == "origin.auth.test"
```

Every mapping is available through `run.resolve()` and `run.reverse()`.
`libc=True` additionally requests physical NSS materialization. By default it
targets managed servers and clients; set `targets=("test",)` when the test body
itself must use `socket.getaddrinfo()` or another libc resolver. Docker and
Podman workloads receive framework-owned `--add-host` entries, while Kubernetes
pods receive `hostAliases`, enabling normal forward and address-to-host lookups
for certificate and GSI name checks. Process isolation rejects a test-targeted
libc mapping before launch because BriXTest never modifies the host's
`/etc/hosts`. Hosts-file backends also reject `reverse=False` because they
cannot provide a forward-only physical mapping.

## Kubernetes and Minikube

Server credentials are base64-encoded into a namespace-scoped Kubernetes
Secret, projected read-only at mode `0400`, and omitted entirely when a server
does not consume secure files. Client-only tokens/proxies are never placed in
that Secret. Use the checked-in Docker-Minikube profile for a live Secret,
DNS/rDNS, rollout, port-forward, log, and namespace-cleanup check:

```console
python3 tools/minikube_cluster.py start
python3 tools/minikube_cluster.py test
```

The complete minimal examples live in `examples/auth/test_auth_recipes.py`.
