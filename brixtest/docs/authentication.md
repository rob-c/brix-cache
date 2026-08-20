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
the verification-key path, issuer, and audience, never the bearer credential.
The built-in issuer uses HS256 specifically for isolated test infrastructure.

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

## Hostname and reverse-DNS mappings

```python
auth_host = host_mapping(
    "origin", "origin.auth.test", address="127.0.0.77",
    aliases=("alias.auth.test",),
)

@case(hosts=[auth_host])
def test_names(run):
    assert run.resolve("alias.auth.test") == "127.0.0.77"
    assert run.reverse("127.0.0.77") == "origin.auth.test"
```

Docker and Podman helpers receive framework-owned `--add-host` entries.
Kubernetes pods receive `hostAliases`, enabling normal libc/NSS forward and
address-to-host lookups for certificate and GSI name checks. Local process tests
use `run.resolve()` and `run.reverse()` without modifying the host's `/etc/hosts`.

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
