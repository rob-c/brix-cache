# Writing tests and debugging

Patterns for new test files, assertions, common fixtures, and the debugging tools that speed up root-cause analysis.

[← Testing overview](testing-runbook.md)

## Writing a new test

**Important Test Requirements:**
- **Deterministic output**: ALL tests should be deterministic (one output from the server, EVER).
- **Test coverage**: All new features should be accompanied by new tests.
- **Integration**: New tests should cover the full integration of all features with the rest of the module where possible.

### Minimal test using the shared session fixtures

```python
"""tests/test_example.py — example test using the shared session."""

import os
import pytest
from settings import NGINX_ANON_PORT, DATA_ROOT

@pytest.fixture(scope="module")
def anon_url():
    return f"root://localhost:{NGINX_ANON_PORT}"


def test_stat_returns_file_info(anon_url):
    """stat on an existing file returns size > 0."""
    from XRootD import client
    from XRootD.client.flags import StatInfoFlags

    fs = client.FileSystem(anon_url)
    status, info = fs.stat("/test.txt")
    assert status.ok, f"stat failed: {status.message}"
    assert info.size > 0
```

### Test using raw XRootD wire protocol (no XRootD library)

For protocol-level tests that must verify exact wire behavior:

```python
import socket
import struct

def test_protocol_opcodes():
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(5)
    sock.connect(("127.0.0.1", NGINX_ANON_PORT))

    # Initial handshake (20 bytes)
    sock.sendall(struct.pack(">IIIII", 0, 0, 0, 4, 2012))

    # kXR_protocol
    sock.sendall(struct.pack(">BB H I BB 10x I", 0, 1, 3006, 0x00000520, 0x02, 0x03, 0))

    # Read handshake response (16 bytes: 8-byte ServerResponseHdr + 8-byte body)
    _ = sock.recv(16)
    # Read kXR_protocol response
    hdr = sock.recv(8)
    dlen = struct.unpack(">I", hdr[4:8])[0]
    if dlen:
        body = sock.recv(dlen)

    sock.close()
```

### Test using a token

```python
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
from utils.make_token import TokenIssuer
from settings import TOKENS_DIR, NGINX_TOKEN_PORT

@pytest.fixture(scope="module")
def token_issuer():
    return TokenIssuer(TOKENS_DIR)

def test_valid_token_accepted(token_issuer):
    token = token_issuer.generate(scope="storage.read:/")
    # ... use token with xrdfs or requests
    import os
    os.environ["BEARER_TOKEN"] = token
    # ... make request
```

### Test using a fresh per-test nginx

```python
import pytest
import server_control
from settings import NGINX_BIN

CONF = """
worker_processes 1;
error_log {LOG_DIR}/error.log debug;
pid       {LOG_DIR}/nginx.pid;
events {{ worker_connections 128; }}
stream {{
    server {{
        listen 127.0.0.1:{PORT};
        brix_root on;
        brix_export {DATA_DIR};
        brix_auth gsi;
        brix_certificate     {SERVER_CERT};
        brix_certificate_key {SERVER_KEY};
        brix_trusted_ca      {CA_CERT};
    }}
}}
"""

@pytest.fixture(scope="module")
def gsi_server(tmp_path_factory):
    if not os.path.exists(NGINX_BIN):
        pytest.skip(f"nginx binary not found: {NGINX_BIN}")

    data_dir = tmp_path_factory.mktemp("gsi-data")
    (data_dir / "secret.txt").write_text("grid data")

    info = server_control.start_nginx_instance(
        conf_text=CONF,
        template_kwargs={"DATA_DIR": str(data_dir)},
    )
    yield info
    info["stop"]()


def test_gsi_can_read_file(gsi_server):
    from XRootD import client
    url = f"root://localhost:{gsi_server['port']}"
    # X509_USER_PROXY and X509_CERT_DIR are set by conftest.py
    fs = client.FileSystem(url)
    status, listing = fs.dirlist("/")
    assert status.ok
```

---

## Environment variables

All settings live in `tests/settings.py` and can be overridden:

| Variable | Default | Purpose |
|---|---|---|
| `TEST_ROOT` | `/tmp/xrd-test` | Base directory for all test state |
| `TEST_NGINX_BIN` | `/tmp/nginx-1.28.3/objs/nginx` | nginx binary path |
| `TEST_BRIX_BIN` | `xrootd` | Reference xrootd binary |
| `TEST_XRDFS_BIN` | `xrdfs` | xrdfs client binary |
| `TEST_XRDCP_BIN` | `xrdcp` | xrdcp client binary |
| `TEST_SKIP_PKI_REGEN` | (unset) | Set to `1` to skip PKI regeneration |
| `TEST_NGINX_ANON_PORT` | `11094` | Anonymous XRootD port |
| `TEST_NGINX_GSI_PORT` | `11095` | GSI XRootD port |
| `TEST_NGINX_GSI_TLS_PORT` | `11096` | GSI + TLS port |
| `TEST_NGINX_TOKEN_PORT` | `11097` | Token auth XRootD port |
| `TEST_NGINX_WEBDAV_PORT` | `8443` | WebDAV HTTPS port (GSI optional) |
| `TEST_NGINX_WEBDAV_GSI_TLS_PORT` | `8444` | WebDAV HTTPS + GSI required auth port |
| `TEST_NGINX_METRICS_PORT` | `9100` | Prometheus metrics port |
| `LARGE_FILE_SEED` | `42` | RNG seed for `large200.bin` |
| `TEST_NGINX_URL` | (unset) | Point tests at an external nginx (CI integration) |

Credentials set by `conftest.py` at session start:

```bash
export X509_CERT_DIR=/tmp/xrd-test/pki/ca
export X509_USER_PROXY=/tmp/xrd-test/pki/user/proxy_std.pem
```

These are read by `xrdfs`, `xrdcp`, and the XRootD Python client.

---

## Debugging test failures

### Inspect nginx error logs

```bash
# Main shared instance
tail -f /tmp/xrd-test/logs/error.log

# Per-test instances (use the conf_path from the fixture)
ls /tmp/xrd-test/instances/
tail -f /tmp/xrd-test/instances/nginx-<uuid>/logs/error.log
```

Increase verbosity in per-test configs by using `error_log {LOG_DIR}/error.log debug;`.

### Verify PKI is valid

```bash
openssl x509 -in /tmp/xrd-test/pki/ca/ca.pem -text -noout
openssl verify -CAfile /tmp/xrd-test/pki/ca/ca.pem /tmp/xrd-test/pki/server/hostcert.pem
```

## Troubleshooting

| Issue | Potential Cause | Fix |
|---|---|---|
| `Address already in use` | A previous test session didn't clean up or another service is on a test port. | Run `./tests/manage_test_servers.sh stop` or `pkill nginx`. |
| `ModuleNotFoundError: No module named 'XRootD'` | XRootD Python bindings are missing. | `pip install xrootd` |
| `ModuleNotFoundError: No module named 'pki_helpers'` | `PYTHONPATH` is not set correctly. | Run `PYTHONPATH=tests pytest ...` or run from the project root. |
| Tests skip with `nginx binary not found` | `TEST_NGINX_BIN` is wrong. | Set `export TEST_NGINX_BIN=/path/to/your/nginx/objs/nginx`. |
| GSI tests fail with `proxy expired` | System clock drift or long-running session. | Delete `/tmp/xrd-test/pki` and rerun to regenerate. |
| Reference xrootd tests skip | `xrootd` is not on your `PATH`. | Install XRootD or point `TEST_BRIX_BIN` to the binary. |
| `Internal Server Error` in WebDAV | Check nginx error log. | `tail -f /tmp/xrd-test/logs/error.log` |
| Worker process crashes (SEGFAULT) | Memory error in C code. | Build with `--with-debug` and run under `gdb` or check dmesg. |

```bash
# Verify CA → host cert
openssl verify -CAfile /tmp/xrd-test/pki/ca/ca.pem \
    /tmp/xrd-test/pki/server/hostcert.pem
# Expected: OK

# Verify proxy chain
openssl verify -CAfile /tmp/xrd-test/pki/ca/ca.pem \
    -untrusted /tmp/xrd-test/pki/user/usercert.pem \
    /tmp/xrd-test/pki/user/proxy_std.pem

# Check proxy expiry (0 = valid for at least 1 hour)
openssl x509 -in /tmp/xrd-test/pki/user/proxy_std.pem -noout -checkend 3600
echo "exit code: $?"

# Inspect proxyCertInfo extension
openssl x509 -in /tmp/xrd-test/pki/user/proxy_std.pem -noout -text \
    | grep -A5 proxyCertInfo
```

### Regenerate expired proxies

```bash
python3 utils/make_proxy.py /tmp/xrd-test/pki
```

VOMS proxies expire separately:

```bash
python3 utils/voms_proxy_fake.py \
    -cert   /tmp/xrd-test/pki/user/usercert.pem \
    -key    /tmp/xrd-test/pki/user/userkey.pem \
    -hostcert /tmp/xrd-test/pki/voms/vomscert.pem \
    -hostkey  /tmp/xrd-test/pki/voms/vomskey.pem \
    -voms cms -fqan "/cms/Role=NULL/Capability=NULL" \
    -uri  "voms.test.local:15000" \
    -out  /tmp/xrd-test/pki/user/proxy_cms.pem -hours 24
```

### Verify token infrastructure

```bash
# Inspect signing authority
cat /tmp/xrd-test/tokens/jwks.json

# Generate a token and inspect it
python3 utils/make_token.py gen --scope "storage.read:/" /tmp/xrd-test/tokens \
    | python3 utils/inspect_token.py -

# Check nginx loaded the JWKS
grep -i "jwks\|token" /tmp/xrd-test/logs/error.log | head -5
```

### Run a single file with verbose output

```bash
pytest tests/test_vo_acl.py -v -s 2>&1 | head -100
```

### Run with pytest-timeout disabled

```bash
pytest tests/test_throughput.py -v -p no:timeout
```

### Force-stop all test processes

```bash
tests/manage_test_servers.sh force-stop
```

---

## Test infrastructure files

| File | Purpose |
|---|---|
| `tests/conftest.py` | Session setup/teardown: PKI regen, server start/stop, `test_env` fixture |
| `tests/pki_helpers.py` | `blitz_test_pki()`: CA + server cert + user cert generation |
| `tests/settings.py` | All ports, paths, and binary locations |
| `tests/server_control.py` | `start_nginx_instance()` and `start_brix_instance()` |
| `tests/manage_test_servers.sh` | Bash lifecycle script: start/stop/restart/status |
| `tests/configs/nginx_shared.conf` | Main nginx config template (all standard listeners) |
| `tests/configs/` | Per-feature nginx config templates |
| `utils/make_proxy.py` | RFC 3820 GSI proxy generation (Python, no openssl CLI) |
| `utils/voms_proxy_fake.py` | VOMS proxy generation (pure Python, replaces `voms-proxy-fake`) |
| `utils/make_token.py` | JWT/WLCG token signing authority (`TokenIssuer` class) |
| `utils/make_crl.py` | CRL generation against the test CA |
| `utils/inspect_token.py` | Decode and print JWT header/payload |
| `utils/token_examples.py` | Example token generation for documentation |
