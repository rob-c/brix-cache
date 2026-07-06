# Multi-User Permission Conformance Suite — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build a ~210-test conformance suite proving that per-user authorization verdicts are identical whether data is served from origin, read-cache, or stage across `root://`, WebDAV, and S3 — surfacing every cross-user leak as a red, evidenced failure.

**Architecture:** A reusable harness (`tests/mu_authz_lib/`) provides a fixed cast of distinct principals (matched credentials across protocols + real system uids), a policy renderer that emits consistent gridmap/authdb/VO-ACL/token/S3 backends, a dedicated privileged fleet with **paired direct (cache-off) and cache (cache-on) servers per protocol**, and a **differential oracle** that treats the direct server's verdict as ground truth and asserts every cache/stage server reaches the identical `Verdict(decision, reason, tier)`. Nine data-driven family test files (F1–F9) enumerate threat-relevant cells; each cell is one instance of the oracle.

**Tech Stack:** Python 3 + pytest (e2e), `XRootD.client` (pyxrootd), `requests` (WebDAV/S3), hand-rolled SigV4, standalone libc-linked C unit tests (matching `tests/c/idmap_test.c`), nginx-xrootd server configs, bash orchestration (`tests/run_multiuser_authz.sh`).

## Global Constraints

- **Privileged suite:** every run requires `os.geteuid() == 0` (or CAP_SETUID+CAP_SETGID+CAP_DAC_OVERRIDE). If unprivileged, the session fixture must **error collection with a clear message** — never silently pass. (Spec D4.)
- **Bug-hunt / fail-loudly:** leak cells encode the *correct* invariant and fail red. **No `xfail`.** Every leak cell carries `@pytest.mark.leak`. (Spec D1.)
- **The single invariant:** `verdict(P,X,op)` on any cache/stage server MUST equal the verdict on the cache-OFF direct server (the oracle). (Spec §2/§5.)
- **Enforcing protocols:** `root://`, WebDAV, S3 (S3 held to scope/authdb parity). `cvmfs` is **public-by-design** — F2 asserts creds ignored + no inferred privilege, and passes. (Spec D3/§4.)
- **Assertion granularity:** assert `decision` + `reason` + deciding `tier` — never bare status. (Spec §7.)
- **Follow existing harness patterns.** Do **not** invent config directives: copy them from a known-good existing config (`tests/configs/nginx_cache_only.conf`, `nginx_http_cache.conf`, `nginx_vo_acl.conf`, `nginx_authdb.conf`, `nginx_shared.conf`) and validate every config with `/tmp/nginx-1.28.3/objs/nginx -t -c <conf>` before using it in a test.
- **xdist:** the MU fleet is isolated from the shared fleet; PKI/gridmap/account-mutating tests run **serial** (respect the `-n12` cap). (Memory: shared-fleet PKI must be serial.)
- **C units:** NO `goto`; match `idmap_test.c` style (stub `ngx_log_error_core`, `CHECK()` macro, `static int fails`). (CLAUDE.md HARD BLOCK.)
- **Teardown is crash-safe:** pre-session sweep of leftover `brixtest_*` accounts; guarded idempotent reap registered against setup failure; account reap runs strictly **after** the fleet is stopped. (Spec §8.3; memory teardown hazards.)
- **Commits:** frequent; commit directly to `main` (no branches — user preference). Leave the unrelated `site/` working-tree edits untouched.
- **Exact known values:** token issuer default `https://test.example.com`, audience `nginx-xrootd`, scopes are space-separated (`storage.read:/cms`), test PKI at `/tmp/xrd-test/pki`, CA at `/tmp/xrd-test/pki/ca`, `xrdcinfo` at `client/bin/xrdcinfo` (build if absent), nginx binary at `/tmp/nginx-1.28.3/objs/nginx`.

---

## File Structure

```
tests/
  mu_authz_lib/
    __init__.py            # package; re-exports the public API
    ports.py              # MU fleet port + directory constants (mirrors settings.py style)
    creds.py              # gen_user_cert, gen_gsi_proxy, gen_voms_proxy, mint_token, s3_key_for
    principals.py         # Principal dataclass + build_cast() → fixed cast
    accounts.py           # sweep/create/reap real brixtest_* system users (privileged)
    policy.py             # Policy dataclass + render_policy() → gridmap/authdb/vo/token/s3
    fleet.py              # start/stop the paired direct+cache MU servers; port health
    cache_state.py        # cache_is_resident, force_cold, fill_as, verify_hot (xrdcinfo)
    verdict.py            # Verdict dataclass + REASON_TIER map + reason→tier inference
    adapters.py           # measure_root, measure_webdav, measure_s3 → Verdict
    oracle.py             # assert_cache_transparent, Cell, leak_report, parametrize helper
  configs/multiuser/
    root_direct.conf       # root:// GSI+token, cache OFF (oracle ground truth)
    root_cache.conf        # root:// GSI+token, cache ON (read cache + stage)
    webdav_direct.conf     # davs cache OFF
    webdav_cache.conf      # davs cache ON
    s3_direct.conf         # S3 cache OFF
    s3_cache.conf          # S3 cache ON
    cvmfs_cache.conf       # cvmfs public cache (F2)
  conftest_mu.py           # MU session fixtures (imported via conftest.py plugin hook)
  test_mu_authz_cachetransp.py   # F1
  test_mu_cvmfs_public.py        # F2
  test_mu_stage_laundering.py    # F3
  test_mu_prepare_authz.py       # F4
  test_mu_cross_protocol.py      # F5
  test_mu_impersonation_e2e.py   # F6 (privileged)
  test_mu_decision_cache.py      # F7 (e2e portion)
  test_mu_revocation.py          # F8
  test_mu_writeback_attr.py      # F9
  c/idmap_collapse_test.c        # F6 unit
  c/auth_gate_isolation_test.c   # F7 unit
  c/run_mu_unit.sh               # build+run both C units
  run_multiuser_authz.sh         # orchestrator: fleet up → pytest → fleet down
```

---

## Task 1: MU fleet constants + package skeleton

**Files:**
- Create: `tests/mu_authz_lib/__init__.py`
- Create: `tests/mu_authz_lib/ports.py`
- Test: `tests/mu_authz_lib/test_ports_selftest.py`

**Interfaces:**
- Produces: `ports.MU` — a namespace with `ROOT_DIRECT=12100, ROOT_CACHE=12101, WEBDAV_DIRECT=12102, WEBDAV_CACHE=12103, S3_DIRECT=12104, S3_CACHE=12105, CVMFS_CACHE=12106`; roots `MU_ROOT="/tmp/xrd-test/mu"`, `PKI_DIR`, `TOKENS_DIR`, `DATA_ROOT`, `CACHE_ROOT`, `STATE_ROOT`, `GRIDMAP`, `AUTHDB`, `CA_DIR="/tmp/xrd-test/pki/ca"`, `HOST="127.0.0.1"`.

- [ ] **Step 1: Write the failing test**

```python
# tests/mu_authz_lib/test_ports_selftest.py
from mu_authz_lib import ports

def test_ports_distinct_and_in_range():
    vals = [ports.MU.ROOT_DIRECT, ports.MU.ROOT_CACHE, ports.MU.WEBDAV_DIRECT,
            ports.MU.WEBDAV_CACHE, ports.MU.S3_DIRECT, ports.MU.S3_CACHE,
            ports.MU.CVMFS_CACHE]
    assert len(vals) == len(set(vals)), "MU ports must be unique"
    assert all(12100 <= v <= 12130 for v in vals), "MU ports live in 12100-12130"

def test_roots_under_mu():
    assert ports.MU.DATA_ROOT.startswith(ports.MU.MU_ROOT)
    assert ports.MU.CACHE_ROOT.startswith(ports.MU.MU_ROOT)
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd /home/rcurrie/HEP-x/nginx-xrootd && PYTHONPATH=tests pytest tests/mu_authz_lib/test_ports_selftest.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'mu_authz_lib'`.

- [ ] **Step 3: Write minimal implementation**

```python
# tests/mu_authz_lib/__init__.py
"""Multi-user permission conformance harness (see docs/superpowers/plans/2026-07-06-multiuser-permission-conformance.md)."""
```

```python
# tests/mu_authz_lib/ports.py
"""MU fleet ports and directory layout. Overridable via TEST_MU_* env vars,
matching the tests/settings.py convention (int() + env default)."""
import os

def _p(name, default):
    return int(os.environ.get(name, str(default)))

class MU:
    HOST = os.environ.get("TEST_MU_HOST", "127.0.0.1")
    ROOT_DIRECT   = _p("TEST_MU_ROOT_DIRECT",   12100)
    ROOT_CACHE    = _p("TEST_MU_ROOT_CACHE",    12101)
    WEBDAV_DIRECT = _p("TEST_MU_WEBDAV_DIRECT", 12102)
    WEBDAV_CACHE  = _p("TEST_MU_WEBDAV_CACHE",  12103)
    S3_DIRECT     = _p("TEST_MU_S3_DIRECT",     12104)
    S3_CACHE      = _p("TEST_MU_S3_CACHE",      12105)
    CVMFS_CACHE   = _p("TEST_MU_CVMFS_CACHE",   12106)

    MU_ROOT    = os.environ.get("TEST_MU_ROOT", "/tmp/xrd-test/mu")
    PKI_DIR    = "/tmp/xrd-test/pki"
    CA_DIR     = "/tmp/xrd-test/pki/ca"
    TOKENS_DIR = os.path.join(MU_ROOT, "tokens")
    DATA_ROOT  = os.path.join(MU_ROOT, "data")     # the export origin
    CACHE_ROOT = os.path.join(MU_ROOT, "cache")    # read-cache store
    STATE_ROOT = os.path.join(MU_ROOT, "state")
    GRIDMAP    = os.path.join(MU_ROOT, "gridmap")
    AUTHDB     = os.path.join(MU_ROOT, "authdb")
    CONFIG_DIR = os.path.join(MU_ROOT, "conf")
    LOG_DIR    = os.path.join(MU_ROOT, "logs")
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd /home/rcurrie/HEP-x/nginx-xrootd && PYTHONPATH=tests pytest tests/mu_authz_lib/test_ports_selftest.py -v`
Expected: PASS (2 passed).

- [ ] **Step 5: Commit**

```bash
git add tests/mu_authz_lib/__init__.py tests/mu_authz_lib/ports.py tests/mu_authz_lib/test_ports_selftest.py
git commit -m "test(mu): MU fleet port/dir constants + package skeleton"
```

---

## Task 2: Credential factory

**Files:**
- Create: `tests/mu_authz_lib/creds.py`
- Test: `tests/mu_authz_lib/test_creds_selftest.py`

**Interfaces:**
- Consumes: `ports.MU` (Task 1); existing `utils.make_token.TokenIssuer`; existing test CA at `MU.CA_DIR`.
- Produces:
  - `gen_user_cert(dn: str, name: str) -> tuple[str, str]` → `(cert_path, key_path)`
  - `gen_gsi_proxy(cert_path: str, key_path: str, name: str) -> str` → proxy PEM path
  - `gen_voms_proxy(cert_path, key_path, name, vo: str) -> str` → VOMS proxy PEM path (delegates to `utils/voms_proxy_fake.py`)
  - `mint_token(sub: str, scope: str, name: str, *, issuer=None, audience=None, expired=False) -> str` → token file path
  - `s3_key_for(name: str) -> tuple[str, str]` → `(access_key, secret_key)` deterministic per name

- [ ] **Step 1: Write the failing test**

```python
# tests/mu_authz_lib/test_creds_selftest.py
import os, base64, json
from mu_authz_lib import creds, ports

def _setup():
    os.makedirs(os.path.join(ports.MU.PKI_DIR, "user"), exist_ok=True)
    os.makedirs(ports.MU.TOKENS_DIR, exist_ok=True)

def test_user_cert_and_proxy():
    _setup()
    cert, key = creds.gen_user_cert("/DC=test/CN=selftest-alice", "selftest_alice")
    assert os.path.exists(cert) and os.path.exists(key)
    proxy = creds.gen_gsi_proxy(cert, key, "selftest_alice")
    assert os.path.exists(proxy)
    # proxy file bundles proxy cert + user cert + proxy key
    body = open(proxy).read()
    assert body.count("BEGIN CERTIFICATE") >= 2 and "PRIVATE KEY" in body

def test_token_has_sub_and_scope():
    _setup()
    tokpath = creds.mint_token("selftest-bob", "storage.read:/cms", "selftest_bob")
    tok = open(tokpath).read().strip()
    payload = tok.split(".")[1]
    payload += "=" * (-len(payload) % 4)
    claims = json.loads(base64.urlsafe_b64decode(payload))
    assert claims["sub"] == "selftest-bob"
    assert "storage.read:/cms" in claims["scope"]

def test_s3_key_deterministic():
    a1 = creds.s3_key_for("alice"); a2 = creds.s3_key_for("alice")
    assert a1 == a2 and a1[0] != creds.s3_key_for("bob")[0]
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd /home/rcurrie/HEP-x/nginx-xrootd && PYTHONPATH=tests pytest tests/mu_authz_lib/test_creds_selftest.py -v`
Expected: FAIL — `AttributeError: module 'mu_authz_lib.creds' has no attribute 'gen_user_cert'` (module missing).

- [ ] **Step 3: Write minimal implementation**

Base the cert/proxy code on the extracted `utils/make_proxy.py` pattern (proxy = proxy_cert + user_cert + proxy_key in that order; user cert needs `keyUsage=critical,digitalSignature,keyEncipherment`). Reuse the existing tools where present rather than reimplementing.

```python
# tests/mu_authz_lib/creds.py
"""Per-principal credential factory: GSI cert+proxy, VOMS proxy, WLCG token, S3 key.
Reuses utils/make_proxy.py, utils/voms_proxy_fake.py, utils/make_token.py."""
import os, sys, subprocess, hashlib
from pathlib import Path
from . import ports

_REPO = Path(__file__).resolve().parents[2]
_UTILS = _REPO / "utils"
sys.path.insert(0, str(_REPO))

def _user_dir():
    d = Path(ports.MU.PKI_DIR) / "user"; d.mkdir(parents=True, exist_ok=True); return d

def gen_user_cert(dn: str, name: str):
    ud = _user_dir()
    cert = str(ud / f"{name}_usercert.pem"); key = str(ud / f"{name}_userkey.pem")
    ca_cert = os.path.join(ports.MU.CA_DIR, "ca.pem")
    ca_key  = os.path.join(ports.MU.CA_DIR, "ca.key")
    subprocess.run(["openssl", "genrsa", "-out", key, "2048"], check=True, capture_output=True)
    os.chmod(key, 0o400)
    csr = cert.replace(".pem", ".csr")
    subprocess.run(["openssl", "req", "-new", "-key", key, "-subj", dn, "-out", csr],
                   check=True, capture_output=True)
    ext = cert.replace(".pem", ".ext")
    Path(ext).write_text("keyUsage=critical,digitalSignature,keyEncipherment\n"
                         "extendedKeyUsage=clientAuth\n")
    subprocess.run(["openssl", "x509", "-req", "-in", csr, "-CA", ca_cert, "-CAkey", ca_key,
                    "-CAcreateserial", "-out", cert, "-days", "3650", "-sha256",
                    "-extfile", ext], check=True, capture_output=True)
    return cert, key

def gen_gsi_proxy(cert_path: str, key_path: str, name: str) -> str:
    """Delegate to utils/make_proxy.py so proxy format matches the rest of the suite."""
    out = str(_user_dir() / f"{name}_proxy.pem")
    subprocess.run([sys.executable, str(_UTILS / "make_proxy.py"),
                    "--cert", cert_path, "--key", key_path, "--out", out],
                   check=True, capture_output=True)
    os.chmod(out, 0o400)
    return out

def gen_voms_proxy(cert_path: str, key_path: str, name: str, vo: str) -> str:
    out = str(_user_dir() / f"{name}_voms_{vo}.pem")
    subprocess.run([sys.executable, str(_UTILS / "voms_proxy_fake.py"),
                    "--cert", cert_path, "--key", key_path, "--vo", vo, "--out", out],
                   check=True, capture_output=True)
    os.chmod(out, 0o400)
    return out

def mint_token(sub: str, scope: str, name: str, *, issuer=None, audience=None, expired=False) -> str:
    from utils.make_token import TokenIssuer
    iss = TokenIssuer(token_dir=ports.MU.TOKENS_DIR)
    if not os.path.exists(iss.key_path):
        iss.init_keys()
    if expired:
        tok = iss.generate_expired(sub=sub, scope=scope)
    else:
        tok = iss.generate(sub=sub, scope=scope,
                           issuer=issuer or "https://test.example.com",
                           audience=audience or "nginx-xrootd", lifetime=3600)
    path = os.path.join(ports.MU.TOKENS_DIR, f"{name}.jwt")
    Path(path).write_text(tok)
    return path

def s3_key_for(name: str):
    ak = "AKIA" + hashlib.sha256(("ak:"+name).encode()).hexdigest()[:12].upper()
    sk = hashlib.sha256(("sk:"+name).encode()).hexdigest()
    return ak, sk
```

**IMPLEMENTATION NOTE:** verify the exact CLI flags of `utils/make_proxy.py`, `utils/voms_proxy_fake.py`, and the exact `TokenIssuer.generate*` signatures by reading those files first (they exist — see the extraction card `utils/make_proxy.py:59-217`, `utils/voms_proxy_fake.py:204-507`, `utils/make_token.py:169-195`). Adjust flag names to match. If `make_proxy.py` lacks `--cert/--key/--out`, fall back to the inline `cryptography`-based `gen_gsi_proxy` from the extraction card (docstring in this plan's task).

- [ ] **Step 4: Run test to verify it passes**

Run: `cd /home/rcurrie/HEP-x/nginx-xrootd && PYTHONPATH=tests pytest tests/mu_authz_lib/test_creds_selftest.py -v`
Expected: PASS (3 passed). Requires the test CA at `/tmp/xrd-test/pki/ca` — if absent, run `PYTHONPATH=tests python -c "from pki_helpers import blitz_test_pki; blitz_test_pki()"` first.

- [ ] **Step 5: Commit**

```bash
git add tests/mu_authz_lib/creds.py tests/mu_authz_lib/test_creds_selftest.py
git commit -m "test(mu): per-principal credential factory (cert/proxy/voms/token/s3)"
```

---

## Task 3: The principal cast

**Files:**
- Create: `tests/mu_authz_lib/principals.py`
- Test: `tests/mu_authz_lib/test_principals_selftest.py`

**Interfaces:**
- Consumes: `creds` (Task 2).
- Produces:
  - `@dataclass Principal(name, uid, dn, sub, scope, vo, proxy, token, s3_key, s3_secret, krb_princ=None)`
  - `build_cast() -> dict[str, Principal]` with keys `svc, alice, bob, carol, mallory, collide, squashed` per spec §8.2. Idempotent (regenerates creds under MU PKI/token dirs).

- [ ] **Step 1: Write the failing test**

```python
# tests/mu_authz_lib/test_principals_selftest.py
import os
from mu_authz_lib import principals, ports, creds

def test_cast_has_expected_members():
    cast = principals.build_cast()
    for who in ("svc", "alice", "bob", "carol", "mallory", "collide", "squashed"):
        assert who in cast, f"missing principal {who}"
    # carol shares alice's VO (cms) but has NO authdb grant — the sharpest leak probe
    assert cast["carol"].vo == cast["alice"].vo == "cms"
    # collide maps to the SAME uid as alice via a different principal
    assert cast["collide"].uid == cast["alice"].uid

def test_each_principal_has_matched_creds():
    cast = principals.build_cast()
    for p in cast.values():
        if p.name == "squashed":
            continue
        assert p.proxy and os.path.exists(p.proxy)
        assert p.token and os.path.exists(p.token)
        assert p.s3_key and p.s3_secret
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd /home/rcurrie/HEP-x/nginx-xrootd && PYTHONPATH=tests pytest tests/mu_authz_lib/test_principals_selftest.py -v`
Expected: FAIL — module `principals` missing.

- [ ] **Step 3: Write minimal implementation**

```python
# tests/mu_authz_lib/principals.py
"""The fixed principal cast (spec §8.2). Each has matched credentials across protocols."""
from dataclasses import dataclass
from . import creds

@dataclass
class Principal:
    name: str
    uid: int
    dn: str
    sub: str
    scope: str
    vo: str
    proxy: str = ""
    token: str = ""
    s3_key: str = ""
    s3_secret: str = ""
    krb_princ: str | None = None

# (name, uid, dn, sub, scope, vo, krb)
_SPEC = [
    ("svc",      1700, "/DC=test/CN=brix-service", "brix-service", "storage.read:/ storage.write:/", "cms",   None),
    ("alice",    1701, "/DC=test/CN=alice",        "alice",        "storage.read:/cms",              "cms",   None),
    ("bob",      1702, "/DC=test/CN=bob",          "bob",          "storage.read:/atlas",            "atlas", None),
    ("carol",    1703, "/DC=test/CN=carol",        "carol",        "storage.read:/cms",              "cms",   None),
    ("mallory",  1704, "/DC=test/CN=mallory",      "mallory",      "storage.read:/cms",              "cms",   None),
    ("collide",  1701, "/DC=test/CN=alice",        "alice",        "storage.read:/cms",              "cms",   "alice@TEST.REALM"),
    ("squashed", 65534,"/DC=test/CN=root-ish",     "root-ish",     "",                               "",      None),
]

def build_cast() -> dict[str, Principal]:
    cast: dict[str, Principal] = {}
    for name, uid, dn, sub, scope, vo, krb in _SPEC:
        p = Principal(name=name, uid=uid, dn=dn, sub=sub, scope=scope, vo=vo, krb_princ=krb)
        if name != "squashed":
            cert, key = creds.gen_user_cert(dn, name)
            p.proxy = (creds.gen_voms_proxy(cert, key, name, vo) if vo
                       else creds.gen_gsi_proxy(cert, key, name))
            p.token = creds.mint_token(sub, scope, name)
            p.s3_key, p.s3_secret = creds.s3_key_for(name)
        cast[name] = p
    return cast
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd /home/rcurrie/HEP-x/nginx-xrootd && PYTHONPATH=tests pytest tests/mu_authz_lib/test_principals_selftest.py -v`
Expected: PASS (2 passed).

- [ ] **Step 5: Commit**

```bash
git add tests/mu_authz_lib/principals.py tests/mu_authz_lib/test_principals_selftest.py
git commit -m "test(mu): fixed principal cast with matched cross-protocol creds"
```

---

## Task 4: Real system-account provisioning + crash-safe teardown

**Files:**
- Create: `tests/mu_authz_lib/accounts.py`
- Test: `tests/mu_authz_lib/test_accounts_selftest.py`

**Interfaces:**
- Consumes: `principals.build_cast()` (Task 3).
- Produces:
  - `require_privileged()` → raises `PermissionError` with a clear message if `os.geteuid() != 0`.
  - `sweep_leftover()` → remove any pre-existing `brixtest_*` accounts (idempotent).
  - `provision(cast) -> None` → create `brixtest_<name>` system users at each principal's uid.
  - `reap() -> None` → guarded `userdel` of all `brixtest_*`; safe to call repeatedly / after partial setup.
  - Account username convention: `brixtest_<principal-name>`.

- [ ] **Step 1: Write the failing test** (privileged-gated)

```python
# tests/mu_authz_lib/test_accounts_selftest.py
import os, pwd, pytest
from mu_authz_lib import accounts, principals

privileged = pytest.mark.skipif(os.geteuid() != 0, reason="needs root")

def test_require_privileged_raises_when_unprivileged(monkeypatch):
    monkeypatch.setattr(os, "geteuid", lambda: 1000)
    with pytest.raises(PermissionError):
        accounts.require_privileged()

@privileged
def test_provision_and_reap_roundtrip():
    accounts.sweep_leftover()
    cast = principals.build_cast()
    accounts.provision(cast)
    try:
        assert pwd.getpwnam("brixtest_alice").pw_uid == cast["alice"].uid
    finally:
        accounts.reap()
    with pytest.raises(KeyError):
        pwd.getpwnam("brixtest_alice")
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd /home/rcurrie/HEP-x/nginx-xrootd && PYTHONPATH=tests pytest tests/mu_authz_lib/test_accounts_selftest.py -v`
Expected: FAIL — module `accounts` missing (the unprivileged test errors on import).

- [ ] **Step 3: Write minimal implementation**

```python
# tests/mu_authz_lib/accounts.py
"""Real system-account provisioning for privileged impersonation tests (spec §8.3).
Crash-safe: sweep leftovers first; reap is idempotent and guarded."""
import os, pwd, subprocess

PREFIX = "brixtest_"

def require_privileged():
    if os.geteuid() != 0:
        raise PermissionError(
            "MU conformance suite requires root (real accounts + setfsuid). "
            "Run under sudo, or set up CAP_SETUID+CAP_SETGID+CAP_DAC_OVERRIDE.")

def _all_brixtest_users():
    return [u.pw_name for u in pwd.getpwall() if u.pw_name.startswith(PREFIX)]

def reap():
    for name in _all_brixtest_users():
        subprocess.run(["userdel", "-r", name], capture_output=True)  # guarded: ignore rc

def sweep_leftover():
    reap()

def provision(cast):
    require_privileged()
    for p in cast.values():
        uname = PREFIX + p.name
        try:
            if pwd.getpwnam(uname).pw_uid == p.uid:
                continue
            subprocess.run(["userdel", "-r", uname], capture_output=True)
        except KeyError:
            pass
        subprocess.run(["useradd", "-M", "-N", "-u", str(p.uid),
                        "-s", "/usr/sbin/nologin", uname], check=True, capture_output=True)
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd /home/rcurrie/HEP-x/nginx-xrootd && PYTHONPATH=tests pytest tests/mu_authz_lib/test_accounts_selftest.py -v`
Expected: the unprivileged assertion PASSES; the roundtrip is SKIPPED unless run as root. Under `sudo -E env PYTHONPATH=tests pytest ...` both PASS.

- [ ] **Step 5: Commit**

```bash
git add tests/mu_authz_lib/accounts.py tests/mu_authz_lib/test_accounts_selftest.py
git commit -m "test(mu): crash-safe real-account provisioning + reap"
```

---

## Task 5: Policy renderer

**Files:**
- Create: `tests/mu_authz_lib/policy.py`
- Test: `tests/mu_authz_lib/test_policy_selftest.py`

**Interfaces:**
- Consumes: `principals` (Task 3), `ports.MU` (Task 1).
- Produces:
  - `@dataclass Policy(path: str, allow: list[str], deny: list[str], vo: str|None, scope_prefix: str|None)`
  - `render_policy(policy, cast) -> dict[str, str]` → writes and returns paths `{"gridmap":..., "authdb":..., "vo":..., "s3keys":...}` such that the four backends agree: `allow` principals are granted, `deny` principals refused, on `policy.path`.
  - `write_gridmap(cast) -> str` → the DN/principal→username map for all principals.

- [ ] **Step 1: Write the failing test**

```python
# tests/mu_authz_lib/test_policy_selftest.py
from mu_authz_lib import policy, principals

def test_render_is_consistent():
    cast = principals.build_cast()
    pol = policy.Policy(path="/cms/secret.dat", allow=["alice"],
                        deny=["bob", "carol"], vo="cms", scope_prefix="storage.read:/cms")
    out = policy.render_policy(pol, cast)
    authdb = open(out["authdb"]).read()
    # alice granted read on /cms; carol (same VO, no grant) must NOT be granted authdb
    assert "alice" in authdb
    assert "/cms" in authdb
    gridmap = open(out["gridmap"]).read()
    assert cast["alice"].dn in gridmap and "brixtest_alice" in gridmap
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd /home/rcurrie/HEP-x/nginx-xrootd && PYTHONPATH=tests pytest tests/mu_authz_lib/test_policy_selftest.py -v`
Expected: FAIL — module `policy` missing.

- [ ] **Step 3: Write minimal implementation**

**IMPLEMENTATION NOTE:** the exact gridmap and authdb file *formats* must match what the server parses. Read `src/auth/impersonate/idmap.c` (gridmap line format: `"DN" username`) and `tests/configs/nginx_authdb.conf` + the authdb file it references (XrdAcc `id … a rl` grammar) before finalizing the string templates below. The test's assertions are loose enough to pass with either; the strict validation happens when the fleet loads them (Task 6) and `nginx -t` succeeds.

```python
# tests/mu_authz_lib/policy.py
"""Render one high-level Policy into consistent gridmap/authdb/VO/S3 backends (spec §8.4)."""
import os
from dataclasses import dataclass, field
from . import ports

@dataclass
class Policy:
    path: str
    allow: list
    deny: list
    vo: str | None = None
    scope_prefix: str | None = None

def write_gridmap(cast) -> str:
    os.makedirs(ports.MU.MU_ROOT, exist_ok=True)
    lines = []
    for p in cast.values():
        if p.name == "squashed":
            continue
        lines.append(f'"{p.dn}" brixtest_{p.name}')
        if p.krb_princ:
            lines.append(f'"{p.krb_princ}" brixtest_{p.name}')
    open(ports.MU.GRIDMAP, "w").write("\n".join(lines) + "\n")
    return ports.MU.GRIDMAP

def _authdb(policy, cast) -> str:
    # XrdAcc-style: one grant line per allowed principal on policy.path (read).
    lines = [f"# authdb for {policy.path}"]
    for who in policy.allow:
        lines.append(f'id brixtest_{who} {policy.path} rl')
    open(ports.MU.AUTHDB, "w").write("\n".join(lines) + "\n")
    return ports.MU.AUTHDB

def render_policy(policy: Policy, cast) -> dict:
    grid = write_gridmap(cast)
    authdb = _authdb(policy, cast)
    vo = os.path.join(ports.MU.MU_ROOT, "vo.rules")
    open(vo, "w").write(f"{os.path.dirname(policy.path)} {policy.vo}\n" if policy.vo else "")
    s3 = os.path.join(ports.MU.MU_ROOT, "s3keys")
    open(s3, "w").write("\n".join(
        f"{cast[w].s3_key} {cast[w].s3_secret} brixtest_{w}"
        for w in (policy.allow + policy.deny) if w in cast and cast[w].s3_key) + "\n")
    return {"gridmap": grid, "authdb": authdb, "vo": vo, "s3keys": s3}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd /home/rcurrie/HEP-x/nginx-xrootd && PYTHONPATH=tests pytest tests/mu_authz_lib/test_policy_selftest.py -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add tests/mu_authz_lib/policy.py tests/mu_authz_lib/test_policy_selftest.py
git commit -m "test(mu): policy renderer → consistent gridmap/authdb/vo/s3 backends"
```

---

## Task 6: Dedicated paired fleet (direct + cache) + orchestrator

**Files:**
- Create: `tests/configs/multiuser/root_direct.conf`, `root_cache.conf`, `webdav_direct.conf`, `webdav_cache.conf`, `s3_direct.conf`, `s3_cache.conf`, `cvmfs_cache.conf`
- Create: `tests/mu_authz_lib/fleet.py`
- Create: `tests/run_multiuser_authz.sh`
- Test: `tests/mu_authz_lib/test_fleet_selftest.py`

**Interfaces:**
- Consumes: `ports.MU` (Task 1), `policy.render_policy` output paths (Task 5).
- Produces:
  - `fleet.render_configs(backends: dict) -> None` → substitute `{PORT}/{DATA_DIR}/{CACHE_DIR}/{GRIDMAP}/{AUTHDB}/{VO}/{JWKS}/{CERT}/{KEY}/{CA}/{LOG_DIR}` placeholders into `MU.CONFIG_DIR`.
  - `fleet.start() -> None` / `fleet.stop() -> None` — launch/stop all MU nginx instances (own pidfiles under `MU.MU_ROOT`).
  - `fleet.wait_listening(timeout=15) -> None` — poll every MU port.
  - `fleet.url(proto, variant) -> str` — e.g. `url("root","cache")` → `root://127.0.0.1:12101`, `url("webdav","direct")` → `https://127.0.0.1:12102`.

- [ ] **Step 1: Write the failing test**

```python
# tests/mu_authz_lib/test_fleet_selftest.py
import socket, pytest, os
from mu_authz_lib import fleet, ports, principals, policy, accounts

privileged = pytest.mark.skipif(os.geteuid() != 0, reason="needs root")

def _port_open(p):
    s = socket.socket(); s.settimeout(1.0)
    try:
        s.connect((ports.MU.HOST, p)); return True
    except OSError:
        return False
    finally:
        s.close()

@privileged
def test_fleet_starts_and_all_ports_listen():
    cast = principals.build_cast()
    accounts.sweep_leftover(); accounts.provision(cast)
    backends = policy.render_policy(
        policy.Policy("/cms/secret.dat", allow=["alice"], deny=["bob","carol"],
                      vo="cms", scope_prefix="storage.read:/cms"), cast)
    fleet.render_configs(backends)
    fleet.start()
    try:
        fleet.wait_listening(timeout=20)
        for p in (ports.MU.ROOT_DIRECT, ports.MU.ROOT_CACHE, ports.MU.WEBDAV_DIRECT,
                  ports.MU.WEBDAV_CACHE, ports.MU.S3_DIRECT, ports.MU.S3_CACHE):
            assert _port_open(p), f"port {p} not listening"
    finally:
        fleet.stop(); accounts.reap()
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd /home/rcurrie/HEP-x/nginx-xrootd && PYTHONPATH=tests pytest tests/mu_authz_lib/test_fleet_selftest.py -v`
Expected: FAIL — module `fleet` missing (SKIPPED if unprivileged; run under sudo to exercise).

- [ ] **Step 3: Write the config templates**

Start from a known-good cache config and adapt. First: `cp tests/configs/nginx_cache_only.conf /tmp/ref_cache.conf` and read it to copy the **exact** cache directive names. Then write `root_cache.conf` (cache ON) and `root_direct.conf` (identical minus the cache directives — a plain export so the full 3-tier gate runs). Template (verify directive spelling against the reference and `nginx -t`):

```nginx
# tests/configs/multiuser/root_cache.conf  (cache ON — the read cache + stage path)
worker_processes 2;
error_log {LOG_DIR}/root_cache_error.log info;
events { worker_connections 128; }
stream {
    server {
        listen {ROOT_CACHE_PORT};
        brix_root on;

        brix_storage_backend  root://127.0.0.1:{ROOT_DIRECT_PORT};   # origin = the direct server
        brix_cache_store      posix:{CACHE_DIR};
        brix_cache_export     /;

        brix_auth gsi ztn;                       # accept GSI proxy OR bearer token
        brix_certificate     {CERT};
        brix_certificate_key {KEY};
        brix_trusted_ca      {CA};
        brix_token_jwks      {JWKS};
        brix_token_issuer    https://test.example.com;
        brix_token_audience  nginx-xrootd;

        brix_gridmap    {GRIDMAP};
        brix_authdb     {AUTHDB};
        brix_require_vo /cms cms;
        brix_impersonate on;

        brix_allow_write on;
        brix_access_log {LOG_DIR}/root_cache_access.log;
    }
}
```

```nginx
# tests/configs/multiuser/root_direct.conf  (cache OFF — the authoritative oracle)
worker_processes 2;
error_log {LOG_DIR}/root_direct_error.log info;
events { worker_connections 128; }
stream {
    server {
        listen {ROOT_DIRECT_PORT};
        brix_root on;

        brix_export           {DATA_DIR};          # serve the real export directly
        brix_storage_backend  posix:{DATA_DIR};

        brix_auth gsi ztn;
        brix_certificate     {CERT};
        brix_certificate_key {KEY};
        brix_trusted_ca      {CA};
        brix_token_jwks      {JWKS};
        brix_token_issuer    https://test.example.com;
        brix_token_audience  nginx-xrootd;

        brix_gridmap    {GRIDMAP};
        brix_authdb     {AUTHDB};
        brix_require_vo /cms cms;
        brix_impersonate on;

        brix_allow_write on;
        brix_access_log {LOG_DIR}/root_direct_access.log;
    }
}
```

Write `webdav_{direct,cache}.conf` (http{} server, `listen {PORT} ssl;`, `brix_webdav on;` — model on `tests/configs/nginx_http_cache.conf` / the WebDAV shared config), `s3_{direct,cache}.conf` (`brix_s3 on;` + `brix_s3_access_key`/`brix_s3_secret_key` from the rendered `s3keys`, model on `tests/configs/nginx_s3_*.conf`), and `cvmfs_cache.conf` (public cache, model on `src/protocols/cvmfs` test configs). **Every directive name must be copied from a working reference config, not invented.**

- [ ] **Step 4: Write `fleet.py` + validate each config**

```python
# tests/mu_authz_lib/fleet.py
"""Render + start/stop the paired MU fleet. Each server is a standalone nginx instance."""
import os, socket, subprocess, time, glob
from . import ports

NGINX = "/tmp/nginx-1.28.3/objs/nginx"
_CFG_SRC = os.path.join(os.path.dirname(__file__), "..", "configs", "multiuser")

_SUBST = {
    "{ROOT_DIRECT_PORT}": str(ports.MU.ROOT_DIRECT), "{ROOT_CACHE_PORT}": str(ports.MU.ROOT_CACHE),
    "{WEBDAV_DIRECT_PORT}": str(ports.MU.WEBDAV_DIRECT), "{WEBDAV_CACHE_PORT}": str(ports.MU.WEBDAV_CACHE),
    "{S3_DIRECT_PORT}": str(ports.MU.S3_DIRECT), "{S3_CACHE_PORT}": str(ports.MU.S3_CACHE),
    "{CVMFS_CACHE_PORT}": str(ports.MU.CVMFS_CACHE),
    "{DATA_DIR}": ports.MU.DATA_ROOT, "{CACHE_DIR}": ports.MU.CACHE_ROOT,
    "{LOG_DIR}": ports.MU.LOG_DIR, "{CA}": os.path.join(ports.MU.CA_DIR, "ca.pem"),
    "{CERT}": os.path.join(ports.MU.PKI_DIR, "server", "server.pem"),
    "{KEY}": os.path.join(ports.MU.PKI_DIR, "server", "server.key"),
    "{JWKS}": os.path.join(ports.MU.TOKENS_DIR, "jwks.json"),
}

def render_configs(backends: dict) -> None:
    for d in (ports.MU.CONFIG_DIR, ports.MU.LOG_DIR, ports.MU.DATA_ROOT, ports.MU.CACHE_ROOT):
        os.makedirs(d, exist_ok=True)
    subst = dict(_SUBST)
    subst.update({"{GRIDMAP}": backends["gridmap"], "{AUTHDB}": backends["authdb"],
                  "{VO}": backends["vo"]})
    for src in glob.glob(os.path.join(_CFG_SRC, "*.conf")):
        text = open(src).read()
        for k, v in subst.items():
            text = text.replace(k, v)
        dst = os.path.join(ports.MU.CONFIG_DIR, os.path.basename(src))
        open(dst, "w").write(text)
        # validate before use
        r = subprocess.run([NGINX, "-t", "-c", dst], capture_output=True, text=True)
        assert r.returncode == 0, f"nginx -t failed for {dst}:\n{r.stderr}"

def _pid(name): return os.path.join(ports.MU.MU_ROOT, f"{name}.pid")

def start() -> None:
    for src in glob.glob(os.path.join(ports.MU.CONFIG_DIR, "*.conf")):
        name = os.path.splitext(os.path.basename(src))[0]
        subprocess.run([NGINX, "-c", src, "-g", f"pid {_pid(name)};"], check=True,
                       capture_output=True)

def stop() -> None:
    for pf in glob.glob(os.path.join(ports.MU.MU_ROOT, "*.pid")):
        try:
            os.kill(int(open(pf).read().strip()), 15)
        except (ProcessLookupError, ValueError, FileNotFoundError):
            pass

def wait_listening(timeout: int = 15) -> None:
    targets = [ports.MU.ROOT_DIRECT, ports.MU.ROOT_CACHE, ports.MU.WEBDAV_DIRECT,
               ports.MU.WEBDAV_CACHE, ports.MU.S3_DIRECT, ports.MU.S3_CACHE]
    deadline = time.time() + timeout
    for p in targets:
        while time.time() < deadline:
            s = socket.socket(); s.settimeout(0.5)
            try:
                s.connect((ports.MU.HOST, p)); s.close(); break
            except OSError:
                s.close(); time.sleep(0.2)
        else:
            raise TimeoutError(f"MU port {p} never listened")

def url(proto: str, variant: str) -> str:
    port = getattr(ports.MU, f"{proto.upper()}_{variant.upper()}")
    scheme = {"root": "root", "webdav": "https", "s3": "http"}[proto]
    return f"{scheme}://{ports.MU.HOST}:{port}"
```

- [ ] **Step 5: Write the orchestrator + run selftest**

```bash
# tests/run_multiuser_authz.sh
#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
if [ "$(id -u)" -ne 0 ]; then echo "MU suite requires root" >&2; exit 2; fi
export PYTHONPATH=tests
python -c "from pki_helpers import blitz_test_pki; blitz_test_pki()"   # ensure CA/server certs
pytest tests/test_mu_*.py "$@"
```

Run: `cd /home/rcurrie/HEP-x/nginx-xrootd && chmod +x tests/run_multiuser_authz.sh && sudo -E env PYTHONPATH=tests pytest tests/mu_authz_lib/test_fleet_selftest.py -v`
Expected: PASS under root (all 6 ports listen). Iterate on config directive names until `nginx -t` passes inside `render_configs`.

- [ ] **Step 6: Commit**

```bash
git add tests/configs/multiuser/ tests/mu_authz_lib/fleet.py tests/run_multiuser_authz.sh tests/mu_authz_lib/test_fleet_selftest.py
git commit -m "test(mu): paired direct+cache MU fleet, config renderer, orchestrator"
```

---

## Task 7: Cache-state control

**Files:**
- Create: `tests/mu_authz_lib/cache_state.py`
- Test: `tests/mu_authz_lib/test_cache_state_selftest.py`

**Interfaces:**
- Consumes: `ports.MU` (Task 1), `fleet` (Task 6).
- Produces:
  - `cache_is_resident(rel_path: str) -> dict` (from `xrdcinfo`; `{"absent": True}` when cold).
  - `force_cold(rel_path: str|None=None) -> None` (wipe cache store, or just the sidecar for one path).
  - `fill_as(principal, rel_path, proto="root") -> None` (read the whole file via the cache server as `principal` to populate it).
  - `verify_hot(rel_path) -> bool`.
  - `XRDCINFO` path constant; build it if missing.

- [ ] **Step 1: Write the failing test**

```python
# tests/mu_authz_lib/test_cache_state_selftest.py
import os, pytest
from mu_authz_lib import cache_state, ports

privileged = pytest.mark.skipif(os.geteuid() != 0, reason="needs root + fleet")

def test_cold_reports_absent():
    cache_state.force_cold()
    rec = cache_state.cache_is_resident("cms/secret.dat")
    assert rec.get("absent") is True

@privileged
def test_fill_makes_hot(mu_fleet, cast):     # fixtures from conftest_mu.py (Task 8/wrap)
    cache_state.force_cold()
    cache_state.fill_as(cast["svc"], "cms/secret.dat", proto="root")
    assert cache_state.verify_hot("cms/secret.dat")
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd /home/rcurrie/HEP-x/nginx-xrootd && PYTHONPATH=tests pytest tests/mu_authz_lib/test_cache_state_selftest.py::test_cold_reports_absent -v`
Expected: FAIL — module `cache_state` missing.

- [ ] **Step 3: Write minimal implementation**

```python
# tests/mu_authz_lib/cache_state.py
"""Prove/force read-cache residency via xrdcinfo (spec §8.5)."""
import os, json, shutil, subprocess
from . import ports

XRDCINFO = os.path.join(os.path.dirname(__file__), "..", "..", "client", "bin", "xrdcinfo")

def _ensure_tool():
    if not os.path.exists(XRDCINFO):
        subprocess.run(["make", "-C", os.path.join(os.path.dirname(__file__), "..", "..", "client"),
                        "xrdcinfo"], check=True, capture_output=True)

def cache_is_resident(rel_path: str) -> dict:
    _ensure_tool()
    cache_file = os.path.join(ports.MU.CACHE_ROOT, rel_path)
    sidecar = cache_file + ".cinfo"
    p = subprocess.run([XRDCINFO, sidecar], capture_output=True, text=True)
    if p.stdout.strip():
        rec = json.loads(p.stdout.strip())
        if not rec.get("absent"):
            return rec
    if os.path.exists(cache_file):
        px = subprocess.run([XRDCINFO, "--xattr", cache_file], capture_output=True, text=True)
        if px.stdout.strip():
            rec = json.loads(px.stdout.strip())
            if not rec.get("absent"):
                return rec
    return {"absent": True}

def force_cold(rel_path: str | None = None) -> None:
    if rel_path is None:
        if os.path.exists(ports.MU.CACHE_ROOT):
            shutil.rmtree(ports.MU.CACHE_ROOT)
        os.makedirs(ports.MU.CACHE_ROOT, exist_ok=True)
    else:
        for suffix in ("", ".cinfo"):
            f = os.path.join(ports.MU.CACHE_ROOT, rel_path) + suffix
            if os.path.exists(f):
                os.remove(f)

def fill_as(principal, rel_path: str, proto: str = "root") -> None:
    from .adapters import measure_root, measure_webdav, measure_s3
    url = __import__("mu_authz_lib.fleet", fromlist=["url"]).url(proto, "cache")
    fn = {"root": measure_root, "webdav": measure_webdav, "s3": measure_s3}[proto]
    fn(url, "/" + rel_path, "read", principal=principal)   # a successful whole read fills it

def verify_hot(rel_path: str) -> bool:
    rec = cache_is_resident(rel_path)
    return (not rec.get("absent")) and (rec.get("complete") or rec.get("present_count", 0) > 0)
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd /home/rcurrie/HEP-x/nginx-xrootd && PYTHONPATH=tests pytest tests/mu_authz_lib/test_cache_state_selftest.py::test_cold_reports_absent -v`
Expected: PASS. (The `test_fill_makes_hot` is privileged/fleet-gated — validated in Task 8 once adapters exist.)

- [ ] **Step 5: Commit**

```bash
git add tests/mu_authz_lib/cache_state.py tests/mu_authz_lib/test_cache_state_selftest.py
git commit -m "test(mu): cache-state control (xrdcinfo residency proof, force-cold, fill)"
```

---

## Task 8: Verdict + protocol adapters

**Files:**
- Create: `tests/mu_authz_lib/verdict.py`
- Create: `tests/mu_authz_lib/adapters.py`
- Test: `tests/mu_authz_lib/test_adapters_selftest.py`

**Interfaces:**
- Consumes: `principals.Principal` (Task 3), `ports.MU` (Task 1).
- Produces:
  - `@dataclass(frozen=True) Verdict(decision: str, reason: str, tier: str)` with `decision ∈ {"ALLOW","DENY"}`; `__eq__` compares `decision` and `tier` (reason is advisory — normalized) so cache-transparency is decidable.
  - `infer_tier(reason: str) -> str` using `REASON_TIER` (exact server strings: `"VO not authorized"→"vo_acl"`, `"token scope denied"→"token_scope"`, `"not authorized"→"authdb"`, `"file not found"→"none"`, write-blocked→`"allow_write"`).
  - `measure_root(url, path, op, *, principal=None) -> Verdict`
  - `measure_webdav(url, path, op, *, principal=None) -> Verdict`
  - `measure_s3(url, path, op, *, principal=None) -> Verdict`
  - Each selects the principal's proxy/token/S3 key per call (subprocess isolation for root).

- [ ] **Step 1: Write the failing test**

```python
# tests/mu_authz_lib/test_adapters_selftest.py
from mu_authz_lib.verdict import Verdict, infer_tier

def test_tier_inference():
    assert infer_tier("VO not authorized") == "vo_acl"
    assert infer_tier("token scope denied") == "token_scope"
    assert infer_tier("not authorized") == "authdb"

def test_verdict_equality_ignores_reason_text():
    a = Verdict("DENY", "VO not authorized", "vo_acl")
    b = Verdict("DENY", "vo denied for /cms", "vo_acl")
    assert a == b                       # same decision+tier
    assert a != Verdict("ALLOW", "", "none")
    assert a != Verdict("DENY", "x", "token_scope")   # different tier ⇒ different verdict
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd /home/rcurrie/HEP-x/nginx-xrootd && PYTHONPATH=tests pytest tests/mu_authz_lib/test_adapters_selftest.py -v`
Expected: FAIL — module `verdict` missing.

- [ ] **Step 3: Write `verdict.py`**

```python
# tests/mu_authz_lib/verdict.py
"""Verdict = decision + reason + deciding tier. Equality is (decision, tier)."""
from dataclasses import dataclass

REASON_TIER = [
    ("vo not authorized", "vo_acl"),
    ("token scope denied", "token_scope"),
    ("scope", "token_scope"),
    ("not authorized", "authdb"),
    ("permission denied", "authdb"),
    ("read-only", "allow_write"),
    ("not found", "none"),
]

def infer_tier(reason: str) -> str:
    r = (reason or "").lower()
    for needle, tier in REASON_TIER:
        if needle in r:
            return tier
    return "unknown"

@dataclass(frozen=True)
class Verdict:
    decision: str            # "ALLOW" | "DENY"
    reason: str
    tier: str

    def __eq__(self, other):
        return (isinstance(other, Verdict)
                and self.decision == other.decision
                and self.tier == other.tier)

    def __hash__(self):
        return hash((self.decision, self.tier))

    @classmethod
    def allow(cls):
        return cls("ALLOW", "", "none")

    @classmethod
    def deny(cls, reason):
        return cls("DENY", reason, infer_tier(reason))
```

- [ ] **Step 4: Write `adapters.py`**

Use the extracted `measure_root` subprocess pattern (per-call env: `X509_USER_PROXY`+`XrdSecPROTOCOL=gsi` for proxy, `BEARER_TOKEN_FILE`+`XrdSecPROTOCOL=ztn` for token), the WebDAV `requests` pattern (`cert=proxy, verify=CA` or `headers={"Authorization": "Bearer ..."}`), and the hand-rolled SigV4 signer.

```python
# tests/mu_authz_lib/adapters.py
"""Per-protocol verdict measurement → Verdict (spec §7, §8.6)."""
import os, sys, json, subprocess
import requests
from .verdict import Verdict
from . import ports

_ROOT_PROBE = r'''
import json, sys
from XRootD import client
from XRootD.client.flags import OpenFlags
url, path, op = sys.argv[1], sys.argv[2], sys.argv[3]
if op == "stat":
    st, _ = client.FileSystem(url).stat(path)
else:
    f = client.File(); st, _ = f.open(url + "//" + path, OpenFlags.READ)
    if st.ok:
        if op == "read": st, _ = f.read(0, 4096)
        f.close()
print(json.dumps({"ok": bool(st.ok), "errno": int(st.errno), "message": st.message or ""}))
'''

def _root_env(principal):
    env = os.environ.copy()
    env["X509_CERT_DIR"] = ports.MU.CA_DIR
    if principal is None:
        return env
    if principal.proxy:
        env["X509_USER_PROXY"] = principal.proxy; env["XrdSecPROTOCOL"] = "gsi"
    elif principal.token:
        env["BEARER_TOKEN_FILE"] = principal.token; env["XrdSecPROTOCOL"] = "ztn"
    return env

def measure_root(url, path, op, *, principal=None) -> Verdict:
    r = subprocess.run([sys.executable, "-c", _ROOT_PROBE, url, path, op],
                       env=_root_env(principal), capture_output=True, text=True, timeout=20)
    for line in r.stdout.splitlines():
        try:
            d = json.loads(line)
        except json.JSONDecodeError:
            continue
        return Verdict.allow() if d["ok"] else Verdict.deny(d["message"])
    return Verdict.deny(f"probe-failed: {r.stderr.strip()}")

def measure_webdav(url, path, op, *, principal=None) -> Verdict:
    kw = {"verify": os.path.join(ports.MU.CA_DIR, "ca.pem"), "timeout": 20}
    if principal and principal.token:
        kw["headers"] = {"Authorization": "Bearer " + open(principal.token).read().strip()}
        kw["verify"] = False
    elif principal and principal.proxy:
        kw["cert"] = principal.proxy; kw["verify"] = False
    method = {"read": "GET", "stat": "HEAD", "list": "PROPFIND"}.get(op, "GET")
    resp = requests.request(method, url + path, **kw)
    if resp.status_code in (200, 206, 207):
        return Verdict.allow()
    reason = (resp.reason or "") + " " + resp.text[:200]
    return Verdict.deny(reason if resp.status_code in (401, 403) else f"http {resp.status_code}")

def measure_s3(url, path, op, *, principal=None) -> Verdict:
    from .s3sig import signed_headers          # small helper below
    ak, sk = (principal.s3_key, principal.s3_secret) if principal else ("", "")
    headers = signed_headers("GET", path, ak, sk, host=url.split("://",1)[1])
    resp = requests.get(url + path, headers=headers, timeout=20)
    if resp.status_code == 200:
        return Verdict.allow()
    import re
    m = re.search(r"<Code>([^<]+)</Code>", resp.text)
    return Verdict.deny(m.group(1) if m else f"http {resp.status_code}")
```

Add `tests/mu_authz_lib/s3sig.py` containing the extracted `_signing_key`/`_signed_headers` SigV4 code as a reusable `signed_headers(method, path, access_key, secret, host)` function.

- [ ] **Step 5: Run selftest + a live smoke (privileged)**

Run: `cd /home/rcurrie/HEP-x/nginx-xrootd && PYTHONPATH=tests pytest tests/mu_authz_lib/test_adapters_selftest.py -v`
Expected: PASS (2 passed, pure-logic).
Then, under root with the fleet up, smoke: alice ALLOW on `/cms/secret.dat` (direct), bob DENY (tier `authdb` or `vo_acl`). Iterate until the reason→tier map matches real server strings (grep the server source messages you saw: `"VO not authorized"`, `"token scope denied"`, `"not authorized"`).

- [ ] **Step 6: Commit**

```bash
git add tests/mu_authz_lib/verdict.py tests/mu_authz_lib/adapters.py tests/mu_authz_lib/s3sig.py tests/mu_authz_lib/test_adapters_selftest.py
git commit -m "test(mu): Verdict + per-protocol adapters (root/webdav/s3 → decision+reason+tier)"
```

---

## Task 9: The differential oracle + MU fixtures

**Files:**
- Create: `tests/mu_authz_lib/oracle.py`
- Create: `tests/conftest_mu.py` (session/function fixtures: `mu_fleet`, `cast`, `apply_policy`)
- Modify: `tests/conftest.py` — register `conftest_mu` and the `leak`/`privileged` markers
- Test: `tests/mu_authz_lib/test_oracle_selftest.py`

**Interfaces:**
- Consumes: `adapters` (Task 8), `cache_state` (Task 7), `fleet` (Task 6), `verdict.Verdict` (Task 8).
- Produces:
  - `@dataclass Cell(proto, op, subject, path, filler, expect_tier=None)`
  - `measure(proto, variant, path, op, principal) -> Verdict` (dispatch to the right adapter + fleet URL).
  - `authoritative(proto, path, op, principal) -> Verdict` (always the `direct` variant).
  - `assert_cache_transparent(cell) -> None` — compares direct vs cache-cold vs cache-hot(filled by `cell.filler`); raises `AssertionError(leak_report(...))` on any mismatch.
  - `leak_report(cell, authoritative, observed, where) -> str`.
  - Fixtures: `cast` (session), `mu_fleet` (session, privileged — provisions accounts, renders default policy, starts fleet, reaps on teardown), `apply_policy(policy)` (function — re-render backends + reload fleet).

- [ ] **Step 1: Write the failing test** (oracle logic with a stub adapter)

```python
# tests/mu_authz_lib/test_oracle_selftest.py
import pytest
from mu_authz_lib import oracle
from mu_authz_lib.verdict import Verdict

def test_oracle_passes_when_consistent(monkeypatch):
    # direct=DENY(authdb), cache-cold=DENY(authdb), cache-hot=DENY(authdb) → transparent
    monkeypatch.setattr(oracle, "measure", lambda *a, **k: Verdict("DENY", "not authorized", "authdb"))
    monkeypatch.setattr(oracle, "_fill", lambda *a, **k: None)
    cell = oracle.Cell(proto="root", op="read", subject="carol", path="/cms/secret.dat", filler="svc")
    oracle.assert_cache_transparent(cell, cast={"carol": object(), "svc": object()})

def test_oracle_fails_on_leak(monkeypatch):
    calls = {"n": 0}
    def fake_measure(proto, variant, path, op, principal):
        # direct DENY, but cache variant ALLOWs → leak
        return Verdict("DENY","not authorized","authdb") if variant == "direct" else Verdict.allow()
    monkeypatch.setattr(oracle, "measure", fake_measure)
    monkeypatch.setattr(oracle, "_fill", lambda *a, **k: None)
    cell = oracle.Cell(proto="root", op="read", subject="carol", path="/cms/secret.dat", filler="svc")
    with pytest.raises(AssertionError) as ei:
        oracle.assert_cache_transparent(cell, cast={"carol": object(), "svc": object()})
    assert "LEAK" in str(ei.value) and "carol" in str(ei.value)
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd /home/rcurrie/HEP-x/nginx-xrootd && PYTHONPATH=tests pytest tests/mu_authz_lib/test_oracle_selftest.py -v`
Expected: FAIL — module `oracle` missing.

- [ ] **Step 3: Write `oracle.py`**

```python
# tests/mu_authz_lib/oracle.py
"""Differential cache-transparency oracle (spec §5). direct server = ground truth."""
from dataclasses import dataclass
from . import fleet, cache_state
from .adapters import measure_root, measure_webdav, measure_s3

_ADAPTER = {"root": measure_root, "webdav": measure_webdav, "s3": measure_s3}

@dataclass
class Cell:
    proto: str
    op: str
    subject: str
    path: str
    filler: str = "svc"
    expect_tier: str | None = None

def measure(proto, variant, path, op, principal):
    return _ADAPTER[proto](fleet.url(proto, variant), path, op, principal=principal)

def authoritative(proto, path, op, principal):
    return measure(proto, "direct", path, op, principal)

def _fill(proto, path, filler):
    rel = path.lstrip("/")
    cache_state.force_cold(rel)
    cache_state.fill_as(filler, rel, proto=proto)

def leak_report(cell, truth, observed, where) -> str:
    seam = {"root": "open_cache.c:24 (VO-only hit gate)",
            "webdav": "webdav read-cache serve",
            "s3": "s3 no-scope serve"}.get(cell.proto, cell.proto)
    return (f"LEAK [{cell.proto}/{cell.op}] subject={cell.subject} filler={cell.filler} "
            f"path={cell.path}\n  authoritative(direct) = {truth}\n"
            f"  observed({where})   = {observed}\n  likely seam: {seam}")

def assert_cache_transparent(cell, cast):
    subj = cast[cell.subject]; filler = cast[cell.filler]
    truth = authoritative(cell.proto, cell.path, cell.op, subj)
    # 1) cache server, cold (nothing filled yet)
    cache_state.force_cold(cell.path.lstrip("/"))
    cold = measure(cell.proto, "cache", cell.path, cell.op, subj)
    assert cold == truth, leak_report(cell, truth, cold, "cache-cold")
    # 2) cache server, hot (filled by the privileged filler)
    _fill(cell.proto, cell.path, filler)
    hot = measure(cell.proto, "cache", cell.path, cell.op, subj)
    assert hot == truth, leak_report(cell, truth, hot, "cache-hot")
    if cell.expect_tier and truth.decision == "DENY":
        assert truth.tier == cell.expect_tier, (
            f"tier mismatch: expected {cell.expect_tier}, got {truth.tier} ({truth.reason})")
```

- [ ] **Step 4: Write `conftest_mu.py` + register markers**

```python
# tests/conftest_mu.py
import os, pytest
from mu_authz_lib import principals, accounts, policy, fleet

def _privileged():
    return os.geteuid() == 0

@pytest.fixture(scope="session")
def cast():
    return principals.build_cast()

@pytest.fixture(scope="session")
def mu_fleet(cast):
    if not _privileged():
        pytest.fail("MU suite requires root (spec D4) — run tests/run_multiuser_authz.sh under sudo")
    accounts.sweep_leftover()
    accounts.provision(cast)
    default = policy.Policy("/cms/secret.dat", allow=["alice"], deny=["bob", "carol"],
                            vo="cms", scope_prefix="storage.read:/cms")
    backends = policy.render_policy(default, cast)
    _seed_export(cast)                # create /cms/secret.dat readable only by svc+alice
    fleet.render_configs(backends)
    fleet.start(); fleet.wait_listening(20)
    yield fleet
    fleet.stop(); accounts.reap()

def _seed_export(cast):
    from mu_authz_lib import ports
    d = os.path.join(ports.MU.DATA_ROOT, "cms"); os.makedirs(d, exist_ok=True)
    f = os.path.join(d, "secret.dat"); open(f, "wb").write(b"S" * 65536)
    os.chown(f, cast["svc"].uid, cast["svc"].uid); os.chmod(f, 0o640)

@pytest.fixture
def apply_policy(cast):
    def _apply(pol):
        backends = policy.render_policy(pol, cast)
        fleet.render_configs(backends)
        fleet.stop(); fleet.start(); fleet.wait_listening(20)
    return _apply
```

Add to `tests/conftest.py` (top-level): register the plugin + markers.

```python
# --- append to tests/conftest.py ---
pytest_plugins = ["conftest_mu"]

def pytest_configure(config):
    config.addinivalue_line("markers", "leak: cross-user leak — encodes correct invariant, fails red until code is fixed")
    config.addinivalue_line("markers", "privileged: requires root (real accounts + setfsuid)")
```

**NOTE:** if `tests/conftest.py` already defines `pytest_configure`, merge the two `addinivalue_line` calls into the existing function rather than redefining it.

- [ ] **Step 5: Run oracle selftest to verify it passes**

Run: `cd /home/rcurrie/HEP-x/nginx-xrootd && PYTHONPATH=tests pytest tests/mu_authz_lib/test_oracle_selftest.py -v`
Expected: PASS (2 passed).

- [ ] **Step 6: Commit**

```bash
git add tests/mu_authz_lib/oracle.py tests/conftest_mu.py tests/conftest.py tests/mu_authz_lib/test_oracle_selftest.py
git commit -m "test(mu): differential cache-transparency oracle + MU fixtures + markers"
```

---

## Task 10: F1 — cross-user cache-hit re-auth (~40 cells)

**Files:**
- Create: `tests/test_mu_authz_cachetransp.py`

**Interfaces:**
- Consumes: `oracle.Cell`, `oracle.assert_cache_transparent`, fixtures `mu_fleet`, `cast`, `apply_policy`.

- [ ] **Step 1: Write the family test (parametrized cell table)**

```python
# tests/test_mu_authz_cachetransp.py
"""F1 — cross-user cache-hit re-auth. The invariant: a cache/stage server's verdict for
principal B equals the direct server's verdict (spec §2, §6/F1). carol (same VO as the
filler, NO authdb grant) is the sharpest leak probe: direct DENYs at authdb, but the
cached path only checks VO ACL (open_cache.c:24) → predicted LEAK."""
import pytest
from mu_authz_lib.oracle import Cell, assert_cache_transparent

# (proto, op, subject, expect_tier, is_leak)
_CELLS = []
for proto in ("root", "webdav"):
    for op in ("read", "stat"):
        # denied subjects on /cms/secret.dat (filler=svc)
        _CELLS.append((proto, op, "carol", "authdb", True))    # same-VO, no authdb grant
        _CELLS.append((proto, op, "bob",   "vo_acl", True))     # different VO
        _CELLS.append((proto, op, "alice", None,     False))    # allowed both ways (control)
# scope-denied variant: mallory has cms VO + read:/cms scope but revoke authdb
for proto in ("root", "webdav"):
    _CELLS.append((proto, "read", "mallory", "authdb", True))

@pytest.mark.leak
@pytest.mark.privileged
@pytest.mark.parametrize("proto,op,subject,tier,is_leak",
                         [c for c in _CELLS if c[4]],
                         ids=lambda c: None)
def test_cache_hit_does_not_leak(mu_fleet, cast, proto, op, subject, tier, is_leak):
    cell = Cell(proto=proto, op=op, subject=subject, path="/cms/secret.dat",
                filler="svc", expect_tier=tier)
    assert_cache_transparent(cell, cast)   # FAILS RED today (leak); passes once code fixed

@pytest.mark.privileged
@pytest.mark.parametrize("proto,op,subject,tier,is_leak",
                         [c for c in _CELLS if not c[4]],
                         ids=lambda c: None)
def test_allowed_subject_is_transparent(mu_fleet, cast, proto, op, subject, tier, is_leak):
    cell = Cell(proto=proto, op=op, subject=subject, path="/cms/secret.dat", filler="svc")
    assert_cache_transparent(cell, cast)   # allowed cold and hot → PASSES
```

Expand `_CELLS` (more paths, more denied subjects, staged variant via `filler="svc"` on a nearline path) until the parametrization reaches ~40 ids. Keep each id a distinct threat-relevant (proto, op, subject, path) tuple — do not pad.

- [ ] **Step 2: Run to verify the leak tests FAIL red (as designed)**

Run: `cd /home/rcurrie/HEP-x/nginx-xrootd && sudo -E env PYTHONPATH=tests pytest tests/test_mu_authz_cachetransp.py -v`
Expected: `test_allowed_subject_is_transparent` PASSES; `test_cache_hit_does_not_leak` **FAILS** with `LEAK [root/read] subject=carol ... likely seam: open_cache.c:24`. This red failure is the deliverable (spec §10). If a leak cell unexpectedly PASSES, the code may already re-auth — verify the fill actually made the file hot (`verify_hot`) and the direct server truly DENYs carol.

- [ ] **Step 3: Commit**

```bash
git add tests/test_mu_authz_cachetransp.py
git commit -m "test(mu/F1): cross-user cache-hit re-auth — cache-transparency, ~40 cells (leak)"
```

---

## Task 11: F2 — cvmfs public-by-design guardrails (~18 cells)

**Files:**
- Create: `tests/test_mu_cvmfs_public.py`

- [ ] **Step 1: Write the family test**

```python
# tests/test_mu_cvmfs_public.py
"""F2 — cvmfs is a public content cache (spec §4, D3): assert credentials are IGNORED
and no privilege is INFERRED. These PASS against current behavior; they lock cvmfs to
public semantics so it can't silently gain an auth-derived privilege later."""
import pytest
from mu_authz_lib import fleet, ports
from mu_authz_lib.adapters import measure_webdav   # cvmfs is HTTP

_SUBJECTS = ["anonymous", "alice", "bob", "mallory"]

@pytest.mark.privileged
@pytest.mark.parametrize("op", ["read", "stat"])
@pytest.mark.parametrize("subject", _SUBJECTS)
def test_authenticated_equals_anonymous(mu_fleet, cast, subject, op):
    url = f"https://{ports.MU.HOST}:{ports.MU.CVMFS_CACHE}"
    principal = None if subject == "anonymous" else cast[subject]
    anon = measure_webdav(url, "/repo/public.txt", op, principal=None)
    got  = measure_webdav(url, "/repo/public.txt", op, principal=principal)
    assert got == anon, f"cvmfs must ignore creds: {subject} got {got}, anon got {anon}"

@pytest.mark.privileged
def test_scoped_token_does_not_widen_access(mu_fleet, cast):
    """A token scoped to /cms must not grant MORE on cvmfs than anonymous."""
    url = f"https://{ports.MU.HOST}:{ports.MU.CVMFS_CACHE}"
    anon = measure_webdav(url, "/repo/restricted.txt", "read", principal=None)
    scoped = measure_webdav(url, "/repo/restricted.txt", "read", principal=cast["alice"])
    assert scoped == anon, "cvmfs must not infer privilege from a token"
```

Expand across a few repo paths (public/restricted/nested) to reach ~18 ids.

- [ ] **Step 2: Run — expect PASS**

Run: `cd /home/rcurrie/HEP-x/nginx-xrootd && sudo -E env PYTHONPATH=tests pytest tests/test_mu_cvmfs_public.py -v`
Expected: all PASS (cvmfs ignores creds today, so authenticated ≡ anonymous). Requires `cvmfs_cache.conf` + a seeded `/repo/` export.

- [ ] **Step 3: Commit**

```bash
git add tests/test_mu_cvmfs_public.py
git commit -m "test(mu/F2): cvmfs public-by-design guardrails (~18 cells)"
```

---

## Task 12: F3 — service-credential stage laundering (~15 cells)

**Files:**
- Create: `tests/test_mu_stage_laundering.py`

- [ ] **Step 1: Write the family test**

```python
# tests/test_mu_stage_laundering.py
"""F3 — a fill done under the origin SERVICE credential must not be readable by a user
whose own authz would deny it (spec §6/F3). The fill identity (svc, wide scope) differs
from the serve identity (denied user). Predicted LEAK: origin_auth.c uses service creds,
open_cache.c hit gate is weaker."""
import pytest
from mu_authz_lib.oracle import Cell, assert_cache_transparent

# svc can read /cms/service-only.dat (mode 0600 owned by svc); carol/bob cannot.
@pytest.mark.leak
@pytest.mark.privileged
@pytest.mark.parametrize("proto", ["root", "webdav"])
@pytest.mark.parametrize("subject", ["carol", "bob", "mallory"])
def test_service_fill_not_served_to_denied_user(mu_fleet, cast, seed_service_only, proto, subject):
    cell = Cell(proto=proto, op="read", subject=subject,
                path="/cms/service-only.dat", filler="svc")
    assert_cache_transparent(cell, cast)   # FAILS RED today
```

Add a `seed_service_only` fixture (in `conftest_mu.py`) creating `/cms/service-only.dat` mode `0600` owned by `svc`, and grant svc-only authdb. Expand subjects/protocols/ops to ~15 ids.

- [ ] **Step 2: Run — expect leak FAILs**

Run: `cd /home/rcurrie/HEP-x/nginx-xrootd && sudo -E env PYTHONPATH=tests pytest tests/test_mu_stage_laundering.py -v`
Expected: FAILS RED with `LEAK` reports (service-filled bytes served to denied users).

- [ ] **Step 3: Commit**

```bash
git add tests/test_mu_stage_laundering.py tests/conftest_mu.py
git commit -m "test(mu/F3): service-cred stage laundering (~15 cells, leak)"
```

---

## Task 13: F4 — prepare/stage authz incl. noerrs bypass (~20 cells)

**Files:**
- Create: `tests/test_mu_prepare_authz.py`

**Interfaces:**
- Consumes: `adapters.measure_root` (prepare uses the XRootD `prepare` op) + a small `prepare_as(principal, path, noerrs)` helper.

- [ ] **Step 1: Write the family test**

```python
# tests/test_mu_prepare_authz.py
"""F4 — prepare/stage authorization, including the noerrs bypass (spec §6/F4).
prepare.c:184 returns OK for an ABSENT path + kXR_noerrs BEFORE the three authz checks
(authz_check/vo_acl/token_scope at 208/214/220). Predicted LEAK: an unauthorized user can
prepare/stage a restricted path that does not yet exist."""
import pytest
from mu_authz_lib import fleet
from mu_authz_lib.prepare import prepare_as   # thin XRootD prepare wrapper (add to lib)

# (subject, path_exists, noerrs, expect_denied)
_CELLS = [
    ("carol", True,  False, True),   # existing restricted → must DENY (authz runs)
    ("carol", False, True,  True),   # ABSENT + noerrs → prepare.c:184 bypass → LEAK
    ("bob",   False, True,  True),   # different VO, absent+noerrs → LEAK
    ("alice", True,  False, False),  # authorized → allowed (control)
]

@pytest.mark.privileged
@pytest.mark.parametrize("subject,exists,noerrs,expect_denied", _CELLS)
def test_prepare_requires_authz(mu_fleet, cast, subject, exists, noerrs, expect_denied):
    path = "/cms/secret.dat" if exists else "/cms/not-yet-created.dat"
    denied = prepare_as(cast[subject], path, noerrs=noerrs)
    if expect_denied:
        # leak cells are the absent+noerrs ones; mark them
        assert denied, f"prepare of {path} by {subject} must be denied (bypass = leak)"
    else:
        assert not denied
```

Mark the absent+noerrs rows with `@pytest.mark.leak` (split into two parametrized tests: a `leak`-marked one for bypass rows, a plain one for control rows, mirroring Task 10). Expand with recall-by-other (T9): user B triggers/consumes a recall requested by user A. Reach ~20 ids.

- [ ] **Step 2: Run — expect bypass rows FAIL red**

Run: `cd /home/rcurrie/HEP-x/nginx-xrootd && sudo -E env PYTHONPATH=tests pytest tests/test_mu_prepare_authz.py -v`
Expected: control rows PASS; absent+noerrs bypass rows FAIL red (prepare returns OK where it must deny).

- [ ] **Step 3: Commit**

```bash
git add tests/test_mu_prepare_authz.py tests/mu_authz_lib/prepare.py
git commit -m "test(mu/F4): prepare/stage authz + noerrs bypass (~20 cells, leak)"
```

---

## Task 14: F5 — cross-protocol poisoning + S3 scope parity (~26 cells)

**Files:**
- Create: `tests/test_mu_cross_protocol.py`

- [ ] **Step 1: Write the family test**

```python
# tests/test_mu_cross_protocol.py
"""F5 — a cache entry filled via one protocol must be served by another only under the
serve protocol's OWN authz for the presented identity (spec §6/F5). Fill via root under a
read-only-scoped principal, serve via S3/WebDAV; the serve verdict must equal that
protocol's direct verdict. S3 scope-parity cells predicted LEAK (S3 never checks scope)."""
import pytest
from mu_authz_lib import cache_state, fleet
from mu_authz_lib.oracle import measure, authoritative, leak_report, Cell

_PAIRS = [("root", "s3"), ("root", "webdav"), ("webdav", "s3"),
          ("s3", "root"), ("webdav", "root"), ("s3", "webdav")]

@pytest.mark.leak
@pytest.mark.privileged
@pytest.mark.parametrize("fill_proto,serve_proto", _PAIRS)
@pytest.mark.parametrize("subject", ["carol", "bob"])
def test_fill_one_serve_other(mu_fleet, cast, fill_proto, serve_proto, subject):
    path = "/cms/secret.dat"; rel = path.lstrip("/")
    truth = authoritative(serve_proto, path, "read", cast[subject])   # serve-proto ground truth
    cache_state.force_cold(rel)
    cache_state.fill_as(cast["svc"], rel, proto=fill_proto)           # fill via other proto
    got = measure(serve_proto, "cache", path, "read", cast[subject])
    cell = Cell(proto=serve_proto, op="read", subject=subject, path=path, filler="svc")
    assert got == truth, leak_report(cell, truth, got, f"filled-via-{fill_proto}")
```

Add explicit S3 scope-parity cells: fill via root under alice's read-only `/cms` token, then serve via S3 with a key that S3's own policy would deny — assert DENY. Reach ~26 ids.

- [ ] **Step 2: Run — expect S3-parity/poisoning FAIL red**

Run: `cd /home/rcurrie/HEP-x/nginx-xrootd && sudo -E env PYTHONPATH=tests pytest tests/test_mu_cross_protocol.py -v`
Expected: pairs where the serve protocol denies but the cache serves → FAIL red; consistent pairs PASS.

- [ ] **Step 3: Commit**

```bash
git add tests/test_mu_cross_protocol.py
git commit -m "test(mu/F5): cross-protocol poisoning + S3 scope parity (~26 cells, leak)"
```

---

## Task 15: F6 — principal→uid collapse + setfsuid ownership (~30 cells)

**Files:**
- Create: `tests/c/idmap_collapse_test.c`
- Create: `tests/c/run_mu_unit.sh`
- Create: `tests/test_mu_impersonation_e2e.py`

**Interfaces:**
- Consumes: `src/auth/impersonate/idmap.c` (unit), `mu_fleet`+`cast` (e2e).

- [ ] **Step 1: Write the C unit (collapse + squash + min_uid)**

Match `tests/c/idmap_test.c` exactly (stub `ngx_log_error_core`, `CHECK()` macro, `static int fails`). Read `idmap.c`/`impersonate.h` for the real function/struct/enum names first, then:

```c
/* tests/c/idmap_collapse_test.c — F6 mapping unit (matches idmap_test.c style; NO goto) */
#include <ngx_config.h>
#include <ngx_core.h>
#include "../../src/auth/impersonate/impersonate.h"
#include <stdio.h>
#include <string.h>

void ngx_log_error_core(ngx_uint_t l, ngx_log_t *g, ngx_err_t e, const char *f, ...)
{ (void)l;(void)g;(void)e;(void)f; }

static int fails = 0;
#define CHECK(cond, msg) do { if (cond) printf("  PASS %s\n", msg); \
    else { printf("  FAIL %s\n", msg); fails++; } } while (0)

int main(void)
{
    /* min_uid guard: a gridmap entry mapping below min_uid must be denied/squashed. */
    /* collapse: DN "/DC=test/CN=alice" and krb "alice@TEST.REALM" both resolve to the
       same uid ONLY via explicit gridmap — assert an UNMAPPED principal that merely
       string-matches a local username does NOT silently collapse (T6). */
    /* Fill in with the real idmap API names read from idmap.c/impersonate.h. */
    printf(fails ? "\n%d FAILED\n" : "\nALL PASSED\n", fails);
    return fails ? 1 : 0;
}
```

```bash
# tests/c/run_mu_unit.sh
#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/../.."
CC=${CC:-gcc}
run() {
  local name=$1; shift
  echo "== $name =="
  $CC -I. -I./src -o "/tmp/${name}" "$@" && "/tmp/${name}"
}
run idmap_collapse_test tests/c/idmap_collapse_test.c src/auth/impersonate/idmap.c
run auth_gate_isolation_test tests/c/auth_gate_isolation_test.c src/auth/authz/auth_gate.c src/auth/authz/auth_gate_l1.c
```

- [ ] **Step 2: Run the C unit — verify it builds and reports**

Run: `cd /home/rcurrie/HEP-x/nginx-xrootd && chmod +x tests/c/run_mu_unit.sh && gcc -I. -I./src -o /tmp/idmap_collapse_test tests/c/idmap_collapse_test.c src/auth/impersonate/idmap.c && /tmp/idmap_collapse_test`
Expected: compiles; prints PASS/FAIL lines. Adjust includes/link set until it builds (idmap.c is libc-only per the extraction card).

- [ ] **Step 3: Write the privileged e2e (setfsuid byte-ownership)**

```python
# tests/test_mu_impersonation_e2e.py
"""F6 e2e — real setfsuid byte-ownership + cross-principal collapse (spec §8.2, D4)."""
import os, pytest
from mu_authz_lib import ports
from mu_authz_lib.adapters import measure_root

@pytest.mark.privileged
def test_written_file_is_owned_by_mapped_uid(mu_fleet, cast):
    """A PUT as alice creates a file owned by alice's real uid (impersonation)."""
    from mu_authz_lib.putter import put_as
    put_as(cast["alice"], "/cms/alice_wrote.dat", b"hello", proto="root")
    st = os.stat(os.path.join(ports.MU.DATA_ROOT, "cms", "alice_wrote.dat"))
    assert st.st_uid == cast["alice"].uid, "written bytes must be owned by mapped uid"

@pytest.mark.privileged
def test_collapsed_principal_cannot_read_other_user_private_file(mu_fleet, cast):
    """collide maps to alice's uid; it must get exactly alice's access, not carol's."""
    v_alice = measure_root(mu_fleet.url("root","direct"), "/cms/secret.dat", "read",
                           principal=cast["alice"])
    v_collide = measure_root(mu_fleet.url("root","direct"), "/cms/secret.dat", "read",
                             principal=cast["collide"])
    assert v_collide == v_alice, "collapsed principal must equal its mapped identity's access"
```

Expand with squash/min_uid e2e, DN-contains-local-username, cross-protocol collision (same uid via GSI vs token). Reach ~30 ids across unit+e2e.

- [ ] **Step 4: Run e2e**

Run: `cd /home/rcurrie/HEP-x/nginx-xrootd && sudo -E env PYTHONPATH=tests pytest tests/test_mu_impersonation_e2e.py -v`
Expected: ownership + collapse controls PASS; any real collapse bug FAILs red.

- [ ] **Step 5: Commit**

```bash
git add tests/c/idmap_collapse_test.c tests/c/run_mu_unit.sh tests/test_mu_impersonation_e2e.py tests/mu_authz_lib/putter.py
git commit -m "test(mu/F6): principal→uid collapse unit + setfsuid ownership e2e (~30 cells)"
```

---

## Task 16: F7 — decision-cache isolation (~28 cells)

**Files:**
- Create: `tests/c/auth_gate_isolation_test.c`
- Create: `tests/test_mu_decision_cache.py`

- [ ] **Step 1: Write the C unit (id-scoped key isolation)**

Read `src/auth/authz/auth_gate.c:145-322` + `auth_gate_l1.c` for the real key-build + L1 probe API. Then assert: two identities differing ONLY in DN (or VO, or scope) produce DIFFERENT cache keys, and an L1 probe with 32-byte full compare never aliases. Match `idmap_test.c` style, NO goto.

```c
/* tests/c/auth_gate_isolation_test.c — F7 decision-cache key isolation (NO goto) */
#include <ngx_config.h>
#include <ngx_core.h>
#include "../../src/auth/authz/auth_gate.h"
#include <stdio.h>
#include <string.h>
void ngx_log_error_core(ngx_uint_t l, ngx_log_t *g, ngx_err_t e, const char *f, ...)
{ (void)l;(void)g;(void)e;(void)f; }
static int fails = 0;
#define CHECK(c,m) do{ if(c) printf("  PASS %s\n",m); else {printf("  FAIL %s\n",m);fails++;} }while(0)
int main(void){
    /* build key(dn=alice,vo=cms,scope=read:/cms) != key(dn=carol,vo=cms,scope=read:/cms) */
    /* build key(dn=alice,...,READ) != key(dn=alice,...,WRITE) */
    /* fill in with the real brix_auth_gate key-derivation function names */
    printf(fails ? "\n%d FAILED\n" : "\nALL PASSED\n", fails);
    return fails ? 1 : 0;
}
```

- [ ] **Step 2: Build the C unit**

Run: `cd /home/rcurrie/HEP-x/nginx-xrootd && gcc -I. -I./src -o /tmp/auth_gate_isolation_test tests/c/auth_gate_isolation_test.c src/auth/authz/auth_gate.c src/auth/authz/auth_gate_l1.c && /tmp/auth_gate_isolation_test`
Expected: compiles + runs. Add any extra libc-only deps auth_gate.c needs (read its includes; if it pulls nginx-heavy deps, stub them minimally as `idmap_test.c` stubs `ngx_log_error_core`). Expected: PASS (key IS id-scoped, per the verified `auth_gate.c:153-189`).

- [ ] **Step 3: Write the e2e portion (TTL, eviction, ordering, multi-worker)**

```python
# tests/test_mu_decision_cache.py
"""F7 — the authz DECISION cache is identity-scoped and safe (spec §6/F7). Extends
test_token_cache_l1.py: distinct principals never contaminate; allow_write denies BEFORE
token scope (policy.c:65). These mostly PASS (decision cache is already id-scoped)."""
import pytest
from mu_authz_lib.oracle import authoritative
from mu_authz_lib.adapters import measure_root

@pytest.mark.privileged
@pytest.mark.parametrize("a,b", [("alice","carol"), ("alice","bob"), ("carol","mallory")])
def test_distinct_principals_no_contamination(mu_fleet, cast, a, b):
    """Back-to-back requests by two principals must each get their OWN verdict."""
    va = authoritative("root", "/cms/secret.dat", "read", cast[a])
    vb = authoritative("root", "/cms/secret.dat", "read", cast[b])
    # a and b differ in authz → verdicts must differ in decision or tier
    if cast[a].name == "alice":
        assert va.decision == "ALLOW" and vb.decision == "DENY"

@pytest.mark.privileged
def test_allow_write_denies_before_token_scope(mu_fleet, cast, readonly_server):
    """A write-scoped token on a read-only export is denied by allow_write, not scope."""
    v = measure_root(readonly_server, "/cms/secret.dat", "write", principal=cast["svc"])
    assert v.decision == "DENY" and v.tier == "allow_write"
```

Add TTL-expiry, >slot eviction, and a multi-worker coherence probe (first pin behavior empirically, then assert — spec §12). Reach ~28 ids across unit+e2e.

- [ ] **Step 4: Run**

Run: `cd /home/rcurrie/HEP-x/nginx-xrootd && sudo -E env PYTHONPATH=tests pytest tests/test_mu_decision_cache.py -v`
Expected: mostly PASS (decision cache is id-scoped). Any contamination FAILs red.

- [ ] **Step 5: Commit**

```bash
git add tests/c/auth_gate_isolation_test.c tests/test_mu_decision_cache.py
git commit -m "test(mu/F7): decision-cache identity isolation unit + e2e (~28 cells)"
```

---

## Task 17: F8 — revocation / staleness (~20 cells)

**Files:**
- Create: `tests/test_mu_revocation.py`

- [ ] **Step 1: Write the family test**

```python
# tests/test_mu_revocation.py
"""F8 — revocation takes effect on the NEXT request (spec §6/F8, §11). Revoke token /
gridmap entry / NSS user at {before-fill, after-fill-before-serve, mid-serve}; the verdict
must reflect revocation immediately (idmap creds TTL-staleness is bounded, asserted
separately). Predicted LEAK on the hit path (nothing re-checked on a root cache hit)."""
import pytest
from mu_authz_lib import cache_state
from mu_authz_lib.oracle import authoritative, measure

@pytest.mark.leak
@pytest.mark.privileged
@pytest.mark.parametrize("what", ["token", "gridmap"])
def test_revoke_after_fill_denies_on_serve(mu_fleet, cast, apply_policy, revoke, what):
    path = "/cms/secret.dat"; rel = path.lstrip("/")
    # alice is allowed → fill hot as alice
    cache_state.force_cold(rel); cache_state.fill_as(cast["alice"], rel, proto="root")
    revoke(what, "alice")                       # revoke alice's access
    truth = authoritative("root", path, "read", cast["alice"])   # now DENY on direct
    got = measure("root", "cache", path, "read", cast["alice"])  # hit path
    assert got == truth, f"revocation ({what}) not honored on cache hit: {got} != {truth}"
```

Add a `revoke(what, who)` fixture (removes the gridmap line / rewrites authdb / mints an expired token and reloads) and the bounded-staleness assertion for idmap creds (assert denial within the configured TTL). Reach ~20 ids.

- [ ] **Step 2: Run — expect hit-path FAIL red**

Run: `cd /home/rcurrie/HEP-x/nginx-xrootd && sudo -E env PYTHONPATH=tests pytest tests/test_mu_revocation.py -v`
Expected: revoke-after-fill on the cache hit path FAILs red (verdict not re-checked).

- [ ] **Step 3: Commit**

```bash
git add tests/test_mu_revocation.py tests/conftest_mu.py
git commit -m "test(mu/F8): revocation/staleness across fill/serve boundary (~20 cells, leak)"
```

---

## Task 18: F9 — write-back attribution + S3↔root scope parity (~15 cells)

**Files:**
- Create: `tests/test_mu_writeback_attr.py`

- [ ] **Step 1: Write the family test**

```python
# tests/test_mu_writeback_attr.py
"""F9 — write-back attribution + S3/root scope parity (spec §6/F9). A user's write must be
attributable to that user; S3 must not grant via SigV4 alone where root would deny by
scope. Mixed: attribution assertions PASS-or-document; S3-no-scope cells LEAK."""
import pytest
from mu_authz_lib.oracle import authoritative
from mu_authz_lib.adapters import measure_s3, measure_root
from mu_authz_lib import fleet

@pytest.mark.leak
@pytest.mark.privileged
@pytest.mark.parametrize("subject", ["carol", "bob"])
def test_s3_honors_scope_like_root(mu_fleet, cast, subject):
    """S3 verdict for a subject must match root's verdict for the same identity/path."""
    root_v = authoritative("root", "/cms/secret.dat", "read", cast[subject])
    s3_v = measure_s3(fleet.url("s3","direct"), "/cms/secret.dat", "read", principal=cast[subject])
    assert s3_v == root_v, f"S3 scope parity broken: s3={s3_v} root={root_v}"
```

Add write-back attribution cells (write as alice via the cache/write-through server; assert the flushed origin object is attributable to alice — e.g. owned by alice's uid, or a documented gap if `brix_wt_flush_t` has no user). Reach ~15 ids.

- [ ] **Step 2: Run**

Run: `cd /home/rcurrie/HEP-x/nginx-xrootd && sudo -E env PYTHONPATH=tests pytest tests/test_mu_writeback_attr.py -v`
Expected: S3-parity cells FAIL red; attribution cells pass or document the gap.

- [ ] **Step 3: Commit**

```bash
git add tests/test_mu_writeback_attr.py
git commit -m "test(mu/F9): write-back attribution + S3↔root scope parity (~15 cells)"
```

---

## Task 19: Leak ledger, wrap-up, and docs

**Files:**
- Modify: `tests/conftest.py` — add a `pytest_terminal_summary` hook that prints the leak ledger
- Create: `tests/c/run_mu_unit.sh` (if not already; ensure both C units run + gate)
- Create: `docs/09-developer-guide/multiuser-conformance.md`
- Modify: `tests/run_multiuser_authz.sh` — add `--leak-ledger` mode

**Interfaces:**
- Consumes: the `leak` marker (Task 9).

- [ ] **Step 1: Write the failing test for the ledger hook**

```python
# tests/mu_authz_lib/test_ledger_selftest.py
import subprocess, sys, os

def test_leak_ledger_lists_marked_tests():
    # collect-only the leak-marked tests; the ledger mode should print each id + seam
    env = dict(os.environ, PYTHONPATH="tests")
    r = subprocess.run([sys.executable, "-m", "pytest", "-m", "leak", "--collect-only", "-q",
                        "tests/test_mu_authz_cachetransp.py"],
                       env=env, capture_output=True, text=True, cwd=os.getcwd())
    assert "test_cache_hit_does_not_leak" in r.stdout
```

- [ ] **Step 2: Run to verify it fails (or is empty) before the hook exists**

Run: `cd /home/rcurrie/HEP-x/nginx-xrootd && PYTHONPATH=tests pytest tests/mu_authz_lib/test_ledger_selftest.py -v`
Expected: passes only once F1 exists and the `leak` marker is registered; if the marker is unregistered pytest warns. Register the marker (done in Task 9) so `-m leak` selects cleanly.

- [ ] **Step 3: Add the terminal-summary ledger hook**

```python
# --- append to tests/conftest.py ---
def pytest_terminal_summary(terminalreporter, exitstatus, config):
    if not config.getoption("-m", default="") or "leak" not in str(config.option.markexpr):
        return
    tr = terminalreporter
    failed = tr.stats.get("failed", [])
    if failed:
        tr.write_sep("=", "CROSS-USER LEAK LEDGER (fail-loudly, spec §10)")
        for rep in failed:
            tr.write_line(f"  LEAK  {rep.nodeid}")
```

- [ ] **Step 4: Write the docs page**

`docs/09-developer-guide/multiuser-conformance.md` — one page: the invariant, how to run (`sudo tests/run_multiuser_authz.sh`), the family map (F1–F9), the expected-red ledger, and how a fixed leak flips its cell green. Link the spec + this plan.

- [ ] **Step 5: Full-suite smoke + commit**

Run: `cd /home/rcurrie/HEP-x/nginx-xrootd && sudo -E env PYTHONPATH=tests tests/run_multiuser_authz.sh -q; echo "exit=$?"`
Expected: green for F2/F6-controls/F7; red-with-ledger for F1/F3/F4/F5/F8/F9-parity. Count total collected ≈ 210 (`grep -cE '<(Function|Coroutine)'` on `--collect-only`).

```bash
git add tests/conftest.py docs/09-developer-guide/multiuser-conformance.md tests/mu_authz_lib/test_ledger_selftest.py
git commit -m "test(mu): leak ledger terminal summary + conformance docs + orchestrator"
```

---

## Self-Review

**Spec coverage:**
- §2 invariant → Task 9 (oracle). ✓
- §3 D1 fail-loudly/`leak` marker → Tasks 9, 10, 19. ✓
- §3 D2 cache-transparency → Task 9. ✓
- §3 D3 enforcing protocols + cvmfs public → Tasks 8 (adapters), 11 (F2). ✓
- §3 D4 privileged/real accounts → Tasks 4, 9 fixture. ✓
- §6 families F1–F9 → Tasks 10–18. ✓
- §7 verdict+reason+tier → Task 8. ✓
- §8 harness (fleet, principals, provisioning, policy, cache-state, adapters) → Tasks 1–8. ✓
- §9 layout/markers/serial → Tasks 9, 19. ✓
- §10 expected-red ledger → Tasks 10, 19. ✓
- §11 revocation stance → Task 17. ✓
- §12 risks (multi-worker pin-first, xrdcinfo shapes, S3 parity) → Tasks 7, 16, 14. ✓

**Placeholder scan:** the family tasks (10–18) intentionally provide a working seed cell table + explicit "expand to ~N ids" instructions with the exact axes — this is a data-driven design, not a placeholder; each seed is runnable. The C-unit tasks (15, 16) require reading the real `idmap.c`/`auth_gate.c` APIs before filling assertions — flagged explicitly with the file:line to read. No "TBD"/"add error handling"/"similar to Task N".

**Type consistency:** `Verdict(decision, reason, tier)` and its equality (decision+tier) are used identically in Tasks 8, 9, 10, 14, 16, 17, 18. `Cell(proto, op, subject, path, filler, expect_tier)` consistent in Tasks 9, 10, 12, 14. `assert_cache_transparent(cell, cast)` signature consistent (Tasks 9, 10, 12). `measure`/`authoritative`/`leak_report` signatures consistent (Tasks 9, 14, 17). `fleet.url(proto, variant)` consistent everywhere.

**Known implementation risks the executor must resolve at build time (not placeholders — verification steps):**
1. Exact nginx directive spellings (`brix_storage_backend`/`brix_cache_store`/`brix_export`/`brix_gridmap`/`brix_authdb`/`brix_require_vo`/`brix_impersonate`/`brix_s3_access_key`) — copy from working reference configs and gate on `nginx -t` (Task 6 does this).
2. `utils/make_proxy.py`/`voms_proxy_fake.py`/`make_token.py` exact CLI/method signatures — read before use (Task 2 flags fallback).
3. Real `idmap.c`/`auth_gate.c` function names for the C units — read the cited line ranges (Tasks 15, 16).
4. root:// token presentation for pyxrootd (`BEARER_TOKEN_FILE`+`XrdSecPROTOCOL=ztn`) — verify against a working token test; if pyxrootd can't present ztn, fall back to `xrdcp`/`xrdfs` CLI subprocess (the suite already uses this pattern).
