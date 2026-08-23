"""Live krb5 GSSAPI origin-leg conformance (phase-70 §5.7).

forward.c's brix_krb5_deleg_to_origin() has always compiled, but nothing has
ever driven it against a real KDC. THIS suite closes that loop: it stands up a
fully *unprivileged* MIT Kerberos KDC (no root, no system krb5.conf) inside a
user namespace, mints three separate identities — a client user (alice), a
gateway service and an origin service — and then runs the PRODUCTION origin-leg
code AS alice against the origin, verifying an in-process GSSAPI acceptor keyed
by the origin keytab observes alice's identity on the far side.

Why user namespaces: `unshare -Ur` maps our unprivileged uid to root *inside*
the namespace so the KDC owns its database/keytabs/stash cleanly and the three
principals act as genuinely distinct accounts (distinct keytabs + ccaches),
all without touching the host or needing privilege. The KDC listens on a high
port in the shared network namespace, so the harness (run outside the ns) still
reaches it over localhost.

Ritual (success / origin-binding-neg / auth-precondition-neg):
  success   — alice → origin: the acceptor sees alice@REALM;
  security  — the same token offered to an acceptor holding the WRONG keytab
              (the gateway's, not the origin's) is refused — the token is bound
              to the origin principal, not universally acceptable;
  security  — a wrong client password never yields a credential at all.

Run (opt-out): runs by default when the krb5 tooling + built nginx objects are
present; force-skip with KRB5_LIVE=0. Docker-free, KDC-direct (no fleet server),
mirroring test_sts_minio_live.py / test_ceph_live.py — not a TEST_REGISTRY suite.
"""

from __future__ import annotations

import os
import shutil
import socket
import subprocess
import time
from pathlib import Path

import pytest

from cmdscripts.c_auth_units import NGX_SRC, OBJS
from cmdscripts.compile_run import REPO_ROOT, run
from settings import HOST         # env-overridable host (the sanctioned idiom)

def _expression_1(kdc):
    return (
        kdc.poll() is not None and kdc.stdout
    )


def _phase_krb5_lab_1(kdc):
    try:
        kdc.wait(timeout=5)
    except subprocess.TimeoutExpired:
        kdc.kill()


def _guard_krb5_lab_1():
    if os.environ.get("KRB5_LIVE") == "0":
        pytest.skip("KRB5_LIVE=0 set — skipping the live krb5 KDC lab")

def _guard_krb5_lab_2(reason):
    if reason:
        pytest.skip(reason)

def _guard_krb5_lab_3():
    if not _userns_works():
        pytest.skip("unprivileged user namespaces (unshare -Ur) unavailable")

def _guard_krb5_lab_4():
    if _port_open(KDC_PORT):
        pytest.skip(f"port {KDC_PORT} already in use — a KDC may be running")

def _guard_krb5_lab_5(harness, hreason):
    if harness is None:
        pytest.skip(hreason)

def _guard_krb5_lab_6(prov):
    if prov.returncode != 0:
        pytest.skip(f"KDC provisioning failed: {(prov.stderr or prov.stdout)[-2000:]}")


pytestmark = pytest.mark.timeout(300)

REALM = "BRIX.TEST"
KDC_PORT = 18800                    # fixed, high, unprivileged (KDC-direct)
MASTER_PW = "brix-kdc-master-pw"
ALICE = f"alice@{REALM}"
ALICE_PW = "alice-fixture-pw-1234"
BAD_PW = "wrong-password-xxxxxxxxxxxx"
ORIGIN_PRINC = f"host/origin.brix.test@{REALM}"
GATEWAY_PRINC = f"xrootd/gateway.brix.test@{REALM}"

KRB5_TOOLS = ("krb5kdc", "kadmin.local", "kdb5_util", "unshare")


# ---- environment probes ---------------------------------------------------

def _which(name: str) -> str | None:
    # KDC binaries commonly live in sbin, which may be off a login PATH.
    return shutil.which(name) or shutil.which(name, path="/usr/sbin:/sbin:/usr/local/sbin")


def _tools_present() -> str | None:
    missing = [t for t in KRB5_TOOLS if _which(t) is None]
    return None if not missing else "missing krb5 tooling: " + " ".join(missing)


def _userns_works() -> bool:
    return run(["unshare", "-Ur", "true"]).returncode == 0


def _port_open(port: int) -> bool:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(0.5)
        return s.connect_ex((HOST, port)) == 0


# ---- lab config -----------------------------------------------------------

def _write_configs(lab: Path) -> dict[str, str]:
    krb5_conf = lab / "krb5.conf"
    kdc_conf = lab / "kdc.conf"
    krb5_conf.write_text(
        "[libdefaults]\n"
        f"    default_realm = {REALM}\n"
        "    dns_lookup_kdc = false\n"
        "    dns_lookup_realm = false\n"
        "    rdns = false\n"
        "    forwardable = true\n"
        "    udp_preference_limit = 1\n"
        "\n"
        "[realms]\n"
        f"    {REALM} = {{\n"
        f"        kdc = {HOST}:{KDC_PORT}\n"
        f"    }}\n"
        "\n"
        "[domain_realm]\n"
        f"    .brix.test = {REALM}\n"
        f"    brix.test = {REALM}\n"
    )
    kdc_conf.write_text(
        "[kdcdefaults]\n"
        f"    kdc_ports = {KDC_PORT}\n"
        f"    kdc_tcp_ports = {KDC_PORT}\n"
        "\n"
        "[realms]\n"
        f"    {REALM} = {{\n"
        f"        database_name = {lab}/principal\n"
        f"        key_stash_file = {lab}/.k5.{REALM}\n"
        f"        acl_file = {lab}/kadm5.acl\n"
        "        supported_enctypes = aes256-cts-hmac-sha1-96:normal "
        "aes128-cts-hmac-sha1-96:normal\n"
        "        max_life = 10h 0m 0s\n"
        "        max_renewable_life = 7d 0h 0m 0s\n"
        f"    }}\n"
    )
    (lab / "kadm5.acl").write_text("")
    return {
        "KRB5_CONFIG": str(krb5_conf),
        "KRB5_KDC_PROFILE": str(kdc_conf),
        "TMPDIR": "/tmp",
    }


def _provision(lab: Path, env: dict[str, str]) -> subprocess.CompletedProcess:
    """Create the KDC database and the three principals, unprivileged, inside a
    user namespace (uid → root). Runs to completion before the KDC boots."""
    kdb5_util = _which("kdb5_util")
    kadmin = _which("kadmin.local")
    origin_kt = lab / "origin.keytab"
    gateway_kt = lab / "gateway.keytab"
    script = "\n".join([
        "set -e",
        f'"{kdb5_util}" create -s -r {REALM} -P "{MASTER_PW}"',
        f'"{kadmin}" -r {REALM} -q "addprinc -pw {ALICE_PW} alice"',
        f'"{kadmin}" -r {REALM} -q "addprinc -randkey host/origin.brix.test"',
        f'"{kadmin}" -r {REALM} -q "addprinc -randkey xrootd/gateway.brix.test"',
        f'"{kadmin}" -r {REALM} -q "ktadd -k {origin_kt} host/origin.brix.test"',
        f'"{kadmin}" -r {REALM} -q "ktadd -k {gateway_kt} xrootd/gateway.brix.test"',
    ])
    return run(["unshare", "-Ur", "bash", "-c", script], env=env)


def _boot_kdc(env: dict[str, str]) -> subprocess.Popen:
    krb5kdc = _which("krb5kdc")
    return subprocess.Popen(
        ["unshare", "-Ur", "--kill-child", krb5kdc, "-n"],
        cwd=str(REPO_ROOT),
        env={**os.environ, **env},
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )


# ---- harness build --------------------------------------------------------

def _krb5_config(args: list[str], fallback: list[str]) -> list[str]:
    tool = _which("krb5-config")
    if tool is None:
        return fallback
    proc = run([tool, *args])
    return proc.stdout.split() if proc.returncode == 0 else fallback


def _krb5_obj(name: str) -> Path | None:
    # Some basenames exist under multiple modules (e.g. cms/forward.o); find_obj's
    # sort would pick the wrong one. Select the krb5-module object explicitly.
    matches = [p for p in (OBJS / "addon").rglob(name) if "krb5" in p.parts]
    return matches[0] if matches else None


def _build_harness(dst: Path) -> tuple[Path | None, str]:
    forward = _krb5_obj("forward.o")
    capture = _krb5_obj("capture.o")   # production round-2 capture (rebuild first)
    kxr = _krb5_obj("kxr_wire.o")      # production kXR krb5 wire codec (§5.7)
    carry = _krb5_obj("carry.o")       # production async-safe FILE-ccache carry (§5.7)
    apreq = _krb5_obj("apreq.o")       # production raw-krb5 outbound AP-REQ builder
    missing = [n for n, o in (("forward.o", forward), ("capture.o", capture),
                              ("kxr_wire.o", kxr), ("carry.o", carry),
                              ("apreq.o", apreq)) if o is None]
    if missing:
        return None, "build nginx first (missing krb5/" + ", ".join(missing) + ")"
    binary = dst / "krb5_forward_live"
    cmd = [
        "gcc", "-O", "-Wall",
        "-I", "src",
        "-I", str(NGX_SRC / "src/core"),
        "-I", str(NGX_SRC / "src/event"),
        "-I", str(NGX_SRC / "src/os/unix"),
        "-I", str(NGX_SRC / "src/stream"),
        "-I", str(OBJS),
        *_krb5_config(["--cflags", "gssapi"], []),
        "tests/c/krb5_forward_live.c",
        str(forward),
        str(capture),
        str(kxr),
        str(carry),
        str(apreq),
        *_krb5_config(["--libs", "gssapi"],
                      ["-lgssapi_krb5", "-lkrb5", "-lk5crypto", "-lcom_err"]),
        "-lpthread",
        "-o", str(binary),
    ]
    built = run(cmd, cwd=REPO_ROOT, env={"TMPDIR": "/tmp"})
    if built.returncode != 0:
        return None, f"harness compile failed: {(built.stderr or built.stdout)[-2000:]}"
    return binary, ""


# ---- lab fixture ----------------------------------------------------------

@pytest.fixture(scope="module")
def krb5_lab(tmp_path_factory):
    _guard_krb5_lab_1()
    reason = _tools_present()
    _guard_krb5_lab_2(reason)
    _guard_krb5_lab_3()
    _guard_krb5_lab_4()

    lab = tmp_path_factory.mktemp("krb5_lab")
    harness, hreason = _build_harness(lab)
    _guard_krb5_lab_5(harness, hreason)

    env = _write_configs(lab)
    prov = _provision(lab, env)
    _guard_krb5_lab_6(prov)

    kdc = _boot_kdc(env)
    try:
        healthy = False
        for _ in range(60):
            if kdc.poll() is not None:
                break
            if _port_open(KDC_PORT):
                healthy = True
                break
            time.sleep(0.25)
        if not healthy:
            out = ""
            if _expression_1(kdc):
                out = kdc.stdout.read()[-2000:]
            pytest.skip(f"KDC never came up on {KDC_PORT}: {out}")

        yield {
            "harness": harness,
            "lab": lab,
            "env": env,
            "origin_keytab": lab / "origin.keytab",
            "gateway_keytab": lab / "gateway.keytab",
        }
    finally:
        kdc.terminate()
        _phase_krb5_lab_1(kdc)


def _forward(lab: dict, keytab: Path, password: str,
             origin: str = ORIGIN_PRINC,
             mode: str = "origin") -> subprocess.CompletedProcess:
    env = {**lab["env"], "KRB5_KTNAME": str(keytab)}
    return run([str(lab["harness"]), ALICE, password, origin, mode], env=env)


# ---- tests ----------------------------------------------------------------

def test_krb5_forward_origin_leg_carries_user_identity(krb5_lab):
    """Production brix_krb5_deleg_to_origin() acts AS alice: the origin's own
    acceptor decrypts the first-leg token and sees alice@REALM."""
    proc = _forward(krb5_lab, krb5_lab["origin_keytab"], ALICE_PW)
    assert proc.returncode == 0, f"origin leg failed: {proc.stdout}{proc.stderr}"
    name = proc.stdout.strip()
    assert name == ALICE, f"acceptor observed {name!r}, expected {ALICE!r}"


def test_krb5_forward_token_bound_to_origin_principal(krb5_lab):
    """Security-negative: the first-leg token is a service ticket for the origin
    principal. An acceptor holding the WRONG keytab (the gateway's) cannot
    decrypt it — so the exchange fails closed with no identity leaked."""
    proc = _forward(krb5_lab, krb5_lab["gateway_keytab"], ALICE_PW)
    assert proc.returncode != 0, "wrong-keytab acceptor unexpectedly accepted"
    assert ALICE not in proc.stdout, "no identity must leak on a failed accept"


def test_krb5_forward_wrong_password_yields_no_credential(krb5_lab):
    """Security-negative: a bad client password fails the AS exchange, so no
    forwardable credential is ever acquired and the origin leg never runs."""
    proc = _forward(krb5_lab, krb5_lab["origin_keytab"], BAD_PW)
    assert proc.returncode != 0, "AS-REQ with a wrong password unexpectedly OK"
    assert ALICE not in proc.stdout, "no identity must leak on AS failure"


def test_krb5_capture_forwarded_tgt_carries_user_identity(krb5_lab):
    """The full EXCHANGE crux: alice's TGT is forwarded into a KRB_CRED exactly as
    the XrdSeckrb5 client sends after the "fwdtgt" challenge, the PRODUCTION
    brix_krb5_capture_fwd_cred() decrypts+imports it, and the resulting delegated
    cred drives the origin leg — the origin's acceptor still sees alice@REALM."""
    proc = _forward(krb5_lab, krb5_lab["origin_keytab"], ALICE_PW, mode="capture")
    assert proc.returncode == 0, f"capture path failed: {proc.stdout}{proc.stderr}"
    name = proc.stdout.strip()
    assert name == ALICE, f"acceptor observed {name!r}, expected {ALICE!r}"


# ---- multi-leg negotiation engine (brix_krb5_deleg_negotiate) -------------

def test_krb5_negotiate_multileg_completes_carrying_user_identity(krb5_lab):
    """The production multi-leg engine brix_krb5_deleg_negotiate() drives the
    WHOLE GSSAPI loop to GSS_S_COMPLETE against the origin's acceptor: every
    initiator token is delivered, the acceptor's AP-REP is fed back through
    gss_init_sec_context, mutual auth is verified, and the established context
    round-trips a confidential gss_wrap/gss_unwrap probe — all AS alice@REALM."""
    proc = _forward(krb5_lab, krb5_lab["origin_keytab"], ALICE_PW, mode="negotiate")
    assert proc.returncode == 0, f"negotiate failed: {proc.stdout}{proc.stderr}"
    name = proc.stdout.strip()
    assert name == ALICE, f"acceptor observed {name!r}, expected {ALICE!r}"


def test_krb5_negotiate_wrong_keytab_origin_fails_closed(krb5_lab):
    """Security-negative: the engine drives against an acceptor holding the WRONG
    keytab (the gateway's). gss_accept_sec_context cannot decrypt the initiator's
    service ticket, the wire callback returns an error, and the engine fails
    closed — no completion, no identity leaked."""
    proc = _forward(krb5_lab, krb5_lab["gateway_keytab"], ALICE_PW, mode="negotiate")
    assert proc.returncode != 0, "negotiate against wrong-keytab origin must fail"
    assert ALICE not in proc.stdout, "no identity must leak on a failed negotiation"


def test_krb5_negotiate_wrong_password_yields_no_credential(krb5_lab):
    """Security-negative: a bad client password fails the AS exchange, so no
    forwardable credential exists and the multi-leg engine is never entered."""
    proc = _forward(krb5_lab, krb5_lab["origin_keytab"], BAD_PW, mode="negotiate")
    assert proc.returncode != 0, "negotiate with a wrong password unexpectedly OK"
    assert ALICE not in proc.stdout, "no identity must leak on AS failure"


# ---- kXR origin-leg wire codec (brix_krb5_kxr_wire + origin_auth.c) --------
# The production codec that origin_auth.c's brix_cache_origin_auth_krb5() uses,
# driven over a REAL socket against a kXR-framed acceptor: the exact
# ClientAuthRequest / ServerResponseHeader (kXR_auth/kXR_authmore/kXR_ok) bytes
# the origin leg emits are exchanged, not just in-memory GSS tokens.

def test_krb5_kxr_classify_reply_status_branches(krb5_lab):
    """Unit: the pure reply classifier maps kXR_authmore→continue, kXR_ok→settle,
    and kXR_error / any unexpected status→fail-closed. No KDC or creds needed."""
    env = {**krb5_lab["env"]}
    proc = run([str(krb5_lab["harness"]), ALICE, ALICE_PW, ORIGIN_PRINC,
                "classify"], env=env)
    assert proc.returncode == 0, f"classify selftest failed: {proc.stdout}{proc.stderr}"
    assert proc.stdout.strip() == "classify-ok"


def test_krb5_kxrwire_multileg_over_frames_carries_user_identity(krb5_lab):
    """The production kXR wire codec brix_krb5_kxr_wire() frames every initiator
    token as a kXR_auth("krb5") request and feeds the origin's kXR_authmore reply
    back through the multi-leg engine until kXR_ok — over a real socket against a
    kXR-framed GSSAPI acceptor. The whole exchange settles with mutual auth and
    the acceptor observes alice@REALM: the exact bytes origin_auth.c sends."""
    proc = _forward(krb5_lab, krb5_lab["origin_keytab"], ALICE_PW, mode="kxrwire")
    assert proc.returncode == 0, f"kxrwire failed: {proc.stdout}{proc.stderr}"
    name = proc.stdout.strip()
    assert name == ALICE, f"acceptor observed {name!r}, expected {ALICE!r}"


def test_krb5_kxrwire_wrong_keytab_origin_fails_closed(krb5_lab):
    """Security-negative: the kXR-framed acceptor holds the WRONG keytab, so
    gss_accept_sec_context fails; it replies kXR_error, the codec classifies it as
    a rejecting origin and the engine fails closed — no completion, no leak."""
    proc = _forward(krb5_lab, krb5_lab["gateway_keytab"], ALICE_PW, mode="kxrwire")
    assert proc.returncode != 0, "kxrwire against wrong-keytab origin must fail"
    assert ALICE not in proc.stdout, "no identity must leak on a rejected exchange"


def test_krb5_kxrwire_wrong_password_yields_no_credential(krb5_lab):
    """Security-negative: a bad client password fails the AS exchange up front, so
    the kXR wire loop is never entered and no identity is produced."""
    proc = _forward(krb5_lab, krb5_lab["origin_keytab"], BAD_PW, mode="kxrwire")
    assert proc.returncode != 0, "kxrwire with a wrong password unexpectedly OK"
    assert ALICE not in proc.stdout, "no identity must leak on AS failure"


def test_krb5_carry_ccache_roundtrip_preserves_delegated_identity(krb5_lab):
    """The async-safe carry (phase-70 §5.7 item ii): a request-scoped delegated
    gss_cred_id_t cannot ride the async brix_cache_fill_t, so brix_krb5_cred_to_ccache
    serialises it to a 0600 FILE ccache (path = the async-safe artifact, mirroring the
    gsi proxy-PEM→0600-path trick) and brix_krb5_cred_from_ccache re-acquires it on a
    FRESH handle. Driving the SAME production kXR multi-leg engine with the
    RE-IMPORTED cred still settles with mutual auth and the acceptor observes
    alice@REALM — proving the round-tripped credential is functionally identical."""
    proc = _forward(krb5_lab, krb5_lab["origin_keytab"], ALICE_PW, mode="carry")
    assert proc.returncode == 0, f"carry roundtrip failed: {proc.stdout}{proc.stderr}"
    name = proc.stdout.strip()
    assert name == ALICE, f"acceptor observed {name!r}, expected {ALICE!r}"


def test_krb5_carry_from_missing_ccache_fails_closed(krb5_lab):
    """Security/robustness-negative: importing from a non-existent ccache path must
    fail closed (no cred, no identity) rather than silently produce a usable
    credential. Uses the capture path to obtain a real delegated cred first, then
    the harness points the import at a bogus path (mode carry-badpath)."""
    proc = _forward(krb5_lab, krb5_lab["origin_keytab"], ALICE_PW,
                    mode="carry-badpath")
    assert proc.returncode != 0, "import from a missing ccache unexpectedly OK"
    assert ALICE not in proc.stdout, "no identity must leak on a failed import"


# ---- raw-krb5 OUTBOUND leg (brix_krb5_apreq_from_ccache) -------------------

def test_krb5_apreq_raw_leg_carries_user_identity(krb5_lab):
    """The raw-krb5 outbound leg — the dialect real "&P=krb5" origins accept.
    The PRODUCTION builder brix_krb5_apreq_from_ccache() reads alice's delegated
    TGT from a FILE ccache (the carry artifact) and produces the "krb5\\0"+AP-REQ
    the outbound origin leg (origin_auth.c brix_cache_origin_auth_krb5_raw) sends.
    Verified EXACTLY as a stock XRootD (libXrdSeckrb5) acceptor does — krb5_rd_req
    against the origin keytab — the ticket decrypts and the authenticated client is
    alice@REALM. This is what the GSSAPI engine could NOT do: a raw AP-REQ, not a
    gss_init_sec_context token."""
    proc = _forward(krb5_lab, krb5_lab["origin_keytab"], ALICE_PW, mode="apreq")
    assert proc.returncode == 0, f"apreq raw leg failed: {proc.stdout}{proc.stderr}"
    name = proc.stdout.strip()
    assert name == ALICE, f"acceptor observed {name!r}, expected {ALICE!r}"


def test_krb5_apreq_bound_to_origin_principal(krb5_lab):
    """Security-negative: the AP-REQ is a service ticket for the ORIGIN principal,
    encrypted under the origin's key. An acceptor holding the WRONG keytab (the
    gateway's) cannot krb5_rd_req it — so the raw leg fails closed with no identity
    leaked, exactly as a rejecting origin would."""
    proc = _forward(krb5_lab, krb5_lab["gateway_keytab"], ALICE_PW, mode="apreq")
    assert proc.returncode != 0, "wrong-keytab acceptor unexpectedly accepted"
    assert ALICE not in proc.stdout, "no identity must leak on a failed accept"


def test_krb5_apreq_wrong_password_yields_no_credential(krb5_lab):
    """Security-negative: a bad client password fails the AS exchange up front, so
    no TGT is ever acquired and the raw AP-REQ builder never runs."""
    proc = _forward(krb5_lab, krb5_lab["origin_keytab"], BAD_PW, mode="apreq")
    assert proc.returncode != 0, "apreq with a wrong password unexpectedly OK"
    assert ALICE not in proc.stdout, "no identity must leak on AS failure"
