"""Python ports for auth-oriented C shell runners."""

from __future__ import annotations

from pathlib import Path
import os
import shutil
import tempfile

from cmdscripts.compile_run import REPO_ROOT, result, run

NGX_SRC = Path(os.environ.get(
    "NGX_SRC",
    "/tmp/nginx-1.28.3" if Path("/tmp/nginx-1.28.3/src/core/ngx_config.h").exists()
    else "/tmp/nginx-1.24.0",
))
OBJS = NGX_SRC / "objs"


def run_gsi_eec(base: Path) -> list[tuple[bool, str]]:
    if shutil.which("openssl") is None:
        return [result(True, "SKIP openssl not on PATH")]
    obj = find_obj("gsi_verify.o")
    if obj is None:
        return [result(True, "SKIP build gsi_verify.o first")]
    fixtures, owned = x509_fixture_dir("gsi_eec")
    try:
        forged = run(
            ["python3", "-c", GSI_EEC_FORGE, str(fixtures)],
            cwd=REPO_ROOT,
            env={"PYTHONPATH": "tests", **HERMETIC_ENV},
        )
        if forged.returncode != 0:
            return [result(False, f"forge gsi_eec fixtures failed: {(forged.stderr or forged.stdout)[-3000:]}")]
        ok, message = compile_and_run(
            base / "test_gsi_eec",
            [
                "-O",
                "-Wall",
                "-I",
                "src",
                "-I",
                "shared",
                "-I",
                str(NGX_SRC / "src/core"),
                "-I",
                str(NGX_SRC / "src/event"),
                "-I",
                str(NGX_SRC / "src/os/unix"),
                "-I",
                str(OBJS),
                "tests/c/gsi_eec_test.c",
                str(obj),
                *X509_POLICY_SOURCES,
                "-lssl",
                "-lcrypto",
            ],
            env={"BRIX_GSI_EEC_FIXTURES": str(fixtures)},
        )
        return [result(ok, f"gsi_eec {message}")]
    finally:
        if owned:
            shutil.rmtree(owned, ignore_errors=True)


# Forge the delegation EEC-scan corpus (Finding 1, gsi-delegation-xrdhttp): one
# CA -> EEC -> two proxies with distinct serials. The EEC is the non-proxy the
# scan must recover; the proxies are what it must skip and never return.
DELEG_FIND_EEC_FORGE = """
import pathlib, sys
import x509forge

d = pathlib.Path(sys.argv[1])
ca = x509forge.make_ca("/DC=test/CN=Deleg EEC Scan CA")
eec = x509forge.make_eec(ca, "/DC=test/CN=alice", not_after_days=4000)
proxy = x509forge.make_proxy(eec, not_after_days=4000, serial=200001)
proxy2 = x509forge.make_proxy(eec, not_after_days=4000, serial=200002)
(d / "ca.pem").write_bytes(ca.pem)
(d / "eec.pem").write_bytes(eec.pem)
(d / "proxy.pem").write_bytes(proxy.pem)
(d / "proxy2.pem").write_bytes(proxy2.pem)
"""


def run_deleg_find_eec(base: Path) -> list[tuple[bool, str]]:
    """Finding 1 primitive: delegation_find_eec() recovers the EEC from a proxy
    chain (success), fails closed on an empty/NULL chain (error), and never
    returns a proxy in the EEC's place (security-negative). Links the REAL
    delegation.o so a file-split or behavioral regression there fails here."""
    if shutil.which("openssl") is None:
        return [result(True, "SKIP openssl not on PATH")]
    # find_obj("delegation.o") is AMBIGUOUS — there is also addon/gsi/delegation.o
    # (the root:// GSI leg), which holds no delegation_find_eec. Resolve the
    # webdav TU explicitly so the link never silently grabs the wrong object.
    obj = next(iter(sorted((OBJS / "addon" / "webdav").rglob("delegation.o"))), None)
    if obj is None:
        return [result(True, "SKIP build src/protocols/webdav/delegation.o first")]
    fixtures, owned = x509_fixture_dir("deleg_find_eec")
    try:
        forged = run(
            ["python3", "-c", DELEG_FIND_EEC_FORGE, str(fixtures)],
            cwd=REPO_ROOT,
            env={"PYTHONPATH": "tests", **HERMETIC_ENV},
        )
        if forged.returncode != 0:
            return [result(False, f"forge deleg_find_eec fixtures failed: {(forged.stderr or forged.stdout)[-3000:]}")]
        ok, message = compile_and_run(
            base / "test_deleg_find_eec",
            [
                "-O",
                "-Wall",
                "-I",
                "src",
                "-I",
                "shared",
                "-I",
                str(NGX_SRC / "src/core"),
                "-I",
                str(NGX_SRC / "src/event"),
                "-I",
                str(NGX_SRC / "src/os/unix"),
                "-I",
                str(OBJS),
                "tests/c/deleg_find_eec_test.c",
                str(obj),
                *X509_POLICY_SOURCES,
                "-lssl",
                "-lcrypto",
            ],
            env={"BRIX_DELEG_FIND_EEC_FIXTURES": str(fixtures)},
        )
        return [result(ok, f"deleg_find_eec {message}")]
    finally:
        if owned:
            shutil.rmtree(owned, ignore_errors=True)


# Shared link recipe for the two P90-70.9 token-gate units: the harness TU +
# the real module objects; json.o drags in jansson, b64url/crypto need OpenSSL.
def _run_token_unit(base: Path, name: str, harness: str,
                    needed: list[str]) -> list[tuple[bool, str]]:
    objs = [find_obj(n) for n in needed]
    missing = [n for n, o in zip(needed, objs) if o is None]
    if missing:
        return [result(True, f"SKIP build {' '.join(missing)} first")]
    ok, message = compile_and_run(
        base / f"test_{name}",
        [
            "-O",
            "-Wall",
            "-I",
            "src",
            "-I",
            str(NGX_SRC / "src/core"),
            "-I",
            str(NGX_SRC / "src/event"),
            "-I",
            str(NGX_SRC / "src/os/unix"),
            "-I",
            str(OBJS),
            harness,
            *[str(o) for o in objs],
            "-ljansson",
            "-lcrypto",
        ],
    )
    return [result(ok, f"{name} {message}")]


def run_protbind(base: Path) -> list[tuple[bool, str]]:
    """The per-host auth-protocol binding engine (XRootD sec.protbind): host
    template matching, base sets, rule resolution and the membership gate that
    admits a credential.  Objects are named by their FULL addon path — both
    `policy.o` and `match.o` collide with same-named objects elsewhere in the
    tree, so find_obj()'s first-match would link the wrong translation unit."""
    objs = [OBJS / "addon/protbind/match.o", OBJS / "addon/protbind/policy.o"]
    missing = [str(o) for o in objs if not o.exists()]
    if missing:
        return [result(True, f"SKIP build {' '.join(missing)} first")]
    ngx_string = OBJS / "src/core/ngx_string.o"
    if not ngx_string.exists():
        return [result(True, "SKIP build nginx (ngx_string.o) first")]
    ok, message = compile_and_run(
        base / "test_protbind",
        [
            "-O",
            "-Wall",
            "-I",
            "src",
            "-I",
            str(NGX_SRC / "src/core"),
            "-I",
            str(NGX_SRC / "src/event"),
            "-I",
            str(NGX_SRC / "src/os/unix"),
            "-I",
            str(OBJS),
            "tests/c/protbind_test.c",
            *[str(o) for o in objs],
            str(ngx_string),
            "-lcrypto",
        ],
    )
    return [result(ok, f"protbind {message}")]


def run_sts_units(base: Path) -> list[tuple[bool, str]]:
    """Exercise the S3 STS seam (phase-70 §5.5): the real sts_http.o parser +
    sts_sign.o SigV4 builder, linked against the production ngx_snprintf and
    crypto. Needs libxml2/libcurl (transport TU) and OpenSSL (signer)."""
    needed = ["sts_http.o", "sts_sign.o", "crypto.o", "sigv4.o"]
    objs = [find_obj(n) for n in needed]
    missing = [n for n, o in zip(needed, objs) if o is None]
    if missing:
        return [result(True, f"SKIP build {' '.join(missing)} first")]
    ngx_string = OBJS / "src/core/ngx_string.o"
    if not ngx_string.exists():
        return [result(True, "SKIP build nginx (ngx_string.o) first")]
    ok, message = compile_and_run(
        base / "test_sts_units",
        [
            "-O",
            "-Wall",
            "-I",
            "src",
            "-I",
            str(NGX_SRC / "src/core"),
            "-I",
            str(NGX_SRC / "src/event"),
            "-I",
            str(NGX_SRC / "src/os/unix"),
            "-I",
            str(OBJS),
            *pkg_config(["--cflags", "libxml-2.0"]),
            "tests/c/sts_units_test.c",
            *[str(o) for o in objs],
            str(ngx_string),
            *pkg_config(["--libs", "libxml-2.0"], ["-lxml2"]),
            *pkg_config(["--libs", "libcurl"], ["-lcurl"]),
            "-lcrypto",
        ],
    )
    return [result(ok, f"sts_units {message}")]


def run_aud_match(base: Path) -> list[tuple[bool, str]]:
    return _run_token_unit(base, "aud_match", "tests/c/aud_match_test.c",
                           ["aud_match.o", "b64url.o", "json.o"])


def run_exchange_cache(base: Path) -> list[tuple[bool, str]]:
    return _run_token_unit(base, "exchange_cache",
                           "tests/c/exchange_cache_test.c",
                           ["exchange_cache.o", "b64url.o", "json.o",
                            "crypto.o"])


def run_exchange(base: Path) -> list[tuple[bool, str]]:
    """RFC 8693 token-exchange client `brix_token_exchange` (exchange.o), plan
    W3.8. Links the real object (its only non-libc deps are ngx_pnalloc +
    ngx_log_error_core, stubbed in the harness) with libcurl + jansson, and
    drives the entry-guards, the RFC-8693 body build, the https-only pin, and
    the connect-fail error map against a closed loopback port — no live server.
    Now that tests/c gcda is captured (the cred_mint link-flag fix), this moves
    exchange.c off 0% in the coverage lane, not just a separate binary."""
    obj = find_obj("exchange.o")
    if obj is None:
        return [result(True, "SKIP build exchange.o first")]
    ok, message = compile_and_run(
        base / "test_exchange",
        [
            "-O",
            "-Wall",
            "-I",
            "src",
            "-I",
            str(NGX_SRC / "src/core"),
            "-I",
            str(NGX_SRC / "src/event"),
            "-I",
            str(NGX_SRC / "src/os/unix"),
            "-I",
            str(OBJS),
            "tests/c/exchange_test.c",
            str(obj),
            *pkg_config(["--libs", "libcurl"], ["-lcurl"]),
            "-ljansson",
        ],
    )
    return [result(ok, f"exchange {message}")]


# Forge the TPC delegated-proxy expiry corpus (phase-58 §5.8): the leaf proxy
# whose lifetime brix_tpc_proxy_pem_expired() inspects. The forge epoch is FIXED
# at 2026-01-01, so a 1-day window is already expired in real time (the "refuse"
# case), while a far-future window stays valid.
TPC_EXPIRY_FORGE = """
import pathlib, sys
import x509forge

d = pathlib.Path(sys.argv[1])
ca = x509forge.make_ca("/DC=test/CN=TPC Expiry CA")

# Expired: EEC + proxy pinned to a 1-day window off the 2026-01-01 epoch.
exp_eec = x509forge.make_eec(ca, "/DC=test/CN=alice", not_after_days=1)
exp_proxy = x509forge.make_proxy(exp_eec, not_after_days=1)
(d / "expired.pem").write_bytes(exp_proxy.pem)

# Valid: a far-future window clears real time by years.
ok_eec = x509forge.make_eec(ca, "/DC=test/CN=alice", not_after_days=4000)
ok_proxy = x509forge.make_proxy(ok_eec, not_after_days=4000)
(d / "valid.pem").write_bytes(ok_proxy.pem)

(d / "garbage.pem").write_bytes(b"this is not a pem credential\\n")
"""


def run_tpc_proxy_expiry(base: Path) -> list[tuple[bool, str]]:
    if shutil.which("openssl") is None:
        return [result(True, "SKIP openssl not on PATH")]
    obj = find_obj("credential.o")
    if obj is None:
        return [result(True, "SKIP build credential.o first")]
    fixtures, owned = x509_fixture_dir("tpc_expiry")
    try:
        forged = run(
            ["python3", "-c", TPC_EXPIRY_FORGE, str(fixtures)],
            cwd=REPO_ROOT,
            env={"PYTHONPATH": "tests", **HERMETIC_ENV},
        )
        if forged.returncode != 0:
            return [result(False, f"forge tpc expiry fixtures failed: {(forged.stderr or forged.stdout)[-3000:]}")]
        ok, message = compile_and_run(
            base / "test_tpc_proxy_expiry",
            [
                "-O",
                "-Wall",
                "-I",
                "src",
                "-I",
                str(NGX_SRC / "src/core"),
                "-I",
                str(NGX_SRC / "src/event"),
                "-I",
                str(NGX_SRC / "src/os/unix"),
                "-I",
                str(OBJS),
                "tests/c/tpc_proxy_expiry_test.c",
                str(obj),
                *pkg_config(["--libs", "openssl"], ["-lssl", "-lcrypto"]),
            ],
            env={"BRIX_TPC_EXPIRY_FIXTURES": str(fixtures)},
        )
        return [result(ok, f"tpc_proxy_expiry {message}")]
    finally:
        if owned:
            shutil.rmtree(owned, ignore_errors=True)


def run_origin_krb5_dispatch(base: Path) -> list[tuple[bool, str]]:
    """Phase-70 §5.7 krb5 origin-dispatch wiring in origin_protocol_bootstrap.c.

    Self-contained: the harness #includes the TU under test and stubs its whole
    external surface (origin wire I/O, the four auth legs, and the RAW krb5
    outbound leg brix_cache_origin_auth_krb5_raw), so NO project objects, krb5, or
    OpenSSL are linked. Compiled with -DBRIX_HAVE_KRB5=1 so the real krb5 dispatch
    branch runs against the stubs.
    """
    ok, message = compile_and_run(
        base / "origin_krb5_dispatch",
        [
            "-O",
            "-Wall",
            "-Werror",
            "-DBRIX_HAVE_KRB5=1",
            "-I", "src",
            "-I", "shared",
            "-I", str(NGX_SRC / "src/core"),
            "-I", str(NGX_SRC / "src/event"),
            "-I", str(NGX_SRC / "src/os/unix"),
            "-I", str(NGX_SRC / "src/stream"),
            "-I", str(OBJS),
            "tests/c/origin_krb5_dispatch_test.c",
        ],
    )
    return [result(ok, f"origin_krb5_dispatch {message}")]


