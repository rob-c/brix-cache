"""Python ports for auth-oriented C shell runners."""

from __future__ import annotations

from pathlib import Path
import os
import shutil
import tempfile

from cmdscripts.compile_run import REPO_ROOT, result, run

NGX_SRC = Path("/tmp/nginx-1.28.3")
OBJS = NGX_SRC / "objs"


def pkg_config(args: list[str], fallback: list[str] | None = None) -> list[str]:
    proc = run(["pkg-config", *args], cwd=REPO_ROOT)
    if proc.returncode != 0:
        return fallback or []
    return proc.stdout.split()


def find_obj(name: str) -> Path | None:
    matches = sorted((OBJS / "addon").rglob(name))
    return matches[0] if matches else None


# Pin TMPDIR for every child process: conftest points the inherited TMPDIR into
# /tmp/xrd-test, which concurrent test sessions wipe/rotate mid-run — gcc loses
# its intermediate .s files mid-compile and forge temp dirs vanish.
HERMETIC_ENV = {"TMPDIR": "/tmp"}


def _coverage_link_flags(args: list[str]) -> list[str]:
    """When a linked-in nginx object was built gcov-instrumented (a sibling
    `.gcno` sits next to it), the harness link line MUST also carry `--coverage`
    — otherwise it fails on the object's undefined `__gcov_*` symbols and, even if
    it linked, the gcov runtime that flushes the `.gcda` at exit would be absent.
    With the flag, running the unit flushes the object's `.gcda` to the path baked
    into it at build time (under `objs/`), so `tools/ci/coverage.py`'s lcov capture
    picks up code (e.g. `cred_mint.c`) that the request-path fleet never exercises.
    A no-op for ordinary (non-instrumented) builds: no `.gcno`, no flag added."""
    for a in args:
        if a.endswith(".o") and Path(REPO_ROOT / a if not os.path.isabs(a) else a
                                     ).with_suffix(".gcno").exists():
            return ["--coverage"]
    return []


def compile_and_run(binary: Path, args: list[str], env: dict[str, str] | None = None) -> tuple[bool, str]:
    child_env = {**HERMETIC_ENV, **(env or {})}
    args = [*_coverage_link_flags(args), *args]
    built = run(["gcc", *args, "-o", str(binary)], cwd=REPO_ROOT, env=child_env)
    if built.returncode != 0:
        return False, f"compile failed: {(built.stderr or built.stdout)[-3000:]}"
    ran = run([str(binary)], cwd=REPO_ROOT, env=child_env)
    return ran.returncode == 0, f"exited {ran.returncode}: {(ran.stderr or ran.stdout)[-3000:]}"


# Single source of truth for the x509 harness link lines. Any file-split of
# these TUs must be reflected here ONCE; the x509_link runner below fails fast
# if the list goes stale (undefined-symbol link errors).
X509_POLICY_SOURCES = [
    "src/auth/crypto/signing_policy.c",
    "src/auth/crypto/store_policy.c",
    "src/auth/crypto/store_policy_store.c",
    "src/auth/crypto/store_policy_conformance.c",
]

X509_HARNESS_TUS = {
    "x509_conformance": "tests/c/x509_conformance_test.c",
    "x509_oracle": "tests/c/x509_oracle.c",
}


def x509_gcc_args(harness_tu: str, sources: list[str] | None = None) -> list[str]:
    return [
        "-Wall",
        "-Wextra",
        "-Werror",
        "-I",
        "src",
        *pkg_config(["--cflags", "openssl"]),
        harness_tu,
        *(X509_POLICY_SOURCES if sources is None else sources),
        *pkg_config(["--libs", "openssl"], ["-lssl", "-lcrypto"]),
    ]


def link_x509_harness(base: Path, name: str, sources: list[str] | None = None) -> tuple[bool, str]:
    built = run(
        ["gcc", *x509_gcc_args(X509_HARNESS_TUS[name], sources), "-o", str(base / f"link_{name}")],
        cwd=REPO_ROOT,
    )
    return built.returncode == 0, (built.stderr or built.stdout)[-3000:]


def run_x509_link(base: Path) -> list[tuple[bool, str]]:
    results: list[tuple[bool, str]] = []
    for name in sorted(X509_HARNESS_TUS):
        ok, detail = link_x509_harness(base, name)
        results.append(result(ok, f"x509_link {name} {'linked' if ok else f'FAILED: {detail}'}"))
    return results


def x509_fixture_dir(name: str) -> tuple[Path, str | None]:
    """Pick the forge output dir; returns (dir, owned-path-to-delete-or-None).

    Never place the corpus under TMPDIR: conftest points TMPDIR at the shared
    /tmp/xrd-test/tmp basetemp, and concurrent pytest sessions rotate each
    other's roots to garbage-* and rm_rf them mid-run — the forged CAs vanish
    and every accept clause fails closed as a reject.
    """
    override = os.environ.get("BRIX_X509_FIXTURES")
    if override:
        return Path(override), None
    made = tempfile.mkdtemp(prefix=f"brix_{name}.", dir="/tmp")
    return Path(made), made


def run_x509_conformance(base: Path) -> list[tuple[bool, str]]:
    fixtures, owned = x509_fixture_dir("x509conf")
    try:
        forged = run(
            ["python3", "-c", f"import x509forge, pathlib; x509forge.forge_all(pathlib.Path({str(fixtures)!r}))"],
            cwd=REPO_ROOT,
            env={"PYTHONPATH": "tests", **HERMETIC_ENV},
        )
        if forged.returncode != 0:
            return [result(False, f"forge x509 fixtures failed: {(forged.stderr or forged.stdout)[-3000:]}")]
        ok, message = compile_and_run(
            fixtures / "brix_x509conf",
            x509_gcc_args(X509_HARNESS_TUS["x509_conformance"]),
            env={"BRIX_X509_FIXTURES": str(fixtures)},
        )
        return [result(ok, f"x509_conformance {message}")]
    finally:
        if owned:
            shutil.rmtree(owned, ignore_errors=True)


def run_x509_oracle(base: Path) -> list[tuple[bool, str]]:
    fixtures, owned = x509_fixture_dir("x509oracle")
    try:
        forged = run(
            [
                "python3",
                "-c",
                f"import x509forge, clauses, pathlib; x509forge.build_all(pathlib.Path({str(fixtures)!r}), clauses.ALL_CLAUSES)",
            ],
            cwd=REPO_ROOT,
            env={"PYTHONPATH": "tests", **HERMETIC_ENV},
        )
        if forged.returncode != 0:
            return [result(False, f"forge x509 oracle fixtures failed: {(forged.stderr or forged.stdout)[-3000:]}")]
        ok, message = compile_and_run(
            fixtures / "brix_x509_oracle",
            x509_gcc_args(X509_HARNESS_TUS["x509_oracle"]),
            env={"BRIX_X509_FIXTURES": str(fixtures)},
        )
        return [result(ok, f"x509_oracle {message}")]
    finally:
        if owned:
            shutil.rmtree(owned, ignore_errors=True)


def run_cred_mint(base: Path) -> list[tuple[bool, str]]:
    if shutil.which("openssl") is None:
        return [result(True, "SKIP openssl not on PATH")]
    obj = find_obj("cred_mint.o")
    if obj is None:
        return [result(True, "SKIP build cred_mint.o first")]
    siblings = [str(s) for s in (find_obj("cred_mint_cert.o"),) if s]
    ok, message = compile_and_run(
        base / "test_cred_mint",
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
            "tests/c/test_cred_mint.c",
            str(obj),
            *siblings,
            "-lcrypto",
        ],
    )
    return [result(ok, f"cred_mint {message}")]


def run_ucred(base: Path) -> list[tuple[bool, str]]:
    if shutil.which("openssl") is None:
        return [result(True, "SKIP openssl not on PATH")]
    cryptography = run(["python3", "-c", "import cryptography"], cwd=REPO_ROOT)
    if cryptography.returncode != 0:
        return [result(True, "SKIP python3 cryptography unavailable")]
    obj = find_obj("ucred.o")
    if obj is None:
        return [result(True, "SKIP build ucred.o first")]
    siblings = [str(s) for s in (find_obj("ucred_parse.o"),) if s]
    ok, message = compile_and_run(
        base / "test_ucred",
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
            "tests/c/test_ucred.c",
            str(obj),
            *siblings,
            "-lcrypto",
        ],
    )
    return [result(ok, f"ucred {message}")]


# Forge the delegation-gate corpus: one trusted grid-format proxy bundle
# (proxy cert, PRIVATE KEY, EEC — the key block in the middle is the point:
# the gate's chain parser must skip it, not stop at it), one bundle rooted in
# a rogue CA, and one non-PEM file. not_after_days=400: the forge epoch is
# FIXED at 2026-01-01, so short windows are already expired in real time.
DELEG_GATE_FORGE = """
import pathlib, sys
import x509forge

d = pathlib.Path(sys.argv[1])
ca = x509forge.make_ca("/DC=test/CN=Deleg Trust CA")
eec = x509forge.make_eec(ca, "/DC=test/CN=alice", not_after_days=400)
proxy = x509forge.make_proxy(eec, not_after_days=400)
(d / "ca.pem").write_bytes(ca.pem)
(d / "good_grid.pem").write_bytes(proxy.pem + proxy.key_pem + eec.pem)

rogue_ca = x509forge.make_ca("/DC=test/CN=Rogue CA")
rogue_eec = x509forge.make_eec(rogue_ca, "/DC=test/CN=mallory", not_after_days=400)
rogue_proxy = x509forge.make_proxy(rogue_eec, not_after_days=400)
(d / "rogue_grid.pem").write_bytes(rogue_proxy.pem + rogue_proxy.key_pem + rogue_eec.pem)

(d / "garbage.pem").write_bytes(b"this is not a pem credential\\n")
"""


def run_deleg_gate(base: Path) -> list[tuple[bool, str]]:
    if shutil.which("openssl") is None:
        return [result(True, "SKIP openssl not on PATH")]
    # vfs_deleg_x509.o holds brix_vfs_deleg_proxy(), split out of vfs_deleg.c by
    # the file-size burndown; without it the harness link fails on that symbol.
    needed = ["vfs_deleg.o", "vfs_deleg_bind.o", "vfs_deleg_x509.o",
              "gsi_verify.o", "gsi_upstream.o", "cred_stage.o"]
    objs = [find_obj(n) for n in needed]
    missing = [n for n, o in zip(needed, objs) if o is None]
    if missing:
        return [result(True, f"SKIP build {' '.join(missing)} first")]
    fixtures, owned = x509_fixture_dir("deleg_gate")
    try:
        forged = run(
            ["python3", "-c", DELEG_GATE_FORGE, str(fixtures)],
            cwd=REPO_ROOT,
            env={"PYTHONPATH": "tests", **HERMETIC_ENV},
        )
        if forged.returncode != 0:
            return [result(False, f"forge deleg fixtures failed: {(forged.stderr or forged.stdout)[-3000:]}")]
        ok, message = compile_and_run(
            base / "test_deleg_gate",
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
                str(NGX_SRC / "src/stream"),
                "-I",
                str(OBJS),
                "tests/c/deleg_gate_test.c",
                *[str(o) for o in objs],
                *X509_POLICY_SOURCES,
                "-lssl",
                "-lcrypto",
            ],
            env={"BRIX_DELEG_FIXTURES": str(fixtures)},
        )
        return [result(ok, f"deleg_gate {message}")]
    finally:
        if owned:
            shutil.rmtree(owned, ignore_errors=True)


# Forge the EEC-normalization corpus (P80.11): one trusted CA -> EEC -> two
# proxies with DISTINCT serials (so their leaf DNs differ but the EEC is one),
# plus an independent ROGUE CA -> EEC -> proxy the trusted store must reject.
# The forge epoch is FIXED at 2026-01-01, so not_after_days must clear real time.
GSI_EEC_FORGE = """
import pathlib, sys
import x509forge

d = pathlib.Path(sys.argv[1])
ca = x509forge.make_ca("/DC=test/CN=EEC Trust CA")
eec = x509forge.make_eec(ca, "/DC=test/CN=alice", not_after_days=4000)
proxy_a = x509forge.make_proxy(eec, not_after_days=4000, serial=100001)
proxy_b = x509forge.make_proxy(eec, not_after_days=4000, serial=100002)
(d / "ca.pem").write_bytes(ca.pem)
(d / "eec.pem").write_bytes(eec.pem)
(d / "proxy_a.pem").write_bytes(proxy_a.pem)
(d / "proxy_b.pem").write_bytes(proxy_b.pem)

rogue_ca = x509forge.make_ca("/DC=test/CN=Rogue EEC CA")
rogue_eec = x509forge.make_eec(rogue_ca, "/DC=test/CN=mallory", not_after_days=4000)
rogue_proxy = x509forge.make_proxy(rogue_eec, not_after_days=4000, serial=100003)
(d / "rogue_ca.pem").write_bytes(rogue_ca.pem)
(d / "rogue_eec.pem").write_bytes(rogue_eec.pem)
(d / "rogue_proxy.pem").write_bytes(rogue_proxy.pem)
"""


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


def run_krb5_deleg_capture(base: Path) -> list[tuple[bool, str]]:
    """Phase-70 §5.7 inbound krb5 forwarded-TGT delegation-capture seams
    (deleg_capture.c).

    Self-contained: the harness #includes the TU under test and stubs its whole
    external surface (gbuf/response wire, pool allocators, the pure origin-SPN
    derivation), so NO project objects, krb5, or OpenSSL are linked. Compiled
    WITHOUT BRIX_HAVE_KRB5 so the always-compiled pure seams build and run; the
    krb5/GSSAPI capture core is proven live vs a real KDC by
    test_krb5_forward_live.py.
    """
    ok, message = compile_and_run(
        base / "krb5_deleg_capture",
        [
            "-O",
            "-Wall",
            "-Werror",
            "-I", "src",
            "-I", "shared",
            "-I", str(NGX_SRC / "src/core"),
            "-I", str(NGX_SRC / "src/event"),
            "-I", str(NGX_SRC / "src/os/unix"),
            "-I", str(NGX_SRC / "src/stream"),
            "-I", str(OBJS),
            "tests/c/krb5_deleg_capture_test.c",
        ],
    )
    return [result(ok, f"krb5_deleg_capture {message}")]


RUNNERS = {
    "x509_link": run_x509_link,
    "origin_krb5_dispatch": run_origin_krb5_dispatch,
    "krb5_deleg_capture": run_krb5_deleg_capture,
    "tpc_proxy_expiry": run_tpc_proxy_expiry,
    "aud_match": run_aud_match,
    "exchange_cache": run_exchange_cache,
    "exchange": run_exchange,
    "x509_conformance": run_x509_conformance,
    "x509_oracle": run_x509_oracle,
    "cred_mint": run_cred_mint,
    "deleg_gate": run_deleg_gate,
    "gsi_eec": run_gsi_eec,
    "deleg_find_eec": run_deleg_find_eec,
    "ucred": run_ucred,
    "sts_units": run_sts_units,
}


def run_checks(base: Path, names: list[str] | None = None) -> list[tuple[bool, str]]:
    selected = names or sorted(RUNNERS)
    results: list[tuple[bool, str]] = []
    for name in selected:
        work = base / name
        work.mkdir(parents=True, exist_ok=True)
        results.extend(RUNNERS[name](work))
    return results


def entry(argv: list[str]) -> int:
    import tempfile

    names = argv or sorted(RUNNERS)
    with tempfile.TemporaryDirectory(prefix="c_auth_units.") as tmp:
        results = run_checks(Path(tmp), names=names)
    for ok, message in results:
        print(f"  {'ok  ' if ok else 'FAIL'} {message}")
    return 0 if all(ok for ok, _ in results) else 1


if __name__ == "__main__":
    from cmdscripts import main

    raise SystemExit(main(entry))
