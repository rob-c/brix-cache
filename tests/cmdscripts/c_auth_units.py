"""Python ports for auth-oriented C shell runners."""

from __future__ import annotations

from pathlib import Path
import os
import shutil
import tempfile

from cmdscripts.compile_run import REPO_ROOT, result, run

# These four are the parent's share of the helpers the complexity burndown
# hoisted out of the runners below.  They carry real names because every shard
# of this module is exec-composed into THESE globals: a generic `_expression_N`
# in a shard silently rebinds the parent's helper of the same name, and the
# parent's call site -- resolved at call time -- then reaches the shard's
# function.  That is not hypothetical; it is how `run_deleg_gate` came to call a
# one-argument helper with three arguments.  Guard #12 now fails the build on
# any duplicate top-level name within one composed unit.
def _find_objs(needed):
    return (
        [find_obj(n) for n in needed]
    )

def _missing_objs(needed, objs):
    return (
        [n for n, o in zip(needed, objs) if o is None]
    )

def _deleg_forge_failure(forged):
    return (
        [result(False, f"forge deleg fixtures failed: {(forged.stderr or forged.stdout)[-3000:]}")]
    )

def _compile_deleg_gate(base, fixtures, objs):
    return (
        compile_and_run(
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
    )


def _guard_sanitizer_link_flags_1(syms, flags):
    if "__asan_" in syms:
        flags.append("-fsanitize=address")

def _guard_sanitizer_link_flags_2(syms, flags):
    if "__ubsan_" in syms or "__ubsan" in syms:
        flags.append("-fsanitize=undefined")

def _guard_sanitizer_link_flags_3(syms, flags):
    if "__tsan_" in syms:
        flags.append("-fsanitize=thread")

def _guard_run_deleg_gate_4(owned):
    if owned:
        shutil.rmtree(owned, ignore_errors=True)


NGX_SRC = Path(os.environ.get(
    "NGX_SRC",
    "/tmp/nginx-1.28.3" if Path("/tmp/nginx-1.28.3/src/core/ngx_config.h").exists()
    else "/tmp/nginx-1.24.0",
))
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


def _sanitizer_link_flags(args: list[str]) -> list[str]:
    """`-fsanitize=...` when a linked-in nginx object was built under a sanitizer.

    Same shape as `_coverage_link_flags`: an object compiled with
    -fsanitize=address/undefined/thread carries __asan_*/__ubsan_*/__tsan_*
    references, so linking it without the matching runtime dies at LD time with
    `undefined reference to __asan_*` — exactly the contaminated-addon-object
    case.  One nm pass over the .o args selects the right flags so the harness
    links against whatever the nginx tree was built with."""
    objs = [a for a in args if a.endswith(".o")
            and Path(a if os.path.isabs(a) else REPO_ROOT / a).exists()]
    if not objs:
        return []
    proc = run(["nm", *objs], cwd=REPO_ROOT)
    syms = proc.stdout if proc.returncode == 0 else ""
    flags = []
    _guard_sanitizer_link_flags_1(syms, flags)
    _guard_sanitizer_link_flags_2(syms, flags)
    _guard_sanitizer_link_flags_3(syms, flags)
    return flags


def compile_and_run(binary: Path, args: list[str], env: dict[str, str] | None = None) -> tuple[bool, str]:
    # detect_leaks=0: an object-linked unit that inherits -fsanitize=address from
    # a contaminated tree must not fail on LeakSanitizer's exit report (the driver
    # is not written to free); real heap errors still abort.
    child_env = {**HERMETIC_ENV, "ASAN_OPTIONS": "detect_leaks=0", **(env or {})}
    args = [*_coverage_link_flags(args), *_sanitizer_link_flags(args), *args]
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
    objs = _find_objs(needed)
    missing = _missing_objs(needed, objs)
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
            return _deleg_forge_failure(forged)
        ok, message = _compile_deleg_gate(base, fixtures, objs)
        return [result(ok, f"deleg_gate {message}")]
    finally:
        _guard_run_deleg_gate_4(owned)


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

from split_continuation import load as _load_continuations
_load_continuations(globals(), __file__, "c_auth_units_part2.py",
                    "c_auth_units_part3.py")
