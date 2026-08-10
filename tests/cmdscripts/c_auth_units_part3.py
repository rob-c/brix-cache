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
    "gsi_verdepth": run_gsi_verdepth,
    "tls_reuse": run_tls_reuse,
    "deleg_find_eec": run_deleg_find_eec,
    "ucred": run_ucred,
    "sts_units": run_sts_units,
    "protbind": run_protbind,
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
    _print_results(results)
    return 0 if all(ok for ok, _ in results) else 1


def _print_results(results: list[tuple[bool, str]]) -> None:
    for ok, message in results:
        print(f"  {'ok  ' if ok else 'FAIL'} {message}")


if __name__ == "__main__":
    from cmdscripts import main

    raise SystemExit(main(entry))
