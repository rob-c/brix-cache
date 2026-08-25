"""Python port of tests/fuzz/run_all.sh."""

from __future__ import annotations

from pathlib import Path
import os

from cmdscripts.compile_run import REPO_ROOT, result, run

def _expression_1(fuzz_time):
    return (
        fuzz_time or os.environ.get("FUZZ_TIME", "60")
    )

def _expression_2(results, target, built):
    return (
        results.append(result(False, f"build {target} failed: {excerpt(built.stderr or built.stdout)}"))
    )

def _expression_3(ran):
    return (
        excerpt(ran.stderr or ran.stdout)
    )


FUZZ_DIR = REPO_ROOT / "tests" / "fuzz"
ARTIFACT_DIR = FUZZ_DIR / "artifacts"
SAN = ["-O1", "-g", "-fsanitize=fuzzer,address,undefined"]


BUILD_ARGS = {
    "fuzz_safe_size": [
        "clang",
        *SAN,
        "-I",
        "../../src",
        "-I",
        "../../src/core/compat",
        "fuzz_safe_size.c",
        "-o",
        "fuzz_safe_size",
    ],
    "fuzz_b64url": [
        "clang",
        *SAN,
        "-I",
        "../../src",
        "-I",
        "../../src/auth/token",
        "fuzz_b64url.c",
        "../../src/auth/token/b64url.c",
        "-lcrypto",
        "-o",
        "fuzz_b64url",
    ],
    "fuzz_zip_dir": [
        "clang",
        *SAN,
        "-iquote",
        "../../src",
        "fuzz_zip_dir.c",
        "-lz",
        "-o",
        "fuzz_zip_dir",
    ],
    "fuzz_jwt_json": [
        "clang",
        *SAN,
        "-I",
        "../../src",
        "-I",
        "../../src/auth/token",
        "fuzz_jwt_json.c",
        "../../src/auth/token/json.c",
        "-ljansson",
        "-o",
        "fuzz_jwt_json",
    ],
    "fuzz_urlcodec": [
        "clang",
        *SAN,
        "-I",
        "../../src",
        "fuzz_urlcodec.c",
        "../../src/core/compat/uri.c",
        "../../src/core/compat/hex.c",
        "-o",
        "fuzz_urlcodec",
    ],
    # ---- hyper-hardening C-1 (pre-auth parse targets) + C-2 (root framing) ----
    "fuzz_gsi_bucket": [
        "clang",
        *SAN,
        "-I",
        "../../src",
        "fuzz_gsi_bucket.c",
        "../../src/auth/gsi/gsi_buf.c",
        "-lcrypto",
        "-o",
        "fuzz_gsi_bucket",
    ],
    "fuzz_sss_frame": [
        "clang",
        *SAN,
        "-I",
        "../../src",
        "fuzz_sss_frame.c",
        "../../src/auth/sss/sss_framing.c",
        "-o",
        "fuzz_sss_frame",
    ],
    "fuzz_macaroon_frame": [
        "clang",
        *SAN,
        "-I",
        "../../src",
        "fuzz_macaroon_frame.c",
        "../../src/auth/token/macaroon_frame.c",
        "../../src/core/compat/hex.c",
        "-o",
        "fuzz_macaroon_frame",
    ],
    "fuzz_root_frame": [
        "clang",
        *SAN,
        "-I",
        "../../src",
        "fuzz_root_frame.c",
        "../../src/protocols/root/connection/recv_frame_bounds.c",
        "-o",
        "fuzz_root_frame",
    ],
    "fuzz_sigv4_canonical": [
        "clang",
        *SAN,
        "-I",
        "../../src",
        "fuzz_sigv4_canonical.c",
        "-o",
        "fuzz_sigv4_canonical",
    ],
    # phase-104 D0.2: the OCI `/v2/` classifier is the whole traversal defense
    # for that surface, and it links standalone (pure C over the shared
    # grammars) — so it fuzzes here rather than only through a live registry.
    "fuzz_oci_classify": [
        "clang",
        *SAN,
        "-I",
        "../../src/protocols/oci",
        "-I",
        "../../shared",
        "fuzz_oci_classify.c",
        "../../src/protocols/oci/oci_classify.c",
        "../../shared/oci/name.c",
        "../../shared/oci/digest.c",
        "-lcrypto",
        "-o",
        "fuzz_oci_classify",
    ],
    # phase-104 §H: the other three parsers that eat bytes nobody on this side
    # wrote — an upstream's 401 header, a layer blob, a package header.
    "fuzz_oci_challenge": [
        "clang",
        *SAN,
        "-I",
        "../../shared",
        "fuzz_oci_challenge.c",
        "../../shared/oci/challenge.c",
        "-o",
        "fuzz_oci_challenge",
    ],
    "fuzz_tar_header": [
        "clang",
        *SAN,
        "-I",
        "../../shared",
        "fuzz_tar_header.c",
        "../../shared/oci/tar.c",
        "../../shared/oci/tar_pax.c",
        # diff-id capture rides the reader's byte source (phase-104 D8.e)
        "../../shared/oci/tar_digest.c",
        "../../shared/oci/digest.c",
        # the reader hands layer xattrs on in the changeset wire format, so
        # the catalog packer comes with it
        "../../shared/cvmfs/catalog/catalog_write.c",
        "../../shared/cvmfs/catalog/xattr_pack.c",
        "../../shared/cvmfs/catalog/catalog.c",
        "../../shared/cvmfs/grammar/hash.c",
        "-lz",
        "-lsqlite3",
        "-lcrypto",
        "-o",
        "fuzz_tar_header",
    ],
    "fuzz_rpm_header": [
        "clang",
        *SAN,
        "-I",
        "../../shared",
        "fuzz_rpm_header.c",
        "../../shared/rpm/rpmhdr.c",
        "../../shared/oci/digest.c",     # pkgid streaming sha256
        "-lcrypto",
        "-o",
        "fuzz_rpm_header",
    ],
}


def excerpt(text: str, head: int = 1800, tail: int = 2000) -> str:
    """Keep BOTH ends of a libFuzzer run.

    libFuzzer prints the sanitizer diagnosis (error class, faulting address,
    stack) first and the run statistics last. A tail-only excerpt therefore
    reports that something crashed while discarding what crashed and where —
    which is exactly what cost us the 2026-08-05 fuzz_b64url triage, where the
    CI log held no error line at all and the reproducer was never uploaded.
    """
    text = (text or "").strip()
    if len(text) <= head + tail:
        return text
    return f"{text[:head]}\n[... {len(text) - head - tail} bytes elided ...]\n{text[-tail:]}"


def run_checks(base: Path, fuzz_time: str | None = None) -> list[tuple[bool, str]]:
    seconds = _expression_1(fuzz_time)
    results: list[tuple[bool, str]] = []
    for target, build_args in BUILD_ARGS.items():
        built = run(build_args, cwd=FUZZ_DIR)
        if built.returncode != 0:
            _expression_2(results, target, built)
            continue
        corpus = FUZZ_DIR / f"corpus_{target.removeprefix('fuzz_')}"
        corpus.mkdir(exist_ok=True)
        # Per-target artifact dir: libFuzzer otherwise drops crash-<sha1> into the
        # cwd, where nothing collects it and the reproducing input is lost.
        artifacts = ARTIFACT_DIR / target
        artifacts.mkdir(parents=True, exist_ok=True)
        run([str(FUZZ_DIR / target), "-runs=0", str(corpus)], cwd=FUZZ_DIR)
        ran = run(
            [
                str(FUZZ_DIR / target),
                f"-max_total_time={seconds}",
                f"-artifact_prefix={artifacts}/",
                str(corpus),
            ],
            cwd=FUZZ_DIR,
        )
        detail = _expression_3(ran)
        reproducers = sorted(p for p in artifacts.iterdir() if p.is_file())
        if reproducers:
            detail += "\nreproducers: " + ", ".join(str(p) for p in reproducers)
        results.append(result(ran.returncode == 0, f"{target} fuzzed for {seconds}s: {detail}"))
    return results


def entry(argv: list[str]) -> int:
    import tempfile

    with tempfile.TemporaryDirectory(prefix="fuzz_all.") as tmp:
        results = run_checks(Path(tmp))
    for ok, message in results:
        print(f"  {'ok  ' if ok else 'FAIL'} {message}")
    if all(ok for ok, _ in results):
        print(f"all fuzz targets clean (FUZZ_TIME={os.environ.get('FUZZ_TIME', '60')}s each)")
        return 0
    return 1


if __name__ == "__main__":
    from cmdscripts import main

    raise SystemExit(main(entry))
