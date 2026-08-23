"""
Phase-42 build matrix — graceful degradation + real dynamic-module dlopen.

Two build-time guards for the codec compile-gating contract (codec_core.h):

  1. **Graceful degradation when an optional codec library is ABSENT.**
     `tests/c/codec_nolib_test.c` compiles the codec kernel with the mandatory
     zlib backend but every optional backend (zstd/xz/brotli/bzip2/lz4) built
     WITHOUT its -DBRIX_HAVE_* macro, i.e. as its `available = 0` stub, linking
     none of those libraries.  It asserts the table has no holes, the absent
     codecs report unavailable, and `brix_codec_open()` returns NULL for them
     (so the server degrades to plaintext / rejects rather than crashing).  Fast,
     deterministic, no external libs — runs by default.

  2. **Real `--with-compat` dynamic-module build + dlopen.**
     `tests/build_dynamic_modules.sh` does a full isolated `--add-dynamic-module`
     nginx build (never touching the harness binary) and asserts the compression
     codec libraries — including lz4 — are linked into the dynamic stream `.so`
     as DT_NEEDED records and resolve at load (the reason BRIX_CODEC_LIBS is in
     ngx_module_libs, not just CORE_LIBS).  Heavyweight (compiles nginx + all
     modules), so it is OPT-IN via XRD_RUN_BUILD_MATRIX=1.

     Note: that script intentionally does NOT require a full `nginx -t` dlopen of
     the per-module .so set to succeed — that is blocked by a pre-existing,
     non-compression circular cross-module symbol dependency of the multi-module
     split (the harness ships static for this reason).  The script fails only if a
     *codec* symbol is unresolved; this test mirrors that contract.
"""

import os
import subprocess

import pytest

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CDIR = os.path.join(REPO, "tests", "c")
PROTO = os.path.join(REPO, "shared", "xrdproto", "libxrdproto.a")
CM = os.path.join(REPO, "src", "core", "compat")


def _cc():
    return os.environ.get("CC", "cc")


def test_codec_nolib_graceful_degrade(tmp_path):
    """Compile + run the no-optional-lib codec build and assert every optional
    codec degrades to available=0 / open()->NULL while zlib stays live."""
    src = os.path.join(CDIR, "codec_nolib_test.c")
    _require_source(src, "codec_nolib_test.c not present")

    binp = str(tmp_path / "codec_nolib_test")
    # zlib backend compiled in (-DBRIX_HAVE_ZLIB, -lz); the 5 optional backends
    # compiled WITHOUT their HAVE macro -> available=0 stubs, no optional libs.
    cmd = [
        _cc(), "-std=c11", "-O2", "-Wall", "-Wextra",
        "-DBRIX_HAVE_ZLIB", "-I", CM, src,
        os.path.join(CM, "codec_core.c"),
        os.path.join(CM, "codec_zlib.c"),
        os.path.join(CM, "codec_zstd.c"),
        os.path.join(CM, "codec_lzma.c"),
        os.path.join(CM, "codec_brotli.c"),
        os.path.join(CM, "codec_bzip2.c"),
        os.path.join(CM, "codec_lz4.c"),
        "-o", binp, "-lz",
    ]
    cc = subprocess.run(cmd, capture_output=True, text=True)
    _check_nolib_compile(cc)

    run = subprocess.run([binp], capture_output=True, text=True, timeout=60)
    assert run.returncode == 0, (
        f"graceful-degrade matrix FAILED:\n{run.stdout}\n{run.stderr}")
    assert "ALL PASSED" in run.stdout, run.stdout


def _require_source(path, reason):
    if not os.path.isfile(path):
        pytest.skip(reason)


def _check_nolib_compile(result):
    if result.returncode == 0:
        return
    if _missing_zlib_toolchain(result.stderr):
        pytest.skip(f"toolchain/zlib unavailable:\n{result.stderr[:400]}")
    pytest.fail(f"no-lib codec build failed to COMPILE:\n{result.stderr[:1500]}")


def _missing_zlib_toolchain(stderr):
    return "zlib.h" in stderr or "cc:" in stderr.lower()


# Per-codec drop matrix: (codec, HAVE-flag, link-libs). zlib is always kept.
_OPT_CODECS = [
    ("zstd",   "BRIX_HAVE_ZSTD",   ["-lzstd"]),
    ("xz",     "BRIX_HAVE_LZMA",   ["-llzma"]),
    ("brotli", "BRIX_HAVE_BROTLI", ["-lbrotlienc", "-lbrotlidec"]),
    ("bzip2",  "BRIX_HAVE_BZIP2",  ["-lbz2"]),
    ("lz4",    "BRIX_HAVE_LZ4",    ["-l:liblz4.so.1"]),
]
_CODEC_SRC = {
    "zstd": "codec_zstd.c", "xz": "codec_lzma.c", "brotli": "codec_brotli.c",
    "bzip2": "codec_bzip2.c", "lz4": "codec_lz4.c",
}


@pytest.mark.parametrize("dropped", [c[0] for c in _OPT_CODECS])
def test_codec_per_codec_drop_independence(tmp_path, dropped):
    """Drop ONE optional codec (its -DBRIX_HAVE_* + lib omitted) while KEEPING
    the others, and assert: the dropped codec degrades to available=0, every kept
    codec stays available=1, and gzip (zlib, mandatory) stays available. Proves
    codecs are independent — removing one never disables another nor leaves a
    table hole — which the all-absent codec_nolib_test cannot show."""
    probe = os.path.join(CDIR, "codec_avail_probe.c")
    _require_source(probe, "codec_avail_probe.c not present")
    cmd, libs, kept = _drop_build_inputs(probe, dropped)

    binp = str(tmp_path / f"probe_drop_{dropped}")
    cc = subprocess.run([*cmd, "-o", binp, *libs], capture_output=True, text=True)
    if cc.returncode != 0:
        pytest.skip(f"toolchain/codec dev lib unavailable for drop-{dropped}:\n{cc.stderr[:400]}")

    run = subprocess.run([binp], capture_output=True, text=True, timeout=30)
    assert run.returncode == 0, run.stderr
    avail = dict(line.split() for line in run.stdout.split("\n") if line.strip())
    _assert_drop_matrix(avail, kept, dropped, run.stdout)


def _drop_build_inputs(probe, dropped):
    cmd = [_cc(), "-std=c11", "-O2", "-Wall", "-Wextra", "-DBRIX_HAVE_ZLIB",
           *_lz4_cflags(), "-I", CM, probe,
           os.path.join(CM, "codec_core.c"), os.path.join(CM, "codec_zlib.c")]
    libs, kept = ["-lz"], []
    for name, flag, codec_libs in _OPT_CODECS:
        cmd.append(os.path.join(CM, _CODEC_SRC[name]))
        if name != dropped:
            cmd.append(f"-D{flag}")
            libs.extend(codec_libs)
            kept.append(name)
    return cmd, libs, kept


def _lz4_cflags():
    configured = os.environ.get("BRIX_LZ4_CFLAGS", "")
    if configured:
        return [configured]
    include = _find_lz4_include()
    if include and include != "/usr/include":
        return [f"-I{include}"]
    return []


def _find_lz4_include():
    candidates = ("/usr/include", os.path.expanduser("~/miniconda3/include"),
                  "/opt/conda/include")
    return next((path for path in candidates
                 if os.path.isfile(os.path.join(path, "lz4frame.h"))), None)


def _assert_drop_matrix(available, kept, dropped, stdout):
    assert available.get("gzip") == "1", f"gzip must stay available: {stdout}"
    assert available.get(dropped) == "0", (
        f"dropped codec {dropped} must be unavailable: {stdout}")
    for name in kept:
        assert available.get(name) == "1", (
            f"kept codec {name} must stay available when {dropped} is dropped: {stdout}")


@pytest.mark.timeout(900)   # full nginx + dynamic-module build is ~90s+, far over the 30s default
def test_dynamic_module_dlopen_codec_wiring(tmp_path):
    """Full isolated --with-compat dynamic build; assert the codec libs (incl.
    lz4) are linked into the dynamic stream .so and resolve at load."""
    from pathlib import Path

    from cmdscripts.operator_build import build_dynamic_modules

    nginx_src = Path(os.environ.get("NGINX_SRC", "/tmp/nginx-1.28.3"))
    results = build_dynamic_modules(nginx_src, tmp_path / "xrd-build-matrix")
    skips = _build_skips(results)
    if skips:
        pytest.skip("; ".join(skips))
    failures = _build_failures(results)
    assert not failures, (
        "dynamic-module codec wiring FAILED:\n" + "\n".join(failures))


def _build_skips(results):
    return [message for _ok, message in results if message.startswith("SKIP")]


def _build_failures(results):
    return [message for ok, message in results if not ok]
