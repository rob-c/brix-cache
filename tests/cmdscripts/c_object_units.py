"""Python ports for C unit runners that link built module objects."""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

from cmdscripts.compile_run import REPO_ROOT, compile_binary, result, run
from cmdscripts.command_results import print_results

# Honour NGX_SRC (mirroring c_regression_units.py) so the unit runners link
# against whichever configured build tree the caller points at — the shared
# /tmp/nginx-1.28.3 by default, or a private tree during concurrent-session work.
def _expression_1(spec):
    return (
        [str(path) for path in spec.required if not path.is_file()]
    )

def _expression_2(name, built):
    return (
        [result(False, f"compile {name} failed: {(built.stderr or built.stdout)[-3000:]}")]
    )

def _expression_3(ran, name):
    return (
        [result(ran.returncode == 0, f"{name} exited {ran.returncode}: {(ran.stderr or ran.stdout)[-3000:]}")]
    )


NGX_SRC = Path(os.environ.get("NGX_SRC", "/tmp/nginx-1.28.3"))
OBJS = NGX_SRC / "objs"


@dataclass(frozen=True)
class ObjectUnitSpec:
    name: str
    binary: str
    required: tuple[Path, ...]
    args: tuple[str, ...]


def addon(path: str) -> Path:
    return OBJS / "addon" / path


SPECS: dict[str, ObjectUnitSpec] = {
    "cache_admit": ObjectUnitSpec(
        "cache_admit",
        "test_cache_admit",
        (addon("cache/cache_admit.o"),),
        ("-O", "-Wall", "tests/c/test_cache_admit.c", str(addon("cache/cache_admit.o"))),
    ),
    "cache_storage": ObjectUnitSpec(
        "cache_storage",
        "test_cache_storage",
        (addon("cache/cache_key.o"),),
        ("-O", "-Wall", "tests/c/test_cache_storage.c", str(addon("cache/cache_key.o"))),
    ),
    "cinfo": ObjectUnitSpec(
        "cinfo",
        "test_cinfo",
        (
            addon("cache/cinfo.o"),
            addon("meta/xmeta.o"),
            addon("meta/xmeta_path.o"),
            addon("meta/xmeta_decode.o"),
            addon("meta/xmeta_encode.o"),
            addon("meta/xmeta_carrier.o"),
            addon("compat/crc32c.o"),
            addon("compat/crc32c_hw.o"),
        ),
        (
            "-O",
            "-Wall",
            "tests/c/test_cinfo.c",
            str(addon("cache/cinfo.o")),
            str(addon("meta/xmeta.o")),
            str(addon("meta/xmeta_path.o")),
            str(addon("meta/xmeta_decode.o")),
            str(addon("meta/xmeta_encode.o")),
            str(addon("meta/xmeta_carrier.o")),
            str(addon("compat/crc32c.o")),
            str(addon("compat/crc32c_hw.o")),
        ),
    ),
    "slice": ObjectUnitSpec(
        "slice",
        "test_slice",
        (addon("cache/slice.o"), addon("cache/meta.o")),
        ("-O", "-Wall", "tests/c/test_slice.c", str(addon("cache/slice.o")), str(addon("cache/meta.o"))),
    ),
    # POSC crash-orphan reaper policy (ofs.persist analog, §1.9). Links the real
    # tmp_path.o; the test stubs the 3 non-libc symbols it names but never drives.
    "tmp_reap": ObjectUnitSpec(
        "tmp_reap",
        "test_tmp_reap",
        (addon("compat/tmp_path.o"),),
        ("-O", "-Wall", "tests/c/test_tmp_reap.c", str(addon("compat/tmp_path.o"))),
    ),
    # Per-worker (sessid,pathid)->conn offload map (§1.1 slice 1). Pure C, no deps.
    "offload_registry": ObjectUnitSpec(
        "offload_registry",
        "test_offload_registry",
        (addon("session/offload_registry.o"),),
        ("-O", "-Wall",
         "-I", str(REPO_ROOT / "src/protocols/root/session"),
         "tests/c/test_offload_registry.c",
         str(addon("session/offload_registry.o"))),
    ),
    "cstore_scan_enumerate": ObjectUnitSpec(
        "cstore_scan_enumerate",
        "test_cstore_scan_enumerate",
        (addon("cache/cstore_scan.o"),),
        (
            "-O",
            "-Wall",
            "-I",
            str(REPO_ROOT / "src"),
            "-I",
            str(REPO_ROOT / "src/fs/cache"),
            "-I",
            str(REPO_ROOT / "shared"),
            "-I",
            str(OBJS),
            "-I",
            str(NGX_SRC / "src/core"),
            "-I",
            str(NGX_SRC / "src/event"),
            "-I",
            str(NGX_SRC / "src/event/modules"),
            "-I",
            str(NGX_SRC / "src/event/quic"),
            "-I",
            str(NGX_SRC / "src/os/unix"),
            "tests/c/test_cstore_scan_enumerate.c",
            str(addon("cache/cstore_scan.o")),
        ),
    ),
    # The catalog verb's decorator walk. vfs_walk.o's cross-TU closure is small
    # enough (resolve/fill_stat/*_beneath/*_confined_canon) that the harness
    # stubs it outright and links the ONE real object, keeping the enumeration
    # hermetic — no pool, no backend registry, no filesystem.
    "vfs_enumerate_decorator": ObjectUnitSpec(
        "vfs_enumerate_decorator",
        "test_vfs_enumerate_decorator",
        (addon("vfs/vfs_walk.o"),),
        (
            "-O",
            "-Wall",
            "-I",
            "src",
            "-I",
            str(REPO_ROOT / "shared"),
            "-I",
            str(OBJS),
            "-I",
            str(NGX_SRC / "src/core"),
            "-I",
            str(NGX_SRC / "src/event"),
            "-I",
            str(NGX_SRC / "src/event/modules"),
            "-I",
            str(NGX_SRC / "src/event/quic"),
            "-I",
            str(NGX_SRC / "src/os/unix"),
            "tests/c/test_vfs_enumerate_decorator.c",
            str(addon("vfs/vfs_walk.o")),
        ),
    ),
    "vfs_caps": ObjectUnitSpec(
        "vfs_caps",
        "test_vfs_caps",
        (addon("backend/sd_registry.o"),),
        (
            "-O",
            "-Wall",
            "-I",
            "src",
            "-I",
            str(NGX_SRC / "src/core"),
            "-I",
            str(NGX_SRC / "src/event"),
            "-I",
            str(NGX_SRC / "src/event/modules"),
            "-I",
            str(NGX_SRC / "src/event/quic"),
            "-I",
            str(NGX_SRC / "src/os/unix"),
            "-I",
            str(OBJS),
            "tests/c/test_vfs_caps.c",
            str(addon("backend/sd_registry.o")),
        ),
    ),
    # Pelican OriginAdvertiseV2 payload builders (build_ad / caps_json / rfc3339)
    # linked against the real object; -ljansson for the document, -lcurl/-lcrypto
    # resolve pelican_register.o's own libcurl + OpenSSL references (the advertise
    # path is stubbed out in the harness but the object still names them).
    "pelican_ad": ObjectUnitSpec(
        "pelican_ad",
        "test_pelican_ad",
        (addon("origin/pelican_register.o"),),
        (
            "-O",
            "-Wall",
            # The advertise sub-struct sits past feature-gated fields in
            # ngx_stream_brix_srv_conf_t, so the harness MUST see the same
            # BRIX_HAVE_* defines the object was compiled with or the struct
            # layout skews and field reads land on the wrong offsets.
            "-DBRIX_HAVE_LIBXML2=1",
            "-DBRIX_HAVE_JANSSON=1",
            "-DBRIX_HAVE_KRB5=1",
            "-DBRIX_HAVE_SECCOMP=1",
            "-DBRIX_HAVE_ZLIB=1",
            "-DBRIX_HAVE_ZSTD=1",
            "-DBRIX_HAVE_LZMA=1",
            "-DBRIX_HAVE_BROTLI=1",
            "-DBRIX_HAVE_BZIP2=1",
            "-DBRIX_HAVE_LZ4=1",
            "-DBRIX_HAVE_SQLITE=1",
            "-I",
            "/usr/include/libxml2",
            "-I",
            "src",
            "-I",
            str(NGX_SRC / "src/core"),
            "-I",
            str(NGX_SRC / "src/event"),
            "-I",
            str(NGX_SRC / "src/event/modules"),
            "-I",
            str(NGX_SRC / "src/event/quic"),
            "-I",
            str(NGX_SRC / "src/os/unix"),
            "-I",
            str(NGX_SRC / "src/http"),
            "-I",
            str(NGX_SRC / "src/http/modules"),
            "-I",
            str(NGX_SRC / "src/stream"),
            "-I",
            str(OBJS),
            "tests/c/pelican_ad_test.c",
            str(addon("origin/pelican_register.o")),
            "-ljansson",
            "-lcurl",
            "-lcrypto",
        ),
    ),
}


def coverage_flags(required: tuple[Path, ...]) -> list[str]:
    """``--coverage`` iff the module objects were compiled with it.

    A tree configured for gcov (the coverage lane) emits a ``.gcno`` beside every
    object and leaves ``__gcov_init``/``__gcov_merge_add`` references in it. The
    unit harness links those objects directly, so without the gcov runtime the
    link dies on undefined ``__gcov_*`` — a failure of the BUILD TREE's flags,
    not of the code under test. Keyed off the ``.gcno`` so a normal tree links
    exactly as before.
    """
    return ["--coverage"] if any(obj.with_suffix(".gcno").is_file()
                                 for obj in required) else []


def run_one(name: str, base: Path) -> list[tuple[bool, str]]:
    spec = SPECS[name]
    missing = _expression_1(spec)
    if missing:
        return [result(True, f"SKIP {name}: build required object(s) first: {', '.join(missing)}")]
    binary = base / spec.binary
    built = compile_binary(binary, list(spec.args) + coverage_flags(spec.required),
                           cwd=REPO_ROOT)
    if built.returncode != 0:
        return _expression_2(name, built)
    # detect_leaks=0: an object-linked unit that inherits -fsanitize=address from
    # a contaminated tree must not fail on LeakSanitizer's exit report; real heap
    # errors still abort.
    ran = run([str(binary)], cwd=REPO_ROOT, env={"ASAN_OPTIONS": "detect_leaks=0"})
    return _expression_3(ran, name)


def run_checks(base: Path, names: list[str] | None = None) -> list[tuple[bool, str]]:
    selected = names or sorted(SPECS)
    results: list[tuple[bool, str]] = []
    for name in selected:
        work = base / name
        work.mkdir(parents=True, exist_ok=True)
        results.extend(run_one(name, work))
    return results


def entry(argv: list[str]) -> int:
    import tempfile

    names = argv or sorted(SPECS)
    with tempfile.TemporaryDirectory(prefix="c_object_units.") as tmp:
        results = run_checks(Path(tmp), names=names)
    return print_results(results, "c_object_units")


if __name__ == "__main__":
    from cmdscripts import main

    raise SystemExit(main(entry))
