"""Python ports for C unit runners that link built module objects."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from cmdscripts.compile_run import REPO_ROOT, compile_binary, result, run

NGX_SRC = Path("/tmp/nginx-1.28.3")
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
        ),
    ),
    "slice": ObjectUnitSpec(
        "slice",
        "test_slice",
        (addon("cache/slice.o"), addon("cache/meta.o")),
        ("-O", "-Wall", "tests/c/test_slice.c", str(addon("cache/slice.o")), str(addon("cache/meta.o"))),
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
}


def run_one(name: str, base: Path) -> list[tuple[bool, str]]:
    spec = SPECS[name]
    missing = [str(path) for path in spec.required if not path.is_file()]
    if missing:
        return [result(True, f"SKIP {name}: build required object(s) first: {', '.join(missing)}")]
    binary = base / spec.binary
    built = compile_binary(binary, list(spec.args), cwd=REPO_ROOT)
    if built.returncode != 0:
        return [result(False, f"compile {name} failed: {(built.stderr or built.stdout)[-3000:]}")]
    ran = run([str(binary)], cwd=REPO_ROOT)
    return [result(ran.returncode == 0, f"{name} exited {ran.returncode}: {(ran.stderr or ran.stdout)[-3000:]}")]


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
    for ok, message in results:
        print(f"  {'ok  ' if ok else 'FAIL'} {message}")
    return 0 if all(ok for ok, _ in results) else 1


if __name__ == "__main__":
    from cmdscripts import main

    raise SystemExit(main(entry))
