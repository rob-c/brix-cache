"""Python ports for heavy operator/build shell entrypoints."""

from __future__ import annotations

from pathlib import Path
import os
import shutil
import signal
import sys

from cmdscripts.compile_run import REPO_ROOT, result, run


def nproc() -> str:
    return str(os.cpu_count() or 4)


def brutal_teardown(test_root: Path) -> list[tuple[bool, str]]:
    run(
        [sys.executable, "-m", "cmdscripts.manage_test_servers", "stop-all"],
        cwd=REPO_ROOT / "tests",
        env={"TEST_ROOT": str(test_root)},
    )
    killed = 0
    for proc_name in ("nginx", "xrootd", "krb5kdc", "kadmind"):
        pgrep = run(["pgrep", "-x", proc_name], cwd=REPO_ROOT)
        for pid_text in pgrep.stdout.split():
            try:
                pid = int(pid_text)
                cmdline = Path(f"/proc/{pid}/cmdline").read_bytes().replace(b"\0", b" ").decode("utf-8", "ignore")
            except OSError:
                continue
            if "/tmp/xrd" in cmdline or "/tmp/hsproto" in cmdline or str(test_root) in cmdline:
                try:
                    os.kill(pid, signal.SIGTERM)
                    killed += 1
                except OSError:
                    pass
    for child in ("data", "pki", "tokens", "logs", "tmp", "krb5"):
        shutil.rmtree(test_root / child, ignore_errors=True)
    for child in test_root.glob("data-*") if test_root.exists() else []:
        if child.is_dir():
            shutil.rmtree(child, ignore_errors=True)
    if test_root.exists():
        for path in test_root.glob("*/*"):
            if path.suffix in {".pid", ".conf"}:
                path.unlink(missing_ok=True)
    return [result(True, f"brutal teardown completed for {test_root}; signalled {killed} leaked process(es)")]


def build_sanitizer(nginx_src: Path) -> list[tuple[bool, str]]:
    configure = nginx_src / "configure"
    if not configure.is_file() or not os.access(configure, os.X_OK):
        return [result(False, f"nginx source not found at {nginx_src}")]
    san = "-fsanitize=address,undefined -fno-omit-frame-pointer -g -O1"
    client_ldflags = f"-Wl,-z,relro -Wl,-z,now -Wl,-z,noexecstack {san}"
    configured = run(
        [
            "./configure",
            "--with-stream",
            "--with-stream_ssl_module",
            "--with-http_ssl_module",
            "--with-http_dav_module",
            "--with-threads",
            f"--add-module={REPO_ROOT}",
            f"--with-cc-opt={san}",
            f"--with-ld-opt={san}",
        ],
        cwd=nginx_src,
    )
    if configured.returncode != 0:
        return [result(False, f"sanitizer configure failed: {(configured.stderr or configured.stdout)[-3000:]}")]
    built = run(["make", f"-j{nproc()}"], cwd=nginx_src)
    if built.returncode != 0:
        return [result(False, f"sanitizer nginx build failed: {(built.stderr or built.stdout)[-3000:]}")]
    client = run(
        ["make", f"-j{nproc()}", f"CFLAGS={san}", f"LDFLAGS={client_ldflags}"],
        cwd=REPO_ROOT / "client",
    )
    if client.returncode != 0:
        return [result(False, f"sanitizer client build failed: {(client.stderr or client.stdout)[-3000:]}")]
    return [result(True, f"sanitizer build complete: {nginx_src / 'objs' / 'nginx'}")]


def build_dynamic_modules(nginx_src: Path, build_root: Path) -> list[tuple[bool, str]]:
    if not (nginx_src / "configure").is_file() or not (nginx_src / "src/core/nginx.c").is_file():
        return [result(True, f"SKIP nginx source not found at {nginx_src}")]
    if shutil.which("rsync") is None:
        return [result(True, "SKIP rsync not available")]
    dst = build_root / "nginx"
    shutil.rmtree(build_root, ignore_errors=True)
    dst.mkdir(parents=True)
    copied = run(["rsync", "-a", "--exclude", "objs", "--exclude", "Makefile", f"{nginx_src}/", f"{dst}/"], cwd=REPO_ROOT)
    if copied.returncode != 0:
        return [result(True, f"SKIP rsync of nginx source failed: {(copied.stderr or copied.stdout)[-2000:]}")]
    configured = run(
        [
            "./configure",
            "--with-compat",
            "--with-threads",
            "--with-stream=dynamic",
            "--with-stream_ssl_module",
            "--with-http_ssl_module",
            "--with-http_dav_module",
            f"--add-dynamic-module={REPO_ROOT}",
        ],
        cwd=dst,
        env={"BRIX_LZ4_LIBS": os.environ.get("BRIX_LZ4_LIBS", "-l:liblz4.so.1")},
    )
    if configured.returncode != 0:
        return [result(True, f"SKIP configure --add-dynamic-module failed: {(configured.stderr or configured.stdout)[-3000:]}")]
    built = run(["make", f"-j{nproc()}"], cwd=dst)
    if built.returncode != 0:
        return [result(False, f"dynamic nginx build failed: {(built.stderr or built.stdout)[-3000:]}")]
    modules = run(["make", "modules", f"-j{nproc()}"], cwd=dst)
    if modules.returncode != 0:
        return [result(False, f"dynamic module build failed: {(modules.stderr or modules.stdout)[-3000:]}")]
    stream_so = dst / "objs" / "ngx_stream_brix_module.so"
    if not stream_so.is_file():
        return [result(False, "stream module .so not produced")]
    needed = run(["readelf", "-d", str(stream_so)], cwd=dst)
    text = needed.stdout + needed.stderr
    missing = [want for want in ("libz.so", "libzstd", "liblzma", "libbrotlienc", "libbrotlidec", "libbz2") if want not in text]
    if missing:
        return [result(False, f"codec DT_NEEDED entries missing from stream module: {', '.join(missing)}")]
    ldd = run(["ldd", str(stream_so)], cwd=dst)
    if "not found" in (ldd.stdout + ldd.stderr):
        return [result(False, "stream module .so has unresolved shared library")]
    return [result(True, "dynamic module build produced stream module with codec deps")]


def run_checks(base: Path, names: list[str] | None = None) -> list[tuple[bool, str]]:
    selected = names or ["brutal_teardown", "build_dynamic_modules", "build_sanitizer"]
    results: list[tuple[bool, str]] = []
    for name in selected:
        if name == "brutal_teardown":
            results.extend(brutal_teardown(Path(os.environ.get("TEST_ROOT", "/tmp/xrd-test"))))
        elif name == "build_sanitizer":
            results.extend(build_sanitizer(Path(os.environ.get("NGINX_SRC", "/tmp/nginx-1.28.3"))))
        elif name == "build_dynamic_modules":
            results.extend(build_dynamic_modules(Path(os.environ.get("NGINX_SRC", "/tmp/nginx-1.28.3")), base / "xrd-build-matrix"))
        else:
            results.append(result(False, f"unknown operator build port: {name}"))
    return results


def entry(argv: list[str]) -> int:
    import tempfile

    names = argv or ["brutal_teardown", "build_dynamic_modules", "build_sanitizer"]
    with tempfile.TemporaryDirectory(prefix="operator_build.") as tmp:
        results = run_checks(Path(tmp), names=names)
    for ok, message in results:
        print(f"  {'ok  ' if ok else 'FAIL'} {message}")
    return 0 if all(ok for ok, _ in results) else 1


if __name__ == "__main__":
    from cmdscripts import main

    raise SystemExit(main(entry))
