"""Heuristic allocation/free invariant lint."""

from __future__ import annotations

from pathlib import Path
import re

from cmdscripts.compile_run import REPO_ROOT

SRC = REPO_ROOT / "src"
ALLOC_MUL_RE = re.compile(r"(malloc|ngx_alloc|ngx_palloc|realloc)\([^;]*\*[^;]*sizeof")
RAW_HTTP_RE = re.compile(r"\b(malloc|free)\s*\(")
OPENSSL_NEW_RE = re.compile(r"[A-Za-z0-9_]+_new\s*\(")
OPENSSL_FREE_RE = re.compile(r"[A-Za-z0-9_]+_free(?:_all)?\s*\(")


def c_files(paths: list[Path]) -> list[Path]:
    out: list[Path] = []
    for root in paths:
        if root.is_dir():
            out.extend(sorted(root.rglob("*.c")))
    return out


def rel(path: Path) -> str:
    return str(path.relative_to(REPO_ROOT))


def lines(path: Path) -> list[str]:
    return path.read_text(encoding="utf-8", errors="ignore").splitlines()


def allocation_multiply_findings() -> list[str]:
    findings = []
    for path in c_files([SRC]):
        file_lines = lines(path)
        for index, text in enumerate(file_lines, start=1):
            if not ALLOC_MUL_RE.search(text):
                continue
            if re.search(r"brix_(p?alloc|alloc)_array|brix_size_mul|safe_size", text):
                continue
            context = "\n".join(file_lines[max(0, index - 4) : index])
            if re.search(r"brix_size_mul|brix_.*_array", context):
                continue
            findings.append(f"  {rel(path)}:{index}  {text.strip()}")
    return findings


def raw_http_findings() -> list[str]:
    findings = []
    for path in c_files([SRC / "webdav", SRC / "s3"]):
        for index, text in enumerate(lines(path), start=1):
            if RAW_HTTP_RE.search(text) and not re.search(r"curl_|json_|EVP_|OPENSSL_|_free_all|ngx_", text):
                findings.append(f"  {rel(path)}:{index}  {text.strip()}")
    return findings


def stream_alloc_findings() -> list[str]:
    findings = []
    for name in ("connection", "session", "cms", "manager", "handshake", "read", "write", "tpc"):
        for path in sorted((SRC / name).glob("*.c")):
            text = path.read_text(encoding="utf-8", errors="ignore")
            if "ngx_alloc" in text and not re.search(r"\bngx_free\s*\(|ngx_pool_cleanup_add", text):
                findings.append(f"  {rel(path)}  (ngx_alloc with no ngx_free/cleanup in file)")
    return findings


def openssl_balance_findings() -> list[str]:
    findings = []
    for path in c_files([SRC / p for p in ("gsi", "tpc", "crypto", "token", "s3", "sss")]):
        text = path.read_text(encoding="utf-8", errors="ignore")
        new_count = len(OPENSSL_NEW_RE.findall(text))
        free_count = len(OPENSSL_FREE_RE.findall(text))
        if new_count > 0 and free_count < new_count:
            findings.append(f"  {rel(path)}  new={new_count} free={free_count}")
    return findings


def run_checks(strict: bool = False) -> tuple[int, str]:
    sections = [
        ("== [1] unchecked size-multiply allocations ==", allocation_multiply_findings(), False),
        ("== [2] raw malloc/free in HTTP handlers (prefer r->pool) ==", raw_http_findings(), True),
        ("== [3] ngx_alloc without ngx_free/cleanup in same file (stream path) ==", stream_alloc_findings(), True),
        ("== [4] OpenSSL new/free token imbalance (advisory) ==", openssl_balance_findings(), False),
    ]
    lines_out: list[str] = []
    hard_findings = 0
    for title, findings, hard in sections:
        lines_out.append(title)
        lines_out.extend(findings)
        if hard:
            hard_findings += len(findings)
    lines_out.append("")
    lines_out.append(f"lint_alloc: {hard_findings} hard finding(s) (checks 2 & 3); checks 1 & 4 advisory.")
    return (1 if strict and hard_findings else 0), "\n".join(lines_out)


def entry(argv: list[str]) -> int:
    strict = bool(argv and argv[0] == "--strict")
    rc, output = run_checks(strict=strict)
    print(output)
    return rc


if __name__ == "__main__":
    from cmdscripts import main

    raise SystemExit(main(entry))
