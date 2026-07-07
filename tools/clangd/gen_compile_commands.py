#!/usr/bin/env python3
"""Generate compile_commands.json for the nginx-xrootd C project.

WHAT: Emits a clang-style compilation database covering both the nginx module
      (src/, compiled out-of-tree by nginx's ./configure) and the native clients
      (client/, built by client/Makefile). clangd and clang-tidy read this for
      exact per-file flags; the committed .clangd provides the same include set
      as a fallback for files not present here (e.g. just-added sources).

WHY:  `bear` is not installed on this host, so we reconstruct the commands from
      the two authoritative sources of build flags:
        1. the nginx generated Makefile (objs/Makefile) for src/  — it records
           every addon object's source path plus the literal CFLAGS / ALL_INCS;
        2. client/Makefile's ALL_CFLAGS for client/.
      Relative -I paths in the nginx command resolve correctly because each
      src/ entry sets "directory" to the nginx build tree.

HOW:  python3 tools/clangd/gen_compile_commands.py  [--nginx /tmp/nginx-1.28.3]
      Writes compile_commands.json at the repo root (gitignored).
"""

import argparse
import json
import os
import re
import shlex
import sys

REPO = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
DEFAULT_NGINX = "/tmp/nginx-1.28.3"

# GCC-only / codegen flags that clang tooling does not need (and -Werror, which
# would turn analyzer diagnostics into hard errors). Kept in sync with .clangd.
DROP_PREFIXES = ("-Werror", "-fprofile", "-fcf-protection")
DROP_EXACT = {"-fstack-clash-protection", "-pipe", "-c"}


def _filter_flags(tokens):
    out = []
    skip_next = False
    for tok in tokens:
        if skip_next:
            skip_next = False
            continue
        if tok == "-o" or tok == "--param":
            skip_next = True
            continue
        if tok in DROP_EXACT:
            continue
        if tok.startswith(DROP_PREFIXES) or tok.startswith("--param"):
            continue
        out.append(tok)
    return out


def _grab_make_var(text, name):
    """Return the full (line-continuation-joined) value of `NAME = ...`.

    A make variable can span many physical lines via trailing `\\`. We collect
    lines starting at the assignment until one does not end in a backslash, then
    drop every continuation backslash so the result is a flat token string that
    shlex can parse (a lone trailing `\\` would raise "No escaped character").
    """
    lines = text.splitlines()
    start = None
    for i, line in enumerate(lines):
        if re.match(rf"^{re.escape(name)}\s*=", line):
            start = i
            break
    if start is None:
        return ""
    collected = []
    for line in lines[start:]:
        cont = line.rstrip().endswith("\\")
        collected.append(line.rstrip().rstrip("\\"))
        if not cont:
            break
    value = " ".join(collected)
    # Strip the leading "NAME =" so only the flag tokens remain.
    return re.sub(rf"^{re.escape(name)}\s*=\s*", "", value)


def nginx_entries(nginx_dir):
    """Build entries for every src/ addon object from objs/Makefile."""
    mk = os.path.join(nginx_dir, "objs", "Makefile")
    if not os.path.isfile(mk):
        print(f"warning: {mk} not found — skipping src/ (build nginx first)",
              file=sys.stderr)
        return []
    text = open(mk, encoding="utf-8", errors="replace").read()

    cflags = _grab_make_var(text, "CFLAGS")
    all_incs = _grab_make_var(text, "ALL_INCS")
    base = _filter_flags(shlex.split(cflags) + shlex.split(all_incs))

    # Each addon object rule: "objs/addon/<...>.o:\t$(ADDON_DEPS) \\\n\t<abs .c>"
    entries, seen = [], set()
    for m in re.finditer(r"^objs/addon/\S+\.o:.*?\n((?:\t.*\n)+)", text, re.M):
        block = m.group(1)
        src = None
        for line in block.splitlines():
            line = line.strip().rstrip("\\").strip()
            if line.endswith(".c"):
                src = line
        if not src or src in seen:
            continue
        seen.add(src)
        cmd = ["clang", "-c"] + base + ["-o", "/dev/null", src]
        entries.append({"directory": nginx_dir, "file": src,
                        "arguments": cmd})
    return entries


def client_entries():
    """Build entries for client/ sources from client/Makefile's ALL_CFLAGS."""
    client = os.path.join(REPO, "client")
    mk = os.path.join(client, "Makefile")
    if not os.path.isfile(mk):
        return []

    flags = ["-std=c11", "-D_GNU_SOURCE", "-pthread",
             "-Ilib", f"-I{os.path.join(REPO, 'src')}",
             f"-I{os.path.join(REPO, 'shared', 'xrdproto')}",
             "-DXROOTD_HAVE_KRB5", "-I/usr/include/fuse3"]

    entries = []
    for root, _dirs, files in os.walk(client):
        if "/bin" in root:
            continue
        for fn in files:
            if not fn.endswith(".c"):
                continue
            path = os.path.join(root, fn)
            cmd = ["clang", "-c"] + flags + ["-o", "/dev/null", path]
            entries.append({"directory": client, "file": path,
                            "arguments": cmd})
    return entries


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--nginx", default=DEFAULT_NGINX,
                    help=f"nginx build tree (default: {DEFAULT_NGINX})")
    ap.add_argument("-o", "--output",
                    default=os.path.join(REPO, "compile_commands.json"))
    args = ap.parse_args()

    db = nginx_entries(args.nginx) + client_entries()
    with open(args.output, "w", encoding="utf-8") as fh:
        json.dump(db, fh, indent=2)
        fh.write("\n")
    print(f"wrote {len(db)} entries to {args.output}")


if __name__ == "__main__":
    main()
