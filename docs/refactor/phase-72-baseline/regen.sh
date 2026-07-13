#!/usr/bin/env bash
# Phase-72 measurement: lizard + CodeChecker over the module sources.
# Usage: docs/refactor/phase-72-baseline/regen.sh <outdir>
set -euo pipefail
OUT=${1:?outdir}; REPO=$(git rev-parse --show-toplevel); BUILD=/tmp/nginx-1.28.3
mkdir -p "$OUT"
lizard "$REPO"/src "$REPO"/shared "$REPO"/client -l c --csv > "$OUT/lizard.csv"
( cd "$BUILD" && make -Bn ) > "$OUT/make_dryrun.txt"
python3 - "$OUT" "$REPO" "$BUILD" <<'EOF'
import json,re,sys
out,repo,build=sys.argv[1],sys.argv[2],sys.argv[3]
lines=open(f"{out}/make_dryrun.txt").read().splitlines()
cmds,cur=[],""
for ln in lines:
    if ln.endswith("\\"): cur+=ln[:-1]+" "
    else: cmds.append(cur+ln); cur=""
ent=[]
for c in cmds:
    c=c.strip()
    if not re.match(r"^(cc|gcc|clang)\b",c) or " -c " not in c: continue
    srcs=[t for t in c.split() if t.endswith(".c")]
    if srcs and srcs[-1].startswith(repo):
        ent.append({"directory":build,"command":c,"file":srcs[-1]})
json.dump(ent,open(f"{out}/compile_commands.json","w"))
print(len(ent),"entries")
EOF
CodeChecker analyze "$OUT/compile_commands.json" -o "$OUT/cc_reports" \
    -j "$(nproc)" --analyzers clangsa clang-tidy
CodeChecker parse "$OUT/cc_reports" -e json > "$OUT/cc_reports.json" || true
