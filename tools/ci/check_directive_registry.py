#!/usr/bin/env python3
#
# WHAT: Census every brix ngx_command_t directive registration across src/ —
#       including the #included directives_*.h fragment headers AND the
#       BRIX_*_DIRECTIVES X-macro expansions — classify each by plane
#       (http/stream), and enforce four anti-drift rules (phase-101 W9.1):
#
#         R1  same-plane duplicate name        (the W1 pmark-on-S3 bug class)
#         R2  prefixed twin of a bare name     (brix_webdav_X vs brix_X)
#         R3  name absent from directives.md   (doc drift)
#         R4  cross-module conf-poke in a setter (the dual-conf-poke pattern)
#
# WHY:  The config surface is shared across four HTTP protocol modules + the
#       stream plane. nginx is first-module-wins, so a name registered twice on
#       one plane makes the later copy dead code with NO config-time diagnostic
#       (exactly how SciTags-on-S3 was a silent no-op for a release). A prefixed
#       twin fragments "learn once, works everywhere". This checker makes both
#       structurally visible at the introducing commit.
#
# HOW:  A plain-array scan finds only ~226 of ~598 entries — the stream module
#       alone pulls ~260 via eight #included fragments, and the tier/async
#       families are X-macros. So the extractor (1) scans .c AND .h, (2) expands
#       every BRIX_*_DIRECTIVES instantiation by reading the pfx argument at the
#       site and the macro header's `ngx_string(pfx "...")` token list — family
#       growth is picked up automatically, no hand-maintained lists.
#
# USAGE:
#   tools/ci/check_directive_registry.py            # WARN mode: report, exit 0
#   tools/ci/check_directive_registry.py --fail     # gate mode: exit 1 on any
#                                                    # non-allowlisted finding
#
# Rollout (phase-101): WARN in the same commit as W2; flip to --fail in the CI
# lane once the W3-W6 renames empty the transitional R2 allowlist.
#
# Allowlist: tools/ci/directive_registry_allowlist.txt — one name per line, each
# with a mandatory `# reason`. An entry without a reason is itself a failure
# (tamper pin: a rule cannot be silenced by a bare name).

import os
import re
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
# The three inputs are env-overridable so the checker's own tests can point it at
# a fixture tree without disturbing the real scan.
SRC = os.environ.get("BRIX_REGISTRY_SRC") or os.path.join(ROOT, "src")
DOCS = os.environ.get("BRIX_REGISTRY_DOCS") or \
    os.path.join(ROOT, "docs", "03-configuration", "directives.md")
ALLOWLIST = os.environ.get("BRIX_REGISTRY_ALLOWLIST") or \
    os.path.join(os.path.dirname(os.path.abspath(__file__)),
                 "directive_registry_allowlist.txt")

PROTO_PREFIXES = ("webdav", "s3", "gridftp", "cvmfs")

# One ngx_command_t entry: { ngx_string("name"), <ctx ...CONF...>, <setter>, ...
_ENTRY = re.compile(
    r'\{\s*ngx_string\("([a-z0-9_]+)"\)\s*,\s*'
    r'((?:[^,{}]|\n)*?(?:CONF|ALL_CONF)(?:[^,{}]|\n)*?)\s*,\s*([A-Za-z0-9_]+)\s*,',
    re.S)

# A macro-body entry keyed off the pfx argument: { ngx_string(pfx "token"), <ctx>,
_MACRO_ENTRY = re.compile(
    r'\{\s*ngx_string\(pfx\s*"([a-z0-9_]+)"\)\s*,\s*'
    r'((?:[^,{}]|\n)*?(?:CONF|ALL_CONF)(?:[^,{}]|\n)*?)\s*,', re.S)

# A macro definition header: #define BRIX_FOO_DIRECTIVES(pfx, ...)
_MACRO_DEF = re.compile(r'#define\s+(BRIX_[A-Z0-9_]+_DIRECTIVES)\s*\(pfx\b')
# A macro instantiation site: BRIX_FOO_DIRECTIVES("brix_", conf_t, CTX, ...)
_MACRO_USE = re.compile(
    r'(BRIX_[A-Z0-9_]+_DIRECTIVES)\s*\(\s*"([a-z0-9_]*)"\s*,[^,]*,\s*([A-Za-z0-9_|]+)')


def _plane(ctx, path):
    """http | stream | None (malformed). Context flags win; path is the tiebreak
    for macro sites whose CTX token is an alias like BRIX_HTTP_ALL_CONF."""
    if "NGX_STREAM" in ctx or "BRIX_STREAM" in ctx:
        return "stream"
    if "NGX_HTTP" in ctx or "HTTP_ALL_CONF" in ctx or "BRIX_HTTP" in ctx:
        return "http"
    rel = path.replace(ROOT, "")
    if any(seg in rel for seg in ("/stream/", "/net/cms/", "/gridftp/", "/root/")):
        return "stream"
    if any(seg in rel for seg in ("/webdav/", "/s3/", "/cvmfs/", "http_common")):
        return "http"
    return None


def _macro_bodies():
    """{macro_name: [(token, ctx), ...]} for every BRIX_*_DIRECTIVES definition."""
    bodies = {}
    for dp, _, fs in os.walk(SRC):
        for f in fs:
            if not f.endswith(".h"):
                continue
            text = open(os.path.join(dp, f), errors="replace").read()
            for dm in _MACRO_DEF.finditer(text):
                name = dm.group(1)
                # the macro body runs to the end of the file or the next #define
                start = dm.start()
                nxt = text.find("#define ", dm.end())
                body = text[start: nxt if nxt > 0 else len(text)]
                bodies[name] = [(m.group(1), m.group(2).strip())
                                for m in _MACRO_ENTRY.finditer(body)]
    return bodies


def collect():
    """Return [(name, plane, kind, path)] for every registration in the tree."""
    macro_bodies = _macro_bodies()
    regs = []
    for dp, _, fs in os.walk(SRC):
        for f in fs:
            if not f.endswith((".c", ".h")):
                continue
            path = os.path.join(dp, f)
            text = open(path, errors="replace").read()

            # literal { ngx_string("...") , ... } entries
            for m in _ENTRY.finditer(text):
                if "offsetof" in m.group(3):
                    continue                       # struct-initialiser false positive
                regs.append((m.group(1), _plane(m.group(2), path), "literal", path))

            # X-macro instantiations: expand pfx + each macro-body token
            for u in _MACRO_USE.finditer(text):
                macro, pfx, ctx = u.group(1), u.group(2), u.group(3)
                for token, mctx in macro_bodies.get(macro, []):
                    plane = _plane(ctx, path) or _plane(mctx, path)
                    regs.append((pfx + token, plane, "macro", path))
    return regs


def _load_allowlist():
    """{name: reason}. A line without a '# reason' is a hard error (tamper pin)."""
    allow, bad = {}, []
    if os.path.exists(ALLOWLIST):
        for raw in open(ALLOWLIST):
            line = raw.rstrip("\n")
            if not line.strip() or line.lstrip().startswith("##"):
                continue
            name, sep, reason = line.partition("#")
            name = name.strip()
            if not name:
                continue
            if not sep or not reason.strip():
                bad.append(name)
            else:
                allow[name] = reason.strip()
    return allow, bad


def _documented():
    if not os.path.exists(DOCS):
        return set()
    text = open(DOCS, errors="replace").read()
    return set(re.findall(r'\bbrix_[a-z0-9_]+', text))


def _index_regs(regs):
    """(names set, {(name, plane): [paths]}) from the raw registration list."""
    by_name_plane = {}
    names = set()
    for name, plane, kind, path in regs:
        names.add(name)
        by_name_plane.setdefault((name, plane), []).append(path)
    return names, by_name_plane


def _rule_r1(by_name_plane, allow):
    """R1 — same-plane duplicate name (two registrations, one plane)."""
    out = []
    for (name, plane), paths in sorted(by_name_plane.items()):
        if plane is None:
            out.append(("R1?", name, f"unclassifiable plane at {paths[0]}"))
        elif len(paths) > 1 and name not in allow:
            out.append(("R1", name,
                        f"same-plane ({plane}) duplicate: {len(paths)} regs "
                        f"({', '.join(os.path.relpath(p, ROOT) for p in sorted(set(paths)))})"))
    return out


def _rule_r2(names, allow):
    """R2 — prefixed twin of an existing bare name (brix_webdav_X vs brix_X)."""
    out = []
    bare = {n for n in names if n.startswith("brix_")}
    for name in sorted(names):
        for p in PROTO_PREFIXES:
            pre = f"brix_{p}_"
            if name.startswith(pre):
                twin = "brix_" + name[len(pre):]
                if twin in bare and name not in allow:
                    out.append(("R2", name, f"prefixed twin of {twin}"))
    return out


def _rule_r3(names, documented, allow):
    """R3 — registered name absent from directives.md."""
    out = []
    for name in sorted(names):
        if name.startswith("brix_") and name not in documented and name not in allow:
            out.append(("R3", name, "not documented in directives.md"))
    return out


def _rule_r4(allow):
    """R4 — cross-module conf-poke inside a setter."""
    out = []
    poke = re.compile(r'(ngx_http_conf_get_module_loc_conf|ngx_stream_conf_get_module_srv_conf)'
                      r'\s*\(\s*cf\s*,')
    for dp, _, fs in os.walk(SRC):
        for f in fs:
            if not f.endswith(".c"):
                continue
            path = os.path.join(dp, f)
            rel = os.path.relpath(path, ROOT)
            for m in poke.finditer(open(path, errors="replace").read()):
                key = f"{rel}:{m.group(1)}"
                if key not in allow and rel not in allow:
                    out.append(("R4", key, "cross-module conf-poke in a setter"))
    return out


# ---- R5 (phase-105 W5.2): bare name => common owner, HTTP plane ---------- #
# The HTTP plane's bare cross-protocol names must register on the common
# module (or its fragment headers / the tier X-macro header). Feature-scoped
# families (brix_<feature>_*) owned by their own feature module are fine, as
# are the per-feature enable toggles. The stream plane is out of scope: the
# root module IS that plane's primary owner by design (101-W3 disposition).
HTTP_COMMON_OWNERS = (
    "core/config/http_common.c",
    "core/config/http_directives_core.h",
    "core/config/http_directives_auth.h",
    "core/config/http_directives_ops.h",
    "core/config/tier_directives.h",
)
# feature prefix -> owner path fragment that legitimately registers it
FEATURE_OWNERS = {
    "admin":     "observability/dashboard/",
    "dashboard": "observability/dashboard/",
    "guard":     "net/httpguard/",
    "srr":       "protocols/srr/",
    "metrics":   "observability/metrics/",
    "health":    "observability/metrics/",
    "scvmfs":    "protocols/cvmfs/",
}
# per-feature enable toggles registered by the feature module itself
FEATURE_TOGGLES = {
    "brix_webdav":    "protocols/webdav/",
    "brix_s3":        "protocols/s3/",
    "brix_cvmfs":     "protocols/cvmfs/",
    "brix_scvmfs":    "protocols/cvmfs/",
    "brix_dashboard": "observability/dashboard/",
    "brix_guard":     "net/httpguard/",
    "brix_health":    "observability/metrics/",
    "brix_metrics":   "observability/metrics/",
    "brix_srr":       "protocols/srr/",
}


def _rule_r5(regs, allow):
    """R5 — bare HTTP-plane name registered outside the common owner."""
    out, seen = [], set()
    for name, plane, kind, path in regs:
        if plane != "http" or not name.startswith("brix_") or name in seen:
            continue
        if any(name.startswith(f"brix_{p}_") for p in PROTO_PREFIXES):
            continue                                # protocol-prefixed: R2's job
        rel = os.path.relpath(path, ROOT).replace(os.sep, "/")
        if any(rel.endswith(o) for o in HTTP_COMMON_OWNERS):
            continue                                # the common owner
        feat = name[len("brix_"):].split("_", 1)[0]
        if FEATURE_OWNERS.get(feat) and FEATURE_OWNERS[feat] in rel:
            continue                                # feature family, self-owned
        if FEATURE_TOGGLES.get(name) and FEATURE_TOGGLES[name] in rel:
            continue                                # enable toggle, self-owned
        if name in allow:
            continue
        seen.add(name)
        out.append(("R5", name,
                    f"bare HTTP name owned by {rel}, not the common module "
                    f"(first-module-wins makes sibling-protocol use silently "
                    f"inert or accidental)"))
    return out


# ---- R6 (phase-105 W5.3): cross-spelling near-miss stems ------------------ #
# Two different spellings whose normalized stems collide are one concept
# drifting apart (brix_webdav_maxdelay vs brix_max_delay — the W3 class).
# Normalization: drop "brix_", protocol prefixes, plane tokens, underscores.
R6_PLANE_TOKENS = ("gsi_", "stream_")


def _r6_stem(name):
    s = name[len("brix_"):] if name.startswith("brix_") else name
    for p in PROTO_PREFIXES:
        if s.startswith(p + "_"):
            s = s[len(p) + 1:]
            break
    for t in R6_PLANE_TOKENS:
        if s.startswith(t):
            s = s[len(t):]
            break
    return s.replace("_", "")


def _rule_r6(names, allow):
    """R6 — distinct spellings sharing one normalized stem."""
    out = []
    stems = {}
    for name in names:
        if name.startswith("brix_"):
            stems.setdefault(_r6_stem(name), set()).add(name)
    for stem, group in sorted(stems.items()):
        if len(group) < 2:
            continue
        if any(n in allow for n in group):
            continue
        pretty = ", ".join(sorted(group))
        out.append(("R6", pretty, f"near-miss spellings share stem '{stem}'"))
    return out


def _report(findings, fail_mode):
    """Group findings by rule, print them, and return the process exit code."""
    by_rule = {}
    for rule, name, why in findings:
        by_rule.setdefault(rule, []).append((name, why))
    for rule in sorted(by_rule):
        print(f"\n[{rule}] {len(by_rule[rule])} finding(s):")
        for name, why in by_rule[rule]:
            print(f"  {name}: {why}")

    # phase-105 W5.4: R1/R2/R4/R5/R6 gate under --fail; R3 stays WARN-scoped
    # until W6 (docs-from-source) closes the 300+ backlog structurally.
    hard = [f for f in findings
            if f[0] in ("R1", "R2", "R4", "R5", "R6", "ALLOWLIST")]
    if fail_mode and hard:
        print(f"\ncheck_directive_registry: FAIL — {len(hard)} gating finding(s)",
              file=sys.stderr)
        return 1
    print("\ncheck_directive_registry: WARN — findings reported, not gating "
          "(R3 gates after phase-105 W6; run with --fail for R1/R2/R4/R5/R6)")
    return 0


def main(argv):
    fail_mode = "--fail" in argv
    regs = collect()
    allow, bad_allow = _load_allowlist()
    documented = _documented()

    names, by_name_plane = _index_regs(regs)

    findings = []
    findings += _rule_r1(by_name_plane, allow)
    findings += _rule_r2(names, allow)
    findings += _rule_r3(names, documented, allow)
    findings += _rule_r4(allow)
    findings += _rule_r5(regs, allow)
    findings += _rule_r6(names, allow)
    # tamper pin: an allowlist line without a reason is itself a failure.
    for name in bad_allow:
        findings.append(("ALLOWLIST", name, "allowlist entry missing a '# reason'"))

    print(f"check_directive_registry: {len(regs)} registrations, "
          f"{len(names)} unique names, {len(allow)} allowlisted")

    if not findings:
        print("check_directive_registry: OK — no drift")
        return 0

    return _report(findings, fail_mode)


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
