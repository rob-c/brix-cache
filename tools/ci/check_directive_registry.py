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
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from directive_registry_w5 import (   # phase-110 W5 rules (file-size split)
    _rule_r11, _rule_r12, _rule_r13, _rule_r14, _phase_is_implemented,
    _vocab_findings_for, _missing_tokens, _R13_REQUIRED_JSON_KEYS)

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

_STREAM_PATH_SEGS = ("/stream/", "/net/cms/", "/gridftp/", "/root/")
_HTTP_PATH_SEGS = ("/webdav/", "/s3/", "/cvmfs/", "http_common")


def _walk_src(*suffixes):
    """Yield (path, text) for every file under SRC whose name ends in one of
    `suffixes` — the read-every-source-file spine the extractors share."""
    for dp, _, fs in os.walk(SRC):
        for f in fs:
            if f.endswith(suffixes):
                path = os.path.join(dp, f)
                yield path, open(path, errors="replace").read()

# One ngx_command_t entry: { ngx_string("name"), <ctx ...CONF...>, <setter>, ...
_ENTRY = re.compile(
    r'\{\s*ngx_string\("([a-z0-9_]+)"\)\s*,\s*'
    r'((?:[^,{}]|\n)*?(?:CONF|ALL_CONF)(?:[^,{}]|\n)*?)\s*,\s*([A-Za-z0-9_]+)\s*,',
    re.S)

# A macro-body entry: keyed off the pfx argument ({ ngx_string(pfx "token") …)
# or a bare literal inside a scope-parameterized body ({ ngx_string("token") …,
# the pmark shape — its plane comes from the conf_scope argument at each
# instantiation site, not from the body).
_MACRO_ENTRY = re.compile(
    r'\{\s*ngx_string\((?:pfx\s*)?"([a-z0-9_]+)"\)\s*,\s*'
    r'((?:[^,{}]|\n)*?(?:CONF|ALL_CONF)(?:[^,{}]|\n)*?)\s*,', re.S)

# A macro definition header: #define BRIX_FOO_DIRECTIVES(pfx, ...) or the
# scope-parameterized form #define BRIX_FOO_DIRECTIVES(conf_scope, ...).
_MACRO_DEF = re.compile(
    r'#define\s+(BRIX_[A-Z0-9_]+_DIRECTIVES)\s*\((?:pfx|conf_scope)\b')
# A macro instantiation site: BRIX_FOO_DIRECTIVES("brix_", conf_t, CTX, ...)
_MACRO_USE = re.compile(
    r'(BRIX_[A-Z0-9_]+_DIRECTIVES)\s*\(\s*"([a-z0-9_]*)"\s*,[^,]*,\s*([A-Za-z0-9_|]+)')
# The scope-parameterized instantiation: BRIX_FOO_DIRECTIVES(NGX_STREAM_SRV_CONF, ...)
_MACRO_USE_SCOPED = re.compile(
    r'(BRIX_[A-Z0-9_]+_DIRECTIVES)\s*\(\s*([A-Za-z0-9_|]*CONF[A-Za-z0-9_|]*)\s*,')


def _plane_from_ctx(ctx):
    """http | stream | None from the CONF context flags alone."""
    if "NGX_STREAM" in ctx or "BRIX_STREAM" in ctx:
        return "stream"
    if "NGX_HTTP" in ctx or "HTTP_ALL_CONF" in ctx or "BRIX_HTTP" in ctx:
        return "http"
    return None


def _plane_from_path(path):
    """http | stream | None from the owning file's path — the tiebreak for macro
    sites whose CTX token is an alias like BRIX_HTTP_ALL_CONF."""
    rel = path.replace(ROOT, "")
    if any(seg in rel for seg in _STREAM_PATH_SEGS):
        return "stream"
    if any(seg in rel for seg in _HTTP_PATH_SEGS):
        return "http"
    return None


def _plane(ctx, path):
    """http | stream | None (malformed). Context flags win; path is the tiebreak."""
    return _plane_from_ctx(ctx) or _plane_from_path(path)


def _macro_body_entries(text, dm):
    """[(token, ctx)] for one BRIX_*_DIRECTIVES definition matched at `dm` — its
    body runs to the next #define or the end of the file."""
    nxt = text.find("#define ", dm.end())
    body = text[dm.start(): nxt if nxt > 0 else len(text)]
    return [(m.group(1), m.group(2).strip())
            for m in _MACRO_ENTRY.finditer(body)]


def _macro_bodies():
    """{macro_name: [(token, ctx), ...]} for every BRIX_*_DIRECTIVES definition."""
    bodies = {}
    for _path, text in _walk_src(".h"):
        for dm in _MACRO_DEF.finditer(text):
            bodies[dm.group(1)] = _macro_body_entries(text, dm)
    return bodies


def _literal_regs(text, path):
    """[(name, plane, "literal", path)] for the { ngx_string("...") , ... }
    entries in one file; struct-initialiser false positives (offsetof) skipped."""
    return [(m.group(1), _plane(m.group(2), path), "literal", path)
            for m in _ENTRY.finditer(text)
            if "offsetof" not in m.group(3)
            and "\\\n" not in m.group(0)]   # macro-body lines (…\) are not
                                            # registrations — expanded per site


def _macro_sites(text):
    """(macro, pfx, ctx) per X-macro instantiation — the scope-parameterized
    form (pmark) carries no pfx argument."""
    sites = [(u.group(1), u.group(2), u.group(3))
             for u in _MACRO_USE.finditer(text)]
    sites += [(u.group(1), "", u.group(2))
              for u in _MACRO_USE_SCOPED.finditer(text)]
    return sites


def _macro_regs(text, path, macro_bodies):
    """[(pfx+token, plane, "macro", path)] for every X-macro instantiation in one
    file, expanded against the collected macro bodies."""
    return [(pfx + token, _plane(ctx, path) or _plane(mctx, path),
             "macro", path)
            for macro, pfx, ctx in _macro_sites(text)
            for token, mctx in macro_bodies.get(macro, [])]


def collect():
    """Return [(name, plane, kind, path)] for every registration in the tree."""
    macro_bodies = _macro_bodies()
    regs = []
    for path, text in _walk_src(".c", ".h"):
        regs.extend(_literal_regs(text, path))
        regs.extend(_macro_regs(text, path, macro_bodies))
    return regs


def _allowlist_line(line, allow, bad):
    """Classify one allowlist line into `allow` / `bad`; blank + `##` comment
    lines and bare-name (no reason) lines are handled here."""
    if not line.strip() or line.lstrip().startswith("##"):
        return
    name, sep, reason = line.partition("#")
    name = name.strip()
    if not name:
        return
    if not sep or not reason.strip():
        bad.append(name)
    else:
        allow[name] = reason.strip()


def _load_allowlist():
    """{name: reason}. A line without a '# reason' is a hard error (tamper pin)."""
    allow, bad = {}, []
    if os.path.exists(ALLOWLIST):
        for raw in open(ALLOWLIST):
            _allowlist_line(raw.rstrip("\n"), allow, bad)
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
    for (name, plane), paths in sorted(by_name_plane.items(),
                                       key=lambda kv: (kv[0][0], kv[0][1] or "")):
        if plane is None:
            out.append(("R1?", name, f"unclassifiable plane at {paths[0]}"))
        elif len(paths) > 1 and name not in allow:
            out.append(("R1", name,
                        f"same-plane ({plane}) duplicate: {len(paths)} regs "
                        f"({', '.join(os.path.relpath(p, ROOT) for p in sorted(set(paths)))})"))
    return out


def _r2_twin(name, bare):
    """The bare twin (brix_X) of a protocol-prefixed name (brix_webdav_X) when
    that twin is itself a registered bare name; else None."""
    for p in PROTO_PREFIXES:
        pre = f"brix_{p}_"
        if name.startswith(pre):
            twin = "brix_" + name[len(pre):]
            return twin if twin in bare else None
    return None


def _rule_r2(names, allow):
    """R2 — prefixed twin of an existing bare name (brix_webdav_X vs brix_X)."""
    out = []
    bare = {n for n in names if n.startswith("brix_")}
    for name in sorted(names):
        twin = _r2_twin(name, bare)
        if twin is not None and name not in allow:
            out.append(("R2", name, f"prefixed twin of {twin}"))
    return out


def _rule_r3(names, documented, allow):
    """R3 — registered name absent from directives.md."""
    out = []
    for name in sorted(names):
        if name.startswith("brix_") and name not in documented and name not in allow:
            out.append(("R3", name, "not documented in directives.md"))
    return out


_R4_POKE = re.compile(
    r'(ngx_http_conf_get_module_loc_conf|ngx_stream_conf_get_module_srv_conf)'
    r'\s*\(\s*cf\s*,')


def _r4_file_findings(path, text, allow):
    """R4 findings for one .c file's cross-module conf-poke sites."""
    rel = os.path.relpath(path, ROOT)
    out = []
    for m in _R4_POKE.finditer(text):
        key = f"{rel}:{m.group(1)}"
        if key not in allow and rel not in allow:
            out.append(("R4", key, "cross-module conf-poke in a setter"))
    return out


def _rule_r4(allow):
    """R4 — cross-module conf-poke inside a setter."""
    out = []
    for path, text in _walk_src(".c"):
        out.extend(_r4_file_findings(path, text, allow))
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
    # phase-104 software-distribution plane: the brix_oci_* / brix_rpm_*
    # families are feature-scoped and owned by their own modules by design.
    "oci":       "protocols/oci/",
    "rpm":       "protocols/rpm/",
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


def _r5_legitimate_owner(name, rel):
    """True when a bare HTTP name `rel` legitimately registers: the common owner,
    a self-owned feature family, or a self-owned enable toggle."""
    if any(rel.endswith(o) for o in HTTP_COMMON_OWNERS):
        return True
    feat = name[len("brix_"):].split("_", 1)[0]
    if FEATURE_OWNERS.get(feat) and FEATURE_OWNERS[feat] in rel:
        return True
    return bool(FEATURE_TOGGLES.get(name) and FEATURE_TOGGLES[name] in rel)


def _r5_in_scope(name, plane, seen):
    """True when this registration is a fresh, bare (non-protocol-prefixed) HTTP
    name R5 should judge."""
    if plane != "http" or not name.startswith("brix_") or name in seen:
        return False
    return not any(name.startswith(f"brix_{p}_") for p in PROTO_PREFIXES)


def _r5_offender(name, plane, path, allow, seen):
    """The R5 finding for one registration, or None when out of scope or clean."""
    if not _r5_in_scope(name, plane, seen):
        return None
    rel = os.path.relpath(path, ROOT).replace(os.sep, "/")
    if _r5_legitimate_owner(name, rel) or name in allow:
        return None
    return ("R5", name,
            f"bare HTTP name owned by {rel}, not the common module "
            f"(first-module-wins makes sibling-protocol use silently "
            f"inert or accidental)")


def _rule_r5(regs, allow):
    """R5 — bare HTTP-plane name registered outside the common owner."""
    out, seen = [], set()
    for name, plane, _kind, path in regs:
        finding = _r5_offender(name, plane, path, allow, seen)
        if finding is not None:
            seen.add(name)
            out.append(finding)
    return out


# ---- R6 (phase-105 W5.3): cross-spelling near-miss stems ------------------ #
# Two different spellings whose normalized stems collide are one concept
# drifting apart (brix_webdav_maxdelay vs brix_max_delay — the W3 class).
# Normalization: drop "brix_", protocol prefixes, plane tokens, underscores.
R6_PLANE_TOKENS = ("gsi_", "stream_")


def _strip_first_prefix(s, prefixes):
    """Drop the first of `prefixes` that `s` starts with (once); else `s`."""
    for p in prefixes:
        if s.startswith(p):
            return s[len(p):]
    return s


def _r6_stem(name):
    s = name[len("brix_"):] if name.startswith("brix_") else name
    s = _strip_first_prefix(s, tuple(p + "_" for p in PROTO_PREFIXES))
    s = _strip_first_prefix(s, R6_PLANE_TOKENS)
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


def _print_findings_by_rule(findings):
    """Group findings by rule and print each group."""
    by_rule = {}
    for rule, name, why in findings:
        by_rule.setdefault(rule, []).append((name, why))
    for rule in sorted(by_rule):
        print(f"\n[{rule}] {len(by_rule[rule])} finding(s):")
        for name, why in by_rule[rule]:
            print(f"  {name}: {why}")


def _report(findings, fail_mode):
    """Group findings by rule, print them, and return the process exit code."""
    _print_findings_by_rule(findings)

    # phase-105 W5.4: R1/R2/R4/R5/R6 gate under --fail; R3 stays WARN-scoped
    # until W6 (docs-from-source) closes the 300+ backlog structurally.
    # phase-106 W8: R7 (variable naming), R9 (plane parity) and R10 (the
    # credential-exposure SECURITY rule) gate too — their backlogs are already
    # empty, so they gate from the first commit. R8 (variable docs) stays
    # WARN-scoped alongside R3, the same docs-from-source posture.
    gating = ("R1", "R2", "R4", "R5", "R6", "R7", "R9", "R10",
              "R11", "R12", "R13", "R14", "ALLOWLIST")
    hard = [f for f in findings if f[0] in gating]
    if fail_mode and hard:
        print(f"\ncheck_directive_registry: FAIL — {len(hard)} gating finding(s)",
              file=sys.stderr)
        return 1
    print("\ncheck_directive_registry: WARN — findings reported, not gating "
          "(R3/R8 gate after their docs-from-source backlogs close; run with "
          "--fail for R1/R2/R4/R5/R6/R7/R9/R10/R11/R12/R13/R14)")
    return 0



# ---- R7-R10 (phase-106 W8): the VARIABLE surface ------------------------- #
#
# Directives got governance in phases 101/105 (R1-R6) because a naming and
# ownership surface drifts silently.  The variable surface never did, and it
# shows: 7 of the 9 variables that existed before phase 106 are unprefixed
# ($cvmfs_cache, $oci_class, ...), three planes invented three different
# cache-status vocabularies, and nothing stopped a future variable from
# carrying credential material into an operator's log file.
#
# R10 is the security rule and gates from the first commit — it has exactly one
# reviewed allowlist entry.  R7/R8/R9 report until their backlogs are empty.

# Variable registrations, both planes.
_VAR_ARRAY_RE = re.compile(
    r'ngx_(?:http|stream)_variable_t\s+\w+\[\]\s*=\s*\{(.*?)\n\};',
    re.S)
_VAR_NAME_RE = re.compile(r'ngx_string\("([a-z_][a-z0-9_]*)"\)')

# Names that would place credential material into anything loggable.
_CREDENTIAL_PATTERNS = ("token", "secret", "key", "password", "passwd",
                        "macaroon", "authorization", "bearer", "private")

# The single reviewed exception: it exists to hand a delegated credential to
# proxy_ssl_certificate, and predates this rule.
_R10_ALLOW = {"brix_delegated_cred"}


def _collect_variables():
    """(name, relpath) for every nginx variable a brix module registers."""
    found = []
    for path, text in _walk_src(".c"):
        if "variable_t" not in text:
            continue
        found += _variables_in(text, os.path.relpath(path, ROOT))
    return found


def _variables_in(text, rel):
    """Variable (name, rel) pairs registered by one source file."""
    out = [(name, rel)
           for block in _VAR_ARRAY_RE.findall(text)
           for name in _VAR_NAME_RE.findall(block)]
    out += _direct_variables_in(text, rel)
    return out


def _direct_variables_in(text, rel):
    """ngx_*_add_variable(cf, &local, ...) registrations.
    The variable NAME must be the identifier actually handed to add_variable —
    matching every local ngx_str_t in a file that merely contains an
    add_variable call elsewhere produces false positives (a thread-pool name,
    a header name, ...).
    """
    registered = set(re.findall(r'add_variable\(\s*cf\s*,\s*&(\w+)', text))
    return [(m.group(2), rel)
            for m in re.finditer(
                r'ngx_str_t\s+(\w+)\s*=\s*ngx_string\("([a-z_][a-z0-9_]*)"\)',
                text)
            if m.group(1) in registered]


def _rule_r7(variables, allow):
    """R7 — every brix-registered variable is brix_-prefixed."""
    out = []
    for name, rel in sorted(set(variables)):
        if name.startswith("brix_") or name in allow:
            continue
        out.append(("R7", name,
                    f"variable is not brix_-prefixed ({rel}); an unprefixed "
                    "name sits in nginx's global namespace and collides with "
                    "any other module registering it"))
    return out


def _var_plane(rel):
    """Which nginx subsystem a variable registration belongs to."""
    return "stream" if "stream" in rel else "http"


def _rule_r9(variables, allow):
    """R9 — plane parity: a name may appear once per plane, never twice within
    one plane.

    Registering the SAME name on both the http and stream planes is the GOAL,
    not a violation — it is what lets one log_format field mean the same thing
    everywhere ($brix_protocol is exactly this).  Two registrations on the SAME
    plane, however, are a duplicate-variable config error at startup.
    """
    homes = {}
    for name, rel in variables:
        homes.setdefault((name, _var_plane(rel)), set()).add(rel)
    out = []
    for (name, plane), rels in sorted(homes.items()):
        if len(rels) < 2 or name in allow:
            continue
        out.append(("R9", name,
                    f"variable registered {len(rels)} times on the {plane} "
                    f"plane ({', '.join(sorted(rels))}); nginx refuses a "
                    "duplicate variable at startup"))
    return out


def _documented_variables():
    """Names mentioned anywhere in docs/03-configuration/.

    Variables are documented in config-reference.md, not directives.md (which
    is the DIRECTIVE reference), so R8 reads the whole configuration-docs
    directory rather than R3's single file.
    """
    docs_dir = os.environ.get("BRIX_REGISTRY_VARDOCS") or \
        os.path.join(ROOT, "docs", "03-configuration")
    if not os.path.isdir(docs_dir):
        return set()
    names = set()
    for dp, _, fs in os.walk(docs_dir):
        for f in fs:
            if f.endswith(".md"):
                text = open(os.path.join(dp, f), errors="replace").read()
                names |= set(re.findall(r'\bbrix_[a-z0-9_]+', text))
    return names


def _rule_r8(variables, documented, allow):
    """R8 — every registered variable is documented.

    Mirrors R3's docs-from-source requirement for directives. An undocumented
    variable is one an operator cannot discover: unlike a directive, there is
    no config that fails to parse to tell them it exists.
    """
    out = []
    for name, rel in sorted(set(variables)):
        if name in documented or name in allow:
            continue
        out.append(("R8", name,
                    f"variable is not documented ({rel}); add a row to "
                    "docs/03-configuration/ — an undocumented variable is one "
                    "nobody can discover"))
    return out


def _rule_r10(variables):
    """R10 — no variable name carries credential material. Security rule:
    gates from day one, allowlist is explicit and tiny."""
    out = []
    for name, rel in sorted(set(variables)):
        if name in _R10_ALLOW:
            continue
        if any(p in name for p in _CREDENTIAL_PATTERNS):
            out.append(("R10", name,
                        f"variable name looks like credential material ({rel}); "
                        "variables are loggable and copyable into upstream "
                        "headers — expose the SUBJECT of an identity, never "
                        "the credential that proved it"))
    return out


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

    # phase-106 W8: the variable surface.
    variables = _collect_variables()
    findings += _rule_r7(variables, allow)
    findings += _rule_r8(variables, _documented_variables(), allow)
    findings += _rule_r9(variables, allow)
    findings += _rule_r10(variables)
    # phase-110 W5: the uniform-vocabulary rules. Backlogs are empty once W1-W4
    # land, so they gate.
    findings += _rule_r11(variables)
    findings += _rule_r12()
    findings += _rule_r13()
    findings += _rule_r14(variables, allow)   # W5.4 self-deleting alias pin
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
