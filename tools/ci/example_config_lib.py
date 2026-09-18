"""Render an example nginx configuration into a scratch tree that `nginx -t`
can validate — the engine behind tools/ci/check_example_configs.py (phase-115
W1.3) and the local stack runner in tests/test_phase115_example_configs.py.

WHAT: three concerns, kept separate so each is testable on its own:
  * discovery  — which files and markdown fences count as examples, and what
                 nginx context a fragment belongs to (`classify`);
  * rendering  — rewrite every absolute filesystem path under a scratch root,
                 materialise the certificates/dirs/stub files those paths
                 name, and neutralise hostnames the parser resolves at config
                 time (`render`);
  * validation — run `nginx -t -p <root>` on the rendered file with a
                 HOSTALIASES map so compose service names resolve (`nginx_t`).

WHY: an example that does not parse is worse than none. README once carried
     directives that no longer existed (`brix_webdav_proxy_upstream`,
     `brix_gridftp_export`, `brix_cache_origin`) for months because nothing
     ever ran them. Paths are rewritten rather than faked with a chroot so the
     check needs no privileges and runs on any CI runner that has the binary.

HOW: logical paths (a `location`, a `brix_cache_export` namespace prefix, a
     `brix_cms_paths` export) are never touched; everything else that starts
     with `/` is prefixed with the scratch root. Directive names decide what
     to materialise: `*_key` → the demo private key, other PEM/CA directives →
     the demo certificate, `*_dir`/`*_folder`/`*_store`/`brix_export` →
     a directory, JWKS → an empty key set, anything else → its parent dir.
"""
from __future__ import annotations

import html
import os
import re
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]

# --- discovery ---------------------------------------------------------------

# Files whose whole body is an example (compose stacks and shipped .example
# files). Markdown fences are discovered separately by `iter_fences`.
FILE_GLOBS = (
    "deploy/compose/*/*.conf",
    "deploy/*/*.conf.example",
    "contrib/*.conf.example",
)
# Markdown trees whose ```nginx fences MUST validate (README is the front door;
# the two configuration references are what operators copy from).
STRICT_DOCS = (
    "README.md",
    "docs/02-concepts/deployment-modes.md",
    "docs/03-configuration/examples.md",
    "docs/10-reference/comparison/deployment-reference.md",
)
DOC_GLOBS = ("README.md", "docs/**/*.md")
# Plans, history and generated API dumps quote grammar that was, or may become,
# real; they are not examples an operator copies.
_DOC_EXCLUDE_RE = re.compile(r"/_legacy/|docs/refactor/|docs/superpowers/|docs/doxygen/|/history-|/postmortem-")
_TEMPLATE_RE = re.compile(r"@[A-Z_]+@")            # sed-substituted *.conf.example

# A leading `# check_example_configs: context=<ctx>` (or `skip`) comment in a
# file or fence overrides the heuristic below.
_MARKER_RE = re.compile(r"check_example_configs:\s*(skip|context=(full|http|stream|server-http|server-stream|location))")

_FENCE_RE = re.compile(r"```nginx[^\n]*\n(.*?)```", re.S)
_HTML_FENCE_RE = re.compile(r'<pre><code class="language-nginx">(.*?)</code></pre>', re.S)


@dataclass
class Example:
    """One validatable example: where it came from, its raw text, its context."""
    source: str          # repo-relative path, plus `#<n>` for a fence
    text: str
    context: str         # full | http | stream | server-http | server-stream | location | skip
    strict: bool = True  # False: a doc fence that only needs the directive check


def _first_directive(text: str) -> str:
    for line in text.splitlines():
        s = line.strip()
        if s and not s.startswith("#"):
            return s.split()[0]
    return ""


_STREAM_ONLY = {"brix_root", "brix_gridftp", "brix_cms_server", "brix_cms_manager",
                "brix_tap_proxy", "brix_manager_mode", "brix_auth", "brix_tls"}


def marked_skip(text: str) -> bool:
    """True when the author opted the example out (proposed grammar, prose)."""
    m = _MARKER_RE.search(text)
    return bool(m and m.group(1) == "skip")


def _code_only(text: str) -> str:
    return "\n".join(l for l in text.splitlines() if not l.strip().startswith("#"))


_FULL_HEADS = frozenset({"stream", "http", "worker_processes", "thread_pool", "user",
                         "error_log", "pid", "load_module", "daemon", "worker_rlimit_nofile"})
_HTTP_HEADS = frozenset({"map", "upstream", "log_format", "brix_metrics"})


def _is_prose(code: str) -> bool:
    """Ellipses, <placeholders> and template slots mark a fence as prose, not config."""
    return "..." in code or bool(re.search(r"<[a-zA-Z][\w -]*>", code)) \
        or bool(_TEMPLATE_RE.search(code))


def _context_of_head(head: str, text: str) -> str:
    if head in _FULL_HEADS:
        return "full"
    if head == "server":
        names = set(re.findall(r"^\s*(brix_[a-z0-9_]+)", text, re.M))
        return "server-stream" if names & _STREAM_ONLY else "server-http"
    if head == "location":
        return "location"
    return "http" if head in _HTTP_HEADS else "skip"   # bare directives: context unknown


def classify(text: str) -> str:
    """Decide which nginx context wraps `text` so it becomes a full config."""
    m = _MARKER_RE.search(text)
    if m:
        return "skip" if m.group(1) == "skip" else m.group(2)
    if _is_prose(_code_only(text)):
        return "skip"
    if re.search(r"^\s*events\s*\{", text, re.M):
        return "full"
    return _context_of_head(_first_directive(text), text)


def _wrap(text: str, context: str) -> str:
    skel = "events { worker_connections 64; }\n"
    if context == "full":
        return text if re.search(r"^\s*events\s*\{", text, re.M) else skel + text
    if context == "http":
        return skel + "http {\n" + text + "\n}\n"
    if context == "stream":
        return skel + "stream {\n" + text + "\n}\n"
    if context == "server-http":
        return skel + "http {\n" + text + "\n}\n"
    if context == "server-stream":
        return skel + "stream {\n" + text + "\n}\n"
    if context == "location":
        return skel + "http {\n server {\n listen 127.0.0.1:18080;\n" + text + "\n }\n}\n"
    raise ValueError(context)


def iter_files(root: Path = ROOT):
    for pattern in FILE_GLOBS:
        for path in sorted(root.glob(pattern)):
            text = path.read_text(errors="replace")
            yield Example(str(path.relative_to(root)), text, classify(text))


def _fences(text: str):
    for m in _FENCE_RE.finditer(text):
        yield m.group(1)
    for m in _HTML_FENCE_RE.finditer(text):
        yield html.unescape(m.group(1))


def iter_fences(root: Path = ROOT, docs=DOC_GLOBS):
    seen = set()
    for pattern in docs:
        for path in sorted(root.glob(pattern)):
            if path in seen or _DOC_EXCLUDE_RE.search(str(path)):
                continue
            seen.add(path)
            rel = str(path.relative_to(root))
            body = path.read_text(errors="replace")
            for n, fence in enumerate(_fences(body), 1):
                yield Example(f"{rel}#{n}", fence, classify(fence), rel in STRICT_DOCS)


# --- rendering ---------------------------------------------------------------

# Directives whose `/…` arguments are namespace paths, not filesystem paths.
LOGICAL_PATH_DIRECTIVES = frozenset({
    "location", "brix_cache_export", "brix_cms_paths", "brix_dashboard_cookie_path",
    "brix_guard_valid_prefix", "rewrite", "return", "try_files", "alias",
    "brix_s3_bucket", "brix_cvmfs_upstream_allow", "brix_tape_rest_prefix",
    "brix_webdav_root", "brix_oci_prefix", "brix_rpm_prefix", "if", "map",
    "brix_cvmfs_repo", "brix_cvmfs_repo_allow", "brix_export_prefix",
    "brix_dashboard_browse_root",
})
_EXEC_DIRS = ("/usr/bin/", "/bin/", "/usr/sbin/", "/usr/local/bin/")
_KEY_SUFFIXES = ("_key", "hostkey", "userkey")
_DIR_SUFFIXES = ("_dir", "_folder", "_store", "_ca", "_capath", "_root", "_path",
                 "brix_export", "_export", "_cadir", "_quarantine_dir")
_CERT_DIRECTIVES = frozenset({
    "ssl_certificate", "ssl_client_certificate", "ssl_trusted_certificate",
    "brix_certificate", "proxy_ssl_certificate", "proxy_ssl_trusted_certificate",
    "brix_tap_proxy_upstream_tls_ca", "brix_storage_credential_mint_ca",
    "brix_webdav_cafile", "brix_cvmfs_origin_cafile", "brix_ca_file",
})
_HOST_RE = re.compile(r"\b[a-z0-9][a-z0-9-]*(?:\.[a-z0-9-]+)*\.(?:example|internal|site)(?:\.(?:org|com|net))?\b")
# Compose service names + the bare hostnames the docs use; every one resolves
# to localhost through HOSTALIASES for the duration of `nginx -t`.
HOST_ALIASES = ("brix", "server", "origin", "manager", "ds1", "ds2", "gateway",
                "backend", "proxy", "cache", "redirector", "dataserver", "arc-ce",
                "parent", "localhost")


@dataclass
class Rendered:
    """A rendered example: the config path plus the scratch tree it lives in."""
    conf: Path
    prefix: Path
    hostaliases: Path
    created: list = field(default_factory=list)


def _demo_pki(prefix: Path) -> tuple[Path, Path, Path]:
    """Mint (cert, key, ca_dir) once per scratch root via the shipped minter."""
    out = prefix / "_pki"
    if not (out / "ca" / "ca.pem").exists():
        env = dict(os.environ, OUT=str(out), HOSTS=" ".join(HOST_ALIASES), DAYS="2")
        subprocess.run([str(ROOT / "deploy/compose/common/pki-init.sh")],
                       check=True, env=env, capture_output=True)
    return out / "hostcert.pem", out / "hostkey.pem", out / "ca"


def _jwks(prefix: Path) -> str:
    """A syntactically complete JWKS with one RSA key, minted once per root."""
    out = prefix / "_pki" / "jwks.json"
    if not out.exists():
        import base64, json
        pem = prefix / "_pki" / "jwk.key"
        subprocess.run(["openssl", "genrsa", "-out", str(pem), "2048"], check=True, capture_output=True)
        mod = subprocess.run(["openssl", "rsa", "-in", str(pem), "-noout", "-modulus"],
                             check=True, capture_output=True, text=True).stdout.split("=")[1].strip()
        n = base64.urlsafe_b64encode(bytes.fromhex(mod)).rstrip(b"=").decode()
        out.write_text(json.dumps({"keys": [{"kty": "RSA", "kid": "example", "alg": "RS256",
                                             "use": "sig", "n": n, "e": "AQAB"}]}))
    return out.read_text()


_OPAQUE_SUFFIXES = ("authdb", "_gridmap", "_file", "_keytab", "_secret", "_pwd_file")
_CA_DIR_SUFFIXES = ("_ca", "_ca_dir", "_ca_store", "_folder", "_capath", "_cadir")
_PLACEHOLDER = "brix-example-placeholder-0123456789abcdef\n"


# (kind, predicate(directive, name, posix)) — first match wins, order matters:
# a key file must be classified before the generic .pem certificate rule.
_FILE_KINDS = (
    ("exec", lambda d, n, p: any(("/" + p).startswith(x) for x in _EXEC_DIRS)),
    ("jwks", lambda d, n, p: d.endswith("_jwks") or n.endswith(".jwks")),
    ("key", lambda d, n, p: d.endswith(_KEY_SUFFIXES) or "key" in n),
    ("cert", lambda d, n, p: d in _CERT_DIRECTIVES or n.endswith((".pem", ".crt", ".cert"))),
    ("htpasswd", lambda d, n, p: n.endswith(".htpasswd") or d.endswith("_users")),
    ("authdb", lambda d, n, p: d.endswith("authdb")),
    ("opaque", lambda d, n, p: d.endswith(_OPAQUE_SUFFIXES)),
)


def _kind_of_file(directive: str, name: str, posix: str):
    """Which demo body a *file* directive expects, or None for a non-file."""
    return next((k for k, hit in _FILE_KINDS if hit(directive, name, posix)), None)


def _kind_of_path(directive: str, name: str) -> str:
    if directive.endswith("_log") or directive in ("error_log", "access_log"):
        return "log"        # nginx creates it; a placeholder body would be read as log lines
    if directive.endswith(_DIR_SUFFIXES) or "certificates" in name or "." not in name:
        return "dir"
    return "opaque-if-missing"


def _write_dir(directive: str, target: Path, pki) -> None:
    target.mkdir(parents=True, exist_ok=True)
    if "credential" in directive:
        # Delegated private keys land here; the store refuses to write
        # (EPERM → HTTP 507) unless it is 0700 and worker-owned.
        target.chmod(0o700)
    if directive.endswith(_CA_DIR_SUFFIXES) or "certificates" in target.name:
        for f in pki[2].iterdir():
            dst = target / f.name
            if not dst.exists():
                dst.write_bytes(f.read_bytes())


def _write_exec(_directive, target: Path, _pki) -> None:
    target.write_text("#!/bin/sh\nexit 0\n")
    target.chmod(0o755)


def _write_opaque_if_missing(_directive, target: Path, _pki) -> None:
    # keytabs, gridmaps, admin bearer files, authdbs: a non-empty opaque body
    if not target.exists():
        target.write_text(_PLACEHOLDER)


_WRITERS = {
    "exec": _write_exec,
    "jwks": lambda _d, t, pki: t.write_text(_jwks(pki[2].parents[1])),
    "key": lambda _d, t, pki: t.write_bytes(pki[1].read_bytes()),
    "cert": lambda _d, t, pki: t.write_bytes(pki[0].read_bytes()),
    "htpasswd": lambda _d, t, _pki: t.write_text("operator:example-plaintext-password\n"),
    "authdb": lambda _d, t, _pki: t.write_text("u * / rl\n"),
    "opaque": lambda _d, t, _pki: t.write_text(_PLACEHOLDER),
    "dir": _write_dir,
    "opaque-if-missing": _write_opaque_if_missing,
}


def _materialise(directive: str, target: Path, pki, created: list):
    """Create whatever `directive` expects to find at `target`."""
    target.parent.mkdir(parents=True, exist_ok=True)
    name = target.name
    posix = str(target.relative_to(pki[2].parents[1]))
    kind = _kind_of_file(directive, name, posix) or _kind_of_path(directive, name)
    if kind == "log":
        return
    _WRITERS[kind](directive, target, pki)
    created.append(str(target))


_ABS_RE = re.compile(r"(?<![\w$:/])(?:(posix|pblock|tape|cache|stage):)?(/(?!/)[^\s;\"']*)")


def _rewrite_line(line: str, prefix: Path, pki, created: list) -> str:
    stripped = line.strip()
    if not stripped or stripped.startswith("#"):
        return line
    directive = stripped.split()[0]
    if directive in LOGICAL_PATH_DIRECTIVES or directive == "load_module":
        return "" if directive == "load_module" else line
    def sub(m):
        scheme, path = m.group(1), m.group(2)
        if path in ("/", "/dev/stderr", "/dev/stdout", "/dev/null"):
            return m.group(0)
        target = prefix / path.lstrip("/")
        _materialise(directive, target, pki, created)
        return f"{scheme}:{target}" if scheme else str(target)

    head, _, comment = line.partition(" #")
    return _ABS_RE.sub(sub, head) + (" #" + comment if comment else "")


def _scaffold(prefix: Path) -> Path:
    """The prefix tree `nginx -p` expects; returns its conf dir."""
    prefix.mkdir(parents=True, exist_ok=True)
    (prefix / "logs").mkdir(exist_ok=True)
    conf_dir = prefix / "conf"
    conf_dir.mkdir(exist_ok=True)
    mime = Path(os.environ.get("NGINX_SRC", "/tmp/nginx-1.28.3")) / "conf" / "mime.types"
    (conf_dir / "mime.types").write_text(mime.read_text() if mime.exists() else "types {}\n")
    return conf_dir


def _with_globals(body: str, prefix: Path) -> str:
    """Add the pid/error_log lines an example fragment never carries."""
    if not re.search(r"^\s*pid\s", body, re.M):
        body = f"pid {prefix}/nginx.pid;\n" + body
    if not re.search(r"^\s*error_log\s", body, re.M):
        body = "error_log stderr;\n" + body
    return body


def render(example: Example, prefix: Path) -> Rendered:
    """Write the wrapped, path-rewritten example under `prefix` and return it."""
    conf_dir = _scaffold(prefix)
    pki = _demo_pki(prefix)
    text = _HOST_RE.sub("localhost", _wrap(example.text, example.context))
    created: list = []
    lines = [_rewrite_line(l, prefix, pki, created) for l in text.splitlines()]
    body = _with_globals("\n".join(lines) + "\n", prefix)
    slug = re.sub(r"[^\w.-]+", "_", example.source)
    conf = conf_dir / f"{slug}.conf"
    conf.write_text(body)
    aliases = prefix / "hostaliases"
    aliases.write_text("".join(f"{h} localhost\n" for h in HOST_ALIASES))
    return Rendered(conf, prefix, aliases, created)


# --- validation --------------------------------------------------------------

_NOISE = re.compile(r"\[notice\]|could not open error log file|postconfig")
# The one [emerg] that is a property of the checker's uid, not of the example.
_NEEDS_ROOT = re.compile(r"requires the nginx master to run as root")


def nginx_bin() -> str:
    return os.environ.get("TEST_NGINX_BIN") or str(
        Path(os.environ.get("NGINX_SRC", "/tmp/nginx-1.28.3")) / "objs" / "nginx")


def unsupported_reason(example: Example, binary: str) -> str:
    """Report an explicitly declared upstream nginx requirement before parsing."""
    required = re.search(r"^\s*#\s*check_example_configs:\s*min-nginx=(\d+\.\d+\.\d+)\s*$",
                         example.text, re.M)
    if required is None:
        return ""
    proc = subprocess.run([binary, "-v"], capture_output=True, text=True,
                          check=True, timeout=15)
    actual = re.search(r"nginx/(\d+\.\d+\.\d+)", proc.stdout + proc.stderr)
    if actual is None:
        raise ValueError(f"cannot determine nginx version from {binary}")
    wanted = tuple(map(int, required[1].split(".")))
    found = tuple(map(int, actual[1].split(".")))
    if found < wanted:
        return f"{example.source} requires nginx >= {required[1]}; selected {actual[1]}"
    return ""


#: nginx -t diagnostics that describe a limitation of the checking HOST, not
#: a broken example: Linux-only socket tuning and Darwin's libc ignoring
#: HOSTALIASES (so an upstream hostname the example aliases cannot resolve).
#: VOMS is not on this list: attribute certificates are verified natively, so
#: a brix_require_vo example parses on every host.
_HOST_LIMITS = (
    (re.compile(r'"so_keepalive" parameter accepts only "on" or "off" on this platform'),
     "so_keepalive tuning is Linux-only"),
    (re.compile(r"host not found in upstream"),
     "this libc ignores HOSTALIASES (Darwin)"),
)


def host_limitation(stderr: str) -> str:
    """Why this HOST cannot parse the example (empty string if it is a real failure).

    Only the platform-specific diagnostics above qualify, and the aliases case
    only where HOSTALIASES is known to be ignored (non-Linux)."""
    for pattern, reason in _HOST_LIMITS:
        if pattern.search(stderr):
            if "HOSTALIASES" in reason and sys.platform.startswith("linux"):
                return ""
            return reason
    return ""


def _without_noise(stderr: str) -> str:
    return "\n".join(l for l in stderr.splitlines() if not _NOISE.search(l))


def _only_needs_root(stderr: str) -> bool:
    """True when every [emerg] is the checker-runs-unprivileged one."""
    emergs = [l for l in stderr.splitlines() if "[emerg]" in l]
    return bool(emergs) and all(_NEEDS_ROOT.search(l) for l in emergs)


def nginx_t(rendered: Rendered, binary: str | None = None) -> tuple[bool, str]:
    """Run `nginx -t` on a rendered example; return (ok, relevant stderr)."""
    binary = binary or nginx_bin()
    prepare_nginx(rendered, binary)
    env = dict(os.environ, HOSTALIASES=str(rendered.hostaliases))
    proc = subprocess.run(
        [binary, "-t", "-q", "-p", str(rendered.prefix), "-c", str(rendered.conf)],
        capture_output=True, text=True, env=env, timeout=120)
    stderr = _without_noise(proc.stderr)
    ok = proc.returncode == 0 or (os.geteuid() != 0 and _only_needs_root(stderr))
    if not ok:
        stderr += _host_limit_emergs(proc.stderr)
    return ok, stderr.strip()


def _host_limit_emergs(raw_stderr: str) -> str:
    """The [emerg] lines naming a host limitation, kept even when the noise
    filter would drop them, so callers can classify."""
    kept = [l for l in raw_stderr.splitlines() if "[emerg]" in l and host_limitation(l)]
    return "\n" + "\n".join(kept) if kept else ""


def prepare_nginx(rendered: Rendered, binary: str) -> None:
    """Apply the selected build's modules and private runtime paths before use."""
    import sys
    sys.path.insert(0, str(ROOT / "tests"))
    from cmdscripts.live_common import (
        inject_nginx_load_modules, inject_nginx_runtime_paths,
    )
    inject_nginx_load_modules(rendered.conf, binary)
    inject_nginx_runtime_paths(rendered.conf, rendered.prefix)


def directive_names(text: str) -> set[str]:
    """Every `brix_*` directive a config text uses (first token per line)."""
    return set(re.findall(r"^\s*(brix_[a-z0-9_]+)\b", text, re.M))


def registered_directives() -> set[str]:
    """Names the module registers, via the phase-105 registry extractor."""
    import sys
    sys.path.insert(0, str(ROOT / "tools" / "ci"))
    import check_directive_registry as reg  # noqa: E402  (tools/ci on sys.path)
    return {name for name, _plane, _kind, _path in reg.collect()}
