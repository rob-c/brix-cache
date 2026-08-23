"""mega_config — assemble ONE nginx-xrootd config exposing every port the
single-server suite tests use, so REMOTE mode reaches all tiers via one host.

Base = nginx_shared.conf; each dedicated config's server block (+ any http/stream
prologue like a rate-limit zone) is folded in on its default port, dropping
duplicate listens. Was tools/build-mega-config.sh (this logic was the embedded
Python). ``build()`` returns the config text; tests assert on it directly.
"""
import re
import sys

from . import REPO

CONFIGS = REPO / "tests" / "configs"

# dedicated config -> default port to fold in.
EXTRAS = {
    "nginx_readonly.conf": "11102",
    "nginx_security_level_standard.conf": "11191",
    "nginx_security_level_pedantic.conf": "11192",
    "nginx_crl.conf": "11104",
    "nginx_crl_reload.conf": "11108",
    "nginx_webdav-dellock.conf": "13210",
    "nginx_webdav-unlock-ownership.conf": "22014",
    "nginx_xrdhttp_digest.conf": "12988",
    "nginx_tpc_ssrf_default.conf": "11180",
    "nginx_tpc_ssrf_allow_local.conf": "11181",
    "nginx_tpc_ssrf_deny_private.conf": "11182",
    "nginx_s3_presigned.conf": "11183",
    "nginx_s3_presigned_sts.conf": "11184",
    "nginx_s3-mpu.conf": "22017",
    "nginx_webdav_auth_cache.conf": "18444",
    "nginx_open_flags_lifecycle.conf": "12980",
    "nginx_readonly-http.conf": "11216",
}

PATHS = {
    "{DATA_DIR}": "/data/xrootd", "{LOG_DIR}": "/var/log/brix", "{TMP_DIR}": "/tmp",
    "{SERVER_CERT}": "/etc/grid-security/hostcert.pem",
    "{SERVER_KEY}": "/etc/grid-security/hostkey.pem",
    "{CA_CERT}": "/etc/grid-security/certificates/ca.pem",
    "{CA_DIR}": "/etc/grid-security/certificates",
    "{VOMSDIR}": "/etc/grid-security/vomsdir",
    "{CRL_PATH}": "/etc/brix/crl/crl.pem",
    "{CRL_RELOAD_INTERVAL}": "5",
    "{TOKEN_DIR}/jwks.json": "/etc/brix/jwks/jwks.json",
}
SHARED_PORTS = {
    "{ANON_PORT}": "11094", "{ANON_RESUME_OFF_PORT}": "11118", "{GSI_PORT}": "11095",
    "{GSI_TLS_PORT}": "11096", "{TOKEN_PORT}": "11097", "{WEBDAV_PORT}": "8443",
    "{WEBDAV_GSI_TLS_PORT}": "8444", "{HTTP_WEBDAV_PORT}": "8080", "{S3_PORT}": "9001",
    "{METRICS_PORT}": "9100", "{AUTH_PORT}": "18445", "{HTTP_STUB_PORT}": "11123",
}
_PROLOGUE_KEEP = re.compile(r"(rate_limit_zone|^\s*(map|upstream|geo|limit_req_zone|js_)\b|^\s*[}])")


def _apply(text, ports):
    for k, v in {**PATHS, **ports}.items():
        text = text.replace(k, v)
    return text.replace("{BIND_HOST}:", "").replace("{BIND_HOST}", "0.0.0.0")


def _brace_end(text, start):
    """Index of the '}' closing the '{' at/after ``start``."""
    depth, j = 0, start
    while j < len(text):
        depth += (text[j] == "{") - (text[j] == "}")
        if depth == 0 and text[j] == "}":
            return j
        j += 1
    return len(text)


def _top_block(text, kw):
    m = re.search(kw + r"\s*\{", text)
    if not m:
        return ""
    return text[m.end():_brace_end(text, m.end() - 1)]


def _split_servers(body):
    """(prologue, [server_blocks]) from a stream/http block body."""
    servers, prologue_parts, i = [], [], 0
    while (m := re.search(r"server\s*\{", body[i:])):
        start = i + m.start()
        prologue_parts.append(body[i:start])
        end = _brace_end(body, i + m.end() - 1)
        servers.append(body[start:end + 1])
        i = end + 1
    prologue_parts.append(body[i:])
    prologue = "\n".join(l for l in "".join(prologue_parts).splitlines()
                         if l.strip() and not l.strip().startswith("#") and _PROLOGUE_KEEP.search(l))
    return prologue, servers


def _listen_port(block):
    m = re.search(r"listen\s+(\d+)", block)
    return m.group(1) if m else None


def _injection_text(prologues, servers):
    prologue_text = "\n".join(
        "  " + line for prologue in prologues for line in prologue.splitlines())
    if prologues:
        prologue_text += "\n"
    return prologue_text + "\n".join(servers)


def _inject(text, kw, prologues, servers):
    if not prologues and not servers:
        return text
    add = _injection_text(prologues, servers)
    m = re.search(kw + r"\s*\{", text)
    if not m:
        return text.rstrip() + f"\n\n{kw.strip(chr(92) + 'b')} {{\n{add}\n}}\n"
    end = _brace_end(text, m.end() - 1)
    return text[:end] + "\n" + add + "\n" + text[end:]


def _append_prologue(prologues, keyword, prologue):
    stripped = prologue.strip()
    if stripped and stripped not in (item.strip() for item in prologues[keyword]):
        prologues[keyword].append(prologue)


def _append_servers(extra, keyword, servers, used):
    for block in servers:
        port = _listen_port(block)
        if port and port in used:
            continue
        if port:
            used.add(port)
        extra[keyword].append("  " + block.strip().replace("\n", "\n  "))


def _collect_config(cfgdir, name, port, used, extra, prologues):
    raw = _apply((cfgdir / name).read_text(), {**SHARED_PORTS, "{PORT}": port})
    for keyword in (r"\bstream\b", r"\bhttp\b"):
        body = _top_block(raw, keyword)
        if not body:
            continue
        prologue, servers = _split_servers(body)
        _append_prologue(prologues, keyword, prologue)
        _append_servers(extra, keyword, servers, used)


def build(cfgdir=CONFIGS, extras=EXTRAS):
    """Return the assembled mega config text."""
    shared = _apply((cfgdir / "nginx_shared.conf").read_text(), SHARED_PORTS)
    used = set(re.findall(r"listen\s+(\d+)", shared))
    extra = {r"\bstream\b": [], r"\bhttp\b": []}
    prol = {r"\bstream\b": [], r"\bhttp\b": []}
    for name, port in extras.items():
        _collect_config(cfgdir, name, port, used, extra, prol)
    merged = _inject(shared, r"\bstream\b", prol[r"\bstream\b"], extra[r"\bstream\b"])
    return _inject(merged, r"\bhttp\b", prol[r"\bhttp\b"], extra[r"\bhttp\b"])


def main(argv):
    from pathlib import Path
    text = build()
    Path(argv[0]).write_text(text)
    print(f"wrote {argv[0]}: {len(re.findall(r'listen [0-9]+', text))} listens")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
