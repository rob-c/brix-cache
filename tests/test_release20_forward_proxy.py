"""2.0 F5(B) — `brix_storage_backend forward://` : the forwarding proxy
(XrdPss forwarding mode, `pss.origin = *` + `pss.permit`).

A client of a forwarding export names the origin INSIDE the path it opens —
`/root://host:port//file`, the XrdPss convention — and the proxy relays the
request to that origin. Two operator gates decide what the proxy will dial on
a client's say-so: the protocol list in the origin URL (`forward://root`,
`forward://roots`, `forward://root,roots`) and the mandatory `permit=<host|.suffix>`
host allowlist, whose match rule is the TPC egress guard's
(`brix_tpc_host_pattern_match`), so a forwarded open and a TPC pull agree on
what `.example.org` permits. A missing permit list is a grammar error: an
empty list would be an open relay.

Implementation: `src/fs/backend/xroot/sd_xroot_fwd*.c` (the `xroot_fwd`
driver: one sd_xroot child per distinct admitted origin, every slot relayed
through the shared `brix_sd_*_maybe_cred` forwarders), the ngx-free key parser
`sd_xroot_fwd_key.c` (tests/test_sd_xroot_fwd_key.py), the `forward://`
origin parser `src/fs/vfs/vfs_backend_config_fwd.c`, and the `permit=` store
param in `src/fs/tier/tier_config_args.c`.

Layers, each with success / error / security-negative legs:
  * TestGrammar     — nginx -t accept/reject of every line shape, including
                      the refusals that keep `forward://` an EXPORT origin and
                      `permit=` a forward-only param.
  * TestForwardedIO — live: a read and a stat through a client-named origin
                      are byte-exact; a scheme outside the list is
                      kXR_Unsupported; a key naming no origin is kXR_NotFound;
                      a host outside the permit list is kXR_NotAuthorized and
                      is never dialled (answered before any resolve); the
                      `.suffix` rule is anchored; a permitted-but-dead origin
                      is an error, not a hang.
  * TestCensus      — the driver is in every census a storage driver must be
                      in (fs_list, ./config, the slot matrix), and the host
                      verdict is the TPC guard's, not a private copy.

Wire driver: the raw root:// client of test_opaque_strict / _cache_partial_helpers
(anonymous login, kXR_open / kXR_read / kXR_stat).
"""
import os
import struct
import subprocess
import time
from pathlib import Path

import pytest

from _cache_partial_helpers import read_range
from fleet_lifecycle_ports import SHARED_PARSE_PLACEHOLDER_PORT
from server_registry import NginxInstanceSpec
from settings import HOST, BIND_HOST, NGINX_BIN
from test_opaque_strict import _login, _errcode, KXR_ERROR
from test_phase25_ratelimit import _xrd_open, KXR_OK

pytestmark = [pytest.mark.serial, pytest.mark.uses_lifecycle_harness,
              pytest.mark.xdist_group("lc-r20-forward")]

REPO = Path(__file__).resolve().parents[1]
kXR_NotAuthorized = 3010
kXR_NotFound = 3011
kXR_Unsupported = 3013
KXR_STAT = 3017
SEED_SIZE = 3 * 1024 * 1024 + 517          # not a block multiple on purpose
REFUSAL_BUDGET = 3.0                       # seconds: a permit refusal never dials


def _line(text):
    return f"        {text}\n"


def _render(lifecycle, tmp_path, name, fwd_lines):
    reg = lifecycle.register(NginxInstanceSpec(
        name=name,
        template="nginx_release20_forward.conf",
        protocol="none",
        readiness="none",
        port=SHARED_PARSE_PLACEHOLDER_PORT,       # nginx -t only, never bound
        template_values={"BIND_HOST": BIND_HOST, "FWD_LINES": fwd_lines},
        reason="brix_storage_backend forward:// grammar (nginx -t).",
    ))
    endpoint = lifecycle.launcher.render_nginx(reg)
    proc = subprocess.run(
        [NGINX_BIN, "-t", "-p", endpoint.prefix, "-c", "conf/nginx.conf"],
        capture_output=True, text=True, timeout=30)
    return proc.returncode, proc.stdout + proc.stderr


# ===========================================================================
# Grammar
# ===========================================================================

class TestGrammar:
    _n = 0

    def _nginx_t(self, lifecycle, tmp_path, *lines):
        TestGrammar._n += 1
        return _render(lifecycle, tmp_path, f"lc-r20-fwd-validate-{TestGrammar._n}",
                       "".join(_line(l) for l in lines))

    @pytest.mark.parametrize("line", [
        "brix_storage_backend forward://root permit=127.0.0.1;",
        "brix_storage_backend forward://root,roots permit=127.0.0.1 permit=.example.org;",
        "brix_storage_backend forward://roots permit=.cern.ch verify_pages;",
        "brix_storage_backend forward://roots,root permit=origin.example.org nearline;",
    ], ids=["root", "both-two-permits", "roots-verify-pages", "reversed-nearline"])
    def test_valid_forms_accepted(self, lifecycle, tmp_path, line):
        """Success: every documented line shape parses — one or both schemes
        in either order, several permit entries, and the root://-only params
        (verify_pages, nearline) that a forwarded origin honours too."""
        rc, out = self._nginx_t(lifecycle, tmp_path, line)
        assert rc == 0, f"{line!r} rejected:\n{out}"

    @pytest.mark.parametrize("line,needle", [
        ("brix_storage_backend forward://http permit=127.0.0.1;",
         "takes a protocol list of root and/or roots"),
        ("brix_storage_backend forward:// permit=127.0.0.1;",
         "takes a protocol list of root and/or roots"),
        ("brix_storage_backend forward://root, permit=127.0.0.1;",
         "takes a protocol list of root and/or roots"),
        ("brix_storage_backend forward://root permit=;",
         '"permit="'),
        ("brix_storage_backend forward://root permit=a/b;",
         '"permit=" takes one host or .suffix per param'),
        ("brix_storage_backend root://127.0.0.1:1094 permit=127.0.0.1;",
         '"permit=" belongs on a forward:// backend line'),
    ], ids=["unknown-scheme", "empty-list", "trailing-comma", "empty-permit",
            "permit-with-slash", "permit-on-fixed-origin"])
    def test_malformed_forms_rejected(self, lifecycle, tmp_path, line, needle):
        """Error: each malformed shape is refused at nginx -t with the
        diagnostic that names the rule."""
        rc, out = self._nginx_t(lifecycle, tmp_path, line)
        assert rc != 0, f"{line!r} must be rejected:\n{out}"
        assert needle in out, out

    def test_missing_permit_is_refused(self, lifecycle, tmp_path):
        """Security negative: a forward:// line with no permit list is not an
        'allow everything' default — it is refused, because an empty list
        would relay to any origin a client names (an open proxy)."""
        rc, out = self._nginx_t(
            lifecycle, tmp_path,
            "brix_storage_backend forward://root,roots;")
        assert rc != 0, out
        assert "needs at least one permit=" in out, out

    def test_forward_is_not_a_store_scheme(self, lifecycle, tmp_path):
        """Security negative: forward:// is an EXPORT origin. A cache tier
        whose store were 'whatever origin the client names' would let a client
        choose where cached bytes come from — refused on every store line."""
        cache = tmp_path / "cache"
        cache.mkdir(exist_ok=True)
        rc, out = self._nginx_t(
            lifecycle, tmp_path,
            f"brix_export {tmp_path};",
            "brix_cache_store forward://root permit=127.0.0.1;")
        assert rc != 0, out
        assert "forward:// is a brix_storage_backend origin, not a" in out, out

    def test_permit_is_not_a_cache_param(self, lifecycle, tmp_path):
        """Error: `permit=` on a cache/stage line is refused — a store has one
        fixed origin, so a permit list there would be honoured by nothing."""
        cache = tmp_path / "cache"
        cache.mkdir(exist_ok=True)
        rc, out = self._nginx_t(
            lifecycle, tmp_path,
            f"brix_export {tmp_path};",
            f"brix_cache_store posix:{cache} permit=127.0.0.1;")
        assert rc != 0, out
        assert '"permit=" belongs on a brix_storage_backend forward:// line' in out, out


# ===========================================================================
# Live lab: one origin, one forwarding proxy
# ===========================================================================

def _seed(origin_root):
    data = bytes((i * 7 + (i >> 8)) & 0xFF for i in range(SEED_SIZE))
    (origin_root / "f.bin").write_bytes(data)
    return data


def _lab(lifecycle, tmp_path, tag, *, protocols="root", permit=None):
    """Start a posix root:// origin and a forwarding proxy in front of it.
    Returns (origin_port, proxy_port, seeded bytes).

    Both instances carry the STABLE ledger names ``lc-r20-fwd-origin`` /
    ``lc-r20-fwd-proxy`` rather than a per-tag name: the ``lifecycle`` fixture
    is per-test and unregisters both on teardown, the class is serialised on
    one xdist_group, and only one lab is ever live -- so two ledger slots cover
    all six labs instead of twelve. `tag` names the lab in the spec reason, and
    so in the registry manifest and the launcher log.
    """
    origin_root = tmp_path / "origin"
    origin_root.mkdir(exist_ok=True)
    data = _seed(origin_root)
    origin = lifecycle.start(NginxInstanceSpec(
        name="lc-r20-fwd-origin",
        template="nginx_lc_cache_partial_origin.conf",
        protocol="root",
        data_root=str(origin_root),
        template_values={"BIND_HOST": BIND_HOST,
                         "ORIGIN_STORAGE": f"brix_export {origin_root};",
                         "ORIGIN_ALLOW_WRITE": ""},
        reason=f"2.0 F5 forwarding-proxy origin ({tag})"))
    permits = " ".join(f"permit={p}" for p in (permit or [HOST]))
    proxy = lifecycle.start(NginxInstanceSpec(
        name="lc-r20-fwd-proxy",
        template="nginx_release20_forward.conf",
        protocol="root",
        data_root=str(tmp_path),
        template_values={
            "BIND_HOST": BIND_HOST,
            "FWD_LINES": _line(
                f"brix_storage_backend forward://{protocols} {permits};")},
        reason=f"2.0 F5 forwarding proxy, client-named origins ({tag})"))
    return origin.port, proxy.port, data


def _key(port, file="/f.bin", *, scheme="root", host=HOST):
    return f"/{scheme}://{host}:{port}/{file}"


def _open(port, path):
    s = _login(port)
    try:
        return _xrd_open(s, path)
    finally:
        s.close()


def _stat(port, path):
    s = _login(port)
    try:
        payload = path.encode() + b"\x00"
        s.sendall(struct.pack(">BBH16sI", 0, 1, KXR_STAT, b"\x00" * 16,
                              len(payload)) + payload)
        hdr = s.recv(8)
        status, dlen = struct.unpack(">HI", hdr[2:8])
        body = b""
        while len(body) < dlen:
            chunk = s.recv(dlen - len(body))
            if not chunk:
                break
            body += chunk
        return status, body
    finally:
        s.close()


def _timed(fn, *args):
    t0 = time.monotonic()
    result = fn(*args)
    return result, time.monotonic() - t0


class TestForwardedIO:
    def test_read_and_stat_through_client_named_origin(self, lifecycle, tmp_path):
        """Success: the proxy relays a read of `/root://host:port//f.bin` to
        that origin and the bytes are exact across a non-aligned length;
        kXR_stat through the same key answers from the origin."""
        origin_port, proxy_port, data = _lab(lifecycle, tmp_path, "ok")
        got = read_range(proxy_port, _key(origin_port), 0, SEED_SIZE)
        assert got == data
        st, body = _stat(proxy_port, _key(origin_port))
        assert st == KXR_OK, (st, body[:64])
        # kXR_stat body: "<id> <size> <flags> <mtime>"
        assert int(body.split()[1]) == SEED_SIZE, body

    def test_scheme_outside_protocol_list_is_unsupported(self, lifecycle, tmp_path):
        """Error: `forward://root` admits root:// only — a roots:// key is
        kXR_Unsupported (a client error, distinct from the permit refusal)."""
        origin_port, proxy_port, _ = _lab(lifecycle, tmp_path, "scheme",
                                         protocols="root")
        st, body = _open(proxy_port, _key(origin_port, scheme="roots"))
        assert st == KXR_ERROR, st
        assert _errcode(body) == kXR_Unsupported, (_errcode(body), body[:96])

    def test_key_naming_no_origin_is_not_found(self, lifecycle, tmp_path):
        """Error: a plain path on a forwarding export names no origin, so
        there is nothing to forward to — kXR_NotFound, not a relay to some
        default host."""
        _, proxy_port, _ = _lab(lifecycle, tmp_path, "plain")
        st, body = _open(proxy_port, "/f.bin")
        assert st == KXR_ERROR, st
        assert _errcode(body) == kXR_NotFound, (_errcode(body), body[:96])

    def test_unlisted_host_is_refused_before_any_dial(self, lifecycle, tmp_path):
        """Security negative: a host outside the permit list is
        kXR_NotAuthorized on open AND on stat, and the answer comes back
        inside the refusal budget — the verdict precedes any resolve or
        connect, so the proxy never touches the host a client named."""
        _, proxy_port, _ = _lab(lifecycle, tmp_path, "permit")
        (st, body), took = _timed(_open, proxy_port,
                                  _key(1094, host="origin.invalid"))
        assert st == KXR_ERROR, st
        assert _errcode(body) == kXR_NotAuthorized, (_errcode(body), body[:96])
        assert took < REFUSAL_BUDGET, f"refusal took {took:.2f}s — did it dial?"
        (st, body), took = _timed(_stat, proxy_port,
                                  _key(1094, host="origin.invalid"))
        assert st == KXR_ERROR and _errcode(body) == kXR_NotAuthorized, \
            (st, _errcode(body))
        assert took < REFUSAL_BUDGET, f"stat refusal took {took:.2f}s"

    def test_suffix_permit_is_anchored(self, lifecycle, tmp_path):
        """Security negative: `permit=.example.org` matches hosts UNDER that
        domain only — `x.example.org.evil.invalid` is refused, so a suffix
        entry cannot be spoofed by prefixing the permitted domain."""
        _, proxy_port, _ = _lab(lifecycle, tmp_path, "suffix",
                                permit=[".example.org"])
        st, body = _open(proxy_port,
                         _key(1094, host="x.example.org.evil.invalid"))
        assert st == KXR_ERROR, st
        assert _errcode(body) == kXR_NotAuthorized, (_errcode(body), body[:96])

    def test_permitted_dead_origin_is_an_error_not_a_hang(self, lifecycle, tmp_path):
        """Error: a permitted host with nothing listening fails the open with
        an origin error — neither of the admission codes — and does so
        promptly rather than parking the client."""
        _, proxy_port, _ = _lab(lifecycle, tmp_path, "dead")
        (st, body), took = _timed(_open, proxy_port, _key(1))
        assert st == KXR_ERROR, st
        assert _errcode(body) not in (kXR_NotAuthorized, kXR_Unsupported), \
            (_errcode(body), body[:96])
        assert took < 20.0, f"dead-origin open took {took:.1f}s"


# ===========================================================================
# Census pins: the driver exists everywhere a storage driver must
# ===========================================================================

class TestCensus:
    def test_fs_list_carries_the_driver_and_the_scheme(self):
        """Success: the backend census has the `xroot_fwd` row and the
        `forward` scheme alias — SHM metric arrays and the scheme→driver map
        both generate from fs_list.h."""
        text = (REPO / "src/core/types/fs_list.h").read_text()
        assert 'X(XROOT_FWD, xroot_fwd, "xroot_fwd", ORIGIN)' in text
        assert 'S("forward", "xroot_fwd", 0, 0)' in text

    def test_build_lists_every_forwarding_source(self):
        """Error leg of the build census: a driver file missing from ./config
        compiles nowhere and the registry row dangles."""
        config = (REPO / "config").read_text()
        for src in ("sd_xroot_fwd_key.c", "sd_xroot_fwd.c", "sd_xroot_fwd_obj.c",
                    "sd_xroot_fwd_ns.c"):
            assert f"src/fs/backend/xroot/{src}" in config, src
        assert "src/fs/vfs/vfs_backend_config_fwd.c" in config

    def test_host_verdict_is_the_tpc_egress_guards(self):
        """Security negative: the permit match is the TPC egress guard's
        `brix_tpc_host_pattern_match`, not a private reimplementation — one
        host-pattern rule, one place to audit."""
        key = (REPO / "src/fs/backend/xroot/sd_xroot_fwd_key.c").read_text()
        assert "brix_tpc_host_pattern_match(" in key
        assert "strstr(" not in key and "strcasestr(" not in key, \
            "a substring match would make `.example.org` permit anything containing it"

    def test_slot_matrix_censuses_the_driver(self):
        """The machine-checked slot matrix has the `xroot_fwd` column and the
        directive reference documents the line."""
        matrix = (REPO / "docs/09-developer-guide/storage-driver-slot-matrix.md").read_text()
        assert "64 slots x 14 drivers = 896 cells" in matrix
        assert "x-fwd" in matrix or "xroot_fwd" in matrix
        directives = (REPO / "docs/03-configuration/directives.md").read_text()
        assert "brix_storage_backend forward://" in directives
        assert "permit=<host|.suffix>" in directives


# ===========================================================================
# Regression pins for the 2026-09-09 discovery: the admission verdict was
# reaching the client as kXR_NotFound
# ===========================================================================

class TestAdmissionPrecedesTheExistenceProbe:
    """The refusals above were kXR_NotFound until 2026-09-09.

    The read-open path probes existence through the export's driver stat and
    reports EVERY stat failure as a miss — deliberately, so a denied principal
    cannot use kXR_NotFound-vs-kXR_NotAuthorized as a namespace oracle. On a
    forwarding export that rule swallowed the two admission verdicts as well,
    because the forward driver reports them from inside the same stat. The fix
    asks the driver for its verdict BEFORE the probe. These pins are static on
    purpose: the live tests above prove the codes, and these say WHY the order
    is what it is, so a future reshuffle of the resolve path cannot quietly
    put the probe back in front.
    """
    RESOLVE = "src/protocols/root/read/open_request_resolve.c"

    def test_admit_is_called_before_the_probe(self):
        """Success: in the read-open resolver the admission call precedes the
        existence probe — the ORDER is the fix, not the presence."""
        text = (REPO / self.RESOLVE).read_text()
        admit = text.index("brix_open_forward_admit(ctx, c, conf,")
        probe = text.index("brix_open_read_probe(ctx, conf, c, clean_path,")
        assert admit < probe, "the existence probe would mask the verdict again"

    def test_verdict_query_dials_nothing(self):
        """Error: the verdict is read from the parsed key alone — it must not
        create a child instance, or a refused host would still be resolved and
        the 'before any dial' guarantee of the timing assertions above would
        be false."""
        drv = (REPO / "src/fs/backend/xroot/sd_xroot_fwd.c").read_text()
        body = drv[drv.index("brix_sd_xroot_fwd_admit_key(brix_sd_instance_t"):]
        body = body[:body.index("\nbrix_sd_instance_t *\nsd_xroot_fwd_resolve")]
        assert "sd_xroot_fwd_child_new" not in body
        assert "sd_xroot_fwd_child_find" not in body

    def test_the_two_verdicts_map_to_the_two_codes(self):
        """Security negative: EACCES must reach the client as NotAuthorized
        and ENOTSUP as Unsupported. Mapping either to kXR_NotFound is the
        regression this class exists for."""
        text = (REPO / self.RESOLVE).read_text()
        helper = text[text.index("brix_open_forward_admit(brix_ctx_t"):]
        helper = helper[:helper.index("\nngx_int_t\nbrix_open_read_resolve")]
        assert "ENOTSUP" in helper and "kXR_Unsupported" in helper
        assert "EACCES" in helper and "kXR_NotAuthorized" in helper
        assert "kXR_NotFound" not in helper
