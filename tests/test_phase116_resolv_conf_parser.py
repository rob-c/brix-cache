"""
test_phase116_resolv_conf_parser.py — phase-116 W1/W2: resolv.conf → resolver.

WHAT: The resolv.conf parser's C unit (tests/c/resolv_conf_unittest.c) plus
      `nginx -t` pins for the brix_resolver / brix_dns_retry /
      brix_dns_cache_max surface: a missing or empty resolv.conf is a warning
      and never an error, `ip:port` and bare-IPv6 nameservers are accepted,
      malformed parameters are refused with their documented message, and an
      explicit `resolver` may precede but not follow `brix_resolver auto`
      (I-DNS-5: the operator's own resolver wins by ordering, never silently).
WHY:  "No hostname may prevent nginx starting" starts at parse time — a
      resolver stanza that failed on a broken /etc/resolv.conf would defeat
      the phase before any hostname was looked up.
HOW:  Parse tier only: config_parse.nginx_t over the audit-16n scaffold
      (never bound), one directive per probe so each refusal has one cause;
      the C unit runs through the c_regression_units registry so the same
      binary the CI lane builds is the one asserted here.
"""
from __future__ import annotations

import pytest

from _phase116_helpers import HAVE_NGINX, parse
from cmdscripts.c_regression_units import run_checks
from dns_stub import write_resolv_conf

pytestmark = [pytest.mark.timeout(120),
              pytest.mark.xdist_group("p116-resolv-conf-parser")]

needs_nginx = pytest.mark.skipif(not HAVE_NGINX, reason="nginx binary unavailable")


def _resolv(tmp_path, nameservers=(("127.0.0.1", 1),), **kw):  # net-literal-allow: synthetic resolv.conf content; port 1 is never dialled
    """A resolv.conf whose nameserver nothing listens on: parse never queries."""
    return write_resolv_conf(tmp_path / "resolv.conf", list(nameservers), **kw)


# --------------------------------------------------------------------------- #
# W1 — the parser itself                                                       #
# --------------------------------------------------------------------------- #

def test_c_unit_resolv_conf_parser(tmp_path):
    ok, msg = run_checks(tmp_path, ["dns_resolv_conf"])[0]
    assert ok, msg


# --------------------------------------------------------------------------- #
# W2 — brix_resolver never fails a config on the file                          #
# --------------------------------------------------------------------------- #

@needs_nginx
def test_missing_resolv_conf_is_a_warning_not_an_error(tmp_path):
    rc, out = parse(tmp_path, STREAM_MAIN=f"brix_resolver auto path={tmp_path}/absent.conf;")
    assert rc == 0, out
    assert "cannot read" in out and "libc defaults" in out, out


@needs_nginx
def test_resolv_conf_without_nameserver_lines_uses_localhost(tmp_path):
    """resolv.conf(5): no nameserver line means the local nameserver."""
    p = tmp_path / "resolv.conf"
    p.write_text("# nothing here\noptions ndots:1\nsearch lab.test\n")
    rc, out = parse(tmp_path, STREAM_MAIN=f"brix_resolver auto path={p};")
    assert rc == 0, out
    assert "no nameserver" not in out and "[emerg]" not in out, out


@needs_nginx
def test_only_unparseable_nameservers_is_a_warning_not_an_error(tmp_path):
    """Every nameserver line skipped: brix says so and the config still
    loads (hostnames use the libc resolver on the thread pool)."""
    p = tmp_path / "resolv.conf"
    p.write_text("nameserver not-an-ip\nnameserver 999.1.1.1\nsearch lab.test\n")
    rc, out = parse(tmp_path, STREAM_MAIN=f"brix_resolver auto path={p};")
    assert rc == 0, out
    assert "no nameserver" in out, out
    assert "[emerg]" not in out, out


@needs_nginx
def test_malformed_lines_are_skipped(tmp_path):
    """Security negative: a hostname in a nameserver line must never reach
    nginx's `resolver`, which would look it up at configuration time."""
    p = tmp_path / "resolv.conf"
    p.write_text("nameserver\nnameserver not-an-ip\noptions ndots:x\n"  # net-literal-allow: malformed-then-valid resolv.conf fixture, parsed only
                 "nameserver 10.0.0.2:x\nnameserver 127.0.0.1\n")
    rc, out = parse(tmp_path, STREAM_MAIN=f"brix_resolver auto path={p};")
    assert rc == 0, out
    assert "[emerg]" not in out and "host not found" not in out, out
    assert "no nameserver" not in out, out


@needs_nginx
def test_ip_port_and_bare_ipv6_nameservers_are_accepted(tmp_path):
    p = _resolv(tmp_path, nameservers=["127.0.0.1:5353", "[::1]:5354", "fe80::1"])  # net-literal-allow: resolv.conf address-syntax fixture, parsed only
    rc, out = parse(tmp_path, STREAM_MAIN=f"brix_resolver auto path={p};")
    assert rc == 0, out
    assert "[emerg]" not in out, out


@needs_nginx
def test_resolver_off_is_accepted(tmp_path):
    rc, out = parse(tmp_path, STREAM_MAIN="brix_resolver off;")
    assert rc == 0, out


@needs_nginx
def test_every_policy_parameter_is_accepted(tmp_path):
    p = _resolv(tmp_path)
    rc, out = parse(tmp_path, STREAM_MAIN=(
        f"brix_resolver auto path={p} valid=30s min_ttl=2s max_ttl=60s "
        "negative_ttl=3s ipv4=on ipv6=off search=off;\n"
        "brix_dns_retry 500ms 10s;\n"
        "brix_dns_cache_max 64;"))
    assert rc == 0, out


@needs_nginx
def test_server_scope_is_accepted_and_main_scope_is_not(tmp_path):
    p = _resolv(tmp_path)
    rc, out = parse(tmp_path, STREAM_KNOBS=f"brix_resolver auto path={p};")
    assert rc == 0, out
    rc, out = parse(tmp_path, OUTER=f"brix_resolver auto path={p};")
    assert rc != 0, out
    assert "is not allowed here" in out or "unknown directive" in out, out


@needs_nginx
def test_http_plane_accepts_the_same_policy(tmp_path):
    p = _resolv(tmp_path)
    rc, out = parse(tmp_path, HTTP_KNOBS=f"brix_resolver auto path={p} ipv6=off;\n"
                                          "brix_dns_retry 200ms 1s;")
    assert rc == 0, out


# --------------------------------------------------------------------------- #
# refusals — one cause each                                                    #
# --------------------------------------------------------------------------- #

@needs_nginx
@pytest.mark.parametrize("line, needle", [
    ("brix_resolver auto bogus=1;", "unknown parameter"),
    ("brix_resolver auto valid=soon;", "brix_resolver"),
    ("brix_resolver auto ipv6=maybe;", "brix_resolver"),
    ("brix_resolver auto path=relative/resolv.conf;", "must be absolute"),
    ("brix_resolver auto path=../../etc/resolv.conf;", "must be absolute"),
    ("brix_resolver auto path=;", "must be absolute"),
    ("brix_dns_retry 1s 200ms;", "expects <initial> <= <max>"),
    ("brix_dns_retry 0 1s;", "expects <initial> <= <max>"),
    ("brix_dns_retry soon 1s;", "invalid time value"),
    ("brix_dns_retry 200ms 1s;\nbrix_dns_retry 200ms 1s;", "is duplicate"),
    ("brix_dns_cache_max lots;", "invalid number"),
])
def test_malformed_directive_is_refused(tmp_path, line, needle):
    rc, out = parse(tmp_path, STREAM_MAIN=line)
    assert rc != 0, f"{line!r} should be refused:\n{out}"
    assert needle in out, f"{line!r}: expected {needle!r} in:\n{out}"


# --------------------------------------------------------------------------- #
# I-DNS-5 — an explicit resolver is honoured by ordering                       #
# --------------------------------------------------------------------------- #

@needs_nginx
def test_explicit_resolver_before_brix_resolver_is_accepted(tmp_path):
    p = _resolv(tmp_path)
    rc, out = parse(tmp_path, STREAM_MAIN=f"resolver 127.0.0.1;\nbrix_resolver auto path={p};")  # net-literal-allow: `resolver` directive under nginx -t; nothing is dialled
    assert rc == 0, out


@needs_nginx
def test_explicit_resolver_after_brix_resolver_is_a_duplicate(tmp_path):
    p = _resolv(tmp_path)
    rc, out = parse(tmp_path, STREAM_MAIN=f"brix_resolver auto path={p};\nresolver 127.0.0.1;")  # net-literal-allow: `resolver` directive under nginx -t; nothing is dialled
    assert rc != 0, out
    assert '"resolver" directive is duplicate' in out, out


# --------------------------------------------------------------------------- #
# path= is opened through symlinks — deliberately (systemd-resolved)           #
# --------------------------------------------------------------------------- #
# On every systemd host /etc/resolv.conf IS a symlink (to
# ../run/systemd/resolve/stub-resolv.conf or .../resolv.conf), so refusing to
# follow one — O_NOFOLLOW, as an early draft of the phase doc claimed — would
# silently degrade the default deployment to "cannot read → nameserver
# 127.0.0.1" and take the search list with it.  resolv_conf.c:452 uses a plain
# fopen() for exactly that reason; these pin the choice so a later hardening
# pass has to argue with a test rather than with a comment.

@needs_nginx
def test_a_symlinked_resolv_conf_is_read_through_the_link(tmp_path):
    """The link's TARGET is parsed: a target holding only unparseable
    nameserver lines produces the "no nameserver" warning, which only the
    contents can produce."""
    target = tmp_path / "real-resolv.conf"
    target.write_text("nameserver not-an-ip\nsearch lab.test\n")
    link = tmp_path / "link-resolv.conf"
    link.symlink_to(target)
    rc, out = parse(tmp_path, STREAM_MAIN=f"brix_resolver auto path={link};")
    assert rc == 0, out
    assert "cannot read" not in out, "the symlink was refused rather than followed"
    assert "no nameserver" in out, out


@needs_nginx
def test_a_symlink_to_a_usable_file_seeds_the_resolver(tmp_path):
    target = tmp_path / "real-resolv.conf"
    target.write_text("nameserver 127.0.0.1\n")  # net-literal-allow: resolv.conf fixture, parsed only
    link = tmp_path / "link-resolv.conf"
    link.symlink_to(target)
    rc, out = parse(tmp_path, STREAM_MAIN=f"brix_resolver auto path={link};")
    assert rc == 0, out
    assert "cannot read" not in out and "no nameserver" not in out, out


@needs_nginx
@pytest.mark.parametrize("kind", ["dangling", "directory", "self"])
def test_an_unreadable_symlink_target_still_starts_the_server(tmp_path, kind):
    """Security-negative: following links must not turn a hostile or broken
    link into a parse failure — a dangling link, a link to a directory and a
    self-referential loop all degrade to the documented warning."""
    link = tmp_path / f"{kind}-resolv.conf"
    if kind == "dangling":
        link.symlink_to(tmp_path / "absent.conf")
    elif kind == "directory":
        link.symlink_to(tmp_path)
    else:
        link.symlink_to(link)
    rc, out = parse(tmp_path, STREAM_MAIN=f"brix_resolver auto path={link};")
    assert rc == 0, f"{kind} symlink must not fail the config:\n{out}"
    assert "cannot read" in out and "libc defaults" in out, out
