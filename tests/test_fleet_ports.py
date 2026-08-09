"""Lint the authoritative port-ownership map (``fleet_ports``).

The collection-time server-declaration gate maps a ``settings.py`` port constant
a test references to the fleet spec that owns it.  A wrong or stale map would let
the gate demand the wrong marker (or miss a real dependency), so these tests pin
the map to the specs it describes:

  * completeness — every settings port constant is either owned or explicitly
    exempt, never neither and never both;
  * validity — every owned constant names a real registered fleet spec;
  * consistency — the map agrees with each spec's own declared ``port`` /
    ``extra_ports`` and its env-injected owned listens;
  * single-ownership — no actual port value is owned by two distinct specs
    (this also back-stops the fixed-port collision guard for the main nginx's
    shared listens, which its spec does not enumerate).
"""

import os
import re
from pathlib import Path

import pytest

import settings
import fleet_specs
import fleet_ports as fp
from port_ladder import PORT_COUNT, PORT_FIRST, PORT_LAST


_NET_LITERAL_ALLOW = "net-literal-allow:"
_PORT_CONTEXT = re.compile(
    r"(?i)(?:\bport\b|\blisten\b|\bbind\s*\(|://[^\s'\"]*:)"
)
_PORT_NUMBER = re.compile(r"(?<![\d.])([1-9][0-9]{3,4})(?![\d.])")


def _template_port_literals(path: Path):
    """Yield concrete ports in active registry-template network directives."""
    for lineno, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        code = line.split("#", 1)[0]
        if _NET_LITERAL_ALLOW in line or not _PORT_CONTEXT.search(code):
            continue
        for match in _PORT_NUMBER.finditer(code):
            value = int(match.group(1))
            if 1024 <= value <= 65535:
                yield lineno, value, code.strip()


def _spec_names():
    return {s.name for s in fleet_specs._all_specs()}


def test_every_port_constant_is_owned_or_exempt():
    """No settings port constant may fall through the map."""
    allc = set(fp._port_constants())
    mapped = set(fp.CONST_TO_SPEC)
    exempt = set(fp.EXEMPT_PORTS)
    missing = sorted(allc - mapped - exempt)
    assert not missing, (
        "settings.py port constants with no owner and no exemption — add each to "
        f"fleet_ports.CONST_TO_SPEC (owned) or EXEMPT_PORTS (not a fleet server): {missing}"
    )


def test_complete_port_ladder_is_contiguous_without_gaps():
    """Every central allocation occupies exactly one lane-relative slot."""
    from fleet_lifecycle_ports import (
        LIFECYCLE_EXCLUSIVE_PORTS,
        LIFECYCLE_SHARED_PORTS,
        PARSE_PLACEHOLDER_PORT,
        SHARED_PARSE_PLACEHOLDER_PORT,
    )

    allocated = set(fp._port_constants().values())
    for ledger in (LIFECYCLE_SHARED_PORTS, LIFECYCLE_EXCLUSIVE_PORTS):
        for entry in ledger.values():
            allocated.add(entry["port"])
            allocated.update(entry.get("extra", {}).values())
    for base, span in fp.CMDSCRIPTS_PORTS.values():
        allocated.update(range(base, base + span))
    from cms_mesh_lib import PORTS as cms_mesh_ports
    from hybrid_mesh_lib import PORTS as hybrid_mesh_ports
    allocated.update(cms_mesh_ports.values())
    allocated.update(hybrid_mesh_ports.values())
    allocated.update((PARSE_PLACEHOLDER_PORT, SHARED_PARSE_PLACEHOLDER_PORT))
    # cvmfs conformance sub-ladder: 27 file blocks x 20 + the fuse-trust matrix
    # sub-range, anchored just past the fixed-fleet ladder (all within +2000).
    from cvmfs.conformance_common import (
        PORT_BLOCKS as cvmfs_blocks, _MATRIX_BASE, _MATRIX_WIDTH)
    for base in cvmfs_blocks.values():
        allocated.update(range(base, base + 20))
    allocated.update(range(_MATRIX_BASE, _MATRIX_BASE + _MATRIX_WIDTH))
    # differential-interop per-file fixed ports (INTEROP category)
    import official_interop_lib as _oil
    allocated.update(_oil.worker_port(b) for b in _oil._INTEROP_BASES)

    assert allocated == set(range(PORT_FIRST, PORT_LAST + 1))
    assert len(allocated) == PORT_COUNT


def test_settings_ports_are_exported_to_managed_children():
    assert PORT_FIRST <= settings.NGINX_ANON_PORT <= PORT_LAST
    assert os.environ["NGINX_ANON_PORT"] == str(settings.NGINX_ANON_PORT)
    assert os.environ["TEST_NGINX_ANON_PORT"] == str(settings.NGINX_ANON_PORT)


def test_registry_specs_have_no_port_values_outside_the_ladder():
    """Catch literal primary, extra, and generic template-env port escapes."""
    outside = []
    for spec in fleet_specs._all_specs():
        values = [("port", spec.port), *spec.extra_ports.items()]
        values.extend(
            (f"env.{key}", int(value))
            for key, value in spec.env.items()
            if "PORT" in key and str(value).isdigit()
        )
        outside.extend(
            (spec.name, key, value) for key, value in values
            if value is not None and not PORT_FIRST <= value <= PORT_LAST
        )
    assert not outside, f"registry spec ports escaped TEST_PORT_START ladder: {outside}"


def test_registry_nginx_templates_have_no_numeric_listen_literals():
    """Owned listeners must be placeholders populated by the central registry."""
    literal = re.compile(
        r"\blisten\s+(?:\[[^]]+\]:|[^;\s]+:)?[1-9][0-9]{3,4}\b")
    offenders = []
    for spec in fleet_specs._all_specs():
        if spec.kind != "nginx" or not spec.template:
            continue
        path = Path(__file__).parent / "configs" / spec.template
        for lineno, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
            code = line.split("#", 1)[0]
            if literal.search(code):
                offenders.append((spec.name, spec.template, lineno, code.strip()))
    assert not offenders, f"registry templates contain fixed listen literals: {offenders}"


def test_no_manual_ports_in_central_registry_runtime():
    """Registry-owned runtime endpoints must use central port placeholders.

    This catches the easy-to-miss form that a listen-only lint cannot see: a
    registry server is correctly moved by ``TEST_PORT_START`` while a client,
    cache origin, redirect target, or secondary backend still dials its original
    numeric port.  Use a settings/ledger constant or a rendered placeholder.
    Specs themselves are covered by
    ``test_registry_specs_have_no_port_values_outside_the_ladder`` above. This
    companion scans every config they render, including backend/origin URLs and
    not merely ``listen`` directives. Deliberate non-listening parser vectors
    may use a literal only with a same-line ``net-literal-allow: <why>`` reason.
    """
    tests_root = Path(__file__).parent
    offenders = []

    # Every template reached by the central registry is runtime configuration.
    for spec in fleet_specs._all_specs():
        if not spec.template:
            continue
        path = tests_root / "configs" / spec.template
        if not path.exists():
            continue
        offenders.extend(
            (path.relative_to(tests_root).as_posix(), line, port, source)
            for line, port, source in _template_port_literals(path)
        )

    detail = "\n".join(
        f"  {path}:{line}: port {port}: {source}"
        for path, line, port, source in offenders
    )
    assert not offenders, (
        "manual ports in registry-owned runtime configs bypass the central "
        "TEST_PORT_START registry; use a rendered port placeholder. "
        "For an intentional non-listening parser/security vector, add "
        f"'net-literal-allow: <reason>' on that line:\n{detail}"
    )


def test_manual_port_guard_catches_backend_literals(tmp_path):
    """Regression: the stale cache-origin shape must never evade the guard."""
    config = tmp_path / "port_guard.conf"
    config.write_text(
        "listen {BIND_HOST}:{PORT};\n"
        "brix_storage_backend root://localhost:{ANON_PORT};\n"  # net-literal-allow: port-guard fixture
        "brix_storage_backend root://localhost:11094;\n",  # net-literal-allow: port-guard fixture
        encoding="utf-8",
    )
    assert list(_template_port_literals(config)) == [
        (3, 11094, "brix_storage_backend root://localhost:11094;")  # net-literal-allow: expected fixture
    ]


def test_no_constant_is_both_owned_and_exempt():
    both = sorted(set(fp.CONST_TO_SPEC) & set(fp.EXEMPT_PORTS))
    assert not both, f"constants both owned and exempt — pick one: {both}"


def test_exemptions_name_real_unowned_constants():
    """An exemption must name an actual settings port constant that no spec's
    own port/extra_ports claims (else it is a real fleet server, not exempt)."""
    allc = set(fp._port_constants())
    stray = sorted(set(fp.EXEMPT_PORTS) - allc)
    assert not stray, f"EXEMPT_PORTS names that are not settings port constants: {stray}"

    primary = fp._primary_const_by_spec()
    misfiled = sorted(c for c in fp.EXEMPT_PORTS if c in primary)
    assert not misfiled, (
        "constants marked exempt are actually a spec's declared port — they own a "
        f"fleet server and must move to CONST_TO_SPEC: {misfiled}"
    )


def test_every_owned_constant_targets_a_registered_spec():
    names = _spec_names()
    bad = {c: s for c, s in fp.CONST_TO_SPEC.items() if s not in names}
    assert not bad, f"ownership map points at unknown spec name(s): {bad}"


def test_primary_ports_map_to_their_own_spec():
    """Every constant that names a spec's own ``port``/``extra_ports`` must map
    back to that same spec — the auto-derivable backbone of the map."""
    primary = fp._primary_const_by_spec()
    wrong = {
        c: (fp.CONST_TO_SPEC.get(c), owner)
        for c, owner in primary.items()
        if fp.CONST_TO_SPEC.get(c) != owner
    }
    assert not wrong, f"primary-port constants mis-owned {{const: (mapped, expected)}}: {wrong}"


def test_no_port_value_is_owned_by_two_specs():
    """Two distinct specs owning the same actual port would race for the socket
    at start-all.  Grouping the map by port *value* (not constant name — aliases
    are fine) surfaces any such collision, including the main nginx's shared
    listens that its spec never enumerates."""
    owners = {}
    for const, spec in fp.CONST_TO_SPEC.items():
        owners.setdefault(getattr(settings, const), set()).add(spec)
    clash = {port: sorted(specs) for port, specs in owners.items() if len(specs) > 1}
    assert not clash, f"port value owned by >1 spec (socket race): {clash}"


def test_port_bands_do_not_overlap():
    """The documented bands must be disjoint — an overlap would let a new
    lifecycle/mock allocation silently land in another family's range."""
    bands = sorted(fp.PORT_BANDS, key=lambda b: b[1])
    for (n1, _lo1, hi1, _), (n2, lo2, _hi2, _) in zip(bands, bands[1:]):
        assert hi1 < lo2, f"port bands {n1!r} and {n2!r} overlap ({hi1} >= {lo2})"


def test_all_fixed_bands_sit_below_the_ephemeral_port_floor():
    """Every band holds FIXED server listens, so every band must end below the OS
    ephemeral (local) port range floor.  A fixed listen inside the ephemeral range
    is a latent flake: an outbound client socket can transiently claim the number
    as its source port and nginx then fails to bind (Address already in use).  This
    is the regression guard for the original 34000-36999 placement, which sat wholly
    inside the 32768+ ephemeral range and flaked intermittently on bind."""
    floor = 32768  # conservative default if the sysctl is unreadable
    try:
        with open("/proc/sys/net/ipv4/ip_local_port_range", encoding="utf-8") as fh:
            floor = int(fh.read().split()[0])
    except (OSError, ValueError):
        pass
    offenders = [(name, lo, hi) for name, lo, hi, _ in fp.PORT_BANDS if hi >= floor]
    assert not offenders, (
        f"fixed-port bands overlap the OS ephemeral range (floor={floor}); a client "
        f"socket can steal these listens intermittently — move them below the floor: "
        f"{offenders}"
    )


def test_every_port_constant_falls_in_a_band():
    """Every settings port constant lives in exactly one documented band, so a
    new fixed port cannot be added outside the reserved ranges."""
    unbanded = sorted(
        n for n, v in fp._port_constants().items() if fp.band_of(v) is None
    )
    assert not unbanded, (
        "settings port constants outside every fleet_ports.PORT_BANDS range — "
        f"widen a band or move the port into one: {unbanded}"
    )


def test_lifecycle_ledgers_are_banded_and_collision_free():
    """Every Phase-4 lifecycle fixed port (primary + extras) must sit in its
    ledger's band and be globally unique across BOTH ledgers, so a mutating
    reload/restart subject or an idempotent Bucket-1 instance never shares a
    fixed port with another instance.

    - ``LIFECYCLE_EXCLUSIVE_PORTS`` (mutation subjects) → ``lifecycle-exclusive``
      band (31000-31999).
    - ``LIFECYCLE_SHARED_PORTS`` (idempotent Bucket-1 instances) →
      ``lifecycle-shared`` band (30000-30999).
    """
    from fleet_lifecycle_ports import (
        LIFECYCLE_EXCLUSIVE_PORTS,
        LIFECYCLE_SHARED_PORTS,
    )

    seen: dict[int, str] = {}
    misbanded = []
    collisions = []
    for ledger, want_band in (
        (LIFECYCLE_EXCLUSIVE_PORTS, "lifecycle-exclusive"),
        (LIFECYCLE_SHARED_PORTS, "lifecycle-shared"),
    ):
        for name, entry in ledger.items():
            ports = [(name, "port", entry["port"])]
            ports += [
                (name, key, val) for key, val in entry.get("extra", {}).items()
            ]
            for owner, label, port in ports:
                if fp.band_of(port) != want_band:
                    misbanded.append((owner, label, port, want_band, fp.band_of(port)))
                if port in seen:
                    collisions.append((port, seen[port], f"{owner}.{label}"))
                else:
                    seen[port] = f"{owner}.{label}"
    assert not misbanded, (
        "lifecycle ledger ports outside their (want, got) band: " f"{misbanded}"
    )
    assert not collisions, f"lifecycle ledger port collisions: {collisions}"


def test_lifecycle_shared_halves_merge_without_loss():
    """The two lifecycle-shared ledger halves must merge into the mapping every
    consumer imports, entry for entry and in declaration order.

    The band data is split across ``fleet_ports_shared_waves`` and
    ``fleet_ports_shared_phase5`` for file size only.  A half left out of
    ``fleet_lifecycle_ports``' merge would drop its instances back onto the
    removed dynamic-port path; a reordered merge would silently shift every
    ladder slot after the move, because ``rebase_lifecycle_ledger`` assigns
    slots by iteration order.
    """
    from fleet_lifecycle_ports import LIFECYCLE_SHARED_PORTS
    from fleet_ports_shared_phase5 import LIFECYCLE_SHARED_PORTS_PHASE5
    from fleet_ports_shared_waves import LIFECYCLE_SHARED_PORTS_WAVES

    halves = (LIFECYCLE_SHARED_PORTS_WAVES, LIFECYCLE_SHARED_PORTS_PHASE5)
    assert list(LIFECYCLE_SHARED_PORTS) == [n for half in halves for n in half]
    for half in halves:
        for name, entry in half.items():
            assert LIFECYCLE_SHARED_PORTS[name] is entry, (
                f"{name} is not the same entry object after the merge, so the "
                f"in-place ladder rebase would leave this half holding a "
                f"historical seed port"
            )


def test_lifecycle_shared_halves_reject_a_duplicate_name():
    """A spec name declared in BOTH halves must fail the import outright.

    ``{**a, **b}`` resolves a repeated key silently (b wins), so the same name
    carrying two ports would hand one instance the other's listen — and the
    collision linter above cannot see it, because after the merge only one entry
    survives.  ``fleet_lifecycle_ports`` rejects the overlap instead.
    """
    import importlib

    import fleet_lifecycle_ports
    import fleet_ports_shared_phase5 as phase5
    import fleet_ports_shared_waves as waves

    stolen = next(iter(phase5.LIFECYCLE_SHARED_PORTS_PHASE5))
    original = waves.LIFECYCLE_SHARED_PORTS_WAVES
    waves.LIFECYCLE_SHARED_PORTS_WAVES = dict(original, **{stolen: {"port": 1}})
    try:
        with pytest.raises(AssertionError, match=stolen):
            importlib.reload(fleet_lifecycle_ports)
    finally:
        waves.LIFECYCLE_SHARED_PORTS_WAVES = original
        importlib.reload(fleet_lifecycle_ports)

    assert fleet_lifecycle_ports.lifecycle_ports_for(stolen)[0] == \
        phase5.LIFECYCLE_SHARED_PORTS_PHASE5[stolen]["port"]


def test_cmdscripts_ledger_is_banded_and_collision_free():
    """Every ``CMDSCRIPTS_PORTS`` block (Phase 5) must sit wholly inside the
    ``cmdscripts`` band (29020-29999) and no two blocks may overlap — so two
    cmdscript self-launchers running concurrently on different xdist workers can
    never fight over a fixed listen."""
    seen: dict[int, str] = {}
    misbanded = []
    collisions = []
    for stem, (base, span) in fp.CMDSCRIPTS_PORTS.items():
        for port in range(base, base + span):
            if fp.band_of(port) != "cmdscripts":
                misbanded.append((stem, port, fp.band_of(port)))
            if port in seen:
                collisions.append((port, seen[port], stem))
            else:
                seen[port] = stem
    assert not misbanded, (
        "cmdscripts ledger ports outside the cmdscripts band: " f"{misbanded}"
    )
    assert not collisions, f"cmdscripts ledger port collisions: {collisions}"


def test_secondary_listens_agree_with_env_injection():
    """Where a hand-authored secondary listen is also injected through the spec's
    ``env`` as an owned-listen key, the two must name the same spec."""
    env_owned = {}
    for spec in fleet_specs._all_specs():
        for key, value in spec.env.items():
            if key in fp.OWNED_LISTEN_ENV and str(value).isdigit():
                env_owned.setdefault(int(value), set()).add(spec.name)
    mism = []
    for const, spec in fp._SECONDARY_CONSTS.items():
        owners = env_owned.get(getattr(settings, const))
        if owners is not None and spec not in owners:
            mism.append((const, spec, sorted(owners)))
    assert not mism, f"secondary listen disagrees with env owner {{(const, mapped, env)}}: {mism}"
