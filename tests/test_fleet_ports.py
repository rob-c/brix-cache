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

import settings
import fleet_specs
import fleet_ports as fp


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
