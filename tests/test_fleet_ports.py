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
