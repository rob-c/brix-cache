"""Lock the static attribution that powers the server-declaration gate.

``fleet_declares.analyze_source`` maps each test to the fleet specs it uses (from
the settings.py port constants it references) and the specs it declares (from its
``registry_server`` markers).  The collection gate and the marker codemod both
depend on this being exact, so these tests pin the behaviors they rely on:

  * a referenced dedicated-port constant becomes a requirement, an exempt one
    does not, and a marker satisfies it;
  * requirements flow through module scope, module-level helpers, and a test's
    own body;
  * same-named methods in different classes attribute independently (the gate
    keys on ``qualname``, not the bare name);
  * the always-on backbone is exactly the ``core``-tagged specs;
  * fixture-reachable specs are surfaced (over-approximating) for subset booting.

Constants are discovered from the live ownership map so the suite tracks
settings.py rather than pinning names that may be renamed.
"""

import textwrap

import fleet_declares as fd
import fleet_ports as fp


BACKBONE = fd.backbone_specs()


def _a_dedicated_const():
    """A settings constant owning a dedicated (non-backbone) spec."""
    for const, spec in sorted(fp.CONST_TO_SPEC.items()):
        if spec not in BACKBONE:
            return const, spec
    raise AssertionError("no dedicated port constant in the ownership map")


def _a_backbone_const():
    for const, spec in sorted(fp.CONST_TO_SPEC.items()):
        if spec in BACKBONE:
            return const, spec
    raise AssertionError("no backbone port constant in the ownership map")


def _only(usages, name):
    matches = [u for u in usages if u.name == name]
    assert matches, f"no test named {name} in {[u.name for u in usages]}"
    return matches[0]


def test_referenced_dedicated_constant_becomes_a_requirement():
    const, spec = _a_dedicated_const()
    src = textwrap.dedent(f"""
        from settings import {const}
        def test_uses_it():
            connect({const})
    """)
    usage = _only(fd.analyze_source(src), "test_uses_it")
    assert spec in usage.required
    assert usage.undeclared == {spec}


def test_marker_satisfies_the_requirement():
    const, spec = _a_dedicated_const()
    src = textwrap.dedent(f"""
        import pytest
        from settings import {const}
        @pytest.mark.registry_server("{spec}")
        def test_declared():
            connect({const})
    """)
    usage = _only(fd.analyze_source(src), "test_declared")
    assert spec in usage.required and spec in usage.declared
    assert usage.undeclared == set()


def test_exempt_constant_creates_no_requirement():
    exempt = sorted(fp.EXEMPT_PORTS)[0]
    src = textwrap.dedent(f"""
        from settings import {exempt}
        def test_exempt():
            payload({exempt})
    """)
    usage = _only(fd.analyze_source(src), "test_exempt")
    assert usage.required == set()


def test_requirement_flows_through_module_scope_and_helpers():
    const, spec = _a_dedicated_const()
    # once at module scope, once only via a helper the test calls
    src = textwrap.dedent(f"""
        from settings import {const}
        MODULE_URL = url({const})
        def _helper():
            return open_conn({const})
        def test_via_module_scope():
            pass
        def test_via_helper():
            return _helper()
    """)
    usages = fd.analyze_source(src)
    assert spec in _only(usages, "test_via_module_scope").required
    assert spec in _only(usages, "test_via_helper").required


def test_same_named_methods_in_different_classes_attribute_independently():
    c1, s1 = _a_dedicated_const()
    # a second dedicated spec, distinct from the first
    c2, s2 = next(
        (c, s) for c, s in sorted(fp.CONST_TO_SPEC.items())
        if s not in BACKBONE and s != s1
    )
    src = textwrap.dedent(f"""
        from settings import {c1}, {c2}
        class TestA:
            def test_same(self):
                connect({c1})
        class TestB:
            def test_same(self):
                connect({c2})
    """)
    usages = fd.analyze_source(src)
    a = next(u for u in usages if u.qualname == "TestA::test_same")
    b = next(u for u in usages if u.qualname == "TestB::test_same")
    assert s1 in a.required and s1 not in b.required
    assert s2 in b.required and s2 not in a.required


def test_backbone_is_exactly_the_core_tagged_specs():
    import fleet_specs
    expected = {s.name for s in fleet_specs._all_specs() if "core" in s.tags}
    assert set(fd.backbone_specs()) == expected
    assert fd.backbone_specs(), "backbone must be non-empty"


def test_conftest_fixture_specs_surfaces_dedicated_and_drops_backbone():
    ded_const, ded_spec = _a_dedicated_const()
    bb_const, bb_spec = _a_backbone_const()
    src = textwrap.dedent(f"""
        import pytest
        from settings import {ded_const}, {bb_const}
        @pytest.fixture
        def some_env():
            return {{"a": {ded_const}, "b": {bb_const}}}
        def not_a_fixture():
            return {ded_const}
    """)
    specs = fd.conftest_fixture_specs(src)
    assert ded_spec in specs
    assert bb_spec not in specs  # backbone is always-on, never a fixture "extra"


def test_unparseable_source_is_survived_not_raised():
    assert fd.analyze_source("def broken(:\n") == []
    assert fd.conftest_fixture_specs("def broken(:\n") == frozenset()
    assert fd.module_autouse_specs("def broken(:\n") == frozenset()


def test_module_autouse_specs_surfaces_the_undeclarable_dependency():
    """An autouse fixture binds every test in the module to its server without
    any test naming it, so the boot set must learn it from the fixture itself."""
    ded_const, ded_spec = _a_dedicated_const()
    src = textwrap.dedent(f"""
        import pytest
        from settings import {ded_const}
        @pytest.fixture(scope="session", autouse=True)
        def module_env():
            wait_port({ded_const})
    """)
    assert ded_spec in fd.module_autouse_specs(src)


def test_module_autouse_specs_ignores_non_autouse_fixtures():
    ded_const, ded_spec = _a_dedicated_const()
    src = textwrap.dedent(f"""
        import pytest
        from settings import {ded_const}
        @pytest.fixture(scope="session")
        def opt_in_env():
            wait_port({ded_const})
        @pytest.fixture(autouse=False)
        def explicit_off():
            wait_port({ded_const})
    """)
    assert fd.module_autouse_specs(src) == frozenset()
    # ...while the broader fixture surface still sees them for subset boot.
    assert ded_spec in fd.conftest_fixture_specs(src)


def test_module_autouse_specs_keeps_backbone_references():
    # Since the forced always-on backbone was retired (zero-boot default), an
    # autouse fixture that binds its module to a *core* server is the only static
    # signal that the boot set must start it — so backbone is now KEPT, not
    # dropped (contrast conftest_fixture_specs, which still subtracts it).
    bb_const, bb_spec = _a_backbone_const()
    src = textwrap.dedent(f"""
        import pytest
        from settings import {bb_const}
        @pytest.fixture(autouse=True)
        def core_env():
            wait_port({bb_const})
    """)
    assert bb_spec in fd.module_autouse_specs(src)
