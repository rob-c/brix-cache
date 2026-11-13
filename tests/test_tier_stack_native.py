"""Tier composition preserves driver config, ordering and service ownership."""

import subprocess

import pytest

from test_nginx_native_contract import server_native_compile  # noqa: F401


@pytest.fixture(scope='module')
def tier_stack(server_native_compile):
    names = ('geteuid', 'brix_imp_worker_runtime_ids', 'chown', 'brix_sd_instance_create',
             'brix_sd_stage_create', 'brix_sd_cache_create', 'brix_sd_frm_create_opts')
    binary = server_native_compile('tier-stack', 'tests/c/tier_stack_native_test.c',
        ['-Wl,--wrap=' + name for name in names])
    def run(mode='stack', fault='', root=0, argument='15', expected=1):
        result = subprocess.run([str(binary), mode, fault, str(root), str(argument), str(expected)],
                                capture_output=True, text=True, timeout=10)
        assert result.returncode == 0, result.stdout + result.stderr
        return result.stdout
    return run


@pytest.mark.parametrize('flags', range(16))
def test_only_configured_and_enabled_tiers_wrap_in_order(tier_stack, flags):
    tier_stack(argument=flags)


@pytest.mark.parametrize('fault', ['backend', 'stage-store', 'cache-store', 'stage-wrap', 'cache-wrap'])
def test_failed_stack_never_publishes_partial_result(tier_stack, fault):
    tier_stack(fault=fault, expected=0)


def test_remote_cache_uses_metadata_attributes(tier_stack):
    tier_stack(fault='remote-cache')


@pytest.mark.parametrize('flags', [0, 3, 7, 15])
def test_nearline_backend_requires_configured_recall_store(tier_stack, flags):
    tier_stack(fault='nearline', argument=flags, expected=int(bool(flags & 8)))


@pytest.mark.parametrize('driver', ['posix', 'block', 'ram', 'pblock'])
@pytest.mark.parametrize('fault,expected', [('', 1), ('worker', 1), ('backend', 0)])
def test_local_factory_retains_geometry_capacity_and_privilege_policy(tier_stack, driver, fault, expected):
    tier_stack(mode=driver, fault=fault, expected=expected)


@pytest.mark.parametrize('driver', ['rados', 'ceph'])
@pytest.mark.parametrize('prefix', ['', '/', '/prefix', 'prefix', '//prefix'])
def test_ceph_factory_preserves_pool_and_prefix(tier_stack, driver, prefix):
    assert 'FACTORY ceph' in tier_stack(mode=driver, argument=prefix)


@pytest.mark.parametrize('driver', ['tape', 'frm'])
@pytest.mark.parametrize('query,depth', [('', 0), ('arc=1', 1), ('arc=8', 8)])
def test_tape_archive_options_reach_factory(tier_stack, driver, query, depth):
    assert f'DEPTH {depth}' in tier_stack(mode=driver, argument=query)


@pytest.mark.parametrize('query', ['arc=0', 'arc=9', 'unknown=1', 'arc=1&bad=1'])
def test_invalid_tape_options_do_not_call_factory(tier_stack, query):
    assert 'created=0' in tier_stack(mode='tape', argument=query, expected=0)


def test_unknown_driver_never_creates_an_instance(tier_stack):
    assert 'created=0' in tier_stack(mode='unknown', expected=0)


@pytest.mark.parametrize('fault', ['', 'missing', 'denied'])
def test_root_handoff_attempts_every_known_store_file(tier_stack, fault):
    output = tier_stack(mode='handoff', fault=fault, root=1, expected=10)
    assert 'identities=1 chowns=10' in output


@pytest.mark.parametrize('root,fault,identities', [(0, '', 0), (1, 'worker', 0),
    (1, 'null-root', 0), (1, 'identity', 1)])
def test_inapplicable_or_failed_identity_never_changes_ownership(tier_stack, root, fault, identities):
    output = tier_stack(mode='handoff', fault=fault, root=root, expected=0)
    assert f'identities={identities} chowns=0' in output
