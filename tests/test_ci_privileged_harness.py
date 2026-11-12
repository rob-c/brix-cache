"""Native account groups and occupied fixture ports retain security proofs."""

import socket
from types import SimpleNamespace

import pytest

from brix_suite import worker_identity
import config_templates
import ephemeral_port as ports
import impersonation_gridmap_helpers as identity
import _test_brix_fault_proxy_helpers as proxy
from settings import BIND_HOST
from test_fault_proxy_privileged import bfp, test_priv_refused_without_optin as _refusal


@pytest.mark.parametrize('group', ['nobody', 'nogroup'])
def test_explicit_nobody_uses_its_primary_group(monkeypatch, group):
    observed = []

    def account(user):
        observed.append(user)
        return SimpleNamespace(pw_gid=65534)

    monkeypatch.setattr(worker_identity.pwd, 'getpwnam', account)
    monkeypatch.setattr(worker_identity.grp, 'getgrgid',
                        lambda _gid: SimpleNamespace(gr_name=group))
    assert identity.worker_template_values() == {'WORKER_GROUP': group}
    assert observed == ['nobody']


def test_missing_worker_account_does_not_substitute_a_privileged_identity(monkeypatch):
    def absent(user):
        raise KeyError(user)

    monkeypatch.setattr(worker_identity.pwd, 'getpwnam', absent)
    monkeypatch.delenv('BRIX_WORKER_GROUP', raising=False)
    assert identity.worker_template_values() == {'WORKER_GROUP': 'nobody'}


@pytest.mark.parametrize('protocol', ['root', 's3', 'webdav'])
def test_gridmap_templates_keep_the_explicit_unprivileged_account(protocol):
    rendered = config_templates.render_config(
        f'nginx_impersonate_gridmap_{protocol}.conf', WORKER_GROUP='nogroup')
    assert '\nuser nobody nogroup;\n' in rendered
    assert '\nuser root' not in rendered


@pytest.mark.parametrize('case', ['closed', 'active', 'timewait'])
def test_listener_release_control_cannot_claim_a_foreign_lease(monkeypatch, case):
    _port, foreign = proxy._listener()
    available = ports.free_port(BIND_HOST)
    candidates = iter([foreign.getsockname()[1], available])
    with foreign:
        monkeypatch.setattr(ports, 'free_port', lambda _host: next(candidates))
        identity.listener_release_control(case, BIND_HOST)
        with socket.create_connection(foreign.getsockname(), timeout=2):
            accepted, _peer = foreign.accept()
            accepted.close()


def test_privilege_refusal_survives_an_occupied_proxy_listener(bfp, monkeypatch):
    _port, foreign = proxy._listener()
    candidates = iter([foreign.getsockname()[1], *ports.free_ports(3, BIND_HOST)])
    with foreign:
        monkeypatch.setattr(proxy, '_free_port', lambda: next(candidates))
        _refusal(bfp)
        with socket.create_connection(foreign.getsockname(), timeout=2):
            accepted, _peer = foreign.accept()
            accepted.close()
