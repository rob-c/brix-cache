"""Checkpoint a single measurement across independent CI steps.

Only preparation resets counters. Every required phase must finish successfully
before the final report can pass, even if partial execution exceeds the floor.
The state file contains paths and verdicts, never a saved process environment.
"""

import json
import os
from pathlib import Path
import subprocess
import sys

from tools.ci import coverage


def _write(path, state):
    temporary = path.with_suffix('.tmp')
    temporary.write_text(json.dumps(state, indent=2) + '\n')
    temporary.replace(path)


def _identity(root, nginx_src, test_cmd):
    return {'root': str(Path(root).resolve()),
            'nginx_src': str(Path(nginx_src).resolve()), 'test_cmd': test_cmd,
            'floor': os.environ.get('COVERAGE_MIN'),
            'privileged': os.environ.get('COVERAGE_PRIVILEGED') == '1'}


def _prepare(path, identity, out_dir):
    # Refuse reuse before rebuilding: stale results must never satisfy a new run.
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open('x') as stream:
        stream.write('{}\n')
    coverage._build(identity['root'], out_dir)
    _directories, _initial, units = coverage._prepare_measurement(
        identity['root'], identity['nginx_src'], out_dir)
    _write(path, {'identity': identity, 'units': units.name, 'results': {}})
    return 0


def _load(path, identity):
    state = json.loads(path.read_text())
    if state.get('identity') != identity:
        raise ValueError('coverage stages must use the prepared SDK, command and floor')
    units = path.parent / state['units']
    if state['units'] != units.name or not units.name.startswith('unit-counters-'):
        raise ValueError('invalid coverage counter directory')
    if units.resolve(strict=True).parent != path.parent.resolve():
        raise ValueError('coverage counter directory escaped the report directory')
    if not units.is_dir():
        raise ValueError('coverage counter directory is not a directory')
    return state, units


def _phases(identity):
    return ('ordinary', 'privileged', 'userns') if identity['privileged'] else ('ordinary',)


def _phase_verdict(state):
    results = state['results']
    return 0 if all(type(results.get(phase)) is int and results[phase] == 0
                    for phase in _phases(state['identity'])) else 1


def _execute(stage, identity, units):
    root = identity['root']
    environment = coverage._measurement_environment(root, identity['nginx_src'], units)
    if stage == 'ordinary':
        return subprocess.run(identity['test_cmd'], shell=True, cwd=f'{root}/tests',
                              env=environment).returncode
    if stage == 'userns':
        return coverage._run_userns_group(root, environment)
    helper = str(Path(root) / 'tools/ci/coverage_privileged.py')
    return subprocess.run(['sudo', '-n', '-E', sys.executable, helper],
                          cwd=root, env=environment).returncode


def _test_phase(stage, path, state, units):
    phases = _phases(state['identity'])
    position = phases.index(stage)
    if stage in state['results']:
        raise ValueError('coverage phase already started; use a fresh report directory')
    previous = phases[:position]
    if any(type(state['results'].get(phase)) is not int for phase in previous):
        raise ValueError('previous coverage phase did not finish')
    state['results'][stage] = 'running'
    _write(path, state)
    result = _execute(stage, state['identity'], units)
    state['results'][stage] = result
    _write(path, state)
    return result


def run(stage, root, nginx_src, out_dir, test_cmd):
    identity = _identity(root, nginx_src, test_cmd)
    path = Path(out_dir) / 'stages.json'
    if stage == 'prepare':
        return _prepare(path, identity, out_dir)
    state, units = _load(path, identity)
    if stage != 'report':
        return _test_phase(stage, path, state, units)
    directories = [f'{nginx_src}/objs', f'{root}/client', f'{root}/shared']
    return coverage._report(root, out_dir, directories,
                            str(path.parent / 'coverage.initial.info'), units,
                            _phase_verdict(state))
