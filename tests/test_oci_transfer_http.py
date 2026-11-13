"""Real OCI copy/conversion over a bounded registry peer with verified uploads."""

from contextlib import contextmanager
import gzip
import hashlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import subprocess
import threading
from urllib.parse import parse_qs, urlsplit

import pytest

from brix_suite.client_build import client_snapshot
from settings import BIND_HOST, HOST, url_host
from test_oci_convert_estargz import Layout, MT_MANIFEST, _image


def digest(body):
    return 'sha256:' + hashlib.sha256(body).hexdigest()


class RegistryPeer(BaseHTTPRequestHandler):
    """Serve fixed source objects and accept only correctly addressed uploads."""

    def log_message(self, *_arguments):
        pass

    def reply(self, status, body=b'', headers=()):
        self.send_response(status)
        self.send_header('Content-Length', str(len(body)))
        for name, value in headers:
            self.send_header(name, value)
        self.end_headers()
        if self.command != 'HEAD':
            self.wfile.write(body)

    def refused(self, operation):
        self.server.requests.append((self.command, self.path))
        if self.server.fault == operation:
            self.reply(self.server.failure_status)
            return True
        return False

    def do_GET(self):
        if '/manifests/' in self.path:
            if self.refused('manifest-get'):
                return
            body = self.server.manifest
            self.reply(200, body, [('Content-Type', MT_MANIFEST),
                                   ('Docker-Content-Digest', digest(body))])
            return
        if self.refused('blob-get'):
            return
        key = self.path.rsplit('/', 1)[-1]
        body = self.server.source.get(key)
        if body is None:
            self.reply(404)
            return
        if key == self.server.corrupt:
            body = b'changed bytes'
        self.reply(200, body, [('Docker-Content-Digest', key)])

    def do_HEAD(self):
        self.server.requests.append(('HEAD', self.path))
        key = self.path.rsplit('/', 1)[-1]
        self.reply(200 if key in self.server.uploads else 404)

    def do_POST(self):
        if self.refused('session'):
            return
        location = '/v2/target/blobs/uploads/fixture'
        self.reply(202, headers=[('Location', location)])

    def do_PUT(self):
        body = self.rfile.read(int(self.headers.get('Content-Length', '0')))
        if '/manifests/' in self.path:
            if self.refused('manifest-put'):
                return
            self.server.published = body
            self.reply(201, headers=[('Docker-Content-Digest', digest(body))])
            return
        if self.refused('blob-put'):
            return
        key = parse_qs(urlsplit(self.path).query).get('digest', [''])[0]
        if digest(body) != key:
            self.server.errors.append('uploaded bytes did not match requested digest')
            self.reply(400)
            return
        self.server.uploads[key] = body
        self.reply(201, headers=[('Docker-Content-Digest', key)])


@contextmanager
def registry_peer(layout, fault='', failure_status=500, corrupt=''):
    peer = ThreadingHTTPServer((BIND_HOST, 0), RegistryPeer)
    peer.source = {'sha256:' + path.name: path.read_bytes()
                   for path in (layout.root / 'blobs/sha256').iterdir()}
    index = json.loads((layout.root / 'index.json').read_text())
    peer.manifest = layout.blob(index['manifests'][0]['digest'])
    peer.fault, peer.failure_status, peer.corrupt = fault, failure_status, corrupt
    peer.uploads, peer.requests, peer.errors = {}, [], []
    peer.published = None
    thread = threading.Thread(target=peer.serve_forever, daemon=True)
    thread.start()
    try:
        yield peer, f'{url_host(HOST)}:{peer.server_port}'
    finally:
        peer.shutdown()
        peer.server_close()
        thread.join(timeout=5)
        assert not thread.is_alive() and not peer.errors


@pytest.fixture(scope='module')
def oci_transfer(tmp_path_factory):
    root = Path(__file__).resolve().parents[1]
    binary = root / 'client/bin/brixoci'
    return client_snapshot(root / 'client', binary,
                           tmp_path_factory.mktemp('oci-transfer') / binary.name)


def transfer(binary, verb, source, destination, temporary):
    options = ['--estargz'] if verb == 'convert' else []
    return subprocess.run([str(binary), verb, *options, source, destination, '--insecure'],
        env=dict(os.environ, TMPDIR=str(temporary)), capture_output=True, text=True, timeout=30)


def load_destination(peer, destination, layout_destination):
    if layout_destination:
        layout = Layout(destination)
        return layout.manifest(), layout.blob
    assert peer.published is not None
    return json.loads(peer.published), peer.uploads.__getitem__


def assert_converted_image(manifest, blob, original):
    config = json.loads(blob(manifest['config']['digest']))
    original_config = json.loads(original.blob(original.manifest()['config']['digest']))
    assert {k: v for k, v in config.items() if k != 'rootfs'} == {
        k: v for k, v in original_config.items() if k != 'rootfs'}
    for layer, diffid in zip(manifest['layers'], config['rootfs']['diff_ids'], strict=True):
        data = blob(layer['digest'])
        assert digest(data) == layer['digest'] and len(data) == layer['size']
        assert digest(gzip.decompress(data)) == diffid
        assert data[-19:-13] == b'STARGZ'
        assert 'containerd.io/snapshot/stargz/toc.digest' in layer['annotations']


@pytest.mark.parametrize('verb', ['copy', 'convert'])
@pytest.mark.parametrize('layout_source,layout_destination', [(False, False), (True, False),
                                                            (False, True)])
def test_transfers_preserve_content_addressing_across_endpoint_types(oci_transfer, tmp_path,
    verb, layout_source, layout_destination):
    source = _image(tmp_path / 'source')
    destination = tmp_path / 'destination'
    with registry_peer(source) as (peer, address):
        src = endpoint(layout_source, source.root, address + '/source:v1')
        dst = endpoint(layout_destination, destination, address + '/target:v2')
        result = transfer(oci_transfer, verb, src, dst, tmp_path)
    assert result.returncode == 0, result.stdout + result.stderr
    manifest, blob = load_destination(peer, destination, layout_destination)
    if verb == 'convert':
        assert_converted_image(manifest, blob, source)
    else:
        assert manifest == source.manifest()
        for desc in [manifest['config'], *manifest['layers']]:
            assert blob(desc['digest']) == source.blob(desc['digest'])
    assert not list(tmp_path.glob('brixoci-convert-*'))


def endpoint(is_layout, directory, registry):
    return 'oci:' + str(directory) if is_layout else registry


@pytest.mark.parametrize('verb', ['copy', 'convert'])
@pytest.mark.parametrize('operation', ['manifest-get', 'blob-get', 'session', 'blob-put', 'manifest-put'])
@pytest.mark.parametrize('status', [403, 500])
def test_remote_refusals_never_publish_destination_manifest(oci_transfer, tmp_path,
                                                           verb, operation, status):
    source = _image(tmp_path / 'source')
    with registry_peer(source, operation, status) as (peer, address):
        result = transfer(oci_transfer, verb, address + '/source:v1',
                          address + '/target:v2', tmp_path)
    assert result.returncode != 0 and peer.published is None
    assert result.stderr and not list(tmp_path.glob('brixoci-convert-*'))


@pytest.mark.parametrize('verb', ['copy', 'convert'])
@pytest.mark.parametrize('kind', ['config', 'layer'])
def test_digest_mismatch_cannot_reach_manifest_publication(oci_transfer, tmp_path, verb, kind):
    source = _image(tmp_path / 'source')
    manifest = source.manifest()
    target = manifest['config'] if kind == 'config' else manifest['layers'][0]
    with registry_peer(source, corrupt=target['digest']) as (peer, address):
        result = transfer(oci_transfer, verb, address + '/source:v1',
                          address + '/target:v2', tmp_path)
    assert result.returncode != 0 and peer.published is None
    assert 'mismatch' in result.stderr


def replace_manifest(layout, manifest):
    value, size = layout.put(json.dumps(manifest).encode())
    layout.bind(value, size)


@pytest.mark.parametrize('kind,hint', [('no-config', 'no config descriptor'),
    ('no-layers', 'no layers'), ('layer-no-digest', 'no digest'),
    ('no-rootfs', 'no rootfs'), ('no-diffids', 'diff_ids'), ('large-config', 'bytes')])
def test_invalid_registry_image_cannot_publish_converted_manifest(oci_transfer, tmp_path, kind, hint):
    source = _image(tmp_path / 'source')
    malformed_image(source, kind)
    with registry_peer(source) as (peer, address):
        result = transfer(oci_transfer, 'convert', address + '/source:v1',
                          address + '/target:v2', tmp_path)
    assert result.returncode != 0 and peer.published is None
    assert hint in result.stderr


def malformed_image(layout, kind):
    manifest = layout.manifest()
    if kind == 'no-config':
        manifest.pop('config')
    elif kind == 'no-layers':
        manifest.pop('layers')
    elif kind == 'layer-no-digest':
        manifest['layers'][0].pop('digest')
    else:
        malformed_config(layout, manifest, kind)
    replace_manifest(layout, manifest)


def malformed_config(layout, manifest, kind):
    config = json.loads(layout.blob(manifest['config']['digest']))
    if kind == 'no-rootfs':
        config.pop('rootfs')
    elif kind == 'no-diffids':
        config['rootfs'].pop('diff_ids')
    else:
        config['padding'] = 'x' * (8 * 1024 * 1024)
    value, size = layout.put(json.dumps(config).encode())
    manifest['config']['digest'], manifest['config']['size'] = value, size


def test_scratch_creation_failure_never_starts_blob_fetch(oci_transfer, tmp_path):
    source = _image(tmp_path / 'source')
    with registry_peer(source) as (peer, address):
        result = transfer(oci_transfer, 'convert', address + '/source:v1',
                          address + '/target:v2', tmp_path / 'missing')
    assert result.returncode != 0 and peer.published is None
    assert 'scratch file:' in result.stderr
    assert all('/blobs/' not in path for _verb, path in peer.requests)
