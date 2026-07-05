"""Lab image build/run tests (@e2e — need docker). Port of smoke/server/client/
authority_image + client_pki_init bats. The ``img`` fixture builds once and runs
one ``docker run`` assertion per test (``.runs()`` asserts success)."""
import base64

import pytest

from labkit import paths

pytestmark = pytest.mark.e2e


def test_server_has_module_and_client(img):
    img("server").runs("nginx -V 2>&1 | grep -q brix && command -v xrdcp")


def test_client_has_pytest_kubectl_suite_pkiinit(img):
    img("client").runs("command -v pytest && command -v kubectl && "
                       "test -f /opt/brix/tests/settings.py && "
                       "test -f /opt/brix/client-pki-init.sh && python3 --version | grep -q 3.12")


def test_client_worker_has_real_pyxrootd(img):
    img("client").runs('"$XRDCL_WORKER_PYTHON" -c "from XRootD import client; print(1)"')


def test_authority_bundles_provisioning_tools(img):
    img("authority").runs("test -f /opt/brix/tests/pki_helpers.py && "
                          "test -f /opt/brix/utils/make_token.py && "
                          "command -v openssl && command -v kadmin.local && command -v nginx")


def test_authority_generates_a_ca(img):
    img("authority").runs(
        'cd /opt/brix && python3 -c "import sys;sys.path.insert(0,\\"tests\\");'
        'from pki_helpers import blitz_test_pki; blitz_test_pki()" && test -f /tmp/work/pki/ca/ca.pem',
        env={"TEST_ROOT": "/tmp/work"})


def test_smoke_serves_healthz(img):
    img("smoke").runs("nginx -g 'daemon on;' && sleep 1 && "
                      "curl -fsS http://127.0.0.1:8080/healthz -o /dev/null -w '%{http_code}' | grep -q 200")


def test_client_pki_init_lays_out_the_suite_pki(img):
    b64 = base64.b64encode(paths.tool("client-pki-init.sh").read_bytes()).decode()
    img("authority").run(_PKI_SCRIPT, env={"SCRIPT_B64": b64}).ok().shows("CLIENT_PKI_OK")


# client-pki-init.sh rebuilds the settings.py-expected client PKI (CA + user cert
# + working proxy + tokens) from authority material, entirely inside the image.
_PKI_SCRIPT = r'''
  set -e
  echo "$SCRIPT_B64" | base64 -d > /tmp/client-pki-init.sh
  cd /opt/brix
  TEST_ROOT=/work python3 -c "import sys;sys.path.insert(0,\"tests\");from pki_helpers import blitz_test_pki;blitz_test_pki()" >/dev/null
  mkdir -p /auth/pki /auth/jwks
  cp /work/pki/ca/ca.pem /work/pki/user/usercert.pem /work/pki/user/userkey.pem \
     /work/pki/server/hostcert.pem /work/pki/server/hostkey.pem /auth/pki/
  TEST_ROOT=/work python3 utils/make_token.py init /work/tokens >/dev/null
  cp /work/tokens/signing_key.pem /auth/pki/
  cp /work/tokens/jwks.json /auth/jwks/jwks.json
  TEST_ROOT=/client PKI_SRC=/auth/pki JWKS_SRC=/auth/jwks/jwks.json UTILS=/opt/brix/utils \
    bash /tmp/client-pki-init.sh
  for f in pki/ca/ca.pem pki/user/usercert.pem pki/user/userkey.pem \
           pki/user/proxy_std.pem tokens/jwks.json tokens/signing_key.pem; do
    test -f /client/$f
  done
  ls /client/pki/ca/*.0 >/dev/null
  echo CLIENT_PKI_OK
'''
