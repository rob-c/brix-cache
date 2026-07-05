"""Fixtures for the k8s-tests suite — all boilerplate lives here so test bodies
stay one line. See labkit/{expect,paths,scenarios}.py and labkit/{shell,kube,
images,helm}.py for the supporting layer.

Tiers:  pytest -m 'not e2e'  (fast, no cluster)  ·  pytest -m e2e  (docker/minikube)
"""
from __future__ import annotations

import sys

import pytest

HERE = __import__("pathlib").Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))                       # import labkit
sys.path.insert(0, str(HERE.parent))                # import labtools (the tool logic)
sys.path.insert(0, str(HERE.parent / "remote-suite" / "tests"))  # import klib

from labkit import paths, shell            # noqa: E402
from labkit.expect import Result, Text     # noqa: E402


def pytest_configure(config):
    config.addinivalue_line("markers", "e2e: needs a live minikube/docker")


def pytest_collection_modifyitems(config, items):
    if config.getoption("-m") == "e2e":
        return
    skip = pytest.mark.skip(reason="e2e: run with -m e2e")
    for item in items:
        if "e2e" in item.keywords:
            item.add_marker(skip)


# --------------------------------------------------------------------------
# Command runners — return a fluent Result (.ok()/.fails()/.shows()).
# --------------------------------------------------------------------------
class Lab:
    def __call__(self, *args, env=None):
        return Result(shell.lab(*[str(a) for a in args], env=env))

    def dry(self, *args, env=None):
        return Result(shell.lab(*[str(a) for a in args], dry=True, env=env))


@pytest.fixture
def lab():
    return Lab()


@pytest.fixture
def reads():
    """Read a lab-relative file as fluent Text: ``reads("README.md").shows(...)``."""
    return lambda rel: Text(paths.LAB / rel)


@pytest.fixture
def absent():
    """True iff none of the lab-relative paths exist."""
    return lambda *rels: all(not (paths.LAB / r).exists() for r in rels)


@pytest.fixture
def catalog_yaml():
    return paths.scenario_file("catalog.yaml")


@pytest.fixture
def tmp_file(tmp_path):
    """Write ``content`` to a temp file and return its path."""
    def _make(name, content):
        p = tmp_path / name
        p.write_text(content)
        return p
    return _make


# --------------------------------------------------------------------------
# klib against an in-memory FakeServer (no cluster). ``svc`` binds service +
# base dir so tests are ``svc.write("f", b"x"); svc.read("f")``.
# --------------------------------------------------------------------------
class FakeServer:
    def __init__(self):
        import re
        self._re = re
        self.files, self.dirs = {}, {"/data/xrootd", "/tmp"}
        self.modes, self.xattrs, self.links = {}, {}, {}

    def exec(self, service, namespace, argv, stdin=None):
        import klib
        rc, out = self._dispatch(argv, stdin)
        return klib._Result(rc, out, "")

    def _exists(self, p):
        return p in self.files or p in self.dirs or p in self.links

    def _dispatch(self, argv, stdin):
        if argv[:2] == ["sh", "-c"]:
            return self._shell(argv[2], stdin)
        cmd, rest = argv[0], argv[1:]
        if cmd == "test":
            ok = {"-e": self._exists, "-d": self.dirs.__contains__,
                  "-f": self.files.__contains__}[rest[0]](rest[1])
            return (0 if ok else 1), ""
        if cmd == "ls":
            p = rest[1]
            if p not in self.dirs:
                return 1, ""
            kids = {q[len(p):].lstrip("/").split("/")[0]
                    for q in [*self.files, *self.dirs, *self.links]
                    if q.startswith(p.rstrip("/") + "/")}
            return 0, "\n".join(sorted(k for k in kids if k))
        if cmd == "mkdir":
            self.dirs.add(rest[-1]); return 0, ""
        if cmd == "rm":
            p = rest[-1]
            self.files.pop(p, None); self.links.pop(p, None); self.dirs.discard(p)
            if rest[0] == "-rf":
                for q in [*self.files, *self.dirs]:
                    if q.startswith(p.rstrip("/") + "/"):
                        self.files.pop(q, None); self.dirs.discard(q)
            return 0, ""
        if cmd == "chmod":
            if not self._exists(rest[1]):
                return 1, ""
            self.modes[rest[1]] = int(rest[0], 8); return 0, ""
        if cmd == "stat":
            p = rest[-1]
            return (0, "%o" % self.modes[p]) if p in self.modes else (1, "")
        if cmd == "setfattr":
            self.xattrs[(rest[-1], rest[1])] = rest[3].encode("latin-1"); return 0, ""
        if cmd == "ln":
            self.links[rest[-1]] = rest[-2]; return 0, ""
        return 1, ""

    def _shell(self, script, stdin):
        import base64
        if (m := self._re.match(r"base64 -w0 -- '(.+)'$", script)):
            f = m.group(1)
            return (0, base64.b64encode(self.files[f]).decode()) if f in self.files else (1, "")
        if (m := self._re.match(r"head -c \d+ \| base64 -d > '(.+)'$", script)):
            self.files[m.group(1)] = base64.b64decode(stdin); return 0, ""
        if (m := self._re.match(r"getfattr -n '(.+)' --only-values -- '(.+)' \| base64 -w0$", script)):
            k = (m.group(2), m.group(1))
            return (0, base64.b64encode(self.xattrs[k]).decode()) if k in self.xattrs else (1, "")
        return 1, ""


class Svc:
    """Thin facade over klib bound to a service + base dir."""
    def __init__(self, fake, service="mega", base="/data/xrootd"):
        import klib
        self.k, self.fake, self.s, self.base = klib, fake, service, base

    def _p(self, p):
        return p if p.startswith("/") else f"{self.base}/{p}"

    def write(self, p, data):   self.k.svc_write(self.s, self._p(p), data)
    def read(self, p):          return self.k.svc_read(self.s, self._p(p))
    def mkdir(self, p):         self.k.svc_mkdir(self.s, self._p(p))
    def exists(self, p):        return self.k.svc_exists(self.s, self._p(p))
    def isfile(self, p):        return self.k.svc_isfile(self.s, self._p(p))
    def isdir(self, p):         return self.k.svc_isdir(self.s, self._p(p))
    def listdir(self, p=None):  return self.k.svc_listdir(self.s, self._p(p) if p else self.base)
    def rm(self, p):            self.k.svc_rm(self.s, self._p(p))
    def rmtree(self, p):        self.k.svc_rmtree(self.s, self._p(p))
    def chmod(self, p, m):      self.k.svc_chmod(self.s, self._p(p), m)
    def mode(self, p):          return self.k.svc_mode(self.s, self._p(p))
    def setxattr(self, p, n, v): self.k.svc_setxattr(self.s, self._p(p), n, v)
    def getxattr(self, p, n):   return self.k.svc_getxattr(self.s, self._p(p), n)
    def symlink(self, target, link): self.k.svc_symlink(self.s, target, self._p(link))


@pytest.fixture
def svc(monkeypatch):
    import klib
    fake = FakeServer()
    monkeypatch.setattr(klib, "_exec", fake.exec)
    return Svc(fake)


# --------------------------------------------------------------------------
# e2e: images (build once, run scripts) and live topologies (deploy/verify).
# --------------------------------------------------------------------------
class Container:
    def __init__(self, tag):
        self.tag = tag

    def run(self, script, env=None):
        from labkit import images
        return Result(images.run_(self.tag, ["bash", "-lc", script], env=env))

    def runs(self, script, env=None):
        """Run and assert success (rc 0)."""
        return self.run(script, env).ok()


@pytest.fixture(scope="session")
def img():
    """Build every lab image once; ``img("server").runs("cmd")``."""
    from labkit import images
    from labkit.scenarios import IMAGES
    tags = {}
    for name, (dockerfile, ctx) in IMAGES.items():
        tag = f"brix-{name}:pytest"
        df = paths.LAB / "images" / dockerfile
        context = paths.REPO if ctx == "." else paths.LAB / ctx
        assert images.build(tag, df, context).returncode == 0, name
        tags[name] = tag
    return lambda name: Container(tags[name])


@pytest.fixture
def topology():
    """Deploy a profile's topology, run its ``xrd-lab test``, tear down.

    ``topology("fleet").shows("fleet OK")``.
    """
    from labkit.scenarios import LIVE
    lab, torn = Lab(), []
    def _run(profile):
        deploy = LIVE[profile][0]
        lab("up")
        if deploy:
            lab("deploy", deploy); torn.append(deploy)
        return lab("test", profile)
    yield _run
    for d in torn:
        lab("down", d)


@pytest.fixture(scope="session")
def kube():
    from labkit.kube import Kube
    return Kube()
