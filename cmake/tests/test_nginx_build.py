"""Exercise CMake's nginx orchestration without compiling the full module."""

import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest


REPO = Path(__file__).resolve().parents[2]
FAKE_CONFIGURE = r'''#!/usr/bin/env python3
import json
import os
from pathlib import Path
import shlex
import sys

arguments = sys.argv[1:]
output = Path(next(arg.split("=", 1)[1] for arg in arguments if arg.startswith("--builddir=")))
output.mkdir(parents=True, exist_ok=True)
Path("configure-arguments.json").write_text(json.dumps(arguments))
with Path("configure-runs").open("a") as history:
    history.write("configured\n")
version = Path("source-version").read_text().strip()
modules = ["ngx_stream_brix_module.so", "ngx_http_brix_xrdhttp_filter_module.so", "ngx_stream_module.so"]
def recipe(name):
    return "\t@printf '%s\\n' " + shlex.quote(version) + " > " + shlex.quote(str(output / name)) + "\n"
# nginx's root Makefile exposes default -> build, and modules; there is no all.
makefile = ".PHONY: default build modules\ndefault: build\nbuild: modules\n" + recipe("nginx") + "modules:\n"
makefile += "".join(recipe(module) for module in modules)
Path("Makefile").write_text(makefile)
if os.environ.get("FAKE_CONFIGURE_FAIL"):
    sys.exit(1)
(output / "Makefile").write_text(makefile)
'''


@unittest.skipUnless(shutil.which("cmake") and shutil.which("make"), "cmake and make required")
class NginxBuildTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="brix-nginx-cmake-")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.build = self.root / "build"

    def source(self, version, name=None):
        source = self.root / (name or f"nginx-{version}")
        (source / "src/core").mkdir(parents=True)
        (source / "src/core/nginx.h").write_text(f'#define NGINX_VERSION "{version}"\n')
        (source / "source-version").write_text(version)
        (source / "configure").write_text(FAKE_CONFIGURE)
        (source / "configure").chmod(0o755)
        return source

    def configure(self, source, *options, success=True):
        result = subprocess.run(
            ["cmake", "-S", str(REPO), "-B", str(self.build),
             "-DBRIX_BUILD_CLIENT=OFF", "-DBRIX_BUILD_JOBS=2",
             f"-DNGINX_SRC_DIR={source}", *options],
            capture_output=True, text=True,
        )
        if success:
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        else:
            self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        return result.stdout + result.stderr

    def run_build(self, success=True, **overrides):
        result = subprocess.run(
            ["bash", str(self.build / "build-nginx-modules.sh")],
            capture_output=True, text=True,
            env={**os.environ, **overrides},
        )
        if success:
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        else:
            self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        return result.stdout

    def test_matching_executable_source_switch_and_incremental_build(self):
        for version in ("1.20.1", "1.28.3", "1.31.5"):
            source = self.source(version)
            output = self.configure(source, "-DBRIX_BUILD_NGINX=OFF")
            self.assertIn(f"version {version}", output)
            self.assertIn("modules (-j2)", self.run_build())
            self.assertFalse((self.build / "modules/nginx").exists())
            self.configure(source, "-DBRIX_BUILD_NGINX=1")
            self.assertIn("build (-j2)", self.run_build())
            self.assertEqual((self.build / "modules/nginx").read_text().strip(), version)
            self.assertEqual((self.build / "nginx-src/configure-runs").read_text(), "configured\n")
            self.assertFalse((source / "Makefile").exists(), "source tree must remain untouched")

    def test_flag_change_discards_stale_objects(self):
        source = self.source("1.28.3")
        self.configure(source, "-DBRIX_MODULE_CFLAGS=-O0")
        self.run_build()
        stale = self.build / "modules/stale.o"
        stale.touch()
        self.configure(source, "-DBRIX_MODULE_CFLAGS=-O2")
        self.run_build()
        self.assertFalse(stale.exists())
        arguments = json.loads((self.build / "nginx-src/configure-arguments.json").read_text())
        self.assertTrue(any(arg.startswith("--with-cc-opt=-O2") for arg in arguments))
        stale.touch()
        self.run_build(BRIX_ENABLE_IO_URING="1", BRIX_OPTIMIZE="v3")
        self.assertFalse(stale.exists())

    def test_invalid_source_and_options_fail_before_build(self):
        output = self.configure(self.root / "missing", success=False)
        self.assertIn("nginx source not found", output)
        source = self.source("1.28.3")
        output = self.configure(source, "-DBRIX_BUILD_JOBS=0", success=False)
        self.assertIn("BRIX_BUILD_JOBS must be a positive integer", output)
        output = self.configure(source, "-DBRIX_BUILD_MODULES=OFF", "-DBRIX_BUILD_NGINX=ON", success=False)
        self.assertIn("BRIX_BUILD_NGINX requires BRIX_BUILD_MODULES=ON", output)

    def test_failed_reconfigure_cannot_reuse_previous_stamp(self):
        source = self.source("1.28.3")
        self.configure(source)
        self.run_build()
        (self.build / "nginx-src/Makefile").unlink()
        self.run_build(success=False, FAKE_CONFIGURE_FAIL="1")
        self.assertFalse((self.build / "nginx-src/.brix-config-id").exists())
        self.run_build()
        self.assertTrue((self.build / "nginx-src/.brix-config-id").exists())

    def test_shell_metacharacters_stay_literal(self):
        source = self.source("1.28.3", "nginx source's tree")
        marker = self.root / "injected"
        flags = f"-DVALUE='quoted' $(touch {marker}) `touch {marker}`"
        self.configure(source, f"-DBRIX_MODULE_CFLAGS={flags}")
        self.run_build()
        self.assertFalse(marker.exists())
        arguments = json.loads((self.build / "nginx-src/configure-arguments.json").read_text())
        self.assertTrue(any(arg.startswith(f"--with-cc-opt={flags}") for arg in arguments))

    def test_generated_directory_cannot_be_selected_as_source(self):
        source = self.source("1.28.3", "build/nginx-src")
        output = self.configure(source, success=False)
        self.assertIn("must not contain each other", output)
        self.assertTrue((source / "configure").exists())


if __name__ == "__main__":
    unittest.main()
