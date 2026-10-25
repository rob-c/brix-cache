"""Compile the real CLI listing selector independently of external services."""
import re
import shutil
import subprocess
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture(scope="module")
def selector(tmp_path_factory):
    compiler = shutil.which("cc")
    if compiler is None:
        pytest.skip("C compiler required for CLI listing dispatch contract")
    text = (ROOT / "client/apps/fs/xrdfs_meta_ls.c").read_text()
    match = re.search(r"static int\nls_dirlist\([^{}]+\n\{.*?\n\}", text, re.S)
    assert match, "CLI listing selector missing"
    directory = tmp_path_factory.mktemp("ls-selector")
    source = directory / "selector.c"
    source.write_text('''
#include <stddef.h>
#include <string.h>
#include "protocols/root/protocol/flags.h"
typedef struct { unsigned server_flags; } brix_conn;
typedef struct { int unused; } brix_dirent;
typedef struct { int code; } brix_status;
static int direct_calls, fanout_calls, refuse;
static int brix_dirlist(brix_conn *c, const char *p, int w,
    brix_dirent **e, size_t *n, brix_status *s)
{
    (void)c; (void)p; (void)w; (void)e; (void)s;
    direct_calls++; *n = 0; return 0;
}
static int brix_dirlist_all(brix_conn *c, const char *p, int w,
    brix_dirent **e, size_t *n, brix_status *s)
{
    (void)c; (void)p; (void)w; (void)e;
    fanout_calls++; s->code = refuse ? 3010 : 0; *n = refuse ? 0 : 2;
    return refuse ? -1 : 0;
}
''' + match.group(0) + '''
int main(int argc, char **argv)
{
    brix_conn c = {kXR_isManager};
    brix_dirent *entries = NULL;
    brix_status status = {0};
    size_t count = 0;
    int rc;
    if (argc != 2) return 2;
    if (strcmp(argv[1], "direct") == 0) c.server_flags = kXR_isServer;
    if (strcmp(argv[1], "dual") == 0) c.server_flags |= kXR_isServer;
    refuse = strcmp(argv[1], "refused") == 0;
    rc = ls_dirlist(&c, "/", 1, &entries, &count, &status);
    if (c.server_flags == kXR_isServer)
        return !(rc == 0 && direct_calls == 1 && fanout_calls == 0);
    if (refuse)
        return !(rc == -1 && status.code == 3010 && direct_calls == 0);
    return !(rc == 0 && count == 2 && fanout_calls == 1 && direct_calls == 0);
}
''')
    binary = directory / "selector"
    result = subprocess.run([compiler, "-std=c11", "-Wall", "-Wextra", "-Werror",
                             "-I", str(ROOT / "src"), str(source), "-o", str(binary)],
                            capture_output=True, text=True, timeout=60)
    assert result.returncode == 0, result.stdout + result.stderr
    return binary


@pytest.mark.parametrize("role", ["manager", "direct", "dual"])
def test_listing_uses_the_correct_existing_api(selector, role):
    subprocess.run([str(selector), role], check=True, timeout=5)


def test_failed_fanout_cannot_be_replaced_by_an_empty_success(selector):
    subprocess.run([str(selector), "refused"], check=True, timeout=5)


def test_plain_and_json_listings_share_the_selector():
    text = (ROOT / "client/apps/fs/xrdfs_meta_ls.c").read_text()
    assert "if (ls_dirlist(c, path, (o->want_long" in text
    assert "if (ls_dirlist(c, path, 1 /*want_stat*/" in text
