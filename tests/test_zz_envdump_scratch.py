import json, os, pathlib
def test_dump():
    tag = os.environ.get("PYTEST_XDIST_WORKER", "serial")
    pathlib.Path(f"/tmp/envdump-{tag}.json").write_text(json.dumps(dict(os.environ), indent=0, sort_keys=True))
