#!/usr/bin/env python3
# tests/cvmfs/harness.py — measures a CVMFS cache: TTFB, errors, coalescing,
# corruption admission. Output JSON is the comparison currency across
# squid/varnish/stock-nginx/module runs.
import argparse, concurrent.futures, hashlib, json, time, urllib.request

def percentile(vals, p):
    xs = sorted(vals)
    if not xs:
        return None
    if len(xs) == 1:
        return float(xs[0])
    k = (len(xs) - 1) * p / 100.0
    lo, hi = int(k), min(int(k) + 1, len(xs) - 1)
    return xs[lo] + (xs[hi] - xs[lo]) * (k - lo)

def fetch(url, expect_sha1, timeout=20):
    t0 = time.monotonic()
    try:
        with urllib.request.urlopen(url, timeout=timeout) as r:
            first = r.read(1)
            ttfb = (time.monotonic() - t0) * 1000.0
            body = first + r.read()
        return {"ok": True, "ttfb_ms": ttfb,
                "body_sha1": hashlib.sha1(body).hexdigest(),
                "expect_sha1": expect_sha1}
    except Exception:
        return {"ok": False, "ttfb_ms": None, "body_sha1": None,
                "expect_sha1": expect_sha1}

def summarize(samples):
    oks = [s for s in samples if s["ok"]]
    return {
        "error_rate": (len(samples) - len(oks)) / len(samples) if samples else 0,
        "corrupt_served": sum(1 for s in oks
                              if s["body_sha1"] != s["expect_sha1"]),
        "ttfb_p50_ms": percentile([s["ttfb_ms"] for s in oks], 50),
        "ttfb_p99_ms": percentile([s["ttfb_ms"] for s in oks], 99),
    }

def _expect(url):
    hexd = url.rsplit("/", 2)[-2] + url.rsplit("/", 2)[-1]
    return hexd.rstrip("C")

def _origin_fetches(mock, path):
    log = json.load(urllib.request.urlopen(mock + "/ctl/log"))
    return sum(1 for e in log if e["path"] == path)

def run_scenarios(cache, mock, objects, stampede_n=50):
    out = {}
    cold = [fetch(cache + u, _expect(u)) for u in objects]
    c = summarize(cold)
    out["cold_ttfb_p50_ms"], out["cold_ttfb_p99_ms"] = c["ttfb_p50_ms"], c["ttfb_p99_ms"]
    warm = [fetch(cache + u, _expect(u)) for u in objects]
    out["warm_ttfb_p50_ms"] = summarize(warm)["ttfb_p50_ms"]
    out["error_rate"] = summarize(cold + warm)["error_rate"]
    out["corrupt_served"] = summarize(cold + warm)["corrupt_served"]

    # stampede: N concurrent cold requests for ONE object → count origin hits
    victim = objects[-1]
    before = _origin_fetches(mock, victim)
    with concurrent.futures.ThreadPoolExecutor(max_workers=stampede_n) as ex:
        res = list(ex.map(lambda _: fetch(cache + victim, _expect(victim)),
                          range(stampede_n)))
    assert all(r["ok"] for r in res), "stampede requests failed"
    out["stampede_origin_fetches"] = _origin_fetches(mock, victim) - before
    return out

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--cache", required=True)
    ap.add_argument("--mock", required=True)
    ap.add_argument("--out", required=True)
    args = ap.parse_args()
    objects = json.load(urllib.request.urlopen(args.mock + "/ctl/objects"))
    results = run_scenarios(args.cache, args.mock, objects)
    with open(args.out, "w") as f:
        json.dump(results, f, indent=2)
    print(json.dumps(results, indent=2))

if __name__ == "__main__":
    main()
