# SciTags packet marking — a CMS deployment example

**Status:** how-to / configuration example (subsystem: [`src/pmark/`](../../src/pmark/README.md))
**Design reference:** [`docs/refactor/phase-34-packet-marking-scitags.md`](../refactor/phase-34-packet-marking-scitags.md)
**Wire spec:** WLCG flow-label marking — IETF `draft-cc-v6ops-wlcg-flow-label-marking`
**Worked from:** CMS data-access layer, [`cms-sw/cmssw` commit `c2797da`](https://github.com/cms-sw/cmssw/commit/c2797dac7df63c62c1aa66a48b65f51f3a764db4)

This page shows how to configure an `nginx-xrootd` gateway so that **CMS jobs which
attach a SciTag to their reads/writes are correctly accounted and marked** — both
out-of-band (Firefly UDP to a site `flowd` collector) and in-band (the IPv6 Flow
Label routers and NRENs read off the wire).

---

## 1. How CMS uses SciTags

CMS appends a SciTag to the XRootD URL as a CGI/opaque argument:

```
root://eoscms.cern.ch//store/data/...root?scitag.flow=206
```

`scitag.flow` carries a **16-bit flow-id**, defined by XRootD as:

```
flow-id = (experiment << 6) | activity          (experiment 1..1023, activity 1..63)
```

So `scitag.flow=206` means **experiment 3 (CMS)**, **activity 14**. CMS assigns a
contiguous block of activity codes to its workflows
([`ScitagConfig.cc`](https://github.com/cms-sw/cmssw/blob/master/FWStorage/Services/plugins/ScitagConfig.cc),
range `193..216` = exp 3, activities 1..24):

| Workflow                | `scitag.flow` | experiment | activity |
|-------------------------|---------------|------------|----------|
| Analysis (primary)      | `206`         | 3 (CMS)    | 14       |
| Production (primary)    | `204`         | 3 (CMS)    | 12       |
| Embedded data           | `215`         | 3 (CMS)    | 23       |
| Pre-mixed pileup        | `216`         | 3 (CMS)    | 24       |

> **The `c2797da` lesson.** CMS had previously been putting the *packet-header*
> value (e.g. `196664`) into `scitag.flow`. That is the **IPv6 Flow Label** value,
> not the flow-id. The fix was to send the flow-id (`206`) on the CGI argument and
> let the endpoint encode the flow label. `nginx-xrootd` does exactly that — see §4.

The gateway must:

1. **Honour** the client's `scitag.flow` (it is *accounting only* — it never widens
   authorization).
2. **Report** the `(experiment, activity)` to the site `flowd` collector via a
   Firefly datagram (which `flowd` then turns into a flow-label encoding).
3. **Stamp** the IPv6 Flow Label on the data socket so the marking is visible to
   the network even without the collector.

---

## 2. Minimal `nginx.conf` for a CMS site

SciTags directives live in the shared `common` preamble, so the *same* set works in
the `root://` stream `server {}` and in the WebDAV/S3 `location {}` blocks.

### `root://` (stream) — the path CMS jobs actually use

```nginx
stream {
    server {
        listen 1094;                       # root://  (and 1095 for roots:// + GSI)
        xrootd;
        xrootd_export /eos/cms;

        # ---- SciTags packet marking --------------------------------------
        xrootd_pmark               on;                       # master switch
        xrootd_pmark_scitag_cgi    on;                       # honour scitag.flow=N
        xrootd_pmark_firefly       on;                       # out-of-band reporting
        xrootd_pmark_firefly_dest  flowd.mysite.example:10514;
        xrootd_pmark_flowlabel     on;                       # in-band IPv6 label (default on)

        # Identify ourselves in the Firefly "application" field
        xrootd_pmark_appname       nginx-xrootd/eoscms;

        # Names below are resolved through the SciTags registry JSON
        xrootd_pmark_defsfile      /etc/xrootd/scitags.json;

        # Fallback mapping when a client sends NO scitag.flow:
        #   everything under this gateway is CMS, default activity = "default"
        xrootd_pmark_map_experiment default              cms;
        xrootd_pmark_map_activity   cms     default      default;
    }
}
```

That is all a CMS site needs. With `xrootd_pmark_scitag_cgi on`, a client that
sends `?scitag.flow=206` overrides the fallback and the flow is marked **exp 3 /
act 14** end-to-end.

### WebDAV / S3 (`davs://`, `https://`) — same directives in `location`

```nginx
http {
    server {
        listen 8443 ssl;
        location / {
            xrootd_webdav on;
            xrootd_pmark              on;
            xrootd_pmark_scitag_cgi   on;        # honour ?scitag.flow=N on the URL
            xrootd_pmark_firefly_dest flowd.mysite.example:10514;
            xrootd_pmark_defsfile     /etc/xrootd/scitags.json;
            xrootd_pmark_map_experiment default cms;

            # Third-party COPY is always marked. To also mark plain GET/PUT:
            xrootd_pmark_http_plain   on;
        }
    }
}
```

For HTTP the SciTag is taken from the request query string
(`...?scitag.flow=206`).

---

## 3. The SciTags registry (`scitags.json`)

`xrootd_pmark_defsfile` points at the standard SciTags experiment/activity
registry so you can map by **name** instead of hard-coding numbers. It is the same
JSON the SciTags project publishes
(<https://www.scitags.org/api.html> / `flowd` ships a copy). Minimal CMS slice:

```json
{
  "experiments": [
    {
      "expId": 3,
      "expName": "cms",
      "activities": [
        { "activityId": 12, "activityName": "production" },
        { "activityId": 14, "activityName": "default" },
        { "activityId": 23, "activityName": "embedded" },
        { "activityId": 24, "activityName": "premix" }
      ]
    }
  ]
}
```

> Key names matter: the parser ([`defsfile.c`](../../src/pmark/defsfile.c))
> reads `expId` / `expName` and `activityId` / `activityName`.

The defsfile is **optional**: if a client always sends `scitag.flow=N`, the numeric
codes are used directly and no name resolution is needed. The defsfile only matters
for the `xrootd_pmark_map_experiment` / `xrootd_pmark_map_activity` *fallback* rules
(which are by name).

---

## 4. What goes on the wire (and why it matches CMS)

When a flow is marked **exp 3, act 14**, two things happen:

**Firefly UDP** to `flowd.mysite.example:10514` — a JSON document reporting the
flow's `experiment-id: 3`, `activity-id: 14`, byte counts, RTT and 5-tuple. This is
byte-compatible with XRootD's `XrdNetPMarkFF`, so existing site `flowd` collectors
and SciTags dashboards consume it unchanged.

**IPv6 Flow Label** stamped on the data socket. The 20-bit label layout is the WLCG
spec (`draft-cc-v6ops-wlcg-flow-label-marking`, bit 1 = most-significant):

```
pos: 01 02|03 04 05 06 07 08 09 10 11|12|13 14 15 16 17 18|19 20
     E  E | C  C  C  C  C  C  C  C  C| E| A  A  A  A  A  A | E  E
```

* **A** (activity, 6 bits) — positions 13–18
* **C** (community/experiment, 9 bits) — positions 3–11, **in reversed bit order**
* **E** (entropy, 5 bits) — positions 1,2,12,19,20, randomised once per flow

For exp 3, act 14 the structural value is

```
(reverse9(3) << 9) | (14 << 2) = 0x30000 | 0x38 = 196664
```

— **exactly the value CMS reads back off the wire** (the `196664` from `c2797da`),
plus the 5 random entropy bits the spec adds for ECMP spread.

> Flow-label stamping needs a real (non-mapped) IPv6 peer and a kernel that permits
> leasing a specific label (`net.ipv6.flowlabel_state_ranges` / `CAP_NET_ADMIN`). It
> is **fail-open**: on IPv4, a v4-mapped peer, or a kernel that refuses, the label is
> simply not set and the Firefly path still reports the flow. Nothing ever fails,
> blocks, or slows a transfer because of marking.

---

## 5. Verifying it works

```bash
# 1. Watch the site collector (or a stand-in) receive Firefly datagrams:
nc -u -l 10514            # or: tcpdump -A -i any udp port 10514

# 2. Drive a marked read through the gateway:
xrdcp 'root://localhost:1094//eos/cms/store/test.root?scitag.flow=206' /dev/null

#    -> Firefly JSON shows  "experiment-id":3,"activity-id":14

# 3. Confirm the in-band label on an IPv6 transfer:
#    capture on the data interface and read the 20-bit flow label; masking off the
#    entropy bits (0x000C0103) must leave 196664 for scitag.flow=206.
tcpdump -i any 'ip6 and host <client-v6>' -vv | grep -i flowlabel
```

Marking counters are exported on `/metrics`:
`pmark_flows_started_total`, `pmark_firefly_sent_total`,
`pmark_flowlabel_set_total`, `pmark_flowlabel_failed_total`,
`pmark_map_unresolved_total`.

---

## 6. Directive reference (CMS-relevant subset)

| Directive | Default | Meaning |
|---|---|---|
| `xrootd_pmark on\|off` | off | master switch |
| `xrootd_pmark_scitag_cgi on\|off` | on | honour client `scitag.flow=N` (override) |
| `xrootd_pmark_firefly on\|off` | on | emit Firefly UDP reports |
| `xrootd_pmark_firefly_dest host[:port]` | — | collector (repeatable; `origin` = the client; default port 10514) |
| `xrootd_pmark_flowlabel on\|off` | on | stamp the IPv6 Flow Label |
| `xrootd_pmark_defsfile <path>` | — | SciTags experiment/activity JSON registry |
| `xrootd_pmark_appname <str>` | `nginx-xrootd` | Firefly `application` field |
| `xrootd_pmark_map_experiment {default\|path <p>\|vo <v>} <expName>` | — | fallback experiment when no `scitag.flow` |
| `xrootd_pmark_map_activity <expName> {default\|role <r>\|user <u>} <actName>` | — | fallback activity |
| `xrootd_pmark_http_plain on\|off` | off | also mark plain WebDAV/S3 GET/PUT (TPC always marked) |
| `xrootd_pmark_echo <seconds>` | 0 (off) | periodic "ongoing" Firefly for long flows |

See the [`src/pmark/` README](../../src/pmark/README.md) and the
[phase-34 design doc](../refactor/phase-34-packet-marking-scitags.md) for the full
directive list, the XRootD `pmark` equivalence table, and the control/data flow.
