# What is this project?

Physicists need to move hundreds of terabytes of collision data between storage nodes and analysis farms. They use two purpose-built protocols for this: XRootD and WebDAV. Neither is something nginx has ever spoken natively — until this module.

> **Just want the glossary?** Every term used in this project is explained in the [Glossary](../10-reference/glossary.md).

---

## In one sentence

`nginx-xrootd` serves petabyte-scale physics datasets over three protocols — XRootD, WebDAV, and S3 — from one nginx process, with no extra daemons.

> **Looking for terminology?** See the [Glossary](../10-reference/glossary.md) — every technical term in this project explained in plain English.

---

## The problem it solves

### Before: three services, three configs, three pager alerts

If you want to share large files with physicists, you need:

| Protocol | What you run |
|---|---|
| [XRootD](../10-reference/glossary.md#xrootd) (`root://`) | `xrootd` daemon (separate process) |
| [WebDAV](../10-reference/glossary.md#webdav) (`davs://`) | Apache/Nginx + WebDAV module (separate config) |
| S3 REST API | MinIO or similar object store (separate service) |

**Three services, three configs, three operational headaches.**

### After: one process, all three protocols

One nginx binary. One configuration file. The same `/data` tree visible three ways:
                    You configure one thing:
                    
                        /data/publications/
                                         │
                         ┌───────────────┼───────────────┐
                         │               │               │
              root://your-server//    davs://your-     s3://your-
              /publications/          server//         server/
                                         publications/   publications/
```

Physicists at CERN, SLAC, and Fermilab move **petabytes** of collision data daily using these tools. This project puts that stack inside one nginx server.

---

## XRootD in plain English

XRootD is a file transfer protocol — think **FTP but purpose-built for 50-GB physics files and parallel multi-server downloads**. It's used almost exclusively in High Energy Physics:

| Thing | Analogy | What it does |
|---|---|---|
| `root://` | Like `http://` or `ftp://` | A URL scheme for XRootD addresses |
| [xrdcp](../10-reference/glossary.md#xrdcp) | Like `scp` or `rsync` | Copies files from/to an XRootD server |
| [xrdfs](../10-reference/glossary.md#xrdfs) | Like `ssh` + `ls` combined | Interactive shell to browse remote filesystems |
| `.root` file | Like a database file | A data container used by the [ROOT](../10-reference/glossary.md#root-framework) analysis framework |

**Example:**

```bash
# Copy a physics dataset from CERN's server
xrdcp root://lxcrcms.cern.ch//store/data/Run2023/sample.root /tmp/my-copy.root
```

That file could be 10–50 GB. XRootD is optimized for exactly this kind of transfer.

---

## What is nginx? (Plain English)

nginx is a lightweight web server — the same software that powers GitHub, Netflix, and millions of websites. It's famous for being fast, stable, and using very little memory compared to alternatives.

**What makes nginx special here:** Unlike Apache or other HTTP servers, nginx has a **stream module** that lets you handle *any* network protocol (not just HTTP). This project uses that capability to speak the XRootD protocol directly — no translation layer needed.

---

## What this server actually serves

This is not a web application. It doesn't have a UI, login page, or dashboard.

**What it does:**
- Takes files on your filesystem (e.g., `/data/publications/`)
- Serves them over `root://`, `davs://`, and optionally `s3://` URLs
- Handles authentication (certificate-based or token-based)
- Tracks access in Prometheus metrics
- Logs everything for auditing

**What it doesn't do:**
- Parse `.root` files (it serves raw bytes — the client does parsing)
- Have a web interface
- Replace your database or application server

---

## Three deployment modes

### 1. Standalone Server *(simplest)*

```
xrdcp client ──> nginx-xrootd ──> local files on disk
```

You install nginx-xrootd directly on the machine that holds the data. Clients connect to it like a normal XRootD server.

**Best for:** Small teams, personal research groups, development environments.

### 2. Transparent Proxy *(for existing infrastructure)*

```
xrdcp client ──> nginx-xrootd ──> existing xrootd daemon on backend
```

You place nginx-xrootd in front of an *existing* XRootD server. The clients see nginx; the backend is invisible to them. nginx handles [TLS](../10-reference/glossary.md#tls), authentication, and metrics — the backend just relays data.

**Best for:** Adding security or monitoring without changing your existing setup.

### 3. WebDAV Perimeter Proxy *(for external access)*

```
HTTP client ──> nginx-xrootd (HTTPS + token auth) ──> internal WebDAV server
```

You expose a plain HTTP/WebDAV server to the outside world through an HTTPS gateway that enforces [WLCG](../10-reference/glossary.md#wlcg) JWT bearer token authentication.

**Best for:** Giving external collaborators access without exposing your internal infrastructure.

---

## Quick comparison table

| Question | Answer |
|---|---|
| Do I need physics knowledge? | No — if you know how to install software, you can use this |
| Do I need XRootD experience? | Not really — `xrdcp` works like any file copy tool once configured |
| Do I need nginx experience? | Minimal — the config is 10–20 lines for a basic server |
| What kind of files does it serve? | Any file on your filesystem (`.root`, text, images, archives) |
| How secure is it? | Supports GSI certificates and JWT bearer tokens with scope enforcement |

---

## Where to go next

- **Want a working server in 30 minutes?** → [Getting Started (Full)](getting-started-full.md) — comprehensive guide with concepts + build steps
- **Never built software from source before?** → [Before You Start](before-you-start.md) — explains servers, ports, and building basics
- **Need more context on XRootD concepts?** → [XRootD Basics](../02-concepts/xrootd-basics.md)
- **Already know the basics, want to configure auth?** → See [Authentication Overview](../06-authentication/)

---

### In this section

| Document | Purpose |
|---|---|
| [What Is This Project](what-is-this.md) ← You are here | High-level project overview and FAQ |
| [Before You Start](before-you-start.md) *(new)* | Concepts primer for non-HEP/non-web developers |
| [Getting Started (Full)](getting-started-full.md) | Full installation and setup guide |
| [First Server Verification](first-server.md) | Post-install verification checklist |

