# Before You Start

If the phrase "configure with the module" means nothing to you yet, this is the right page. Five short sections cover everything you need to follow the other guides without hitting a wall.

---

## What's a Server?

A server is software that listens for incoming connections and responds to them. No special hardware required — it's just a program running on whatever machine you have.

**Analogy:** Think of a restaurant kitchen. The kitchen (server) sits idle until someone orders food (makes a request), then prepares and delivers it. It can handle one customer at a time, or many simultaneously if it has enough staff.

nginx is one of the most widely-deployed servers on the internet — GitHub, Netflix, and Cloudflare all run it. Unlike Apache, nginx handles thousands of simultaneous connections with minimal memory, which is exactly what physics data transfers demand.

---

## What's a Port?

Every computer has 65,536 numbered "doors" called ports. Different services listen on different ones:

| Port | Service |
|---|---|
| 80 | HTTP (web pages) |
| 443 | HTTPS (secure web pages) |
| 22 | SSH (remote login) |
| 1094 | XRootD (physics file transfers — our main port here) |

**Analogy:** A building has one address but multiple doors. Port 80 is the front door for web traffic; port 1094 is a side door for physics data. The server software decides what to do with each incoming request based on which "door" it came through.

---

## What's a Protocol?

A protocol is the rulebook for a conversation between two programs — what bytes to send, in what order, and what they mean:

| Protocol | Purpose | Like this... |
|---|---|---|
| HTTP/HTTPS | Web pages, API calls | Browsing a website |
| SSH | Secure remote access | Logging into a terminal |
| FTP/SFTP | File transfers | Drag-and-drop file sharing |
| XRootD (`root://`) | Physics data transfers | Like FTP but optimized for 10-50 GB files and parallel downloads |

**URL schemes:** The part before `://` tells the client which protocol to use:
- `http://` → plain text (not encrypted)
- `https://` → encrypted (TLS/SSL)
- `root://` → XRootD protocol (physics world equivalent of http:// for large files)

---

## What Does "Building from Source" Mean?

Most people install software with a package manager (`apt`, `dnf`, `brew`). But BriX-Cache adds custom functionality to nginx, so we need to:

1. Download the **source code** (the human-readable C programs that make up nginx)
2. **Compile** it — translate those programs into machine-executable binary form
3. Add our module during compilation — this is like inserting a new feature while building

**Analogy:** Buying a pre-built car vs buying parts and assembling your own. Pre-built (apt install) works for standard use. Building from source lets us add custom modifications (our XRootD module).

---

## What Are These Terms You'll See?

| Term | Simple Explanation |
|---|---|
| **CLI** | Command Line Interface — typing commands instead of clicking buttons |
| **Terminal/Shell** | The program where you type CLI commands (bash, zsh) |
| **sudo** | "Run as superuser" — gives temporary admin privileges (like "Run As Administrator" on Windows) |
| **make** | A build tool that compiles C/C++ programs from source code |
| **./configure** | A script that checks your system and prepares the build for your specific setup |
| **TCP/IP** | The fundamental protocol suite of the internet — how computers talk to each other across networks |
| **TLS/SSL** | Encryption layer that secures connections (what makes `https://` secure) |
| **Daemon** | A background service process (like a server program running silently) |

---

### Want to learn more about these basics?

If you'd like external references for any of the concepts above, here are quick links:

| Concept | External Reference | Time to read |
|---|---|---|
| What is TCP/IP? | [Wikipedia](https://en.wikipedia.org/wiki/Internet_Protocol_Suite) | 3 min |
| How does HTTPS/TLS work? | [Let's Encrypt explanation](https://letsencrypt.org/how-it-works/) | 5 min |
| What is a proxy server? | [MDN Web Docs](https://developer.mozilla.org/en-US/docs/Glossary/Proxy_server) | 3 min |

> **Don't feel like reading external links?** That's fine — all the information you need to use this project is included in these docs.

---

## What You Need Before Starting

### ❌ What you DON'T need (don't worry about these)

- Physics experience ✓
- XRootD knowledge ✓  
- nginx expertise ✓
- C programming skills ✓
- Grid security / PKI background ✓
- Understanding of "what is a port" or "how HTTPS works" ✓

> We explain all of the above *inline* as you go. You don't need to read anything beforehand.

### ✅ What you DO need

- Access to a Linux computer (physical or virtual)
- Ability to run commands in a terminal
- Internet access for downloads
- ~500 MB of free disk space

---

## Quick Verification Checklist

After following the installation guide, verify everything works:

```bash
# 1. Is nginx running?
ps aux | grep nginx

# 2. Can you reach it? (replace port with yours)
curl -s http://localhost:80/ || echo "Not listening on HTTP"
xrdcp --help 2>&1 | head -5 || echo "xrdcp not installed — install with: sudo apt install xrootd-client"

# 3. Is XRootD responding? (after starting nginx-xrootd)
xrdfs localhost ping
```

If any of these fail, check the [First Server Verification](first-server.md) guide for troubleshooting steps.

---

## Where to Go Next

| You want to... | Read this next |
|---|---|
| Build and run your first server | [Getting Started (Full)](getting-started-full.md) |
| Understand what XRootD actually is | [XRootD Basics](../02-concepts/xrootd-basics.md) |
| Know which deployment mode fits you | [Deployment Modes](../02-concepts/deployment-modes.md) |
