# Building BriX-Cache on Windows

**Status**: 🚧 Draft Implementation (Planning Stage)  
**Last Updated**: 2025-12-19 (Phase 5 Documentation Fixes)  
**nginx Version**: 1.28.3+ (mainline)  
**Platform Support**: Windows 10/11, Windows Server 2019/2022, WSL2

---

## ⚠️ Important: nginx/Windows Limitations

**Before building on Windows, understand these critical limitations:**

Per [nginx.org](https://nginx.org/en/docs/windows.html):

### Beta Status
- ⚠️ **nginx/Windows is considered beta** by upstream
- ⚠️ **Production use not recommended** for high-traffic deployments
- ⚠️ Uses **native Win32 API** (not Cygwin emulation layer)

### Performance Limitations
- ❌ Only `select()` and `poll()` connection processing methods
- ❌ **No epoll/kqueue equivalent** on Windows
- ❌ **Lower performance and scalability** expected vs. Linux/Unix
- ⚠️ Suitable for development, testing, and low-traffic production

### Missing Features
- ❌ XSLT filter module
- ❌ Image filter module
- ❌ GeoIP module
- ❌ Embedded Perl language
- ⚠️ Some third-party modules may not work

### Recommendation
**For production deployments on Windows:**
1. ✅ **Use WSL2** (Windows Subsystem for Linux) - runs full Linux nginx
2. ✅ **Use Docker Desktop** with Linux containers
3. ⚠️ **Native Windows** only for development/testing or low-traffic scenarios

---

## Prerequisites

### Native Windows Build

#### Required Software

1. **Visual Studio 2019 or later** (Community Edition is free)
   - Download: https://visualstudio.microsoft.com/
   - Required components:
     - ✅ "Desktop development with C++"
     - ✅ Windows 10/11 SDK
     - ✅ MSVC v142/v143 build tools

2. **nginx source code** (mainline version recommended)
   ```powershell
   # Download latest mainline version
   curl -O https://nginx.org/download/nginx-1.28.3.zip
   Expand-Archive nginx-1.28.3.zip
   cd nginx-1.28.3
   ```

3. **BriX-Cache module source**
   ```powershell
   git clone https://github.com/your-org/brix-cache.git C:\src\brix-cache
   ```

4. **PCRE2 library** (required by nginx)
   - Download from: https://www.pcre.org/
   - Or use pre-built binaries

5. **OpenSSL** (for HTTPS support)
   - Download from: https://www.openssl.org/
   - Or use pre-built binaries

6. **zlib** (for compression)
   - Download from: http://www.zlib.net/

#### Optional Dependencies

- **Libxslt** - if you need XSLT (not supported on Windows)
- **GD library** - if you need image filter (not supported on Windows)
- **GeoIP** - not supported on Windows

### WSL2 Build (Recommended for Production)

#### Prerequisites

1. **Enable WSL2** (Windows 10 version 2004+ or Windows 11)
   ```powershell
   # Run in PowerShell as Administrator
   dism.exe /online /enable-feature /featurename:Microsoft-Windows-Subsystem-Linux /all /norestart
   dism.exe /online /enable-feature /featurename:VirtualMachinePlatform /all /norestart
   ```

2. **Install WSL2 kernel**
   - Download: https://aka.ms/wsl2kernel
   - Install and restart if prompted

3. **Set WSL2 as default**
   ```powershell
   wsl --set-default-version 2
   ```

4. **Install Linux distribution** (Ubuntu recommended)
   ```powershell
   wsl --install -d Ubuntu-22.04
   ```

5. **Complete Ubuntu setup**
   - Launch Ubuntu from Start menu
   - Create username and password
   - Update packages:
     ```bash
     sudo apt update && sudo apt upgrade -y
     ```

---

## Build Instructions

### Native Windows Build

#### Step 1: Prepare Build Environment

Open **Developer Command Prompt for VS2019/2022**:
```
Start Menu → Visual Studio 2019/2022 → Developer Command Prompt
```

Or open regular cmd.exe and run:
```cmd
"C:\Program Files (x86)\Microsoft Visual Studio\2019\Community\VC\Auxiliary\Build\vcvars64.bat"
```

#### Step 2: Configure nginx with BriX-Cache

```cmd
cd C:\nginx-1.28.3

configure ^
  --with-cc=cl ^
  --with-debug ^
  --prefix=C:\nginx ^
  --add-module=C:\src\brix-cache
```

**Configuration Options:**
- `--with-cc=cl` - Use Microsoft Visual C++ compiler
- `--with-debug` - Enable debug logging (optional, reduces performance)
- `--prefix=C:\nginx` - Installation directory
- `--add-module=C:\src\brix-cache` - Add BriX-Cache module

**Additional Options:**
```cmd
--with-http_ssl_module ^
--with-http_v2_module ^
--with-stream ^
--with-stream_ssl_module
```

#### Step 3: Build nginx

```cmd
nmake
```

This will:
1. Compile nginx core
2. Compile BriX-Cache module
3. Link everything together

**Expected output:**
```
cl -c -O2 -I... objs/addon/platform/windows/posix_wrapper.obj
cl -c -O2 -I... objs/addon/platform/windows/event_wrapper.obj
...
link /OUT:objs/nginx.exe ...
```

#### Step 4: Install nginx

```cmd
mkdir C:\nginx
copy objs\nginx.exe C:\nginx\
copy conf\* C:\nginx\conf\
copy html\* C:\nginx\html\
copy -r C:\src\brix-cache\conf\* C:\nginx\conf\
```

#### Step 5: Test nginx

```cmd
cd C:\nginx
nginx -t
```

**Expected output:**
```
nginx: the configuration file C:\nginx/conf/nginx.conf syntax is ok
nginx: configuration file C:\nginx/conf/nginx.conf test is successful
```

#### Step 6: Run nginx

```cmd
start nginx
```

Check if running:
```cmd
tasklist /fi "imagename eq nginx.exe"
```

Stop nginx:
```cmd
nginx -s stop
```

### WSL2 Build (Recommended)

#### Step 1: Update WSL2

Open Ubuntu terminal:
```bash
sudo apt update && sudo apt upgrade -y
```

#### Step 2: Install Build Dependencies

```bash
sudo apt install -y \
    build-essential \
    libpcre3-dev \
    libssl-dev \
    zlib1g-dev \
    libxml2-dev \
    libxslt1-dev \
    libgd-dev \
    libgeoip-dev \
    git \
    wget
```

#### Step 3: Download nginx Source

```bash
cd /tmp
wget https://nginx.org/download/nginx-1.28.3.tar.gz
tar xzf nginx-1.28.3.tar.gz
cd nginx-1.28.3
```

#### Step 4: Clone BriX-Cache

```bash
git clone https://github.com/your-org/brix-cache.git /tmp/brix-cache
```

#### Step 5: Configure Build

```bash
./configure \
  --prefix=/usr/local/nginx \
  --with-http_ssl_module \
  --with-http_v2_module \
  --with-stream \
  --with-stream_ssl_module \
  --add-module=/tmp/brix-cache
```

**Optimization Options:**
```bash
# For production builds
CFLAGS="-O3 -march=native" \
./configure \
  --prefix=/usr/local/nginx \
  --add-module=/tmp/brix-cache \
  --with-cc-opt="-O3 -march=native" \
  --with-ld-opt="-L/usr/local/lib"
```

#### Step 6: Build and Install

```bash
make -j$(nproc)
sudo make install
```

#### Step 7: Test and Run

```bash
sudo /usr/local/nginx/sbin/nginx -t
sudo /usr/local/nginx/sbin/nginx
```

---

## Configuration

### Basic nginx.conf for Windows

```nginx
# C:\nginx\conf\nginx.conf

worker_processes 2;  # Match CPU cores
error_log logs/error.log;

events {
    worker_connections 1024;
    # Note: Windows uses select(), limited to ~1024 connections
}

http {
    include       mime.types;
    default_type  application/octet-stream;
    
    sendfile        on;
    keepalive_timeout  65;
    
    # BriX-Cache configuration
    brix_cache_path C:/nginx/cache levels=1:2 keys_zone=brix:100m max_size=10g;
    
    server {
        listen       80;
        server_name  localhost;
        
        location / {
            root   html;
            index  index.html;
            
            # Enable BriX-Cache
            brix_cache brix;
            brix_cache_valid 200 302 10m;
            brix_cache_valid 404 1m;
        }
    }
}
```

### Key Differences: Windows vs. Linux

| Feature | Windows | Linux/WSL2 |
|---------|---------|------------|
| Path separator | `\` or `/` | `/` |
| Case sensitivity | Insensitive | Sensitive |
| Max connections | ~1024 (select limit) | 65535+ (epoll) |
| Performance | Lower | Higher |
| Production ready | ⚠️ Development only | ✅ Yes |

---

## Performance Expectations

### Native Windows Performance

**Connection Handling:**
- Limited to ~1024 concurrent connections per worker (select() limit)
- Higher latency under load vs. epoll/kqueue
- Suitable for: Development, testing, low-traffic (<100 req/s)

**Throughput:**
- Expect 30-50% lower throughput vs. Linux on same hardware
- File I/O performance similar
- Network I/O bottleneck due to select()

**Memory Usage:**
- Similar memory footprint to Linux
- Windows overhead: +50-100MB base

### WSL2 Performance

**Connection Handling:**
- Full epoll support (65535+ connections)
- Near-native Linux performance
- Suitable for: Production deployments

**Throughput:**
- 95-98% of native Linux performance
- Minor overhead from WSL2 translation layer
- File I/O: Use Linux filesystem (`/home/`) for best performance

**Recommendation:**
- ✅ Use WSL2 for production on Windows
- ✅ Use native Windows for development/testing only

---

## Troubleshooting

### Common Build Errors

#### Error: `'sys/socket.h' file Not Found`

**Problem:** Windows doesn't have POSIX socket headers

**Solution:** Use Winsock2 headers
```c
// In your code, include:
#include <winsock2.h>
#include <ws2tcpip.h>
```

**For BriX-Cache:** Ensure PAL is used:
```c
#include "platform/platform_api.h"
// Don't include POSIX headers directly
```

#### Error: `undefined symbol: epoll_create`

**Problem:** epoll not available on Windows

**Solution:** Use PAL event abstraction
```c
// Instead of:
int efd = epoll_create1(0);

// Use PAL:
int efd = brix_plat_event_init();
```

#### Error: `link: fatal error LNK1181: cannot open input file 'pcre2.lib'`

**Solution:** Specify PCRE2 location:
```cmd
configure --with-pcre=C:\src\pcre2
```

#### Error: `nginx: [emerg] bind() to 0.0.0.0:80 failed (10013: ...)`

**Problem:** Port 80 already in use

**Solution:**
1. Check what's using port 80:
   ```cmd
   netstat -ano | findstr :80
   ```
2. Stop conflicting service or use different port
3. Run as Administrator

#### Error: `The code execution cannot proceed because VCRUNTIME140.dll was not found`

**Solution:** Install Visual C++ Redistributable:
- Download: https://aka.ms/vs/17/release/vc_redist.x64.exe
- Install and retry

### Runtime Issues

#### nginx Won't Start

**Check error log:**
```cmd
type C:\nginx\logs\error.log
```

**Common causes:**
- Port already in use
- Missing dependencies (DLLs)
- Configuration syntax error
- Insufficient permissions

**Solution:** Run as Administrator, check config syntax with `nginx -t`

#### High Memory Usage

**Problem:** Windows memory management differs from Linux

**Solution:**
1. Reduce `worker_processes`
2. Reduce `worker_connections`
3. Tune `brix_cache_path` size

#### Slow Performance

**Problem:** select() bottleneck

**Solutions:**
1. Reduce concurrent connections
2. Use multiple worker processes
3. **Best:** Switch to WSL2 for production

#### BriX-Cache Not Working

**Check:**
1. Module loaded: `nginx -V 2>&1 | findstr brix`
2. Cache directory exists and writable
3. Configuration syntax correct

**Enable debug logging:**
```nginx
error_log logs/error.log debug;
```

---

## Testing

### Verify BriX-Cache Module

```cmd
cd C:\nginx
nginx -V 2>&1 | findstr brix
```

**Expected output:**
```
--add-module=C:/src/brix-cache
```

### Test Caching

```cmd
# Make a request
curl -I http://localhost/

# Check cache status in response headers
# X-Brix-Cache: HIT indicates cache hit
```

### Performance Test

```cmd
# Install Apache Bench (part of Apache)
ab -n 1000 -c 10 http://localhost/

# Expected: Lower RPS vs. Linux, but functional
```

---

## Known Issues

### Critical Issues

1. **select() Connection Limit**
   - **Impact:** Max ~1024 concurrent connections per worker
   - **Workaround:** Use WSL2 for production
   - **Status:** nginx upstream limitation

2. **No epoll/kqueue**
   - **Impact:** Higher latency, lower scalability
   - **Workaround:** Use WSL2
   - **Status:** nginx upstream limitation

3. **Path Separator Issues**
   - **Impact:** Some configs may fail with `/` vs `\`
   - **Workaround:** Use `/` (nginx accepts both on Windows)
   - **Status:** Documented, nginx handles conversion

### Moderate Issues

4. **File Locking Differences**
   - **Impact:** Advisory locks behave differently
   - **Workaround:** Test locking behavior
   - **Status:** Windows limitation

5. **Signal Handling**
   - **Impact:** Some signals not supported
   - **Workaround:** Use `nginx -s stop/reload`
   - **Status:** Windows limitation

6. **Extended Attributes**
   - **Impact:** PAL xattr stubbed on Windows
   - **Workaround:** Features using xattr won't work
   - **Status:** PAL implementation TODO

### Minor Issues

7. **Log Rotation**
   - **Impact:** `nginx -s reopen` may not work as expected
   - **Workaround:** Restart nginx
   - **Status:** Windows limitation

8. **Case Sensitivity**
   - **Impact:** URI matching case-insensitive
   - **Workaround:** Be explicit in configs
   - **Status:** Windows filesystem behavior

---

## Alternatives to Native Windows

### Option 1: WSL2 (Recommended)

**Pros:**
- ✅ Full Linux compatibility
- ✅ epoll support (high performance)
- ✅ All nginx features work
- ✅ Production-ready

**Cons:**
- ⚠️ Minor overhead (~2-5%)
- ⚠️ File I/O slower when accessing Windows filesystem

**Setup:** See WSL2 Build section above

### Option 2: Docker Desktop

**Pros:**
- ✅ Full Linux environment
- ✅ Easy deployment
- ✅ Production-ready

**Cons:**
- ⚠️ Resource overhead (VM)
- ⚠️ Learning curve

**Example:**
```yaml
# docker-compose.yml
version: '3'
services:
  nginx:
    image: nginx:1.28
    ports:
      - "80:80"
    volumes:
      - ./nginx.conf:/etc/nginx/nginx.conf
      - ./cache:/var/cache/nginx
```

### Option 3: Cygwin

**⚠️ Not Recommended**

**Pros:**
- POSIX compatibility layer

**Cons:**
- ❌ Performance overhead
- ❌ Complexity
- ❌ Not officially supported by nginx

---

## Future Enhancements

### Planned PAL Improvements

1. **IOCP Event Loop** (Phase 2)
   - Replace select() with IOCP for better performance
   - Estimated: 2-3x performance improvement
   - Timeline: Weeks 13-20

2. **Full xattr Support**
   - Map NTFS Alternate Data Streams to POSIX xattr
   - Enable all BriX-Cache features on Windows

3. **Job Objects Integration**
   - Security confinement on Windows
   - Equivalent to seccomp on Linux

### nginx Upstream Wishlist

- IOCP support in nginx core (not just select/poll)
- Better Windows integration
- Production-ready Windows build

---

## References

- [nginx/Windows Documentation](https://nginx.org/en/docs/windows.html)
- [nginx Windows Performance Tuning](https://www.nginx.com/resources/admin-guide/nginx-windows-performance/)
- [WSL2 Documentation](https://docs.microsoft.com/en-us/windows/wsl/)
- [BriX-Cache PAL Architecture](../../src/platform/ARCHITECTURE.md)
- [Windows PAL Implementation](../../src/platform/windows/)

---

## Support

**For issues:**
1. Check this documentation
2. Review error logs: `C:\nginx\logs\error.log`
3. Test on WSL2 to isolate Windows-specific issues
4. Report bugs: https://github.com/your-org/brix-cache/issues

**Community:**
- nginx mailing list: nginx@nginx.org
- BriX-Cache issues: GitHub

---

**Last Updated:** 2025-12-19 (Phase 5 Documentation Fixes)  
**Status:** 🚧 Draft - Implementation in Progress
