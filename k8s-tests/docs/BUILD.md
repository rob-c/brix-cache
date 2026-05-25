# Building Docker Images for nginx-xrootd K8s Tests

This document describes how the container images for the K8s testing framework are built, where the Dockerfiles are located, and the logic behind the build process.

## 1. Build Strategy: RPM-First
To ensure the containerized environment matches a production RPM-based installation, we use a two-stage build process:
1. **RPM Build**: A source tarball is created from the local repository and built into an RPM inside an AlmaLinux 9 container.
2. **Image Build**: The resulting RPM is then injected into the final server images using `--build-arg RPM_FILE`.

## 2. Dockerfile Locations
All Dockerfiles are located in the `k8s-tests/Dockerfiles/` directory:

| Component | Location | Base Image | Description |
|---|---|---|---|
| **RPM Builder** | `Dockerfiles/rpm-builder/` | AlmaLinux 9 | Builds the `.rpm` from local source. |
| **Server** | `Dockerfiles/server/` | AlmaLinux 9 (minimal) | The `nginx-xrootd` server node. |
| **Client** | `Dockerfiles/client/` | AlmaLinux 9 | Interactive client with `xrdcp` and `xrdfs`. |
| **Test Runner** | `Dockerfiles/test-runner/` | AlmaLinux 9 | Python environment for `pytest` and aggregation. |
| **Reference** | `Dockerfiles/xrootd-reference/` | AlmaLinux 9 | Official XRootD server for integration checks. |

## 3. How to Build

The easiest way to build all images is using the unified `xrd-k8s` tool:

```bash
# Build everything (RPM + all images)
./xrd-k8s build all

# Build only the RPM
./xrd-k8s build rpm

# Build images (requires RPM to be present in k8s-tests/rpms/)
./xrd-k8s build images
```

## 4. Manual Build Commands
If you need to build a specific image manually, follow these steps from the **project root**:

### Step A: Build the RPM
```bash
docker build -t nginx-xrootd-rpm-builder -f k8s-tests/Dockerfiles/rpm-builder/Dockerfile .
id=$(docker create nginx-xrootd-rpm-builder)
docker cp $id:/artifacts/. k8s-tests/rpms/
docker rm $id
```

### Step B: Build the Server Image
```bash
RPM_NAME=$(ls k8s-tests/rpms/nginx-mod-xrootd-*.rpm | head -n 1 | xargs basename)
docker build -t nginx-xrootd-server:latest \
    --build-arg RPM_FILE=$RPM_NAME \
    -f k8s-tests/Dockerfiles/server/Dockerfile .
```

## 5. Image Naming Convention
- `nginx-xrootd-server`: The primary module host.
- `nginx-xrootd-client`: Client-side tools.
- `nginx-xrootd-test-runner`: Automated test executor.
- `xrootd-reference`: Official XRootD reference implementation.
