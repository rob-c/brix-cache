# The Absolute Beginner's Guide to XRootD Testing with Kubernetes

Welcome! If you have never used Kubernetes (K8s) or Minikube before, this guide is for you. We will use these tools to create a "virtual laboratory" on your machine—a private network of servers that you can use for testing and debugging.

## 1. The Core Concept: Servers as "VMs"

In this laboratory, we don't use real virtual machines (VMs). Instead, we use **Pods** (containers). 

- Think of each **Pod** as a lightweight VM that comes up instantly.
- Each Pod has its own **Private IP address** and its own **Operating System** (AlmaLinux 9).
- These "VMs" are connected in a private network where they can talk to each other using both IPv4 and IPv6.

## 2. The 5-Server Laboratory

When you follow this guide, you will bring up a network of 5 servers:

| Name | Role | IP Address | Description |
|---|---|---|---|
| `nginx-data` | **Data Node** | `172.16.0.10` | Running the `nginx-xrootd` module. Stores real files. |
| `nginx-redir`| **Redirector** | `172.16.0.11` | A "Gateway". It doesn't have files, but it points you to `nginx-data`. |
| `xrootd-data`| **XRootD Server**| `172.16.0.20` | Running the official reference XRootD server. |
| `xrootd-redir`| **XRootD Redir** | `172.16.0.21` | Official XRootD in manager mode. |
| `client` | **Interactive** | `172.16.0.100`| Your "Control Room". You will "SSH" into this to run tests. |

## 3. Launching the Laboratory

From the root of the repository, run these three commands. They do all the heavy lifting for you:

```bash
# 1. Start the cluster foundation (Minikube)
k8s-tests/xrd-k8s cluster start

# 2. Build the software (RPMs and Images)
k8s-tests/xrd-k8s build all

# 3. Launch the 5-server lab
kubectl apply -f k8s-tests/k8s-manifests/lab-5-vms.yaml
```

Wait about 60 seconds for everything to "power on". You can check the status with:
```bash
kubectl get pods -n xrootd-lab
```

## 4. Entering the "Control Room" (Interactive Testing)

To perform actions against the servers, you need to "enter" the `client` Pod. This is the equivalent of SSH-ing into a test machine:

```bash
# "SSH" into the client pod
kubectl exec -it deployment/interactive-client -n xrootd-lab -- bash
```

Now you are inside the client. You can try reading files from the other servers using their IP addresses:

```bash
# Try to list files on the nginx data node
xrdfs root://172.16.0.10 ls /

# Try to read through the nginx redirector (which points to the data node)
xrdfs root://172.16.0.11 stat /hello.txt

# Try the official XRootD server
xrdfs root://172.16.0.20 ls /
```

## 5. Monitoring and Debugging

If you want to see what a server is doing in real-time (e.g., to see error messages or access logs), you can "tail" its output from your **host machine** (your terminal, not the client pod):

```bash
# Watch logs from the nginx data node
kubectl logs -f deployment/nginx-data -n xrootd-lab

# Watch logs from the official XRootD server
kubectl logs -f deployment/xrootd-data -n xrootd-lab
```

## 6. Running Automated Tests

If you want to run the full suite of automated tests instead of a manual lab:

1. Stop your manual lab: `kubectl delete namespace xrootd-lab`
2. Run the automated suite: `./xrd-k8s deploy all && ./xrd-k8s test`

## 7. Cleaning Up

When you are finished, you can delete everything to free up your computer's resources:

```bash
k8s-tests/xrd-k8s teardown
```

## Summary of Key Commands

- `kubectl get pods -n xrootd-lab`: See what's running.
- `kubectl exec -it ...`: "SSH" into a container.
- `kubectl logs -f ...`: Watch a server's "screen" (logs).
- `kubectl describe pod ...`: Debug why a server didn't start.
