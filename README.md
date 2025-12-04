Here is the professional, GitHub-ready `README.md` file. It incorporates the file structure from your screenshot and follows the exact workflow we established.

-----

# IICPC Track 2: Network & Application Blocking System

## Project Overview

This repository contains the solution for Track 2 of the IICPC Technical Challenge. It is a security appliance designed to enforce strict application allowlisting and DNS filtering. The system utilizes **Go** for high-performance user-space logic and **eBPF** for kernel-level enforcement.

**Core Capabilities:**

  * **Application Blocker:** Prevents unauthorized process execution using Linux Security Modules (LSM).
  * **DNS Proxy:** Intercepts DNS traffic to filter domains based on a configurable policy.
  * **Audit Logging:** Provides real-time, zero-allocation structured logging of all security events.
  * **Network Filter:** (Optional) Enforces traffic control (TC) to drop direct IP connections bypassing the proxy.

## Project Structure

The codebase is organized into a clean separation of concerns between the Core logic and Linux Adapters.

```text
IICPC-NETWORK/
├── adapters/
│   └── linux/
│       ├── adapter.go          # Go bridge to manage eBPF programs
│       ├── blocker.bpf.c       # C source for App Blocker (LSM Hook)
│       ├── network.bpf.c       # C source for Network Filter (TC Hook)
│       ├── vmlinux.h           # Kernel headers
│       └── [Generated BPF artifacts: _bpfel.go, .o files]
├── cmd/
│   └── core-service/
│       └── main.go             # Application entry point
├── core/
│   ├── audit.go                # Structured logging logic (sync.Pool)
│   ├── dns_proxy.go            # UDP DNS Server & Filter logic
│   ├── orchestrator.go         # Coordinator between Policy and Kernel
│   └── policy.go               # Thread-safe Policy Engine (atomic.Value)
├── audit.json.log              # Runtime audit logs
├── go.mod                      # Go module definitions
├── go.sum                      # Go module checksums
├── malware.sh                  # Test script for blocker verification
└── policy.json                 # Configuration rules
```

## Prerequisites

**System Requirements:**

  * **OS:** Linux (Ubuntu 22.04 / 24.04 recommended)
  * **Kernel:** Version 5.15+ (Requires BPF LSM support)
  * **Go:** Version 1.22+
  * **Build Tools:** Clang, LLVM, `bpftool`

**1. Install Dependencies**

```bash
sudo apt update
sudo apt install clang llvm libbpf-dev linux-tools-common linux-tools-generic linux-tools-$(uname -r)
```

**2. Enable BPF LSM (Crucial Step)**
The application requires the BPF Linux Security Module to be active. Check your status:

```bash
cat /sys/kernel/security/lsm
```

If `bpf` is not listed in the output:

1.  Edit GRUB config: `sudo nano /etc/default/grub`
2.  Modify `GRUB_CMDLINE_LINUX_DEFAULT` to append: `lsm=lockdown,capability,landlock,yama,apparmor,ima,evm,bpf`
3.  Apply changes: `sudo update-grub`
4.  Reboot the system.

## Installation & Build

**1. Initialize Modules**
Ensure all Go dependencies (including `cilium/ebpf`) are installed to resolve editor errors.

```bash
go mod tidy
go get github.com/cilium/ebpf/cmd/bpf2go
```

**2. Compile eBPF Bytecode**
The C kernel programs must be compiled into Go-compatible bytecode.

```bash
cd adapters/linux
go generate
cd ../..
```

*Note: Run `go generate` whenever you modify `.c` files.*

## Configuration

The system behavior is controlled by `policy.json` in the project root.

```json
{
  "allowed_domains": [
    "codeforces.com"
  ],
  "allowed_apps": [
    "/usr/bin/bash",
    "/usr/bin/curl",
    "./malware.sh"
  ],
  "allowed_ips": []
}
```

## Running the Service

The application must run with root privileges to load eBPF programs and bind to privileged network ports.

```bash
sudo go run cmd/core-service/main.go
```

## Testing & Verification

### 1\. Verify Application Blocking

To test the kernel-level execution prevention:

1.  Create a test script:
    ```bash
    echo 'echo "I am a bad program!"' > malware.sh
    chmod +x malware.sh
    ```
2.  Remove `"./malware.sh"` from `policy.json`.
3.  Run the script:
    ```bash
    ./malware.sh
    ```
4.  **Expected Result:** `bash: ./malware.sh: Operation not permitted`

### 2\. Verify DNS Filtering

To test the DNS Proxy (listening on port 8053 for development):

**Allowed Domain:**

```bash
dig @127.0.0.1 -p 8053 codeforces.com
```

  * **Result:** Returns a valid IP address.

**Blocked Domain:**

```bash
dig @127.0.0.1 -p 8053 google.com
```

  * **Result:** Returns `status: NXDOMAIN` (Non-Existent Domain).

### 3\. Verify Audit Logs

To view security events in real-time:

```bash
tail -f audit.json.log
```

**Output Format:**

```json
{"ts":1733385200,"client_ip":"127.0.0.1","domain":"codeforces.com","allowed":true}
{"ts":1733385205,"client_ip":"127.0.0.1","domain":"google.com","allowed":false}
```

## Troubleshooting

**Red Lines in `adapter.go`:**
If your editor shows errors regarding `link.AttachTC` or `ebpf` packages:

1.  Ensure you have run `go mod tidy`.
2.  Force update the library: `go get github.com/cilium/ebpf@latest`.

**Silent Failures:**
If the application starts but does not block anything:

1.  Verify `go generate` ran successfully without errors.
2.  Verify `cat /sys/kernel/security/lsm` contains `bpf`.
3.  Check kernel debug logs: `sudo cat /sys/kernel/debug/tracing/trace_pipe`.
