# Adding Custom Tools to Quiver

There are two stages to adding a custom tool:

1. **Install the binary** inside the Docker container
2. **Register the tool** in the Quiver UI

How you handle step 1 depends on where the tool comes from. There are three installation patterns covered below.

---

## Stage 1: Installing the Binary

### Pattern A — apt package (simplest)

Use this when the tool exists in the standard Debian bookworm package repositories.

Edit `backend/user-tools.txt` and add one package name per line:

```
# Lines starting with # are ignored
fping
masscan
arp-scan
```

Rebuild the backend container:

```bash
docker-compose up --build backend
```

**Examples of tools available via apt:**

| Package | What it does |
|---|---|
| `fping` | Fast ICMP host discovery |
| `masscan` | Extremely fast port scanner |
| `arp-scan` | ARP-based LAN host discovery |
| `hping3` | Manual TCP/IP packet crafting |
| `nbtscan` | NetBIOS name scanner |
| `onesixtyone` | SNMP community string scanner |
| `dirb` | Web content/directory scanner |
| `wfuzz` | Web fuzzer (wordlist-based) |
| `dnsenum` | DNS enumeration |

`dirb` has already been added as a custom tool to show more of how this would work.

**Cautions:**
- The package must exist in Debian bookworm's default repos. If `apt-get` can't find it, the entire build fails.
- To verify a package exists before adding it, check [https://packages.debian.org](https://packages.debian.org) and search for the package name under the `bookworm` distribution.
- Do not add GUI applications, database daemons, or multi-service tools (e.g. BloodHound, Metasploit). These are not CLI tools and will not work in this environment.
- One wrong package name fails the whole build — double-check spelling.

---

### Pattern B — Pre-built binary from GitHub releases

Use this when the tool publishes pre-compiled Linux binaries (most modern Go/Rust security tools do).

Add a `RUN` block to `backend/Dockerfile` after the existing tool install blocks:

```dockerfile
# Example: install a hypothetical tool "mytool"
RUN curl -L https://github.com/author/mytool/releases/download/v1.0.0/mytool_linux_amd64.tar.gz \
    | tar xz -C /usr/local/bin mytool && chmod +x /usr/local/bin/mytool
```

For a `.zip` release:

```dockerfile
RUN curl -L https://github.com/author/mytool/releases/download/v1.0.0/mytool_linux_amd64.zip \
    -o /tmp/mytool.zip && cd /tmp && unzip mytool.zip && mv mytool /usr/local/bin/ && chmod +x /usr/local/bin/mytool
```

**Cautions:**
- Every command in a `RUN` block must be joined with `&&` and `\` for line continuation. A missing `&&` means only the first command actually runs — no error is shown, the rest are silently skipped.
- Always use `linux_amd64` builds. The container runs on x86-64 Linux regardless of your host machine.
- Pin to a specific release version (e.g. `v1.0.0`), not `latest`. Floating versions break reproducible builds.
- After editing the Dockerfile, you must rebuild: `docker-compose up --build backend`

---

### Pattern C — Go tool compiled from source

Use this when the tool is a Go project on GitHub without pre-built releases.

**Key lessons learned the hard way:**

1. The `golang` apt package in Debian bookworm is Go 1.19, which is too old for most modern Go tools. Install Go from the official release instead.
2. Real Go projects already have a `go.mod` file. Never run `go mod init` on a cloned repo — it fails immediately.
3. Go tools sometimes trigger CGO (C interop) even when they don't need it. Set `CGO_ENABLED=0` to force a fully static build, which avoids needing C headers.

Template for installing a Go tool:

```dockerfile
# Install Go 1.24 and build <toolname> from source
RUN curl -L https://go.dev/dl/go1.24.5.linux-amd64.tar.gz | tar xz -C /usr/local && \
    git clone --depth=1 https://github.com/author/toolname.git /opt/toolname && \
    cd /opt/toolname && \
    CGO_ENABLED=0 /usr/local/go/bin/go build -o /usr/local/bin/toolname . && \
    rm -rf /usr/local/go
```

The `rm -rf /usr/local/go` at the end removes the Go toolchain after the build to keep the image lean. The compiled binary stays at `/usr/local/bin/toolname`.

`SpiSuite` has been added as a custom tool using this method to show how to add it and show that it works.

**Cautions:**
- `go build` downloads dependencies from the internet during the build. If the build machine has no internet access, this will fail.
- Check the tool's `go.mod` file on GitHub to see its required Go version before choosing which Go release to install.
- The `--depth=1` flag on `git clone` saves time and space by not cloning the full git history.

---

### Pattern D — Python tool via pip

Use this when the tool is a Python package. The container already has Python 3.12.

```dockerfile
RUN pip install --no-cache-dir --break-system-packages toolname==1.0.0
```

Or for a GitHub-only tool:

```dockerfile
RUN pip install --no-cache-dir --break-system-packages git+https://github.com/author/toolname.git
```

**Example — bloodhound-python** (AD data collection, the CLI-equivalent of BloodHound's ingestor):

```dockerfile
RUN pip install --no-cache-dir --break-system-packages bloodhound
```

This installs the `bloodhound` Python package, which provides the `bloodhound-python` command for collecting AD data from Linux. Note this is the ingestor only — you still need a BloodHound CE instance separately to visualize the data.

**Cautions:**
- Always pin to a version number (`toolname==1.0.0`) when possible. Unpinned installs can break future rebuilds if the package releases a breaking change.
- `--break-system-packages` is required because the container uses a system Python. This is safe here since we own the container.

---

## Stage 2: Registering the Tool in the UI

Once the binary is installed and the container is rebuilt, go to **Tools → Add Tool** in the browser.

Fill in:

| Field | Description | Example |
|---|---|---|
| **Name** | Display name shown in the UI | `Masscan — Fast Port Scan` |
| **Binary** | The command as it appears in PATH | `masscan` |
| **Category** | Recon / Web / Enumeration / Vuln Scan / Utilities | `recon` |
| **Default Flags** | Flags always appended to the command | `--rate=1000` |
| **Workflow Tags** | Comma-separated engagement types | `external, internal` |
| **Parameters** | Named inputs filled in at run time | see below |

**Binary check indicator:** When you type the binary name, a live indicator checks whether that binary exists in the container. A green checkmark means it's installed and ready. A red X means it's not found — don't save until this is resolved.

**Adding parameters:**

Each parameter becomes an input field when you run the tool in a session.

| Field | Description | Example |
|---|---|---|
| Name | Label shown in the UI | `Target CIDR` |
| Flag | CLI flag prepended to the value | `--range` |
| Placeholder | Hint text in the input field | `192.168.1.0/24` |

At run time, Quiver builds the command as:
```
<binary> <default_flags> <flag1> <value1> <flag2> <value2> [extra flags]
```

---

## Quick Reference: Which Pattern to Use?

```
Is it in Debian bookworm's apt repos?
  YES → user-tools.txt (Pattern A)
  NO  ↓

Does the GitHub releases page have a linux_amd64 binary?
  YES → Dockerfile curl pattern (Pattern B)
  NO  ↓

Is it a Go project?
  YES → Dockerfile Go build pattern (Pattern C)
  NO  ↓

Is it a Python package?
  YES → Dockerfile pip pattern (Pattern D)
  NO  → Requires custom research (Ruby gem, compiled C, etc.)
```

---

## Troubleshooting

**`E: Unable to locate package <name>`**
The package doesn't exist in Debian bookworm. Check [packages.debian.org](https://packages.debian.org) or switch to a different installation pattern.

**`go: /opt/toolname/go.mod already exists`**
You ran `go mod init` on a repo that already has one. Remove the `go mod init` line from your Dockerfile block.

**`fatal error: stdlib.h: No such file or directory`**
CGO is trying to compile C code but the C headers aren't available. Add `CGO_ENABLED=0` before the `go build` command.

**Binary check shows red X after rebuild**
The binary name in the UI doesn't match what was installed. Run `docker exec quiver_backend which <binary>` to find the actual command name, then update the Binary field in the tool registry.

**Build fails with `exit code: 1` but no clear error**
Scroll up in the build output — Docker logs the actual error before the final failure line. The last line is always generic; the real cause is a few lines above it.
