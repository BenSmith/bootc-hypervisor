# WARNING WARNING WARNING
### This has not been thoroughly tested, and the implementation is AI-generated, so ... 
### DO NOT count on this to be your sole mechanism to access important things.

It would be wise to have a recovery plan regardless of system maturity.

---


# Secrets Management for Workloads

This document describes the recommended approach for managing secrets (API keys, passwords, certificates, etc.) in the hypervisor workload system using systemd credentials.

## Table of Contents

- [Overview](#overview)
- [Security Model](#security-model)
- [How It Works](#how-it-works)
- [Setup and Usage](#setup-and-usage)
- [Bootc Integration](#bootc-integration)
- [Attack Scenarios](#attack-scenarios)
- [Comparison to Alternatives](#comparison-to-alternatives)
- [Advanced Configuration](#advanced-configuration)

## Overview

The workload system uses **systemd credentials** (`systemd-creds`) for secure secrets management. This provides:

- **Encryption at rest** using AES256-GCM with TPM2 or host keys
- **Runtime decryption** into RAM-only tmpfs (never touches disk unencrypted)
- **Per-workload isolation** preventing credential leakage between workloads
- **Automatic cleanup** when services stop
- **Bootc compatibility** - encrypted credentials can be safely committed to git

### Why systemd Credentials?

- **Native integration**: Built into systemd, no external dependencies
- **Offline-first**: Works without network access (perfect for homelab/edge)
- **TPM2 support**: Hardware-backed encryption when available
- **Simple**: No complex infrastructure (Vault, SOPS, etc.) required
- **Immutable-friendly**: Encrypted files are safe to bake into bootc images
- **Transparency**: It uses systemd-creds, easy to audit for exfiltration risks
- **No corporate risk**: No need for concern about shifting terms of service/licensing/paywalls

## Security Model

### The Complete Flow

```
┌─────────────────────────────────────────────────────────────────┐
│ 1. ENCRYPTION (One-time setup)                                  │
│                                                                  │
│  Plain secret → systemd-creds encrypt → Encrypted .cred file    │
│  "my-api-key"                            (AES256-GCM)            │
│                                                                  │
│  Stored in: /etc/credstore.encrypted/jellyfin-api-key.cred      │
│  Permissions: root:root 0600                                    │
│  Format: Binary blob (not readable as text)                     │
└─────────────────────────────────────────────────────────────────┘
                           ↓
┌─────────────────────────────────────────────────────────────────┐
│ 2. BOOT TIME (Automatic decryption)                             │
│                                                                  │
│  systemd reads service file:                                    │
│    LoadCredential=api-key:/etc/credstore.encrypted/...cred      │
│                                                                  │
│  systemd decrypts using:                                        │
│    - TPM2 chip (if available) OR                                │
│    - Host key (/var/lib/systemd/credential.secret)              │
│                                                                  │
│  Writes decrypted secret to:                                    │
│    /run/credentials/workload-jellyfin-1.service/api-key         │
│                                                                  │
│  Permissions: _wl-jellyfin-1:root 0400 (read-only)              │
│  Location: tmpfs (RAM only, never hits disk)                    │
└─────────────────────────────────────────────────────────────────┘
                           ↓
┌─────────────────────────────────────────────────────────────────┐
│ 3. RUNTIME (Service access)                                     │
│                                                                  │
│  Only the workload service can read its credentials:            │
│    - Runs as user: _wl-jellyfin-1                               │
│    - Sees: /run/credentials/workload-jellyfin-1.service/        │
│    - Cannot see other workload's credentials                    │
│                                                                  │
│  Generator reads credential and:                                │
│    - Injects into environment: JELLYFIN_API_KEY=<value>         │
│    - OR mounts into container as file                           │
└─────────────────────────────────────────────────────────────────┘
                           ↓
┌─────────────────────────────────────────────────────────────────┐
│ 4. SHUTDOWN (Automatic cleanup)                                 │
│                                                                  │
│  When service stops:                                            │
│    - /run/credentials/workload-jellyfin-1.service/ deleted      │
│    - Memory cleared (tmpfs wiped)                               │
│    - Encrypted .cred file remains safely on disk                │
└─────────────────────────────────────────────────────────────────┘
```

### Encryption Keys

systemd-creds supports three encryption key types:

#### Option A: TPM2 (Most Secure)

```bash
sudo systemd-creds encrypt --with-key=tpm2 --name=my-secret - /etc/credstore.encrypted/my-secret.cred
```

**Security properties:**
- Encrypts using your **TPM2 chip** (hardware security module)
- Secret can ONLY be decrypted on **this specific machine**
- Even if attacker steals the .cred file, they cannot decrypt without your TPM
- Tamper-resistant (TPM2 PCR policy can require specific boot state)
- Survives OS reinstall (tied to hardware, not software)

**Requirements:**
- TPM2 chip present and enabled in BIOS
- `tpm2-tss` package installed (included in the hypervisor image)

#### Option B: Host Key (Still Secure)

```bash
sudo systemd-creds encrypt --with-key=host --name=my-secret - /etc/credstore.encrypted/my-secret.cred
```

**Security properties:**
- Uses `/var/lib/systemd/credential.secret` (auto-generated 128-bit key)
- Created automatically at first boot
- Permissions: root:root 0600
- Machine-specific (not portable to other systems)
- Survives reboots but NOT OS reinstalls

**Use when:**
- TPM2 not available
- Testing/development
- Secrets need to survive reboots but not migrations

#### Option C: Host+TPM2 (Hybrid - Maximum Security)

```bash
sudo systemd-creds encrypt --with-key=host+tpm2 --name=my-secret - /etc/credstore.encrypted/my-secret.cred
```

**Security properties:**
- Requires BOTH the host key AND TPM2 to decrypt
- Defense in depth: two layers of protection
- Most secure option

**Use when:**
- Maximum security required
- Production deployments
- Compliance requirements

### File Permissions and Isolation

| Location | Format | Who Can Read | Persistent? |
|----------|--------|--------------|-------------|
| `/etc/credstore.encrypted/*.cred` | Encrypted binary | root only (0600) | YES (survives reboot) |
| `/run/credentials/{service}/` | Plain text | Service user only | NO (tmpfs, RAM only) |
| Inside container | Plain text (env/file) | Container processes | NO (dies with container) |

**Key security property:** The plaintext secret **never touches disk** - only exists in RAM (`/run` is tmpfs).

### Per-Workload Isolation

Each service gets its own credential directory with strict permissions:

```bash
# Jellyfin workload (user: _wl-jellyfin-1, UID: 10001)
/run/credentials/workload-jellyfin-1.service/
  ├── api-key          (owner: 10001:root, mode: 0400)
  └── db-password      (owner: 10001:root, mode: 0400)

# Plex workload (user: _wl-plex-2, UID: 10002)
/run/credentials/workload-plex-2.service/
  └── claim-token      (owner: 10002:root, mode: 0400)
```

**Isolation guarantees:**
- User `_wl-jellyfin-1` **cannot** read `_wl-plex-2`'s credentials
- Even if jellyfin container is compromised, it cannot access plex secrets
- Standard Linux DAC (discretionary access control) enforces this
- No shared credential namespace

## How It Works

### Workload Configuration (TOML)

Define secrets in your workload configuration:

```toml
[workload]
name = "jellyfin"
id = "1"

[container]
image = "jellyfin/jellyfin:latest"

# Environment variables (can reference secrets)
[container.environment]
JELLYFIN_PublishedServerUrl = "https://jellyfin.example.com"  # Plain value
JELLYFIN_API_KEY = "${SECRET:jellyfin-api-key}"               # Secret reference
JELLYFIN_DB_PASSWORD = "${SECRET:db-password}"                # Secret reference

# Secrets configuration
[secrets]
# Load systemd credentials (encrypted at rest)
credentials = [
    "jellyfin-api-key",
    "db-password"
]

# Optional: Mount secrets as files (for config files with embedded secrets)
files = [
    { credential = "tls-cert", path = "/config/cert.pem" },
    { credential = "tls-key", path = "/config/key.pem" }
]
```

### Generator Integration

The systemd generator (`workload-generator`) processes the configuration:

1. **Reads** `[secrets]` section from TOML
2. **Generates** systemd service file with `LoadCredential=` directives:
   ```ini
   [Service]
   LoadCredential=jellyfin-api-key:/etc/credstore.encrypted/jellyfin-api-key.cred
   LoadCredential=db-password:/etc/credstore.encrypted/db-password.cred
   ```
3. **Expands** `${SECRET:name}` references in environment variables:
   - Reads from `/run/credentials/workload-jellyfin-1.service/jellyfin-api-key`
   - Substitutes into environment: `JELLYFIN_API_KEY=actual-secret-value`
4. **Passes** environment variables to `podman run`

### Runtime Behavior

When the workload service starts:

1. **systemd decrypts** credentials into `/run/credentials/{service}/`
2. **Generator reads** decrypted credentials and expands `${SECRET:}` references
3. **Podman starts** container with environment variables set
4. **Container sees** plain environment variables (no knowledge of systemd credentials)

When the workload service stops:

1. **systemd removes** `/run/credentials/{service}/` directory
2. **tmpfs clears** memory (plaintext secrets gone)
3. **Encrypted .cred files** remain safely on disk

## Setup and Usage

### Initial Setup (One-Time Per Secret)

#### Create Encrypted Credential

```bash
# Interactive (prompts for secret, press Ctrl+D when done)
sudo systemd-creds encrypt --with-key=tpm2 --name=jellyfin-api-key - /etc/credstore.encrypted/jellyfin-api-key.cred

# From stdin (useful for scripting)
echo -n "my-super-secret-value" | \
  sudo systemd-creds encrypt --with-key=tpm2 --name=jellyfin-api-key - /etc/credstore.encrypted/jellyfin-api-key.cred

# From file (for certificates, etc.)
sudo systemd-creds encrypt --with-key=tpm2 /path/to/cert.pem /etc/credstore.encrypted/tls-cert.cred
```

**Important:** Use `echo -n` (no newline) for secrets that shouldn't have trailing newlines (most API keys, passwords).

#### Verify Encryption

```bash
# Encrypted files are binary blobs (should see gibberish)
cat /etc/credstore.encrypted/jellyfin-api-key.cred

# Check file permissions
ls -la /etc/credstore.encrypted/
# Should show: -rw------- 1 root root
```

#### Decrypt for Verification (Optional)

```bash
# Decrypt to verify content (only works on the same machine)
sudo systemd-creds decrypt /etc/credstore.encrypted/jellyfin-api-key.cred -
# Outputs: my-super-secret-value
```

### Add to Workload Configuration

Create or edit `/etc/workloads.d/jellyfin.toml`:

```toml
[workload]
name = "jellyfin"
id = "1"

[container]
image = "jellyfin/jellyfin:latest"

[container.environment]
JELLYFIN_API_KEY = "${SECRET:jellyfin-api-key}"

[secrets]
credentials = ["jellyfin-api-key"]
```

### Enable and Start Workload

```bash
# Enable the workload (generates systemd units)
sudo workload-ctl enable jellyfin

# Check service status
sudo systemctl status workload-jellyfin-1.service

# View decrypted credentials (as root)
sudo ls -la /run/credentials/workload-jellyfin-1.service/
sudo cat /run/credentials/workload-jellyfin-1.service/jellyfin-api-key
```

### Verify Container Sees Environment Variable

```bash
# Check environment inside container
sudo workload-ctl exec jellyfin env | grep JELLYFIN_API_KEY
# Should show: JELLYFIN_API_KEY=my-super-secret-value
```

### Managing Secrets

#### Rotate a Secret

```bash
# 1. Create new encrypted credential (overwrites old one)
echo -n "new-secret-value" | \
  sudo systemd-creds encrypt --with-key=tpm2 --name=jellyfin-api-key - /etc/credstore.encrypted/jellyfin-api-key.cred

# 2. Restart workload to pick up new secret
sudo systemctl restart workload-jellyfin-1.service
```

#### Remove a Secret

```bash
# 1. Remove credential reference from TOML
sudo workload-ctl edit jellyfin
# (Remove from [secrets] and [container.environment])

# 2. Reload and restart
sudo systemctl daemon-reload
sudo systemctl restart workload-jellyfin-1.service

# 3. Optionally delete encrypted file
sudo rm /etc/credstore.encrypted/jellyfin-api-key.cred
```

#### List All Encrypted Credentials

```bash
ls -lh /etc/credstore.encrypted/
```

## Bootc Integration

### Baking Encrypted Credentials into the Image

Since encrypted credentials are safe to distribute, you can include them in your bootc image:

```dockerfile
# In hypervisor.Containerfile

# Create credstore directory
RUN mkdir -p /etc/credstore.encrypted

# Copy encrypted credentials
COPY credstore.encrypted/ /etc/credstore.encrypted/

# Set permissions
RUN chmod 0700 /etc/credstore.encrypted && \
    chmod 0600 /etc/credstore.encrypted/*.cred
```

**Benefits:**
- **Version controlled**: Encrypted secrets in git (safe!)
- **Immutable**: Can't be tampered with at runtime
- **Atomic updates**: New secrets = rebuild image
- **Rollback support**: Revert to old image = old secrets
- **Reproducible**: Same image = same encrypted secrets everywhere

**Build workflow:**

```bash
# 1. Create secrets locally
mkdir -p credstore.encrypted
echo -n "api-key" | sudo systemd-creds encrypt --with-key=tpm2 --name=jellyfin-api-key - credstore.encrypted/jellyfin-api-key.cred

# 2. Add to git (safe because encrypted)
git add credstore.encrypted/jellyfin-api-key.cred
git commit -m "Add jellyfin API key credential"

# 3. Build image
sudo podman build -t hypervisor:latest -f hypervisor.Containerfile .

# 4. Deploy to machines with TPM2
# Credentials will auto-decrypt on boot (TPM-backed)
```

### Machine-Specific Secrets

For secrets that vary per deployed machine (NOT in the shared image):

```bash
# On each deployed machine, store in /etc (mutable layer)
sudo systemd-creds encrypt \
  --with-key=tpm2 \
  --name=machine-specific-token \
  - /etc/credstore.encrypted/machine-specific-token.cred
```

**Where this lives:**
- `/etc` is the mutable layer in bootc (persists across image updates)
- Machine-specific credentials survive `bootc upgrade`
- Not part of the shared image (each machine has different values)

**Use cases:**
- Machine-specific Tailscale auth keys
- Per-host TLS certificates
- Hardware-specific license keys

### Hybrid Approach (Recommended)

Combine both strategies:

- **Shared secrets** (same across all machines): Bake into image
  - Example: Shared API keys, public certificates
- **Machine-specific secrets**: Store in `/etc` on each machine
  - Example: Host-specific keys, per-machine credentials

## Attack Scenarios

| Attack Vector | Protected? | Explanation |
|--------------|------------|-------------|
| **Steal encrypted .cred file** | ✅ YES | Encrypted with TPM2/host key - useless without the machine |
| **Shell as workload user** | ⚠️ PARTIAL | Can read own workload's credentials but NOT other workloads |
| **Root on running system** | ❌ NO | Root can read `/run/credentials/` (all secrets decrypted in memory) |
| **Physical disk access (machine off)** | ✅ YES | Secrets encrypted at rest, RAM cleared when powered off |
| **Swap TPM2 chip** | ✅ YES | TPM2 is unique per machine, can't decrypt on different TPM |
| **Boot malicious USB/kernel** | ✅ YES* | *IF using PCR policy (see Advanced Configuration) |
| **Container escape to host** | ⚠️ PARTIAL | Can read own service's credentials, but not encryption keys |
| **Backup tape stolen** | ✅ YES | Backups contain encrypted .cred files only |
| **Network sniffing** | ✅ YES | Secrets never transmitted over network |
| **Memory dump (cold boot)** | ⚠️ MAYBE | Depends on attack timing, tmpfs may retain data briefly |
| **Compromised container registry** | ✅ YES | Secrets not in images, only in encrypted credentials |

**Key limitation:** If an attacker gains **root access on a running system**, they can read decrypted secrets from `/run/credentials/`. However, this is true of ANY secrets system - root access means full compromise.

**Mitigation:** Use TPM2 PCR policies (see Advanced Configuration) to prevent unauthorized boot paths.

## Comparison to Alternatives

### vs. Plain Files in Volumes

**Old approach (INSECURE):**
```toml
[storage]
volumes = ["/etc/secrets/api-key.txt:/secrets/api-key:ro"]
```

**Problems:**
- ❌ Secret stored as plaintext on disk
- ❌ Anyone with disk access can read it
- ❌ Backup tapes contain plaintext secrets
- ❌ No automatic cleanup
- ❌ Visible to all users with disk access

### vs. Hardcoded in Container Images

**Bad practice:**
```dockerfile
ENV API_KEY="secret-value"
```

**Problems:**
- ❌ Baked into image layers (visible in `podman inspect`)
- ❌ Visible in container registry
- ❌ Can't rotate without rebuilding image
- ❌ Leaked if image is ever made public
- ❌ Git history contains plaintext secrets

### vs. Environment Variables in systemd (No Encryption)

**Unencrypted approach:**
```ini
[Service]
Environment="API_KEY=secret-value"
```

**Problems:**
- ❌ Plaintext in systemd service files
- ❌ Visible in `systemctl show`
- ❌ No encryption at rest
- ❌ Stored in `/etc/systemd/system/` as plaintext

### vs. External Secrets Management (Vault, SOPS, etc.)

| Feature | systemd-creds | HashiCorp Vault | SOPS |
|---------|---------------|-----------------|------|
| Network required | ❌ No | ✅ Yes | ❌ No |
| External service | ❌ No | ✅ Yes | ❌ No |
| Centralized rotation | ❌ No | ✅ Yes | ❌ No |
| TPM2 support | ✅ Yes | ⚠️ Indirect | ✅ Yes |
| Offline-first | ✅ Yes | ❌ No | ✅ Yes |
| Built into systemd | ✅ Yes | ❌ No | ❌ No |
| Audit trail | ❌ Basic | ✅ Comprehensive | ❌ No |
| Multi-machine | ❌ No | ✅ Yes | ✅ Yes |
| Complexity | ⭐ Low | ⭐⭐⭐ High | ⭐⭐ Medium |

**When to use systemd-creds:**
- Homelab/edge deployments
- Offline/air-gapped systems
- Simple infrastructure
- TPM2-backed security desired
- No external dependencies wanted

**When to use external secrets:**
- Large-scale deployments (100+ machines)
- Centralized secret rotation required
- Compliance/audit requirements
- Multi-team environments

## Advanced Configuration

### TPM2 PCR Policies

Bind secret decryption to system boot state:

```bash
# Require Secure Boot + specific kernel command line
sudo systemd-creds encrypt \
  --with-key=tpm2 \
  --tpm2-pcrs=7+11 \
  --name=my-secret \
  - /etc/credstore.encrypted/my-secret.cred
```

**PCR meanings:**
- **PCR 0**: BIOS/UEFI firmware
- **PCR 7**: Secure Boot state (enabled/disabled)
- **PCR 11**: Kernel command line
- **PCR 14**: MOK (Machine Owner Key) list

**Security benefit:**
- Secret can ONLY decrypt if system boots with:
  - Secure Boot enabled (PCR 7)
  - Specific kernel cmdline (PCR 11)
- If attacker boots malicious kernel → decryption fails
- If attacker disables Secure Boot → decryption fails

**Use case:**
- Maximum security for production systems
- Prevent unauthorized boot paths
- Compliance requirements (e.g., FIPS, DoD)

### Credential Scoping

Limit which services can access credentials:

```ini
# In generated service file (future enhancement)
LoadCredentialEncrypted=api-key:/etc/credstore.encrypted/jellyfin-api-key.cred
# Only this service can decrypt
```

### Credential Expiration

Set expiration timestamps (prevents old credentials from working):

```bash
# Create credential that expires in 90 days
sudo systemd-creds encrypt \
  --with-key=tpm2 \
  --not-after="+90days" \
  --name=temporary-secret \
  - /etc/credstore.encrypted/temporary-secret.cred
```

**Use cases:**
- Temporary access credentials
- Time-limited API keys
- Compliance requirements (rotate every X days)

### Multiple Credential Stores

Organize credentials by sensitivity:

```bash
/etc/credstore.encrypted/           # Standard secrets
/etc/credstore.encrypted/critical/  # High-security secrets (PCR-bound)
/etc/credstore.encrypted/shared/    # Shared across workloads
```

## Implementation Status

### Currently Implemented
- ✅ Basic workload provisioning
- ✅ Rootless container execution
- ✅ Per-workload user isolation

### Planned (Secrets Support)
- ⏳ `[container.environment]` section in TOML schema
- ⏳ `[secrets]` section in TOML schema
- ⏳ Generator support for `LoadCredential=`
- ⏳ `${SECRET:name}` expansion in environment variables
- ⏳ `workload-ctl secret` commands:
  - `workload-ctl secret create <name>`
  - `workload-ctl secret list`
  - `workload-ctl secret delete <name>`
  - `workload-ctl secret rotate <name>`
- ⏳ Volume-mounted secrets (credential files)
- ⏳ Registry credential automation

## References

- [systemd.exec(5) - LoadCredential documentation](https://www.freedesktop.org/software/systemd/man/systemd.exec.html#LoadCredential=ID:PATH)
- [systemd-creds(1) - Credential management tool](https://www.freedesktop.org/software/systemd/man/systemd-creds.html)
- [TPM2 integration in systemd](https://systemd.io/TPM2/)
- [Bootc security best practices](https://containers.github.io/bootc/)

## Examples

### Example 1: Simple API Key

```toml
# /etc/workloads.d/myapp.toml
[workload]
name = "myapp"
id = "5"

[container]
image = "myapp:latest"

[container.environment]
API_KEY = "${SECRET:myapp-api-key}"

[secrets]
credentials = ["myapp-api-key"]
```

```bash
# Setup
echo -n "sk-1234567890abcdef" | \
  sudo systemd-creds encrypt --with-key=tpm2 --name=myapp-api-key - /etc/credstore.encrypted/myapp-api-key.cred

# Enable
sudo workload-ctl enable myapp

# Verify
sudo workload-ctl exec myapp env | grep API_KEY
```

### Example 2: Multiple Secrets + Config File

```toml
# /etc/workloads.d/database.toml
[workload]
name = "postgres"
id = "10"

[container]
image = "postgres:16"

[container.environment]
POSTGRES_PASSWORD = "${SECRET:db-password}"
POSTGRES_USER = "${SECRET:db-username}"

[secrets]
credentials = ["db-password", "db-username", "tls-cert", "tls-key"]
files = [
    { credential = "tls-cert", path = "/var/lib/postgresql/server.crt" },
    { credential = "tls-key", path = "/var/lib/postgresql/server.key" }
]
```

```bash
# Create credentials
echo -n "secure-password-123" | sudo systemd-creds encrypt --with-key=tpm2 --name=db-password - /etc/credstore.encrypted/db-password.cred
echo -n "dbadmin" | sudo systemd-creds encrypt --with-key=tpm2 --name=db-username - /etc/credstore.encrypted/db-username.cred
sudo systemd-creds encrypt --with-key=tpm2 /path/to/server.crt /etc/credstore.encrypted/tls-cert.cred
sudo systemd-creds encrypt --with-key=tpm2 /path/to/server.key /etc/credstore.encrypted/tls-key.cred
```

### Example 3: Machine-Specific Tailscale Auth

```toml
# /etc/workloads.d/tailscale.toml (baked into image)
[workload]
name = "tailscale"
id = "99"

[container]
image = "tailscale/tailscale:latest"

[container.environment]
TS_AUTHKEY = "${SECRET:tailscale-authkey}"

[secrets]
credentials = ["tailscale-authkey"]
```

```bash
# On each deployed machine (NOT in image)
echo -n "tskey-auth-kXXXXX-YYYYYYYYYYYYYYYYYY" | \
  sudo systemd-creds encrypt --with-key=tpm2 --name=tailscale-authkey - /etc/credstore.encrypted/tailscale-authkey.cred
```

Each machine has a different auth key, but the workload config is the same across all machines.

---

**Last updated:** 2026-01-02
