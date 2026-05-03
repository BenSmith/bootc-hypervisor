> **Disclaimer:** This documentation and the software it describes are provided as-is, without warranty of fitness for any particular purpose. The implementation is largely AI-assisted. Regardless of system maturity, maintain a recovery plan — do not rely on any single mechanism as the sole means of accessing critical secrets.

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
│                                                                 │
│  Plain secret → systemd-creds encrypt → Encrypted credential    │
│  "my-api-key"                            (AES256-GCM)           │
│                                                                 │
│  Stored in: /etc/credstore.encrypted/jellyfin-api-key           │
│  Permissions: root:root 0600                                    │
│  Format: Binary blob (not readable as text)                     │
└─────────────────────────────────────────────────────────────────┘
                           ↓
┌─────────────────────────────────────────────────────────────────┐
│ 2. BOOT TIME (Automatic decryption)                             │
│                                                                 │
│  systemd reads service file:                                    │
│    LoadCredentialEncrypted=api-key:/etc/credstore.encrypted/... │
│                                                                 │
│  systemd decrypts using:                                        │
│    - TPM2 chip (if available) OR                                │
│    - Host key (/var/lib/systemd/credential.secret)              │
│                                                                 │
│  Writes decrypted secret to:                                    │
│    /run/credentials/workload-jellyfin.service/api-key           │
│                                                                 │
│  Permissions: _wl-jellyfin:root 0400 (read-only)                │
│  Location: tmpfs (RAM only, never hits disk)                    │
└─────────────────────────────────────────────────────────────────┘
                           ↓
┌─────────────────────────────────────────────────────────────────┐
│ 3. RUNTIME (Service access)                                     │
│                                                                 │
│  Only the workload service can read its credentials:            │
│    - Runs as user: _wl-jellyfin                                 │
│    - Sees: /run/credentials/workload-jellyfin.service/          │
│    - Cannot see other workload's credentials                    │
│                                                                 │
│  Generator reads credential and:                                │
│    - Injects into environment: JELLYFIN_API_KEY=<value>         │
│    - OR mounts into container as file                           │
└─────────────────────────────────────────────────────────────────┘
                           ↓
┌─────────────────────────────────────────────────────────────────┐
│ 4. SHUTDOWN (Automatic cleanup)                                 │
│                                                                 │
│  When service stops:                                            │
│    - /run/credentials/workload-jellyfin.service/ deleted        │
│    - Memory cleared (tmpfs wiped)                               │
│    - Encrypted credential remains safely on disk                │
└─────────────────────────────────────────────────────────────────┘
```

### Encryption Keys

systemd-creds supports three encryption key types:

#### Option A: TPM2 (Most Secure)

```bash
sudo systemd-creds encrypt --with-key=tpm2 --name=my-secret - /etc/credstore.encrypted/my-secret
```

**Security properties:**
- Encrypts using your **TPM2 chip** (hardware security module)
- Secret can ONLY be decrypted on **this specific machine**
- Even if attacker steals the encrypted credential, they cannot decrypt without your TPM
- Tamper-resistant (TPM2 PCR policy can require specific boot state)
- Survives OS reinstall (tied to hardware, not software)

**Requirements:**
- TPM2 chip present and enabled in BIOS
- `tpm2-tss` package installed (included in the hypervisor image)

#### Option B: Host Key (Still Secure)

```bash
sudo systemd-creds encrypt --with-key=host --name=my-secret - /etc/credstore.encrypted/my-secret
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
sudo systemd-creds encrypt --with-key=host+tpm2 --name=my-secret - /etc/credstore.encrypted/my-secret
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
| `/etc/credstore.encrypted/*` | Encrypted binary | root only (0600) | YES (survives reboot) |
| `/run/credentials/{service}/` | Plain text | Service user only | NO (tmpfs, RAM only) |
| Inside container | Plain text (env/file) | Container processes | NO (dies with container) |

**Key security property:** The plaintext secret **never touches disk** - only exists in RAM (`/run` is tmpfs).

### Per-Workload Isolation

Each service gets its own credential directory with strict permissions:

```bash
# Jellyfin workload (user: _wl-jellyfin, UID: 10001)
/run/credentials/workload-jellyfin.service/
  ├── api-key          (owner: 10001:root, mode: 0400)
  └── db-password      (owner: 10001:root, mode: 0400)

# Plex workload (user: _wl-plex, UID: 10002)
/run/credentials/workload-plex.service/
  └── claim-token      (owner: 10002:root, mode: 0400)
```

**Isolation guarantees:**
- User `_wl-jellyfin` **cannot** read `_wl-plex`'s credentials
- Even if jellyfin container is compromised, it cannot access plex secrets
- Standard Linux DAC (discretionary access control) enforces this
- No shared credential namespace

## How It Works

> **Key point:** You do not need to manually declare credentials anywhere beyond the TOML config. The generator **automatically detects** every `${SECRET:name}` reference in `[container.environment]` and every credential listed in `[secrets.files]`, then emits the required `LoadCredentialEncrypted=` directives in the generated service file. Just use the syntax and the plumbing is handled for you.

### Workload Configuration (TOML)

Define secrets in your workload configuration:

```toml
[workload]
name = "jellyfin"

[container]
image = "jellyfin/jellyfin:latest"

# Environment variables (can reference secrets)
[container.environment]
JELLYFIN_PublishedServerUrl = "https://jellyfin.example.com"  # Plain value
JELLYFIN_API_KEY = "${SECRET:jellyfin-api-key}"               # Secret reference
JELLYFIN_DB_PASSWORD = "${SECRET:db-password}"                # Secret reference

# Secrets configuration
[secrets]
# Mount secrets as files (for config files with embedded secrets)
# Credentials are auto-detected from ${SECRET:...} env vars and files[] entries
# Files are mounted read-only (mode = "ro") by default for security
# Use mode = "rw" only if the container needs to modify the secret temporarily (rare)
files = [
    { credential = "tls-cert", path = "/config/cert.pem" },                    # defaults to ro
    { credential = "tls-key", path = "/config/key.pem", mode = "ro" },         # explicit ro
    # { credential = "writable-secret", path = "/data/secret", mode = "rw" }   # must explicitly set rw
]
```

### Generator Integration

The `workload-generate` script (run as an early-boot oneshot service; see `docs/workloads.md` for why it isn't itself a systemd generator) processes credential configuration when it emits per-workload unit files:

1. **Auto-detects** needed credentials by scanning:
   - Environment variables for `${SECRET:name}` references
   - `secrets.files` array for credential references
2. **Generates** systemd service file with `LoadCredentialEncrypted=` directives:
   ```ini
   [Service]
   LoadCredentialEncrypted=jellyfin-api-key:/etc/credstore.encrypted/jellyfin-api-key
   LoadCredentialEncrypted=db-password:/etc/credstore.encrypted/db-password
   LoadCredentialEncrypted=tls-cert:/etc/credstore.encrypted/tls-cert
   LoadCredentialEncrypted=tls-key:/etc/credstore.encrypted/tls-key
   ```
3. **Converts** `${SECRET:name}` references in environment variables to shell command substitution:
   - TOML: `JELLYFIN_API_KEY = "${SECRET:jellyfin-api-key}"`
   - Becomes: `--env JELLYFIN_API_KEY=$(<${CREDENTIALS_DIRECTORY}/jellyfin-api-key)`
   - `${CREDENTIALS_DIRECTORY}` is set by systemd to `/run/credentials/workload-{name}.service`
4. **Mounts** credential files into container:
   - TOML: `{ credential = "tls-cert", path = "/config/cert.pem" }`
   - Becomes: `--volume /run/credentials/workload-jellyfin.service/tls-cert:/config/cert.pem:ro`
5. **Generates** ExecStart command with environment variables and volume mounts for `podman run`

At service start time, the shell expands `$(<file)` to read the decrypted credentials.

### Runtime Behavior

When the workload service starts:

1. **systemd decrypts** credentials into `/run/credentials/{service}/`
2. **Shell expands** command substitution syntax (e.g., `$(<${CREDENTIALS_DIRECTORY}/secret-name)`)
3. **Podman starts** container with:
   - Fully expanded environment variables
   - Credential files mounted at specified paths
4. **Container sees**:
   - Plain environment variables (no knowledge of systemd credentials)
   - Credential files as regular files in the filesystem

**Note:** `workload-generate` runs once at early boot (via `workload-generate.service`), not at each workload service start. It emits the per-workload unit file with shell command substitution syntax in the `ExecStart=` line, and that substitution is expanded by the shell when the workload service actually starts — at which point systemd has already decrypted the credentials into `/run/credentials/{service}/`.

When the workload service stops:

1. **systemd removes** `/run/credentials/{service}/` directory
2. **tmpfs clears** memory (plaintext secrets gone)
3. **Encrypted credentials** remain safely on disk

### Credential Mutability and Persistence

**Important:** Even if credentials are mounted with `mode = "rw"`, modifications **do not persist** across service restarts.

#### Why Changes Don't Persist

1. **Credentials live in tmpfs (RAM only)**
   - Location: `/run/credentials/workload-{name}.service/`
   - tmpfs = temporary filesystem in memory, never written to disk
   - All contents erased when service stops

2. **Fresh decryption on every start**
   ```
   Service Start:
   1. systemd decrypts /etc/credstore.encrypted/{name}
   2. Writes plaintext to /run/credentials/{service}/{name} (fresh copy)
   3. Container mounts and can read (or modify if mode=rw)

   Service Stop/Restart:
   1. systemd removes /run/credentials/{service}/ directory
   2. All modifications lost (RAM cleared)

   Next Service Start:
   1. Fresh decryption from /etc/credstore.encrypted/ (original value)
   2. Any previous modifications are gone
   ```

3. **Source of truth is always `/etc/credstore.encrypted/`**
   - Only the encrypted file persists across reboots
   - Container cannot modify the encrypted source
   - Each start = fresh decryption of original encrypted value

#### Security Implications

This ephemeral nature is a **security feature**:

- ✅ **Container compromise can't permanently corrupt secrets**
  - Even if attacker modifies credentials in running container
  - Service restart restores original values

- ✅ **No persistent damage**
  - Malicious changes exist only during current service lifetime
  - Restart = automatic remediation

- ✅ **Immutable credential source**
  - Container has no write access to `/etc/credstore.encrypted/`
  - Only systemd (with decryption keys) can modify source

#### When to Use `mode = "rw"`

Since modifications don't persist, `mode = "rw"` is rarely needed. Possible use cases:

- **Temporary in-memory modifications**: Container needs to reformat or process the credential before use
- **Application requirements**: Some applications expect to write to credential files even if changes aren't persisted

**Note:** For persistent credential updates, use `workloadctl secret rotate` to update the encrypted source.

Most workloads should use `mode = "ro"` (the default).

## Setup and Usage

### Initial Setup (One-Time Per Secret)

#### Create Encrypted Credential

```bash
# Interactive (prompts for secret, press Ctrl+D when done)
sudo systemd-creds encrypt --with-key=tpm2 --name=jellyfin-api-key - /etc/credstore.encrypted/jellyfin-api-key

# From stdin (useful for scripting)
echo -n "my-super-secret-value" | \
  sudo systemd-creds encrypt --with-key=tpm2 --name=jellyfin-api-key - /etc/credstore.encrypted/jellyfin-api-key

# From file (for certificates, etc.)
sudo systemd-creds encrypt --with-key=tpm2 --name=tls-cert /path/to/cert.pem /etc/credstore.encrypted/tls-cert
```

**Important Notes:**
- Use `echo -n` (no newline) for secrets that shouldn't have trailing newlines (most API keys, passwords)
- The `--name` parameter sets the embedded credential name (used by systemd for validation)
- The filename can be anything, but should match the `--name` for consistency
- We omit `.cred` suffix to keep names simple and avoid confusion

#### Verify Encryption

```bash
# Encrypted files are binary blobs; cat will produce garbled terminal output
sudo cat /etc/credstore.encrypted/jellyfin-api-key

# Check file permissions (should be 600 or 644)
ls -la /etc/credstore.encrypted/
# Should show: -rw------- 1 root root (or -rw-r--r--)
```

#### Decrypt for Verification (Optional)

```bash
# Decrypt to verify content (only works on the same machine)
sudo systemd-creds decrypt /etc/credstore.encrypted/jellyfin-api-key -
# Outputs: my-super-secret-value
```

### Add to Workload Configuration

Create or edit `/etc/workloads.d/jellyfin.toml`:

```toml
[workload]
name = "jellyfin"

[container]
image = "jellyfin/jellyfin:latest"

[container.environment]
JELLYFIN_API_KEY = "${SECRET:jellyfin-api-key}"
# Credentials auto-detected from ${SECRET:...} references
```

### Enable and Start Workload

```bash
# Enable the workload (generates systemd units)
sudo workloadctl enable jellyfin

# Check service status
sudo systemctl status workload-jellyfin.service

# View decrypted credentials (as root)
sudo ls -la /run/credentials/workload-jellyfin.service/
sudo cat /run/credentials/workload-jellyfin.service/jellyfin-api-key
```

### Verify Container Sees Environment Variable

```bash
# Check environment inside container (using workload user for rootless containers)
sudo -u _wl-jellyfin podman exec workload-jellyfin env | grep JELLYFIN_API_KEY
# Should show: JELLYFIN_API_KEY=my-super-secret-value

# Or use workloadctl if available (may not work for all setups)
# sudo workloadctl exec jellyfin env | grep JELLYFIN_API_KEY
```

### Managing Secrets

#### Rotate a Secret

```bash
# 1. Create new encrypted credential (overwrites old one)
echo -n "new-secret-value" | \
  sudo systemd-creds encrypt --with-key=tpm2 --name=jellyfin-api-key - /etc/credstore.encrypted/jellyfin-api-key

# 2. Restart workload to pick up new secret
sudo systemctl restart workload-jellyfin.service
```

#### Remove a Secret

```bash
# 1. Remove credential reference from TOML
sudo workloadctl edit jellyfin
# (Remove from [secrets] and [container.environment])

# 2. Reload and restart
sudo systemctl daemon-reload
sudo systemctl restart workload-jellyfin.service

# 3. Optionally delete encrypted file
sudo rm /etc/credstore.encrypted/jellyfin-api-key
```

#### List All Encrypted Credentials

```bash
ls -lh /etc/credstore.encrypted/
```

### Verifying Secrets Are Securely Injected

After setting up secrets, you can verify they're working correctly and securely:

#### 1. Verify Credential Decryption

```bash
# Check that systemd decrypted the credential to tmpfs (RAM-only)
sudo ls -la /run/credentials/workload-jellyfin.service/

# Expected output:
# dr-xr-x---+ 2 root root  60 <date> .
# -r--r-----+ 1 root root  XX <date> jellyfin-api-key
# Note: The + indicates ACLs for user access

# Verify the plaintext secret (should NOT be the encrypted blob)
sudo cat /run/credentials/workload-jellyfin.service/jellyfin-api-key
# Expected: my-super-secret-value (plaintext)
# NOT: base64-encoded encrypted data
```

#### 2. Verify Environment Variable Expansion

```bash
# For rootless containers, use the workload user (NOT root's podman)
# Get the workload user from the service name (e.g., _wl-jellyfin)
WORKLOAD_USER="_wl-jellyfin"

# Check environment variables inside the running container
sudo -u $WORKLOAD_USER podman exec workload-jellyfin env | grep JELLYFIN_API_KEY
# Expected: JELLYFIN_API_KEY=my-super-secret-value

# Verify mixed expansion (if using embedded secrets)
sudo -u $WORKLOAD_USER podman exec workload-jellyfin env | grep DATABASE_URL
# Expected: DATABASE_URL=postgresql://dbuser:my-password@localhost:5432/myapp
```

**Important**: Rootless containers run under the workload user's podman instance, not root's. Always use `sudo -u <workload-user>` when accessing container logs or exec.

#### 3. Verify Credential Isolation

```bash
# Check that credentials are NOT readable by other users
sudo -u nobody cat /run/credentials/workload-jellyfin.service/jellyfin-api-key
# Expected: Permission denied

# If you have multiple workloads, verify they can't see each other's secrets
sudo -u _wl-plex cat /run/credentials/workload-jellyfin.service/jellyfin-api-key
# Expected: Permission denied
```

#### 4. Verify Credential File Permissions

```bash
# Check ACLs on credential file (should show workload user has access)
sudo getfacl /run/credentials/workload-jellyfin.service/jellyfin-api-key

# Expected output includes:
# user::r--
# user:_wl-jellyfin:r--
# This proves the workload user has read access via ACL
```

#### 5. Verify Cleanup on Service Stop

```bash
# Stop the workload
sudo systemctl stop workload-jellyfin.service

# Verify credentials directory is removed
ls /run/credentials/workload-jellyfin.service/
# Expected: No such file or directory

# Restart and verify credentials are recreated
sudo systemctl start workload-jellyfin.service
sleep 2
sudo cat /run/credentials/workload-jellyfin.service/jellyfin-api-key
# Expected: my-super-secret-value (recreated from encrypted file)
```

#### 6. Troubleshooting: Check for Credential Errors

```bash
# If credentials aren't working, check systemd logs
sudo journalctl -u workload-jellyfin.service | grep -i credential

# Verify the service file has LoadCredentialEncrypted
sudo grep LoadCredential /run/systemd/system/workload-jellyfin.service
# Expected: LoadCredentialEncrypted=jellyfin-api-key:/etc/credstore.encrypted/jellyfin-api-key

# Test manual decryption
sudo systemd-creds decrypt /etc/credstore.encrypted/jellyfin-api-key -
# Should output the plaintext secret
```

#### 7. Complete Verification Checklist

Run this complete test to verify everything works:

```bash
WORKLOAD="jellyfin"
WORKLOAD_USER="_wl-jellyfin"
SECRET_NAME="jellyfin-api-key"

echo "=== Secrets Verification Checklist ==="

# 1. Credential file exists and is encrypted
echo -n "1. Encrypted credential exists: "
[[ -f "/etc/credstore.encrypted/$SECRET_NAME" ]] && echo "✓" || echo "✗"

# 2. Can decrypt manually
echo -n "2. Manual decryption works: "
sudo systemd-creds decrypt "/etc/credstore.encrypted/$SECRET_NAME" - >/dev/null 2>&1 && echo "✓" || echo "✗"

# 3. Service is running
echo -n "3. Workload service running: "
sudo systemctl is-active workload-$WORKLOAD.service >/dev/null 2>&1 && echo "✓" || echo "✗"

# 4. Credentials directory exists
echo -n "4. Credentials directory exists: "
[[ -d "/run/credentials/workload-$WORKLOAD.service" ]] && echo "✓" || echo "✗"

# 5. Credential is decrypted (plaintext, not encrypted binary blob)
echo -n "5. Credential is plaintext: "
CRED_CONTENT=$(sudo cat "/run/credentials/workload-$WORKLOAD.service/$SECRET_NAME" 2>/dev/null)
# Check: not empty, less than 200 bytes (encrypted blobs are much larger binary objects)
if [[ -n "$CRED_CONTENT" ]] && [[ ${#CRED_CONTENT} -lt 200 ]]; then
    echo "✓"
else
    echo "✗"
fi

# 6. Container is running
echo -n "6. Container is running: "
sudo -u $WORKLOAD_USER podman ps --filter "name=workload-$WORKLOAD" --quiet | grep -q . && echo "✓" || echo "✗"

# 7. Environment variable is set in container (customize JELLYFIN_API_KEY to match your env var)
echo -n "7. Secret in container env: "
sudo -u $WORKLOAD_USER podman exec workload-$WORKLOAD env 2>/dev/null | grep -q "JELLYFIN_API_KEY" && echo "✓" || echo "✗"

echo ""
echo "If all checks show ✓, your secrets are working correctly!"
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
    chmod 0600 /etc/credstore.encrypted/*
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
echo -n "api-key" | sudo systemd-creds encrypt --with-key=tpm2 --name=jellyfin-api-key - credstore.encrypted/jellyfin-api-key

# 2. Add to git (safe because encrypted)
git add credstore.encrypted/jellyfin-api-key
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
  - /etc/credstore.encrypted/machine-specific-token
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
| **Steal encrypted credential file** | ✅ YES | Encrypted with TPM2/host key - useless without the machine |
| **Shell as workload user** | ⚠️ PARTIAL | Can read own workload's credentials but NOT other workloads |
| **Root on running system** | ❌ NO | Root can read `/run/credentials/` (all secrets decrypted in memory) |
| **Modify credentials in container** | ✅ YES | Changes only in tmpfs RAM, lost on restart - fresh decryption restores originals |
| **Physical disk access (machine off)** | ✅ YES | Secrets encrypted at rest, RAM cleared when powered off |
| **Swap TPM2 chip** | ✅ YES | TPM2 is unique per machine, can't decrypt on different TPM |
| **Boot malicious USB/kernel** | ✅ YES* | *IF using PCR policy (see Advanced Configuration) |
| **Container escape to host** | ⚠️ PARTIAL | Can read own service's credentials, but not encryption keys |
| **Backup tape stolen** | ✅ YES | Backups contain encrypted credential files only |
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
  - /etc/credstore.encrypted/my-secret
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
LoadCredentialEncrypted=api-key:/etc/credstore.encrypted/jellyfin-api-key
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
  - /etc/credstore.encrypted/temporary-secret
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
- ✅ `[container.environment]` section in TOML schema
- ✅ `[secrets]` section in TOML schema
- ✅ Auto-detection of credentials from env vars and file mounts
- ✅ Generator support for `LoadCredentialEncrypted=`
- ✅ `${SECRET:name}` expansion in environment variables
- ✅ `secrets.files` - volume-mounted credential files
- ✅ `workloadctl secret` commands:
  - ✅ `workloadctl secret create <name>`
  - ✅ `workloadctl secret list`
  - ✅ `workloadctl secret show <name>`
  - ✅ `workloadctl secret delete <name>`
  - ✅ `workloadctl secret rotate <name>`

### Possible Future Enhancements
- ⏳ Registry credential automation
- ⏳ Credential expiration enforcement
- ⏳ PCR policy validation

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

[container]
image = "myapp:latest"

[container.environment]
API_KEY = "${SECRET:myapp-api-key}"
# Credentials auto-detected from ${SECRET:...} references
```

```bash
# Setup
echo -n "sk-1234567890abcdef" | \
  sudo systemd-creds encrypt --with-key=tpm2 --name=myapp-api-key - /etc/credstore.encrypted/myapp-api-key

# Enable
sudo workloadctl enable myapp

# Verify (use the workload user for rootless containers)
sudo -u _wl-myapp podman exec workload-myapp env | grep API_KEY
```

### Example 2: Multiple Secrets + Config File

```toml
# /etc/workloads.d/database.toml
[workload]
name = "postgres"

[container]
image = "postgres:16"

[container.environment]
POSTGRES_PASSWORD = "${SECRET:db-password}"
POSTGRES_USER = "${SECRET:db-username}"

[secrets]
# Credentials auto-detected from ${SECRET:...} env vars and files[] entries
files = [
    { credential = "tls-cert", path = "/var/lib/postgresql/server.crt" },
    { credential = "tls-key", path = "/var/lib/postgresql/server.key" }
]
```

```bash
# Create credentials
echo -n "secure-password-123" | sudo systemd-creds encrypt --with-key=tpm2 --name=db-password - /etc/credstore.encrypted/db-password
echo -n "dbadmin" | sudo systemd-creds encrypt --with-key=tpm2 --name=db-username - /etc/credstore.encrypted/db-username
sudo systemd-creds encrypt --with-key=tpm2 --name=tls-cert /path/to/server.crt /etc/credstore.encrypted/tls-cert
sudo systemd-creds encrypt --with-key=tpm2 --name=tls-key /path/to/server.key /etc/credstore.encrypted/tls-key
```

### Example 3: Machine-Specific Tailscale Auth

```toml
# /etc/workloads.d/tailscale.toml (baked into image)
[workload]
name = "tailscale"

[container]
image = "tailscale/tailscale:latest"

[container.environment]
TS_AUTHKEY = "${SECRET:tailscale-authkey}"
# Credentials auto-detected from ${SECRET:...} references
```

```bash
# On each deployed machine (NOT in image)
echo -n "tskey-auth-kXXXXX-YYYYYYYYYYYYYYYYYY" | \
  sudo systemd-creds encrypt --with-key=tpm2 --name=tailscale-authkey - /etc/credstore.encrypted/tailscale-authkey
```

Each machine has a different auth key, but the workload config is the same across all machines.

---

**Last updated:** 2026-01-02
