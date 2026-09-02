# workloadctl

Declarative workload manager for Linux. Drop a TOML file into
`/etc/workloads.d/<name>/`, and workloadctl provisions everything underneath
it: a dedicated system user, systemd units, storage, secrets, networking and
lifecycle.

A workload is either a **container** (rootless podman) or a **VM** (KVM/QEMU,
declared with a `[vm]` section). Both share one TOML model, one command
surface, and one isolation rule — **one workload, one unprivileged system
user** — so `status`, `logs`, `update`, `rollback` and `backup` mean the same
thing whichever substrate a workload runs on.

Stdlib Python only. No package manager, no virtualenv, no daemon of its own.

## Quick start

```bash
sudo workloadctl create webserver \
  --image docker.io/nginxinc/nginx-unprivileged:alpine \
  --ports 8080:8080 \
  --enable

workloadctl status webserver
workloadctl logs webserver
```

`create` writes the TOML; `--enable` also creates the user and starts it. Or
write the file yourself and enable it:

```bash
sudo mkdir -p /etc/workloads.d/webserver
sudo tee /etc/workloads.d/webserver/workload.toml <<'EOF'
[workload]
name = "webserver"

[container]
image = "docker.io/nginxinc/nginx-unprivileged:alpine"

[network]
ports = ["8080:8080"]
EOF

workloadctl validate webserver && sudo workloadctl enable webserver
```

## The isolation model

Every workload gets its own locked-down system user, `_wl-<name>`, at UID
10000+, with `/usr/sbin/nologin` as its shell and its own subuid/subgid ranges.
Containers run under that user's own rootless podman; VMs run as QEMU processes
owned by it. Nothing runs privileged, and no two workloads share an identity.

That uid is not just hygiene — it is the **selector everything else keys on**.
Egress policy matches on it, storage is owned by it, and because the host
assigns it, software inside the workload cannot forge it.

Units are generated at boot rather than installed. A tiny *shell* systemd
generator emits one oneshot, `workload-generate.service`, which runs the Python
generator during early boot to write per-workload units into
`/run/systemd/system/` before `basic.target`. Python is deliberately kept out
of generator context — generators must be fast, and import overhead blows
systemd's budget. Both layers always exit 0, so a broken workload never blocks
boot.

The consequence worth knowing: **the TOML is the source of truth, and the units
are derived.** Edit the file, re-enable, and the units follow. `workloadctl
drift` reports any live unit that no longer matches what its TOML would
produce.

## Container workloads

Three topologies, chosen with `workload.mode`:

| mode | shape |
|---|---|
| `single` | one `[container]` block — the common case |
| `pod` | several `[[containers]]` sharing a network namespace; they talk over localhost |
| `bridge` | per-container namespaces on an auto-created network; they resolve each other by container name |

Single- and multi-container shapes are normalised internally, so a
one-container TOML produces byte-identical units either way. Container-targeted
commands take `<workload>/<container>`.

Convenience flags expand to the right devices, groups and mounts rather than
making you spell them out: `--gpu amd|nvidia|intel|auto` (or
`nvidia:<index|UUID>` to pin one card), `--audio`, `--input`,
`--virtualization`.

**Reading logs:** units run with `--log-driver=passthrough`, so `podman logs`
will not work. Use `workloadctl logs <name>`, which knows where journald
actually attributes the output.

## VM workloads

A `[vm]` section — mutually exclusive with `[container]` — runs the workload as
raw QEMU/KVM: UEFI/OVMF, split `system.qcow2`/`data.qcow2` with generational
rollback, virtiofs volumes, a cloud-init seed and a per-workload SSH key.
`update` rebuilds the system disk and leaves data alone; `rollback` restores the
previous generation.

**Networking is passt, not a bridge.** passt terminates the guest's stack in
userspace and re-originates its traffic as host sockets owned by `_wl-<name>` —
which is what makes the workload uid an unforgeable selector for egress policy.
Three consequences catch people out:

- The guest has **no LAN identity of its own**; it is assigned the host's
  address. Inbound needs an explicit `[vm.network].ports`.
- `exec` and `shell` reach it on a uid-derived management address that is never
  routable and never configurable.
- `[vm.network].bridge` is the escape hatch for a VM that genuinely needs a LAN
  address. The operator provisions that bridge; workloadctl does not.

### Egress filtering

**A VM is filtered by default** (`egress = "filtered"`; the alternative is
`"open"`). A filtered guest's DNS and its 80/443 traffic are redirected to a
per-workload egress inspector, and everything else is denied. The guest is not
configured to cooperate and is not asked to — there are no proxy variables to
unset, because the redirect does not consult the guest.

Policy is declared per host, and TLS is terminated for inspection by default
(`tls = "inspect"`, or `"splice"` to allow a host through on its name alone):

```toml
[vm.network]
egress = "filtered"

[[vm.network.policy]]
host    = "api.github.com"
methods = ["GET", "POST"]
paths   = ["/repos/myorg/*"]
```

`workloadctl rules` reports what a VM is permitted to do; `workloadctl egress`
reports what it actually did, per request. The two together are the operator's
whole view of the filter.

### The credential broker

A sandboxed workload that must call an authenticated API never receives the
key. Seal it on the host, declare the material, and name it from the policy
entry it applies to; a host-side broker attaches it on the way out.

Seal the real key under the workload that may spend it — here a VM workload
named `agent-vm`:

```bash
echo -n "sk-ant-..." | sudo workloadctl secret create broker/agent-vm/anthropic
```

The scoped name is a `secret` name form, not a broker-specific flag, so
`secret list`, `rotate`, `export` and the rest take it too. It lands at
`/etc/credstore.encrypted/broker/agent-vm/anthropic`, sealed under the name
`broker-agent-vm-anthropic` — and because the seal name is bound into the blob
and checked on decrypt, a unit pointed at another workload's file fails to
start rather than reading that workload's key.

Then, in `/etc/workloads.d/agent-vm/workload.toml`:

```toml
[[vm.network.policy]]
host       = "api.anthropic.com"
methods    = ["POST"]
paths      = ["/v1/messages"]
credential = "anthropic"

[[vm.network.credential]]
name        = "anthropic"          # the sealed material, broker/agent-vm/anthropic
placeholder = "sk-ant-placeholder-not-a-real-key"
env         = "ANTHROPIC_API_KEY"  # what the guest gets instead
```

```bash
workloadctl validate agent-vm && sudo workloadctl restart agent-vm
```

The guest holds `placeholder` in `ANTHROPIC_API_KEY`, calls the provider's real
hostname, and its own inspector relays the request to that workload's broker
instead of to the origin. The broker discards the placeholder and sets the real
header. The key is decrypted only into the broker instance's own tmpfs, under a
dynamic user disjoint from the workload's, so it is never in the guest, never in
`workload.toml`, and never in the workload user's filesystem.

The guest is told nothing: no endpoint, no variable, no name — so it cannot
decline to use the broker and cannot be pointed at another workload's.

## Secrets

systemd credentials — AES256-GCM, sealed to the TPM2 (or a host key), decrypted
into tmpfs only at unit start. Encrypted blobs are therefore safe to commit into
an image. Reference one from a workload's environment as `${SECRET:name}`, and
manage the store with `workloadctl secret`, which also does passphrase-protected
export/import for moving one between hosts.

## Commands

Read-only commands work as any user; mutating ones need `sudo`.

**Lifecycle** — `create`, `enable`, `disable` (`--purge` to take the user and
data too), `start`, `stop`, `restart`, `reboot`, `recreate`, `update`,
`rollback`

**Inspect** — `list`, `status`, `info`, `health`, `logs`, `stats`, `images`,
`catalog`

**Reach into it** — `exec`, `shell`, `cp`

**Filtered VMs** — `rules` (what it may do), `egress` (what it did), `pcap`

**Author and edit** — `edit` (config or a control file, copy-on-write),
`catalog` + `init` (instantiate a shipped bundle), `duplicate`, `install`,
`build`

**Data** — `backup`, `restore`, `secret`

**When something is wrong** — `validate` (before enabling), `doctor`
(everything at once), `diagnose` (user, subids, linger, SELinux), `drift` (live
units vs. what the TOML would generate now), `cleanup` (orphaned users,
directories and SELinux modules)

`incant` is the deliberate escape hatch: it sends a raw command to a
workload's control plane as the owning identity — `podman` for a container, QMP
for a VM — with the fiddly invocation supplied. It bypasses the declarative
model, which is the point and also the warning. It reaches the runtime's
*manager*, not the workload interior; for the interior use `exec` / `shell`.

For a container it is `podman`, run as `_wl-<name>` with that user's rootless
environment:

```bash
workloadctl incant webproxy -- volume ls
```

```bash
# the same thing by hand
sudo -n -u _wl-webproxy \
  -E XDG_RUNTIME_DIR=/run/user/10003 \
  -E HOME=/var/lib/workloads/webproxy \
  -E DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/10003/bus \
  podman volume ls
```

The UID is allocated at create time, so it has to be looked up
(`workloadctl info webproxy`). Dropping the bus address is the interesting
mistake: read-only calls like `volume ls` still work, so it surfaces much later
on the first command that migrates a cgroup — `podman exec` failing with
`Permission denied` writing `cgroup.procs`.

For a VM it is one command on the QEMU monitor. The first token is the QMP
command; any further `key=value` tokens become its arguments, and the JSON
reply is printed:

```bash
workloadctl incant buildhost -- query-status
workloadctl incant buildhost -- system_powerdown
```

```bash
# the same thing by hand
sudo sh -c 'printf "%s\n%s\n" \
    "{\"execute\":\"qmp_capabilities\"}" \
    "{\"execute\":\"query-status\"}" \
  | socat -t2 - UNIX-CONNECT:/run/workload-vm/buildhost/qmp.sock'
```

QMP opens with a greeting and refuses every command until it is answered with
`qmp_capabilities`, so the handshake is not optional; the socket lives in a
`0750` directory owned by `_wl-buildhost`; and what comes back is a stream of
JSON objects to match up yourself.

`workloadctl <command> --help` for the full surface; most read commands take
`--json`.

## Requirements

- systemd, and Fedora 43+ or an equivalent
- Python 3.14+, podman 5.3+
- `passt`, `nftables`, `openssl`, `shadow-utils`
- SELinux tooling: `policycoreutils`, `policycoreutils-python-utils`,
  `container-selinux` (`udica` recommended)
- VM workloads additionally want `qemu-kvm` and `virtiofsd`; `pcap` wants
  `tcpdump`

No bootc or immutable OS required — workloadctl is a standalone RPM and runs on
ordinary Fedora. It is *bootc-ready*, which is a different claim: TOMLs and
encrypted secrets can be baked into an image, and everything self-provisions on
first boot.

## Install

```bash
cd workloadctl
rpmbuild -bb --define "_topdir $(pwd)/rpmbuild" \
  --define "_sourcedir $(pwd)" rpm/workloadctl.spec
sudo dnf install rpmbuild/RPMS/noarch/workloadctl-*.rpm
```

Or `just rpm-install` from the same directory, which does both steps.

## Development

```bash
just test              # full unit suite
just test-unit         # fast subset
just test-integration  # integration only
just lint              # syntax check
just rpm-build         # build the RPM from this checkout
```

There is no virtualenv: scripts run against the system `python3`, and `lib/` has
no third-party dependencies. `just test-runtime` boots a throwaway VM and runs
runtime checks against it; it skips cleanly on a host without `/dev/kvm`.

## Comparison with Quadlets

Podman Quadlets generate a systemd unit from a container spec. workloadctl
starts a layer earlier and finishes a layer later: it owns the OS user, the
subuid ranges, the storage, the secrets and the update path, and it treats a VM
as the same kind of object as a container. Quadlets answer "what unit should
this container get?"; workloadctl answers "what does this host need in order to
run this thing safely, and how do I take it back?"

If you want a unit file from a container spec, Quadlets are simpler and you
should use them.

## Documentation

- [Workload guide](docs/workloads.md) — configuration reference with worked examples
- [CLI reference](docs/cli.md) — every command and flag
- [Schema reference](docs/schema-reference.toml) — the annotated full TOML schema
- [Secrets](docs/secrets.md) — TPM2-encrypted credentials end to end
- [Filtered VM walkthrough](docs/vm-egress-walkthrough.md) — one request, TOML to packet
- [Credential broker](docs/agent-broker.md) — design, threat model, operation
- [VM virtiofs](docs/vm-virtiofs.md) — how guest volumes are shared and confined
- [Run files](docs/workload-run-files.md) — what lands in `/run` and who owns it
- [Testing](docs/testing.md) — the test-value rubric this suite is written to
- [Design decisions](docs/adr/) — the ADRs, including passt networking and egress inspection
- [Example bundles](workloads/) — 33 shipped workload definitions, one per directory

## License

MIT — see [LICENSE](LICENSE).
