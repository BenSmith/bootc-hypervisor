# forgejo-runner

A Fedora VM that registers with a Forgejo instance as a native Actions runner.

```
host (workloadctl)
└── workload-forgejo-runner.service   [VM, raw QEMU]
    └── forgejo-runner.service        [native systemd unit]
```

The runner is **native** (jobs run as processes in the guest), which is the whole
point of it being a VM: `podman build` works without container-in-container. It
also carries the nested-KVM tooling (`qemu-kvm`, `swtpm`, `edk2-ovmf`) so the
hypervisor's own gate rung — a real bootc image under a swtpm-backed vTPM — runs
here too.

Split out of the `virtual-forgejo` bundle: the forge itself can be a host
container workload (see the sibling `forgejo` bundle), and this VM exists only to
run jobs.

## No data disk

Nothing here is precious. Build artifacts go to the registry or the forge, the
workspace is scratch, and container image layers live in the host `zot` registry.
The runner's only state is its server-side registration, which is cheap to
recreate: `setup.sh` creates the runner on the Forgejo server on every
provision, and the seed declares the connection from it.

## Prerequisites

1. A running Forgejo instance **on this host**, reachable from both the host
   and the VM. The runner reaches it on its own derived address
   (`198.18.x.y` from its uid — the only door a passt guest has onto its own
   host) at the forge's published HTTP port; the forge need only publish that
   port (wildcard is fine). See "Reaching the forge from the VM" below.
2. A **Forgejo admin API token**. The host setup hook uses it to create the
   runner; it never enters the VM.

   ```sh
   sudo workloadctl secret create forgejo-admin-token
   ```

3. `FORGEJO_ADMIN_URL` in the instance TOML set to where this host reaches
   that forge's admin API (localhost, or the forge's LAN port).

## Provisioning

```sh
sudo workloadctl init forgejo-runner
sudo workloadctl edit forgejo-runner     # set [vm.cloud_init.template_vars].FORGEJO_ADMIN_URL
sudo workloadctl enable forgejo-runner
```

`enable` runs the host setup hook first, which creates the runner on the server
and seals its uuid and token at
`/etc/credstore.encrypted/forgejo-runner-{uuid,token}`; the seed is built
afterwards and declares them as a `server.connections` entry, so the runner
starts already registered.

Watch first boot (cloud-init installs packages, fetches the runner binary, and
declares the connection):

```sh
sudo workloadctl exec forgejo-runner -- tail -f /var/log/forgejo-runner-bootstrap.log
```

If the admin token is absent, `enable` warns and continues — the VM provisions
but the runner stays unregistered. Create the token and re-run `enable` to create
the runner.

## Reset to a clean baseline

A total rebuild — the workload user and disks are removed, then re-provisioned
from the base cloud image, which re-runs the host setup hook and creates the
runner afresh:

```sh
sudo workloadctl disable --purge forgejo-runner
sudo workloadctl enable        forgejo-runner
```

`workloadctl update` is **not** the reset verb: it rebuilds only the system disk
and does not re-run the host setup hook, so the seed would keep the previous
runner's credentials.

The previous registration leaves an offline runner row in Forgejo; the hook
prunes any runner with this name on the next provision.

## Idle cost

The VM is always-on and idle between builds. CPU is ~0; memory is reclaimed by
free-page-reporting on the balloon device (`[vm].balloon`, on by default), so an
idle guest settles near its working set rather than holding everything it has
ever touched. Only pages the guest has *freed* are reported, not clean page
cache.

## Caveats

- **Registration flow.** The runner is created server-side
  (`POST /api/v1/admin/actions/runners`) and its uuid+token declared as a
  `server.connections` entry in `config.yml` — the modern flow. Neither the
  deprecated `GET .../registration-token` endpoint nor the deprecated
  `forgejo-runner register` command is used. This requires **runner v13+** (pinned
  in `workload.toml`); older runners have no `server.connections`.
- **Image-signing key.** Not provisioned here. After (re-)provisioning, run the
  `seal-signing-key` workflow once to seal the key into host-key systemd
  credentials — they are bound to this VM's `/var/lib/systemd/credential.secret`,
  which a rebuild regenerates. Until then builds push unsigned with a warning.
  See `docs/ci-image-signing.md`.
- **Jobs run as root in the guest.** The `native:host` executor runs steps on
  the host OS as `root`, which is deliberate — the hypervisor's workflows assume
  `sudo podman`, `/run/credentials/` and privileged image builds. The VM is the
  isolation boundary; nothing inside it is unprivileged.
- **Egress is open.** A build host reaches arbitrary registries and mirrors, so
  there is no allowlist that both works and means anything. See
  `docs/workloads.md` on egress posture.
- **Reaching the forge from the VM — two shapes.**

  *Same-host (the homelab shape):* `FORGEJO_URL` empty. A passt guest cannot
  reach a service on its own host (the address it holds is the host's, and
  host loopback is deliberately unmapped), so the forge — a container on this
  same host — answers on this VM's own **derived address** (`198.18.x.y` from
  its uid, put on the shared dummy link at VM start and removed on stop).
  The seed composes the connection URL from `WORKLOADCTL_VM_INSPECT_ADDR` +
  `FORGEJO_PORT`, and `SAME_HOST_HOSTNAMES` lists the forge's `ROOT_URL` host
  (plus any other same-host service, e.g. a registry) — the guest's
  `/etc/hosts` maps each to the derived address. Set the forge's **`ROOT_URL`
  to that hostname** (not the host's primary address): Forgejo derives its
  action URLs (cache, artifact uploads) from `ROOT_URL`, and the guest
  cannot reach the primary, so a primary-based `ROOT_URL` makes those URLs
  fail with `ECONNREFUSED`. LAN clients resolve the same name to the host
  primary, so the web UI is unaffected.

  *Remote:* `FORGEJO_URL` set to a full URL. The forge is on another host;
  the guest dials that URL directly (a passt guest reaches other LAN hosts
  fine), no `/etc/hosts` mapping, and `ROOT_URL` is whatever that forge uses.
  Leave `SAME_HOST_HOSTNAMES` empty unless other same-host services need the
  mapping.
