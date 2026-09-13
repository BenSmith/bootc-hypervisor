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
The runner's only state is its registration, and a Forgejo registration token is
**one-shot** — so instead of persisting it, `setup.sh` mints a fresh one on every
provision and the cloud-init seed reads it from the credstore.

## Prerequisites

1. A running Forgejo instance you can reach from the VM.
2. A **Forgejo admin API token**. The host setup hook uses it to mint a
   registration token; it never enters the VM.

   ```sh
   sudo workloadctl secret create forgejo-admin-token
   ```

3. `FORGEJO_URL` in the instance TOML set to that forge.

## Provisioning

```sh
sudo workloadctl init forgejo-runner
sudo workloadctl edit forgejo-runner     # set [vm.cloud_init.template_vars].FORGEJO_URL
sudo workloadctl enable forgejo-runner
```

`enable` runs the host setup hook first, which mints a registration token and
seals it at `/etc/credstore.encrypted/forgejo-runner-token`; the seed is built
afterwards and carries it into the guest, which registers on first boot.

Watch first boot (cloud-init installs packages, fetches the runner binary, and
registers):

```sh
sudo workloadctl exec forgejo-runner -- tail -f /var/log/forgejo-runner-bootstrap.log
```

If the admin token is absent, `enable` warns and continues — the VM provisions
but the runner stays unregistered. Create the token and re-run `enable` to mint.

## Reset to a clean baseline

A total rebuild — the workload user and disks are removed, then re-provisioned
from the base cloud image, which re-runs the host setup hook and mints a fresh
token:

```sh
sudo workloadctl disable --purge forgejo-runner
sudo workloadctl enable        forgejo-runner
```

`workloadctl update` is **not** the reset verb: it rebuilds only the system disk
and does not re-run the host setup hook, so the seed would keep a consumed token.

The previous registration leaves an offline runner row in Forgejo; the hook
prunes any runner with this name on the next provision.

## Idle cost

The VM is always-on and idle between builds. CPU is ~0; memory is reclaimed by
free-page-reporting on the balloon device (`[vm].balloon`, on by default), so an
idle guest settles near its working set rather than holding everything it has
ever touched. Only pages the guest has *freed* are reported, not clean page
cache.

## Caveats

- **Deprecated registration endpoint.** `setup.sh` uses
  `GET /admin/actions/runners/registration-token`, which Forgejo 15 marks
  deprecated in favour of `POST /admin/actions/runners`. The modern endpoint
  registers the runner outright and returns its own token, which
  `forgejo-runner register` does not accept; revisit when the deprecated endpoint
  is removed.
- **Image-signing key.** Not provisioned here. After (re-)provisioning, run the
  `seal-signing-key` workflow once to seal the key into host-key systemd
  credentials — they are bound to this VM's `/var/lib/systemd/credential.secret`,
  which a rebuild regenerates. Until then builds push unsigned with a warning.
  See `docs/ci-image-signing.md`.
- **Egress is open.** A build host reaches arbitrary registries and mirrors, so
  there is no allowlist that both works and means anything. See
  `docs/workloads.md` on egress posture.
