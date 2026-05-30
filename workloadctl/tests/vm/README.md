# workloadctl test VM

A throwaway Fedora VM for **manual** end-to-end validation of workloadctl —
in particular multi-container pod and bridge modes, which the unit tests can
only cover at the generator/CLI level.

It is deliberately light: a plain Fedora Cloud image booted with raw QEMU
(user-mode networking, SSH on `localhost:2222`), provisioned by cloud-init.
No libvirt, no bootc image build. This is separate from the hypervisor
repo's `just test-vm`, which builds and boots the full bootc image.

## Requirements

`qemu-system-x86_64`, `qemu-img`, `cloud-localds` (Fedora: `qemu-system-x86-core
qemu-img cloud-utils genisoimage`), and access to `/dev/kvm`.

## Workflow

```sh
just vm-up        # boot (first run downloads ~600 MB Fedora cloud image)
just vm-deploy    # build the RPM, install it + the test workloads in the VM
just vm-ssh       # shell into the VM
just vm-down      # power off, drop the overlay (base image stays cached)
```

`vm-deploy` is re-runnable — rerun it after changing workloadctl to push a
fresh build. Runtime artifacts (cached image, overlay, SSH key, console log)
live in `tests/vm/run/`, which is gitignored.

## Manual validation checklist

Boot and deploy, then `just vm-ssh` and work through the following. The two
test workloads ship to `/etc/workloads.d/` as `podtest.toml` (pod mode) and
`bridgetest.toml` (bridge mode).

### Pod mode — shared network namespace

```sh
sudo workloadctl enable podtest
workloadctl status podtest          # umbrella + pod service + 2 containers
sudo podman pod ps                  # (run as _wl-podtest) pod workload-podtest

# containers share a netns -> the client reaches the server on localhost:
workloadctl exec podtest/client wget -qO- localhost:8080      # => POD-OK
# the pod publishes 8080 to the host:
curl -s localhost:8080                                        # => POD-OK
```

### Bridge mode — per-container netns, DNS by name

```sh
sudo workloadctl enable bridgetest
workloadctl status bridgetest       # umbrella + net service + 2 containers

# each container has its own netns; the client resolves the server by
# its short name over the auto-created bridge network:
workloadctl exec bridgetest/client wget -qO- http://server:8080     # => BRIDGE-OK
curl -s localhost:8081                                              # => BRIDGE-OK
```

### Lifecycle

```sh
workloadctl logs podtest                 # merged logs from all sub-services
workloadctl logs podtest/server          # one container
workloadctl update podtest               # pulls each image, restarts umbrella
sudo systemctl stop workload-podtest.service     # PartOf -> containers stop
sudo systemctl start workload-podtest.service
sudo workloadctl disable podtest --purge         # tears everything down
sudo workloadctl disable bridgetest --purge
```

## Cleanup

`just vm-down` powers the VM off and removes the overlay. The base cloud
image stays cached in `tests/vm/run/`; delete that directory to reclaim the
~600 MB.
