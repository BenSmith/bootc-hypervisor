#!/usr/bin/env bash
# Throwaway Fedora VM for manual workloadctl validation.
#
# Plain Fedora Cloud image + cloud-init + raw QEMU (user-mode networking,
# SSH forwarded to localhost:2222). No libvirt, no daemon, no root needed
# for the VM itself. Runtime artifacts live in tests/vm/run/ (gitignored);
# the base cloud image is cached there across down/up.
#
#   vm.sh up       boot the VM (downloads the base image on first run)
#   vm.sh deploy   build the workloadctl RPM, install it + test workloads
#   vm.sh ssh ...  ssh into the VM (optionally run a command)
#   vm.sh console  tail the serial console log
#   vm.sh status   is the VM running?
#   vm.sh down     power off, drop the overlay (keeps the cached base image)
set -euo pipefail

VMDIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="$(cd "$VMDIR/../.." && pwd)"
RUN="$VMDIR/run"

FEDORA_VER=44
IMG="Fedora-Cloud-Base-Generic-${FEDORA_VER}-1.7.x86_64.qcow2"
IMG_URL="https://download.fedoraproject.org/pub/fedora/linux/releases/${FEDORA_VER}/Cloud/x86_64/images/${IMG}"

BASE="$RUN/$IMG"
OVERLAY="$RUN/overlay.qcow2"
SEED="$RUN/seed.img"
KEY="$RUN/id_vm"
PIDFILE="$RUN/vm.pid"
CONSOLE="$RUN/console.log"
SSH_PORT=2222
SSH=(ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null
     -o LogLevel=ERROR -o ConnectTimeout=5 -i "$KEY" -p "$SSH_PORT")
SCP=(scp -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null
     -o LogLevel=ERROR -i "$KEY" -P "$SSH_PORT")

die() { echo "error: $*" >&2; exit 1; }

running() { [ -f "$PIDFILE" ] && kill -0 "$(cat "$PIDFILE")" 2>/dev/null; }

cmd_up() {
  [ -e /dev/kvm ] || die "no /dev/kvm — KVM is unavailable"
  if running; then echo "VM already running (pid $(cat "$PIDFILE"))."; return 0; fi
  mkdir -p "$RUN"

  if [ ! -f "$BASE" ]; then
    echo "Downloading $IMG (~600 MB, cached for future runs)..."
    curl -fL --progress-bar -o "$BASE.part" "$IMG_URL"
    mv "$BASE.part" "$BASE"
  fi

  [ -f "$KEY" ] || ssh-keygen -q -t ed25519 -N '' -f "$KEY" -C workloadctl-testvm

  local ud; ud="$(mktemp)"
  sed "s|__SSH_PUBKEY__|$(cat "$KEY.pub")|" "$VMDIR/seed/user-data" > "$ud"
  cloud-localds "$SEED" "$ud" "$VMDIR/seed/meta-data"
  rm -f "$ud"

  rm -f "$OVERLAY"
  qemu-img create -q -f qcow2 -F qcow2 -b "$BASE" "$OVERLAY" 20G

  echo "Booting VM..."
  qemu-system-x86_64 \
    -name workloadctl-testvm \
    -machine q35 -accel kvm -cpu host \
    -m 2048 -smp 2 \
    -drive file="$OVERLAY",if=virtio,format=qcow2 \
    -drive file="$SEED",if=virtio,format=raw \
    -netdev user,id=net0,hostfwd=tcp::${SSH_PORT}-:22 \
    -device virtio-net-pci,netdev=net0 \
    -display none -serial file:"$CONSOLE" \
    -pidfile "$PIDFILE" -daemonize

  echo -n "Waiting for SSH (cloud-init first boot)"
  local i
  for i in $(seq 1 80); do
    if "${SSH[@]}" ben@localhost true 2>/dev/null; then
      echo " ready."
      echo "  next: just vm-deploy   (build + install workloadctl)"
      return 0
    fi
    echo -n "."; sleep 3
  done
  echo
  die "VM did not answer SSH — inspect $CONSOLE"
}

cmd_deploy() {
  running || die "VM is not running — run: just vm-up"
  echo "Building workloadctl RPM..."
  ( cd "$REPO" && just rpm-build >/dev/null )
  local rpm; rpm="$(ls -t "$REPO"/rpmbuild/RPMS/noarch/workloadctl-*.rpm 2>/dev/null | head -1)"
  [ -n "$rpm" ] || die "no RPM found under rpmbuild/RPMS/noarch/"

  echo "Copying $(basename "$rpm") and test workloads into the VM..."
  "${SCP[@]}" "$rpm" ben@localhost:/tmp/workloadctl.rpm >/dev/null
  "${SCP[@]}" "$VMDIR"/multi/*.toml ben@localhost:/tmp/ >/dev/null

  echo "Installing (dnf pulls podman + SELinux tools via RPM Requires)..."
  "${SSH[@]}" ben@localhost '
    set -e
    sudo dnf install -y /tmp/workloadctl.rpm passt crun >/dev/null
    sudo cp /tmp/podtest.toml /tmp/bridgetest.toml /etc/workloads.d/
    echo "  installed: $(rpm -q workloadctl)"
    echo "  test workloads in /etc/workloads.d/: podtest.toml bridgetest.toml"
  '
}

cmd_ssh() { running || die "VM is not running"; "${SSH[@]}" ben@localhost "$@"; }

cmd_console() { [ -f "$CONSOLE" ] || die "no console log yet"; tail -f "$CONSOLE"; }

cmd_status() {
  if running; then echo "running (pid $(cat "$PIDFILE")) — ssh localhost:$SSH_PORT";
  else echo "not running"; fi
}

cmd_down() {
  if running; then kill "$(cat "$PIDFILE")" 2>/dev/null || true; fi
  rm -f "$PIDFILE" "$OVERLAY" "$SEED" "$CONSOLE"
  echo "VM down. Base image kept at $BASE (delete tests/vm/run/ to reclaim space)."
}

case "${1:-}" in
  up)      cmd_up ;;
  deploy)  cmd_deploy ;;
  ssh)     shift; cmd_ssh "$@" ;;
  console) cmd_console ;;
  status)  cmd_status ;;
  down)    cmd_down ;;
  *) echo "usage: vm.sh {up|deploy|ssh|console|status|down}" >&2; exit 1 ;;
esac
