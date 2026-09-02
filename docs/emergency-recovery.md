# Emergency Recovery Guide

## Boot Frozen or Unresponsive

If the system freezes during boot and you cannot get a login prompt:

### 1. Boot to Emergency Mode

Add to kernel command line (press `e` at GRUB):
```
systemd.unit=emergency.target
```

Or:
```
systemd.unit=rescue.target
```

### 2. Bypass Problematic Workloads

If a workload is causing boot issues, boot to emergency mode and:

A workload is a *directory* under `/etc/workloads.d/`, and what the generator
reads is the `workload.toml` inside it. Masking is the reversible option — the
bundle stays on disk and the workload comes back when you remove the symlink.

```bash
# Mask it (same semantics as systemd masking; workloadctl reports it as masked)
ln -sf /dev/null /etc/workloads.d/problematic-workload/workload.toml

# Or remove the bundle outright
rm -r /etc/workloads.d/problematic-workload

# Reboot normally
reboot
```

Neither needs a `systemctl disable`: workload units live in `/run` and are
regenerated from the configs at every boot, so a config the generator no longer
sees produces no unit.

### 3. SELinux Issues

If SELinux is blocking boot:

```bash
# Boot permissive (add to kernel cmdline). Prefer this over selinux=0, which
# disables SELinux outright and leaves the filesystem needing a relabel.
enforcing=0

# Or after booting to emergency mode
setenforce 0
```

### 4. Generator Debug Mode

View generator logs after boot:
The tag to grep is `workload-generate` — the Python step that writes the units.
`workload-generator` is only the shell systemd generator that emits the oneshot
running it, so grepping for that name matches nothing.

```bash
# Check kernel messages for generator output (the early lines go via /dev/kmsg)
journalctl -b -k -g workload-generate

# Or the oneshot's own unit
journalctl -b -u workload-generate.service
```

### 5. Complete Workload System Bypass

To bypass the workload system entirely:

`/usr` is read-only on a bootc host, so the generator cannot simply be renamed.
Mask the unit it emits instead — from the kernel command line, which needs no
writable filesystem at all:

```
systemd.mask=workload-generate.service
```

With that oneshot masked, no workload units are written and nothing workload-
related starts. To make it persist across reboots, once you have a shell:

```bash
sudo systemctl mask workload-generate.service   # /etc is writable
sudo systemctl unmask workload-generate.service # undo
```

## Prevention

The system is designed to be resilient:

- **Generator always exits 0**: Even catastrophic generator failures won't block boot
- **Workloads use `Wants` not `Requires`**: Individual workload failures don't block multi-user.target
- **Emergency target is minimal**: Can always boot to emergency shell

## External Boot Media Recovery

If unable to boot at all:

1. Boot from USB/external media
2. Mount the root filesystem:
   ```bash
   # Find the root partition (usually btrfs with 'root' subvolume)
   lsblk -f

   # Mount it
   mount -o subvol=root /dev/sdXN /mnt

   # Chroot or directly edit files
   nano /mnt/etc/workloads.d/problematic/workload.toml
   ```

3. Reboot and try again

## Reporting Issues

If you encounter boot-blocking issues despite these safeguards, please report with:

- Full `dmesg` output
- `journalctl -b` output
- Contents of `/etc/workloads.d/` (`ls -R`, since each workload is a directory)
- SELinux AVCs: `ausearch -m avc -ts recent`
