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

```bash
# Disable the problematic workload
rm /etc/workloads.d/problematic-workload.toml

# Or mask it (like systemd masking)
ln -sf /dev/null /etc/workloads.d/problematic-workload.toml

# Reboot normally
reboot
```

### 3. SELinux Issues

If SELinux is blocking boot:

```bash
# Temporarily set permissive mode (add to kernel cmdline)
selinux=0

# Or after booting to emergency mode
setenforce 0
```

### 4. Generator Debug Mode

View generator logs after boot:
```bash
# Check kernel messages for generator output
dmesg | grep workload-generator

# Or check journal
journalctl -b | grep workload-generator
```

### 5. Complete Workload System Bypass

To bypass the workload system entirely:

```bash
# Boot to emergency mode
# Disable the generator
mv /usr/lib/systemd/system-generators/workload-generator{,.disabled}

# Reboot
reboot
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
   nano /mnt/etc/workloads.d/problematic.toml
   ```

3. Reboot and try again

## Reporting Issues

If you encounter boot-blocking issues despite these safeguards, please report with:

- Full `dmesg` output
- `journalctl -b` output
- Contents of `/etc/workloads.d/`
- SELinux AVCs: `ausearch -m avc -ts recent`
