# SMB Server Container

Samba guest-only file share running rootless. All file access runs as the
workload user — no per-client UID mapping. Suitable for shared storage on a
trusted LAN.

## Setup

1. **Build the container:**
   ```bash
   cd containers/smb-server
   sudo ./build.sh
   ```

2. **Enable once to create volume directories (will fail — that's expected):**
   ```bash
   sudo workloadctl enable smb-server
   ```

3. **Copy the config template and edit:**
   ```bash
   sudo cp /usr/share/workloadctl/workloads/smb-server/smb.conf \
           /var/lib/workloads/smb-server/smb.conf
   sudo nano /var/lib/workloads/smb-server/smb.conf
   ```

4. **Enable again:**
   ```bash
   sudo workloadctl enable smb-server
   ```

5. **Open the firewall:**
   ```bash
   sudo firewall-cmd --add-service=samba --permanent
   sudo firewall-cmd --reload
   ```

## Mounting from a Client

```bash
sudo mount -t cifs //<host-ip>/exports /mnt/share \
    -o guest,uid=$(id -u),gid=$(id -g),file_mode=0664,dir_mode=0775
```

The `uid`/`gid` options are required for non-root writes.

## Port 445

The system image sets `net.ipv4.ip_unprivileged_port_start = 0`, so smbd can
bind to port 445 directly. If running on a system without that sysctl, use a
firewall redirect instead — see the comments in `smb-server.toml`.

## Troubleshooting

```bash
workloadctl logs smb-server
workloadctl status smb-server

# Test connection
smbclient //<host-ip>/exports -N -c ls
```
