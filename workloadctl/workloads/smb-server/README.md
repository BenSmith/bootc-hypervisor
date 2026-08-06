# SMB Server Container

Samba guest-only file share running rootless. All file access runs as the
workload user — no per-client UID mapping. Suitable for shared storage on a
trusted LAN.

## Setup

1. **Build the container:**
   ```bash
   sudo workloadctl build smb-server
   ```

2. **Enable.** This creates the volume directories and seeds `smb.conf` from the
   shipped template (it is a `[setup].required_files` entry with an absolute
   hint, so `enable` copies it for you):
   ```bash
   sudo workloadctl enable smb-server
   ```

3. **Edit the config to set share paths and other settings, then apply:**
   ```bash
   sudo nano /var/lib/workloads/smb-server/data/smb.conf
   sudo workloadctl recreate smb-server
   ```

   Edit that copy, *not* an `/etc/workloads.d/smb-server/` override —
   `smb.conf` reaches the container through the `./smb.conf` volume, which
   resolves under `data/`. The copy-on-write override path
   (`workloadctl edit smb-server <file>`) only feeds control files that go
   through `resolve_control_file`: Containerfiles, `build.sh`, `[host].setup`,
   `policy.cil`. An override here would be silently ignored.

4. **Open the firewall:**
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

## Sharing a host path another workload writes

To export a tree that lives outside this workload — say a media library another
workload writes into — bind-mount the host path and join a group that both
workload users are in:

```toml
[storage]
volumes = [
    "./exports:/exports",
    "/var/mnt/downloads/complete:/downloads:ro",
    # … the rest unchanged
]

[security]
userns = "keep-id"
extra_groups = ["wl-downloads"]
```

Then add a stanza in `smb.conf` pointing at the container path. Keep the mount
*outside* `/exports`: that share is writable, and nesting the bind inside it
would expose the whole tree as writable through it.

```ini
[downloads]
    path = /downloads
    comment = Shared downloads (read-only)
    browseable = yes
    writable = no
    guest ok = yes
    force user = root
```

The group must exist on the host *before* enable — the generator resolves
`extra_groups` to GIDs when it writes the units — and the host directory needs
to be group-readable and traversable by it (2770 root:wl-downloads works).

`force user = root` is not a privilege grant: under `userns = "keep-id"` the
container's uid 0 is the unprivileged `_wl-smb-server` host user. It has to be
the container-side name, because smbd resolves it against the *container's*
passwd database — the host username has no entry there, and an unresolvable
name fails every tree connect with `NT_STATUS_NO_SUCH_USER`. `entrypoint.sh`
handles the matching group half; see the comment there.

## Port 445

The system image sets `net.ipv4.ip_unprivileged_port_start = 0`, so smbd can
bind to port 445 directly. If running on a system without that sysctl, use a
firewall redirect instead — see the comments in `workload.toml`.

## Troubleshooting

```bash
workloadctl logs smb-server
workloadctl status smb-server

# Test connection
smbclient //<host-ip>/exports -N -c ls
```
