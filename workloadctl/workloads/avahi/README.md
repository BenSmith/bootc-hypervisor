# Avahi Container

mDNS publisher for service-name aliases. Publishes `<name>.local` A records
pointing at this host's LAN IP so other devices on the LAN can resolve them
without any central DNS. Designed to pair with the `caddy` workload.

## How it works

The container runs three layers wired together by the entrypoint:

```
dbus-daemon  ───►  avahi-daemon  ───►  N x avahi-publish -a -R
```

`avahi-publish -a -R <name>.local <host-ip>` is run once per alias and stays
running to keep its record registered. The `-R` (`--no-reverse`) is
load-bearing: without it, every alias would try to claim the reverse PTR
record for the same IP (`<reversed-ip>.in-addr.arpa`), and avahi's
mDNS tiebreaking lets only the lexicographically smallest name survive.
With `-R` each alias publishes a bare A record and they all coexist.

`/etc/avahi/hosts` is *not* used — that mechanism has the same PTR-collision
limitation and can only publish one alias per IP.

## Setup

Only one mDNS responder per host can bind UDP 5353, so we have to make
avahi-in-the-container that responder. That means turning off both the
host's avahi-daemon and systemd-resolved's mDNS on the publishing host.

1. **Build the container:**
   ```bash
   sudo workloadctl build avahi
   ```

2. **Mask any host-side avahi-daemon:**
   ```bash
   sudo systemctl disable --now avahi-daemon.socket avahi-daemon.service 2>/dev/null || true
   sudo systemctl mask avahi-daemon.socket avahi-daemon.service
   ```

3. **Turn off systemd-resolved's mDNS on the publisher host.** Resolved binds
   5353 globally whenever any link has mDNS enabled (even in `resolve` mode),
   which trips avahi's "another mDNS stack" detection and causes spurious
   `Local name collision` errors against avahi's own records. On a host that
   *publishes*, resolved must be fully off mDNS:
   ```bash
   # (copy /usr/lib/systemd/resolved.conf to /etc/systemd/resolved.conf first if needed)
   sudo sed -i 's/^#*MulticastDNS=.*/MulticastDNS=no/' /etc/systemd/resolved.conf
   sudo systemctl restart systemd-resolved
   ```
   Note: this means containers running on the *publisher* host can no longer
   resolve `.local` names via the host stub resolver. If a co-tenant container
   needs `.local` resolution, ship `nss-mdns` inside *that* container.

4. **Edit `ALIASES`** in `/etc/workloads.d/avahi/workload.toml`, then:
   ```bash
   sudo workloadctl enable avahi
   ```

5. **Open the firewall** (UDP 5353):
   ```bash
   sudo firewall-cmd --add-service=mdns --permanent
   sudo firewall-cmd --reload
   ```

## Setup on a *resolver* host

This is any other LAN host that wants to resolve the names published by `tp`.
Two options, in order of recommendation:

**Option A — `nss-mdns` (recommended).** Plugs into glibc NSS, works for
every program on the host, doesn't bind UDP 5353, doesn't fight with anything:
```bash
sudo dnf install -y nss-mdns                                          # or: apt install libnss-mdns
# verify /etc/nsswitch.conf has mdns4_minimal BEFORE dns on the hosts: line
grep ^hosts /etc/nsswitch.conf
# expected: hosts: files mdns4_minimal [NOTFOUND=return] dns ...
getent hosts zot.local                                                # smoke test
```

**Option B — systemd-resolved in `resolve` mode.** Only if you don't want
`nss-mdns`. Resolved will bind 5353 too, but as a resolver-only it doesn't
announce records, so it won't conflict with the publisher's avahi *across
the LAN* — but it would conflict on the same host. Don't use this on the
publisher.
```bash
sudo sed -i 's/^#*MulticastDNS=.*/MulticastDNS=resolve/' /etc/systemd/resolved.conf
sudo systemctl restart systemd-resolved
resolvectl query zot.local
```

## Verifying

On the publisher (`tp`), the host CLI tools (`avahi-resolve`, `resolvectl
query .local`) **won't work** — `avahi-resolve` needs a daemon socket on the
host's `/run/avahi-daemon`, and we deliberately turned off resolved's mDNS.
What you *can* check:

```bash
sudo ss -ulnpH 'sport = :5353'                          # only avahi-daemon should appear
sudo -u _wl-avahi podman logs workload-avahi --tail 50  # look for: "Established under name <X>"
```

A clean log has no `Local name collision` and no "Detected another mDNS
stack" warnings.

End-to-end resolution test from another LAN host:

```bash
ping zot.local
getent hosts zot.local
avahi-browse -art | grep zot                            # if avahi installed
```

## Troubleshooting

### Only one alias publishes, the rest fail with `Local name collision`

Symptom in `podman logs workload-avahi`:

```
Static host name zoop.local: avahi_server_add_address failure: Local name collision
Static host name poop.local: avahi_server_add_address failure: Local name collision
Static host name "noop.local" successfully established.
```

…where the one that survives is the alphabetically smallest. Cause: aliases
were published via `/etc/avahi/hosts` or via `avahi-publish -a` *without* `-R`.
All N aliases probe the same reverse PTR slot and only one can win the
tiebreak. Fix: use `avahi-publish -a -R <name>.local <ip>` per alias (this is
what the current entrypoint does — check it hasn't been edited).

### Avahi prints "Detected another IPv4/IPv6 mDNS stack" warnings

Something else on the publishing host is bound to UDP 5353. Find it:

```bash
sudo ss -ulnpH 'sport = :5353'
```

Common culprits:
- `systemd-resolve` — set `MulticastDNS=no` (step 3 above). The per-link
  setting alone (`resolvectl mdns <link> no`) does **not** free the socket;
  resolved keeps a global 5353 socket open as long as any link is configured
  for mDNS. The global `MulticastDNS=no` in `/etc/systemd/resolved.conf` is
  the only setting that actually closes it.
- Host-side `avahi-daemon` — step 2 above (mask the host service).

### Resolution works from `tp`'s LAN neighbors but not from `tp` itself

Expected. We turned off `tp`'s mDNS resolver path so avahi could own 5353
without conflict. Programs on `tp` that need to resolve `.local` either
install `nss-mdns` *on `tp`* (it doesn't bind 5353, so it coexists with
the container avahi just fine — it's a pure NSS module) or use a different
mechanism.

### Names don't resolve from other LAN hosts

- **Firewall on the publisher?**
  ```bash
  sudo firewall-cmd --list-services                     # expect 'mdns'
  ```
- **Different broadcast domain?** mDNS does not cross routers. Verify the
  remote host is on the same subnet, or set up an mDNS reflector on your
  router (OpenWrt/UniFi/pfSense all support this).
- **Remote host has no mDNS resolver?** See "Setup on a resolver host"
  above — install `nss-mdns` or enable `MulticastDNS=resolve` in resolved.
- **Wifi access point dropping multicast?** Many consumer APs rate-limit or
  drop multicast frames. `tcpdump -ni <iface> -l udp port 5353` from the
  remote host while you ping should show queries going out; if the
  publisher's reply isn't coming back, suspect the AP.

### Wrong IP published

The entrypoint detects the host IP via `ip route get 1.1.1.1`. On hosts with
multiple interfaces (VPN, secondary NIC, bridge) the default route may point
at the wrong one. Override it in the toml:

```toml
[container.environment]
HOST_IP = "203.0.113.50"
ALIASES = "zot registry"
```

The entrypoint logs the parsed alias list and the chosen IP at startup —
check the first few lines of `podman logs workload-avahi`.

### Container restarts in a loop

The entrypoint shuts the whole process tree down if *any* subprocess
(`dbus-daemon`, `avahi-daemon`, or any of the `avahi-publish` instances)
exits. Systemd then restarts the unit. To find which subprocess is dying,
look at the very end of `podman logs workload-avahi` from the last run —
the failing component prints its error before the entrypoint's
`a subprocess exited unexpectedly` line.

## Why host networking

mDNS uses LAN multicast on UDP 5353. Pasta's isolated network namespace
cannot receive multicast from the host's LAN, so `network.mode = "host"` is
a hard requirement for any mDNS responder.

## Why `userns = "keep-id:uid=0,gid=0"`

The container needs to:
- write to `/run` (avahi-daemon's runtime dir, dbus-daemon's socket dir)
- `setuid` into the `avahi` user (UID 70) and the `messagebus` user (UID 81)
  so the daemons drop privileges per their respective D-Bus policies

Both require being "root" inside the container's user namespace. Mapping the
workload user to UID 0 inside the userns gives us that without giving the
container any privilege on the host — the in-container "root" is still just
the rootless `_wl-avahi` workload user from the outside.
