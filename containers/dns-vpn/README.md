# DNS-over-VPN Proxy Container

Runs dnsmasq in the container's own network namespace. All DNS queries are
forwarded to the upstream DNS server specified in `wg0.conf` over the WireGuard
tunnel. LAN clients can use this host as their DNS resolver.

## Setup

1. **Build the container:**
   ```bash
   cd containers/dns-vpn
   sudo ./build.sh
   ```

2. **Copy your WireGuard config and enable:**
   ```bash
   sudo cp ~/Downloads/vpn.conf /var/lib/workloads/dns-vpn/wg0.conf
   sudo workload-ctl enable dns-vpn
   ```

3. **Open the firewall for LAN DNS access:**
   ```bash
   sudo firewall-cmd --add-service=dns --permanent
   sudo firewall-cmd --reload
   ```

4. **Test:**
   ```bash
   dig @<host-ip> example.com
   ```

## Configuration

The upstream DNS server is read automatically from the `DNS =` line in
`wg0.conf`. To override it:

```toml
# In workloads.d/dns-vpn.toml
[container.environment]
UPSTREAM_DNS = "10.5.0.1"
```

## Pointing Clients at This DNS Server

**systemd-resolved** (other Linux hosts):
```bash
resolvectl dns <interface> <host-ip>
```

**Static DNS** on routers/devices: set DNS server to `<host-ip>`.

## Troubleshooting

```bash
# Check logs
workload-ctl logs dns-vpn

# Verify DNS is resolving through VPN
dig @<host-ip> whoami.cloudflare.com TXT
```
