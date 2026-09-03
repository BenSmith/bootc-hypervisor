# Pi-hole VPN Container

Pi-hole ad blocker with upstream DNS routed through a WireGuard VPN tunnel.
All DNS queries from LAN clients are filtered by Pi-hole, then forwarded to
the VPN provider's DNS server over the encrypted tunnel.

## Setup

1. **Build the container:**
   ```bash
   sudo workloadctl build pihole-vpn
   ```

2. **Copy your WireGuard config and enable:**
   ```bash
   sudo cp ~/Downloads/vpn.conf /var/lib/workloads/pihole-vpn/data/wg0.conf
   sudo workloadctl enable pihole-vpn
   ```

3. **Open the firewall:**
   ```bash
   sudo firewall-cmd --add-service=dns --permanent
   sudo firewall-cmd --add-service=http --permanent
   sudo firewall-cmd --reload
   ```

4. **Download blocklists:**
   ```bash
   sudo workloadctl exec pihole-vpn pihole -g
   ```

5. **Point devices to `<host-ip>` as their DNS server.**

Web interface: `http://<host-ip>/admin`

## Configuration

The VPN upstream DNS is read from the `DNS =` line in `wg0.conf` automatically.
To override it:

```toml
# In /etc/workloads.d/pihole-vpn/workload.toml
[container.environment]
UPSTREAM_DNS = "10.5.0.1"
```

To set an admin password:
```bash
echo -n "your-password" | sudo workloadctl secret create pihole-vpn-webpassword
```
Then set `WEBPASSWORD = "${SECRET:pihole-vpn-webpassword}"` in the workload config.

## Troubleshooting

```bash
workloadctl logs pihole-vpn
workloadctl status pihole-vpn

# Check public IP used for DNS (should show VPN server)
sudo workloadctl exec pihole-vpn curl https://ipinfo.io/ip
```
