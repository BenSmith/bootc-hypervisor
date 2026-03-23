# WireGuard VPN Container

Runs a WireGuard VPN tunnel inside the container's own network namespace.
Host traffic is unaffected — only this container's traffic exits via VPN.

## Setup

1. **Build the container:**
   ```bash
   cd containers/wireguard-vpn
   sudo ./build.sh
   ```

2. **Copy your WireGuard config:**
   ```bash
   sudo cp ~/Downloads/vpn.conf /var/lib/workloads/wireguard-vpn/wg0.conf
   ```

3. **Enable:**
   ```bash
   sudo workload-ctl enable wireguard-vpn
   ```

4. **Verify connection:**
   ```bash
   workload-ctl status wireguard-vpn
   workload-ctl logs wireguard-vpn

   # Check public IP (should show VPN server IP)
   sudo -u _wl-wireguard-vpn podman exec workload-wireguard-vpn curl https://ipinfo.io/ip
   ```

## WireGuard Config Format

Your `wg0.conf` should be a standard WireGuard client config:

```ini
[Interface]
PrivateKey = YOUR_PRIVATE_KEY
Address = 10.5.0.2/16
DNS = 10.5.0.1

[Peer]
PublicKey = SERVER_PUBLIC_KEY
AllowedIPs = 0.0.0.0/0, ::/0
Endpoint = SERVER_IP:51820
PersistentKeepalive = 25
```

Local network traffic (RFC 1918: 192.168.0.0/16, 10.0.0.0/8, 172.16.0.0/12) is
automatically excluded from the VPN so the container can still reach the LAN.

## Troubleshooting

```bash
# Check logs
workload-ctl logs wireguard-vpn

# Verify WireGuard is up inside the container
sudo -u _wl-wireguard-vpn podman exec workload-wireguard-vpn wg show
```
