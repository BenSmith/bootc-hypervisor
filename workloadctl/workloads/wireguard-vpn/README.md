# WireGuard VPN Container

Runs a WireGuard VPN tunnel inside the container's own network namespace.
Host traffic is unaffected — only this container's traffic exits via VPN.

## Setup

1. **Build the container:**
   ```bash
   sudo workloadctl build wireguard-vpn
   ```

2. **Copy your WireGuard config:**
   ```bash
   sudo cp ~/Downloads/vpn.conf /var/lib/workloads/wireguard-vpn/data/wg0.conf
   ```

3. **Enable:**
   ```bash
   sudo workloadctl enable wireguard-vpn
   ```

4. **Verify connection:**
   ```bash
   workloadctl status wireguard-vpn
   workloadctl logs wireguard-vpn

   # Check public IP (should show VPN server IP)
   sudo workloadctl exec wireguard-vpn curl https://ipinfo.io/ip
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
workloadctl logs wireguard-vpn

# Verify WireGuard is up inside the container
sudo workloadctl exec wireguard-vpn wg show
```
