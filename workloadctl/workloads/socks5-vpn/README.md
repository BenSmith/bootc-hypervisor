# VPN SOCKS5 Proxy Container

SOCKS5 proxy (microsocks) tunneled through WireGuard VPN. All proxy traffic
exits via the VPN. Binds to `127.0.0.1:1080` by default — local use only.

## Setup

1. **Build the container:**
   ```bash
   cd containers/socks5-vpn
   sudo ./build.sh
   ```

2. **Copy your WireGuard config and enable:**
   ```bash
   sudo cp ~/Downloads/vpn.conf /var/lib/workloads/socks5-vpn/wg0.conf
   sudo workloadctl enable socks5-vpn
   ```

## Usage

```bash
# Test — should show the VPN server's IP
curl --socks5 127.0.0.1:1080 https://ipinfo.io/ip

# Use with environment variable
export https_proxy=socks5h://127.0.0.1:1080

# Use with curl
curl --socks5-hostname 127.0.0.1:1080 https://example.com
```

`socks5h` (hostname mode) sends hostnames through the proxy for remote
resolution rather than resolving locally — preferred for privacy.

## Exposing to the Network

To allow other LAN devices to use the proxy, change the port binding in
`workloads.d/socks5-vpn.toml`:

```toml
[network]
ports = ["1080:1080"]  # binds to all interfaces instead of 127.0.0.1
```

Then open the firewall:
```bash
sudo firewall-cmd --add-port=1080/tcp --permanent
sudo firewall-cmd --reload
```

## Troubleshooting

```bash
workloadctl logs socks5-vpn
workloadctl status socks5-vpn
```
