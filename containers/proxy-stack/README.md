# Proxy Stack Container

Combined container running Squid, microsocks, Pi-hole, and WireGuard VPN.

| Service    | Port | Purpose                              |
|------------|------|--------------------------------------|
| Squid      | 3128 | HTTP/HTTPS caching proxy             |
| microsocks | 1080 | SOCKS5 proxy                         |
| Pi-hole    | 53   | DNS with ad/tracker blocking         |
| Pi-hole    | 80   | Web admin interface                  |

All traffic exits through the WireGuard tunnel. Pi-hole handles DNS for both
LAN clients and the proxy services themselves.

## Setup

1. **Build the container:**
   ```bash
   cd containers/proxy-stack
   sudo ./build.sh
   ```

2. **Copy your WireGuard config and squid.conf template:**
   ```bash
   sudo cp ~/Downloads/vpn.conf /var/lib/workloads/proxy-stack/wg0.conf
   podman run --rm localhost/proxy-stack:latest cat /usr/share/proxy-stack/squid.conf \
     | sudo tee /var/lib/workloads/proxy-stack/squid.conf
   ```

3. **Edit squid.conf** — at minimum adjust `acl localnet` to match your subnet.

4. **Enable:**
   ```bash
   sudo workload-ctl enable proxy-stack
   ```

5. **Open the firewall:**
   ```bash
   sudo firewall-cmd --add-service=dns --permanent
   sudo firewall-cmd --add-service=http --permanent
   sudo firewall-cmd --add-port=3128/tcp --permanent
   sudo firewall-cmd --add-port=1080/tcp --permanent
   sudo firewall-cmd --reload
   ```

6. **Download Pi-hole blocklists:**
   ```bash
   sudo workload-ctl exec proxy-stack pihole -g
   ```

## Using the Proxies

**HTTP proxy** (Squid):
```bash
export http_proxy=http://<host-ip>:3128
export https_proxy=http://<host-ip>:3128

# DNF
proxy=http://<host-ip>:3128  # in /etc/dnf/dnf.conf
```

**SOCKS5 proxy** (microsocks):
```bash
curl --socks5 <host-ip>:1080 https://ipinfo.io/ip
export https_proxy=socks5h://<host-ip>:1080
```

**DNS**: point clients to `<host-ip>`.

## Configuration

The VPN upstream DNS is read from `wg0.conf` automatically. Both proxies and
Pi-hole use it. To override:

```toml
[container.environment]
UPSTREAM_DNS = "10.5.0.1"
```

To set a Pi-hole web admin password:
```bash
echo -n "your-password" | sudo workload-ctl secret create proxy-stack-webpassword
```

## Troubleshooting

```bash
workload-ctl logs proxy-stack
workload-ctl status proxy-stack

# Verify VPN exit IP
curl --socks5 <host-ip>:1080 https://ipinfo.io/ip

# Check Squid config syntax
sudo workload-ctl exec proxy-stack squid -k parse
```
