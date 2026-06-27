# Squid Caching Proxy Container

HTTP/HTTPS caching proxy optimized for package management and container images.

## What's Included

- **Squid proxy** - Caching HTTP/HTTPS proxy
- **Repository support** - Pre-configured for Fedora, Docker Hub, GitHub, Quay.io
- **10GB cache** - Caches packages and container layers
- **systemd** - Manages squid service

## Building

```bash
sudo workloadctl build squid
```

Or manually:
```bash
podman build -t localhost/squid:latest .
```

## Initial Setup

1. **Build the container** (see above)

2. **Create directories and copy config:**
   ```bash
   sudo mkdir -p /var/lib/workloads/squid/{cache,logs}
   sudo cp squid.conf /var/lib/workloads/squid/
   sudo chown -R _wl-squid:_wl-squid /var/lib/workloads/squid
   ```

   Note: Using workload username ensures correct ownership regardless of UID

3. **Customize configuration** (optional):
   ```bash
   sudo vi /var/lib/workloads/squid/squid.conf
   ```

   Adjust:
   - `acl localnet` entries to match your network
   - `cache_dir` size (default: 10GB)
   - `cache_mem` (default: 256MB)
   - Add more repository ACLs as needed

4. **Enable the workload:**
   ```bash
   sudo vi /etc/workloads.d/squid/workload.toml  # Set enabled = true
   sudo systemctl daemon-reload
   sudo systemctl start workload-squid.service
   ```

5. **Verify it's running:**
   ```bash
   curl -x http://localhost:3128 http://example.com
   ```

## Usage

### Configure Clients

**Environment variables:**
```bash
export HTTP_PROXY=http://<host>:3128
export HTTPS_PROXY=http://<host>:3128
```

**DNF configuration** (`/etc/dnf/dnf.conf`):
```ini
proxy=http://<host>:3128
```

**Podman build** (automatic with environment variables):
```bash
http_proxy=http://box:3128 https_proxy=http://box:3128 \
podman build -t myimage .
```

**Container registries** (`~/.config/containers/registries.conf`):
```toml
# Note: Squid currently configured for CONNECT to specific repos only
# Add more ACLs to squid.conf if needed
```

### Check Cache Status

**View logs:**
```bash
sudo tail -f /var/lib/workloads/squid/logs/access.log
sudo tail -f /var/lib/workloads/squid/logs/cache.log
```

**Cache statistics:**
```bash
sudo -u _wl-squid podman exec squid squidclient mgr:info
```

**Cache size:**
```bash
sudo du -sh /var/lib/workloads/squid/cache
```

## Firewall Configuration

If clients can't access the proxy from the network:

```bash
sudo firewall-cmd --add-port=3128/tcp --permanent
sudo firewall-cmd --reload
```

## Configuration

The default configuration includes:

### Allowed HTTPS Domains
- Fedora repositories (*.fedoraproject.org)
- Docker Hub (*.docker.io, *.docker.com)
- GitHub (*.github.com, *.githubusercontent.com)
- Quay.io (*.quay.io)

### Cache Settings
- **Disk cache:** 10GB in `/var/spool/squid`
- **Memory cache:** 256MB
- **Max object size:** 512MB (good for container layers)
- **Package caching:** RPMs, DEBs, etc. cached for 90 days

### Network ACLs
- Local networks: 192.168.0.0/16, 10.0.0.0/8, 172.16.0.0/12
- Adjust `acl localnet` entries to match your network

## Adding More Repositories

To allow HTTPS access to additional domains, edit `squid.conf`:

```squid
# Add new ACL
acl custom_repos ssl::server_name .example.com

# Allow CONNECT to it
http_access allow CONNECT custom_repos
```

Then restart:
```bash
sudo systemctl restart workload-squid.service
```

## Monitoring

**Service status:**
```bash
systemctl status workload-squid.service
```

**Watch access log:**
```bash
sudo tail -f /var/lib/workloads/squid/logs/access.log
```

**Cache hits vs misses:**
```bash
sudo grep -E "TCP_(HIT|MISS)" /var/lib/workloads/squid/logs/access.log | \
  awk '{print $4}' | sort | uniq -c
```

## Troubleshooting

**403 Forbidden for HTTPS:**
- Check that the domain is in the allowed ACLs
- Add domain to `acl *_repos ssl::server_name` entries
- Add corresponding `http_access allow CONNECT` rule

**Cache not working:**
- Check disk space: `df -h /var/lib/workloads/squid/cache`
- Verify permissions: `ls -la /var/lib/workloads/squid/cache` (should be owned by _wl-squid)
- Check cache log: `sudo tail /var/lib/workloads/squid/logs/cache.log`

**Service won't start:**
- Check configuration syntax: `sudo -u _wl-squid podman exec squid squid -k parse`
- Review logs: `sudo journalctl -u workload-squid.service`

## Performance Tuning

For heavy usage, adjust in `squid.conf`:

```squid
# Increase memory cache
cache_mem 512 MB

# Increase disk cache (in MB)
cache_dir ufs /var/spool/squid 20480 16 256

# More aggressive caching
refresh_pattern -i \.(rpm|deb)$ 259200 100% 259200
```

## Security Notes

This configuration:
- ✅ Allows local networks only
- ✅ Restricts HTTPS CONNECT to specific domains
- ✅ Denies unsafe ports
- ❌ No authentication (trusted network only)
- ❌ No HTTPS interception/SSL bumping

For production or untrusted networks, add authentication or use firewall rules to restrict access.
