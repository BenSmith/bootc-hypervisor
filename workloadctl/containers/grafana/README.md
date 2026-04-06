# Grafana Container

Grafana dashboards and data visualization. Pairs with the `prometheus` workload
for system monitoring. Web interface at `http://<host-ip>:3000`.

## Setup

1. **Build the container:**
   ```bash
   cd containers/grafana
   sudo ./build.sh
   ```

2. **Enable once to create volume directories (will fail — that's expected):**
   ```bash
   sudo workloadctl enable grafana
   ```

3. **Copy the config template and edit:**
   ```bash
   sudo cp /usr/share/workloadctl/containers/grafana/grafana.ini \
           /var/lib/workloads/grafana/grafana.ini
   sudo nano /var/lib/workloads/grafana/grafana.ini
   ```

4. **Enable again:**
   ```bash
   sudo workloadctl enable grafana
   ```

5. **Open the firewall:**
   ```bash
   sudo firewall-cmd --add-port=3000/tcp --permanent
   sudo firewall-cmd --reload
   ```

## Default Credentials

- Username: `admin`
- Password: `admin` (change on first login)

To use an encrypted password instead:
```bash
echo -n "your-password" | sudo workloadctl secret create grafana-admin-password
```
Then set `GF_SECURITY_ADMIN_PASSWORD = "${SECRET:grafana-admin-password}"` in the workload config.

## Connecting to Prometheus

Both workloads use pasta networking (isolated namespaces), so Grafana cannot
reach Prometheus via `localhost`. Use the host's LAN IP instead:

```
Data source URL: http://<host-ip>:9090
```

## Troubleshooting

```bash
workloadctl logs grafana
workloadctl status grafana
```
