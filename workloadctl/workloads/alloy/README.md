# alloy

Per-host telemetry collector. Runs on every host and forwards metrics, logs,
and traces to the central otel-lgtm backend.

## Environment variables (set in workload TOML)

| Variable | Example | Purpose |
|----------|---------|---------|
| `CENTRAL_HOST` | `203.0.113.10` | otel-lgtm host. A LAN IP/hostname for a remote backend; `host.containers.internal` if otel-lgtm runs on this same host (see Networking). |
| `HOST_LABEL` | `gaming` | Short name for this machine |
| `ROLE_LABEL` | `gaming` | Role tag (gaming, nas, networking, thin-client) |

## What it collects

- **Metrics**: host CPU, memory, disk, network, filesystem (node_exporter)
  and per-workload systemd state + cgroup metrics (from the workload-exporter
  textfile drop, read by node_exporter's textfile collector)
- **Logs**: all systemd journal entries
- **Traces**: OTLP from workloadctl CLI and any other local apps that send to
  the local receiver on `4317` (gRPC) / `4318` (HTTP)

## Networking

alloy runs under **pasta** networking — its own network namespace. This is
deliberate: alloy's local OTLP receiver listens on `4317/4318`, the same ports
the otel-lgtm backend uses. With its own namespace those never collide, so
alloy and otel-lgtm can run on the same host. The receiver binds `0.0.0.0`
*inside the container* (a pasta-forwarded port can't reach a loopback bind);
host-facing exposure is governed solely by the `[network] ports` list in
`alloy.toml`, which publishes only on `127.0.0.1`.

Two per-host variants, both in `alloy.toml`:

- **Normal host (alloy only):** publish the receiver so local apps can reach it
  — `ports = ["127.0.0.1:4317:4317", "127.0.0.1:4318:4318"]`. This is the
  shipped default.
- **Host also running otel-lgtm:** do *not* publish those ports
  (`ports = []`) — otel-lgtm already owns `4317/4318` on the host, and local
  apps send OTLP straight to it. Also set `CENTRAL_HOST = "host.containers.internal"`,
  since under pasta `127.0.0.1` is the container's own loopback.

Host metrics still come from the bind-mounted `/host/proc` regardless of
namespace; the host (otel-lgtm, workload-exporter) is reached via
`host.containers.internal`.

## Enable

```bash
sudo workloadctl enable alloy
```

This pulls `docker.io/grafana/alloy:latest` and copies the sample
`alloy-config.alloy` from `/usr/share/workloadctl/workloads/alloy/` into
`/var/lib/workloads/alloy/`. Edit that file on the host to customize
collection, then `sudo workloadctl recreate alloy`.

## Notes

- **SELinux:** reading the host journal (`syslogd_var_run_t` / `var_log_t`) is
  denied to the stock container domain under SELinux enforcing, so without help
  `loki.source.journal` silently collects nothing. Instead of `label=disable`,
  `[security].selinux_policy = true` makes `enable` load a per-workload type
  from `alloy.cil` (a udica CIL block inheriting the base container domain), so
  alloy runs confined as its own `wl_alloy.process` with just journal read
  access — no other container is widened — and `disable` removes it. If the
  host-metrics collectors hit AVC denials, regenerate/extend `alloy.cil` with
  `udica` / `audit2allow -a` rather than disabling confinement.
- **Journal path:** `alloy-config.alloy` sets `loki.source.journal` `path` to
  `/var/log/journal` explicitly. sd_journal's default location keys off
  `/etc/machine-id`, which inside the container is the *container's* id — the
  reader would open an empty directory and read 0 lines with no error.
