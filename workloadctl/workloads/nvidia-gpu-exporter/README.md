# nvidia-gpu-exporter

Prometheus GPU metrics for **NVIDIA** cards, for the central otel-lgtm/Grafana
backend. Runs [`utkuozdemir/nvidia_gpu_exporter`][exp]: it shells out to
`nvidia-smi` and serves every field at `:9835/metrics`.

Enable it only on hosts that have NVIDIA GPUs.

## Why this exists (NVIDIA vs AMD)

GPU telemetry splits by kernel driver:

- **AMD (`amdgpu`)** publishes GPU state as standard sysfs
  (`/sys/class/drm/card*/device/gpu_busy_percent`, `mem_info_vram_*`) plus
  hwmon. node_exporter's built-in `drm`/`hwmon` collectors read it directly,
  and alloy already runs node_exporter over the host tree. So AMD needs **no
  workload** — just `"drm"` in alloy's `set_collectors` (already added to the
  shipped `alloy-config.alloy`).
- **NVIDIA (proprietary driver)** exposes nothing via sysfs; state is only
  reachable through NVML / `nvidia-smi`. node_exporter and alloy have no NVML
  component, so a helper has to call it. This workload is that helper, kept in
  its own confined workload user with `nvidia-smi` injected via CDI — rather
  than dragging GPU devices + driver userspace into the fleet-wide alloy agent.

## Image / signature policy

Pulled from **Docker Hub** (`docker.io/utkuozdemir/nvidia_gpu_exporter`), which
the host `policy.json` allows (`insecureAcceptAnything`). Third-party
`ghcr.io/...` would be default-rejected (`Source image rejected by policy`);
Docker Hub sidesteps that, so a normal `pull = "newer"` works.

## Enable

```bash
sudo workloadctl enable nvidia-gpu-exporter
# Under pasta the published port answers on the host's LAN address, not on the
# host's own loopback — a localhost probe gets connection refused while the
# exporter is healthy.
curl -s "$(hostname -I | awk '{print $1}'):9835/metrics" | grep nvidia_smi_utilization
```

Then wire alloy to scrape it — uncomment the `nvidia_gpu_exporter`
`prometheus.scrape` block in
`/var/lib/workloads/alloy/data/alloy-config.alloy` and:

```bash
sudo workloadctl recreate alloy
```

Metrics arrive at otel-lgtm tagged with this host's `host_name`/`host_role`
(added by alloy's transform). Point a Grafana panel at e.g.
`nvidia_smi_utilization_gpu_ratio`, `nvidia_smi_memory_used_bytes`,
`nvidia_smi_temperature_gpu`, `nvidia_smi_power_draw_watts`.

## Notes

- **GPU access:** `[devices] gpu = "nvidia"` →
  `--device=nvidia.com/gpu=all --device /dev/dri`. All cards are visible; the
  exporter reports one series set per GPU (labelled by index/UUID/name).
- **SELinux:** follows the same confined GPU-container pattern as the other
  NVIDIA workloads (`container_t` + the CDI hook). If enforcing throws AVCs on
  `nvidia-smi`, generate a per-workload CIL with `udica` and set
  `[security].selinux_policy = true` (see the alloy README for the pattern).
- **Exposure:** `:9835` is published on all host interfaces so alloy can reach
  it via `host.containers.internal`. Bind it to a specific interface or
  firewall the port if the host faces an untrusted network.

[exp]: https://github.com/utkuozdemir/nvidia_gpu_exporter
