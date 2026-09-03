# jellyfin

Free Software media server with hardware-accelerated video transcoding.

Unlike most workloads under `workloads/`, this one **builds no image** — it
runs the upstream `docker.io/jellyfin/jellyfin` image directly. This directory
exists only to ship the host setup script.

## Files

- `setup.sh` — host prerequisite script run by `workloadctl enable/disable`.
  Turns on the `container_use_devices` SELinux boolean so the container can
  open the GPU render node `/dev/dri/renderD128`.

## Hardware transcoding

The workload passes `/dev/dri/renderD128` into the container and adds the
`render` group. In the Jellyfin dashboard set:

- Hardware acceleration: **VAAPI**
- VA-API device: **/dev/dri/renderD128**

Works with AMD (`amdgpu`) and Intel (`i915`) GPUs. AMD Navi 10 / RX 5000-series
supports H.264 and HEVC encode/decode but not AV1 encode.

For NVIDIA, switch `[devices]` in `workload.toml` to `gpu = "nvidia"` and pick
NVENC in the UI instead.

## Media

By default jellyfin is a **fully independent workload**: the library is its
own directory, `/var/lib/workloads/jellyfin/data/media`, mounted read-only at
`/media` in the container.

For deployment you can point it elsewhere by editing the last `[storage]`
volume in `workload.toml` — but use an absolute host path outside every
workload's own tree, e.g. `/var/mnt/media:/media:ro`.

Do **not** point it inside another workload's directory (the `smb-server`
exports, say). `/var/lib/workloads/<name>/data` is chowned to that workload's
user and chmod `0700` on every service start, so `_wl-jellyfin` cannot
traverse into it however permissive the leaf directory is, and a hand-applied
`chmod` is undone at the next start.

To share one tree with another workload — so media can be added over SMB, for
instance — the admin creates the path and a group both workload users join;
`workload-ensure-user` creates and chowns nothing outside
`/var/lib/workloads/<name>`. See the `[storage]` comments in `workload.toml`
for the exact commands.
