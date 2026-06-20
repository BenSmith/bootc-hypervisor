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

For NVIDIA, switch `[devices]` in `jellyfin.toml` to `gpu = "nvidia"` and pick
NVENC in the UI instead.

## Media

By default jellyfin is a **fully independent workload**: the library is its
own directory, `/var/lib/workloads/jellyfin/media`, mounted read-only at
`/media` in the container.

For deployment you can point it elsewhere by editing the last `[storage]`
volume in `jellyfin.toml` — e.g. at the `smb-server` share
(`/var/lib/workloads/smb-server/exports/media`) so media can be added over
SMB. The workload user only needs read access to whatever path you choose.
