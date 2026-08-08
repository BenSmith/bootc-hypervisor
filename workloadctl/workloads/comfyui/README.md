# comfyui

Node-based AI image/video/audio generation. Powers Stable Diffusion, SDXL, Flux
and Wan Video via a graph editor, with a REST API alongside the web UI on
port 8188.

Self-built bundle: the `Containerfile` ships here and CI publishes the result as
`registry.local/workloads/comfyui:latest`.

## Enable

```bash
sudo workloadctl build comfyui      # only if you are not consuming the CI image
sudo workloadctl enable comfyui
```

Then open `http://<host-ip>:8188`. The UI loads an empty graph — load a workflow
JSON with the Load button, or POST one to `http://<host-ip>:8188/api/prompt`.
See https://docs.comfy.org for the API reference.

## Choosing a GPU vendor

There is no cross-vendor image. **The vendor is fixed at build time** by the
PyTorch wheel index; `[devices] gpu = "auto"` in the TOML then passes whatever
devices the host actually has. This mirrors how `oobabooga` handles the same
problem (it selects via image tag rather than build arg).

| Build | Vendor | Image size |
|-------|--------|------------|
| `sudo workloadctl build comfyui` | NVIDIA (cu128, default) | 9.23 GB |
| `sudo env CUDA_INDEX=rocm7.1 workloadctl build comfyui` | AMD | 16.2 GB |
| `sudo env CUDA_INDEX=cpu workloadctl build comfyui` | CPU only | smaller |

`workloadctl build` has **no `--build-arg` flag**. Build args are TOML only:
`[build] arg_env` forwards a host env var to `podman build` when it is set, and
this bundle lists `CUDA_INDEX` plus the three torch pins and `COMFYUI_VERSION`.
Use `sudo env VAR=...`, not `sudo VAR=...` — the bare form needs the sudoers
`setenv` permission.

No CUDA/ROCm base image is involved — the wheels vendor the GPU userspace, and
the host driver arrives via CDI. That is why a plain `fedora:44` base works.

Only indexes carrying the pinned torch triple as **cp314** wheels can be swapped
in as a one-liner (F44's `python3` is 3.14). Verified working: `cu128`,
`rocm7.1`, `rocm7.2`, `cpu`. Verified *not* working: `rocm6.2` (no cp314 wheels
at all), `rocm6.4` and `rocm7.0` (cap at torch 2.9.1), `xpu` (no torch 2.11.0).
Those need the version pins moved too, not just the index — which is why
`TORCH_VERSION`, `TORCHVISION_VERSION`, and `TORCHAUDIO_VERSION` are in
`arg_env` alongside `CUDA_INDEX`, so it stays one invocation:

```bash
sudo env CUDA_INDEX=rocm7.0 TORCH_VERSION=2.9.1 \
  TORCHVISION_VERSION=0.24.1 TORCHAUDIO_VERSION=2.9.1 \
  workloadctl build comfyui
```

The Containerfile has a one-liner for re-checking any index/version pair before
committing to a build; the versions above are illustrative, not verified.

### Vendor mismatch does not fail loudly

`gpu = "auto"` emits a CDI guard **only** on NVIDIA hosts. Everywhere else there
is no start-time check, so a CUDA image on a non-NVIDIA host starts normally and
generates on CPU — orders of magnitude slower, with nothing in the unit state to
say so. Confirm which device was picked:

```bash
workloadctl logs comfyui | head -20
```

### ROCm: check your card is supported first

ROCm's matrix is narrow — roughly gfx906/908/90a/942 plus the RDNA
gfx103x/11xx/12xx parts. **An unsupported AMD GPU does not degrade to CPU.**

Measured on a gfx902 Picasso APU with `torch 2.11.0+rocm7.1`: torch reported
`is_available: True`, `device_count: 1` and `AMD Radeon Vega 10 Graphics`, then
**SIGSEGV'd (exit 139) on the first kernel launch**. `HSA_OVERRIDE_GFX_VERSION`
of `9.0.0` and `9.0.2` did not help (HSA `Memory critical error` / silent crash).
CPU inference inside the same ROCm image was fine.

In a workload that is a crash *loop*, not a slow start: ComfyUI places the model
on the ROCm device and dies on first inference, and `Restart=on-failure` retries
until `StartLimitBurst` gives up. If your card is unsupported, force CPU rather
than hoping — append `--cpu` to `COMFYUI_ARGS`.

### Pin the card on a shared or multi-GPU host

On NVIDIA, `auto` expands to `nvidia.com/gpu=all` — *every* card, not one. So
ComfyUI will load a model onto a GPU another workload is already using. This is
the common failure on a host where a streaming desktop and a diffusion workload
co-tenant — which is why `sunshine-streaming` pins by UUID. 16 GB does not
stretch between a streaming desktop and an SDXL or Flux graph.

```toml
gpu = "nvidia:GPU-<uuid>"     # nvidia-ctk cdi list
```

ComfyUI does not inherit Sunshine's *nondeterminism* here — torch takes device 0
predictably — so the symptom is contention (VRAM exhaustion, thrashing) rather
than a randomly chosen card.

Separately, on a hybrid box (Intel iGPU + discrete card) `auto` resolves by the
first card in sysfs order and can land on the iGPU, leaving ComfyUI quietly on
CPU. The generator logs a warning whenever it sees more than one candidate.

## Models

Everything lives under `/var/lib/workloads/comfyui/data/`:

| Path | Mounted at | Holds |
|------|-----------|-------|
| `data/models` | `/comfyui/models` | checkpoints, LoRAs, VAE, ControlNet |
| `data/output` | `/comfyui/output` | generated images/video |
| `data/custom_nodes` | `/comfyui/custom_nodes` | community nodes |
| `data/input` | `/comfyui/input` | drag-and-dropped source files |
| `data/user` | `/comfyui/user` | workflow history, UI preferences |

The entrypoint seeds `models/`, `custom_nodes/`, `input/` and `user/` from a
pristine copy taken at build time, so the subdirectory tree (and the stock
`models/configs/*.yaml`, needed to load `.ckpt` checkpoints) exists before you
add anything. Seeding uses `cp -a -n`, so it never overwrites your files and is
a no-op once populated.

```bash
sudo cp ~/Downloads/sdxl.safetensors /var/lib/workloads/comfyui/data/models/checkpoints/
sudo workloadctl recreate comfyui     # pick up newly mounted files
```

If seeding is ever denied, the entrypoint says so on stderr and starts anyway.
The usual cause is an SELinux label: the volume needs `container_file_t`, which
`workload-ensure-user` applies to `/var/lib/workloads` via `semanage fcontext` +
`restorecon`. Bind mounts from anywhere else need a `:z` suffix.

## Custom nodes

```bash
sudo workloadctl exec comfyui -- \
  git clone https://github.com/.../custom-node.git /comfyui/custom_nodes/
sudo workloadctl recreate comfyui
```

`gcc`, `gcc-c++` and `python3-devel` are kept in the image precisely because
many custom nodes compile C extensions on first import.

## Tuning

`COMFYUI_ARGS` in `[container.environment]` is word-split and passed to
`main.py`. Useful additions:

| Flag | Effect |
|------|--------|
| `--highvram` | keep everything in VRAM (faster, more VRAM) |
| `--normalvram` | balance model + workflow (default) |
| `--lowvram` | minimise VRAM use (for <6 GB cards) |
| `--force-fp16` | force fp16 |
| `--cpu` | ignore any GPU |

`[resources]` sets `memory_swap_max = "0"` (a diffusion model that starts paging
thrashes the host far longer than an OOM kill costs) and `shm_size = "1g"`.
Uncomment `memory_max` to bound it — roughly 16G for SDXL, 32G for Flux.

## Troubleshooting

Units run `--log-driver=passthrough`, so `podman logs` will not work. Use:

```bash
workloadctl logs comfyui             # add -f to tail
journalctl -t workload-comfyui-comfyui
```

The healthcheck probes `/api/object_info`, which returns 200 with no models
loaded. `on_failure = "kill"` means a failing probe kills the container and
systemd restarts it, so a probe that can never pass shows up as a restart loop.
