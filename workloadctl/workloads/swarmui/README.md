# swarmui

[SwarmUI](https://github.com/mcmonkeyprojects/SwarmUI) — a modular AI image
generation web UI, MIT licensed. It is a full suite, not a node editor: the
**Generate** tab is a normal prompt-and-go interface, the **Comfy Workflow** tab
drops you into the unrestricted node graph when you need it, and there is a model
browser, image history, and a Grid Generator on top.

ComfyUI is the engine underneath — SwarmUI downloads, configures, and supervises
it — so model support tracks ComfyUI while the UI stays usable.

This bundle is an **alternative to the `comfyui` bundle, not a companion**. Both
can run (7801 and 8188 do not clash) but each carries its own PyTorch, so running
both costs ~20 GB of disk for nothing. Pick one.

## Enable

```bash
sudo workloadctl build swarmui
sudo workloadctl enable swarmui
# then open http://<host-ip>:7801
```

To pin a specific release instead of the bundle default:

```bash
sudo workloadctl build swarmui --build-arg SWARMUI_VERSION=0.9.9-Beta
```

## First run — the backend install

**The image does not contain PyTorch.** Unlike the `comfyui` bundle, which bakes
a vendor-specific torch into the image at build time, SwarmUI installs its own
ComfyUI backend at *runtime*, into the `dlbackend` volume, on first setup. Budget
**~15 GB and 10–20 minutes**, and note it needs working egress.

On first load SwarmUI runs an install wizard. It asks which accelerator to
target — pick NVIDIA/CUDA — and then fetches ComfyUI, builds a venv, and pulls
torch and the CUDA userspace.

This is the one genuine advantage over the `comfyui` bundle: **vendor is a
runtime answer, not a build-time constant.** Moving this workload to an AMD host
needs no rebuild, just a different answer in the wizard.

Progress is only visible in the UI, so a cold start looks like a stalled
container from the outside. That is why `start_period` is 180s.

## Multi-GPU: one backend per card

This is the reason to prefer SwarmUI on this host, and it is *not* automatic —
you have to register the backends.

**Server → Backends → Add Backend → ComfyUI Self-Starting.** Add one per card,
incrementing `GPU_ID` each time (`0`, `1`, …). SwarmUI then routes and queues
generations across them.

The payoff on a multi-GPU host: each card holds a *different* model and both
stay busy, instead of one model being resident at a time. On cards in the ~16 GB
class, where most models want most of a card, that is the difference between a
model collection being usable and not.

If you must drive multiple GPUs from the Comfy Workflow tab directly, use
**MultiGPU → Use All** at the top left, which spreads queued requests across
backends.

The trade-off is stated in `workload.toml`: SwarmUI assumes it owns every card
it can see, so do not co-tenant it with a streaming desktop
(`wayfire-game-streaming`, `vncdesktop-sway`) without pinning `gpu` to a UUID
first.

## Models — where things go

SwarmUI seeds the tree on first start under `/var/lib/workloads/swarmui/data/models`.
The layout is not guessable, and putting a file in the wrong directory makes it
silently invisible rather than producing an error:

| Directory | Contents |
|---|---|
| `Stable-Diffusion/` | Full single-file checkpoints — SDXL, Pony, Illustrious, NoobAI |
| `diffusion_models/` | DiT/unet-only models incl. GGUF — Chroma, FLUX.2/klein, Z-Image, Krea 2, Qwen-Image |
| `clip/` | Text encoders — T5-XXL, the Qwen LLM encoders |
| `VAE/` | VAEs — the FLUX `ae`, Wan 2.1, Qwen-Image |
| `Lora/` | LoRAs |

**GGUF works with no setup.** SwarmUI autoinstalls the ComfyUI-GGUF node the
first time it sees a GGUF diffusion model, so quantised models can go straight
into `diffusion_models/`.

Most modern models autodownload their matching text encoder and VAE on first
use, so you do not have to supply those by hand unless you want a specific one —
which, see below, you do.

Staging note: `/home/desktop/models-staging` is on the same `hot-default` LV as
`/var/lib/workloads`, so moving models in is a rename, not a copy.

## Text encoders and uncensored models

Two independent layers decide whether a model will produce a given image, and
conflating them wastes a lot of time:

1. **Text-encoder refusal.** Models whose prompt encoder is an *aligned instruct
   LLM* can sanitise or decline a prompt before the diffusion model ever sees it.
   That covers Z-Image (Qwen3-4B), FLUX.2/klein (Qwen3-8B), Qwen-Image
   (Qwen2.5-VL-7B), and Krea 2 (Qwen3-VL-4B). This layer is **fixable** — drop an
   abliterated/heretic build of the same base into `clip/` and select it.
2. **Training data.** If the diffusion model never saw the content, no encoder
   swap conjures it. This layer is **not** fixable after the fact.

Models using a **pure text encoder have no layer 1 at all**: T5-XXL (Chroma,
FLUX.1) and CLIP (the SDXL family) are encoder-only, with no instruction tuning
and nothing to refuse with. Chroma is the standout here — Apache-2.0, explicitly
de-distilled and de-filtered from FLUX-schnell, and structurally incapable of
prompt refusal.

**Overriding an autodownloaded encoder:** the Generate tab's advanced parameters
expose a text-encoder selector for models that use a separate one, so a file
dropped in `clip/` should be selectable there. *This is the one thing in this
bundle not verified against a running instance.* If the selector does not appear
for a given architecture, the Comfy Workflow tab is a guaranteed fallback — build
the graph with an explicit `CLIPLoader` (or ComfyUI-GGUF's `CLIPLoader (GGUF)`
for a quantised encoder) and it will load whatever you point it at.

**Sharded encoders need a single file — but rarely a conversion.** Encoders
shipped in HuggingFace `transformers` layout — a `text_encoder/` directory of
`model-0000N-of-0000M.safetensors` plus an index, which is how BFL ships klein's
Qwen3-8B — are not loadable by `CLIPLoader`, which wants one file.

Merging the shards yourself is the last resort, not the first. Every encoder on
this roster is a stock LLM (Qwen3-4B, Qwen3-8B, Qwen2.5-VL-7B, Qwen3-VL-4B), and
a **plain single-file LLM GGUF of that same base loads directly** via
ComfyUI-GGUF's `CLIPLoader (GGUF)`. The extra tensors an LLM carries and a text
encoder does not — `lm_head`, the output norm — are ignored on load. So the
abliterated/heretic GGUF you would want for layer 1 anyway *is* the repack; you
do not need both.

Check before assuming a file is the wrong kind. A GGUF's header names its
architecture and shape, and that is what has to match:

```bash
pip install --user gguf   # header-only reader, no torch
# qwen3, 36 blocks, 4096 embedding  →  Qwen3-8B  →  klein's encoder
python3 -c 'import gguf,sys; r=gguf.GGUFReader(sys.argv[1]);
print({f.name: str(f.contents()) for f in r.fields.values()
       if "architecture" in f.name or "block_count" in f.name
       or "embedding_length" in f.name})' model.gguf
```

Qwen3-8B is 36 blocks × 4096; Qwen3-4B is 36 × 2560. A mismatch here is the
difference between "wrong file" and "wrong format", and they need different
fixes.

## Tuning

`SWARMUI_ARGS` in `[container.environment]` is appended to `launch-linux.sh`:

- `--loglevel debug` — verbose logging; the first thing to reach for when a
  backend install fails
- `--port <n>` — change the listen port (also update `[network].ports`)

Per-backend VRAM behaviour is set in the backend's own settings in the UI
(Server → Backends), not here — that is where ComfyUI's `--lowvram` /
`--highvram` equivalents live.

## Troubleshooting

**Container is up but 7801 does not answer.** Almost always the first-run data
setup or a backend install still in progress; both are silent from outside.
`workloadctl logs swarmui` shows the actual state.

**Backend install fails or hangs.** Check egress, then blow away just the backend
without losing settings or models:

```bash
sudo systemctl stop workload-swarmui
sudo rm -rf /var/lib/workloads/swarmui/data/dlbackend/*
sudo systemctl start workload-swarmui
```

**A model does not appear in the browser.** Wrong subdirectory — see the table
above — or it needs a refresh (the model browser has a reload button). SwarmUI
does not warn about files it does not recognise.

**Generations are mush.** Distilled and base models want very different
settings: distilled variants (`Turbo`, `Flash`, klein-9B) run few steps at
CFG ~1.0, base models want many steps and CFG 3–7. Community merges inherit
whichever parent they came from, and the filename is often the only clue.
Mismatched settings look exactly like a broken install.

**A third-party extension logs `No .NET SDKs were found` and does not load.**
Expected on the default image, and fixable by rebuilding — see "Extensions"
below. The server itself is unaffected: verified that it stays up and healthy
with the failed extension present, so this degrades rather than breaks.

Custom *ComfyUI* nodes are a different thing and always work — those are Python,
and `build-essential` plus `python3.11-dev` are deliberately kept in the runtime
stage so nodes with C extensions compile on first import.

## Extensions

SwarmUI's **built-in** extensions — Grid Generator, Dynamic Thresholding, the
ComfyUI backend — are compiled into the main build and work on every variant.
Nothing below applies to them.

**Third-party** extensions are different. Installing one from the UI only does a
`git clone` into `src/Extensions/`; SwarmUI then compiles it *itself* on the next
start (`ExtensionsManager.BuildExtension` shells out to `dotnet build` and
`Assembly.LoadFile`s the result). That needs the real .NET SDK, which the default
image does not ship — dropping it is part of why the image is 1.4 GB rather than
3.6 GB.

To get it back, rebuild with the SDK as the runtime base:

```bash
sudo workloadctl build swarmui \
  --build-arg RUNTIME_BASE=mcr.microsoft.com/dotnet/sdk:8.0-bookworm-slim
```

That lands at ~2.0 GB instead of 1.4 GB — the other two savings (the NuGet cache
and the unused runtime identifiers) are kept either way. Both variants are built
and tested; the flag is the only difference.

Two things to expect on the SDK variant:

- **The first build of each extension restores NuGet packages over the network**
  — a one-off minute or so. The result is cached in `src/bin/extensions/<name>/`
  and reused on later starts, so it is not a per-start cost.
- **Extensions can be version-incompatible and fail to compile.** This is normal
  and is not an image problem: `SwarmUI-FaceTools` against 0.9.8 dies with
  `error CS1061: 'WorkflowGenerator' does not contain a definition for
  'CurrentVae'`, because it targets a different SwarmUI API. Real compiler errors
  naming SwarmUI types mean the extension does not match this SwarmUI version;
  pin a matching release or update SwarmUI.

**Reading logs.** Units run `--log-driver=passthrough`, so `podman logs` fails.
Use `workloadctl logs swarmui`.
