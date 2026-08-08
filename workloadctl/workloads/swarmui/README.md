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

## Version

`SWARMUI_VERSION` defaults to the newest *tag*, and is passed to
`git clone --branch`, so it accepts a tag or a branch name (not a commit SHA).

There is **no `--build-arg` flag** on `workloadctl build`. Build args are TOML
only: `[build] arg_env` (this bundle lists `SWARMUI_VERSION` and `RUNTIME_BASE`)
forwards a host env var, and `[build] args` stores a durable default. So a
one-off build of a different ref is:

```bash
sudo env SWARMUI_VERSION=master workloadctl build swarmui
```

`sudo env VAR=...`, not `sudo VAR=...` — the bare form needs the sudoers
`setenv` permission. To pin a ref durably, put it on the deployed instance in
`/etc/workloads.d/<instance>/workload.toml` (`args = { SWARMUI_VERSION = "master" }`),
not in the bundle.

**Upstream tags infrequently — the gap between the newest tag and `master` runs
to hundreds of commits and many months.** SwarmUI's in-app update check compares
tags, so it reports you are up to date throughout.

That gap matters because architecture support is what moves in it. A model
SwarmUI has no entry for is not merely unlisted — the Generate tab cannot pair
its text encoder or VAE, cannot apply its prompt template, and cannot set its
sampler defaults, so it is unusable there even when the ComfyUI backend
underneath supports it fully. Before concluding a model file is wrong, compare
the running build against `master`:

```bash
workloadctl exec swarmui -- git -C /SwarmUI log -1 --format='%h %ci'
git ls-remote https://github.com/mcmonkeyprojects/SwarmUI HEAD
```

The bundle default stays a tag because CI rebuilds this image weekly and a
moving branch is not reproducible. Pass `master` when you need what is on it.

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

## Sharing cards with other GPU workloads

Running SwarmUI on a machine that is also driving a display is the normal case.
The caveat is contention, not exclusivity, and it scales with what the neighbour
actually holds: an idle compositor (`vncdesktop-sway`) is a few hundred MB and
co-tenants fine, while a streaming desktop with a game running
(`sunshine-streaming`, `wolf-game-streaming`) can take 8–14 GB and will not fit
alongside a diffusion graph on a 16 GB card.

SwarmUI competes harder than a hand-driven ComfyUI because it queues onto every
registered backend at once. Even so, the symptom is usually a slow or failed
generation rather than a broken host — ComfyUI adapts to the VRAM it finds, and
the offload dial is per-backend under **Server → Backends** (see [Tuning](#tuning)).

What makes a server different from a workstation is whose job dies. On your own
desktop a shortfall fails the generation you started; on a host serving desktop
sessions the compositor can be what loses its allocation instead. If that
matters, reserve a card:

```toml
gpu = "nvidia:GPU-<uuid>"     # nvidia-ctk cdi list
```

## Models — where things go

SwarmUI seeds the tree on first start under `/var/lib/workloads/swarmui/data/models`.
The layout is not guessable, and putting a file in the wrong directory makes it
silently invisible rather than producing an error:

| Directory | Contents |
|---|---|
| `Stable-Diffusion/` | Full single-file checkpoints — SDXL, Pony, Illustrious, NoobAI |
| `diffusion_models/` | DiT/unet-only models incl. GGUF — Chroma, FLUX.2/klein, Z-Image, Krea 2, Qwen-Image |
| `text_encoders/` | Text encoders — T5-XXL, the Qwen LLM encoders |
| `clip/` | Legacy name for the same thing; still scanned. Prefer `text_encoders/` |
| `VAE/` | VAEs — the FLUX `ae`, Wan 2.1, Qwen-Image |
| `Lora/` | LoRAs |

**`text_encoders/` vs `clip/`.** Both are seeded and both are scanned, so this is
easy to get wrong in a way that still works — until it does not. `text_encoders/`
is the current name and is where SwarmUI's own autodownloader writes: requesting
Z-Image on a fresh instance pulled its Qwen3-4B encoder to `text_encoders/`, not
`clip/`. Put new encoders there. `clip/` is the older name, kept for the CLIP-L/G
encoders of the SDXL era and for backwards compatibility.

**GGUF works with no setup.** SwarmUI autoinstalls the ComfyUI-GGUF node the
first time it sees a GGUF diffusion model, so quantised models can go straight
into `diffusion_models/`.

Most modern models autodownload their matching text encoder and VAE on first
use, so you do not have to supply those by hand unless you want a specific one —
which, see below, you do.

Staging note: `/home/desktop/models-staging` is on the same `hot-default` LV as
`/var/lib/workloads`, so moving models in is a rename, not a copy.

## Text encoders

Component models keep the text encoder in its own file, and SwarmUI autodownloads
a known-good one per architecture (SHA-verified). To use a different build,
enable **Advanced Model Addons → Qwen Model** in the Generate tab — it is an
advanced, toggleable parameter of subtype `Clip`, so it lists everything in
`text_encoders/` and `clip/`. The selection wins outright: the workflow generator
checks the parameter before its own built-in default, so nothing silently falls
back. Each family has its own parameter (`Qwen Model`, `Mistral Model`,
`Gemma Model`); pick the one matching the architecture.

**Some encoders must carry the vision tower — a text-only build will not do.**
This is the trap worth knowing about, because it fails late and the error blames
the wrong thing. Krea 2 does not condition on the encoder's final hidden state;
it takes a **12-layer tap across a Qwen3-VL stack**, 12 × 2560 = 30720 features.
ComfyUI decides a file is a Qwen3-VL by looking for a *vision* tensor:

```
comfy/sd.py   if "model.visual.deepstack_merger_list.0.norm.weight" in sd:
                  return TEModel.QWEN3VL_4B if <merger>.shape[0] == 2560 else QWEN3VL_8B
```

Miss that key and detection falls through to plain Qwen3, the multi-layer branch
never runs, and you get a single hidden state — 2560 features — and a hard
failure at generation time:

```
ValueError: Krea2 expects conditioning with 12x2560=30720 features
(a 12-layer Qwen3-VL stack) but got 2560.
```

The message says to use `CLIPLoader` type `krea2`, which is misleading: the type
is already correct, and the file is what is wrong.

**So GGUF is not usable for these.** A `.gguf` export from llama.cpp carries the
text tower only — vision weights go to a separate `mmproj` file that
`CLIPLoader (GGUF)` has no way to consume. The GGUF will be accepted, will load,
and will produce 2560 features. This does not apply to encoders whose
conditioning is a plain hidden state (T5-XXL, the CLIP family, plain Qwen3), where
a single-file LLM GGUF of the same base loads fine via ComfyUI-GGUF and surplus
tensors like `lm_head` are ignored. The rule is about what the file **lacks**,
not what it carries.

Note that SwarmUI picks the loader purely on the extension — `LoadClip` swaps
`CLIPLoader` for `CLIPLoaderGGUF` on a `.gguf` name — so there is no warning at
selection time.

**One file, not a shard set.** `CLIPLoader` takes a single file, so an encoder
shipped in HuggingFace `transformers` layout (`model-0000N-of-0000M.safetensors`
plus an index) has to be merged first. For a vision-carrying encoder that merge
is the *normal* path, not a last resort — it is the only format that works.

The merge is a plain concatenation; no renaming is needed. ComfyUI remaps the
transformers prefixes itself when it loads:

```python
state_dict_prefix_replace(sd, {"model.language_model.": "model.",
                               "model.visual.": "visual.",
                               "lm_head.": "model.lm_head."})
```

```python
# merge shards -> one file (run with a python that has safetensors + torch)
from safetensors.torch import load_file, save_file
sd = {}
for f in ("model-00001-of-00002.safetensors", "model-00002-of-00002.safetensors"):
    sd.update(load_file(f))
save_file(sd, "encoder-merged.safetensors")
```

Tied embeddings are the usual failure here — if a repo stores `lm_head` as a view
of `embed_tokens`, `save_file` refuses to write aliased storage. Check the index
for an `lm_head` entry first; when it is absent (the common case, because it is
tied and therefore omitted) the merge is clean.

Avoid quantisations whose scale tensors are not ComfyUI's. ComfyUI's own
`fp8_scaled` files carry `weight_scale`; a vLLM/compressed-tensors FP8 build
carries `weight_scale_inv` and will not load correctly despite being the same
architecture and size. Plain bf16 is the safe choice when in doubt.

**Verify a file before blaming the config.** A GGUF header names its architecture
and shape:

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
fixes. For safetensors, read the header keys directly — the presence or absence
of `model.visual.*` tensors is the whole answer for a VL encoder, and a GGUF that
reports architecture `qwen3vl` can still have none of them.

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
sudo env RUNTIME_BASE=mcr.microsoft.com/dotnet/sdk:8.0-bookworm-slim \
  workloadctl build swarmui
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
