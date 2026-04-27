# desktop-kdeplasma-rdp — development notes

## GPU / VAAPI / hardware encoding

### kpipewire encode path is VAAPI-only

Confirmed via `ldd` and `strings` on `krdpserver` and `libKPipeWire.so` (Fedora 43):
- kpipewire uses `H264VAAPIEncoder` — no GStreamer path, no NVENC path
- Software fallbacks: x264, then openh264
- GStreamer NVENC (`nvh264enc`) is present in plain Fedora (`gstreamer1-plugins-bad-free`) and
  works with CDI injection, but krdp never calls it

### GPU vendor support matrix

| Vendor | VAAPI encode for krdp | Package            | Source |
|--------|----------------------|--------------------|--------|
| AMD (GCN+) | Yes | `mesa-va-drivers` | plain Fedora |
| Intel Gen8–11 (iris/crocus) | Yes | `mesa-va-drivers`  | plain Fedora |
| Intel Gen12+ (iHD) | Yes | `intel-media-driver` | plain Fedora |
| NVIDIA (proprietary) | **No** | `libva-nvidia-driver` is decode-only | plain Fedora |
| NVIDIA (nouveau) | **No** | NVENC is not implemented in nouveau | — |

Both packages are installed in this image. NVIDIA users get x264/openh264 software encode;
this is the upstream ceiling — no workaround exists within krdp.

### Hardware OpenGL (KWin compositor, separate from encode)

`kwin-start` detects `/dev/dri/renderD*` at startup:
- Render node present → hardware GL (AMD radeonsi, Intel iris, NVIDIA via CDI)
- No render node → `LIBGL_ALWAYS_SOFTWARE=1` (llvmpipe fallback)

This is OpenGL for the compositor, independent of VAAPI for video encoding.

### For NVIDIA hardware-accelerated streaming

Use `sunshine-game-streaming` or `wolf-game-streaming` — those workloads use NVENC
directly and are not limited by krdp's VAAPI-only encode path.
