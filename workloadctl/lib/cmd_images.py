"""
cmd_images — the image inventory across every enabled workload, and the
`images prune` sweep of each workload user's own rootless store.
"""

import json
import pwd
from typing import Any

from workload_lib import USERNAME_PREFIX
from podman import Podman
from workloadctl_core import (
    WorkloadManager,
    created_unix,
    format_created,
    format_size,
    require_root,
)


# ---------------------------------------------------------------------------
# cmd_images
# ---------------------------------------------------------------------------

def cmd_images(args, manager: WorkloadManager):
    """Show images used by workloads or prune unused images"""
    if args.subcommand == "prune":
        require_root()
        print("Pruning unused images from all workloads...")
        print()

        pruned = False
        for entry in pwd.getpwall():
            if entry.pw_name.startswith(USERNAME_PREFIX):
                print(f"Pruning images for {entry.pw_name}...")
                try:
                    # Authoritative $HOME from passwd (the state/ subdir), matching
                    # what the workload service and exporter use. Do NOT reconstruct
                    # WORKLOADS_BASE/<name> — that's the root, one level above the
                    # real podman graphroot, so the prune would hit an empty store.
                    home = entry.pw_dir
                    result = Podman.for_user(
                        entry.pw_name, entry.pw_uid, home
                    ).run("image", "prune", "-f", capture_output=True)
                    if result.returncode == 0 and result.stdout.strip():
                        pruned = True
                except Exception:
                    continue

        if pruned:
            print()
            print("✓ Image pruning complete")
        else:
            print("No images to prune")
    else:
        # List images
        configs = manager.get_all_configs()
        images_data: list[dict[str, Any]] = []

        for config in configs:
            if not manager.user_exists(config):
                continue
            # VM workloads have no OCI images — container_specs() returns the
            # qcow2 download URL as the "image", which would blow up
            # `podman inspect --type=image` ("invalid reference format") and
            # abort the whole listing. Skip them.
            if config.is_vm:
                continue

            podman = manager.podman(config)
            # Iterate every container's image so multi-container (pod/bridge)
            # workloads list each image instead of crashing on the absent
            # top-level [container] block.
            for cname, image, _pull in config.container_specs():
                info = podman.image_info(image)
                if info:
                    size_bytes = info.get("Size") or 0
                    images_data.append({
                        "workload": config.name,
                        "container": cname,
                        "image": image,
                        "size_bytes": size_bytes,
                        "created": created_unix(info.get("Created"))
                    })

        if args.json:
            print(json.dumps({"images": images_data, "total": len(images_data)}, indent=2))
            return

        # Human-readable output
        print(f"{'WORKLOAD':<20} {'CONTAINER':<16} {'IMAGE':<50} {'SIZE':<10} {'PULLED':<15}")
        print("-" * 112)

        for img in images_data:
            image = img["image"]
            if len(image) > 50:
                image = image[:47] + "..."
            size_str = format_size(img["size_bytes"]) if img["size_bytes"] else "unknown"
            pulled_str = format_created(img["created"])
            print(f"{img['workload']:<20} {img['container']:<16} {image:<50} {size_str:<10} {pulled_str:<15}")

        print()
        if len(images_data) == 0:
            print("No workload images found")
        else:
            print(f"Total: {len(images_data)} workload image(s)")
