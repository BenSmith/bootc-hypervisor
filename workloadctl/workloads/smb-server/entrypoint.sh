#!/bin/bash
set -euo pipefail

mkdir -p /var/lib/samba/private /var/lib/samba/lock

# Make the workload's [security].extra_groups usable by smbd.
#
# Under userns=keep-id the container's uid 0 IS the unprivileged _wl-smb-server
# host user, and podman's --group-add=keep-groups hands this process the host
# user's supplementary GIDs — so the *inherited* credentials can already read a
# shared tree like /var/mnt/downloads (mode 2770, group wl-downloads).
#
# smbd does not use the inherited credentials. `force user` rebuilds the session
# token from scratch via getpwnam + getgrouplist against the CONTAINER's
# passwd/group database, which knows nothing of the host's groups — so every
# forced session lands with gid 0 only and gets EACCES on the shared tree.
#
# Synthesize an entry per inherited GID with root as a member, so a forced
# session gets exactly the access the host user has. The GIDs are host-allocated
# and differ per host, so this has to happen at runtime; it cannot be baked into
# the image. Nothing is granted that the host user did not already hold.
for gid in $(id -G); do
    [[ $gid -eq 0 ]] && continue
    if entry=$(getent group "$gid"); then
        # GID already named in the image (a Fedora system group). Add root to it
        # rather than shadowing it with a second entry for the same GID.
        name=${entry%%:*}
        members=${entry##*:}
        [[ ",$members," == *,root,* ]] && continue
        sed -i "s|^${name}:\(.*\):.*$|${name}:\1:${members:+$members,}root|" /etc/group
    else
        printf 'wlgrp%s:x:%s:root\n' "$gid" "$gid" >> /etc/group
    fi
done

exec smbd --foreground --no-process-group
