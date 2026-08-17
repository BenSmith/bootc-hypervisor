# Sharing a host directory into a VM

`generate_virtiofs_service` in `generators/workload-generate`, plus the
`wlvfsd_t` domain in `security/workload-vm.cil` — what a share costs, why the
daemon serving it holds no privileges, what confines it instead, and the three
ways to break it.

A `[vm].volumes` entry becomes one `virtiofsd` sidecar service per volume,
started before the VM and stopped with it. The guest mounts it over virtiofs;
cloud-init does that on first boot. What follows is the part that is not obvious
from the schema.

---

## 1. Every file in a share belongs to the workload user

The sidecar maps the guest's primary user (uid 1000, the cloud-init default) to
the workload's host user *bidirectionally*, so that user reads its own files
back as itself. Every other guest id — root included — is squashed one-way onto
the same host user.

So a guest that creates a file as root, or `chown`s one to root, gets a file
owned by `_wl-<name>` on the host. Inside the guest it reads back as the default
user rather than as root.

| | guest sees | host sees |
|---|---|---|
| file created by the default user | that user | `_wl-<name>` |
| file created by guest root | the default user | `_wl-<name>` |
| file `chown`ed to any other uid | the default user | `_wl-<name>` |

**Why.** Passing guest ids through is the obvious reading of "share a directory
faithfully", and it means the guest chooses the owner and mode of files on the
host filesystem. Measured on a live VM with passthrough: a guest planting a
setuid-root binary in its share produced `-rwsr-xr-x root root` on the host. The
share sits in a 0700 workload-owned directory and nothing on the host execs from
it, so it was not directly exploitable — but `backup` collects `data/`, so the
bit travels in the archive to wherever it is restored, and anything that ever
runs as `_wl-<name>` and execs from the tree gets root. Squashing removes the
primitive instead of relying on those two facts staying true.

**What it costs.** A multi-user guest does not see per-user ownership inside the
share, on the host *or* in the guest — squash is one-way, so the reverse lookup
finds only the `map` entry and every squashed file reads back as the default
user. These are single-user appliance VMs. A workload that genuinely needs
multi-user ownership wants a **data disk**: a block device the guest formats and
owns outright, with no host-side identity to translate.

**One id is not covered, and only §2 makes that safe.** `--translate-*` ranges
are half-open and built with `checked_add`, so a range reaching 2³² fails to
parse; 4294967295 is therefore left identity-mapped, and virtiofsd identity-maps
anything unmapped rather than refusing it. Unprivileged it lands with everything
else — at euid 0 it would not.

---

## 2. The daemon has no privileges, because the map leaves it nobody to be

virtiofsd serves each request under the *calling guest user's* uid and gid: it
`setresuid`/`setresgid`s per request. That is what would demand
`CAP_SETUID`/`CAP_SETGID`, plus `fowner`/`fsetid` to carry a file's mode across
the switch.

The id map means it never happens. Every guest id translates to the one host
uid, so `self.uid == current_uid` and the switch is not attempted at all
(virtiofsd `passthrough/credentials.rs`: `change_uid = !self.uid.is_root() &&
self.uid != current_uid`). There is no caller to impersonate, so there is
nothing to be privileged for.

It runs as `_wl-<name>` with `CapabilityBoundingSet=` and `AmbientCapabilities=`
empty. Not reduced — empty.

**The id map is load-bearing for function, not only for security.** If a change
lets other guest ids through, the sidecar fails with `EPERM` on the credential
switch rather than quietly needing privilege back. That is the failure direction
to preserve.

It is also what makes the 4294967295 gap in §1 harmless. For that id virtiofsd
calls `setresuid(-1, 4294967295, -1)` — which the kernel reads as `-1`, "leave
it alone", and returns success — so the file gets whatever euid was already in
effect. Unprivileged that is the workload user. At euid 0 it would be root, and
a guest naming that id could plant a root-owned file.

### Why `--sandbox=none`

| mode | verdict |
|---|---|
| `chroot` | **Impossible unprivileged.** A hard euid-0 requirement, not a capability check: `CAP_SYS_CHROOT` makes no difference (`sandbox mode 'chroot' can only be used by root`). |
| `namespace` | Works, but needs `user_namespace create`, `cap_userns { sys_admin setpcap }`, and mount/mounton/unmount across several types — the cost `security/pasta_sandbox.cil` exists to pay. A bad trade for a process that holds no capabilities. |
| `none` | What ships. Confined by the three layers below. |

What that costs is the daemon's own view restriction; what it buys is a process
that cannot chown, cannot setuid, and holds nothing to abuse. virtiofsd still
installs its own seccomp filter, so that layer is intact — and note it sets
`PR_SET_NO_NEW_PRIVS` on *itself* in doing so, **after** the exec, which is the
only reason NNP can be observed on the running process at all (see §4).

---

## 3. What confines it

1. **DAC.** It is the workload's own unprivileged user. The share is the only
   interesting thing it can write even with no policy loaded at all.
2. **The unit's mount namespace.** `ProtectSystem=strict` mounts the whole
   hierarchy read-only — `/run` included — with `ReadWritePaths=` naming exactly
   the share and the socket directory. Plus `ProtectProc=invisible`,
   `PrivateTmp=`, and `ProtectHome=` where the share allows it.
3. **The `wlvfsd_t` SELinux domain**, which is the whole of the type
   enforcement — there is no sandbox of virtiofsd's own behind it.

The domain exists for a reason unrelated to any of this: once QEMU is confined
as `svirt_t`, SELinux checks `connectto` against the *peer process's* domain,
and Fedora ships no virtiofsd domain to be. `security/workload-vm.cil` explains
that at length, including why a dedicated type beats the one-line blanket allow.

---

## 4. Three ways to break it

### `NoNewPrivileges=` — do not set it

It is the obvious next tightening and it breaks the unit outright, with an error
pointing nowhere near the cause: exec fails `203/EXEC`, "Permission denied", on
a mode-0755 binary.

Under NNP the kernel refuses any SELinux domain transition that is not *bounded*
by the calling domain, and `wlvfsd_t` is not bounded by `init_t`:

```
type=SELINUX_ERR op=security_bounded_transition seresult=denied
  oldcontext=system_u:system_r:init_t:s0
  newcontext=system_u:system_r:wlvfsd_t:s0
```

systemd then retries as `execute_no_trans`, which is also denied. Setting
`SELinuxContext=` explicitly does not help — the check is on the transition,
however it is requested. Making it work would mean a `typebounds` declaration
constraining `wlvfsd_t` to a subset of `init_t` forever, to buy nothing: the
bounding set is already empty, so there are no privileges left to gain.

`DynamicUser=` implies NNP and is out for the same reason.

**The seccomp-implying options are not affected**, despite the documentation's
"requires NNP" phrasing — `PrivateDevices=`, `ProtectKernel*=`,
`RestrictSUIDSGID=`, `SystemCallFilter=` and the rest. systemd only forces NNP
for those when the *manager* lacks `CAP_SYS_ADMIN` (`exec-invoke.c`,
`context_has_no_new_privileges`), which is never true for a system service. They
are absent from the unit because they are untested against virtiofsd, not
because they cannot be used.

### A stale pid file left by an older sidecar

virtiofsd writes `<socket-path>.pid` and holds an `flock` on it, opening that
exact path `O_CREAT|O_WRONLY` at mode 0600. One written by a root-era sidecar is
unopenable by the workload user, and the daemon exits with:

```
ERROR virtiofsd] Error creating pid file '…/virtiofs-<tag>.sock.pid':
  Permission denied (os error 13)
```

which reads as an SELinux or policy fault and is not one. `/run` is a tmpfs, so
a reboot hides it — but a restart after `dnf upgrade` does not. The unit's
`ExecStartPre` removes both the socket and the pid file on every start. It is
deliberately not `-` prefixed: a removal that genuinely fails is the diagnostic
worth having. Removing it is safe against a live peer, because virtiofsd takes
the lock and re-checks the inode precisely so a racing unlink is handled.

### A volume under `/home`, `/root` or `/run/user`

`ProtectHome=yes` masks exactly those, and a path cannot be both masked and
served. `[vm].volumes` takes an arbitrary host path, so the generator sets
`ProtectHome=` only when the share is elsewhere.

### Two flags that follow from being unprivileged

- **`--inode-file-handles=never`.** The default `prefer` uses
  `name_to_handle_at`/`open_by_handle_at`, which need `CAP_DAC_READ_SEARCH` in
  the initial user namespace — so it can now only fail and fall back. It fails
  once at startup and virtiofsd disables handles for the run, leaving a `WARN`
  and one `dac_read_search` AVC per start that look exactly like a policy bug.
- **`LimitNOFILE=1000000`.** virtiofsd wants that many fds (`limits.rs`
  `DEFAULT_NOFILE`) and holds one per open guest file — more of them with
  handles off. As root it raised its own hard limit; unprivileged it cannot, so
  systemd does it first. That also makes virtiofsd skip its `setrlimit`
  entirely, which is why `process setrlimit` could leave the policy.

---

## 5. The SELinux rule list, and how it is produced

**The method is the point.** A permissive harvest yields exactly the classes the
harvest exercised, and nothing warns about the rest — so an incomplete workout
does not produce a module that fails, it produces one that serves a share which
is healthy until a single ordinary operation is not.

Do not extend the list from a denial in isolation. Rebuild it: remove every
`wlvfsd_t` rule, mark the domain permissive, disable dontaudit, and drive a live
guest across the whole filesystem surface.

```bash
sudo semanage permissive -a wlvfsd_t
sudo semodule -DB          # or the dontaudit'd denials stay invisible
# …drive the guest…
sudo grep -a 'scontext=[^ ]*:wlvfsd_t' /var/log/audit/audit.log | grep -a denied
sudo semanage permissive -d wlvfsd_t && sudo semodule -B
```

The workout: create/read/write/truncate/append, mkdir/rmdir, symlink
read+create+rename+delete, hard link, FIFO and unix socket create and delete,
chmod/chown/utimes on files, directories **and** each of the three classes below
them (`mkfifo -m`, `chmod` on a bound unix socket, `lutimes`/`lchown` on a
symlink), rename within a directory and across directories — of a fifo and a
socket as well as a file — statfs, a first-boot cloud-init, and a clean stop.

The classes an incomplete workout drops are predictable, and they are the ones
below `file`:

| class / permission | what a guest loses without it |
|---|---|
| `lnk_file` | `ln -s` anywhere in the share |
| `fifo_file`, `sock_file` | a build that opens a FIFO; a daemon binding a unix socket in its own home |
| `dir:setattr` | chmod/chown/utimes on a directory — cloud-init chowns a HOME |
| `dir:rename`, `dir:reparent` | `mv` within a directory, and between two of them |
| `file:link` | hard links |
| `setattr` on the three classes | `mkfifo -m` (creates the node, then EPERMs on the mode); `chmod` on a socket a daemon just bound; `lutimes`/`lchown` on a symlink, which is what `cp -a`, `rsync -a` and `tar -xp` do to every symlink they copy |
| `rename` on `fifo_file`, `sock_file` | `mv` on a FIFO or a socket, when the same `mv` on a file and a symlink both work |

A workout of files and directories alone finds none of them, and none is
reachable by any test that reads the rendered unit file.

**If this list ever needs extending, extend the workout first.**

The domain grants **no capability at all**. With an empty bounding set a
capability rule could only be unreachable text asserting a privilege the daemon
does not have, so a capability denial for `wlvfsd_t` means the *unit* changed,
and the question is why it needs the privilege back.

### A volume outside the workload tree needs a label

`wlvfsd_t` is granted the types workloadctl itself labels: `svirt_image_t` for
the workload's own tree, `qemu_var_run_t` for the socket directory. A volume
pointing at an operator path carries whatever label that path already has
(`/srv` is `var_t`) and the sidecar is denied it. The module cannot pre-empt
this without granting the union of every type on the host, so the fix is an
fcontext rule on the path — `workloadctl diagnose <name>` reports the denial
rather than leaving a share that mounts empty. See
[workloads.md](workloads.md#virtiofs-volumes).

### …and a volume that *cannot hold* a label needs a mount option

An fcontext rule is the fix only for a filesystem with xattrs. A single-label
filesystem — cifs, nfs, vfat, anything the kernel policy marks
`fs_noxattr_type` — has nowhere to keep a per-file label, so every inode on it
takes one type from a `genfscon` line (`genfscon cifs /` → `cifs_t`).
`semanage fcontext` plus `restorecon` cannot change that, and running them
looks like it worked. The label has to come from the mount:

```
//server/share  /var/mnt/agentic  cifs  \
    context=system_u:object_r:svirt_image_t:s0,uid=_wl-<name>,gid=_wl-<name>,\
    forceuid,forcegid,file_mode=0700,dir_mode=0700,mfsymlinks,sfu,guest  0 0
```

Three groups of options, each load-bearing:

- **`context=`** gives the share the one type `wlvfsd_t` is already granted. It
  sets the type on the **superblock** as well as on every inode, which is why
  the module needs `filesystem getattr` on `svirt_image_t` and not only on
  `fs_t` — without it the share reads and writes normally and `df` alone
  returns EPERM.
- **`uid=`/`gid=`/`forceuid`/`forcegid`/`file_mode`/`dir_mode`** are what
  isolate the share, and on this kind of volume they are doing the work alone.
  Every VM's sidecar is `wlvfsd_t` and the superblock is one type, so type
  enforcement cannot tell two workloads apart here (MCS categories are unused —
  ADR 006 §9.5). DAC is the boundary: mode 0700 owned by `_wl-<name>` means
  another workload's user is refused.
- **`mfsymlinks,sfu`** because SMB has no native symlinks, FIFOs or unix
  sockets for a session like this. Without them `ln -s` and `mkfifo` in the
  share fail with **EOPNOTSUPP**, which is not a policy fault and must not be
  treated as one — `mfsymlinks` emulates symlinks client-side, `sfu` covers the
  special files.

**The error message for the missing label is a lie, and it is worth knowing why.**
virtiofsd checks its shared directory with Rust's `Path::is_dir()`, which
returns `false` on *any* stat error, so a denied `getattr` prints:

```
[ERROR virtiofsd] /var/mnt/agentic does not exist
```

on a path that is mounted and populated. Because it is a MAC denial it is
indifferent to uid and capabilities — the identical message appears for a
sidecar run as **root with a full capability set** — so it invites every
explanation except the right one. Read the audit log rather than the message:

```
denied { getattr } path="/var/mnt/agentic" dev="cifs" \
    scontext=system_u:system_r:wlvfsd_t:s0 tcontext=system_u:object_r:cifs_t:s0 tclass=dir
```

One consequence for testing: a sidecar started by hand, or wrapped in `strace`,
execs a `bin_t` binary rather than `wlvfsd_exec_t`, so the type transition in
§3 does not fire and the daemon runs unconfined. Such a run **succeeds where
the real unit fails**, which looks like a race and is not one. Reproduce
through systemd (`systemd-run` is enough — PID 1 execs the labelled binary and
the transition applies).

**A container workload hits the same wall, and hides it better.** There the
type is `container_file_t`, no policy rule is needed, and the denial is
`dontaudit`-suppressed — a healthy unit, `Permission denied`, and no AVC unless
you run `semodule -DB`. See
[workloads.md](workloads.md#volumes-on-external-filesystems).

---

## 6. What was proven

On a dev host, SELinux **enforcing**, with the module loaded and no permissive
entries:

- **Posture, read from `/proc` rather than the unit** — `Uid` and `Gid` the
  workload user in all four positions; `CapPrm`, `CapEff` and `CapBnd` all zero;
  context `system_u:system_r:wlvfsd_t:s0`; `Seccomp: 2`.
- **Filesystem surface** — the whole workout above, **zero AVCs**.
- **Ownership** — a guest running as its own root, asking explicitly for
  `root:root` and mode 4755, produced a file owned by `_wl-<name>` on the host.
- **cloud-init first boot** — the path the removed `fowner`/`fsetid` rules
  existed for. `status: done`, guest reachable, `/home/<user>/.ssh` 0700 and
  `authorized_keys` 0600, so sshd accepted the injected key.
- **Upgrade** — with a root-owned pid file planted, the sidecar fails to start
  without the `ExecStartPre` and starts with it.
- **A CIFS-backed volume** (§5) — an operator-mounted SMB share served into a
  guest. Mounted with `context=`, the whole workout above passes with zero AVCs
  and a guest write arrives on the SMB server; mounted without it, the sidecar
  refuses to start even as root. `df` needed the second `filesystem getattr`
  rule, and `ln -s`/`mkfifo` needed `mfsymlinks,sfu` rather than any policy
  change. Only DAC separates two workloads on such a volume.

`tests/cli_surface/test_runtime_vm_virtiofs.py` is the standing version of the
first four, against the `rt-vm-virtiofs` fixture. It is a runtime-rung check, so
it needs nested `/dev/kvm` and the VM toolchain and skips cleanly without them —
see [testing.md](testing.md).

---

## 7. Symptoms

| What you see | Where to look |
|---|---|
| `ln -s` fails with EPERM, everything else works | a missing class in the module — §5, and rebuild rather than adding one rule |
| Sidecar fails `203/EXEC`, "Permission denied", binary is 0755 | `NoNewPrivileges=` or `DynamicUser=` in a drop-in — §4 |
| `Error creating pid file … Permission denied` | stale root-owned pid file — §4 |
| Share mounts empty; `diagnose` reports a denial | volume outside the workload tree, unlabelled — §5 |
| Sidecar exits `<path> does not exist` on a path that *is* mounted | that check reports EACCES the same way; an unlabelable filesystem (cifs/nfs) needs `context=` — §5 |
| Same failure as root with full capabilities; succeeds under `strace` | a MAC denial, and `strace` loses the type transition — §5 |
| `df` in the guest returns EPERM while reads and writes work | superblock type missing from `filesystem getattr` — §5 |
| `ln -s` / `mkfifo` fail EOPNOTSUPP (not EPERM) on a CIFS share | SMB, not policy: mount `mfsymlinks,sfu` — §5 |
| `dac_read_search` AVC once per start, share works | `--inode-file-handles` is not `never` — §4 |
| Guest writes land, but `ls -l` in the guest shows the wrong owner | expected: the squash is one-way — §1 |
| Sidecar active, guest sees an empty directory | cloud-init did not mount it; check `stat -f -c %T` in the guest |
| VM healthy, `workloadctl exec`/`shell` fail to authenticate | a share mounted at the guest home — §8 |

---

## 8. A share mounted at the guest home hides the login key

cloud-init writes `~/.ssh/authorized_keys` in its **init** stage (`cc_users`) and
mounts `[vm].volumes` in the **config** stage that follows (`cc_mounts`). So a
share whose guest path *is* the login user's home — `["./home:/home/ben"]` with
`[vm].user = "ben"` — covers the only key the CLI has, and covers it on every
subsequent boot too, since the fstab entry mounts before sshd starts.

The guest is fine. `status` is `active`, the console logs in, cloud-init reports
`done` — and `workloadctl exec` fails authentication with nothing to point at.

`seed_vm_home_share_ssh_key` in `libexec/workload-ensure-user` closes this. A
share covering the guest home gets `.ssh/authorized_keys` written **on the host**
with the workload's own pubkey — the same key `${WORKLOADCTL_SSH_KEY}` would have
put in the shadowed home — before the seed ISO is built. A share mounted at
`/home` is handled the same way, seeding `<share>/<user>/`.

**It runs when `workload-<name>-setup.service` runs: `workloadctl enable`, and
each boot.** Not on `workloadctl restart` — the setup unit is a
`RemainAfterExit=yes` oneshot, so it stays active across a restart of the VM unit
and does not re-run. That matters only for *healing* a share whose key was
removed after the fact (an old backup restored over it, say): `workloadctl enable`
fixes it, a bare restart does not. Don't reach for
`systemctl restart workload-<name>-setup.service` instead — `Requires=`
propagates the stop to the VM and you end up power-cycling it anyway.

Three properties worth keeping:

- **Additive.** Keys already in the file stay; a file that already carries ours
  is left byte-identical. The operator's `authorized_keys` is theirs.
- **No-follow.** This is root writing into a tree the *workload user* owns, so
  it descends with `O_NOFOLLOW` (`_descend_nofollow`, the same walk §1's
  provisioning uses) and opens the file `O_NOFOLLOW`, refusing hardlinks. A
  symlink swapped in for `authorized_keys` fails the start; it never redirects
  root's write.
- **Fatal, not best-effort.** An unseeded share is a VM nobody can log into, so
  a failure here stops the start rather than producing one.

A share **outside** the workload tree is skipped with a warning naming the file
to copy: the walk needs a root-owned anchor to be safe, and an operator who
mounts a directory of their own at the guest home owns what is in it.

Mounting *below* the home (`/home/ben/data`) hides nothing and is untouched.
