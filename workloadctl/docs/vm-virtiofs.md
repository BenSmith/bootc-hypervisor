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
chmod/chown/utimes on both files **and** directories, rename within a directory
and across directories, statfs, a first-boot cloud-init, and a clean stop.

The classes an incomplete workout drops are predictable, and they are the ones
below `file`:

| class / permission | what a guest loses without it |
|---|---|
| `lnk_file` | `ln -s` anywhere in the share |
| `fifo_file`, `sock_file` | a build that opens a FIFO; a daemon binding a unix socket in its own home |
| `dir:setattr` | chmod/chown/utimes on a directory — cloud-init chowns a HOME |
| `dir:rename`, `dir:reparent` | `mv` within a directory, and between two of them |
| `file:link` | hard links |

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
| `dac_read_search` AVC once per start, share works | `--inode-file-handles` is not `never` — §4 |
| Guest writes land, but `ls -l` in the guest shows the wrong owner | expected: the squash is one-way — §1 |
| Sidecar active, guest sees an empty directory | cloud-init did not mount it; check `stat -f -c %T` in the guest |
