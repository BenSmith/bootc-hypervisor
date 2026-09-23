"""The per-workload SELinux type, and the udica module that confines it.

Two things, both taking an `action` because they run in both directions
and a teardown is the same step with the sign flipped: the fcontext for a
VM workload's tree (svirt_image_t, so a confined QEMU can use its disks)
and the CIL module built from a bundle's shipped policy over udica's base
templates. `shadowed_filecon_paths` is the check that a bundle's filecon
lines are not silently overridden by the roots registered via semanage.
Everything here shells out to semodule, semanage and restorecon and prints
its own diagnostic; SelinuxPolicyError tells the caller that has happened.

Installed to /usr/libexec/workloadctl/workload_selinux.py.
"""

import difflib
import re
import shutil
import subprocess
import tempfile
from pathlib import Path

from cli_log import error, info, warn
from config_parser import workload_root_dir
from container_network_config import container_uses_inspect
from egress_ca import CA_DIR_NAME, DENIAL_DIR_NAME, LEAF_DIR_NAME
from workload_lib import (
    NAME_PATTERN,
    WORKLOAD_BUNDLES_DIR,
    selinux_module_name,
    selinux_type_name,
)
from workloadctl_core import WorkloadConfig


# THE PKI SUBTREE HAS ITS OWN LABELS, AND THAT IS THE WHOLE POINT
#
# `wlinspect_t` is a separate domain from `svirt_t` so that the component
# terminating guest input cannot reach the workload's disks, volumes or state
# directory. The inspector reads a private key and writes a leaf cache, and
# both live in that state directory beside the disk images.
# Granting the domain `svirt_image_t` would be one rule shorter, would work,
# and would hand the inspector the guest's disks — so the material moves
# instead: three directories with labels of their own, and the domain is
# granted those.
#
# Two types, not one, because the permissions genuinely differ. The CA is
# READ-ONLY to the inspector: an inspector that could rewrite it could replace
# the anchor the guest was seeded with, which is unrecoverable without a
# re-provision. The leaves are read-write because minting them is the job.
CA_SELINUX_TYPE = "wlinspect_ca_t"
LEAF_SELINUX_TYPE = "wlinspect_leaf_t"


def pki_fcontext_patterns(name: str) -> list[tuple[str, str]]:
    """(pattern, type) for every directory in one workload's PKI subtree.

    Registered in `file_contexts.local` beside the per-workload svirt_image_t
    rule, and more specific than it, which is the only reason these win: within
    ONE source most-specific-wins applies, and `.local` outranks the base file
    wholesale. A CIL `filecon` in the policy module lands in the base file and
    would be silently shadowed -- see shadowed_filecon_paths().

    Here rather than in egress_ca, whose names these are: egress_ca is on the
    listener's side of the line and takes a state directory it is handed,
    while this function is the one that knows where a WORKLOAD's state
    directory is. The directory names stay in egress_ca so the minter that
    creates the directories and the pattern that labels them cannot drift;
    the composition with the workload root, and the types, live here.
    """
    root = workload_root_dir(name)
    return [
        (f"{root}/state/{CA_DIR_NAME}(/.*)?", CA_SELINUX_TYPE),
        (f"{root}/state/{LEAF_DIR_NAME}(/.*)?", LEAF_SELINUX_TYPE),
        (f"{root}/state/{DENIAL_DIR_NAME}(/.*)?", LEAF_SELINUX_TYPE),
    ]


class SelinuxPolicyError(Exception):
    """Raised by apply_selinux_policy() when loading/removing a workload's
    SELinux type fails.

    Same contract as substrate.ProvisionFailed: the diagnostic has already
    been printed, so the caller exits 1 without printing again (the enable
    path) or lets it fold into the disable path's best-effort failure list.
    """

UDICA_TEMPLATE_DIR = Path("/usr/share/udica/templates")
_BUNDLES_DIR = WORKLOAD_BUNDLES_DIR


def _selinux_available() -> bool:
    """True if the host can load CIL policy modules (semodule + udica bases)."""
    return bool(shutil.which("semodule")) and UDICA_TEMPLATE_DIR.is_dir()


def _selinux_enforcing() -> bool:
    """True if SELinux is currently in enforcing mode."""
    try:
        result = subprocess.run(["getenforce"], capture_output=True, text=True)
        return result.returncode == 0 and result.stdout.strip() == "Enforcing"
    except FileNotFoundError:
        return False


def _available_bundles() -> list[str]:
    """Bundle names shipping a CIL policy under the workloads share dir.

    A bundle is a subdir <name>/ that contains policy.cil (the template
    apply_selinux_policy loads). Returned sorted for stable output.
    """
    if not _BUNDLES_DIR.is_dir():
        return []
    return sorted(
        d.name for d in _BUNDLES_DIR.iterdir()
        if d.is_dir() and (d / "policy.cil").exists()
    )


def _print_available_bundles(bundle: str):
    """Hint at valid selinux_policy bundles after a missing-template error."""
    available = _available_bundles()
    if not available:
        return
    match = difflib.get_close_matches(bundle, available, n=1)
    if match:
        error(f"         did you mean {match[0]!r}?")
    error("         available bundles: " + ", ".join(available))


# SELinux type for a VM workload's tree. NOT container_file_t, which the
# blanket /var/lib/workloads rule applies: `virt_domain` has no read, write,
# getattr or append on container_file_t, so a confined QEMU cannot use a disk
# image labelled with it. svirt_image_t carries the full set.
IMAGE_SELINUX_TYPE = "svirt_image_t"


def fcontext_pattern(name: str) -> str:
    """The fcontext pattern covering one VM workload's whole tree."""
    return f"{workload_root_dir(name)}(/.*)?"


def apply_vm_fcontext(config: WorkloadConfig, action: str):
    """Register (enable) or unregister (disable) a workload's PKI/tree fcontext rules.

    VM disks need svirt_image_t, not the container_file_t the blanket
    /var/lib/workloads rule gives them. A per-workload rule wins its whole
    subtree by specificity — directories, disks, nvram.fd and files nobody
    enumerated — while sibling container workloads keep matching the blanket
    rule, so the blanket rule does not move and existing hosts need no
    migration.

    A container has no disk to relabel this way, but one running its own
    egress inspector (`container_uses_inspect()`) still has a CA/leaf PKI
    subtree that needs moving OFF container_file_t: wlinspect_t has read on
    wlinspect_ca_t/wlinspect_leaf_t only, never on the blanket type (see
    workload-inspect.cil). Skipping this for containers is exactly the bug
    P1-10 shipped — `provision_egress_pki_dirs()`'s `restorecon` had nothing
    registered to relabel the subtree TO, so it silently stayed
    container_file_t and the inspector's own `os.path.exists()` on its CA
    read back False (EACCES reads the same as ENOENT). So this registers the
    PKI patterns for both substrates that need them, and the whole-tree
    svirt_image_t pattern for a VM only — a container's tree otherwise stays
    on the blanket rule on purpose.

    **Gated on is_vm or container_uses_inspect(), not on
    [security].selinux_policy.** Labelling is a precondition for the
    inspector/VM starting at all, not an optional hardening step, and that
    flag is opt-in — a workload that omitted it would fail to start with an
    EPERM that looks like nothing is wrong. The two are independent in both
    directions: this is `semanage`, the policy module is `semodule`, and they
    land in different files in the store.

    Both rules must live in `file_contexts.local`, which is why this is
    `semanage` and not a CIL `filecon` shipped in the bundle: `.local` outranks
    the base `file_contexts` *wholesale*, so most-specific-wins applies only
    within one source. A module's filecon lands in the base file and would be
    silently shadowed by the blanket rule.

    Best-effort: a host without semanage, or with SELinux disabled, is not a
    reason to fail an enable.
    """
    is_vm = config.is_vm
    inspected_container = not is_vm and container_uses_inspect(config.config)
    if not is_vm and not inspected_container:
        return
    if not shutil.which("semanage"):
        return

    pki_patterns = pki_fcontext_patterns(config.name)

    if action == "disable":
        # The PKI rules first: they are more specific than the tree rule, so
        # removing the general one first would leave three orphans matching
        # nothing registered above them. A container has no tree rule to
        # remove -- only the PKI subtree was ever registered for it.
        for pki_pattern, _ in pki_patterns:
            subprocess.run(["semanage", "fcontext", "-d", pki_pattern],
                           check=False, capture_output=True)
        if is_vm:
            subprocess.run(
                ["semanage", "fcontext", "-d", fcontext_pattern(config.name)],
                check=False, capture_output=True)
        return

    listed = subprocess.run(["semanage", "fcontext", "-l"],
                            capture_output=True, text=True)
    known = listed.stdout if listed.returncode == 0 else ""

    wanted = list(pki_patterns)
    if is_vm:
        wanted = [(fcontext_pattern(config.name), IMAGE_SELINUX_TYPE)] + wanted
    registered_any = False
    for one, selinux_type in wanted:
        # Each rule is checked on its own rather than short-circuiting on the
        # tree rule. An upgrade onto a host provisioned before the PKI subtree
        # had labels of its own has the tree rule already and the three PKI
        # rules not at all, and a check that returns early on the first hit
        # never registers them -- on exactly the hosts that need it.
        if one in known:
            continue
        result = subprocess.run(
            ["semanage", "fcontext", "-a", "-t", selinux_type, one],
            capture_output=True, text=True)
        if result.returncode != 0:
            # WARN AND CARRY ON, never return. Each rule stands alone, and
            # returning here left the ones already registered unlabelled: the
            # relabel below is the only thing that applies them, and skipping
            # it produces a tree whose rules say one thing and whose files say
            # another -- which presents as the inspector reporting its own CA
            # missing (EACCES and ENOENT are the same answer to Path.exists)
            # or as "QMP socket not ready", never as a failed semanage call.
            warn(f"  WARNING: could not register the SELinux fcontext rule for "
                 f"'{config.name}': {result.stderr.strip()}")
            continue
        info(f"  Registered SELinux fcontext: {one} -> {selinux_type}")
        registered_any = True

    if not registered_any:
        return  # everything already registered; the tree is already labelled

    # Relabel now rather than waiting for the next start. -F is REQUIRED: both
    # container_file_t and svirt_image_t are in contexts/customizable_types, and
    # plain restorecon skips any file whose *current* type is listed there,
    # printing "not reset as customized by admin" only under -v and exiting 0.
    # Without -F this migration silently never happens.
    subprocess.run(["restorecon", "-RF", str(workload_root_dir(config.name))],
                   check=False, capture_output=True)


# Path prefixes workloadctl registers in file_contexts.local (the blanket rule
# from the RPM's %post, plus every per-workload VM rule under the same root).
# A CIL filecon anywhere under these is unreachable — see below.
LOCAL_FCONTEXT_ROOTS = ("/var/lib/workloads", "/run/workload-vm")

# CIL is s-expressions, so a filecon is `(filecon "<path>" <class> <context>)`.
_CIL_FILECON_RE = re.compile(r'\(\s*filecon\s+"([^"]*)"')


def shadowed_filecon_paths(cil_text: str) -> list[str]:
    """Paths in a bundle's `policy.cil` whose `filecon` will be silently ignored.

    A module's filecon lands in the base `file_contexts`, and
    `file_contexts.local` outranks the base file *wholesale* — most-specific-wins
    applies only within one source. So a filecon under a path workloadctl has
    registered via semanage does not conflict with that rule and does not lose
    on specificity; it is simply never consulted. The label an operator asked
    for is not applied, nothing errors, and the module loads clean.

    Filecons elsewhere are fine and are how `security/wlvfsd.cil` retypes
    /usr/libexec/virtiofsd: nothing registers /usr/libexec in `.local`, so that
    rule competes within the base file where specificity does apply.
    """
    shadowed = []
    for path in _CIL_FILECON_RE.findall(cil_text):
        # CIL filecons may be literal paths or regexes; either way the leading
        # literal segment is what decides which source file the entry lands
        # against, so a plain prefix test is the right comparison.
        if any(path == root or path.startswith(root + "/")
               for root in LOCAL_FCONTEXT_ROOTS):
            shadowed.append(path)
    return shadowed


def apply_selinux_policy(config: WorkloadConfig, action: str):
    """Load (enable) or remove (disable) a workload's per-workload SELinux type.

    The bundle ships its policy as a CIL template (`policy.cil`) using the
    __WL_MODULE__ placeholder. On enable we substitute the name-keyed block name
    (wl_<name>) and load it alongside udica's base templates (which the
    workload's `(blockinherit ...)` resolves against); on disable we remove the
    wl_<name> module, leaving the shared base templates loaded.

    No-op for workloads without `[security].selinux_policy = true`.
    """
    if not config.selinux_policy:
        return

    module = selinux_module_name(config.name)

    if not _selinux_available():
        # Hard-fail only on enable: the container would fail to start under
        # enforcing mode without its type loaded. disable is best-effort
        # teardown — without tooling there's nothing we could remove anyway, so
        # never block it.
        if action != "disable" and _selinux_enforcing():
            error(f"  ERROR: selinux_policy is set for '{config.name}' but SELinux tooling "
                  f"(semodule + container-selinux templates) is missing. The container "
                  f"would fail to start under enforcing mode. Install container-selinux "
                  f"and policycoreutils, then re-run enable.")
            raise SelinuxPolicyError(f"selinux tooling missing for '{config.name}'")
        warn(f"  WARNING: SELinux tooling (semodule + udica templates) not "
             f"found; skipping policy {action} for '{config.name}'")
        return

    if action == "disable":
        loaded = subprocess.run(["semodule", "-l"], capture_output=True, text=True)
        if module in loaded.stdout.split():
            info(f"  Removing SELinux module {module}...")
            subprocess.run(["semodule", "-r", module], check=False)
        return

    # enable: substitute the block name and load the workload CIL alongside the
    # udica base templates (so any `(blockinherit ...)` resolves). semodule -i
    # upgrades in place, so re-enabling is idempotent. The CIL is sourced from
    # the bundle dir (defaults to the workload name; a `selinux_policy` string
    # names it explicitly so a renamed workload keeps its original policy).
    bundle = config.selinux_bundle
    if bundle is None:
        # Reached only if a workload without selinux_policy is routed here.
        error(f"  ERROR: no SELinux bundle resolved for '{config.name}' "
              f"(selinux_policy not set)")
        raise SelinuxPolicyError(f"no SELinux bundle resolved for '{config.name}'")
    if not NAME_PATTERN.match(bundle):
        # bundle goes straight into a filesystem path; reject anything that
        # isn't a plain workload-style name (blocks traversal / odd values).
        error(f"  ERROR: invalid [workload] bundle {bundle!r} "
              f"(must match {NAME_PATTERN.pattern})")
        # Common footgun: users copy the SELinux *type* name (wl_foo_bar,
        # underscores) into `bundle`, but the bundle is a directory name
        # and dirs are hyphenated. Suggest the hyphenated form.
        if "_" in bundle:
            error(f"         did you mean {bundle.replace('_', '-')!r}? "
                  f"(the bundle is a directory name and uses hyphens, not the "
                  f"underscores of the SELinux type name)")
        raise SelinuxPolicyError(f"invalid bundle {bundle!r} for '{config.name}'")
    template = config.resolve_control_file("policy.cil")
    if not template.exists():
        error(f"  ERROR: SELinux policy template not found: {template}")
        _print_available_bundles(bundle)
        raise SelinuxPolicyError(f"policy template not found for '{config.name}'")

    bases = sorted(str(p) for p in UDICA_TEMPLATE_DIR.glob("*.cil"))
    src = template.read_text().replace("__WL_MODULE__", module)

    info(f"  Installing SELinux module {module} (type {selinux_type_name(config.name)})...")
    with tempfile.TemporaryDirectory() as work:
        cil = Path(work) / f"{module}.cil"
        cil.write_text(src)
        try:
            subprocess.run(["semodule", "-i", str(cil), *bases], check=True)
        except subprocess.CalledProcessError as e:
            error(f"  Error: SELinux policy install failed (exit {e.returncode})")
            raise SelinuxPolicyError(f"semodule -i failed for '{config.name}'")
