%global source_date_epoch_from_changelog 0

Name:           workloadctl
Version:        0.1.0
Release:        %{?buildserial:1.%{buildserial}}%{!?buildserial:1}
Summary:        Declarative rootless container workload manager

License:        MIT
URL:            https://github.com/BenSmith/bootc-hypervisor

BuildArch:      noarch

# %{_unitdir} (used in %install and %files for the exporter unit + slice) is
# defined by systemd-rpm-macros. Without it rpmbuild emits the literal
# "%{_unitdir}/..." and fails with: File must begin with "/".
BuildRequires:  systemd-rpm-macros
Requires:       python3 >= 3.14
Requires:       podman >= 5.3
Requires:       systemd
Requires:       shadow-utils
Suggests:       bash-completion
# SELinux: enable registers an fcontext rule for /var/lib/workloads so the
# transferred image storage is labeled container_file_t. semanage
# (policycoreutils-python-utils) is required for that — restorecon alone
# would relabel the tree back to var_lib_t and break every container.
Requires:       policycoreutils
Requires:       policycoreutils-python-utils
# Per-workload SELinux policy ships as udica-style CIL (e.g. alloy.cil) that
# inherits base container templates from /usr/share/udica/templates (shipped by
# container-selinux, not udica) and loads via semodule. The udica binary itself
# is an authoring-only tool; it is not invoked at runtime.
Requires:       container-selinux
Recommends:     udica
# VM workloads need passt for networking (ADR 006) and nftables for the egress
# policy the uid-keyed output chain is written into. dnsmasq went with the
# managed bridge: passt serves the guest DHCP and DNS itself.
Requires:       passt
Requires:       nftables
Suggests:       qemu-kvm
Suggests:       virtiofsd

%description
workloadctl is a declarative workload provisioning system for rootless
podman containers. Define workloads as TOML files in /etc/workloads.d/,
and workloadctl handles user creation, systemd service generation,
volume management, secrets, and container lifecycle.

Each workload runs as a dedicated locked-down system user with its own
UID/subuid namespace, home directory, and rootless podman instance.

%prep
# Installed directly from a repo checkout; switch to %%autosetup once a
# tarball Source is added.

%install
# The CLI is the one entrypoint users invoke by bare name off PATH, so it cannot
# live beside the library the way the generator and libexec helpers do. Install
# the real program into the private module dir (where its sys.path[0] resolves
# the lib modules with zero path manipulation) and expose it on PATH through a
# thin exec wrapper. This keeps the modules private instead of registering a
# sitewide .pth that would put 21 generic top-level names on every host process's
# sys.path.
install -dm 0755 %{buildroot}%{_libexecdir}/workloadctl
install -pm 0755 %{_sourcedir}/bin/workloadctl \
    %{buildroot}%{_libexecdir}/workloadctl/workloadctl
install -dm 0755 %{buildroot}%{_bindir}
cat > %{buildroot}%{_bindir}/workloadctl << 'EOF'
#!/bin/sh
exec %{_libexecdir}/workloadctl/workloadctl "$@"
EOF
chmod 0755 %{buildroot}%{_bindir}/workloadctl

# Private library modules under %{_libexecdir}/workloadctl/. Every workloadctl
# entrypoint is installed into this same directory, so each finds the modules via
# its own sys.path[0] -- no .pth, no sys.path manipulation.
for _f in %{_sourcedir}/lib/*.py; do
    install -pm 0644 "$_f" %{buildroot}%{_libexecdir}/workloadctl/
done

# Generate version module with the package Version-Release (buildserial lives
# in Release), so workloadctl --version matches the RPM's V-R. Name and Epoch
# are deliberately not in it: Name is constant and no Epoch is defined, so V-R
# alone identifies a build.
cat > %{buildroot}%{_libexecdir}/workloadctl/_version.py << 'EOF'
__version__ = "%{version}-%{release}"
EOF
chmod 0644 %{buildroot}%{_libexecdir}/workloadctl/_version.py
install -Dpm 0755 %{_sourcedir}/generators/workload-generator \
    %{buildroot}%{_prefix}/lib/systemd/system-generators/workload-generator

install -Dpm 0755 %{_sourcedir}/generators/workload-generate \
    %{buildroot}%{_libexecdir}/workloadctl/workload-generate
install -Dpm 0755 %{_sourcedir}/libexec/workload-ensure-user \
    %{buildroot}%{_libexecdir}/workloadctl/workload-ensure-user
install -Dpm 0755 %{_sourcedir}/libexec/workload-write-env \
    %{buildroot}%{_libexecdir}/workloadctl/workload-write-env
install -Dpm 0755 %{_sourcedir}/libexec/workload-exporter \
    %{buildroot}%{_libexecdir}/workloadctl/workload-exporter
install -Dpm 0755 %{_sourcedir}/libexec/workload-vm-build-disk \
    %{buildroot}%{_libexecdir}/workloadctl/workload-vm-build-disk
install -Dpm 0755 %{_sourcedir}/libexec/workload-vm-notify \
    %{buildroot}%{_libexecdir}/workloadctl/workload-vm-netdev
%{_libexecdir}/workloadctl/workload-vm-notify
install -Dpm 0755 %{_sourcedir}/libexec/workload-vm-qmp \
    %{buildroot}%{_libexecdir}/workloadctl/workload-vm-qmp
install -Dpm 0755 %{_sourcedir}/libexec/workload-vm-shutdown \
    %{buildroot}%{_libexecdir}/workloadctl/workload-vm-shutdown

install -Dpm 0644 %{_sourcedir}/systemd/workload-exporter.service \
    %{buildroot}%{_unitdir}/workload-exporter.service
install -Dpm 0644 %{_sourcedir}/systemd/workload-exporter.timer \
    %{buildroot}%{_unitdir}/workload-exporter.timer
install -Dpm 0644 %{_sourcedir}/systemd/workload-exporter-disk.service \
    %{buildroot}%{_unitdir}/workload-exporter-disk.service
install -Dpm 0644 %{_sourcedir}/systemd/workload-exporter-disk.timer \
    %{buildroot}%{_unitdir}/workload-exporter-disk.timer
install -Dpm 0644 %{_sourcedir}/systemd/workloads.slice \
    %{buildroot}%{_unitdir}/workloads.slice

install -Dpm 0644 %{_sourcedir}/systemd/80-workloadctl.preset \
    %{buildroot}%{_presetdir}/80-workloadctl.preset

install -Dpm 0644 %{_sourcedir}/systemd/workloads-dirs.conf \
    %{buildroot}%{_prefix}/lib/tmpfiles.d/workloads-dirs.conf

install -Dpm 0644 %{_sourcedir}/seccomp-workload-baseline.json \
    %{buildroot}%{_datadir}/containers/seccomp-workload-baseline.json

install -Dpm 0644 %{_sourcedir}/completions/workloadctl-completion.bash \
    %{buildroot}%{_datadir}/bash-completion/completions/workloadctl

install -Dpm 0644 %{_sourcedir}/docs/workloads.md \
    %{buildroot}%{_docdir}/workloadctl/workloads.md

install -Dpm 0644 %{_sourcedir}/docs/schema-reference.toml \
    %{buildroot}%{_docdir}/workloadctl/schema-reference.toml

# Shipped workload bundles: one subdir per bundle co-locating the template
# declaration (workload.toml) with its control files (Containerfile, build.sh,
# setup.sh, policy.cil, cloud-init user-data, *.conf templates — any subset).
# This replaces the old split across containers/, vms/, and docdir examples.
# `catalog`/`init` read the declarations from here; build/setup/SELinux lookups
# resolve control files from here; [vm.cloud_init].user_data_file references
# real on-disk paths under it. So it must be a real share location, not docdir.
install -dm 0755 %{buildroot}%{_datadir}/workloadctl
cp -a %{_sourcedir}/workloads %{buildroot}%{_datadir}/workloadctl/workloads
find %{buildroot}%{_datadir}/workloadctl/workloads -name '*.sh' -exec chmod 0755 {} \;

# `cp -a` copies whatever the build tree holds, tracked or not, so a dirty
# checkout leaks into the package. Two ways it shows up, both fixed here:
#
#   1. Ignored build droppings inside an otherwise-valid bundle. A __pycache__/
#      beside a bundle's sources is the common one; it is noise in the payload
#      and its .pyc files are stale the moment python changes.
#   2. Whole bundle dirs with no workload.toml. A branch switch deletes the
#      tracked files but leaves any directory that still holds an ignored one,
#      so the package ships a "bundle" that is nothing but empty directories.
#
# Pruning makes the package honest regardless of the builder's tree; the
# warning tells them the tree is dirty.
find %{buildroot}%{_datadir}/workloadctl/workloads \
    -name __pycache__ -type d -prune -exec rm -rf {} +
for bundle in %{buildroot}%{_datadir}/workloadctl/workloads/*/; do
    # Guard the unmatched-glob case: with no bundles at all the loop would
    # otherwise run once on the literal pattern and warn about a bundle named '*'.
    [ -d "$bundle" ] || continue
    if [ ! -f "${bundle}workload.toml" ]; then
        echo "WARNING: dropping bundle with no workload.toml: $(basename "$bundle")" >&2
        rm -rf "$bundle"
    fi
done

install -Dpm 0644 %{_sourcedir}/LICENSE %{buildroot}%{_datadir}/licenses/workloadctl/LICENSE


install -dm 0755 %{buildroot}%{_sysconfdir}/workloads.d

# The timers are the enabled units; each oneshot service is pulled in by its
# timer, not enabled on its own.
%post
%systemd_post workload-exporter.timer workload-exporter-disk.timer
systemd-tmpfiles --create workloads-dirs.conf 2>/dev/null || :
# On upgrade ($1 >= 2), running workloads keep the units the *previous* build
# generated: %%post does not regenerate them, and nothing else will until a
# reboot re-runs workload-generate or the operator re-enables. On a bootc host
# that window cannot open (new code is only live after a reboot, which
# regenerates), but on a plain-RPM host it stays open indefinitely and silently.
#
# Each generated unit carries `# Generated by workload-generate (<NEVR>)`, so
# the skew is a string compare against the version being installed. Warn only
# when it is real — an install with no live units, or an upgrade whose units
# already match, says nothing. Every step is non-fatal: a warning must never
# fail the transaction.
if [ "$1" -ge 2 ]; then
    stale=$(grep -l '^# Generated by workload-generate (' \
                /run/systemd/system/workload-*.service 2>/dev/null \
            | xargs -r grep -L \
                'Generated by workload-generate (%{version}-%{release})' \
                2>/dev/null | wc -l) || stale=0
    if [ "${stale:-0}" -gt 0 ]; then
        cat >&2 <<EOF
workloadctl: $stale running workload unit(s) were generated by the previous
  build and are NOT regenerated by this upgrade. They keep their old shape
  until units are rewritten. To refresh now:
      sudo workloadctl enable <workload>    # per workload, or
      sudo systemctl reboot                 # regenerates everything at boot
  To see which: sudo workloadctl doctor
EOF
    fi
fi

%preun
%systemd_preun workload-exporter.timer workload-exporter-disk.timer

%postun
%systemd_postun_with_restart workload-exporter.timer workload-exporter-disk.timer
# On full uninstall ($1 == 0, not upgrade) reverse the host-global state this
# package registers, which no per-workload teardown can safely remove (it is
# shared across workloads while the package is installed): the semanage
# fcontext rules from %%post.
#
# The `allow _workload-br` line in qemu-bridge-helper's allowlist is no longer
# cleaned up here because it is no longer created: retiring the managed bridge
# (ADR 006) took the setuid-root helper out of the VM data path entirely. A
# line left behind by a pre-ADR-006 install names an interface that no longer
# exists, so it grants nothing; an admin bridge (allow br0) was always left
# alone and still is, since the admin owns it.
if [ $1 -eq 0 ]; then
    semanage fcontext -d '/var/lib/workloads(/.*)?' 2>/dev/null || :
fi

%files
%{_datadir}/licenses/workloadctl/LICENSE
%{_bindir}/workloadctl
%{_prefix}/lib/systemd/system-generators/workload-generator
%dir %{_libexecdir}/workloadctl
%{_libexecdir}/workloadctl/*.py
%{_libexecdir}/workloadctl/workloadctl
%{_libexecdir}/workloadctl/workload-generate
%{_libexecdir}/workloadctl/workload-ensure-user
%{_libexecdir}/workloadctl/workload-write-env
%{_libexecdir}/workloadctl/workload-exporter
%{_libexecdir}/workloadctl/workload-vm-build-disk
%{_libexecdir}/workloadctl/workload-vm-notify
%{_libexecdir}/workloadctl/workload-vm-qmp
%{_libexecdir}/workloadctl/workload-vm-shutdown
%{_unitdir}/workload-exporter.service
%{_unitdir}/workload-exporter.timer
%{_unitdir}/workload-exporter-disk.service
%{_unitdir}/workload-exporter-disk.timer
%{_unitdir}/workloads.slice
%{_presetdir}/80-workloadctl.preset
%{_prefix}/lib/tmpfiles.d/workloads-dirs.conf
%{_datadir}/containers/seccomp-workload-baseline.json
%{_datadir}/bash-completion/completions/workloadctl
%{_docdir}/workloadctl/
%{_datadir}/workloadctl/
%dir %{_sysconfdir}/workloads.d

%changelog
