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
# Likewise %{python3_sitelib} (the workloadctl.pth drop) comes from
# python3-rpm-macros, which rpm-build does not pull in on its own.
BuildRequires:  python3-rpm-macros

Requires:       python3 >= 3.11
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
# VM workloads require the bridge networking stack and a hypervisor.
Requires:       dnsmasq
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
install -Dpm 0755 %{_sourcedir}/bin/workloadctl %{buildroot}%{_bindir}/workloadctl

# Private library modules under %{_libexecdir}/workloadctl/.
# A .pth file in %{python3_sitelib} makes them importable by all workloadctl
# scripts without any sys.path manipulation.
install -dm 0755 %{buildroot}%{_libexecdir}/workloadctl
for _f in %{_sourcedir}/lib/*.py; do
    install -pm 0644 "$_f" %{buildroot}%{_libexecdir}/workloadctl/
done

# Generate version module with the full package version-release (buildserial
# lives in Release), so workloadctl --version matches the RPM NEVR.
cat > %{buildroot}%{_libexecdir}/workloadctl/_version.py << 'EOF'
__version__ = "%{version}-%{release}"
EOF
chmod 0644 %{buildroot}%{_libexecdir}/workloadctl/_version.py
install -dm 0755 %{buildroot}%{python3_sitelib}
echo '%{_libexecdir}/workloadctl' > %{buildroot}%{python3_sitelib}/workloadctl.pth
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
    %{buildroot}%{_libexecdir}/workloadctl/workload-vm-notify
install -Dpm 0755 %{_sourcedir}/libexec/workload-vm-qmp \
    %{buildroot}%{_libexecdir}/workloadctl/workload-vm-qmp
install -Dpm 0755 %{_sourcedir}/libexec/workload-vm-shutdown \
    %{buildroot}%{_libexecdir}/workloadctl/workload-vm-shutdown

install -Dpm 0644 %{_sourcedir}/systemd/workload-exporter.service \
    %{buildroot}%{_unitdir}/workload-exporter.service
install -Dpm 0644 %{_sourcedir}/systemd/workload-exporter.timer \
    %{buildroot}%{_unitdir}/workload-exporter.timer
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

install -Dpm 0644 %{_sourcedir}/LICENSE %{buildroot}%{_datadir}/licenses/workloadctl/LICENSE


install -dm 0755 %{buildroot}%{_sysconfdir}/workloads.d

# The timer is the enabled unit; its oneshot service is pulled in by the timer,
# not enabled on its own.
%post
%systemd_post workload-exporter.timer
systemd-tmpfiles --create workloads-dirs.conf 2>/dev/null || :

%preun
%systemd_preun workload-exporter.timer

%postun
%systemd_postun_with_restart workload-exporter.timer
# On full uninstall ($1 == 0, not upgrade) reverse the host-global state that
# workload-ensure-user accretes but never per-workload teardown can safely
# remove (it's shared across workloads while the package is installed):
#   - the semanage fcontext rule for /var/lib/workloads
#   - the managed VM bridge's allow line in qemu-bridge-helper's allowlist
# A custom/admin bridge (e.g. allow br0) is intentionally left alone — the admin
# owns it and may rely on it outside workloadctl.
if [ $1 -eq 0 ]; then
    semanage fcontext -d '/var/lib/workloads(/.*)?' 2>/dev/null || :
    if [ -f /etc/qemu/bridge.conf ]; then
        sed -i '/^allow _workload-br$/d' /etc/qemu/bridge.conf 2>/dev/null || :
    fi
fi

%files
%{_datadir}/licenses/workloadctl/LICENSE
%{_bindir}/workloadctl
%{python3_sitelib}/workloadctl.pth
%{_prefix}/lib/systemd/system-generators/workload-generator
%dir %{_libexecdir}/workloadctl
%{_libexecdir}/workloadctl/*.py
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
%{_unitdir}/workloads.slice
%{_presetdir}/80-workloadctl.preset
%{_prefix}/lib/tmpfiles.d/workloads-dirs.conf
%{_datadir}/containers/seccomp-workload-baseline.json
%{_datadir}/bash-completion/completions/workloadctl
%{_docdir}/workloadctl/
%{_datadir}/workloadctl/
%dir %{_sysconfdir}/workloads.d

%changelog
