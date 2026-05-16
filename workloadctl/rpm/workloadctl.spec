Name:           workloadctl
Version:        0.1.0
Release:        %{?buildserial:0.%{buildserial}}%{!?buildserial:1}%{?dist}
Summary:        Declarative rootless container workload manager

License:        MIT
URL:            https://github.com/BenSmith/bootc-hypervisor

BuildArch:      noarch

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
# checkpolicy only compiles the optional per-workload .te policy modules.
Suggests:       checkpolicy

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

# Private library — kept under %{_libexecdir} instead of %{python3_sitelib}
# to avoid implying a public, importable Python API.
install -Dpm 0644 %{_sourcedir}/lib/workload_lib.py \
    %{buildroot}%{_libexecdir}/workloadctl/workload_lib.py
install -Dpm 0644 %{_sourcedir}/lib/podman.py \
    %{buildroot}%{_libexecdir}/workloadctl/podman.py

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

install -Dpm 0644 %{_sourcedir}/systemd/workload-exporter.service \
    %{buildroot}%{_unitdir}/workload-exporter.service
install -Dpm 0644 %{_sourcedir}/systemd/workloads.slice \
    %{buildroot}%{_unitdir}/workloads.slice

install -Dpm 0644 %{_sourcedir}/systemd/workloads-dirs.conf \
    %{buildroot}%{_prefix}/lib/tmpfiles.d/workloads-dirs.conf

install -Dpm 0644 %{_sourcedir}/seccomp-workload-baseline.json \
    %{buildroot}%{_datadir}/containers/seccomp-workload-baseline.json

install -Dpm 0644 %{_sourcedir}/completions/workloadctl-completion.bash \
    %{buildroot}%{_datadir}/bash-completion/completions/workloadctl

install -Dpm 0644 %{_sourcedir}/docs/workloads.md \
    %{buildroot}%{_docdir}/workloadctl/workloads.md

install -dm 0755 %{buildroot}%{_datadir}/workloadctl
cp -a %{_sourcedir}/containers %{buildroot}%{_datadir}/workloadctl/containers
find %{buildroot}%{_datadir}/workloadctl/containers -name '*.sh' -exec chmod 0755 {} \;

install -dm 0755 %{buildroot}%{_docdir}/workloadctl/examples
install -pm 0644 %{_sourcedir}/workloads.d/*.toml \
    %{buildroot}%{_docdir}/workloadctl/examples/

install -Dpm 0644 %{_sourcedir}/LICENSE %{buildroot}%{_datadir}/licenses/workloadctl/LICENSE

install -dm 0755 %{buildroot}%{_sysconfdir}/workloads.d

%post
%systemd_post workload-exporter.service
systemd-tmpfiles --create workloads-dirs.conf 2>/dev/null || :

%preun
%systemd_preun workload-exporter.service

%postun
%systemd_postun_with_restart workload-exporter.service

%files
%{_datadir}/licenses/workloadctl/LICENSE
%{_bindir}/workloadctl
%{_libexecdir}/workloadctl/workload_lib.py
%{_libexecdir}/workloadctl/podman.py
%{_prefix}/lib/systemd/system-generators/workload-generator
%dir %{_libexecdir}/workloadctl
%{_libexecdir}/workloadctl/workload-generate
%{_libexecdir}/workloadctl/workload-ensure-user
%{_libexecdir}/workloadctl/workload-write-env
%{_libexecdir}/workloadctl/workload-exporter
%{_unitdir}/workload-exporter.service
%{_unitdir}/workloads.slice
%{_prefix}/lib/tmpfiles.d/workloads-dirs.conf
%{_datadir}/containers/seccomp-workload-baseline.json
%{_datadir}/bash-completion/completions/workloadctl
%{_docdir}/workloadctl/
%{_datadir}/workloadctl/
%dir %{_sysconfdir}/workloads.d

%changelog
