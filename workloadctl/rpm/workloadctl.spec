%{!?python3_sitelib: %global python3_sitelib %(python3 -c "import sysconfig; print(sysconfig.get_path('purelib'))")}

Name:           workloadctl
Version:        1.0.0
Release:        1%{?dist}
Summary:        Declarative rootless container workload manager

License:        MIT
URL:            https://github.com/BenSmith/bootc-hypervisor

BuildArch:      noarch

Requires:       python3 >= 3.11
Requires:       podman >= 5.3
Requires:       systemd
Requires:       shadow-utils
Suggests:       bash-completion

%description
workloadctl is a declarative workload provisioning system for rootless
podman containers. Define workloads as TOML files in /etc/workloads.d/,
and workloadctl handles user creation, systemd service generation,
volume management, secrets, and container lifecycle.

Each workload runs as a dedicated locked-down system user with its own
UID/subuid namespace, home directory, and rootless podman instance.

%prep
# No source tarball yet — installed directly from repo checkout
# When building from tarball: %%autosetup -n workloadctl-%%{version}

%install
# Binary
install -Dpm 0755 %{_sourcedir}/bin/workloadctl %{buildroot}%{_bindir}/workloadctl

# Python library
install -Dpm 0644 %{_sourcedir}/lib/workload_lib.py \
    %{buildroot}%{python3_sitelib}/workload_lib.py

# systemd generator (shell wrapper)
install -Dpm 0755 %{_sourcedir}/generators/workload-generator-wrapper \
    %{buildroot}%{_prefix}/lib/systemd/system-generators/workload-generator

# libexec helpers
install -Dpm 0755 %{_sourcedir}/generators/workload-generate \
    %{buildroot}%{_libexecdir}/workloadctl/workload-generate
install -Dpm 0755 %{_sourcedir}/libexec/workload-ensure-user \
    %{buildroot}%{_libexecdir}/workloadctl/workload-ensure-user
install -Dpm 0755 %{_sourcedir}/libexec/workload-write-env \
    %{buildroot}%{_libexecdir}/workloadctl/workload-write-env
install -Dpm 0755 %{_sourcedir}/libexec/workload-metrics \
    %{buildroot}%{_libexecdir}/workloadctl/workload-metrics

# systemd units
install -Dpm 0644 %{_sourcedir}/systemd/workload-metrics.service \
    %{buildroot}%{_unitdir}/workload-metrics.service
install -Dpm 0644 %{_sourcedir}/systemd/workload-metrics.timer \
    %{buildroot}%{_unitdir}/workload-metrics.timer

# tmpfiles.d
install -Dpm 0644 %{_sourcedir}/systemd/workloads-dirs.conf \
    %{buildroot}%{_prefix}/lib/tmpfiles.d/workloads-dirs.conf

# seccomp profile
install -Dpm 0644 %{_sourcedir}/seccomp-workload-baseline.json \
    %{buildroot}%{_datadir}/containers/seccomp-workload-baseline.json

# bash completion
install -Dpm 0644 %{_sourcedir}/completions/workloadctl-completion.bash \
    %{buildroot}%{_datadir}/bash-completion/completions/workloadctl

# documentation
install -Dpm 0644 %{_sourcedir}/docs/workloads.md \
    %{buildroot}%{_docdir}/workloadctl/workloads.md

# container build recipes (examples)
install -dm 0755 %{buildroot}%{_datadir}/workloadctl
cp -a %{_sourcedir}/containers %{buildroot}%{_datadir}/workloadctl/containers
find %{buildroot}%{_datadir}/workloadctl/containers -name '*.sh' -exec chmod 0755 {} \;

# example workload configs
install -dm 0755 %{buildroot}%{_docdir}/workloadctl/examples
install -pm 0644 %{_sourcedir}/workloads.d/*.toml \
    %{buildroot}%{_docdir}/workloadctl/examples/

# license
install -Dpm 0644 %{_sourcedir}/LICENSE %{buildroot}%{_datadir}/licenses/workloadctl/LICENSE

# config directory
install -dm 0755 %{buildroot}%{_sysconfdir}/workloads.d

%post
%systemd_post workload-metrics.timer
systemd-tmpfiles --create workloads-dirs.conf 2>/dev/null || :

%preun
%systemd_preun workload-metrics.timer

%postun
%systemd_postun_with_restart workload-metrics.timer

%files
%{_datadir}/licenses/workloadctl/LICENSE
%{_bindir}/workloadctl
%{python3_sitelib}/workload_lib.py
%{python3_sitelib}/__pycache__/workload_lib.*
%{_prefix}/lib/systemd/system-generators/workload-generator
%dir %{_libexecdir}/workloadctl
%{_libexecdir}/workloadctl/workload-generate
%{_libexecdir}/workloadctl/workload-ensure-user
%{_libexecdir}/workloadctl/workload-write-env
%{_libexecdir}/workloadctl/workload-metrics
%{_unitdir}/workload-metrics.service
%{_unitdir}/workload-metrics.timer
%{_prefix}/lib/tmpfiles.d/workloads-dirs.conf
%{_datadir}/containers/seccomp-workload-baseline.json
%{_datadir}/bash-completion/completions/workloadctl
%{_docdir}/workloadctl/
%{_datadir}/workloadctl/
%dir %{_sysconfdir}/workloads.d

%changelog
* Sun Apr 05 2026 Ben Smith <ben@bensmith.dev> - 1.0.0-1
- Initial package: extracted workload system from bootc-hypervisor
- FHS-compliant paths: /usr/libexec/workloadctl/, /usr/share/workloadctl/
- Renamed CLI from workload-ctl to workloadctl
