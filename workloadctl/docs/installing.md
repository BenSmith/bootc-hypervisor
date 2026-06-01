# Installing workloadctl on non-bootc Fedora systems

workloadctl ships as an RPM hosted in the Forgejo package registry at
`https://git.local/api/packages/ben/rpm`. The forge VM (git.local) uses
Caddy with an internal CA, so you need to trust that CA before HTTPS works.

## One-time setup per machine

### 1. Trust git.local's Caddy CA

```bash
sudo curl -sk https://git.local/caddy-root.crt \
  -o /etc/pki/ca-trust/source/anchors/git-local-caddy-root.crt
sudo update-ca-trust
```

`-k` skips verification for this one bootstrap fetch — you can't verify
the CA before you've installed it. All subsequent HTTPS connections verify
normally.

### 2. Add the DNF repo

```bash
sudo tee /etc/yum.repos.d/workloadctl.repo << 'EOF'
[forgejo-ben]
name=ben - Forgejo
baseurl=https://git.local/api/packages/ben/rpm
enabled=1
gpgcheck=0
proxy=_none_
EOF
```

`proxy=_none_` is needed on machines that route general traffic through a
proxy — `*.local` addresses should bypass it but DNF doesn't always respect
that automatically.

### 3. Install

```bash
sudo dnf install -y workloadctl
```

## Upgrades

```bash
sudo dnf upgrade workloadctl
```

If DNF says "nothing to do" despite a newer version being available, the
metadata cache is stale — clear it and retry:

```bash
sudo dnf clean metadata && sudo dnf upgrade workloadctl
```

This is most common on first setup or after the repo is newly configured.

## Notes

**`.rpmnew` after install/upgrade**: the RPM ships its own
`/etc/yum.repos.d/workloadctl.repo` (without `proxy=_none_`). If you have
a hand-written repo file in place, RPM saves the package's version as
`workloadctl.repo.rpmnew` instead of overwriting yours. Delete it:

```bash
sudo rm -f /etc/yum.repos.d/workloadctl.repo.rpmnew
```

If you're on a machine that doesn't need the proxy exclusion, you can let
the RPM-owned file win and skip the manual step.

**CA cert per forge instance**: `git.local` and `zamd.local` each run their
own Caddy instance with separate CAs. `http://zamd.local/caddy-root.crt`
gives you zamd's CA (for `registry.local`, `zot.local`, etc.).
`http://git.local/caddy-root.crt` gives you the forge CA. Install both if
you need access to services on both hosts.
