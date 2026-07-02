# Zot Registry

OCI-native container registry with pull-through cache and web UI. Built from
the upstream `zot-linux-amd64` release binary on a Fedora base.

## Files

- `Containerfile` — fetches and verifies the Zot binary, installs to `/usr/local/bin/zot`
- built via `sudo workloadctl build zot-registry` → `localhost/zot-registry:latest`
- `entrypoint.sh` — runs `zot serve /etc/zot/config.json`
- `config.json` — default config: pull-through sync from docker.io, ghcr.io,
  quay.io, registry.fedoraproject.org, codeberg.org, plus search + UI extensions

## Pinned version

`ZOT_VERSION` and `ZOT_SHA256` are baked into the Containerfile. To bump:

1. Pick a new tag from <https://github.com/project-zot/zot/releases>
2. Grab the matching checksum from the release's `checksums.sha256.txt`
3. Update both ARGs in `Containerfile`
4. Rebuild

## Customizing upstreams

Edit `/var/lib/workloads/zot-registry/config.json` after enabling and restart
the workload. Each entry under `extensions.sync.registries` maps an upstream
URL; with `prefix: "**"` they all match every repo and Zot tries them in
order. Remove entries you don't need to speed up cache misses.

## Web UI

Open `http://<host>:5050/` after enabling. The UI surfaces repos, tags, layer
sizes, and metadata. CVE scanning is off by default (would pull a large Trivy
DB on startup); enable by adding `"cve": { "updateInterval": "24h" }` under
`extensions.search`.
