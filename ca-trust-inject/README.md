# CI-injected CA trust anchors

Drop `*.crt` (PEM) files here to have them baked into the image's **system**
trust store at build time — `hypervisor.Containerfile` copies any `*.crt` here
into `/etc/pki/ca-trust/source/anchors/` and runs `update-ca-trust`.

This directory is intentionally **empty in git** (only this README). It exists so
secret-bearing pipelines can inject trust anchors *without committing them to the
source*:

- The **Forgejo** pipeline writes the homelab root CA here from the
  `HOMELAB_ROOT_CA` repo/org secret before building (see
  `.forgejo/workflows/build-hypervisor-version.yml`). Internal images then trust
  the shared homelab CA out of the box — every `*.local` service fronted by Caddy
  validates with no per-host import.
- The **GitHub** pipeline does not set the secret, so the public ghcr image
  ships no extra anchors.

Only the **public** root certificate is ever placed here. The CA private key
never lives in this repo or in any image — it is provisioned per Caddy host
(`workloadctl secret` / a `0400` file owned by the workload user).
