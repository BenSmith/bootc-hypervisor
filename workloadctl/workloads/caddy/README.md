# Caddy Container

Per-host reverse proxy on 80/443. Routes incoming requests to local
workloads by `Host` header so clients can use names like `http://zot.local`
without specifying the backend port. Pairs with the `avahi` workload that
publishes those names via mDNS.

## Setup

1. **Build the container:**
   ```bash
   sudo workloadctl build caddy
   ```

   > **SELinux:** `workloadctl enable` uses `semanage` to label the workload's
   > image storage as `container_file_t`. It ships in `policycoreutils-python-utils`,
   > which is preinstalled on the hypervisor image. On a plain host, install it
   > first — without it the labeling step is skipped and the container cannot
   > read its own libraries (see Troubleshooting):
   > ```bash
   > sudo dnf install policycoreutils-python-utils checkpolicy
   > ```

2. **Drop a Caddyfile in place** (the sample fronts zot and grafana):
   ```bash
   sudo workloadctl enable caddy             # creates /var/lib/workloads/caddy/
   sudo cp /usr/share/workloadctl/workloads/caddy/Caddyfile /var/lib/workloads/caddy/Caddyfile
   ```

3. **Edit routes** and recreate the container:
   ```bash
   sudo nano /var/lib/workloads/caddy/Caddyfile
   sudo workloadctl recreate caddy
   ```

4. **Open the firewall.** UDP/443 is for HTTP/3, which Caddy serves
   automatically alongside HTTP/2 over TCP — omit it if you don't want
   HTTP/3:
   ```bash
   sudo firewall-cmd --add-service=http --add-service=https --permanent
   sudo firewall-cmd --add-port=443/udp --permanent
   sudo firewall-cmd --reload
   ```

## Caddyfile pattern

```caddyfile
zot.local, registry.local {
    reverse_proxy 127.0.0.1:5050
}

grafana.local {
    reverse_proxy 127.0.0.1:3000
}

# Catchall — Caddy v2 routes most-specific-first, so this only handles
# requests whose Host didn't match any block above.
:80 {
    respond "no site configured for {host}" 404
}
```

Each backend address is the host-side port that the corresponding workload's
`[network] ports = [...]` forwards from. For `zot-registry` that's `5050:5000`,
so Caddy talks to `127.0.0.1:5050`. Caddy itself runs in host networking, so
`127.0.0.1` is the actual host loopback.

The catchall site block is optional but recommended. Without it, hitting the
host by IP or with a Host header that doesn't match anything yields Caddy's
default empty-200 response, which looks identical to a working site whose
backend is silent. The 404 makes "you didn't configure this name" obvious.

## Verifying

```bash
# Local test, no DNS needed — -k trusts the local CA, --resolve fakes the name:
curl -k --resolve zot.local:443:127.0.0.1 https://zot.local/v2/
curl -kL http://grafana.local/                         # full path: DNS + 80->443 redirect + backend
curl http://zot.local/v2/                              # registry API over plain HTTP: expect 404, NOT a redirect
workloadctl logs caddy | tail                          # access + error log
```

Named sites are served over HTTPS; `http://<name>` 308-redirects to
`https://<name>`, so use `-L` (follow redirects) and `-k` (trust Caddy's
internal CA) when testing with `curl`. The one exception is the registry API:
`http://<name>/v2*` must return 404 (see "Stopping the redirect" below) — if
it 308s, image signing will break.

## Troubleshooting

### 502 Bad Gateway

Caddy received the request but couldn't reach the backend.

- **Wrong port?** Compare the Caddyfile address to the workload's
  `[network] ports` mapping. The host-side number is what Caddy needs.
  ```bash
  ss -tlnp | grep <port>                  # confirm something is actually listening
  ```
- **Backend on a different host?** `127.0.0.1` won't reach it. Use the LAN IP
  of the host actually running the workload.
- **Backend bound to a non-loopback address only?** Some workloads only listen
  on the container's internal interface; check `workloadctl info <name>` and
  the container's own config.

### 404 "no site matched" / Caddy default page

The `Host` header on the request didn't match any site block in the Caddyfile.

- **Client used the IP instead of the name?** Caddy routes by Host header,
  not by IP. Hit it by name (`http://zot.local`), which means the name has
  to actually resolve — confirm the `avahi` workload is publishing it.
  ```bash
  avahi-resolve -n zot.local
  ```
- **Site block uses a different name?** Caddyfile labels must match exactly,
  including subdomains. Use commas for aliases:
  `zot.local, registry.local { ... }`.

### Caddy can't bind 80/443 / "permission denied"

The hypervisor image sets `net.ipv4.ip_unprivileged_port_start=0`, so this
should not happen. If it does:
```bash
sysctl net.ipv4.ip_unprivileged_port_start         # expect 0
```
If it's higher, this host is missing the hypervisor sysctl drop-in. Add it
manually:
```bash
echo 'net.ipv4.ip_unprivileged_port_start = 0' | sudo tee /etc/sysctl.d/50-privileged-ports.conf
sudo sysctl --system
sudo workloadctl recreate caddy
```

### Container restart loop / "cannot apply additional memory protection"

The service flaps with exit code 127 and `journalctl` shows AVC denials like:
```
avc: denied { read } ... comm="caddy" path="/usr/lib64/libc.so.6"
  tcontext=...:object_r:var_lib_t:s0
```
The image layers under the workload user's storage are labeled `var_lib_t`
instead of `container_file_t`, so the `container_t` process can't read them.
This means `enable` couldn't run `semanage` — check its output for
`Failed to set up SELinux policy: ... 'semanage'`. Install the package and
re-enable so the fcontext rule is created and the storage relabeled:
```bash
sudo dnf install policycoreutils-python-utils checkpolicy
sudo workloadctl disable caddy
sudo workloadctl enable caddy
```

### Port 80 or 443 already in use

Another workload (or host service) is holding the port.
```bash
sudo ss -tlnp 'sport = :80 or sport = :443'
```
Common culprits: Pi-hole's web UI defaults to port 80, a host nginx/httpd,
another reverse proxy. Move the conflicting service to a high port and front
it via a Caddyfile site block instead.

### TLS certificate warnings

The sample Caddyfile uses `local_certs`, which has Caddy's internal CA sign
the certs. Browsers will warn until you install Caddy's root CA on each
client, or until you switch to plain HTTP. To extract the root:
```bash
sudo cat /var/lib/workloads/caddy/data/caddy/pki/authorities/local/root.crt
```
Install that on your clients' trust stores. For HTTP-only operation, replace
the global block in the Caddyfile with `{ auto_https off }`.

### Stopping the http://name -> https://name redirect

Caddy redirects HTTP to HTTPS by default once a site has a cert. The sample
Caddyfile *disables* that (`auto_https disable_redirects`) and reimplements
the redirect inside the `:80` catchall, so `http://<name>` still 308-redirects
to `https://<name>` for any `*.local` Host — with one deliberate carve-out:

**the registry API (`/v2*`) is never redirected, on any host.** cosign's
registry client treats `*.local` names as possibly-http and races http vs
https on its first ping; if the http probe wins via a followed redirect,
every later request gets pinned to http and loops on the 308 until cosign
fails with "stopped after 10 redirects". The `:80` block hard-404s `/v2*`
instead, so the http probe always loses. The rule is path-based on purpose —
it protects any current or future registry behind this proxy without
maintaining a hostname list. See `docs/cosign-local-redirect-loop.md` for the
full failure analysis.

To serve plain HTTP *without* any redirect, drop the `@dotlocal` redirect
from the `:80` block; to drop HTTPS entirely, replace the global block with
`{ auto_https off }`.

### `curl: (35) ... tlsv1 alert internal error` on an unknown name

Hitting Caddy over HTTPS with a `Host`/SNI that matches no site block fails the
TLS handshake — `local_certs` only mints certs for configured names, and the
`:80` catchall has no HTTPS equivalent. This is expected; use a configured name
(and check `avahi` is publishing it). The `:80` catchall still gives a clean
`404` for unknown names over plain HTTP.

### Changes to Caddyfile not taking effect

Caddy reads `/etc/caddy/Caddyfile` at start, so the blunt option is:
```bash
sudo workloadctl recreate caddy
```

For zero-downtime reloads (preserves in-flight connections, doesn't drop
the listening sockets), use Caddy's `caddy reload` inside the running
container:
```bash
sudo workloadctl exec caddy caddy reload --config /etc/caddy/Caddyfile
```
Recreate is fine for occasional edits; reload is the right call when the
proxy is actively serving traffic.

### Verifying what Caddy actually saw

The access log includes the request's `Host`, path, status, and which
upstream was selected:
```bash
workloadctl logs caddy
```
If a request isn't appearing in the log at all, it didn't reach Caddy —
suspect firewall or DNS, not the proxy.

## Why host networking

Two reasons:
- Caddy needs to bind 80/443 on the host's actual interfaces.
- Pasta-networked backends are reachable on the host's loopback at their
  forwarded port. From inside a pasta container, that loopback is not
  shared, so a pasta-mode Caddy would not reach them without extra
  port-forwarding plumbing. Host networking sidesteps the whole issue.

## Why the Containerfile pins `XDG_DATA_HOME`

Caddy v2 picks its on-disk storage path at runtime from, in order,
`$XDG_DATA_HOME/caddy` → `$HOME/.local/share/caddy` → a hardcoded fallback.
With `userns=keep-id` the in-container process is the rootless workload
user, which has no `pwent` in the image and therefore no real `$HOME`, so
without an explicit pin Caddy lands somewhere unmapped (often `/.local/...`)
and the bind-mounted `./caddy` volume goes unused. The visible symptom is
that Caddy's internal CA root fingerprint changes on every container
restart, breaking clients that previously trusted it.

Setting `XDG_DATA_HOME=/var/lib/caddy` (and `XDG_CONFIG_HOME=/etc/caddy/config`)
forces the storage into the bind-mounted volumes so certs and state
persist across restarts. The CA root referenced in the TLS section above
lives at `/var/lib/workloads/caddy/data/caddy/pki/authorities/local/root.crt`
(self-signed CA only; with the shared CA below, only `intermediate.crt`/`.key`
live there and the root is the mounted file).

## Shared homelab CA

By default each host's Caddy generates its own self-signed root, so clients must
trust a different root per host — and they are all confusingly named
`Caddy Local Authority`, which makes a mismatched one fail with
`SEC_ERROR_BAD_SIGNATURE` rather than a clear "untrusted" error. To trust ONE
root for every host's `*.local` services, point every Caddy at a shared homelab
root via the `pki` block (already wired into the sample `Caddyfile` and
`caddy.toml`).

The shared-root `pki` block is **generated host-side** by `setup.sh` (the
`[host] setup` hook) into `/etc/caddy/pki/homelab-ca.caddyfile`, which the
Caddyfile imports. It keys off whether the private root key is present:

- **Key present** → the snippet roots Caddy's `local` CA at the shared homelab
  root (below).
- **Key absent** → the snippet is comment-only, so Caddy falls back to its own
  auto-generated internal CA. Caddy **still starts and serves HTTPS** (clients
  just won't trust it until you set up the shared CA) — it does *not* crash-loop
  on a missing key. Place the key later and re-run enable (see "Per host") to
  switch over.

- **Public root cert** — provided by the image trust store. The Forgejo build
  injects it from the `HOMELAB_ROOT_CA` secret into
  `/etc/pki/ca-trust/source/anchors/homelab-root.crt` (see `ca-trust-inject/` at
  the repo root). `[setup] required_files` copies it from there into the workload
  dir as `./homelab-root.crt` so it gets a `container_file_t` label the container
  can read — mounting the trust anchor directly fails (`cert_t` is SELinux-denied
  to `container_t`, surfacing as `open …homelab-root.crt: permission denied`).
- **Private root key** — a per-host `0400` file at
  `/var/lib/workloads/caddy/data/homelab-root.key`, owned by the workload user.
  Never shipped in the image or committed. caddy runs as that user under
  `keep-id`, so it can read it (no `userns=host` needed).

Each Caddy still mints its own intermediate signed by the shared root, so leaf
certs rotate normally; only the root is shared.

### One-time CA generation (once for the whole homelab)
```
openssl ecparam -name prime256v1 -genkey -noout -out homelab-root.key
openssl req -x509 -new -key homelab-root.key -sha256 -days 3650 \
    -subj "/CN=Homelab Root CA/O=asdf" -out homelab-root.crt
```
Set the Forgejo `HOMELAB_ROOT_CA` secret to the contents of `homelab-root.crt`,
and back up `homelab-root.key` offline — it is the homelab CA key.

### Per host
```
sudo install -m 0400 -o _wl-caddy -g _wl-caddy homelab-root.key \
    /var/lib/workloads/caddy/data/homelab-root.key
# Re-run enable (not recreate) so the [host] setup hook regenerates the PKI
# snippet now that the key is present. recreate does NOT re-run host setup.
sudo workloadctl disable caddy && sudo workloadctl enable caddy
```
If you enabled caddy *before* placing the key, the bind-mount source may be an
empty placeholder file — `install` overwrites it fine. (An older build could
have left a *directory* there; `sudo rm -rf
/var/lib/workloads/caddy/data/homelab-root.key` first if so.)

### Switching an existing self-signed Caddy to the shared root
Caddy reuses an existing on-disk `local` CA in preference to the configured
root, so clear the stale authority + cached leaf certs first or it keeps serving
the old root:
```
sudo systemctl stop workload-caddy.service
# Caddy's data dir is /var/lib/caddy/caddy (XDG_DATA_HOME=/var/lib/caddy + its
# own caddy/ subdir), so the authority lives under data/caddy/caddy/ — note the
# doubled caddy/.
sudo rm -rf /var/lib/workloads/caddy/data/caddy/caddy/pki/authorities/local \
            /var/lib/workloads/caddy/data/caddy/caddy/certificates
sudo systemctl start workload-caddy.service
# served chain should now be issued by "Homelab - ECC Intermediate":
echo | openssl s_client -connect zot.local:443 -servername zot.local 2>/dev/null | grep ^issuer=
```

### Clients
Hosts built from the internal image already trust the root (CI-injected). Other
machines trust it once: put `homelab-root.crt` in
`/etc/pki/ca-trust/source/anchors/` and run `update-ca-trust`. Firefox uses its
own store — import the root under Authorities (trust for websites), or set
`security.enterprise_roots.enabled`.
