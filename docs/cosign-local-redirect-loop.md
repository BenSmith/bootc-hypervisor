# cosign, `*.local` names, and the 80→443 redirect loop

Why the Caddy reverse proxy hard-404s the registry API on plain HTTP instead of
redirecting it, and why CI signs with `containers/image` rather than the `cosign`
binary.

Cited from `workloadctl/workloads/caddy/Caddyfile`,
`workloadctl/workloads/caddy/README.md`,
`workloadctl/workloads/virtual-forgejo/cloud-init/user-data`, and the Forgejo
build workflows.

## Symptom

Pushing to or signing an image in `registry.local` fails, intermittently, with:

```
stopped after 10 redirects
```

It correlates with host load rather than with anything about the image, which is
what makes it look like a flake rather than a configuration bug.

## Cause

cosign's registry client treats a `*.local` hostname as *possibly* plain HTTP. On
its first `/v2/` ping it races an HTTP attempt against an HTTPS attempt.

With Caddy's automatic 80→443 redirects enabled, the HTTP attempt does not fail —
it gets a 308 to HTTPS, follows it, and *succeeds*. The client therefore records
the win as "this registry answers on http", pins `scheme=http` for the rest of the
session, and rewrites every subsequent redirect target back to `http`. Each
request is then redirected to HTTPS, rewritten back to HTTP, redirected again — a
80→443→80 loop that terminates only when the redirect limit trips.

Whether the HTTP or HTTPS probe wins is a timing race, which is why a busy host
fails and an idle one does not.

## Fix

The `:80` block responds **404** to `/v2*` on every host:

```caddyfile
handle /v2* {
    respond "registry API is https-only" 404
}
```

A hard 404 makes the HTTP probe *lose* every time, deterministically, so cosign
always settles on HTTPS and never pins the wrong scheme. Caddy's automatic
redirects are disabled globally (`auto_https disable_redirects`) and the `:80`
block owns all plain-HTTP behaviour, so this exemption cannot be reintroduced by a
per-site redirect.

**The rule is path-based, not host-based, on purpose.** It protects any current or
future registry behind this proxy without anyone maintaining a hostname list —
including registries added long after the person who debugged this has forgotten
about it.

Non-registry `*.local` hosts still get a generic 80→443 redirect from the same
block; only `/v2*` is exempt.

## Consequence for CI

The Forgejo build workflows do not invoke `cosign` at all. They sign at push time
via `containers/image` (`podman push --sign-by-sigstore-private-key`), which does
not perform the scheme race and so cannot hit this failure. The resulting
signature is a cosign-compatible sigstore attachment, verifiable with both
`sigstoreSigned` policy and `cosign verify`.

See [ci-image-signing.md](ci-image-signing.md) for the rest of that scheme.

## If you are changing the Caddy config

Removing the `/v2*` handler restores the bug, and it will present as intermittent
signing failures under load rather than as anything pointing back at the proxy.
`workloadctl/workloads/caddy/README.md` documents the two supported ways to change
the HTTP behaviour without losing the exemption.
