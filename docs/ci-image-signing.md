# CI image signing

Both forges publish signed images, but they get the signing key in different
ways, and only one of them can use a forge secret at build time. This is the
reference for the Forgejo path, which is the unusual one.

Cited from `.forgejo/workflows/seal-signing-key.yml`,
`.forgejo/workflows/build-hypervisor.yml`,
`.forgejo/workflows/build-minimal-bootc.yml`, and `CLAUDE.md`.

## The two schemes

| | GitHub | Forgejo |
|---|---|---|
| Signer | `cosign sign --key env://COSIGN_PRIVATE_KEY` after push | `podman push --sign-by-sigstore-private-key` at push |
| Key source | `secrets.COSIGN_PRIVATE_KEY`, in the job env | host-key-sealed systemd credentials on the runner VM |
| Forge secrets in the build path | yes | **no** |
| Signature format | cosign/sigstore attachment | the same cosign-compatible sigstore attachment |

The signature is interchangeable: both are verified by a `sigstoreSigned`
`policy.json` entry *and* by `cosign verify --key cosign.pub`. The difference is
only in how the private key reaches the signer.

## Why Forgejo does not use a forge secret

The Forgejo runner is `runs-on: native` — it executes build jobs directly on the
runner VM rather than in a container (see the container-in-container note in
`CLAUDE.md`). Build jobs run as root children of `forgejo-runner.service`, so
anything the service can read, a build job can read. That cuts both ways: it is
what makes the credential approach possible, and it is why a plain repo secret is
worth avoiding — a secret in the job environment is exposed to every job,
including ones added later.

So the key is sealed *once* to the runner VM and never travels through Forgejo's
secret store again.

## Sealing the key

`.forgejo/workflows/seal-signing-key.yml` is operator-triggered
(`workflow_dispatch`) and re-runnable. It:

1. Reads `secrets.COSIGN_SECRET` / `secrets.COSIGN_PASSWORD` — the only time
   those are used.
2. Copies any credentials already sealed into
   `/etc/forgejo-runner/creds/backup-<UTC timestamp>/`.
3. `systemd-creds encrypt --with-key=host` each one into
   `/etc/forgejo-runner/creds/cosign-key.cred.new` and `cosign-pass.cred.new`.
4. Decrypts both `.new` blobs and compares the SHA-256 of what comes back with
   the SHA-256 of what went in, then moves them into place. A mismatch aborts
   with the live credentials untouched.
5. Writes a `forgejo-runner.service.d/50-signing-creds.conf` drop-in with
   `LoadCredentialEncrypted=` for both, so systemd decrypts them into the
   service's credential tmpfs at start.
6. Schedules the runner restart with `systemd-run --on-active=30` rather than
   restarting inline — an immediate restart would kill the very job doing the
   sealing.

Steps 2 and 4 exist because of the interaction between two other facts on this
page: the blobs are bound to this VM and regenerable from nowhere else, and the
documented flow deletes `COSIGN_SECRET` from Forgejo once the first seal works.
Without them, a re-run with a mangled secret would overwrite the only live copy
of the signing key and the source it could be rebuilt from would already be
gone. Digests are compared rather than values so neither the key nor the
passphrase can reach the job log.

`--with-key=host` binds the ciphertext to the VM's
`/var/lib/systemd/credential.secret`. That is the point: the sealed files are
useless if copied off the VM. It is also why the sealing has to be re-run when
the runner VM is re-provisioned — the credentials do **not** survive a rebuild.

**An empty passphrase is still sealed.** A key generated without a password
yields an empty `cosign-pass`, and that empty credential is written anyway so the
build-side flags can stay unconditional.

### After a successful seal

1. Let the delayed restart happen (~30s). It aborts any concurrently running
   jobs, so run this workflow while the runner is otherwise idle.
2. Verify signing on the next build.
3. **Delete `COSIGN_SECRET` and `COSIGN_PASSWORD` from the Forgejo repo
   secrets.** Leaving them defeats the whole arrangement.

## Signing at push

Build jobs read the decrypted credentials from
`/run/credentials/forgejo-runner.service/` and pass:

```
--sign-by-sigstore-private-key "${CREDS}/cosign-key"
--sign-passphrase-file        "${CREDS}/cosign-pass"
```

No `cosign` binary is involved on Forgejo — `containers/image` does the signing
as part of the push. That is deliberate: see
[cosign-local-redirect-loop.md](cosign-local-redirect-loop.md) for the failure
that made running `cosign` against `registry.local` unreliable.

**Missing credentials fail the job.** Each signing step checks
`test -s "${CREDS}/cosign-key"` first and exits non-zero with a message pointing
at the seal workflow. Nothing unsigned reaches the registry.

## Floating tags

Only the digest is signed. The floating tags (`:44`, `:latest`) are `skopeo
copy`-ed from the signed digest **within the same repository**, so the
digest-addressed signature already covers them — a `sigstoreSigned` policy check
on `:latest` resolves to the same manifest and passes.

This is exactly the property that has to hold, and it is easy to lose: a floating
tag rebuilt independently, or copied across repositories, is not covered. On
GitHub the equivalent guarantee is asserted explicitly — after signing the
digest, the workflow runs `cosign verify` against the digest *and* against every
published tag.
