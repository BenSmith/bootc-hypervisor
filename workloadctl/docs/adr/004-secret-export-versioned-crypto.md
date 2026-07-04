# ADR 004: `secret export` uses a versioned, integrity-protected format

**Status:** **Implemented** 2026-07-03 (code review 2026-07 follow-up, item D5;
carded as B14). `secret export` writes v2 (AES-256-CBC, pbkdf2 600k iters,
encrypt-then-HMAC-SHA256); `import` detects and reads both v1 and v2.

**Date:** 2026-07-03.

## Context

`secret export` / `secret import` is a **documented portability feature** (see
`docs/cli.md`, `docs/workloads.md` "Portable Credential Transfer"): it converts a
TPM-bound credential into a passphrase-encrypted blob so it can be moved to another
machine and re-imported. That is precisely a "sensitive file, stored and transported
off-host" scenario.

The current export uses `openssl enc -aes-256-cbc` with a passphrase:

- **No MAC / integrity** — CBC without authentication; a tampered or truncated blob
  is not detected on decrypt.
- **Weak KDF** — OpenSSL's low default PBKDF2 iteration count (no `-pbkdf2 -iter`).

Because the exported blob is meant to leave the host and be stored, these are real
weaknesses, not a theoretical concern of an ephemeral in-process path.

## Decision

**Move `secret export` to a versioned, integrity-protected format**, keeping
backward-compatible import of existing blobs.

- New format version: AES-256 with `-pbkdf2 -iter 600000` **and** an integrity
  mechanism (authenticated encryption, e.g. `-aead`/GCM, or an explicit HMAC over the
  ciphertext).
- `secret import` detects the format version by header and decrypts either the legacy
  v1 (`aes-256-cbc`, unauthenticated) or the new v2 blobs — existing exports remain
  restorable.

(`age` was considered as an alternative — cleaner modern AEAD — but adds a runtime
dependency and a harder format break. The versioned-OpenSSL path is the lower-cost
upgrade and keeps the stdlib-only / minimal-dependency posture.)

## Rationale

A portability feature whose output is stored and transported must protect integrity
and use a modern KDF; the upgrade is cheap and, with version detection, costs no
migration for existing exports. Leaving it unauthenticated was rejected because the
threat model (off-host storage/transport) is exactly where integrity matters.

## Consequences

- Export output format changes (v2 header); import stays compatible with v1.
- `docs/cli.md` / `docs/workloads.md` note the format version and the integrity
  guarantee.
- See B14 in `docs/wip/code-review-2026-07-open-items.md` for the implementation card
  (this ADR resolves the D5 gate on B14).
