# ADR 004: `secret export` uses a versioned, integrity-protected format

**Status:** Implemented. `secret export` writes v2 (AES-256-CBC, PBKDF2 600k
iterations, encrypt-then-HMAC-SHA256); `secret import` detects the header and
reads both v1 and v2.

## Context

`secret export` / `secret import` is a documented portability feature: it
converts a TPM-bound credential into a passphrase-encrypted blob so it can be
moved to another machine and re-imported. That is precisely a "sensitive file,
stored and transported off-host" scenario.

The original export used `openssl enc -aes-256-cbc` with a passphrase:

- **No integrity** — CBC without authentication; a tampered or truncated blob is
  not detected on decrypt.
- **Weak KDF** — OpenSSL's low default PBKDF2 iteration count (no `-pbkdf2 -iter`).

Because the blob is meant to leave the host and be stored, these are real
weaknesses rather than a theoretical concern about an ephemeral in-process path.

## Decision

**Move `secret export` to a versioned, integrity-protected format, keeping
backward-compatible import of existing blobs.**

- v2 is AES-256 with `-pbkdf2 -iter 600000` plus an explicit HMAC-SHA256 over the
  ciphertext (encrypt-then-MAC).
- `secret import` detects the format version by header and decrypts either legacy
  v1 (`aes-256-cbc`, unauthenticated) or v2, so existing exports stay restorable.

`age` was considered — cleaner modern AEAD — but adds a runtime dependency and a
harder format break. The versioned-OpenSSL path is the lower-cost upgrade and
keeps the stdlib-only posture.

## Rationale

A portability feature whose output is stored and transported must protect
integrity and use a modern KDF; the upgrade is cheap and, with version detection,
costs no migration. Leaving it unauthenticated was rejected because the threat
model — off-host storage and transport — is exactly where integrity matters.

## Consequences

- Export output format changes (v2 header); import stays compatible with v1.
- `docs/cli.md` and `docs/workloads.md` state the format version and the
  integrity guarantee.
- Implemented in `lib/cmd_secret.py`.
