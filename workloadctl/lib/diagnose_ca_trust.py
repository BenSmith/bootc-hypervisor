"""
diagnose_ca_trust — is every configured trust anchor actually in the TLS bundle?

Two halves, split so the verdict is testable without a host: _ca_trust_facts()
reads a trust store relative to a root, ca_trust_anchor_check() judges what it
read. Host-wide state, reported per workload by the diagnose battery because
the failure it produces (a pull that cannot verify the registry) is read as the
workload's problem.
"""
import base64
import hashlib
from pathlib import Path


# Anchors an operator or the image installed, and the bundle that actually
# grants trust. Kept relative to a root so the probe can be pointed at a
# fixture tree, and so the /usr/etc comparison can reuse the same tail.
CA_ANCHOR_DIR = "pki/ca-trust/source/anchors"
CA_TLS_BUNDLE = "pki/ca-trust/extracted/pem/tls-ca-bundle.pem"


def _cert_fingerprints(data: bytes) -> set[str]:
    """SHA-256 over every certificate body in `data`, PEM or DER.

    Hashing the decoded body rather than the file means the two encodings of
    one certificate give one fingerprint, which is what lets an anchor be
    matched against a bundle that re-encoded it.

    Anything that is not a certificate yields the empty set: an operator's
    README in the anchor dir must not read as an untrusted anchor, and a
    truncated PEM must not raise. Discriminated on content, not extension —
    a DER certificate opens with the SEQUENCE tag 0x30, which no text file
    written by hand does.
    """
    marker = b"-----BEGIN CERTIFICATE-----"
    if marker not in data:
        return {hashlib.sha256(data).hexdigest()} if data[:1] == b"\x30" else set()
    out = set()
    for chunk in data.split(marker)[1:]:
        body, _, _ = chunk.partition(b"-----END CERTIFICATE-----")
        try:
            der = base64.b64decode(body, validate=False)
        except ValueError:
            continue
        if der:
            out.add(hashlib.sha256(der).hexdigest())
    return out


def _ca_trust_facts(root: Path = Path("/")):
    """Facts for ca_trust_anchor_check, or None when they can't be read.

    Returns (unbundled, local_anchors):

    - `unbundled` — anchor files whose certificates are absent from the
      extracted TLS bundle. This is the property that actually matters and it
      is mechanism-independent: it asks whether the trust the host was
      configured to have is in effect, not how it got out of step.
    - `local_anchors` — anchor files that differ from, or are absent from, the
      booted deployment's /usr/etc copy. None when there is no /usr/etc, i.e.
      no ostree /etc merge, so nothing can distinguish a locally added anchor
      from a shipped one. Only ever used to pick the fix, never the verdict.
    """
    anchor_dir = root / "etc" / CA_ANCHOR_DIR
    try:
        bundle_fps = _cert_fingerprints((root / "etc" / CA_TLS_BUNDLE).read_bytes())
        anchors = sorted(p for p in anchor_dir.iterdir() if p.is_file())
    except OSError:
        return None

    unbundled = []
    for path in anchors:
        try:
            fps = _cert_fingerprints(path.read_bytes())
        except OSError:
            continue
        if fps and not fps <= bundle_fps:
            unbundled.append(path.name)

    shipped_dir = root / "usr/etc" / CA_ANCHOR_DIR
    if not shipped_dir.is_dir():
        return unbundled, None
    local = []
    for path in anchors:
        shipped = shipped_dir / path.name
        try:
            if not shipped.is_file() or shipped.read_bytes() != path.read_bytes():
                local.append(path.name)
        except OSError:
            local.append(path.name)
    return unbundled, local


def ca_trust_anchor_check(
    unbundled: list[str],
    local_anchors: list[str] | None,
) -> tuple[bool, str, str | None]:
    """Verdict: is every configured trust anchor actually in the TLS bundle?

    The gap this closes is that installing an anchor and trusting it are two
    steps, and only the first one is visible. `update-ca-trust` extracts
    source/anchors into extracted/, but on a bootc host extracted/ is under
    /etc — so a host that ever ran `update-ca-trust` by hand has that path
    marked locally modified, ostree's 3-way merge keeps the host copy forever,
    and the image's extraction is discarded. A *new* anchor file still lands;
    nothing extracts it.

    The shape it catches: a root in source/anchors sitting beside an older
    extracted bundle that does not contain it, so every private-registry pull
    fails `unable to get local issuer certificate` while the anchor is plainly
    present. The symptom points away
    from the cause — the trust store looks correct — which is why this is a
    check and not a note.

    Asks the direct question rather than the mechanical one. "Does extracted/
    differ from /usr/etc" would also fire on a host with a deliberate local
    anchor, which is a permanent and correct divergence, and would report
    nothing on a non-ostree host. "Is this anchor in the bundle" is true or
    false everywhere, and `local_anchors` only chooses which repair to name.
    """
    if not unbundled:
        return (True, "Trust anchors are all in the extracted TLS bundle", None)

    named = ", ".join(unbundled)
    message = (f"Trust anchor not in the extracted bundle: {named} — the "
               f"anchor is installed but grants no trust, so TLS to anything "
               f"it signs fails with 'unable to get local issuer certificate'")

    if local_anchors is None:
        # No /usr/etc: no merge to converge back to, so regeneration is the
        # only repair and carries none of the divergence cost it does below.
        return (False, message, "sudo update-ca-trust")

    if local_anchors:
        # Restoring would silently drop these from the bundle — revoking trust
        # the operator added by hand is a worse failure than the one being
        # fixed, so it is not offered.
        return (False, message,
                f"sudo update-ca-trust  (this host carries locally added "
                f"anchors — {', '.join(local_anchors)} — so extracted/ cannot "
                f"be restored from the image without revoking them; it stays "
                f"locally modified and every later anchor rotation needs this "
                f"command again)")

    # Every anchor is the image's, so the bundle can be restored from the
    # booted deployment. That brings `ostree admin config-diff` clean, which
    # is the point: the merge tracks the image again and later anchor
    # rotations apply by themselves, instead of needing a repair each time.
    return (False, message,
            "sudo cp -a /usr/etc/pki/ca-trust/extracted/. "
            "/etc/pki/ca-trust/extracted/ && "
            "sudo restorecon -R /etc/pki/ca-trust/extracted  "
            "(restores the merge, so later anchor rotations self-apply; "
            "`sudo update-ca-trust` also restores trust but leaves this host "
            "diverged from the image forever)")
