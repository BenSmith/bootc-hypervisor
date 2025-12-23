# Podman 4 compatible fork of https://gitlab.com/fedora/bootc/base-images
# Modified to work around podman 4.x limitations - (no heredoc, read-only bind mounts)
# github is using podman 4, fedora 43/gitlab is using 5

ARG REPOS_IMAGE=quay.io/fedora/fedora:rawhide
ARG BUILDER_IMAGE=quay.io/fedora/fedora:rawhide

FROM $REPOS_IMAGE as repos

FROM $BUILDER_IMAGE as builder
RUN dnf -y install rpm-ostree selinux-policy-targeted python3
ARG MANIFEST=fedora-standard

COPY . /src
RUN chmod -R a=rX,u+w /src  # Fix permissions, allow world-read
WORKDIR /src
RUN rm -vf /src/*.repo      # Remove hardcoded .repo files, use base image repos

# PODMAN 4/GitHub Actions: Copy repos to writable location instead of bind mount
COPY --from=repos / /repos

# PODMAN 4 COMPATIBILITY: Inline sh -c instead of heredoc
RUN --mount=type=cache,id=bootc-base-image-cache,target=/cache sh -c 'set -xeuo pipefail && \
    ./install-manifests && \
    install -m 0755 -t /usr/libexec ./bootc-base-imagectl && \
    /usr/libexec/bootc-base-imagectl list >/dev/null && \
    /usr/libexec/bootc-base-imagectl build-rootfs --cachedir=/cache --reinject --manifest=${MANIFEST} /repos /target-rootfs'

# get the keys for github keyless signing
FROM alpine AS keyless-keys

RUN apk add curl jq openssl

# writes to ~/.sigstore/root/
RUN curl -o cosign -L "https://github.com/sigstore/cosign/releases/latest/download/cosign-linux-amd64" && \
    chmod +x cosign && \
    ./cosign initialize

# Extract the base64-encoded cosign public key from trusted_root.json,
# decode it from base64, convert from DER to PEM format
RUN mkdir -p /etc/pki/rekor && \
    cat ~/.sigstore/root/tuf-repo-cdn.sigstore.dev/targets/trusted_root.json | \
    jq -r '.tlogs[0].publicKey.rawBytes' | \
    base64 -d > rekor_temp.pub && \
    openssl pkey -pubin -inform DER -in rekor_temp.pub -outform PEM -out /etc/pki/rekor/rekor.pub

# same with the fulcio cert
RUN mkdir -p /etc/pki/fulcio && \
    cat ~/.sigstore/root/tuf-repo-cdn.sigstore.dev/targets/trusted_root.json | \
    jq -r '.certificateAuthorities[0].certChain.certificates[0].rawBytes' | \
    base64 -d > fulcio_temp.crt && \
    openssl x509 -inform DER -in fulcio_temp.crt -outform PEM -out /etc/pki/fulcio/fulcio.crt.pem


FROM scratch
COPY --from=builder /target-rootfs/ /
COPY --from=keyless-keys /etc/pki /etc/pki
COPY policy.json /etc/containers/policy.json

# Bootc labels and metadata
LABEL containers.bootc 1
LABEL bootc.diskimage-builder quay.io/centos-bootc/bootc-image-builder
ENV container=oci
STOPSIGNAL SIGRTMIN+3
CMD ["/usr/sbin/init"]
