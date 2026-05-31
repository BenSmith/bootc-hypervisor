# Podman 4 compatible fork of https://gitlab.com/fedora/bootc/base-images
# Modified to work around podman 4.x limitations - (no heredoc, read-only bind mounts)
# github is using podman 4, fedora 43/gitlab is using 5

ARG REPOS_IMAGE=quay.io/fedora/fedora:rawhide
ARG BUILDER_IMAGE=quay.io/fedora/fedora:rawhide

FROM $REPOS_IMAGE as repos

FROM $BUILDER_IMAGE as builder
RUN dnf -y install rpm-ostree selinux-policy-targeted python3
ARG MANIFEST=fedora-standard
ARG VERSION=rawhide

COPY . /src
RUN chmod -R a=rX,u+w /src  # Fix permissions, allow world-read
WORKDIR /src
RUN rm -vf /src/*.repo      # Remove hardcoded .repo files, use base image repos

# PODMAN 4/GitHub Actions: Copy repos to writable location instead of bind mount
COPY --from=repos / /repos
RUN rm -f /etc/yum.repos.d/fedora-cisco-openh264.repo || true

# PODMAN 4 COMPATIBILITY: Inline sh -c instead of heredoc
RUN --mount=type=cache,id=bootc-base-image-cache-${VERSION},target=/cache sh -c 'set -xeuo pipefail && \
    ./install-manifests && \
    install -m 0755 -t /usr/libexec ./bootc-base-imagectl && \
    /usr/libexec/bootc-base-imagectl list >/dev/null && \
    /usr/libexec/bootc-base-imagectl build-rootfs --cachedir=/cache --reinject --manifest=${MANIFEST} /repos /target-rootfs'

FROM scratch
COPY --from=builder /target-rootfs/ /
COPY cosign.pub /etc/pki/containers/cosign.pub
COPY policy.json /etc/containers/policy.json

# Bootc labels and metadata
LABEL containers.bootc 1
LABEL ostree.bootable 1
LABEL bootc.diskimage-builder quay.io/centos-bootc/bootc-image-builder

LABEL org.opencontainers.image.title="Minimal Fedora bootc Image"
LABEL org.opencontainers.image.description="Build of Fedora bootc minimal"

ENV container=oci

STOPSIGNAL SIGRTMIN+3
CMD ["/usr/sbin/init"]
