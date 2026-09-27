# Dev-container variant of ../pi-agent.Containerfile: same Fedora + tooling, but no PyCharm.
ARG FEDORA_VERSION=44
FROM registry.fedoraproject.org/fedora:${FEDORA_VERSION}

COPY rtk-0.42.4-1.x86_64.rpm /tmp/rtk.rpm

RUN dnf install -y --setopt=install_weak_deps=False \
        fd-find \
        fontconfig \
        freetype \
        gh \
        git \
        gzip \
        just \
        nodejs24 \
        # pi needs full ICU; without it, pi crashes (earendil-works/pi#6359)
        nodejs24-full-i18n \
        nodejs24-npm \
        openssl \
        podman \
        procps-ng \
        python3 \
        python3-pip \
        python3-rpm-macros \
        ripgrep \
        rpm-build \
        ruff \
        tar \
        uv \
        which \
        /tmp/rtk.rpm \
    && dnf clean all \
    && rm /tmp/rtk.rpm

RUN npm install -g --ignore-scripts @earendil-works/pi-coding-agent && \
    pi install --approve git:github.com/MasuRii/pi-rtk-optimizer@d155d253cb2f1358e34e717d47a82ebccb08cb8e

# Stay root: rootless podman maps container uid 0 to the host user, so files the
# IDE creates in the bind-mounted workspace come out owned by you on the host.
# A non-root uid would map into the subuid range and show up as an unknown owner.