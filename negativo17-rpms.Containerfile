# negativo17's NVIDIA driver packages as an image: FROM scratch, holding a dnf
# repository at /repo (the RPMs, their repodata, and the key that signs them).
# publish-negativo-rpms.yml builds, signs and pushes it as
# registry.local/negativo-rpms; the Forgejo builds of
# hypervisor-nvidia-negativo17.Containerfile install from it rather than from
# negativo17.org, which throttles each connection to tens of KB/s, enough to
# time a CI dnf step out. The driver version is therefore whatever was last
# published: re-run the publish workflow to take a new one.
#
# Every RPM must carry a valid signature from negativo17/RPM-GPG-KEY-slaanesh
# (fingerprint 0C5D 0F47 0484 AE2F C40A 9B65 97F3 0089 93E8 909B), or the build
# stops. The image signature covers what was published; this covers what was
# downloaded.
#
# SEED names an image with RPMs at /repo (any image; it need not be signed):
# each package the set needs that the seed holds under its upstream file name is
# taken from there instead of downloaded. The check above applies to them all
# the same, so a seed can only save the download, never change what is trusted.
ARG FEDORA_VERSION=44
ARG SEED=seed-none

FROM scratch AS seed-none
COPY negativo17/packages /none

FROM ${SEED} AS seed

FROM fedora:${FEDORA_VERSION} AS fetch
COPY negativo17/ /negativo17/
# The set is negativo17/packages plus their requirements within fedora-nvidia,
# recursively; `--providers-of=requires` leaves out a seed nothing else
# requires, so the seeds are listed again. It is a subset of the real repo, so
# the consuming dnf can resolve to nothing it could not have chosen online.
# aria2c because the cap is per connection: 16 per file is ~15x dnf's one.
RUN --mount=type=bind,from=seed,target=/seed \
    dnf install -y --setopt=install_weak_deps=False aria2 createrepo_c && \
    rpmkeys --import /negativo17/RPM-GPG-KEY-slaanesh && \
    curl -fsSL https://negativo17.org/repos/fedora-nvidia.repo \
        -o /etc/yum.repos.d/fedora-nvidia.repo && \
    seeds=$(grep -v '^#' /negativo17/packages) && \
    query="dnf repoquery -q --repo=fedora-nvidia --arch=x86_64,noarch --latest-limit=1" && \
    { $query $seeds; $query --providers-of=requires --recursive $seeds; } | sort -u > /tmp/nevras && \
    $query --location $(cat /tmp/nevras) > /tmp/urls && \
    cat /tmp/nevras && \
    [ "$(wc -l < /tmp/urls)" -eq "$(wc -l < /tmp/nevras)" ] && \
    mkdir /repo && \
    while read -r url; do \
        if [ -f "/seed/repo/${url##*/}" ]; then cp "/seed/repo/${url##*/}" /repo/; else echo "$url"; fi; \
    done < /tmp/urls > /tmp/fetch && \
    echo "$(ls /repo | wc -l) from the seed, $(wc -l < /tmp/fetch) to download" && \
    { [ ! -s /tmp/fetch ] || aria2c -i /tmp/fetch -d /repo -x16 -s16 -j4 -k1M --file-allocation=none \
        --max-tries=10 --retry-wait=10 --console-log-level=warn --summary-interval=60; } && \
    [ "$(ls /repo/*.rpm | wc -l)" -eq "$(wc -l < /tmp/nevras)" ] && \
    rpm -K /repo/*.rpm | tee /tmp/checked && \
    ! grep -v ': digests signatures OK$' /tmp/checked && \
    cp /negativo17/RPM-GPG-KEY-slaanesh /repo/ && \
    createrepo_c /repo && \
    rpm -qp --qf '%{VERSION}\n' /repo/akmod-nvidia-*.rpm > /repo/VERSION && \
    dnf clean all

FROM scratch
COPY --from=fetch /repo /repo
