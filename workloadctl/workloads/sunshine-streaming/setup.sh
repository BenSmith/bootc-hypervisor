#!/bin/bash
# Host setup for the sunshine-streaming workload.
#
# Usage:
#   setup.sh enable   — configure host prerequisites
#   setup.sh disable  — remove host prerequisites
#
# Idempotent in both directions. Called by workloadctl enable/disable.
set -euo pipefail

# Instance context comes from workloadctl (see host_setup_env() in
# lib/cmd_provision.py). Required, not defaulted: this bundle can be
# instantiated under another name via `init --as`, and falling back to the
# bundle name here would silently provision paths for a workload that doesn't
# exist.
WORKLOAD_NAME="${WORKLOAD_NAME:?not set — run via workloadctl enable/disable}"
WORKLOAD_USER="${WORKLOAD_USER:?not set — run via workloadctl enable/disable}"

# The udev-relay helper, resolved through the same /etc→/usr override chain
# workloadctl applies to setup.sh itself (resolve_control_file). We can't reach
# it via $0's dir: the override chain is per-file, so this script may be running
# from an operator override in ${WORKLOAD_INSTANCE_DIR} that carries only
# setup.sh, with no udev-relay beside it. Prefer an override copy, else the
# shipped bundle's — the shell mirror of ${WORKLOAD_INSTANCE_DIR}→${WORKLOAD_BUNDLE_DIR}.
UDEV_RELAY="${WORKLOAD_INSTANCE_DIR:?not set — run via workloadctl enable/disable}/udev-relay"
[ -f "$UDEV_RELAY" ] || UDEV_RELAY="${WORKLOAD_BUNDLE_DIR:?not set — run via workloadctl enable/disable}/udev-relay"

# Keyed to the instance, not the bundle: the relay unit is host-global, so two
# instances of this bundle would otherwise fight over one unit file.
RELAY_SERVICE="${WORKLOAD_NAME}-udev-relay.service"
RELAY_UNIT="/etc/systemd/system/${RELAY_SERVICE}"

# Homelab-CA-signed TLS cert for Sunshine's web UI (https://<host>:47990).
# The leaf is minted here on the host and mounted read-only into the container
# (./tls -> /etc/sunshine/tls); the CA *private key* never enters the container.
TLS_DIR="/var/lib/workloads/${WORKLOAD_NAME}/data/tls"
# Where to find the shared Homelab CA. The public root ships in the image trust
# store; the private key is the per-host 0400 file you place for the caddy
# workload (the homelab PKI authority). Override either with env vars.
CA_CERT="${HOMELAB_CA_CERT:-/etc/pki/ca-trust/source/anchors/homelab-root.crt}"
CA_KEY="${HOMELAB_CA_KEY:-/var/lib/workloads/caddy/data/homelab-root.key}"

# Sunshine's base port, read from the instance's own workload.toml rather than
# hardcoded here: a copy of the number in this script would silently drift from
# the port the container actually binds. This bundle uses Sunshine's built-in
# default unless SUNSHINE_PORT is set to coexist with a sibling host on the same
# machine. Every other port derives from the base (see the NOTE at end of enable()).
SUNSHINE_PORT="$(python3 - "${WORKLOAD_INSTANCE_DIR:?not set — run via workloadctl enable/disable}/workload.toml" <<'PY'
import sys, tomllib
with open(sys.argv[1], "rb") as fh:
    cfg = tomllib.load(fh)
print(cfg.get("container", {}).get("environment", {}).get("SUNSHINE_PORT", 47989))
PY
)"
SUNSHINE_HTTPS_PORT=$(( SUNSHINE_PORT - 5 ))
SUNSHINE_WEB_PORT=$(( SUNSHINE_PORT + 1 ))
SUNSHINE_RTSP_PORT=$(( SUNSHINE_PORT + 21 ))
SUNSHINE_UDP_LO=$(( SUNSHINE_PORT + 9 ))
SUNSHINE_UDP_HI=$(( SUNSHINE_PORT + 11 ))

# Static mDNS advertisement so Moonlight can discover this host. Keyed to the
# instance, not the bundle — two instances would otherwise overwrite one file.
AVAHI_SERVICE_DIR="/etc/avahi/services"
AVAHI_SERVICE="${AVAHI_SERVICE_DIR}/${WORKLOAD_NAME}-sunshine.service"

mint_tls_cert() {
    # Mint a Homelab-CA-signed leaf so the Sunshine web UI is browser-trusted
    # (no security warning) at https://<host>:47990. Done host-side so the CA
    # private key never lands in the streaming container, which runs arbitrary
    # games/browsers. Only the resulting leaf cert+key (scoped to this host)
    # are exposed, read-only, via the ./tls volume.
    if [ ! -r "$CA_CERT" ] || [ ! -r "$CA_KEY" ]; then
        echo "  [host] Homelab CA not found (cert=$CA_CERT key=$CA_KEY)."
        echo "         Skipping TLS cert — Sunshine keeps its self-signed cert"
        echo "         (browser warns at https://<host>:${SUNSHINE_WEB_PORT}). To enable a trusted"
        echo "         cert, place the Homelab CA key/cert or set HOMELAB_CA_CERT/"
        echo "         HOMELAB_CA_KEY, then re-run enable."
        return 0
    fi

    if [ -f "$TLS_DIR/cert.pem" ] && [ -f "$TLS_DIR/pkey.pem" ]; then
        echo "  [host] TLS cert already present ($TLS_DIR) — leaving as-is"
        return 0
    fi

    echo "  [host] Minting Homelab-CA-signed TLS cert for the Sunshine web UI..."
    mkdir -p "$TLS_DIR"

    # SAN: short hostname, its .local mDNS alias, every current LAN IP, loopback.
    # Host networking means these match exactly what the browser connects to.
    local host_s san ip
    host_s="$(hostname -s)"
    san="DNS:${host_s},DNS:${host_s}.local,DNS:localhost,IP:127.0.0.1,IP:::1"
    for ip in $(hostname -I 2>/dev/null); do
        san="${san},IP:${ip}"
    done

    local csr
    csr="$(mktemp)"
    openssl req -new -newkey rsa:2048 -nodes -keyout "$TLS_DIR/pkey.pem" \
        -subj "/CN=${host_s}" \
        -addext "subjectAltName=${san}" \
        -addext "keyUsage=digitalSignature,keyEncipherment" \
        -addext "extendedKeyUsage=serverAuth" \
        -out "$csr" 2>/dev/null
    openssl x509 -req -in "$csr" -CA "$CA_CERT" -CAkey "$CA_KEY" \
        -CAserial "$TLS_DIR/ca.srl" -CAcreateserial -days 3650 \
        -copy_extensions copy -out "$TLS_DIR/cert.pem" 2>/dev/null
    rm -f "$csr"

    # Root-owned, world-readable so the keep-id container can read them (the
    # workload user isn't provisioned until after this host hook, so we can't
    # chown to it; and a rootless `:U` mount can't chown root-written files).
    # workload-ensure-user's restorecon applies container_file_t. The key is a
    # low-value per-host leaf (re-mintable), not the CA key.
    chmod 0644 "$TLS_DIR/pkey.pem"
    chmod 0644 "$TLS_DIR/cert.pem"

    echo "  [host] Wrote CA-signed cert to $TLS_DIR."
    echo "         Moonlight clients must re-pair once (the pinned cert changed)."
}

publish_mdns() {
    # Sunshine advertises _nvstream._tcp via libavahi-client, which reaches
    # avahi-daemon over the system D-Bus socket. That socket is deliberately NOT
    # mounted into this container — it runs arbitrary games and browsers, the
    # same reason the Homelab CA private key stays out (see mint_tls_cert), and
    # the system bus is a far broader grant than mDNS. So publish host-side
    # instead: avahi-daemon picks up static service files from
    # /etc/avahi/services with no client involvement, and reloads on change.
    #
    # Trade-off: a static record is advertised even while the workload is
    # stopped, so Moonlight lists a stopped host and fails on connect rather
    # than not listing it. disable() removes the file.
    if [ ! -d "$AVAHI_SERVICE_DIR" ]; then
        echo "  [host] avahi service dir not found ($AVAHI_SERVICE_DIR) — skipping"
        echo "         mDNS. Moonlight won't discover this host; add it manually"
        echo "         as <ip>:${SUNSHINE_PORT}."
        return 0
    fi
    echo "  [host] Publishing mDNS record for Moonlight discovery..."
    cat > "$AVAHI_SERVICE" <<XML
<?xml version="1.0" standalone='no'?>
<!DOCTYPE service-group SYSTEM "avahi-service.dtd">
<!-- Managed by workloadctl (${WORKLOAD_NAME} setup.sh) — edits will be lost. -->
<service-group>
  <name>${WORKLOAD_NAME}</name>
  <service>
    <type>_nvstream._tcp</type>
    <port>${SUNSHINE_PORT}</port>
  </service>
</service-group>
XML
    chmod 0644 "$AVAHI_SERVICE"
}

enable() {
    # The uinput module autoload and the /dev/uinput group-access rule
    # (KERNEL=="uinput", GROUP="input", MODE="0660") ship in the hypervisor
    # image (/usr/lib/modules-load.d/uinput.conf +
    # /usr/lib/udev/rules.d/72-uinput-input.rules), so they persist across bootc
    # upgrades and can't be clobbered when a sibling streaming workload is
    # disabled. Just load the module now so /dev/uinput exists before the
    # container starts on a first enable that precedes a reboot; the image udev
    # rule already sets its perms to 0660 root:input.
    echo "  [host] Ensuring uinput kernel module is loaded..."
    modprobe uinput 2>/dev/null || true

    # Host-side udev relay. The container's libudev drops the host udevd's
    # hotplug events (sender UID maps to "nobody" in the container user
    # namespace), and a rootless host-networked container can't re-broadcast
    # them itself (no CAP_NET_ADMIN over the host net namespace). This host
    # service re-broadcasts input events with a corrected sender UID so
    # wayfire's libinput sees Sunshine's devices appear at runtime.
    echo "  [host] Installing udev input-event relay..."
    cat > "$RELAY_UNIT" <<UNIT
[Unit]
Description=Relay host udev input hotplug events into the ${WORKLOAD_NAME} container
After=network.target

[Service]
Type=simple
ExecStart=/usr/bin/python3 ${UDEV_RELAY} ${WORKLOAD_USER}
Restart=on-failure
RestartSec=3

[Install]
WantedBy=multi-user.target
UNIT
    systemctl daemon-reload
    systemctl enable --now "$RELAY_SERVICE"

    mint_tls_cert
    publish_mdns

    echo "  [host] Host setup complete"
    echo ""
    echo "  NOTE: Sunshine runs on base port ${SUNSHINE_PORT}. Open the firewall ports:"
    echo "    sudo firewall-cmd --permanent \\"
    echo "      --add-port={${SUNSHINE_HTTPS_PORT},${SUNSHINE_PORT},${SUNSHINE_WEB_PORT},${SUNSHINE_RTSP_PORT}}/tcp \\"
    echo "      --add-port=${SUNSHINE_UDP_LO}-${SUNSHINE_UDP_HI}/udp"
    echo "    sudo firewall-cmd --reload"
    echo "        (the udp range carries video/audio/input — pairing succeeds"
    echo "         without it, then the stream dies)"
    echo "        Finish setup at https://<host>:${SUNSHINE_WEB_PORT} — Sunshine has no"
    echo "        credentials until you create them there, and the pairing PIN"
    echo "        page is unreachable until you do."
}

disable() {
    # The uinput module autoload + /dev/uinput udev rule are image-owned and
    # shared by every game-streaming workload, so disable() leaves them in place.

    echo "  [host] Removing udev input-event relay..."
    if [ -e "$RELAY_UNIT" ]; then
        systemctl disable --now "$RELAY_SERVICE" 2>/dev/null || true
        rm -f "$RELAY_UNIT"
        systemctl daemon-reload
    fi

    if [ -e "$AVAHI_SERVICE" ]; then
        echo "  [host] Removing mDNS record..."
        rm -f "$AVAHI_SERVICE"
    fi

    echo "  [host] Host teardown complete"
}

case "${1:-}" in
    enable)  enable ;;
    disable) disable ;;
    *)
        echo "Usage: $0 {enable|disable}" >&2
        exit 1
        ;;
esac
