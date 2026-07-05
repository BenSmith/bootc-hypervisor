#!/bin/bash
# Host setup for the sunshine-game-streaming workload.
#
# Usage:
#   setup.sh enable   — configure host prerequisites
#   setup.sh disable  — remove host prerequisites
#
# Idempotent in both directions. Called by workloadctl enable/disable.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
RELAY_SERVICE="sunshine-udev-relay.service"
RELAY_UNIT="/etc/systemd/system/${RELAY_SERVICE}"
WORKLOAD_NAME="sunshine-game-streaming"
WORKLOAD_USER="_wl-${WORKLOAD_NAME}"

# Homelab-CA-signed TLS cert for Sunshine's web UI (https://<host>:47990).
# The leaf is minted here on the host and mounted read-only into the container
# (./tls -> /etc/sunshine/tls); the CA *private key* never enters the container.
TLS_DIR="/var/lib/workloads/${WORKLOAD_NAME}/data/tls"
# Where to find the shared Homelab CA. The public root ships in the image trust
# store; the private key is the per-host 0400 file you place for the caddy
# workload (the homelab PKI authority). Override either with env vars.
CA_CERT="${HOMELAB_CA_CERT:-/etc/pki/ca-trust/source/anchors/homelab-root.crt}"
CA_KEY="${HOMELAB_CA_KEY:-/var/lib/workloads/caddy/data/homelab-root.key}"

mint_tls_cert() {
    # Mint a Homelab-CA-signed leaf so the Sunshine web UI is browser-trusted
    # (no security warning) at https://<host>:47990. Done host-side so the CA
    # private key never lands in the streaming container, which runs arbitrary
    # games/browsers. Only the resulting leaf cert+key (scoped to this host)
    # are exposed, read-only, via the ./tls volume.
    if [ ! -r "$CA_CERT" ] || [ ! -r "$CA_KEY" ]; then
        echo "  [host] Homelab CA not found (cert=$CA_CERT key=$CA_KEY)."
        echo "         Skipping TLS cert — Sunshine keeps its self-signed cert"
        echo "         (browser warns at https://<host>:47990). To enable a trusted"
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
    # labwc's libinput sees Sunshine's devices appear at runtime.
    echo "  [host] Installing udev input-event relay..."
    cat > "$RELAY_UNIT" <<UNIT
[Unit]
Description=Relay host udev input hotplug events into the sunshine-game-streaming container
After=network.target

[Service]
Type=simple
ExecStart=/usr/bin/python3 ${SCRIPT_DIR}/udev-relay ${WORKLOAD_USER}
Restart=on-failure
RestartSec=3

[Install]
WantedBy=multi-user.target
UNIT
    systemctl daemon-reload
    systemctl enable --now "$RELAY_SERVICE"

    mint_tls_cert

    echo "  [host] Host setup complete"
    echo ""
    echo "  NOTE: Sunshine requires the following firewall ports:"
    echo "    sudo firewall-cmd --permanent --add-port={47984,47989,47990,48010}/tcp --add-port=47998-48000/udp"
    echo "    sudo firewall-cmd --reload"
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
