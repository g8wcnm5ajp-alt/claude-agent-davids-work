#!/bin/bash
#
# Deploy.sh -- installs the Forescout Tech Support Collector directly
# on THIS Enterprise Manager. Run this ON the EM, as root, from inside
# the unpacked ForescoutTechSupportCollector directory.
#
# What this does, in order (each step is idempotent -- safe to re-run
# this whole script, e.g. to pick up a renewed cert or redeploy a
# newer image, without duplicating anything):
#   1. Generates a dedicated SSH keypair for this app (if one doesn't
#      already exist) and registers its public half in this EM's own
#      authorized_keys, restricted to ONLY the existing webapp-query.py
#      forced-command wrapper (already deployed on this EM, used by
#      this app the same way as any other caller) -- the private key
#      never leaves this box.
#   2. Uses a cert.pem + private.key already dropped into certs/ by
#      hand (e.g. one issued by your own internal CA), or falls back
#      to copying this EM's own Apache SSL cert if none was supplied.
#   3. Creates the TechSupportBridge docker network.
#   4. Loads and runs the bundled image -- auto-restarts on reboot.
#   5. Opens the app's port through this EM's own built-in firewall via
#      fstool's own addhook mechanism (survives an EM firewall
#      reactivation/reboot, unlike a raw iptables rule added by hand).
#
# Usage: sudo ./Deploy.sh
set -euo pipefail

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
IMAGE_NAME="forescout-tech-support-collector"
CONTAINER_NAME="forescout-tech-support-collector"
NETWORK_NAME="TechSupportBridge"
HTTPS_PORT=8443
FW_HOOK_NAME="ForeScoutTechSupportHelper"

KEY_DIR="${DIR}/keys"
KEY_FILE="${KEY_DIR}/webapp_query_rsa"
KEY_COMMENT="forescout-tech-support-collector-em"
CERT_DIR="${DIR}/certs"
DATA_DIR="${DIR}/data"
APACHE_CERT="/usr/local/forescout/etc/net_portal_ssl/cert.pem"
APACHE_KEY="/usr/local/forescout/etc/net_portal_ssl/private.key"
AUTHORIZED_KEYS="/root/.ssh/authorized_keys"
WEBAPP_QUERY_WRAPPER="/root/scripts/webapp-query/webapp-query.py"

if [ "$(id -u)" -ne 0 ]; then
    echo "Must be run as root." >&2
    exit 1
fi

if ! command -v docker >/dev/null 2>&1; then
    echo "Error: docker is not installed on this EM." >&2
    exit 1
fi

if [ ! -f "${DIR}/image.tar" ]; then
    echo "Error: ${DIR}/image.tar not found -- run this from inside the unpacked package." >&2
    exit 1
fi

if [ ! -x "$(command -v fstool)" ]; then
    echo "Error: fstool not found -- this script must run on a Forescout EM." >&2
    exit 1
fi

echo "=== 1. SSH key for this app's own EM->appliance/EM calls ==="
mkdir -p "$KEY_DIR"
if [ ! -f "$KEY_FILE" ]; then
    ssh-keygen -t rsa -b 4096 -f "$KEY_FILE" -N "" -C "$KEY_COMMENT" -q
    echo "Generated new keypair at $KEY_FILE"
else
    echo "Keypair already exists at $KEY_FILE -- not regenerating"
fi
chmod 600 "$KEY_FILE"
chmod 644 "${KEY_FILE}.pub"

if [ ! -f "$WEBAPP_QUERY_WRAPPER" ]; then
    echo "Error: $WEBAPP_QUERY_WRAPPER not found -- deploy webapp-query.py to this EM first." >&2
    exit 1
fi

mkdir -p "$(dirname "$AUTHORIZED_KEYS")"
touch "$AUTHORIZED_KEYS"
if ! grep -q "$KEY_COMMENT" "$AUTHORIZED_KEYS" 2>/dev/null; then
    PUBKEY_CONTENT="$(cat "${KEY_FILE}.pub")"
    echo "command=\"${WEBAPP_QUERY_WRAPPER}\",no-port-forwarding,no-X11-forwarding,no-agent-forwarding,no-pty ${PUBKEY_CONTENT}" \
        >> "$AUTHORIZED_KEYS"
    chmod 600 "$AUTHORIZED_KEYS"
    echo "Registered restricted key in $AUTHORIZED_KEYS"
else
    echo "Key already registered in $AUTHORIZED_KEYS -- skipped"
fi

echo
echo "=== 2. HTTPS certificate ==="
mkdir -p "$CERT_DIR"
KEY_PASSWORD_FILE="${CERT_DIR}/key_password.txt"

if [ -f "$CERT_DIR/cert.pem" ] && [ -f "$CERT_DIR/private.key" ]; then
    echo "Using cert/key already in $CERT_DIR from a previous run -- not touching them"
    echo "(delete $CERT_DIR/cert.pem and $CERT_DIR/private.key first if you want to supply new ones)"
else
    echo "No cert/key found in $CERT_DIR yet."
    echo
    echo "  1) I have a cert + key to use (e.g. one issued by our own internal CA)"
    echo "  2) Use this EM's own Apache web cert (${APACHE_CERT})"
    echo "  3) Generate a self-signed cert (browsers will show a one-time trust warning)"
    echo
    read -r -p "Choice [1/2/3]: " CERT_CHOICE

    case "$CERT_CHOICE" in
        1)
            read -r -p "Path to the certificate (PEM, leaf or full chain): " USER_CERT_PATH
            read -r -p "Path to the private key (PEM): " USER_KEY_PATH
            if [ ! -f "$USER_CERT_PATH" ] || [ ! -f "$USER_KEY_PATH" ]; then
                echo "Error: could not find one or both of those files." >&2
                exit 1
            fi
            cp "$USER_CERT_PATH" "$CERT_DIR/cert.pem"
            cp "$USER_KEY_PATH" "$CERT_DIR/private.key"
            chmod 600 "$CERT_DIR/private.key"
            echo "Installed the supplied cert/key into $CERT_DIR"
            ;;
        2)
            if [ ! -f "$APACHE_CERT" ] || [ ! -f "$APACHE_KEY" ]; then
                echo "Error: $APACHE_CERT / $APACHE_KEY not found -- this isn't a real EM, or the cert has moved." >&2
                exit 1
            fi
            cp "$APACHE_CERT" "$CERT_DIR/cert.pem"
            cp "$APACHE_KEY" "$CERT_DIR/private.key"
            chmod 600 "$CERT_DIR/private.key"
            echo "Copied this EM's own Apache web cert into $CERT_DIR"
            ;;
        3)
            EM_IP_FOR_CERT="$(hostname -I 2>/dev/null | awk '{print $1}')"
            EM_FQDN="$(hostname -f 2>/dev/null || hostname)"
            openssl req -x509 -newkey rsa:4096 -nodes \
                -keyout "$CERT_DIR/private.key" -out "$CERT_DIR/cert.pem" \
                -days 825 -subj "/CN=${EM_FQDN}" \
                -addext "subjectAltName=DNS:${EM_FQDN},IP:${EM_IP_FOR_CERT:-127.0.0.1}" \
                >/dev/null 2>&1
            chmod 600 "$CERT_DIR/private.key"
            echo "Generated a self-signed cert for ${EM_FQDN} in $CERT_DIR"
            echo "(browsers will show a one-time trust warning for this cert -- expected)"
            ;;
        *)
            echo "Error: invalid choice." >&2
            exit 1
            ;;
    esac

    if grep -q "ENCRYPTED" "$CERT_DIR/private.key" 2>/dev/null; then
        read -r -s -p "That key is passphrase-protected -- enter its passphrase: " KEY_PASS
        echo
        printf "%s" "$KEY_PASS" > "$KEY_PASSWORD_FILE"
        chmod 600 "$KEY_PASSWORD_FILE"
    fi
fi

if grep -q "ENCRYPTED" "$CERT_DIR/private.key" 2>/dev/null && [ ! -f "$KEY_PASSWORD_FILE" ]; then
    echo "WARNING: $CERT_DIR/private.key looks passphrase-protected but $KEY_PASSWORD_FILE is missing." >&2
    echo "The app will fail to start until you create it:" >&2
    echo "    echo -n 'the-passphrase' > $KEY_PASSWORD_FILE && chmod 600 $KEY_PASSWORD_FILE" >&2
fi

echo
echo "=== 3. Docker network ==="
if ! docker network inspect "$NETWORK_NAME" >/dev/null 2>&1; then
    docker network create "$NETWORK_NAME" >/dev/null
    echo "Created docker network $NETWORK_NAME"
else
    echo "Docker network $NETWORK_NAME already exists -- skipped"
fi

echo
echo "=== 4. Loading and starting the container ==="
docker load -i "${DIR}/image.tar"

if docker ps -a --format '{{.Names}}' | grep -qx "$CONTAINER_NAME"; then
    echo "Removing existing $CONTAINER_NAME container ..."
    docker rm -f "$CONTAINER_NAME" >/dev/null
fi

mkdir -p "$DATA_DIR"

docker run -d \
    --name "$CONTAINER_NAME" \
    --network "$NETWORK_NAME" \
    --restart unless-stopped \
    --add-host=host.docker.internal:host-gateway \
    -p "${HTTPS_PORT}:5000" \
    -v "${KEY_DIR}:/keys:ro" \
    -v "${CERT_DIR}:/certs" \
    -v "${DATA_DIR}:/data" \
    -v "$(dirname "$APACHE_CERT"):/host-apache-certs:ro" \
    -e FORESCOUT_EM_HOST=host.docker.internal \
    -e FORESCOUT_SSL_CERT=/certs/cert.pem \
    -e FORESCOUT_SSL_KEY=/certs/private.key \
    -e FORESCOUT_SSL_KEY_PASSWORD_FILE=/certs/key_password.txt \
    "$IMAGE_NAME" >/dev/null

echo "Container $CONTAINER_NAME started"

echo
echo "=== 5. Opening the firewall port (fstool fw addhook) ==="
fstool fw delhook "$FW_HOOK_NAME" >/dev/null 2>&1 || true
fstool fw addhook "$FW_HOOK_NAME" "iptables -I INPUT -s 0.0.0.0/0 -m tcp -p tcp --dport ${HTTPS_PORT} -j ACCEPT"
if iptables -L INPUT -n | grep -q "dpt:${HTTPS_PORT}"; then
    echo "Firewall rule for port $HTTPS_PORT confirmed active"
else
    echo "WARNING: could not confirm the firewall rule via iptables -- check by hand." >&2
fi

EM_IP="$(hostname -I 2>/dev/null | awk '{print $1}')"
cat <<EOF

=== Done ===

  https://${EM_IP:-<this-EM-ip>}:${HTTPS_PORT}/

Default login: admin / ForescoutTechSupport123
(you will be forced to change this on first sign-in)

To uninstall later: sudo ./Remove.sh
EOF
