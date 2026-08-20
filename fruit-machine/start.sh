#!/usr/bin/env bash
#
# start.sh
#
# Builds the fruit-machine Docker image and runs it as a container that
# restarts automatically if Docker itself restarts or the host reboots
# (--restart unless-stopped), so it "runs on load" without needing to be
# started by hand each time. Token/leaderboard data, the session secret
# key, and the self-signed TLS cert all persist across container
# recreation via a named volume, not baked into the image.
#
# Serves both HTTP (port 8888) and HTTPS (port 8889, self-signed cert
# generated on first run by entrypoint.sh) at once, per the design note.
# Browsers will show a one-time trust warning on the HTTPS port, since
# the cert isn't CA-signed -- expected: this runs on both an internal-
# only host with no public DNS and a public one, and self-signed is the
# one approach that works identically on both.
#
# Usage: ./start.sh

set -euo pipefail

IMAGE_NAME="fruit-machine"
CONTAINER_NAME="fruit-machine"
HTTP_PORT=8888
HTTPS_PORT=8889
VOLUME_NAME="fruit-machine-data"

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

if ! command -v docker >/dev/null 2>&1; then
    echo "Error: docker is not installed." >&2
    exit 1
fi

echo "Building image ${IMAGE_NAME} ..."
docker build -t "$IMAGE_NAME" "$DIR"

if docker ps -a --format '{{.Names}}' | grep -qx "$CONTAINER_NAME"; then
    echo "Removing existing ${CONTAINER_NAME} container ..."
    docker rm -f "$CONTAINER_NAME" >/dev/null
fi

echo "Starting container ${CONTAINER_NAME} on ports ${HTTP_PORT} (HTTP) and ${HTTPS_PORT} (HTTPS) ..."
docker run -d \
    --name "$CONTAINER_NAME" \
    --restart unless-stopped \
    -p "${HTTP_PORT}:5000" \
    -p "${HTTPS_PORT}:5001" \
    -v "${VOLUME_NAME}:/data" \
    -e "FRUIT_MACHINE_ADMIN_PASSWORD=${FRUIT_MACHINE_ADMIN_PASSWORD:-fruit-admin-2026}" \
    "$IMAGE_NAME"

echo "Done. Fruit machine running at:"
echo "  http://<host>:${HTTP_PORT}/"
echo "  https://<host>:${HTTPS_PORT}/ (self-signed cert -- browser will warn once)"
