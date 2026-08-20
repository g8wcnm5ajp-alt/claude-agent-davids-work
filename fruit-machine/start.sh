#!/usr/bin/env bash
#
# start.sh
#
# Builds the fruit-machine Docker image and runs it as a container that
# restarts automatically if Docker itself restarts or the host reboots
# (--restart unless-stopped), so it "runs on load" without needing to be
# started by hand each time. Token/leaderboard data persists across
# container recreation via a named volume, not baked into the image.
#
# Usage: ./start.sh

set -euo pipefail

IMAGE_NAME="fruit-machine"
CONTAINER_NAME="fruit-machine"
HOST_PORT=8888
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

echo "Starting container ${CONTAINER_NAME} on port ${HOST_PORT} ..."
docker run -d \
    --name "$CONTAINER_NAME" \
    --restart unless-stopped \
    -p "${HOST_PORT}:5000" \
    -v "${VOLUME_NAME}:/data" \
    -e "FRUIT_MACHINE_ADMIN_PASSWORD=${FRUIT_MACHINE_ADMIN_PASSWORD:-fruit-admin-2026}" \
    "$IMAGE_NAME"

echo "Done. Fruit machine running at http://<host>:${HOST_PORT}/"
