#!/usr/bin/env bash
#
# stop.sh
#
# Stops and removes the fruit-machine container (and its image, unless
# -k/--keep-image is given). The named data volume is left alone by
# default -- token/leaderboard data survives -- pass -v/--remove-volume
# to wipe it too.
#
# Usage: ./stop.sh [-k|--keep-image] [-v|--remove-volume]

set -euo pipefail

CONTAINER_NAME="fruit-machine"
IMAGE_NAME="fruit-machine"
VOLUME_NAME="fruit-machine-data"

KEEP_IMAGE=0
REMOVE_VOLUME=0

for arg in "$@"; do
    case "$arg" in
        -k|--keep-image) KEEP_IMAGE=1 ;;
        -v|--remove-volume) REMOVE_VOLUME=1 ;;
        *) echo "Usage: $0 [-k|--keep-image] [-v|--remove-volume]" >&2; exit 1 ;;
    esac
done

if docker ps -a --format '{{.Names}}' | grep -qx "$CONTAINER_NAME"; then
    echo "Stopping and removing container ${CONTAINER_NAME} ..."
    docker rm -f "$CONTAINER_NAME" >/dev/null
else
    echo "No container named ${CONTAINER_NAME} found."
fi

if [[ $KEEP_IMAGE -eq 0 ]]; then
    if docker images --format '{{.Repository}}' | grep -qx "$IMAGE_NAME"; then
        echo "Removing image ${IMAGE_NAME} ..."
        docker rmi "$IMAGE_NAME" >/dev/null
    fi
fi

if [[ $REMOVE_VOLUME -eq 1 ]]; then
    echo "Removing data volume ${VOLUME_NAME} (token/leaderboard data will be lost) ..."
    docker volume rm "$VOLUME_NAME" >/dev/null 2>&1 || true
fi

echo "Done."
