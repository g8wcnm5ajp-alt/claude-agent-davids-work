#!/usr/bin/env bash
#
# stop.sh
#
# Stops and removes the forescout-lookup container (and its image,
# unless -k/--keep-image is given). Never touches ./keys/ -- the
# restricted SSH key is provisioned by hand, not managed by this script.
#
# Usage: ./stop.sh [-k|--keep-image]

set -euo pipefail

CONTAINER_NAME="forescout-lookup"
IMAGE_NAME="forescout-lookup"

KEEP_IMAGE=0
for arg in "$@"; do
    case "$arg" in
        -k|--keep-image) KEEP_IMAGE=1 ;;
        *) echo "Usage: $0 [-k|--keep-image]" >&2; exit 1 ;;
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

echo "Done."
