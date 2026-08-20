#!/bin/sh
#
# entrypoint.sh
#
# Generates a self-signed TLS cert/key on first run (persisted in /data,
# the same volume as the DB and the session secret key, so it doesn't
# regenerate -- and re-trigger a browser's "certificate changed" warning
# -- on every container restart), then execs gunicorn bound with it.
#
# Self-signed, not a CA-issued cert: this app runs on both an internal-
# only host (192.168.22.230, no public DNS) and a public one
# (www.yubique.com) -- a real Let's Encrypt cert only works for the
# latter, so self-signed is the one approach that works identically on
# both. Browsers will show a trust warning on first visit; that's
# expected for a self-signed cert, not a misconfiguration.

set -e

CERT=/data/cert.pem
KEY=/data/key.pem

if [ ! -f "$CERT" ] || [ ! -f "$KEY" ]; then
    echo "Generating self-signed TLS certificate ..."
    openssl req -x509 -nodes -newkey rsa:2048 \
        -keyout "$KEY" -out "$CERT" -days 3650 \
        -subj "/CN=${TLS_CN:-fruit-machine}"
    chmod 600 "$KEY"
fi

# Two gunicorn processes in one container: plain HTTP on 5000
# (backgrounded) and HTTPS on 5001 (foreground/exec'd, so it becomes PID 1
# and receives signals for graceful container shutdown). Gunicorn itself
# has no CLI option to serve one plaintext bind and one TLS bind from a
# single instance -- --certfile/--keyfile apply to every socket it binds.
# The backgrounded HTTP process isn't orphaned on `docker stop`: Docker
# kills every process in the container's namespace on teardown, not just
# PID 1.
gunicorn --bind 0.0.0.0:5000 --workers 2 app:app &
exec gunicorn --bind 0.0.0.0:5001 --certfile="$CERT" --keyfile="$KEY" --workers 2 app:app
