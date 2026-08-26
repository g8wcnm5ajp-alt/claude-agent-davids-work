#!/bin/bash
# LegacySet.sh -- set|restore
#
# Enables (or reverts) the crypto needed to SSH from a RHEL/Rocky 9
# client to old network gear (e.g. Cisco switches only offering
# diffie-hellman-group1/14-sha1 KEX, CBC ciphers, and ssh-rsa/SHA-1
# host key signatures):
#   set     -- sets crypto-policy to LEGACY, and activates OpenSSL's
#              "legacy" provider (a separate switch from crypto-policy
#              -- SHA-1 RSA signature verification lives there in
#              OpenSSL 3.x, crypto-policy alone doesn't enable it).
#   restore -- reverts crypto-policy to DEFAULT and restores
#              openssl.cnf from the pristine backup 'set' made the
#              first time it ran.
# Idempotent both ways -- safe to run 'set' or 'restore' more than
# once. Must be run as root.
#
# After running either, open a FRESH shell/login before it takes
# effect -- an already-open session won't pick up the change.
#
# Not part of the forescout-lookup app itself -- a standalone utility
# for connecting FROM a RHEL/Rocky 9 box TO old network gear (kept in
# this repo at David's request rather than a session temp directory).
set -euo pipefail

OPENSSL_CNF="/etc/pki/tls/openssl.cnf"
# One fixed pristine-backup name, not a new timestamped file each run --
# 'set' only ever writes this ONCE (before its first edit), so 'restore'
# always has a genuine pre-change original to go back to, never an
# already-modified copy from a later re-run.
ORIG_BACKUP="${OPENSSL_CNF}.orig"

usage() {
    echo "Usage: $0 set|restore" >&2
    exit 1
}

require_root() {
    if [ "$(id -u)" -ne 0 ]; then
        echo "Must be run as root (sudo)." >&2
        exit 1
    fi
}

do_set() {
    echo "=== 1. Setting crypto-policy to LEGACY ==="
    update-crypto-policies --set LEGACY
    CURRENT_POLICY=$(update-crypto-policies --show)
    if [ "$CURRENT_POLICY" != "LEGACY" ]; then
        echo "ERROR: policy still shows '$CURRENT_POLICY' after --set LEGACY -- stopping." >&2
        exit 1
    fi
    echo "Policy confirmed: $CURRENT_POLICY"

    echo
    echo "=== 2. Enabling the OpenSSL legacy provider in $OPENSSL_CNF ==="
    if [ ! -f "$OPENSSL_CNF" ]; then
        echo "ERROR: $OPENSSL_CNF not found." >&2
        exit 1
    fi

    if [ ! -f "$ORIG_BACKUP" ]; then
        cp "$OPENSSL_CNF" "$ORIG_BACKUP"
        echo "Pristine backup saved to $ORIG_BACKUP"
    else
        echo "Pristine backup already exists at $ORIG_BACKUP -- not overwriting"
    fi

    if ! grep -q '^legacy[[:space:]]*=[[:space:]]*legacy_sect' "$OPENSSL_CNF"; then
        sed -i '/^default[[:space:]]*=[[:space:]]*default_sect/a legacy = legacy_sect' "$OPENSSL_CNF"
        echo "Added 'legacy = legacy_sect' to [provider_sect]"
    else
        echo "'legacy = legacy_sect' already present -- skipped"
    fi

    if ! grep -q '^\[legacy_sect\]' "$OPENSSL_CNF"; then
        printf '\n[legacy_sect]\nactivate = 1\n' >> "$OPENSSL_CNF"
        echo "Appended [legacy_sect] activate = 1"
    else
        echo "[legacy_sect] already present -- skipped"
    fi

    echo
    echo "=== 3. Verifying ==="
    if openssl list -providers | grep -q '^  legacy$'; then
        echo "Legacy provider: ACTIVE"
    else
        echo "WARNING: legacy provider does not show as active. Check $OPENSSL_CNF by hand." >&2
    fi

    cat <<'EOF'

Done. Open a NEW shell/login (this one won't pick up the change), then connect with:

    ssh -o KexAlgorithms=+diffie-hellman-group14-sha1 \
        -o Ciphers=+aes256-cbc,aes192-cbc,aes128-cbc \
        <switch-ip>

To make that permanent for one specific device, add to ~/.ssh/config instead:

    Host old-switch
        HostName <switch-ip>
        KexAlgorithms +diffie-hellman-group14-sha1
        Ciphers +aes256-cbc,aes192-cbc,aes128-cbc

Run this script with 'restore' later to undo both changes.
EOF
}

do_restore() {
    echo "=== 1. Reverting crypto-policy to DEFAULT ==="
    update-crypto-policies --set DEFAULT
    CURRENT_POLICY=$(update-crypto-policies --show)
    echo "Policy now: $CURRENT_POLICY"

    echo
    echo "=== 2. Restoring $OPENSSL_CNF ==="
    if [ -f "$ORIG_BACKUP" ]; then
        cp "$ORIG_BACKUP" "$OPENSSL_CNF"
        echo "Restored $OPENSSL_CNF from $ORIG_BACKUP"
    else
        echo "No pristine backup found at $ORIG_BACKUP -- nothing to restore from." >&2
        echo "(Was 'set' ever run on this box? $OPENSSL_CNF left untouched.)" >&2
        exit 1
    fi

    echo
    echo "=== 3. Verifying ==="
    if openssl list -providers | grep -q '^  legacy$'; then
        echo "NOTE: legacy provider still shows active in this shell -- a fresh shell/login will reflect the restored config."
    else
        echo "Legacy provider: no longer active"
    fi

    echo
    echo "Done. Open a NEW shell/login for the reverted policy to fully take effect."
}

require_root

case "${1:-}" in
    set)     do_set ;;
    restore) do_restore ;;
    *)       usage ;;
esac
