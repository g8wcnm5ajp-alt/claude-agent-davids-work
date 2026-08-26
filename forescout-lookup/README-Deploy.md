# ForeScout Tech Support Collector

Self-contained Forescout tech-support log collection tool, deployable directly onto an Enterprise Manager.

## Install

```
sudo ./Deploy.sh
```

Run this **on the EM itself**, as root, from inside this unpacked directory. It:

1. Generates a dedicated SSH keypair for this app and registers it in this EM's own `authorized_keys`, restricted to the existing `webapp-query.py` forced-command wrapper. The private key never leaves this box.
2. Copies this EM's own Apache SSL certificate so the app serves HTTPS with a cert your browser already trusts for this box.
3. Creates the `TechSupportBridge` docker network.
4. Loads and starts the container (auto-restarts on reboot).
5. Opens port 8443 through this EM's own firewall via `fstool fw addhook` (survives a firewall reactivation/reboot).

Safe to re-run — every step is idempotent.

## Access

```
https://<this-EM's-IP>:8443/
```

Default login: `admin` / `ForescoutTechSupport123` — you'll be forced to change this on first sign-in.

## Uninstall

```
sudo ./Remove.sh
```

Leaves `./data`, `./keys`, and `./certs` in place by default (so a later re-`Deploy.sh` doesn't lose history or need a fresh key). Pass `--purge` to remove those too.

## What's in this package

- `Deploy.sh` / `Remove.sh` — install/uninstall scripts.
- `image.tar` — the pre-built Docker image (`docker load`'d by `Deploy.sh`, nothing built at install time).
- `keys/`, `certs/`, `data/` — created by `Deploy.sh` on first install; not shipped in the package.
