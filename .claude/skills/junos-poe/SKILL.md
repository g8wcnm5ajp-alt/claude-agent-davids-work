---
name: junos-poe
description: Enable or disable a Juniper switch interface and/or its PoE, either directly (junos-interface-poe-bounce.sh) or in bulk from a CSV via an appliance hop (junos-interface-poe-bulk.sh / .py). Use when asked to bring a switch port up/down, toggle PoE, check a port's real link state, or run one of these three scripts. Covers which variant to use on a given host, the credential model, safe testing, and deployment.
---

# Junos interface/PoE tool

Three scripts in the repo root, all version-stamped (`vX.Y.Z` printed at
the start of every run) and sharing the same idempotent design: check the
switch's real current state first, only send `set`/`delete` + `commit` for
whatever's actually wrong, always report final state.

## Which script to use

| Script | Target | Requires | Use when |
|---|---|---|---|
| `junos-interface-poe-bounce.sh` | one switch directly | `expect` | You're on a host with `expect` and SSH straight to the switch (no appliance hop) |
| `junos-interface-poe-bulk.sh` | many switches from a CSV, via an appliance hop | `expect` | Same as above but driving a whole fleet from `.210`-style credentials |
| `junos-interface-poe-bulk.py` | same as bulk.sh | python3 stdlib only (`pty`/`select`/`os`/`re`) | The EM (`192.168.22.210`) or any host that has no `expect`/`tclsh` and **cannot have packages installed** (restricted OS) |

`bulk.py` is a full reimplementation of `bulk.sh`'s logic, not a subset —
same CLI shape, same behavior, verified against the same real infrastructure.
Keep them in sync when either changes.

Both bulk tools group CSV rows by switch IP first: every port listed for
the same switch is handled in a single login and, if anything on that
switch actually needs to change, a *single* commit covering every port
that needs it -- not one connection and one commit per port. A switch
where every listed port is already in the desired state gets no commit
at all. If the same switch IP appears with a different appliance IP on a
later row, the first appliance seen for that switch wins (with a
warning) -- the CSV should be consistent about which appliance reaches
which switch.

**Never try to install `expect` (or anything else) to make the `.sh`
versions work on a restricted host.** Use `bulk.py` there instead. A prior
attempt to install `expect` via yum on the EM triggered a VM rollback —
that whole class of fix is off the table for EM/appliance hosts.

## Credential model (as deployed in this environment)

- **Single-target (`bounce.sh`)**: one username/password, straight to the switch. `-u`, `-H`, `-p`/`$JUNOS_PASSWORD`/prompt.
- **Bulk (`bulk.sh`/`bulk.py`)**: two different accounts, one hop each, sharing one password:
  - Appliance hop: always `root@<appliance-ip>`, key-based (no password, no username flag) — the EM's root account has a pre-shared key trusted by every appliance.
  - Switch hop: an operator-class Junos CLI account (e.g. `claude`), via `-s` + `-p`/`$JUNOS_PASSWORD`/prompt.
  - Login is tolerant of 0, 1, or 2 password prompts on the way in — some appliances already have key trust to their own switch and skip the second prompt entirely. Don't assume exactly two.
- Real Junos accounts matter: `root` on Junos drops into a raw shell (`%`), not the CLI (`>`). The switch account must be an operator-class account that lands directly in the Junos CLI, or none of the `show`/`configure` logic will work.

## CSV format (bulk tools)

One row per line, no header: `appliance_ip,switch_ip,switch_port`. Blank
lines and `#`-comments are skipped. `switches.csv` in the repo root holds
one known-good row for testing; the live copy on `.210`
(`/root/scripts/junos-repo/switches.csv`) is user-maintained — don't
overwrite it, diff first if something looks off.

## Key flags (all three scripts)

- `-a enable|disable` — required, desired state
- `-m both|interface|poe` — default `both`
- `-w <seconds>` — settle delay before the final status check (default 9; bumped up from 3→5→9 after live testing showed shorter waits weren't reliably enough for the physical link to renegotiate)
- `-c` — preview mode: print the *entire* command sequence (login, `set cli screen-length 0`, the `show` state-checks with their real results, the `configure`/`set-or-delete`/`commit`/`exit` block — or, if nothing needs to change, what it *would* have run — then the final report commands), and pause for a y/N confirm before anything that writes to the switch runs. Nothing that modifies switch config happens before that confirm; the login and `show` commands are read-only and unavoidable (the tool can't know whether to preview `set` or `delete` without checking real state first). In the bulk tools this is per-*switch-group* (covering every port on that switch in one combined plan and one prompt, matching the single-commit behavior), not per-row; a decline skips that whole switch's changes and is tracked separately from real failures in the summary, applied to every port in the group.
- `-p <password>` — least-preferred password source (visible via `ps`); prefer `$JUNOS_PASSWORD` or the interactive prompt.

## Known real-device gotchas already fixed in these scripts (don't re-break them)

- `StrictHostKeyChecking=no` + `UserKnownHostsFile=/dev/null` on every SSH hop. Plain `accept-new` isn't used because it needs OpenSSH 7.6+ and some management hosts still run 7.4. `UserKnownHostsFile=/dev/null` matters separately: `StrictHostKeyChecking=no` alone still refuses a *changed* host key (only auto-accepts *unknown* ones), and appliances/switches in this kind of fleet get reimaged or reassigned IPs often enough that a persistent known_hosts file causes real failures.
- `set cli screen-length 0` right after login, before any `show`. Without it, any output taller than the terminal triggers Junos's `---(more)---` pager, and blind `send`s after that get eaten as pager navigation keystrokes instead of reaching the CLI — this corrupted commands into garbage in live testing before the fix (nothing was committed, but it's a real risk class, not theoretical).
- Real Junos reports a disabled interface as **"Administratively down"**, not "Disabled". Only enabled interfaces say "Enabled". State-detection regexes must match on this, not on a generic Enabled/Disabled pair.
- The two `expect`-based scripts feed their whole Tcl script in via a heredoc on `stdin`, so by the time the script runs, plain `stdin` is already exhausted. The `-c` confirmation prompt reads from `/dev/tty` instead of `gets stdin` for exactly this reason — `bulk.py` doesn't have this problem since it's a normal process reading its own real stdin via `input()`.

## Testing safely

- `ge-0/0/11` on the reference test switch (`192.168.22.223`) is admin-up but link-down (nothing physically connected) — safe to bounce for real without affecting live traffic. `ge-0/0/0` was also link-down at first check but has since shown link-up (something got connected) -- **always verify with a read-only `show interfaces <port> terse` immediately before assuming a port is safe**, don't trust an old note. Confirm state before and after any real test either way, and leave it back the way you found it.
- To exercise the skip-vs-act decision logic without expect, `test/double_hop_probe.py` is a minimal python3-stdlib probe of just the double-hop + one interface check — useful on hosts without `expect` for confirming the mechanism works before trusting `bulk.py` fully.
- `test/run-mock-test.sh` + `test/mock-junos-cli.sh` give a full mock Junos CLI (stateful *per port*: tracks each interface's/PoE's admin state independently via `MOCK_IFACE_STATES`/`MOCK_POE_STATES`, supports `show poe interface`) for exercising `bounce.sh` without touching real hardware at all — the mock's wording (e.g. "Administratively down") is kept in sync with what real Junos actually says, specifically so this class of bug can't regress silently again.
- `test/run-mock-bulk-test.sh` exercises `bulk.sh`'s multi-port-per-switch grouping specifically: one login, at most one commit, only the ports that actually need it included. Mirror any grouping-logic change here in `bulk.py` too and re-verify against real hardware, since the mock only proves the command sequencing, not the double-hop itself.

## Deployment locations

- `192.168.22.230` ("certserv", CentOS 7): has `expect` installed; test host for the `.sh` variants.
- `192.168.22.210` ("farncaem", the EM): `/root/scripts/junos-repo/` — restricted OS, python3+ssh only, no `expect`, nothing installable. Deploy `bulk.py` here for real use; `bounce.sh`/`bulk.sh` can be copied here for reference but cannot run.
- After any pscp deploy, verify with `md5sum` on both ends — pscp has intermittently delivered stale content silently on this network without erroring.
