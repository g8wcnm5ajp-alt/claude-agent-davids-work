#!/usr/bin/env python3
#
# junos-interface-poe-bulk.py
#
# Python3-stdlib-only equivalent of junos-interface-poe-bulk.sh, for hosts
# (like the EM this normally runs on) that don't have expect/tclsh and
# where installing packages isn't an option. Uses only os/pty/select/re/
# argparse/getpass -- nothing beyond the standard library.
#
# Reads a CSV file where each row is:
#
#   appliance_ip,switch_ip,switch_port
#
# Rows are grouped by switch IP first: every port listed for the same
# switch is handled in a single login and, if anything on that switch
# actually needs to change, a single commit covering all of them -- not
# one connection and one commit per port. A switch where every listed
# port is already in the desired state gets no commit at all. For each
# switch group, SSHes to the appliance first, then hops from there to the
# Juniper switch, applying the same idempotent enable/disable logic
# (interface and/or PoE, skip-if-already-in-desired-state per port) as
# junos-interface-poe-bounce.sh / junos-interface-poe-bulk.sh.
#
# The appliance hop is always root@<appliance-ip>, run from the root
# account on the EM (Enterprise Manager) this script itself runs on --
# that account's public key is already trusted by every appliance, so it
# needs neither a username flag nor a password. Only the switch hop (an
# operator-class Junos CLI account, e.g. "claude") needs a username and
# password. The login sequence tolerates 0, 1, or 2 password prompts,
# since some appliances turn out to already have key trust to their own
# switch and skip the second prompt entirely.
#
# Usage:
#   ./junos-interface-poe-bulk.py -s <switch-username> -f <csv-file> -a enable|disable [-m both|interface|poe] [-w <settle-seconds>] [-p <password>] [-c]
#
# -c: for each switch group, after logging in and checking current state
# for every port on it, print exactly which commands are about to be sent
# (or that nothing needs to change) and pause for one y/N confirmation
# covering the whole switch before applying them. A "no" skips that
# switch's changes but continues the batch -- it's tracked separately from
# real failures in the summary (applied to every port on that switch).
#
# CSV format: one row per line, no header, e.g.:
#   192.168.1.10,192.168.22.223,ge-0/0/11
#   192.168.1.10,192.168.22.223,ge-0/0/12
#   192.168.1.11,192.168.22.224,ge-0/0/5
# Blank lines and lines starting with # are skipped. If the same switch IP
# appears with a different appliance IP on a later row, the first
# appliance seen for that switch wins and a warning is printed.
#
# One switch group failing (bad login, unreachable host, etc.) does not
# stop the rest of the batch -- failures are collected and reported in a
# summary at the end, and the script exits non-zero if any group failed.
#
# Password resolution order: -p flag, then JUNOS_PASSWORD env var, then an
# interactive prompt. Prefer the env var or the prompt over -p where
# possible -- a password passed on the command line is visible to anyone on
# the box running `ps`. This password is only ever needed for the switch
# login; the appliance hop is passwordless (key-based).

import argparse
import getpass
import os
import pty
import re
import select
import shutil
import sys
import time

VERSION = "1.2.0"

SETTLE_SECS_DEFAULT = 9
SSH_TIMEOUT = 20

# Operational-mode and configuration-mode prompts both end in these chars
OP_PROMPT = re.compile(r'[%>] $', re.M)
CFG_PROMPT = re.compile(r'[%#] $', re.M)
PW_PROMPT = re.compile(r'[Pp]assword:')
PERM_DENIED = re.compile(r'[Pp]ermission [Dd]enied|[Aa]uthentication [Ff]ailed')


def read_until(fd, patterns, timeout):
    """Read from fd until one of patterns matches the accumulated buffer,
    the process closes (EOF), or timeout elapses. Returns (name, buffer)."""
    buf = ''
    deadline = time.time() + timeout
    while time.time() < deadline:
        remaining = max(0, deadline - time.time())
        r, _, _ = select.select([fd], [], [], min(remaining, 0.5))
        if fd in r:
            try:
                chunk = os.read(fd, 65536).decode(errors='replace')
            except OSError:
                return 'EOF', buf
            if not chunk:
                return 'EOF', buf
            buf += chunk
            for name, pat in patterns.items():
                if pat.search(buf):
                    return name, buf
    return 'TIMEOUT', buf


def send(fd, s):
    os.write(fd, s.encode())


def run_switch_group(switch_user, password, appliance, switch, ports, mode, action, settle, confirm):
    """Handle every port on one switch in a single login + (at most) one
    commit. Returns a single group-level status -- 'ok', 'declined', or
    'failed' -- applied to all ports in the group in the caller's summary,
    rather than tracking each port independently: a login failure obviously
    affects every port on that switch equally, and a single combined -c
    confirmation covers every pending change for the switch at once, so
    per-port granularity beyond that wouldn't reflect anything the batch
    actually did differently port-by-port."""
    desired = 'enabled' if action == 'enable' else 'disabled'
    do_iface = mode in ('both', 'interface')
    do_poe = mode in ('both', 'poe')

    ssh_opts = ['-o', 'StrictHostKeyChecking=no', '-o', 'UserKnownHostsFile=/dev/null']
    # Hop 1: ssh to the appliance, whose remote command is itself an ssh to
    # the switch -- avoids ever needing to match the appliance's own
    # (unknown) shell prompt, since the Junos CLI just appears directly
    # once both hops are up.
    cmd = ['ssh', '-tt', *ssh_opts, f'root@{appliance}',
           'ssh', '-tt', *ssh_opts, f'{switch_user}@{switch}']

    print(f"\n=== {appliance} -> {switch} [{', '.join(ports)}] ===\n")

    pid, fd = pty.fork()
    if pid == 0:
        os.execvp(cmd[0], cmd)
        os._exit(1)

    try:
        # Tolerant of 0, 1, or 2 password prompts -- some appliances have
        # pre-existing key trust to the switch and skip straight from the
        # appliance login to the Junos operational prompt with no second
        # password prompt at all.
        pw_sent = 0
        while True:
            name, buf = read_until(fd, {'op': OP_PROMPT, 'pw': PW_PROMPT, 'denied': PERM_DENIED}, SSH_TIMEOUT)
            if name == 'op':
                break
            if name == 'pw':
                pw_sent += 1
                if pw_sent > 2:
                    print(f"ERROR: too many password prompts, aborting")
                    return 'failed'
                send(fd, password + '\r')
                continue
            print(f"ERROR: login failed or timed out ({name}), {pw_sent} password(s) sent")
            return 'failed'

        # Disable the CLI's "---(more)---" pager for this session -- without
        # this, any output taller than the terminal stalls waiting for a
        # keypress, and subsequent blind sends get consumed as pager
        # navigation keystrokes instead of reaching the CLI.
        send(fd, 'set cli screen-length 0\r')
        read_until(fd, {'op': OP_PROMPT}, SSH_TIMEOUT)

        # --- check current state of every port up front ---
        port_state = {}   # port -> {'iface_state', 'poe_state', 'need_iface', 'need_poe'}
        any_change = False
        for port in ports:
            info = {'need_iface': False, 'need_poe': False}
            if do_iface:
                send(fd, f'show interfaces {port}\r')
                _, buf = read_until(fd, {'op': OP_PROMPT}, SSH_TIMEOUT)
                # Real Junos reports a disabled interface as "Administratively
                # down", not "Disabled" -- only enabled interfaces say "Enabled".
                if re.search(r'Administratively down', buf, re.I):
                    iface_state = 'disabled'
                elif re.search(r'Physical interface: [^,]+, Enabled', buf, re.I):
                    iface_state = 'enabled'
                else:
                    iface_state = 'unknown'
                info['iface_state'] = iface_state
                print(f"[{port}] Current interface state: {iface_state}")
                if iface_state == desired:
                    print(f"[{port}] Interface is already {desired} -- skipping interface action.")
                else:
                    info['need_iface'] = True
                    any_change = True
            if do_poe:
                send(fd, f'show poe interface {port}\r')
                _, buf = read_until(fd, {'op': OP_PROMPT}, SSH_TIMEOUT)
                m = re.search(r'administrative status:\s*(Enabled|Disabled)', buf, re.I)
                poe_state = m.group(1).lower() if m else 'unknown'
                info['poe_state'] = poe_state
                print(f"[{port}] Current PoE state: {poe_state}")
                if poe_state == desired:
                    print(f"[{port}] PoE is already {desired} -- skipping PoE action.")
                else:
                    info['need_poe'] = True
                    any_change = True
            port_state[port] = info

        # Preview + confirm, if -c was given -- one combined plan covering
        # every port on this switch, not one prompt per port.
        declined = False
        if confirm:
            verb = 'set' if desired == 'disabled' else 'delete'
            n = 1
            print(f"\nFull command sequence for {appliance} -> {switch}:")

            def step(text):
                nonlocal n
                print(f"  {n}. {text}")
                n += 1

            def note(text):
                print(f"     {text}")

            step(f"ssh root@{appliance} -> ssh {switch_user}@{switch}   (done -- logged in, {pw_sent} password(s) sent)")
            step("set cli screen-length 0                        (done)")
            for port in ports:
                info = port_state[port]
                if do_iface:
                    step(f"show interfaces {port}                      (done -- current state: {info['iface_state']})")
                if do_poe:
                    step(f"show poe interface {port}                   (done -- current state: {info['poe_state']})")

            if not any_change:
                step(f"(nothing to change -- all ports already {desired})")
                for port in ports:
                    if do_iface:
                        note(f"would have run: {verb} interfaces {port} disable")
                    if do_poe:
                        note(f"would have run: {verb} poe interface {port} disable")
                if do_iface or do_poe:
                    note("                 commit")
            else:
                step("configure")
                for port in ports:
                    info = port_state[port]
                    if info['need_iface']:
                        step(f"{verb} interfaces {port} disable")
                    elif do_iface:
                        note(f"(interface {port} already {desired} -- would have run: {verb} interfaces {port} disable)")
                    if info['need_poe']:
                        step(f"{verb} poe interface {port} disable")
                    elif do_poe:
                        note(f"(PoE {port} already {desired} -- would have run: {verb} poe interface {port} disable)")
                step("commit                                          (one commit for all ports on this switch)")
                step("exit                                           (leave configuration mode)")

            for port in ports:
                step(f"show interfaces {port}                        (final report)")
                if do_poe:
                    step(f"show poe interface {port}                     (final report)")
            step("exit                                           (log out, unwinds both hops)")

            answer = input(f"\nContinue with {switch} [{', '.join(ports)}]? [y/N]: ")
            if not answer.strip().lower().startswith('y'):
                print(f"Skipped by user -- no changes made on {switch}.")
                any_change = False
                declined = True

        # Apply every port's pending change, in exactly one commit for the
        # whole switch -- not one commit per port.
        if any_change:
            send(fd, 'configure\r')
            read_until(fd, {'cfg': CFG_PROMPT}, SSH_TIMEOUT)

            for port in ports:
                info = port_state[port]
                verb = 'set' if desired == 'disabled' else 'delete'
                if info['need_iface']:
                    send(fd, f'{verb} interfaces {port} disable\r')
                    read_until(fd, {'cfg': CFG_PROMPT}, SSH_TIMEOUT)
                if info['need_poe']:
                    send(fd, f'{verb} poe interface {port} disable\r')
                    read_until(fd, {'cfg': CFG_PROMPT}, SSH_TIMEOUT)

            send(fd, 'commit\r')
            read_until(fd, {'cfg': CFG_PROMPT}, SSH_TIMEOUT)
            send(fd, 'exit\r')
            read_until(fd, {'op': OP_PROMPT}, SSH_TIMEOUT)

            print(f"Waiting {settle}s for the change to take effect...")
            time.sleep(settle)

        # Always report final status for every port (physical link only,
        # not the full dump).
        for port in ports:
            print(f"\n--- current state of {port} on {switch} ---\n")

            send(fd, f'show interfaces {port}\r')
            _, buf = read_until(fd, {'op': OP_PROMPT}, SSH_TIMEOUT)
            m = re.search(r'Physical link is (Up|Down)', buf, re.I)
            print(f"Physical link: {m.group(1) if m else 'unknown'}")

            if do_poe:
                send(fd, f'show poe interface {port}\r')
                _, buf = read_until(fd, {'op': OP_PROMPT}, SSH_TIMEOUT)
                m = re.search(r'operational status:\s*(ON|OFF)', buf, re.I)
                print(f"PoE operational status: {m.group(1) if m else 'unknown'}")

        send(fd, 'exit\r')
        read_until(fd, {}, 8)  # brief drain while the double-hop unwinds
        return 'declined' if declined else 'ok'
    finally:
        try:
            os.close(fd)
        except OSError:
            pass
        try:
            for _ in range(20):
                done_pid, _ = os.waitpid(pid, os.WNOHANG)
                if done_pid == pid:
                    break
                time.sleep(0.25)
        except ChildProcessError:
            pass


def trim_row(line):
    return [p.strip() for p in line.split(',')]


def main():
    parser = argparse.ArgumentParser(
        description="CSV-driven bulk Junos interface/PoE enable-disable via an appliance hop.")
    parser.add_argument('-s', dest='switch_user', required=True,
                         help='Username to log into the switch with (via the appliance)')
    parser.add_argument('-f', dest='csv_file', required=True,
                         help='CSV file: one row per line, "appliance_ip,switch_ip,switch_port"')
    parser.add_argument('-a', dest='action', required=True, choices=['enable', 'disable'],
                         help='Desired state')
    parser.add_argument('-m', dest='mode', default='both', choices=['both', 'interface', 'poe'],
                         help='What to apply it to (default: both)')
    parser.add_argument('-w', dest='settle', type=int, default=SETTLE_SECS_DEFAULT,
                         help=f'Seconds to wait after a change before reporting final status (default: {SETTLE_SECS_DEFAULT})')
    parser.add_argument('-p', dest='password', default=None,
                         help="Password (visible via `ps` to anyone on the box -- prefer $JUNOS_PASSWORD or the prompt)")
    parser.add_argument('-c', dest='confirm', action='store_true',
                         help='Preview the exact commands to be run per switch and pause for y/N confirmation before applying them')
    args = parser.parse_args()

    print(f"junos-interface-poe-bulk.py v{VERSION}")

    if not shutil.which('ssh'):
        print("Error: this script requires 'ssh' to be installed.", file=sys.stderr)
        sys.exit(1)

    if not os.path.isfile(args.csv_file):
        print(f"Error: file not found: {args.csv_file}", file=sys.stderr)
        sys.exit(1)

    password = args.password or os.environ.get('JUNOS_PASSWORD')
    if not password:
        password = getpass.getpass(f"Password for {args.switch_user}@switch: ")

    # Group rows by switch IP, preserving first-seen order, so every port on
    # the same switch is handled in one login and (at most) one commit
    # instead of reconnecting and committing per port.
    groups = []          # [(appliance, switch, [ports])]
    group_index = {}     # switch -> index into groups
    total = 0
    failed = 0
    failed_rows = []

    with open(args.csv_file) as f:
        for raw in f:
            line = raw.strip()
            if not line or line.startswith('#'):
                continue

            parts = trim_row(line)
            if len(parts) != 3 or not all(parts):
                print(f"Error: malformed row (need appliance_ip,switch_ip,switch_port): {line}", file=sys.stderr)
                failed += 1
                failed_rows.append(f"{line} (malformed)")
                continue

            appliance, switch, port = parts
            total += 1
            if switch in group_index:
                idx = group_index[switch]
                g_appliance, g_switch, g_ports = groups[idx]
                if g_appliance != appliance:
                    print(f"Warning: switch {switch} listed with different appliances "
                          f"({g_appliance} vs {appliance}) -- using {g_appliance}", file=sys.stderr)
                g_ports.append(port)
            else:
                group_index[switch] = len(groups)
                groups.append((appliance, switch, [port]))

    ok = 0
    declined = 0
    declined_rows = []

    for appliance, switch, ports in groups:
        status = run_switch_group(args.switch_user, password, appliance, switch, ports,
                                   args.mode, args.action, args.settle, args.confirm)
        if status == 'ok':
            ok += len(ports)
        elif status == 'declined':
            declined += len(ports)
            declined_rows.append(f"{appliance},{switch},[{', '.join(ports)}]")
        else:
            failed += len(ports)
            failed_rows.append(f"{appliance},{switch},[{', '.join(ports)}]")

    print(f"\n=== summary: {ok}/{total} rows succeeded ({declined} declined by user) ===")
    if declined_rows:
        print("Declined rows:")
        for row in declined_rows:
            print(f"  - {row}")
    if failed_rows:
        print("Failed rows:")
        for row in failed_rows:
            print(f"  - {row}")
        sys.exit(1)

    sys.exit(0)


if __name__ == '__main__':
    main()
