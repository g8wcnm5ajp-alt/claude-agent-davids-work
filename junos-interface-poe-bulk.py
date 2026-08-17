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
# and for every row, SSHes to the appliance first, then hops from there to
# the Juniper switch, applying the same idempotent enable/disable logic
# (interface and/or PoE, skip-if-already-in-desired-state) as
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
# -c: for each row, after logging in and checking current state, print
# exactly which commands are about to be sent (or that nothing needs to
# change) and pause for a y/N confirmation before applying them. A "no"
# skips that row's changes but continues the batch -- it's tracked
# separately from real failures in the summary.
#
# CSV format: one row per line, no header, e.g.:
#   192.168.1.10,192.168.22.223,ge-0/0/11
#   192.168.1.11,192.168.22.224,ge-0/0/5
# Blank lines and lines starting with # are skipped.
#
# One row failing (bad login, unreachable host, etc.) does not stop the
# rest of the batch -- failures are collected and reported in a summary at
# the end, and the script exits non-zero if any row failed.
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

VERSION = "1.1.1"

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


def run_row(switch_user, password, appliance, switch, port, mode, action, settle, confirm):
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

    print(f"\n=== {appliance} -> {switch} {port} ===\n")

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

        need_iface_change = False
        need_poe_change = False

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
            print(f"Current interface state: {iface_state}")
            if iface_state == desired:
                print(f"Interface {port} is already {desired} -- skipping interface action.")
            else:
                need_iface_change = True

        if do_poe:
            send(fd, f'show poe interface {port}\r')
            _, buf = read_until(fd, {'op': OP_PROMPT}, SSH_TIMEOUT)
            m = re.search(r'administrative status:\s*(Enabled|Disabled)', buf, re.I)
            poe_state = m.group(1).lower() if m else 'unknown'
            print(f"Current PoE state: {poe_state}")
            if poe_state == desired:
                print(f"PoE on {port} is already {desired} -- skipping PoE action.")
            else:
                need_poe_change = True

        # Preview + confirm, if -c was given.
        declined = False
        if confirm:
            verb = 'set' if desired == 'disabled' else 'delete'
            steps = [f"ssh root@{appliance} -> ssh {switch_user}@{switch}   (done -- logged in, {pw_sent} password(s) sent)",
                     "set cli screen-length 0                        (done)"]
            if do_iface:
                steps.append(f"show interfaces {port}                      (done -- current state: {iface_state})")
            if do_poe:
                steps.append(f"show poe interface {port}                   (done -- current state: {poe_state})")
            if not need_iface_change and not need_poe_change:
                steps.append(f"(nothing to change -- {port} already {desired})")
            else:
                steps.append("configure")
                if need_iface_change:
                    steps.append(f"{verb} interfaces {port} disable")
                if need_poe_change:
                    steps.append(f"{verb} poe interface {port} disable")
                steps.append("commit")
                steps.append("exit                                           (leave configuration mode)")
            steps.append(f"show interfaces {port}                        (final report)")
            if do_poe:
                steps.append(f"show poe interface {port}                     (final report)")
            steps.append("exit                                           (log out, unwinds both hops)")

            print(f"\nFull command sequence for {appliance} -> {switch}:")
            for i, step in enumerate(steps, 1):
                print(f"  {i}. {step}")

            answer = input(f"\nContinue with {switch} {port}? [y/N]: ")
            if not answer.strip().lower().startswith('y'):
                print(f"Skipped by user -- no changes made for {switch} {port}.")
                need_iface_change = False
                need_poe_change = False
                declined = True

        # Apply whatever changes are actually needed, in one commit.
        if need_iface_change or need_poe_change:
            send(fd, 'configure\r')
            read_until(fd, {'cfg': CFG_PROMPT}, SSH_TIMEOUT)

            if need_iface_change:
                if desired == 'disabled':
                    send(fd, f'set interfaces {port} disable\r')
                else:
                    send(fd, f'delete interfaces {port} disable\r')
                read_until(fd, {'cfg': CFG_PROMPT}, SSH_TIMEOUT)

            if need_poe_change:
                if desired == 'disabled':
                    send(fd, f'set poe interface {port} disable\r')
                else:
                    send(fd, f'delete poe interface {port} disable\r')
                read_until(fd, {'cfg': CFG_PROMPT}, SSH_TIMEOUT)

            send(fd, 'commit\r')
            read_until(fd, {'cfg': CFG_PROMPT}, SSH_TIMEOUT)
            send(fd, 'exit\r')
            read_until(fd, {'op': OP_PROMPT}, SSH_TIMEOUT)

            print(f"Waiting {settle}s for the change to take effect...")
            time.sleep(settle)

        # Always report final status (physical link only, not the full dump).
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
                         help='Preview the exact commands to be run per row and pause for y/N confirmation before applying them')
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

    total = 0
    ok = 0
    failed = 0
    declined = 0
    failed_rows = []
    declined_rows = []

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
            status = run_row(args.switch_user, password, appliance, switch, port,
                              args.mode, args.action, args.settle, args.confirm)
            if status == 'ok':
                ok += 1
            elif status == 'declined':
                declined += 1
                declined_rows.append(f"{appliance},{switch},{port}")
            else:
                failed += 1
                failed_rows.append(f"{appliance},{switch},{port}")

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
