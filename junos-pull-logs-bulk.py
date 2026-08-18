#!/usr/bin/env python3
#
# junos-pull-logs-bulk.py
#
# Python3-stdlib-only equivalent of junos-pull-logs-bulk.sh, for hosts
# (like the EM this normally runs on) that don't have expect/tclsh and
# where installing packages isn't an option. Uses only os/pty/select/re/
# argparse/getpass -- nothing beyond the standard library.
#
# Reads a CSV file where each row is:
#
#   appliance_ip,switch_ip
#
# For each row, SSHes to the appliance first, then hops from there to the
# Juniper switch, pulls "show log messages", and saves it to a local file
# (local to wherever this script runs -- e.g. the EM) named:
#
#   SwitchLog-<appliance_ip>-<switch_ip>.log
#
# The appliance hop is always root@<appliance-ip>, run from the root
# account on the EM this script itself runs on -- that account's public
# key is already trusted by every appliance, so it needs neither a
# username flag nor a password. Only the switch hop (an operator-class
# Junos CLI account, e.g. "claude") needs a username and password.
#
# Usage:
#   ./junos-pull-logs-bulk.py -s <switch-username> -f <csv-file> [-p <password>] [-o <output-dir>]
#
# CSV format: one row per line, no header, e.g.:
#   192.168.1.10,192.168.22.223
#   192.168.1.11,192.168.22.224
# Blank lines and lines starting with # are skipped. If the same switch IP
# appears more than once, later rows are skipped with a warning -- one log
# pull per switch.
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

VERSION = "1.0.0"

SSH_TIMEOUT = 20

OP_PROMPT = re.compile(r'[%>] $', re.M)
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


def run_switch(switch_user, password, appliance, switch, outfile):
    """Log in via the appliance hop, pull the log, save it. Returns True on
    success, False on failure (already printed an error)."""
    ssh_opts = ['-o', 'StrictHostKeyChecking=no', '-o', 'UserKnownHostsFile=/dev/null']
    cmd = ['ssh', '-tt', *ssh_opts, f'root@{appliance}',
           'ssh', '-tt', *ssh_opts, f'{switch_user}@{switch}']

    print(f"\n=== {appliance} -> {switch} ===")

    pid, fd = pty.fork()
    if pid == 0:
        os.execvp(cmd[0], cmd)
        os._exit(1)

    try:
        pw_sent = 0
        while True:
            name, buf = read_until(fd, {'op': OP_PROMPT, 'pw': PW_PROMPT, 'denied': PERM_DENIED}, SSH_TIMEOUT)
            if name == 'op':
                break
            if name == 'pw':
                pw_sent += 1
                if pw_sent > 2:
                    print("ERROR: too many password prompts, aborting")
                    return False
                send(fd, password + '\r')
                continue
            print(f"ERROR: login failed or timed out ({name}), {pw_sent} password(s) sent")
            return False

        send(fd, 'set cli screen-length 0\r')
        read_until(fd, {'op': OP_PROMPT}, SSH_TIMEOUT)

        send(fd, 'show log messages\r')
        _, raw = read_until(fd, {'op': OP_PROMPT}, SSH_TIMEOUT)

        send(fd, 'exit\r')
        read_until(fd, {}, 8)  # brief drain while the double-hop unwinds

        raw = raw.replace('\r\n', '\n').replace('\r', '\n')
        lines = raw.split('\n')[1:-1]
        # Some Junos platforms (e.g. dual-RE-style EX/QFX) print a routing-
        # engine mastership indicator ("{master:0}") plus a blank line
        # right before every prompt; strip that trailing block too if
        # present.
        if lines and re.match(r'^\{master:\d+\}$', lines[-1]):
            lines = lines[:-1]
        if lines and lines[-1].strip() == '':
            lines = lines[:-1]
        clean = '\n'.join(lines)

        with open(outfile, 'w') as fh:
            fh.write(clean + '\n')

        nlines = len(clean.split('\n'))
        print(f"Saved {nlines} line(s) to {outfile}")
        return True
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
        description="CSV-driven bulk Junos switch log collection via an appliance hop.")
    parser.add_argument('-s', dest='switch_user', required=True,
                         help='Username to log into the switch with (via the appliance)')
    parser.add_argument('-f', dest='csv_file', required=True,
                         help='CSV file: one row per line, "appliance_ip,switch_ip"')
    parser.add_argument('-p', dest='password', default=None,
                         help="Password (visible via `ps` to anyone on the box -- prefer $JUNOS_PASSWORD or the prompt)")
    parser.add_argument('-o', dest='output_dir', default='.',
                         help='Directory to save logs into (default: current directory)')
    args = parser.parse_args()

    print(f"junos-pull-logs-bulk.py v{VERSION}")

    if not shutil.which('ssh'):
        print("Error: this script requires 'ssh' to be installed.", file=sys.stderr)
        sys.exit(1)

    if not os.path.isfile(args.csv_file):
        print(f"Error: file not found: {args.csv_file}", file=sys.stderr)
        sys.exit(1)

    if not os.path.isdir(args.output_dir):
        print(f"Error: output directory not found: {args.output_dir}", file=sys.stderr)
        sys.exit(1)

    password = args.password or os.environ.get('JUNOS_PASSWORD')
    if not password:
        password = getpass.getpass(f"Password for {args.switch_user}@switch: ")

    total = 0
    ok = 0
    failed = 0
    failed_rows = []
    seen_switches = set()

    with open(args.csv_file) as f:
        for raw in f:
            line = raw.strip()
            if not line or line.startswith('#'):
                continue

            parts = trim_row(line)
            if len(parts) != 2 or not all(parts):
                print(f"Error: malformed row (need appliance_ip,switch_ip): {line}", file=sys.stderr)
                failed += 1
                failed_rows.append(f"{line} (malformed)")
                continue

            appliance, switch = parts
            if switch in seen_switches:
                print(f"Warning: switch {switch} already processed -- skipping duplicate row", file=sys.stderr)
                continue
            seen_switches.add(switch)

            total += 1
            outfile = os.path.join(args.output_dir, f"SwitchLog-{appliance}-{switch}.log")

            if run_switch(args.switch_user, password, appliance, switch, outfile):
                ok += 1
            else:
                failed += 1
                failed_rows.append(f"{appliance},{switch}")

    print(f"\n=== summary: {ok}/{total} switch(es) succeeded ===")
    if failed_rows:
        print("Failed rows:")
        for row in failed_rows:
            print(f"  - {row}")
        sys.exit(1)

    sys.exit(0)


if __name__ == '__main__':
    main()
