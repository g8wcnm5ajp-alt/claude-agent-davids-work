#!/usr/bin/env python3
#
# cisco-pull-logs-bulk.py
#
# Python3-stdlib-only equivalent of cisco-pull-logs-bulk.sh, for hosts
# (like the EM this normally runs on) that don't have expect/tclsh and
# where installing packages isn't an option. Uses only os/pty/select/re/
# argparse/getpass -- nothing beyond the standard library.
#
# Reads a CSV file where each row is:
#
#   appliance_ip,switch_ip
#
# For each row, SSHes to the appliance first, then hops from there to the
# Cisco switch, pulls "show logging", and saves it to a local file (local
# to wherever this script runs -- e.g. the EM) named:
#
#   SwitchLog-<appliance_ip>-<switch_ip>.log
#
# The appliance hop is always root@<appliance-ip>, run from the root
# account on the EM this script itself runs on -- that account's public
# key is already trusted by every appliance, so it needs neither a
# username flag nor a password. Only the switch hop needs a username and
# password (and possibly an enable password -- this script assumes it's
# the same as the login password).
#
# Usage:
#   ./cisco-pull-logs-bulk.py -s <switch-username> -f <csv-file> [-p <password>] [-o <output-dir>]
#
# CSV format: one row per line, no header, e.g.:
#   192.168.1.10,192.168.22.221
#   192.168.1.11,192.168.22.222
# Blank lines and lines starting with # are skipped. If the same switch IP
# appears more than once, later rows are skipped with a warning -- one log
# pull per switch.
#
# One row failing (bad login, unreachable host, etc.) does not stop the
# rest of the batch -- failures are collected and reported in a summary at
# the end, and the script exits non-zero if any row failed.
#
# Password resolution order: -p flag, then CISCO_PASSWORD env var, then an
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
import subprocess
import sys
import time

VERSION = "1.0.0"

SSH_TIMEOUT = 20

USER_PROMPT = re.compile(r'[^)]>\s*$')
EXEC_PROMPT = re.compile(r'[^)]#\s*$')
PW_PROMPT = re.compile(r'[Pp]assword:')
PERM_DENIED = re.compile(r'[Pp]ermission [Dd]enied|[Aa]uthentication [Ff]ailed|% ?[Ll]ogin invalid|% ?[Bb]ad (secrets|passwords)')


def supports_required_rsa_size():
    """Some Cisco switches (older IOS, e.g. Catalyst 3560) present a legacy
    RSA host key under 1024 bits. Modern OpenSSH (8.5+) hard-rejects that
    with "Bad server host key: Invalid key length" and there's no
    negotiable workaround except RequiredRSASize -- which is itself only
    understood by OpenSSH new enough to need it. Detect support with
    `ssh -G` (a config dry-run, no network needed) rather than assuming,
    since this script may run from appliances with a range of OpenSSH
    versions and an unrecognized -o option is a hard failure, not a
    no-op."""
    try:
        r = subprocess.run(['ssh', '-o', 'RequiredRSASize=512', '-G', 'localhost'],
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        return r.returncode == 0
    except OSError:
        return False


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
    switch_ssh_opts = ssh_opts + (['-o', 'RequiredRSASize=512'] if supports_required_rsa_size() else [])
    cmd = ['ssh', '-tt', *ssh_opts, f'root@{appliance}',
           'ssh', '-tt', *switch_ssh_opts, f'{switch_user}@{switch}']

    print(f"\n=== {appliance} -> {switch} ===")

    pid, fd = pty.fork()
    if pid == 0:
        os.execvp(cmd[0], cmd)
        os._exit(1)

    try:
        # Tolerant of however many password prompts appear (appliance
        # login, possibly enable mode, possibly a separate enable secret)
        # and of landing directly at privileged exec with no "enable" step
        # needed at all.
        pw_sent = 0
        while True:
            name, buf = read_until(fd, {'exec': EXEC_PROMPT, 'user': USER_PROMPT,
                                         'pw': PW_PROMPT, 'denied': PERM_DENIED}, SSH_TIMEOUT)
            if name == 'exec':
                break
            if name == 'user':
                send(fd, 'enable\r')
                continue
            if name == 'pw':
                pw_sent += 1
                if pw_sent > 3:
                    print("ERROR: too many password prompts, aborting")
                    return False
                send(fd, password + '\r')
                continue
            print(f"ERROR: login failed or timed out ({name}), {pw_sent} password(s) sent")
            return False

        send(fd, 'terminal length 0\r')
        read_until(fd, {'exec': EXEC_PROMPT}, SSH_TIMEOUT)

        send(fd, 'show logging\r')
        _, raw = read_until(fd, {'exec': EXEC_PROMPT}, SSH_TIMEOUT)

        send(fd, 'exit\r')
        read_until(fd, {}, 8)  # brief drain while the double-hop unwinds

        raw = raw.replace('\r\n', '\n').replace('\r', '\n')
        lines = raw.split('\n')
        clean = '\n'.join(lines[1:-1])

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
        description="CSV-driven bulk Cisco switch log collection via an appliance hop.")
    parser.add_argument('-s', dest='switch_user', required=True,
                         help='Username to log into the switch with (via the appliance)')
    parser.add_argument('-f', dest='csv_file', required=True,
                         help='CSV file: one row per line, "appliance_ip,switch_ip"')
    parser.add_argument('-p', dest='password', default=None,
                         help="Password (visible via `ps` to anyone on the box -- prefer $CISCO_PASSWORD or the prompt)")
    parser.add_argument('-o', dest='output_dir', default='.',
                         help='Directory to save logs into (default: current directory)')
    args = parser.parse_args()

    print(f"cisco-pull-logs-bulk.py v{VERSION}")

    if not shutil.which('ssh'):
        print("Error: this script requires 'ssh' to be installed.", file=sys.stderr)
        sys.exit(1)

    if not os.path.isfile(args.csv_file):
        print(f"Error: file not found: {args.csv_file}", file=sys.stderr)
        sys.exit(1)

    if not os.path.isdir(args.output_dir):
        print(f"Error: output directory not found: {args.output_dir}", file=sys.stderr)
        sys.exit(1)

    password = args.password or os.environ.get('CISCO_PASSWORD')
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
