#!/usr/bin/env python3
#
# junos-pull-logs.py
#
# Python3-stdlib-only equivalent of junos-pull-logs.sh, for hosts (like the
# EM this normally runs on, or any machine without expect/tclsh) where
# installing packages isn't an option. Uses only os/pty/select/re/argparse/
# getpass -- nothing beyond the standard library. Logs into a Juniper
# switch over SSH, pulls "show log messages", and saves the raw output to
# a local file (local to wherever this script runs, not the switch).
#
# Usage:
#   ./junos-pull-logs.py -u <username> -H <switch-ip> [-p <password>] [-o <output-file>]
#
# Password resolution, in order of preference: -p flag, then JUNOS_PASSWORD
# env var, then an interactive prompt. Prefer the env var or the prompt over
# -p where possible -- a password passed on the command line is visible to
# anyone on the box running `ps`.

import argparse
import datetime
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

# Operational-mode prompt ends in these chars
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


def main():
    parser = argparse.ArgumentParser(description="Pull a Junos switch's log to a local file.")
    parser.add_argument('-u', dest='username', required=True, help='Username to log into the switch with')
    parser.add_argument('-H', dest='host', required=True, help='Switch management IP or hostname')
    parser.add_argument('-p', dest='password', default=None,
                         help="Password (visible via `ps` to anyone on the box -- prefer $JUNOS_PASSWORD or the prompt)")
    parser.add_argument('-o', dest='outfile', default=None,
                         help='Local file to save the log to (default: <switch-ip>-junos-log-<timestamp>.txt)')
    args = parser.parse_args()

    print(f"junos-pull-logs.py v{VERSION}")

    if not shutil.which('ssh'):
        print("Error: this script requires 'ssh' to be installed.", file=sys.stderr)
        sys.exit(1)

    password = args.password or os.environ.get('JUNOS_PASSWORD')
    if not password:
        password = getpass.getpass(f"Password for {args.username}@{args.host}: ")

    outfile = args.outfile or f"{args.host}-junos-log-{datetime.datetime.now():%Y%m%d-%H%M%S}.txt"

    # "no" rather than "accept-new" for compatibility -- accept-new needs
    # OpenSSH 7.6+, and some management hosts still ship 7.4.
    ssh_opts = ['-o', 'StrictHostKeyChecking=no', '-o', 'UserKnownHostsFile=/dev/null']
    cmd = ['ssh', '-tt', *ssh_opts, f'{args.username}@{args.host}']

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
                    print("ERROR: too many password prompts, aborting", file=sys.stderr)
                    sys.exit(1)
                send(fd, password + '\r')
                continue
            print(f"ERROR: login failed or timed out ({name}), {pw_sent} password(s) sent", file=sys.stderr)
            sys.exit(1)

        # Disable the CLI's "---(more)---" pager -- without it, output
        # taller than the terminal stalls waiting for a keypress.
        send(fd, 'set cli screen-length 0\r')
        read_until(fd, {'op': OP_PROMPT}, SSH_TIMEOUT)

        print(f"\nPulling log from {args.host} ...\n")
        send(fd, 'show log messages\r')
        _, raw = read_until(fd, {'op': OP_PROMPT}, SSH_TIMEOUT)

        send(fd, 'exit\r')
        read_until(fd, {}, 5)

        # Strip the echoed command (first line) and the trailing prompt
        # (last line) so the saved file is just the log content itself.
        # Normalize \r\n to \n first since the device sends CRLF endings.
        raw = raw.replace('\r\n', '\n').replace('\r', '\n')
        lines = raw.split('\n')[1:-1]
        # Some Junos platforms (e.g. dual-RE-style EX/QFX) print a routing-
        # engine mastership indicator ("{master:0}") plus a blank line
        # right before every prompt; strip that trailing block too if
        # present, so it doesn't end up as noise at the end of the saved
        # log.
        if lines and re.match(r'^\{master:\d+\}$', lines[-1]):
            lines = lines[:-1]
        if lines and lines[-1].strip() == '':
            lines = lines[:-1]
        clean = '\n'.join(lines)

        with open(outfile, 'w') as fh:
            fh.write(clean + '\n')

        nlines = len(clean.split('\n'))
        print(f"Saved {nlines} line(s) to {outfile}")
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

    print("Done.")


if __name__ == '__main__':
    main()
