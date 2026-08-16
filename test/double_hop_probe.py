#!/usr/bin/env python3
#
# Standalone probe for the double-hop (appliance -> switch) mechanism used
# by junos-interface-poe-bulk.sh, written using only python3 stdlib
# (pty/select/os/re). Use this on hosts that have python3 but not
# expect/tclsh and where installing packages isn't an option -- it exercises
# the identical login/state-check/change/report logic as the real script's
# expect block, just reimplemented over a raw pty instead of Tcl.
#
# Usage: python3 double_hop_probe.py <switch_user> <password> <appliance> <switch> <port> <action>
# Appliance hop is always root@<appliance> via pre-shared key (no password).

import os, pty, re, select, sys, time

def read_until(fd, patterns, timeout=20):
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
    switch_user, password, appliance, switch, port, action = sys.argv[1:7]
    desired = 'enabled' if action == 'enable' else 'disabled'

    op_prompt = re.compile(r'[%>] $', re.M)
    cfg_prompt = re.compile(r'[%#] $', re.M)
    pw_prompt = re.compile(r'[Pp]assword:')
    perm_denied = re.compile(r'[Pp]ermission [Dd]enied|[Aa]uthentication [Ff]ailed')

    ssh_opts = ['-o', 'StrictHostKeyChecking=no', '-o', 'UserKnownHostsFile=/dev/null']
    cmd = ['ssh', '-tt', *ssh_opts, f'root@{appliance}',
           'ssh', '-tt', *ssh_opts, f'{switch_user}@{switch}']
    print(f"=== spawning: {' '.join(cmd)} ===")

    pid, fd = pty.fork()
    if pid == 0:
        os.execvp(cmd[0], cmd)
        os._exit(1)

    # Single retry loop tolerant of 0, 1, or 2 password prompts -- some
    # appliances have pre-existing key trust to the switch and skip the
    # second prompt entirely, going straight from the appliance login to
    # the Junos operational prompt.
    pw_sent = 0
    while True:
        name, buf = read_until(fd, {'op': op_prompt, 'pw': pw_prompt, 'denied': perm_denied}, timeout=20)
        if name == 'op':
            break
        if name == 'pw':
            pw_sent += 1
            if pw_sent > 2:
                print(f"ERROR: too many password prompts, aborting\n{buf}")
                sys.exit(1)
            send(fd, password + '\r')
            continue
        print(f"ERROR: login failed or timed out ({name}), {pw_sent} password(s) sent\n{buf}")
        sys.exit(1)
    print(f"=== switch login OK via appliance double-hop ({pw_sent} password prompt(s)) ===")

    send(fd, 'set cli screen-length 0\r')
    name, buf = read_until(fd, {'op': op_prompt}, timeout=20)

    send(fd, f'show interfaces {port}\r')
    name, buf = read_until(fd, {'op': op_prompt}, timeout=20)
    if re.search(r'Administratively down', buf, re.I):
        state = 'disabled'
    elif re.search(r'Physical interface: [^,]+, Enabled', buf, re.I):
        state = 'enabled'
    else:
        state = 'unknown'
    print(f"Current interface state: {state}")

    if state == desired:
        print(f"Interface {port} is already {desired} -- skipping interface action.")
    else:
        send(fd, 'configure\r')
        read_until(fd, {'cfg': cfg_prompt}, timeout=20)
        if desired == 'disabled':
            send(fd, f'set interfaces {port} disable\r')
        else:
            send(fd, f'delete interfaces {port} disable\r')
        read_until(fd, {'cfg': cfg_prompt}, timeout=20)
        send(fd, 'commit\r')
        read_until(fd, {'cfg': cfg_prompt}, timeout=20)
        send(fd, 'exit\r')
        read_until(fd, {'op': op_prompt}, timeout=20)
        print("Waiting 9s for the change to take effect...")
        time.sleep(9)

    send(fd, f'show interfaces {port}\r')
    name, buf = read_until(fd, {'op': op_prompt}, timeout=20)
    m = re.search(r'Physical link is (Up|Down)', buf, re.I)
    print(f"Physical link: {m.group(1) if m else 'unknown'}")

    send(fd, 'exit\r')
    read_until(fd, {'eof': re.compile(r'(?!)')}, timeout=10)  # drain briefly
    print("Done.")

if __name__ == '__main__':
    main()
