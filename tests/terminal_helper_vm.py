#!/usr/bin/env python3
"""Real systemd/PTY qualification; runs only inside the disposable test VM."""
import array
import os
from pathlib import Path
import re
import socket
import struct
import subprocess
import time

SOCKET = '/run/vega-web-terminal.sock'
SERVICE_UID = 998
ALICE_UID = 1001
HOME = Path('/home/alice')


def wait_for(predicate, description, timeout=12):
    until = time.monotonic() + timeout
    while time.monotonic() < until:
        result = predicate()
        if result:
            return result
        time.sleep(0.05)
    raise AssertionError('timed out: ' + description)


def wheel(enabled=True):
    members = 'alice' if enabled else ''
    Path('/etc/group').write_text(
        'root:x:0:\nvega-web:x:998:\nwheel:x:1000:' + members
        + '\nalice:x:1001:\nbob:x:1002:\n')


def connect(username='alice', uid=SERVICE_UID, rejecting=False):
    # SO_PEERCRED is captured at connect, performed by the actual service UID.
    # Pass the established descriptor back to the root test observer so it can
    # inspect process/cgroup state without changing the helper's peer identity.
    parent, child = socket.socketpair()
    pid = os.fork()
    if pid == 0:
        parent.close()
        try:
            os.setgroups([uid])
            os.setgid(uid)
            os.setuid(uid)
            peer = socket.socket(socket.AF_UNIX)
            peer.connect(SOCKET)
            child.sendmsg([b'F'], [(socket.SOL_SOCKET, socket.SCM_RIGHTS,
                                    array.array('i', [peer.fileno()]))])
            peer.close()
            os._exit(0)
        except BaseException:
            os._exit(1)
    child.close()
    parent.settimeout(5)
    _, ancdata, _, _ = parent.recvmsg(1, socket.CMSG_SPACE(array.array('i').itemsize))
    _, status = os.waitpid(pid, 0)
    parent.close()
    assert status == 0 and len(ancdata) == 1, 'service UID failed to connect'
    descriptors = array.array('i')
    descriptors.frombytes(ancdata[0][2][:descriptors.itemsize])
    peer = socket.socket(fileno=descriptors[0])
    peer.settimeout(5)
    name = username.encode()
    try:
        peer.sendall(b'U' + struct.pack('!H', len(name)) + name)
    except (BrokenPipeError, ConnectionResetError):
        if not rejecting:
            raise
    return peer


def send(peer, command):
    data = command.encode()
    peer.sendall(b'I' + struct.pack('!I', len(data)) + data)


def receive_until(peer, marker, timeout=8):
    until = time.monotonic() + timeout
    result = b''
    peer.settimeout(0.2)
    while time.monotonic() < until:
        try:
            chunk = peer.recv(65536)
        except TimeoutError:
            continue
        assert chunk, f'helper closed before {marker!r}: {result[-500:]!r}'
        result += chunk
        if marker in result:
            return result
    raise AssertionError(f'missing {marker!r}: {result[-500:]!r}')


def status(pid):
    return dict(line.split(':', 1) for line in Path(f'/proc/{pid}/status').read_text().splitlines())


def members(group):
    result = set()
    if group.exists():
        for path in [group / 'cgroup.procs', *group.glob('**/cgroup.procs')]:
            try:
                result.update(int(pid) for pid in path.read_text().split())
            except FileNotFoundError:
                pass
    return result


def session():
    wheel()
    peer = connect()
    output = receive_until(peer, b'VM_READY> ')
    match = re.search(rb'VM_SHELL=(\d+)', output)
    assert match, output
    shell = int(match[1])
    supervisor = int(status(shell)['PPid'])
    group_name = Path(f'/proc/{shell}/cgroup').read_text().strip().split('::', 1)[1]
    group = Path('/sys/fs/cgroup') / group_name.lstrip('/')
    assert 'vega-web-terminal@' in group_name, group_name
    ids = members(group)
    brokers = [pid for pid in ids if int(status(pid)['Uid'].split()[1]) == SERVICE_UID]
    assert len(brokers) == 1, ids
    assert int(status(supervisor)['Uid'].split()[1]) == 0
    assert int(status(shell)['Uid'].split()[1]) == ALICE_UID
    assert set(map(int, status(brokers[0])['Groups'].split())) == {SERVICE_UID}
    print(f'VM_SESSION supervisor={supervisor}:root broker={brokers[0]}:998 shell={shell}:1001', flush=True)
    return peer, group, shell, brokers[0]


def cleanup(peer, group, close=True):
    started = time.monotonic()
    pids = members(group)
    if close:
        peer.close()
    wait_for(lambda: not members(group) and all(not Path(f'/proc/{pid}').exists() for pid in pids),
             'all terminal cgroup processes exit and are reaped')
    if not close:
        peer.settimeout(2)
        try:
            while peer.recv(65536):
                pass
        except ConnectionResetError:
            pass
        peer.close()
    print(f'VM_CLEANUP processes={len(pids)} seconds={time.monotonic() - started:.2f}', flush=True)


def test_identity_resize_disconnect():
    peer, group, _, _ = session()
    peer.sendall(b'R' + struct.pack('!HH', 101, 37))
    send(peer, "printf 'SIZE='; stty size; printf 'RESIZE_DONE\\n'\n")
    output = receive_until(peer, b'RESIZE_DONE\r\n')
    assert b'SIZE=37 101' in output, output
    cleanup(peer, group)


def test_resistant_descendants():
    peer, group, _, _ = session()
    marker = HOME / 'descendant.pid'
    marker.unlink(missing_ok=True)
    send(peer, "trap '' HUP TERM; setsid bash -c 'trap \"\" HUP TERM; echo $$ > /home/alice/descendant.pid; exec sleep 600' &\n")
    wait_for(marker.exists, 'escaped descendant starts')
    descendant = int(marker.read_text())
    wait_for(lambda: descendant in members(group), 'descendant belongs to service cgroup')
    assert os.getsid(descendant) == descendant, 'descendant must escape the shell session'
    cleanup(peer, group)
    assert not Path(f'/proc/{descendant}').exists()


def blocked_write(pid, socket_output=False):
    try:
        fields = Path(f'/proc/{pid}/syscall').read_text().split()
        if not fields or fields[0] != '1':  # x86_64 write syscall
            return False
        fd = int(fields[1], 0)
        target = os.readlink(f'/proc/{pid}/fd/{fd}')
        return target.startswith('socket:') if socket_output else 'ptmx' in target
    except (FileNotFoundError, ProcessLookupError):
        return False


def fill_pty(peer, broker):
    send(peer, "trap '' HUP TERM; stty raw -echo; printf 'BLOCK_READY\\n'; exec sleep 600\n")
    receive_until(peer, b'BLOCK_READY\n')
    peer.setblocking(False)
    data = b'I' + struct.pack('!I', 65536) + b'x' * 65536
    sent = 0
    until = time.monotonic() + 6
    while time.monotonic() < until:
        try:
            count = peer.send(data)
            sent += count
            data = data[count:] or (b'I' + struct.pack('!I', 65536) + b'x' * 65536)
        except BlockingIOError:
            if blocked_write(broker):
                break
            time.sleep(0.02)
    wait_for(lambda: blocked_write(broker), 'broker blocked in write to PTY')
    print(f'VM_BACKPRESSURE direction=PTY bytes={sent}', flush=True)


def test_blocked_pty_disconnect():
    peer, group, _, broker = session()
    fill_pty(peer, broker)
    # Half-close also needs to revoke, while the client still reads output.
    peer.shutdown(socket.SHUT_WR)
    cleanup(peer, group, close=False)


def test_blocked_output_disconnect():
    peer, group, _, broker = session()
    send(peer, 'exec yes TERMINAL_BACKPRESSURE\n')
    wait_for(lambda: blocked_write(broker, socket_output=True), 'broker blocked in socket write')
    print('VM_BACKPRESSURE direction=socket', flush=True)
    cleanup(peer, group)


def test_wheel_revocation_while_blocked():
    peer, group, _, broker = session()
    fill_pty(peer, broker)
    wheel(False)
    # Keep the peer connected: the root supervisor must detect group removal.
    cleanup(peer, group, close=False)
    wheel()


def test_shell_exit():
    peer, group, _, _ = session()
    send(peer, 'exit\n')
    cleanup(peer, group, close=False)


def test_identity_rejection():
    for username, uid in [('alice', 0), ('root', SERVICE_UID), ('bob', SERVICE_UID)]:
        peer = connect(username, uid, rejecting=True)
        try:
            assert peer.recv(4096) == b'', f'accepted forbidden identity {username}/{uid}'
        except ConnectionResetError:
            pass
        peer.close()


def main():
    assert os.geteuid() == 0
    assert Path('/run/vega-terminal-test-vm').is_file(), 'guest-only test'
    assert 'ID=lyra-terminal-test-vm' in Path('/etc/os-release').read_text(), 'guest-only test'
    for directory, uid in [(HOME, ALICE_UID), (Path('/home/bob'), 1002)]:
        directory.mkdir(parents=True, exist_ok=True)
        os.chown(directory, uid, uid)
    profile = HOME / '.bash_profile'
    profile.write_text("PS1='VM_READY> '; unset HISTFILE; printf 'VM_SHELL=%s\\n' \"$$\"\n")
    os.chown(profile, ALICE_UID, ALICE_UID)
    wheel()
    subprocess.run(['systemctl', 'start', 'vega-web-terminal.socket'], check=True)
    for test in [test_identity_resize_disconnect, test_resistant_descendants,
                 test_blocked_pty_disconnect, test_blocked_output_disconnect,
                 test_wheel_revocation_while_blocked, test_shell_exit,
                 test_identity_rejection, test_identity_resize_disconnect]:
        started = time.monotonic()
        print('VM_TEST ' + test.__name__, flush=True)
        test()
        print(f'VM_PASS {test.__name__} {time.monotonic() - started:.2f}s', flush=True)
    print('LYRA_TERMINAL_VM_RESULT=0', flush=True)


if __name__ == '__main__':
    try:
        main()
    except BaseException:
        import traceback
        traceback.print_exc()
        subprocess.run(['systemctl', '--no-pager', '--full', 'status', 'vega-web-terminal@*.service'])
        raise
