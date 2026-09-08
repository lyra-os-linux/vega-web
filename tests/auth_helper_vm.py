"""Guest-only authentication qualification with artificial accounts/passwords."""
import array
import concurrent.futures
import http.client
import json
import os
from pathlib import Path
import shutil
import socket
import ssl
import struct
import subprocess
import time
import urllib.parse

PASSWORD = 'Vega-test-only-73!'
SOCKET = '/run/vega-web-auth.sock'
UNIT = 'vega-web.service'


def ctl(*args):
    result = subprocess.run(['systemctl', *args], text=True, capture_output=True)
    assert result.returncode == 0, (args, result.stdout, result.stderr)
    return result.stdout.strip()


def until(predicate, seconds=8):
    end = time.monotonic() + seconds
    while time.monotonic() < end:
        result = predicate()
        if result:
            return result
        time.sleep(0.05)
    raise AssertionError('condition timed out')


def put(path, content):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content)


def request(method, path, fields=None, cookie='', source='127.0.0.1'):
    connection = http.client.HTTPSConnection(
        '127.0.0.1', 9090, timeout=40, context=ssl._create_unverified_context(),
        source_address=(source, 0))
    try:
        data = urllib.parse.urlencode(fields or {})
        connection.request(method, path, body=data, headers={
            'Content-Type': 'application/x-www-form-urlencoded', 'Cookie': cookie})
        response = connection.getresponse()
        return response.status, dict(response.getheaders()), response.read().decode()
    finally:
        connection.close()


def ready():
    try:
        return request('GET', '/login')[0] == 200
    except (OSError, http.client.HTTPException):
        return False


def restart():
    ctl('restart', UNIT)
    until(ready)


def login(user='alice', password=PASSWORD, source='127.0.0.1'):
    return request('POST', '/login', {'username': user, 'password': password}, source=source)


def accepted():
    return int(ctl('show', 'vega-web-auth.socket', '-p', 'NAccepted', '--value'))


def connections():
    return int(ctl('show', 'vega-web-auth.socket', '-p', 'NConnections', '--value'))


def successful_login(user='alice', source='127.0.0.1'):
    status, headers, body = login(user, source=source)
    assert status == 303 and headers.get('location') == '/', (status, body[-300:])
    cookie = headers['set-cookie']
    assert 'HttpOnly' in cookie and 'Secure' in cookie and 'SameSite=Strict' in cookie
    cookie = cookie.split(';', 1)[0]
    assert request('GET', '/software', cookie=cookie, source=source)[0] == 200
    return cookie


def denied(response):
    assert response[0] != 303 and 'set-cookie' not in response[1], response[:2]


def connect_as(uid=998, groups=None):
    # Establish the connection under the requested credentials, then transfer
    # the FD to the root test observer. SO_PEERCRED retains the connecting UID.
    receiver, sender = socket.socketpair()
    child = os.fork()
    if child == 0:
        receiver.close()
        try:
            os.setgroups(groups if groups is not None else [uid])
            os.setgid(uid)
            os.setuid(uid)
            stream = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            stream.connect(SOCKET)
            sender.sendmsg([b'ok'], [(socket.SOL_SOCKET, socket.SCM_RIGHTS, array.array('i', [stream.fileno()]))])
        except OSError as error:
            sender.send(str(error.errno).encode())
        finally:
            os._exit(0)
    sender.close()
    data, ancdata, _, _ = receiver.recvmsg(128, socket.CMSG_SPACE(4))
    os.waitpid(child, 0)
    receiver.close()
    if data != b'ok':
        raise PermissionError(data.decode())
    descriptors = array.array('i')
    descriptors.frombytes(ancdata[0][2])
    stream = socket.socket(fileno=descriptors[0])
    stream.settimeout(36)
    return stream


def frame(user='alice', password=PASSWORD):
    user, password = user.encode(), password.encode()
    return b'VPA1' + struct.pack('!HH', len(user), len(password)) + user + password


def raw_request(data, uid=998, groups=None):
    with connect_as(uid, groups) as stream:
        try:
            stream.sendall(data)
            stream.shutdown(socket.SHUT_WR)
            result = b''
            while chunk := stream.recv(128):
                result += chunk
            return result
        except (BrokenPipeError, ConnectionResetError):
            return b''


def service_probe():
    result = json.loads(Path('/var/lib/vega-web/shadow-probe.json').read_text())
    assert result['uid'] == 998 and 15 not in result['groups'], result
    assert not any(result['readable'].values()), result
    pid = int(ctl('show', UNIT, '-p', 'MainPID', '--value'))
    status = Path(f'/proc/{pid}/status').read_text()
    assert set(status.split('Groups:')[1].splitlines()[0].split()) == {'998', '1003'}, status
    assert 'libpam.so' not in Path(f'/proc/{pid}/maps').read_text()
    # Also prove DAC denial outside the service's mount namespace.
    result = subprocess.run(
        ['/usr/bin/python3', '-c', 'open("/etc/shadow", "rb")'],
        user=998, group=998, extra_groups=[998, 1003], capture_output=True)
    assert result.returncode != 0 and b'PermissionError' in result.stderr
    print('PASS: HTTPS UID/groups, hidden shadow files, DAC denial and no loaded libpam')


def migration():
    # A legacy service proves the actual read and keeps a hash file descriptor
    # open. Updating files/group membership alone cannot revoke that descriptor.
    put('/usr/lib/systemd/system/' + UNIT, '''[Service]
ExecStart=/usr/bin/python3 /legacy-web.py
User=vega-web
Group=vega-web
''')
    ctl('daemon-reload')
    ctl('start', UNIT)
    until(lambda: Path('/var/lib/vega-web/legacy-read').exists())
    old_pid = int(ctl('show', UNIT, '-p', 'MainPID', '--value'))
    assert '15' in Path(f'/proc/{old_pid}/status').read_text().split('Groups:')[1].splitlines()[0].split()
    print('PASS: legacy service really reads synthetic shadow with root:shadow 0640')
    shutil.copyfile('/candidate/' + UNIT, '/usr/lib/systemd/system/' + UNIT)
    put('/etc/systemd/system/vega-web.service.d/test.conf', '''[Service]
ExecStartPre=/usr/bin/python3 /shadow_probe.py
StandardOutput=append:/var/lib/vega-web/web.log
StandardError=inherit
Environment=VEGA_WEB_LOGIN_ATTEMPTS=2
Environment=VEGA_WEB_LOGIN_RECOVERY_SECS=5
Environment=VEGA_WEB_LOGIN_DELAY_MS=10
Environment=VEGA_WEB_LOGIN_MAX_DELAY_SECS=1
''')
    subprocess.run(['/usr/lib/vega/vega-web-migrate-auth'], check=True)
    until(ready)
    assert not Path(f'/proc/{old_pid}').exists(), 'legacy process still holds old groups/descriptors'
    assert 'vega-web' not in subprocess.check_output(['getent', 'group', 'shadow'], text=True)
    service_probe()
    subprocess.run(['/usr/lib/vega/vega-web-migrate-auth'], check=True)
    until(ready)
    service_probe()
    ctl('stop', UNIT)
    subprocess.run(['/usr/lib/vega/vega-web-migrate-auth'], check=True)
    assert ctl('show', UNIT, '-p', 'ActiveState', '--value') == 'inactive'
    ctl('start', UNIT)
    until(ready)
    print('PASS: active/inactive migration, old PID termination and idempotence')


def authentication():
    cookie = successful_login()
    response = request('POST', '/terminal', {'password': PASSWORD}, cookie)
    assert response[0] == 303 and response[1].get('location') == '/terminal', response[:2]
    assert '/assets/xterm.js' in request('GET', '/terminal', cookie=cookie)[2]
    assert request('POST', '/logout', cookie=cookie)[0] == 303
    assert request('GET', '/software', cookie=cookie)[1].get('location') == '/login'
    denied(login(password='wrong'))
    original = Path('/etc/shadow').read_text()
    for case in ['locked', 'account-expired', 'password-expired']:
        lines = original.splitlines()
        for index, line in enumerate(lines):
            fields = line.split(':')
            if fields[0] == 'alice':
                if case == 'locked':
                    fields[1] = '!' + fields[1]
                elif case == 'account-expired':
                    fields[7] = '1'
                else:
                    fields[2] = '0'
                lines[index] = ':'.join(fields)
        Path('/etc/shadow').write_text('\n'.join(lines) + '\n')
        restart()
        before = accepted()
        denied(login())
        assert accepted() == before + 1
        print('PASS: PAM rejects ' + case)
    Path('/etc/shadow').write_text(original)
    restart()
    denied(login(user='does-not-exist'))
    successful_login()
    print('PASS: real HTTPS/PAM login, reauthentication, logout and bad credentials')


def protocol():
    assert raw_request(frame()) == b'\0'
    for uid, groups in [(0, [0]), (1001, [1001, 998])]:
        assert raw_request(frame(), uid, groups) == b''
    try:
        connect_as(1002)
        raise AssertionError('unrelated account connected to restricted socket')
    except PermissionError:
        pass
    for data in [b'', b'junk', b'VPA1\xff\xff\xff\xff', frame()[:-1],
                 frame() + frame(), b'VPA1\0\x05\0\x01alice\0']:
        assert raw_request(data) != b'\0'
    start = time.monotonic()
    with connect_as() as stream:
        stream.sendall(b'V')
        time.sleep(3)
        stream.sendall(b'P')
        try:
            assert stream.recv(1) == b''
        except ConnectionResetError:
            pass
    assert 4 <= time.monotonic() - start < 8
    until(lambda: connections() == 0)
    held = [connect_as() for _ in range(4)]
    try:
        until(lambda: connections() == 4)
        assert raw_request(frame()) != b'\0', 'MaxConnections did not reject a fifth connection'
    finally:
        for stream in held:
            stream.close()
    until(lambda: connections() == 0)
    assert raw_request(frame()) == b'\0'
    print('PASS: peer UID, socket mode, malformed/oversized/batched input, total deadline and capacity')


def rate_limit():
    restart()
    cookie = successful_login()
    denied(login(password='wrong'))
    denied(login(password='wrong'))
    before = accepted()
    assert 'Muitas tentativas' in login()[2]
    assert 'Muitas tentativas' in login(source='127.0.0.2')[2]
    assert 'Muitas tentativas' in login(user='bob')[2]
    assert request('POST', '/terminal', {'password': PASSWORD}, cookie)[0] == 429
    assert accepted() == before, 'blocked requests reached PAM'
    successful_login('bob', source='127.0.0.2')
    time.sleep(5.2)
    successful_login()
    print('PASS: threshold survives HTTP response; IP/user isolation, terminal sharing and recovery')


def unavailable_and_timeout():
    # A service-owned fake endpoint must not receive even the request bytes.
    fake_path = '/var/lib/vega-web/fake-auth.sock'
    peer = os.fork()
    if peer == 0:
        try:
            os.setgroups([998, 1003])
            os.setgid(998)
            os.setuid(998)
            server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            server.settimeout(8)
            server.bind(fake_path)
            server.listen(1)
            stream, _ = server.accept()
            stream.settimeout(3)
            assert stream.recv(1) == b'', 'client sent credentials to an untrusted peer'
            os._exit(0)
        except Exception:
            os._exit(1)
    until(lambda: Path(fake_path).exists())
    web_override = '/etc/systemd/system/vega-web.service.d/endpoint.conf'
    put(web_override, '[Service]\nEnvironment=VEGA_WEB_AUTH_SOCKET=' + fake_path + '\n')
    ctl('daemon-reload')
    restart()
    denied(login())
    assert os.waitpid(peer, 0)[1] == 0
    Path(web_override).unlink()
    ctl('daemon-reload')
    restart()
    print('PASS: HTTPS rejects a non-root helper before sending credentials')

    dropin = '/etc/systemd/system/vega-web-auth@.service.d/test.conf'
    put(dropin, '[Service]\nExecStart=\nExecStart=/usr/bin/false\n')
    ctl('daemon-reload')
    restart()
    denied(login())
    Path(dropin).unlink()
    ctl('daemon-reload')
    restart()
    successful_login()

    stack = Path('/etc/pam.d/vega-web').read_text()
    # Real PAM loads pam_exec and blocks in a child process; production
    # RuntimeMaxSec=30 must kill the entire helper cgroup.
    Path('/etc/pam.d/vega-web').write_text('auth required pam_exec.so /usr/bin/sleep 60\naccount required pam_unix.so\n')
    restart()
    before = accepted()
    start = time.monotonic()
    with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
        pending = [pool.submit(login, f'slow-{i}') for i in range(4)]
        until(lambda: connections() == 4)
        assert 'ocupado' in login()[2]
        assert accepted() == before + 4, 'HTTPS concurrency limit forwarded a fifth authentication'
        for future in pending:
            denied(future.result(timeout=38))
    elapsed = time.monotonic() - start
    assert 29 <= elapsed < 38, elapsed
    until(lambda: connections() == 0)
    # No PAM sleep child may outlive the timed-out request.
    for file in Path('/proc').glob('[0-9]*/cmdline'):
        try:
            assert b'/usr/bin/sleep\x0060' not in file.read_bytes(), file
        except FileNotFoundError:
            pass
    Path('/etc/pam.d/vega-web').write_text(stack)
    time.sleep(5.2)
    successful_login()  # same HTTPS process: semaphore capacity was released
    print('PASS: helper failure has no local fallback; PAM runtime/cgroup cleanup and HTTP slot recovery')


def legacy_override():
    path = '/etc/systemd/system/vega-web.service.d/legacy.conf'
    put(path, '[Service]\nEnvironment=VEGA_WEB_PAM_SERVICE=other-stack\n')
    ctl('daemon-reload')
    ctl('restart', UNIT)
    until(lambda: ctl('show', UNIT, '-p', 'ExecMainStatus', '--value') == '1')
    assert not ready()
    assert 'VEGA_WEB_PAM_SERVICE personalizado' in Path('/var/lib/vega-web/web.log').read_text()
    ctl('stop', UNIT)
    Path(path).unlink()
    ctl('daemon-reload')
    ctl('reset-failed', UNIT)
    restart()
    successful_login()
    print('PASS: a legacy custom PAM stack cannot silently fall back to the default')


def main():
    assert os.getuid() == 0
    assert Path('/run/vega-auth-test-vm').is_file()
    assert 'ID=lyra-auth-test-vm' in Path('/etc/os-release').read_text()
    for name in ['/etc/shadow', '/etc/shadow-', '/etc/gshadow']:
        os.chown(name, 0, 15)
        os.chmod(name, 0o640)
    for name in ['/etc/vega/web/tls', '/var/lib/vega-web']:
        Path(name).mkdir(parents=True, exist_ok=True)
        os.chown(name, 998, 998)
        os.chmod(name, 0o700)
    Path('/run/dbus').mkdir()
    subprocess.run(['/usr/bin/ip', 'link', 'set', 'lo', 'up'], check=True)
    dbus = subprocess.Popen(['/usr/bin/dbus-daemon', '--nofork', '--config-file=/dbus-test.conf'])
    until(lambda: Path('/run/dbus/system_bus_socket').exists())
    try:
        for test in [migration, authentication, protocol, rate_limit, unavailable_and_timeout, legacy_override]:
            test()
        service_probe()
        print('LYRA_AUTH_VM_RESULT=0')
    except Exception:
        print(ctl('show', UNIT, '-p', 'ExecStartPre', '-p', 'ExecMainStatus', '-p', 'Result'))
        log = Path('/var/lib/vega-web/web.log')
        if log.exists():
            print(log.read_text()[-4000:])
        raise
    finally:
        ctl('stop', UNIT)
        dbus.terminate()


if __name__ == '__main__':
    main()
