"""Guest-only tests: real authentication, caller identity, RPM and firewall."""
import array
import concurrent.futures
from http import client as http_client
import os
from pathlib import Path
import re
import shutil
import socket
import ssl
import struct
import subprocess
import time
import traceback
import urllib.parse

PASSWORD = 'Vega-test-only-73!'
SOCKET = '/run/vega-web-admin.sock'
HELPER = '/usr/lib/vega/vega-web-admin-helper'
PACKAGE = 'vega-web-broker-vm'
INSTALL = b'\x01' + PACKAGE.encode()
PORT = b'\x02' + struct.pack('>H', 38443) + b'\x01'


def command(*args, check=True, **kwargs):
    result = subprocess.run(args, capture_output=True, text=True, timeout=35, **kwargs)
    if check:
        assert result.returncode == 0, (args, result.returncode, result.stdout, result.stderr)
    return result


def ctl(*args):
    return command('systemctl', *args).stdout.strip()


def until(predicate, seconds=15):
    end = time.monotonic() + seconds
    while time.monotonic() < end:
        if predicate():
            return
        time.sleep(0.1)
    raise AssertionError('condition timed out')


def connect_as(uid=998):
    receiver, sender = socket.socketpair()
    child = os.fork()
    if child == 0:
        receiver.close()
        try:
            os.setgroups([uid])
            os.setgid(uid)
            os.setuid(uid)
            stream = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            stream.connect(SOCKET)
            sender.sendmsg([b'ok'], [(socket.SOL_SOCKET, socket.SCM_RIGHTS,
                                    array.array('i', [stream.fileno()]))])
        except OSError as error:
            sender.send(str(error.errno).encode())
        finally:
            os._exit(0)
    sender.close()
    data, ancillary, _, _ = receiver.recvmsg(128, socket.CMSG_SPACE(4))
    os.waitpid(child, 0)
    receiver.close()
    if data != b'ok':
        raise PermissionError(data.decode())
    descriptors = array.array('i')
    descriptors.frombytes(ancillary[0][2])
    stream = socket.socket(fileno=descriptors[0])
    stream.settimeout(65)
    return stream


def read_exact(stream, length):
    data = b''
    while len(data) < length:
        chunk = stream.recv(length - len(data))
        if not chunk:
            raise EOFError('incomplete frame')
        data += chunk
    return data


def frame(user='alice', password=PASSWORD, operation=PORT, session=b'S' * 32):
    user, password = user.encode(), password.encode()
    return b'VWA1' + struct.pack('>HHH', len(user), len(password), len(operation)) + session + user + password + operation


def prepare(**kwargs):
    stream = connect_as()
    stream.sendall(frame(**kwargs))
    assert read_exact(stream, 1) == b'\x00', 'prepare refused'
    return stream, read_exact(stream, 32), read_exact(stream, 16)


def commit(stream, grant, extra=b''):
    stream.sendall(b'VWC1' + grant + extra)
    stream.shutdown(socket.SHUT_WR)
    if read_exact(stream, 1) != b'\x00':
        return None
    value = struct.unpack('>I', read_exact(stream, 4))[0]
    assert stream.recv(1) == b''
    return value


def rejected(payload, uid=998):
    with connect_as(uid) as stream:
        try:
            stream.sendall(payload)
            stream.shutdown(socket.SHUT_WR)
            assert stream.recv(1) != b'\x00'
        except (BrokenPipeError, ConnectionResetError):
            pass


def commits():
    file = Path('/var/log/vega-admin-broker.log')
    return file.read_text().count('phase=committed') if file.exists() else 0


def log(name):
    print('PASS:', name, flush=True)


def http(method, path, fields=None, cookie=''):
    conn = http_client.HTTPSConnection('127.0.0.1', 9090, timeout=70,
                                     context=ssl._create_unverified_context())
    try:
        conn.request(method, path, urllib.parse.urlencode(fields or {}),
                     {'Content-Type': 'application/x-www-form-urlencoded', 'Cookie': cookie})
        response = conn.getresponse()
        return response.status, dict(response.getheaders()), response.read().decode()
    finally:
        conn.close()


def ready():
    try:
        return http('GET', '/login')[0] == 200
    except (OSError, http_client.HTTPException):
        return False


def login(user='alice'):
    status, headers, body = http('POST', '/login', {'username': user, 'password': PASSWORD})
    assert status == 303, (status, body)
    cookie = headers['set-cookie'].split(';', 1)[0]
    status, _, body = http('GET', '/administracao', cookie=cookie)
    assert status == 200, (status, body)
    csrf = re.search(r'name="csrf" value="([0-9a-f]{64})"', body).group(1)
    return cookie, csrf


def https_tests():
    ctl('stop', 'vega-web.service')
    shutil.copyfile('/candidate/vega-web.service', '/usr/lib/systemd/system/vega-web.service')
    for path in ['/etc/vega/web/tls', '/var/lib/vega-web', '/run/faillock']:
        Path(path).mkdir(parents=True, exist_ok=True)
    os.chown('/etc/vega/web/tls', 998, 998)
    dropin = Path('/etc/systemd/system/vega-web.service.d/admin-test.conf')
    dropin.parent.mkdir(parents=True)
    base = '''[Service]
StandardOutput=append:/var/lib/vega-web/web.log
StandardError=inherit
Environment=VEGA_WEB_LOGIN_DELAY_MS=10
Environment=VEGA_WEB_LOGIN_MAX_DELAY_SECS=1
'''
    dropin.write_text(base)
    ctl('daemon-reload')
    ctl('start', 'vega-web.service')
    until(ready)
    cookie, csrf = login()
    bob, bob_csrf = login('bob')
    before = commits()
    action = {'action': 'add-port', 'port': '38444', 'protocol': 'tcp',
              'password': PASSWORD, 'csrf': csrf}
    assert http('POST', '/administracao', {**action, 'csrf': bob_csrf}, cookie)[0] == 403
    assert http('POST', '/administracao', {**action, 'username': 'root'}, cookie)[0] == 422
    assert http('POST', '/administracao', {**action, 'csrf': bob_csrf}, bob)[0] == 403
    assert commits() == before
    status, _, body = http('POST', '/administracao', action, cookie)
    assert status == 200 and '38444/tcp' in body, (status, body)
    command('firewall-cmd', '--query-port=38444/tcp')
    status, _, body = http('POST', '/administracao', {
        'action': 'install', 'package': PACKAGE, 'csrf': csrf, 'password': PASSWORD}, cookie)
    assert status == 202 and 'Transação' in body and 'ainda precisa concluir' in body, (status, body)
    log('real HTTPS/PAM login: authenticated administrator succeeds, ordinary user and forged identities fail')

    # A slow PAM module only in this VM lets logout/expiry race a prepared
    # HTTP request deterministically, while the root helper remains isolated.
    stack = Path('/etc/pam.d/vega-web')
    original = stack.read_text()
    hook = Path('/usr/bin/vega-pam-delay')
    hook.write_text('#!/bin/bash\ntouch /run/faillock/admin-entered\nsleep 5\n')
    hook.chmod(0o755)
    entered = Path('/run/faillock/admin-entered')
    for mode in ['logout', 'expiry']:
        if mode == 'expiry':
            dropin.write_text(base + 'Environment=VEGA_WEB_SESSION_MAX_SECS=2\n')
            ctl('daemon-reload')
            ctl('restart', 'vega-web.service')
            until(ready)
        cookie, csrf = login()
        entered.unlink(missing_ok=True)
        before = commits()
        stack.write_text('auth required pam_exec.so /usr/bin/vega-pam-delay\n' + original)
        try:
            with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
                pending = pool.submit(http, 'POST', '/administracao', {
                    'action': 'add-port', 'port': '38445', 'protocol': 'tcp',
                    'csrf': csrf, 'password': PASSWORD}, cookie)
                until(entered.exists)
                if mode == 'logout':
                    start = time.monotonic()
                    assert http('POST', '/logout', cookie=cookie)[0] == 303
                    assert time.monotonic() - start < 2
                assert pending.result(timeout=5)[0] == 401
        finally:
            stack.write_text(original)
        until(lambda: ctl('show', 'vega-web-admin.socket', '-p', 'NConnections', '--value') == '0')
        assert commits() == before
        assert command('firewall-cmd', '--query-port=38445/tcp', check=False).returncode != 0
        log('HTTP ' + mode + ' cancels the pending administrative grant while PAM is busy')

    # The admin helper's own hard deadline bounds a PAM module that never
    # responds. It must recover its socket slot without restarting HTTPS.
    before = commits()
    pid = ctl('show', 'vega-web.service', '-p', 'MainPID', '--value')
    hook.write_text('#!/bin/bash\nsleep 120\n')
    stack.write_text('auth required pam_exec.so /usr/bin/vega-pam-delay\n' + original)
    try:
        with connect_as() as stream:
            stream.sendall(frame())
            start = time.monotonic()
            try:
                assert stream.recv(1) != b'\x00'
            except ConnectionResetError:
                pass
            assert 55 < time.monotonic() - start < 65
    finally:
        stack.write_text(original)
    until(lambda: ctl('show', 'vega-web-admin.socket', '-p', 'NConnections', '--value') == '0')
    assert commits() == before and ctl('show', 'vega-web.service', '-p', 'MainPID', '--value') == pid
    assert http('GET', '/login')[0] == 200
    stream, grant, _ = prepare()
    with stream:
        pass
    log('stuck PAM is terminated by the admin unit deadline; slot and existing HTTPS process recover')


def main():
    assert os.geteuid() == 0 and Path('/run/vega-admin-test-vm').exists(), 'disposable VM required'
    for directory in ['/var/log', '/var/lib/polkit', '/var/lib/vega-web', '/var/lib/rpm',
                      '/var/log/journal', '/etc/zypp/repos.d', '/etc/firewalld', '/run/dbus',
                      '/home/alice', '/home/bob', '/usr/share/polkit-1/rules.d']:
        Path(directory).mkdir(parents=True, exist_ok=True)
    os.chown('/var/lib/polkit', 999, 999)
    os.chown('/var/lib/vega-web', 998, 998)
    command('ip', 'link', 'set', 'lo', 'up')
    command('dbus-daemon', '--config-file=/dbus-test.conf', '--fork', '--nopidfile')
    polkit_log = open('/var/log/polkit-test.log', 'w')
    subprocess.Popen(['/usr/libexec/polkit-1/polkitd'], stdout=polkit_log, stderr=subprocess.STDOUT)
    until(lambda: command('python3', '-c', 'import dbus; assert dbus.SystemBus().name_has_owner("org.freedesktop.PolicyKit1")', check=False).returncode == 0)
    command('modprobe', 'nf_tables')
    firewall_log = open('/var/log/firewalld-test.log', 'w')
    subprocess.Popen(['firewalld', '--nofork', '--nopid'], stdout=firewall_log, stderr=subprocess.STDOUT)
    until(lambda: command('firewall-cmd', '--state', check=False).returncode == 0)
    assert command('rpm', '--eval', '%{_dbpath}').stdout.strip() == '/var/lib/rpm'
    command('rpm', '--initdb')
    packages = list(Path('/packages').glob('*.rpm'))
    assert len(packages) == 1
    assert command('rpm', '-qp', '--queryformat', '%{NAME}', str(packages[0])).stdout == PACKAGE
    # State the local repository format explicitly across libzypp releases,
    # and require a usable fixture before testing any administrative grant.
    command('zypper', '--non-interactive', 'addrepo', '--type', 'plaindir',
            '--no-gpgcheck', '/packages', 'vm-native')
    refresh = command('zypper', '--non-interactive', 'refresh', '--force')
    print('VM repository refresh:', refresh.stdout, refresh.stderr, flush=True)
    available = command('zypper', '--non-interactive', '--no-refresh', 'search',
                        '--details', '--match-exact', '--type', 'package', PACKAGE)
    assert PACKAGE in available.stdout, (available.stdout, available.stderr)
    vegad_log = open('/var/log/vegad-test.log', 'w')
    subprocess.Popen(['/usr/lib/vega/vegad'], stdout=vegad_log, stderr=subprocess.STDOUT)
    until(lambda: command('python3', '-c', 'import dbus; assert dbus.SystemBus().name_has_owner("org.lyraos.Vega1")', check=False).returncode == 0)
    transactions = open('/var/log/transactions.log', 'w')
    subprocess.Popen(['dbus-monitor', '--system', "type='signal',interface='org.lyraos.Vega1.Software'"],
                     stdout=transactions, stderr=subprocess.STDOUT)
    # Collect the candidate's audit output independently of journald plumbing.
    dropin = Path('/etc/systemd/system/vega-web-admin@.service.d/audit.conf')
    dropin.parent.mkdir(parents=True)
    dropin.write_text('[Service]\nStandardError=append:/var/log/vega-admin-broker.log\n')
    ctl('daemon-reload')
    ctl('start', 'vega-web.service', 'vega-web-admin.socket')

    rejected(frame(), uid=0)
    try:
        connect_as(1002)
        raise AssertionError('ordinary user opened service socket')
    except PermissionError:
        pass
    rejected(frame(password='wrong-password'))
    rejected(frame(user='bob'))
    rejected(frame(user='missing-user'))
    rejected(frame(user='root'))
    rejected(frame(session=b'\0' * 32))
    rejected(b'VWA1' + struct.pack('>HHH', 8, 65535, 1) + b'S' * 32)
    rejected(frame(operation=b'\x01--force'))
    rejected(frame(operation=b'\x02\0\0\x01'))
    assert commits() == 0
    log('peer UID, fresh password, administrative membership and bounded typed input')

    with prepare(operation=INSTALL)[0] as stream:
        pass  # Cancel after preparation, before consuming the grant.
    stream, grant, _ = prepare()
    with stream:
        assert commit(stream, bytes(byte ^ 1 for byte in grant)) is None
    stream, grant, _ = prepare()
    with stream:
        assert commit(stream, grant, b'VWC1' + grant) is None
    stream, grant, _ = prepare()
    with stream:
        group = Path('/etc/group')
        original = group.read_text()
        group.write_text(original.replace('wheel:x:1000:alice', 'wheel:x:1000:'))
        try:
            assert commit(stream, grant) is None
        finally:
            group.write_text(original)
    stream, grant, _ = prepare()
    with stream:
        shadow = Path('/etc/shadow')
        original = shadow.read_text()
        rows = original.splitlines()
        for index, row in enumerate(rows):
            if row.startswith('alice:'):
                fields = row.split(':')
                fields[7] = '1'
                rows[index] = ':'.join(fields)
        shadow.write_text('\n'.join(rows) + '\n')
        try:
            assert commit(stream, grant) is None
        finally:
            shadow.write_text(original)
    assert commits() == 0
    assert not Path('/usr/share/vega-web-broker-vm/proof').exists()
    assert command('firewall-cmd', '--query-port=38443/tcp', check=False).returncode != 0
    log('cancellation, grant mismatch, duplicate/altered commit and privilege/account revocation')

    stream, grant, _ = prepare()
    with stream:
        started = time.monotonic()
        assert stream.recv(1) != b'\x00'
        assert 8 <= time.monotonic() - started < 18
    assert commits() == 0
    log('unconsumed grant expires within the bounded window')

    # Matching UID/groups alone must never satisfy the authentication policy.
    probe = '''import dbus
bus = dbus.SystemBus(private=True)
try:
    bus.call_blocking("org.lyraos.Vega1", "/org/lyraos/Vega1", "org.lyraos.Vega1.Software", "Install", "ss", ("official", "vega-web-broker-vm"))
except dbus.DBusException:
    raise SystemExit(0)
raise SystemExit(1)
'''
    for uid, groups in [(1001, [1000, 1001]), (1002, [1002]), (998, [998])]:
        command('python3', '-c', probe, user=uid, group=uid, extra_groups=groups)
    # Installing a caller-owned agent that claims authentication succeeded
    # cannot satisfy AUTH_SELF: Polkit requires a root authentication response.
    fake_agent = '''import dbus, dbus.service, os
from dbus.mainloop.glib import DBusGMainLoop
from gi.repository import GLib
DBusGMainLoop(set_as_default=True)
bus = dbus.SystemBus(private=True)
authority = dbus.Interface(bus.get_object("org.freedesktop.PolicyKit1", "/org/freedesktop/PolicyKit1/Authority"), "org.freedesktop.PolicyKit1.Authority")
loop = GLib.MainLoop()
outcome = {"challenged": False, "response_denied": False, "install_denied": False}
class Agent(dbus.service.Object):
    @dbus.service.method("org.freedesktop.PolicyKit1.AuthenticationAgent", in_signature="sssa{ss}sa(sa{sv})", out_signature="", async_callbacks=("success", "failure"))
    def BeginAuthentication(self, action, message, icon, details, cookie, identities, success, failure):
        outcome["challenged"] = True
        def denied(error):
            outcome["response_denied"] = "Only uid 0" in str(error)
            success()
        authority.AuthenticationAgentResponse2(dbus.UInt32(1001), cookie,
            ("unix-user", {"uid": dbus.UInt32(1001)}), reply_handler=success, error_handler=denied)
    @dbus.service.method("org.freedesktop.PolicyKit1.AuthenticationAgent", in_signature="s", out_signature="")
    def CancelAuthentication(self, cookie):
        pass
agent = Agent(bus, "/test/UnauthenticatedAgent")
stat = open("/proc/self/stat").read().rsplit(")", 1)[1].split()
subject = ("unix-process", {"pid": dbus.UInt32(os.getpid()), "uid": dbus.Int32(1001), "start-time": dbus.UInt64(int(stat[19]))})
authority.RegisterAuthenticationAgent(subject, "C", "/test/UnauthenticatedAgent")
def denied(error):
    outcome["install_denied"] = error.get_dbus_name() == "org.lyraos.Vega1.Error.AuthorizationFailed"
    loop.quit()
software = dbus.Interface(bus.get_object("org.lyraos.Vega1", "/org/lyraos/Vega1"), "org.lyraos.Vega1.Software")
software.Install("official", "vega-web-broker-vm", reply_handler=lambda value: loop.quit(), error_handler=denied)
GLib.timeout_add_seconds(12, loop.quit)
loop.run()
assert all(outcome.values()), outcome
'''
    command('python3', '-c', fake_agent, user=1001, group=1001, extra_groups=[1000, 1001])
    direct = command(HELPER, '--worker', input='ignored', user=998, group=998, check=False)
    assert direct.returncode != 0
    log('Polkit refuses unauthenticated calls, a fake user agent, and direct HTTPS root-worker launch')

    stream, grant, audit = prepare(operation=INSTALL)
    with stream:
        transaction = commit(stream, grant)
    assert transaction is not None and transaction > 0
    def installed():
        events = Path('/var/log/transactions.log').read_text()
        result = re.search(r'member=TransactionFinished\s+uint32 ' + str(transaction) +
                           r'\s+boolean (true|false)', events)
        if result is None:
            return False
        assert result[1] == 'true', events[-5000:]
        return True
    until(installed)
    until(lambda: Path('/usr/share/vega-web-broker-vm/proof').exists())
    command('rpm', '-q', PACKAGE)
    stream, grant2, audit2 = prepare()
    with stream:
        assert commit(stream, grant2) == 0
    assert grant != grant2 and audit != audit2
    command('firewall-cmd', '--query-port=38443/tcp')
    command('firewall-cmd', '--permanent', '--query-port=38443/tcp')
    rules = command('nft', 'list', 'ruleset').stdout
    assert '38443' in rules
    assert commits() == 2
    log('authenticated administrator installs real RPM and persists/applies a real nftables firewall port')
    stream, _, _ = prepare()
    with stream:
        assert commit(stream, grant) is None
    assert commits() == 2
    log('consumed grant cannot be replayed on another prepared connection')

    polkit = Path('/var/log/polkit-test.log').read_text()
    assert 'user=alice ' in polkit, polkit
    assert 'action=org.lyraos.vega.software.install' in polkit
    assert 'action=org.lyraos.vega.firewall.configure' in polkit
    audit_log = Path('/var/log/vega-admin-broker.log').read_text()
    assert PASSWORD not in audit_log
    assert 'uid=1001' in audit_log and f'transaction={transaction}' in audit_log
    assert audit_log.count('phase=polkit-authenticated') == 2
    assert grant.hex() not in audit_log and grant2.hex() not in audit_log
    log('real Polkit challenges preserve actual UID, action and transaction without credentials/grants')
    https_tests()
    print('LYRA_ADMIN_VM_RESULT=0', flush=True)


if __name__ == '__main__':
    try:
        main()
    except Exception:
        traceback.print_exc()
        for args in [('firewall-cmd', '--state'), ('nft', 'list', 'ruleset')]:
            result = command(*args, check=False)
            print(args, result.returncode, result.stdout[-1000:], result.stderr[-2000:], flush=True)
        for name in ['polkit-test.log', 'firewalld-test.log', 'firewalld', 'vegad-test.log', 'transactions.log', 'zypper.log', 'vega-admin-broker.log']:
            path = Path('/var/log') / name
            if path.exists():
                print(name + '\n' + path.read_text(errors='replace')[-6000:], flush=True)
        web_log = Path('/var/lib/vega-web/web.log')
        if web_log.exists():
            print('HTTPS log:\n' + web_log.read_text(errors='replace')[-5000:], flush=True)
        raise
