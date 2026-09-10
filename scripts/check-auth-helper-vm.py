#!/usr/bin/env python3
"""Qualify PAM isolation, service-account migration and HTTPS login in a VM."""
import argparse
from pathlib import Path
import re
import subprocess
from vm_support import SystemdVM

REPO = Path(__file__).resolve().parents[1]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--kernel', required=True, type=Path)
    parser.add_argument('--bin-dir', type=Path, default=REPO / 'target/debug')
    parser.add_argument('--log', type=Path, default=REPO / 'target/auth-helper-vm.log')
    args = parser.parse_args()
    if not args.kernel.is_file():
        parser.error('missing kernel')
    vm = SystemdVM('auth', 'lyra-auth-test-vm')
    for name in ['sleep', 'false', 'ip', 'dbus-daemon', 'gpasswd', 'getent', 'id', 'cut']:
        vm.tool(name)
    for name in ['vega-web', 'vega-web-auth-helper', 'vega-web-terminal-helper']:
        vm.binary(args.bin_dir / name, '/usr/lib/vega/' + name)
    for name in ['vega-web.service', 'vega-web-auth.socket', 'vega-web-auth@.service',
                 'vega-web-terminal.socket', 'vega-web-terminal@.service']:
        vm.put('/candidate/' + name, (REPO / 'packaging' / name).read_text())
        if name != 'vega-web.service':
            vm.put('/usr/lib/systemd/system/' + name, (REPO / 'packaging' / name).read_text())
    vm.put('/usr/lib/vega/vega-web-migrate-auth', (REPO / 'packaging/migrate-auth.sh').read_text(), 0o755)
    vm.put('/etc/pam.d/vega-web', (REPO / 'packaging/pam.d/vega-web').read_text())
    # Only public PAM stack definitions and their module binaries are copied.
    # Password/account databases below are artificial; no host hashes enter the VM.
    pending = ['common-auth', 'common-account']
    seen = set()
    modules = {'pam_exec.so'}
    while pending:
        name = pending.pop()
        if name in seen:
            continue
        if '/' in name:
            parser.error('PAM include outside /etc/pam.d is unsupported by this test builder')
        seen.add(name)
        content = (Path('/etc/pam.d') / name).read_text()
        vm.put('/etc/pam.d/' + name, content)
        for line in content.splitlines():
            line = line.split('#', 1)[0]
            modules.update(re.findall(r'\b(pam_[\w-]+\.so)\b', line))
            pending.extend(re.findall(r'(?:@include|include|substack)\s+([\w.-]+)', line))
    for name in sorted(modules):
        locations = ['/usr/lib64/security', '/usr/lib/security', '/lib64/security',
                     '/usr/lib/x86_64-linux-gnu/security', '/lib/x86_64-linux-gnu/security']
        source = next((Path(base) / name for base in locations if (Path(base) / name).is_file()), None)
        if source is None:
            parser.error('missing PAM module: ' + name)
        vm.binary(source)
    vm.put('/etc/passwd', 'root:x:0:0:root:/root:/bin/bash\n'
           'vega-web:x:998:998:service:/var/lib/vega-web:/bin/false\n'
           'alice:x:1001:1001:alice:/home/alice:/bin/bash\n'
           'bob:x:1002:1002:bob:/home/bob:/bin/bash\n')
    vm.put('/etc/group', 'root:x:0:\nshadow:x:15:vega-web\nvega-web:x:998:\n'
           'wheel:x:1000:alice\nalice:x:1001:\nbob:x:1002:\nmetrics:x:1003:vega-web\n')
    vm.put('/etc/gshadow', 'root:!::\nshadow:!::vega-web\nvega-web:!::\n'
           'wheel:!::alice\nalice:!::\nbob:!::\nmetrics:!::vega-web\n', 0o640)
    # A fixed test-only credential, intentionally public and used only in the VM.
    password_hash = subprocess.check_output(
        ['openssl', 'passwd', '-6', '-salt', 'vega-test', 'Vega-test-only-73!'], text=True).strip()
    vm.put('/etc/shadow', f'root:!:20000:0:99999:7:::\nvega-web:!:20000:0:99999:7:::\n'
           f'alice:{password_hash}:20000:0:99999:7:::\nbob:{password_hash}:20000:0:99999:7:::\n', 0o640)
    vm.put('/etc/shadow-', (vm.root / 'etc/shadow').read_text(), 0o640)
    vm.put('/etc/hostname', 'vega-auth-test\n')
    vm.put('/etc/hosts', '127.0.0.1 localhost vega-auth-test\n')
    vm.put('/dbus-test.conf', '''<!DOCTYPE busconfig PUBLIC "-//freedesktop//DTD D-Bus Bus Configuration 1.0//EN"
"http://www.freedesktop.org/standards/dbus/1.0/busconfig.dtd">
<busconfig><type>system</type><listen>unix:path=/run/dbus/system_bus_socket</listen>
<policy context="default"><allow user="*"/><allow own="*"/><allow send_destination="*"/>
<allow receive_sender="*"/></policy></busconfig>
''')
    vm.put('/shadow_probe.py', '''import json, os
from pathlib import Path
result = {"uid": os.getuid(), "groups": os.getgroups(), "readable": {}}
for file in ["/etc/shadow", "/etc/shadow-", "/etc/gshadow"]:
    try:
        with open(file, "rb") as stream:
            stream.read(1)
        result["readable"][file] = True
    except PermissionError:
        result["readable"][file] = False
Path("/var/lib/vega-web/shadow-probe.json").write_text(json.dumps(result))
''')
    vm.put('/legacy-web.py', '''import time
from pathlib import Path
# Hold the old file descriptor open so migration must kill this process.
stream = open("/etc/shadow", "rb")
stream.read(1)
Path("/var/lib/vega-web/legacy-read").touch()
while True:
    time.sleep(60)
''')
    vm.run(args.kernel, args.log, REPO / 'tests/auth_helper_vm.py',
           'vega-auth-test-vm', 'LYRA_AUTH_VM_RESULT=0')


if __name__ == '__main__':
    main()
