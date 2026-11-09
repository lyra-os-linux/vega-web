#!/usr/bin/env python3
"""Qualify the real terminal helper in an isolated QEMU/systemd VM."""
import argparse
from pathlib import Path
import re
import subprocess
from vm_support import SystemdVM

REPO = Path(__file__).resolve().parents[1]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--kernel', required=True, type=Path)
    parser.add_argument('--helper', type=Path, default=REPO / 'target/debug/vega-web-terminal-helper')
    parser.add_argument('--log', type=Path, default=REPO / 'target/terminal-helper-vm.log')
    args = parser.parse_args()
    for path in [args.kernel, args.helper]:
        if not path.is_file():
            parser.error(f'missing {path}')
    vm = SystemdVM('terminal', 'lyra-terminal-test-vm')
    for name in ['sleep', 'setsid', 'stty', 'yes']:
        vm.tool(name)
    vm.binary(args.helper, '/usr/lib/vega/vega-web-terminal-helper')
    vm.put('/etc/passwd', 'root:x:0:0:root:/root:/bin/bash\nvega-web:x:998:998:service:/:/bin/false\n'
           'alice:x:1001:1001:alice:/home/alice:/bin/bash\nbob:x:1002:1002:bob:/home/bob:/bin/bash\n')
    vm.put('/etc/group', 'root:x:0:\nvega-web:x:998:\nwheel:x:1000:alice\nalice:x:1001:\nbob:x:1002:\n')
    # The helper checks the password with PAM (vega-web#34): the real
    # vega-web stack and a deliberately public, VM-only credential.
    password_hash = subprocess.check_output(['openssl', 'passwd', '-6', '-salt', 'vega-test', 'Vega-test-only-73!'], text=True).strip()
    vm.put('/etc/shadow', 'root:!:20000:0:99999:7:::\nvega-web:!:20000:0:99999:7:::\n'
           f'alice:{password_hash}:20000:0:99999:7:::\nbob:{password_hash}:20000:0:99999:7:::\n', 0o600)
    vm.put('/etc/pam.d/vega-web', (REPO / 'packaging/pam.d/vega-web').read_text())
    pending, seen, modules = ['common-auth', 'common-account'], set(), set()
    while pending:
        name = pending.pop()
        if name in seen:
            continue
        if '/' in name:
            parser.error('PAM include outside /etc/pam.d')
        seen.add(name)
        content = (Path('/etc/pam.d') / name).read_text()
        vm.put('/etc/pam.d/' + name, content)
        for line in content.splitlines():
            line = line.split('#', 1)[0]
            modules.update(re.findall(r'\b(pam_[\w-]+\.so)\b', line))
            pending.extend(re.findall(r'(?:@include|include|substack)\s+([\w.-]+)', line))
    for name in modules:
        source = next((Path(base) / name for base in ['/usr/lib64/security', '/lib64/security',
            '/usr/lib/security', '/usr/lib/x86_64-linux-gnu/security', '/lib/x86_64-linux-gnu/security']
            if (Path(base) / name).is_file()), None)
        if source is None:
            parser.error('PAM module missing: ' + name)
        vm.binary(source)
    for name in ['vega-web-terminal.socket', 'vega-web-terminal@.service']:
        vm.put('/usr/lib/systemd/system/' + name, (REPO / 'packaging' / name).read_text())
    vm.run(args.kernel, args.log, REPO / 'tests/terminal_helper_vm.py',
           'vega-terminal-test-vm', 'LYRA_TERMINAL_VM_RESULT=0')


if __name__ == '__main__':
    main()
