#!/usr/bin/env python3
"""Qualify the real terminal helper in an isolated QEMU/systemd VM."""
import argparse
from pathlib import Path
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
    for name in ['vega-web-terminal.socket', 'vega-web-terminal@.service']:
        vm.put('/usr/lib/systemd/system/' + name, (REPO / 'packaging' / name).read_text())
    vm.run(args.kernel, args.log, REPO / 'tests/terminal_helper_vm.py',
           'vega-terminal-test-vm', 'LYRA_TERMINAL_VM_RESULT=0')


if __name__ == '__main__':
    main()
