#!/usr/bin/env python3
"""Build an ephemeral initramfs and test the real helper with QEMU/systemd.

No host accounts, services, disks or network are used by the guest. Host-side
execution needs readable kernel/userspace binaries, cpio and QEMU, not root.
"""
import argparse
import gzip
from pathlib import Path
import re
import shutil
import subprocess
import sys
import sysconfig
import tempfile

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
    base = Path(tempfile.mkdtemp(prefix='vega-terminal-vm-'))
    root = base / 'root'

    def put(path, text, mode=0o644):
        target = root / path.lstrip('/')
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(text)
        target.chmod(mode)

    def binary(source, destination=None):
        source = Path(source)
        target = root / str(destination or source).lstrip('/')
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source, target)
        target.chmod(0o755)
        result = subprocess.run(['ldd', str(source)], capture_output=True, text=True, check=True)
        for dependency in re.findall(r'(?:=>\s+|^\s*)(/[^\s]+)', result.stdout, re.M):
            dep_target = root / dependency.lstrip('/')
            dep_target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(dependency, dep_target)
            dep_target.chmod(0o755)

    for directory in ['dev', 'proc', 'sys', 'run', 'tmp', 'root', 'usr/bin', 'etc/systemd/system']:
        (root / directory).mkdir(parents=True, exist_ok=True)
    (root / 'tmp').chmod(0o1777)
    for name in ['bash', 'mount', 'systemctl', 'mkdir', 'touch', 'sleep', 'setsid', 'stty', 'yes']:
        source = shutil.which(name)
        if not source:
            parser.error(f'missing tool: {name}')
        # Use a consistent usr/bin layout even on Debian's merged-/usr host.
        binary(source, '/usr/bin/' + name)
    (root / 'bin').symlink_to('usr/bin')
    (root / 'usr/bin/sh').symlink_to('bash')
    for name in ['systemd', 'systemd-shutdown']:
        source = next((p for p in [Path('/usr/lib/systemd') / name,
                                   Path('/lib/systemd') / name] if p.is_file()), None)
        if source is None:
            parser.error(f'missing {name}')
        binary(source, '/usr/lib/systemd/' + name)
    executor = Path('/usr/lib/systemd/systemd-executor')
    if executor.is_file():
        binary(executor)
    binary(args.helper, '/usr/lib/vega/vega-web-terminal-helper')
    binary(sys.executable, '/usr/bin/python3')
    # Copy standard library only; installed host applications are excluded.
    stdlib = Path(sysconfig.get_path('stdlib'))
    shutil.copytree(stdlib, root / str(stdlib).lstrip('/'), ignore=shutil.ignore_patterns(
        'site-packages', 'dist-packages', '__pycache__', 'test', 'tests', 'ensurepip',
        'idlelib', 'tkinter', 'turtledemo', 'config-*'))
    for extension in (stdlib / 'lib-dynload').glob('*.so'):
        binary(extension)
    # Optional library search directories in the host cache must remain usable
    # in the guest; copy the loader cache, never host accounts or credentials.
    loader_cache = Path('/etc/ld.so.cache')
    if loader_cache.is_file():
        shutil.copyfile(loader_cache, root / 'etc/ld.so.cache')
    put('/etc/passwd', 'root:x:0:0:root:/root:/bin/bash\nvega-web:x:998:998:service:/:/bin/false\n'
        'alice:x:1001:1001:alice:/home/alice:/bin/bash\nbob:x:1002:1002:bob:/home/bob:/bin/bash\n')
    put('/etc/group', 'root:x:0:\nvega-web:x:998:\nwheel:x:1000:alice\nalice:x:1001:\nbob:x:1002:\n')
    put('/etc/nsswitch.conf', 'passwd: files\ngroup: files\nhosts: files\n')
    put('/etc/machine-id', '')
    put('/etc/os-release', 'ID=lyra-terminal-test-vm\nPRETTY_NAME="Vega terminal disposable test VM"\n')
    for name in ['vega-web-terminal.socket', 'vega-web-terminal@.service']:
        put('/usr/lib/systemd/system/' + name, (REPO / 'packaging' / name).read_text())
    for name in ['sysinit', 'basic', 'multi-user', 'sockets', 'shutdown']:
        put(f'/usr/lib/systemd/system/{name}.target', f'[Unit]\nDescription=Test {name}\nDefaultDependencies=no\n')
    put('/etc/systemd/system/terminal-test.target', '[Unit]\nDefaultDependencies=no\n'
        'Wants=basic.target sysinit.target terminal-test.service\n')
    put('/etc/systemd/system/terminal-test.service', '''[Unit]
DefaultDependencies=no
After=basic.target sysinit.target
[Service]
Type=oneshot
ExecStart=/bin/bash /test.sh
StandardOutput=tty
StandardError=inherit
TTYPath=/dev/console
TimeoutStartSec=180
''')
    put('/terminal_helper_vm.py', (REPO / 'tests/terminal_helper_vm.py').read_text())
    put('/test.sh', '''#!/bin/bash
export PATH=/usr/bin:/bin
touch /run/vega-terminal-test-vm
python3 -u /terminal_helper_vm.py
result=$?
echo "VM_GUEST_EXIT=$result"
systemctl --force --force poweroff
''', 0o755)
    put('/init', '''#!/bin/bash
export PATH=/usr/bin:/bin
mount -t proc proc /proc
mount -t sysfs sysfs /sys
mount -t devtmpfs devtmpfs /dev
mount -t tmpfs tmpfs /run
mkdir -p /dev/pts /sys/fs/cgroup
mount -t devpts devpts /dev/pts
mount -t cgroup2 cgroup2 /sys/fs/cgroup
exec /usr/lib/systemd/systemd --system --log-level=warning --log-target=console --unit=terminal-test.target
''', 0o755)
    files = b'\0'.join(str(path.relative_to(root)).encode() for path in root.rglob('*')) + b'\0'
    archive = subprocess.run(['cpio', '--null', '-o', '--format=newc', '--owner=0:0'],
                             cwd=root, input=files, capture_output=True, check=True)
    initrd = base / 'initramfs.cpio.gz'
    with gzip.open(initrd, 'wb', compresslevel=1) as stream:
        stream.write(archive.stdout)
    print(f'VM image: {initrd} ({initrd.stat().st_size} bytes)', flush=True)
    args.log.parent.mkdir(parents=True, exist_ok=True)
    command = ['qemu-system-x86_64', '-accel', 'tcg', '-cpu', 'max', '-smp', '2', '-m', '1536',
               '-kernel', str(args.kernel.resolve()), '-initrd', str(initrd),
               '-append', 'rdinit=/init console=ttyS0 quiet panic=1 selinux=0 systemd.log_level=warning',
               '-display', 'none', '-serial', 'stdio', '-monitor', 'none', '-no-reboot', '-nic', 'none']
    with args.log.open('w') as stream:
        result = subprocess.run(command, stdout=stream, stderr=subprocess.STDOUT, timeout=240)
    content = args.log.read_text(errors='replace')
    print(content[-18000:])
    if result.returncode or 'LYRA_TERMINAL_VM_RESULT=0' not in content or 'VM_GUEST_EXIT=0' not in content:
        raise SystemExit('VM validation failed; see ' + str(args.log))
    print('PASS: real helper lifecycle under systemd; evidence: ' + str(args.log))


if __name__ == '__main__':
    main()
