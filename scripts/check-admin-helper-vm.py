#!/usr/bin/env python3
"""Qualify administrative grants against real PAM, Polkit, Zypper and firewalld."""
import argparse
import importlib.util
from pathlib import Path
import re
import shutil
import subprocess
import sys
from vm_support import SystemdVM

REPO = Path(__file__).resolve().parents[1]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--kernel', required=True, type=Path)
    parser.add_argument('--modules-dir', required=True, type=Path)
    parser.add_argument('--vegad', required=True, type=Path)
    parser.add_argument('--policy', required=True, type=Path)
    parser.add_argument('--bin-dir', type=Path, default=REPO / 'target/debug')
    parser.add_argument('--log', type=Path, default=REPO / 'target/admin-helper-vm.log')
    args = parser.parse_args()
    for path in [args.kernel, args.vegad, args.policy]:
        if not path.is_file():
            parser.error('missing input: ' + str(path))
    vm = SystemdVM('admin', 'lyra-admin-test-vm')

    def copy_tree(source):
        source = Path(source)
        target = vm.root / str(source).lstrip('/')
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copytree(source, target, dirs_exist_ok=True,
                        ignore=shutil.ignore_patterns('__pycache__', 'tests', 'test'))

    for name in ['sleep', 'false', 'ip', 'dbus-daemon', 'dbus-monitor', 'getent', 'id', 'pkcheck',
                 'rpm', 'rpmdb', 'rpmkeys', 'rpmdb2solv', 'repo2solv',
                 'zypper', 'modprobe', 'nft', 'journalctl', 'gpasswd']:
        vm.tool(name)
    (vm.root / 'usr/sbin').symlink_to('bin')
    (vm.root / 'sbin').symlink_to('usr/bin')
    vm.binary(args.vegad, '/usr/lib/vega/vegad')
    for name in ['vega-web', 'vega-web-auth-helper', 'vega-web-admin-helper', 'vega-web-terminal-helper']:
        vm.binary(args.bin_dir / name, '/usr/lib/vega/' + name)
    polkit = next((p for p in [Path('/usr/libexec/polkit-1/polkitd'),
                              Path('/usr/lib/polkit-1/polkitd')] if p.is_file()), None)
    if polkit is None:
        parser.error('polkitd missing')
    vm.binary(polkit, '/usr/libexec/polkit-1/polkitd')
    for name in ['vega-web-admin.socket', 'vega-web-admin@.service',
                 'vega-web-auth.socket', 'vega-web-auth@.service',
                 'vega-web-terminal.socket', 'vega-web-terminal@.service']:
        vm.put('/usr/lib/systemd/system/' + name, (REPO / 'packaging' / name).read_text())
    vm.put('/candidate/vega-web.service', (REPO / 'packaging/vega-web.service').read_text())
    # A dependency anchor; it does not run the host/network service.
    vm.put('/usr/lib/systemd/system/vega-web.service', '[Service]\nType=oneshot\nExecStart=/usr/bin/true\nRemainAfterExit=yes\n')
    vm.tool('true')
    vm.put('/usr/share/polkit-1/actions/org.lyraos.vega.policy', args.policy.read_text())
    for policy in Path('/usr/share/polkit-1/actions').glob('*[Ff]irewall*'):
        vm.put(str(policy), policy.read_text())
    vm.put('/etc/polkit-1/rules.d/50-vega-web-admin.rules', (REPO / 'packaging/50-vega-web-admin.rules').read_text())
    vm.put('/etc/polkit-1/rules.d/00-vega-test-audit.rules', '''polkit.addRule(function(action, subject) {
  if (action.id.indexOf("org.lyraos.vega.") === 0)
    polkit.log("VEGA_TEST_SUBJECT user=" + subject.user + " unit=" + subject.system_unit +
               " nnp=" + subject.no_new_privileges + " action=" + action.id);
});
''')
    vm.put('/etc/pam.d/vega-web', (REPO / 'packaging/pam.d/vega-web').read_text())
    pending, seen, modules = ['common-auth', 'common-account'], set(), {'pam_exec.so'}
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
    # Artificial accounts and a deliberately public, VM-only credential.
    vm.put('/etc/passwd', 'root:x:0:0:root:/root:/bin/bash\nvega-web:x:998:998:web:/var/lib/vega-web:/bin/false\n'
           'polkitd:x:999:999:polkit:/var/lib/polkit:/bin/false\nalice:x:1001:1001:alice:/home/alice:/bin/bash\n'
           'bob:x:1002:1002:bob:/home/bob:/bin/bash\n')
    vm.put('/etc/group', 'root:x:0:\nvega-web:x:998:\npolkitd:x:999:\nwheel:x:1000:alice\nalice:x:1001:\nbob:x:1002:\n')
    password_hash = subprocess.check_output(['openssl', 'passwd', '-6', '-salt', 'vega-test', 'Vega-test-only-73!'], text=True).strip()
    vm.put('/etc/shadow', 'root:!:20000:0:99999:7:::\nvega-web:!:20000:0:99999:7:::\npolkitd:!:20000:0:99999:7:::\n'
           f'alice:{password_hash}:20000:0:99999:7:::\nbob:{password_hash}:20000:0:99999:7:::\n', 0o600)
    # No host passwords, repository credentials, local policies or disks.
    vm.put('/etc/os-release', 'ID=opensuse-leap\nVERSION_ID=16.1\nPRETTY_NAME="Vega administrative test VM"\n')
    vm.put('/etc/hosts', '127.0.0.1 localhost\n')
    for name in ['protocols', 'services']:
        source = next((Path(base) / name for base in ['/etc', '/usr/etc', '/usr/share/netcfg']
                       if (Path(base) / name).is_file()), None)
        if source is None:
            parser.error('missing network database: ' + name)
        vm.put('/etc/' + name, source.read_text())
    vm.put('/dbus-test.conf', '''<!DOCTYPE busconfig PUBLIC "-//freedesktop//DTD D-Bus Bus Configuration 1.0//EN"
"http://www.freedesktop.org/standards/dbus/1.0/busconfig.dtd">
<busconfig><type>system</type><listen>unix:path=/run/dbus/system_bus_socket</listen><auth>EXTERNAL</auth>
<policy context="default"><allow user="*"/><allow own="*"/><allow send_destination="*"/>
<allow receive_sender="*"/></policy></busconfig>
''')
    # Runtime Python packages needed by real firewalld; only installed code.
    for name in ['firewall', 'dbus', 'gi', 'nftables', 'decorator', '_dbus_bindings', '_dbus_glib_bindings']:
        spec = importlib.util.find_spec(name)
        if spec is None:
            parser.error('missing Python module: ' + name)
        source = Path(spec.origin)
        if spec.submodule_search_locations:
            copy_tree(source.parent)
            for binary in source.parent.rglob('*.so'):
                vm.binary(binary)
        elif source.suffix == '.so':
            vm.binary(source)
        else:
            vm.put(str(source), source.read_text())
    versioned_python = vm.root / f'usr/bin/python{sys.version_info.major}.{sys.version_info.minor}'
    versioned_python.symlink_to('python3')
    for name in ['firewalld', 'firewall-cmd']:
        source = Path(shutil.which(name))
        vm.put('/usr/bin/' + name, source.read_text(), 0o755)
    for directory in ['/usr/lib/firewalld', '/usr/share/firewalld', '/usr/lib/rpm']:
        if Path(directory).is_dir():
            copy_tree(directory)
    for base in ['/usr/lib64', '/usr/lib/x86_64-linux-gnu', '/usr/lib']:
        if (Path(base) / 'girepository-1.0').is_dir():
            copy_tree(Path(base) / 'girepository-1.0')
        for library in ['libnftables.so.1', 'libgio-2.0.so.0']:
            if (Path(base) / library).is_file():
                vm.binary(Path(base) / library)
        for plugin in (Path(base) / 'rpm-plugins').glob('*.so'):
            vm.binary(plugin)
    # ldd on the build host can select x86-64-v3 libraries. Include their
    # baseline SONAMEs too: guest CPU/cache paths must not depend on host ISA.
    for variant in list(vm.root.glob('**/glibc-hwcaps/*/*')):
        if not variant.is_file():
            continue
        dynamic = subprocess.check_output(['readelf', '-d', str(variant)], text=True)
        soname = re.search(r'\(SONAME\).*\[([^]]+)\]', dynamic)
        if soname:
            relative_base = variant.relative_to(vm.root).parts
            base = Path('/') / Path(*relative_base[:relative_base.index('glibc-hwcaps')])
            baseline = base / soname[1]
            if baseline.is_file():
                vm.binary(baseline)
    vm.put('/etc/firewalld/firewalld.conf', 'DefaultZone=public\nFirewallBackend=nftables\n')
    # Match the database explicitly selected by libzypp in this minimal image.
    vm.put('/etc/rpm/macros', '%_dbpath /var/lib/rpm\n')
    # Kernel modules for the selected guest kernel, never loaded on the host.
    module_dest = vm.root / 'usr/lib/modules' / args.modules_dir.name
    module_dest.mkdir(parents=True)
    for name in ['modules.dep', 'modules.dep.bin', 'modules.alias', 'modules.alias.bin',
                 'modules.builtin', 'modules.builtin.bin', 'modules.builtin.modinfo', 'modules.softdep']:
        if (args.modules_dir / name).is_file():
            shutil.copyfile(args.modules_dir / name, module_dest / name)
    for directory in ['kernel/net/netfilter', 'kernel/net/ipv4/netfilter',
                      'kernel/net/ipv6', 'kernel/crypto', 'kernel/lib']:
        if (args.modules_dir / directory).is_dir():
            shutil.copytree(args.modules_dir / directory, module_dest / directory)
    (vm.root / 'lib').mkdir(exist_ok=True)
    (vm.root / 'lib/modules').symlink_to('../usr/lib/modules')
    # An actual dependency-free RPM, installed only into the disposable VM.
    build = vm.base / 'rpm-build'
    build.mkdir()
    spec = build / 'test.spec'
    spec.write_text('''Name: vega-web-broker-vm
Version: 1
Release: 1
Summary: Disposable broker qualification payload
License: MIT
BuildArch: noarch
AutoReqProv: no
%description
VM-only proof of a successful native RPM transaction.
%install
mkdir -p %{buildroot}/usr/share/vega-web-broker-vm
printf 'installed through authenticated broker\\n' > %{buildroot}/usr/share/vega-web-broker-vm/proof
%files
/usr/share/vega-web-broker-vm/proof
''')
    result = subprocess.run(['rpmbuild', '-bb', '--define', '_topdir ' + str(build), str(spec)],
                            capture_output=True, text=True)
    if result.returncode:
        raise RuntimeError('test RPM build failed:\n' + result.stdout + result.stderr)
    rpm = next((build / 'RPMS').rglob('*.rpm'))
    (vm.root / 'packages').mkdir()
    shutil.copyfile(rpm, vm.root / 'packages' / rpm.name)
    vm.run(args.kernel, args.log, REPO / 'tests/admin_helper_vm.py',
           'vega-admin-test-vm', 'LYRA_ADMIN_VM_RESULT=0')


if __name__ == '__main__':
    main()
