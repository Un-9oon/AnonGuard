#!/usr/bin/python3 -I
"""Configure a native Linux Client or Volunteer relay; VMs are optional test fixtures."""
import argparse
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import socket
import stat
import subprocess
import sys


def ipv4_endpoint(value, wildcard=False):
    host, port = value.rsplit(':', 1)
    address = ipaddress.IPv4Address(host)
    port = int(port)
    if (not 1024 <= port <= 65535 or address.is_multicast
            or (address.is_unspecified and not wildcard)):
        raise ValueError('Endpoint must be numeric IPv4:port, port 1024..65535')
    return f'{address}:{port}'


def bootstrap(data):
    document = json.loads(data)
    if (not isinstance(document, dict) or set(document) != {'version', 'authorities', 'quorum'} or type(document['version']) is not int or document['version'] != 1
            or not isinstance(document['authorities'], list)
            or not 1 <= len(document['authorities']) <= 16):
        raise ValueError('Unsupported bootstrap format')
    quorum = document['quorum']
    if type(quorum) is not int or not (2 * len(document['authorities'])) // 3 < quorum <= len(document['authorities']):
        raise ValueError('Bootstrap quorum must exceed two thirds')
    identities, addresses, keys = set(), set(), set()
    for authority in document['authorities']:
        if not isinstance(authority, dict) or set(authority) != {'id', 'address', 'public_key'}:
            raise ValueError('Unknown or missing authority fields')
        identity = authority['id']
        if not isinstance(identity, str) or not re.fullmatch(r'[A-Za-z0-9_-]{1,64}', identity):
            raise ValueError('Invalid authority identifier')
        address = ipv4_endpoint(authority['address'])
        public = authority['public_key']
        if not isinstance(public, str) or not re.fullmatch(r'[0-9a-fA-F]{64}', public) or int(public, 16) == 0:
            raise ValueError('Authority pin must be a nonzero 32-byte hex key')
        public = public.lower()
        if identity in identities or address in addresses or public in keys:
            raise ValueError('Duplicate authority identity, endpoint or key')
        identities.add(identity)
        addresses.add(address)
        keys.add(public)
        authority.update(address=address, public_key=public)
    return document


def read_bootstrap(path, expected):
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(descriptor, 'rb') as stream:
        if not stat.S_ISREG(os.fstat(stream.fileno()).st_mode):
            raise ValueError('Bootstrap must be a regular file')
        data = stream.read(65537)
    if len(data) > 65536:
        raise ValueError('Bootstrap exceeds size bound')
    digest = hashlib.sha256(data).hexdigest()
    if not re.fullmatch('[0-9a-fA-F]{64}', expected) or digest != expected.lower():
        raise ValueError('Bootstrap digest does not match the independently authenticated digest')
    return bootstrap(data), data, digest


def client_firewall():
    # nft resolves these dedicated system accounts at activation. They must exist.
    net = '"anonguard-net"'
    adapter = '"anonguard-adapter"'
    return f'''add table inet anonguard_native
flush table inet anonguard_native
add chain inet anonguard_native input {{ type filter hook input priority -10; policy drop; }}
add chain inet anonguard_native output {{ type filter hook output priority -10; policy drop; }}
add chain inet anonguard_native forward {{ type filter hook forward priority -10; policy drop; }}
add chain inet anonguard_native nat_output {{ type nat hook output priority -100; policy accept; }}
add rule inet anonguard_native nat_output meta skuid != {{ {net}, {adapter} }} ip protocol udp udp dport 53 redirect to :1053
add rule inet anonguard_native nat_output meta skuid != {{ {net}, {adapter} }} ip protocol tcp tcp dport 53 redirect to :1053
add rule inet anonguard_native nat_output meta skuid != {{ {net}, {adapter} }} ip daddr != 127.0.0.0/8 ip protocol tcp redirect to :9040
add rule inet anonguard_native input ct state invalid drop
add rule inet anonguard_native input ct state established accept
add rule inet anonguard_native input iifname "lo" ip daddr 127.0.0.1 tcp dport {{ 9050, 9040, 1053 }} accept
add rule inet anonguard_native input iifname "lo" ip daddr 127.0.0.1 udp dport 1053 accept
add rule inet anonguard_native input ip protocol udp udp sport 67 udp dport 68 accept
add rule inet anonguard_native output ct state invalid drop
add rule inet anonguard_native output meta skuid {net} meta nfproto ipv4 ip protocol tcp accept
add rule inet anonguard_native output meta skuid {adapter} oifname "lo" ip daddr 127.0.0.1 tcp dport 9050 accept
add rule inet anonguard_native output meta skuid {adapter} oifname "lo" ct state established tcp sport {{ 9040, 1053 }} accept
add rule inet anonguard_native output meta skuid {adapter} oifname "lo" ct state established udp sport 1053 accept
add rule inet anonguard_native output oifname "lo" ip daddr 127.0.0.1 tcp dport {{ 9050, 9040, 1053 }} accept
add rule inet anonguard_native output oifname "lo" ip daddr 127.0.0.1 udp dport 1053 accept
add rule inet anonguard_native output ip protocol udp udp sport 68 udp dport 67 accept
'''


FIREWALL_SERVICE = '''[Unit]
Description=Native AnonGuard client default-deny boundary
DefaultDependencies=no
Before=network-pre.target shutdown.target
Wants=network-pre.target
Conflicts=shutdown.target

[Service]
Type=oneshot
ExecStart=/usr/sbin/nft -f /etc/anonguard/native.nft
ExecReload=/usr/sbin/nft -f /etc/anonguard/native.nft
RemainAfterExit=yes
# No ExecStop: never remove restrictions merely because a service exits.

[Install]
WantedBy=multi-user.target
'''

SANDBOX = '''NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
RestrictAddressFamilies=AF_INET AF_UNIX
CapabilityBoundingSet=
LimitCORE=0
UMask=0077
TasksMax=256
MemoryHigh=768M
MemoryMax=1G
MemorySwapMax=0
CPUQuota=200%
LimitNOFILE=4096
'''


def profile(role, document, digest, bind='0.0.0.0:9443', advertised=None):
    if role not in ('client', 'volunteer'):
        raise ValueError('Choose client or volunteer')
    bound = ipv4_endpoint(bind, wildcard=True)
    if role == 'volunteer':
        if advertised is None:
            raise ValueError('Volunteer requires a reachable advertised endpoint')
        advertised = ipv4_endpoint(advertised)
        if ipaddress.IPv4Address(advertised.split(':')[0]).is_loopback:
            raise ValueError('Volunteer endpoint cannot be loopback')
    endpoints = ','.join(f"{a['id']}@{a['address']}" for a in document['authorities'])
    pins = ','.join(f"{a['id']}:{a['public_key']}" for a in document['authorities'])
    arguments = f'--authorities {endpoints} --authority-keys {pins} --quorum-threshold {document["quorum"]}'
    service_role = 'client' if role == 'client' else 'relay'
    directory = f'anonguard-{service_role}'
    extra = '--onion --padded-sessions --privacy-profile balanced --listen 127.0.0.1:9050' if role == 'client' else f'--relay --listen {bound} --advertise-address {advertised}'
    dependencies = ('Requires=anonguard-native-firewall.service\nAfter=anonguard-native-firewall.service\nWants=anonguard-native-adapter.service\n'
                    if role == 'client' else '')
    files = {
        f'etc/anonguard/{service_role}.env': f'ANONGUARD_ARGS="{arguments}"\n',
        f'etc/systemd/system/anonguard-{service_role}.service': f'''[Unit]
Description=Native AnonGuard {service_role}
After=network-online.target
Wants=network-online.target
{dependencies}
[Service]
Type=simple
User=anonguard-net
Group=anonguard-net
StateDirectory={directory}
StateDirectoryMode=0700
EnvironmentFile=/etc/anonguard/{service_role}.env
ExecStart=/usr/bin/anonguard-daemon {extra} --identity-key-path /var/lib/{directory}/identity.key --guard-state-path /var/lib/{directory}/guards.json $ANONGUARD_ARGS
Restart=on-failure
RestartSec=5
{SANDBOX}
[Install]
WantedBy=multi-user.target
''',
    }
    if role == 'client':
        files['etc/anonguard/native.nft'] = client_firewall()
        files['etc/systemd/system/anonguard-native-firewall.service'] = FIREWALL_SERVICE
        files['etc/systemd/system/anonguard-native-adapter.service'] = f'''[Unit]
Description=Native transparent TCP and protected DNS adapter
BindsTo=anonguard-client.service
Requires=anonguard-native-firewall.service
After=anonguard-native-firewall.service anonguard-client.service

[Service]
Type=simple
User=anonguard-adapter
Group=anonguard-adapter
ExecStart=/usr/bin/anonguard-native-adapter
Restart=on-failure
RestartSec=5
{SANDBOX}
[Install]
WantedBy=multi-user.target
'''
        for manager in ('NetworkManager', 'systemd-networkd'):
            files[f'etc/systemd/system/{manager}.service.d/anonguard-native.conf'] = '''[Unit]
Requires=anonguard-native-firewall.service
After=anonguard-native-firewall.service
'''
    files['etc/anonguard/device.json'] = json.dumps({
        'version': 1, 'role': role, 'bootstrap_sha256': digest,
        'socks': '127.0.0.1:9050' if role == 'client' else None,
        'relay_bind': bound if role == 'volunteer' else None,
        'relay_advertise': advertised if role == 'volunteer' else None,
        'exit_node': False, 'deployment_accepted': False,
    }, indent=2) + '\n'
    return files


def write_exclusive(path, text, mode=0o600):
    previous_mask = os.umask(0o022)
    try:
        path.parent.mkdir(mode=0o755, parents=True, exist_ok=True)
    finally:
        os.umask(previous_mask)
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode)
    os.fchmod(descriptor, mode)
    with os.fdopen(descriptor, 'w') as stream:
        stream.write(text)
        stream.flush()
        os.fsync(stream.fileno())


def apply(files):
    if sys.platform != 'linux' or os.geteuid() != 0 or os.environ.get('SSH_CONNECTION'):
        raise ValueError('Apply requires root at the Linux device console, not an SSH session')
    # Never reinterpret an existing installation or silently replace its keys/guards.
    if Path('/etc/anonguard/device.json').exists() or Path('/var/lib/anonguard/identity.key').exists():
        raise ValueError('Existing configuration/state requires an explicit reviewed migration')
    for name in ('anonguard.service', 'anonguard-client.service', 'anonguard-relay.service'):
        result = subprocess.run(['/usr/bin/systemctl', 'is-active', '--quiet', name], check=False)
        enabled = subprocess.run(['/usr/bin/systemctl', 'is-enabled', '--quiet', name], check=False)
        if result.returncode == 0 or enabled.returncode == 0:
            raise ValueError('Stop and disable existing AnonGuard services before native configuration')
    for relative in files:
        path = Path('/') / relative
        if path.exists() or path.is_symlink():
            raise ValueError('Refusing to overwrite existing native configuration')
        for parent in path.parents:
            if parent.exists():
                metadata = parent.lstat()
                if stat.S_ISLNK(metadata.st_mode) or metadata.st_uid != 0 or metadata.st_mode & 0o022:
                    raise ValueError('Configuration ancestor is not administrator-controlled')
    for required in ('/usr/bin/anonguard-daemon', '/usr/bin/systemctl', '/usr/bin/systemd-sysusers',
                     '/usr/lib/sysusers.d/anonguard-native.conf'):
        metadata = Path(required).lstat()
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_uid != 0 or metadata.st_mode & 0o022:
            raise ValueError('Required installed dependency is not administrator-controlled')
    if json.loads(files['etc/anonguard/device.json'])['role'] == 'client':
        for required in ('/usr/bin/anonguard-native-adapter', '/usr/sbin/nft'):
            if not os.access(required, os.X_OK):
                raise ValueError('Native client dependency missing: ' + required)
    # Provision dedicated accounts before nft resolves their identities.
    subprocess.run(['/usr/bin/systemd-sysusers', '/usr/lib/sysusers.d/anonguard-native.conf'], check=True)
    for relative, content in files.items():
        write_exclusive(Path('/') / relative, content, 0o644 if relative.endswith('/device.json') else 0o600)
    subprocess.run(['/usr/bin/systemctl', 'daemon-reload'], check=True)
    client = json.loads(files['etc/anonguard/device.json'])['role'] == 'client'
    if client:
        subprocess.run(['/usr/sbin/nft', '--check', '--file', '/etc/anonguard/native.nft'], check=True)
        # Restrictions become active before any transport/application adapter starts.
        subprocess.run(['/usr/bin/systemctl', 'enable', '--now', 'anonguard-native-firewall.service'], check=True)
        subprocess.run(['/usr/bin/systemctl', 'enable', '--now', 'anonguard-client.service'], check=True)
        subprocess.run(['/usr/bin/systemctl', 'enable', '--now', 'anonguard-native-adapter.service'], check=True)
    else:
        subprocess.run(['/usr/bin/systemctl', 'enable', '--now', 'anonguard-relay.service'], check=True)


def check_app_containment():
    """Probe the current ordinary user's namespace permission; no policy changes."""
    if sys.platform != 'linux' or os.geteuid() == 0:
        raise ValueError('Run --check-app-containment as the ordinary application user on Linux, without sudo')
    executable = Path('/usr/bin/bwrap')
    for dependency in (executable, Path('/usr/bin/true')):
        resolved = dependency.resolve(strict=True)
        metadata = resolved.stat()
        if (not stat.S_ISREG(metadata.st_mode) or metadata.st_uid != 0
                or metadata.st_mode & (0o022 | stat.S_ISUID | stat.S_ISGID)
                or not os.access(resolved, os.X_OK)):
            raise ValueError('Probe requires trusted non-set-ID OS dependency: ' + str(dependency))
        for parent in resolved.parents:
            metadata = parent.stat()
            if metadata.st_uid != 0 or metadata.st_mode & 0o022:
                raise ValueError('Probe dependency ancestor is not administrator-controlled')
    restriction = Path('/proc/sys/kernel/apparmor_restrict_unprivileged_userns')
    restricted = restriction.read_text().strip() == '1' if restriction.exists() else None
    result = subprocess.run([
        str(executable), '--ro-bind', '/', '/', '--proc', '/proc', '--dev', '/dev',
        '--unshare-all', '--die-with-parent', '--new-session', '--', '/usr/bin/true',
    ], capture_output=True, text=True, timeout=10, env={'PATH': '/usr/bin:/bin', 'LANG': 'C'})
    report = {'namespace_probe_passed': result.returncode == 0,
              'apparmor_userns_restricted': restricted,
              'host_policy_modified': False, 'deployment_accepted': False,
              'scope': 'current user basic Bubblewrap namespaces; not full application containment'}
    if result.returncode:
        report['diagnostic'] = result.stderr.strip()[:2000]
        report['action'] = ('Review the vendor Bubblewrap AppArmor profile and '
                            '/usr/share/doc/anonguard/anonguard-bwrap.apparmor with an administrator. '
                            'Keep existing vendor attachments; do not disable AppArmor or kernel restrictions. '
                            'See docs/LINUX_APP_CONTAINMENT.md; other kernel/container restrictions may also deny namespaces.')
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--role', choices=('client', 'volunteer'))
    parser.add_argument('--bootstrap', type=Path)
    parser.add_argument('--bootstrap-sha256')
    action = parser.add_mutually_exclusive_group(required=True)
    action.add_argument('--output', type=Path, help='Render only; never activate services')
    action.add_argument('--apply', action='store_true', help='Configure this device from its console')
    action.add_argument('--check-app-containment', action='store_true',
                        help='Read-only ordinary-user Bubblewrap prerequisite probe; no bootstrap needed')
    parser.add_argument('--relay-bind', default='0.0.0.0:9443')
    parser.add_argument('--relay-advertise')
    args = parser.parse_args()
    try:
        if args.check_app_containment:
            report = check_app_containment()
            print(json.dumps(report))
            return 0 if report['namespace_probe_passed'] else 1
        if args.role is None:
            if not sys.stdin.isatty():
                raise ValueError('Noninteractive setup requires --role')
            print('1. Client: protect this device\n2. Volunteer: forward encrypted relay traffic (not an exit)')
            args.role = {'1': 'client', '2': 'volunteer'}.get(input('Choose 1 or 2: ').strip())
            if args.role is None:
                raise ValueError('Invalid role choice')
        if args.bootstrap is None:
            if not sys.stdin.isatty():
                raise ValueError('A trusted network bootstrap file is required')
            args.bootstrap = Path(input('Network bootstrap file: ').strip())
        if args.bootstrap_sha256 is None:
            if not sys.stdin.isatty():
                raise ValueError('Supply the independently authenticated bootstrap SHA-256')
            args.bootstrap_sha256 = input('Trusted bootstrap SHA-256: ').strip()
        if args.role == 'volunteer' and args.relay_advertise is None and sys.stdin.isatty():
            args.relay_advertise = input('Reachable relay IPv4:port (configure NAT forwarding separately): ').strip()
        document, _data, digest = read_bootstrap(args.bootstrap, args.bootstrap_sha256)
        files = profile(args.role, document, digest, args.relay_bind, args.relay_advertise)
        if args.apply:
            apply(files)
        else:
            args.output.mkdir(mode=0o700)
            for relative, content in files.items():
                write_exclusive(args.output / relative, content, 0o644 if relative.endswith('/device.json') else 0o600)
        print(json.dumps({'role': args.role, 'configured': True, 'services_started': args.apply,
                          'deployment_accepted': False, 'virtual_machine_required': False}))
        return 0
    except (ValueError, OSError, KeyError, TypeError, subprocess.SubprocessError) as error:
        print(f'Native setup refused: {error}', file=sys.stderr)
        if args.apply:
            print('Partial configuration may remain. Inspect from the console; never remove the firewall to restore direct traffic.', file=sys.stderr)
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
