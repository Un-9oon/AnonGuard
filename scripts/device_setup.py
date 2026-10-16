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
    if (not isinstance(document, dict) or set(document) != {'version', 'authorities', 'quorum'} or type(document['version']) is not int or document['version'] != 6
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
            raise ValueError('Authority pin must be a nonzero 32-byte composite hex pin')
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


def transport_configuration(value, document):
    """Validate operator-authenticated obfs4 bindings before any host mutation."""
    if (not isinstance(value, dict) or set(value) != {'mode', 'binary', 'bridges', 'authorities'}
            or value['mode'] != 'client' or value['binary'] != '/usr/bin/obfs4proxy'):
        raise ValueError('Native transport requires client mode and packaged /usr/bin/obfs4proxy')
    endpoints = set()
    for field, maximum in (('bridges', 3), ('authorities', 16)):
        entries = value[field]
        if not isinstance(entries, list) or not 1 <= len(entries) <= maximum:
            raise ValueError('Invalid native transport binding count')
        pins, addresses = set(), set()
        for entry in entries:
            if not isinstance(entry, dict) or set(entry) != {'identity', 'bridge', 'arguments'}:
                raise ValueError('Invalid native transport binding fields')
            pin = entry['identity']
            if (not isinstance(pin, list) or len(pin) != 32 or not any(pin)
                    or any(type(byte) is not int or not 0 <= byte <= 255 for byte in pin)):
                raise ValueError('Invalid native composite identity pin')
            if not isinstance(entry['bridge'], str):
                raise ValueError('Transport endpoint must be numeric IPv4:port')
            try:
                host, port = entry['bridge'].rsplit(':', 1)
                ip = ipaddress.IPv4Address(host)
            except ValueError:
                raise ValueError('Transport endpoint must be numeric IPv4:port') from None
            if (not port.isascii() or not port.isdecimal() or not 1 <= int(port) <= 65535
                    or ip.is_unspecified or ip.is_multicast):
                raise ValueError('Invalid native transport endpoint')
            endpoint = f'{ip}:{int(port)}'
            if endpoint != entry['bridge']:
                raise ValueError('Transport endpoint must use canonical numeric encoding')
            ip = ipaddress.IPv4Address(endpoint.rsplit(':', 1)[0])
            if ip.is_loopback or ip.is_link_local or ip.is_reserved or int(ip) == 0xffffffff:
                raise ValueError('Native transport requires a reachable unicast IPv4 endpoint')
            if tuple(pin) in pins or endpoint in addresses:
                raise ValueError('Duplicate native transport identity or endpoint')
            pins.add(tuple(pin)); addresses.add(endpoint); endpoints.add(endpoint)
            arguments = entry['arguments']
            if (not isinstance(arguments, dict) or not arguments
                    or any(not isinstance(k, str) or not k or not isinstance(v, str)
                           or any(ord(c) < 32 or 127 <= ord(c) <= 159 for c in k + v)
                           for k, v in arguments.items())):
                raise ValueError('Invalid native transport arguments')
            def escape(text):
                return ''.join(('\\' if c in '\\=;' else '') + c for c in text)
            encoded = ';'.join(escape(k) + '=' + escape(v) for k, v in sorted(arguments.items()))
            if len(encoded.encode('utf-8')) > 254:
                raise ValueError('Native transport arguments exceed 254 bytes')
    expected = {tuple(bytes.fromhex(a['public_key'])) for a in document['authorities']}
    actual = {tuple(entry['identity']) for entry in value['authorities']}
    if actual != expected:
        raise ValueError('Transport bindings must cover exactly the trusted authority pins')
    return value, sorted(endpoints)


def read_transport(path, expected, document):
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(descriptor, 'rb') as stream:
        metadata = os.fstat(stream.fileno())
        if (not stat.S_ISREG(metadata.st_mode) or metadata.st_mode & 0o077
                or metadata.st_uid not in (0, os.geteuid())):
            raise ValueError('Transport config must be a private regular file owned by this account or root')
        data = stream.read(65537)
    if len(data) > 65536:
        raise ValueError('Transport configuration exceeds 64 KiB')
    digest = hashlib.sha256(data).hexdigest()
    if not isinstance(expected, str) or not re.fullmatch('[0-9a-fA-F]{64}', expected) or digest != expected.lower():
        raise ValueError('Transport config digest does not match the independently authenticated digest')
    value, _ = transport_configuration(json.loads(data), document)
    return value, digest


def client_firewall(transport_endpoints=None):
    # nft resolves these dedicated system accounts at activation. They must exist.
    net = '"anonguard-net"'
    adapter = '"anonguard-adapter"'
    bypass = f'{net}, {adapter}'
    if transport_endpoints is None:
        backend_egress = f'add rule inet anonguard_native output meta skuid {net} meta nfproto ipv4 ip protocol tcp accept\n'
        transport_rules = ''
    else:
        bypass += ', "anonguard-pt-native"'
        # Only the dedicated PT account can reach provisioned external endpoints.
        # Daemon output is restricted to loopback; ordinary users still cannot
        # open the dynamically negotiated PT SOCKS port under the output policy.
        backend_egress = f'add rule inet anonguard_native output meta skuid {net} oifname "lo" ip daddr 127.0.0.1 tcp dport 1024-65535 accept\n'
        destinations = ', '.join(endpoint.replace(':', ' . ') for endpoint in transport_endpoints)
        transport_rules = f'''add rule inet anonguard_native input iifname "lo" ip daddr 127.0.0.1 tcp dport 1024-65535 accept
add rule inet anonguard_native output meta skuid "anonguard-pt-native" ip daddr . tcp dport {{ {destinations} }} accept
add rule inet anonguard_native output meta skuid "anonguard-pt-native" oifname "lo" ip daddr 127.0.0.1 ct state established ip protocol tcp accept
'''
    return f'''add table inet anonguard_native
flush table inet anonguard_native
add chain inet anonguard_native input {{ type filter hook input priority -10; policy drop; }}
add chain inet anonguard_native output {{ type filter hook output priority -10; policy drop; }}
add chain inet anonguard_native forward {{ type filter hook forward priority -10; policy drop; }}
add chain inet anonguard_native nat_output {{ type nat hook output priority -100; policy accept; }}
add rule inet anonguard_native nat_output meta skuid != {{ {bypass} }} ip protocol udp udp dport 53 redirect to :1053
add rule inet anonguard_native nat_output meta skuid != {{ {bypass} }} ip protocol tcp tcp dport 53 redirect to :1053
add rule inet anonguard_native nat_output meta skuid != {{ {bypass} }} ip daddr != 127.0.0.0/8 ip protocol tcp redirect to :9040
add rule inet anonguard_native input ct state invalid drop
add rule inet anonguard_native input ct state established accept
add rule inet anonguard_native input iifname "lo" ip daddr 127.0.0.1 tcp dport {{ 9050, 9040, 1053 }} accept
add rule inet anonguard_native input iifname "lo" ip daddr 127.0.0.1 udp dport 1053 accept
add rule inet anonguard_native input ip protocol udp udp sport 67 udp dport 68 accept
add rule inet anonguard_native output ct state invalid drop
{backend_egress}{transport_rules}\
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


def profile(role, document, digest, bind='0.0.0.0:9443', advertised=None,
            transport=None, transport_digest=None, direct_entry_lab=False,
            link_cover_profile='strict', privacy_profile='balanced'):
    if role not in ('client', 'volunteer'):
        raise ValueError('Choose client or volunteer')
    if link_cover_profile not in ('strict', 'economy') or privacy_profile not in ('balanced', 'balanced-longtail'):
        raise ValueError('Unsupported native cover or session profile')
    if role != 'client' and privacy_profile != 'balanced':
        raise ValueError('Session profile applies only to a client')
    if role != 'client' and (transport is not None or direct_entry_lab):
        raise ValueError('Entry transport policy applies only to a client')
    if role == 'client' and ((transport is None) == (not direct_entry_lab)):
        raise ValueError('Client requires authenticated transport config or explicit --direct-entry-lab')
    transport_endpoints = None
    if transport is not None:
        transport, transport_endpoints = transport_configuration(transport, document)
        if not isinstance(transport_digest, str) or not re.fullmatch('[0-9a-f]{64}', transport_digest):
            raise ValueError('Authenticated transport digest required')
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
    extra = f'--onion --padded-sessions --privacy-profile {privacy_profile} --listen 127.0.0.1:9050' if role == 'client' else f'--relay --listen {bound} --advertise-address {advertised}'
    extra += f' --link-cover-profile {link_cover_profile}'
    dependencies = ('Requires=anonguard-native-firewall.service\nAfter=anonguard-native-firewall.service\nWants=anonguard-native-adapter.service\n'
                    if role == 'client' else '')
    credentials = ''
    if transport is not None:
        extra += (' --protected-entry --private-bridges'
                  ' --bridge-transports ${CREDENTIALS_DIRECTORY}/bridges.json'
                  ' --authority-transports ${CREDENTIALS_DIRECTORY}/authorities.json')
        dependencies += ('Requires=anonguard-native-pt.service\nBindsTo=anonguard-native-pt.service\n'
                         'PartOf=anonguard-native-pt.service\nAfter=anonguard-native-pt.service\n')
        credentials = ('LoadCredential=bridges.json:/run/anonguard-native-pt/bridges.json\n'
                       'LoadCredential=authorities.json:/run/anonguard-native-pt/authorities.json\n')
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
{credentials}\
ExecStart=/usr/bin/anonguard-daemon {extra} --identity-key-path /var/lib/{directory}/identity.key --guard-state-path /var/lib/{directory}/guards.json $ANONGUARD_ARGS
Restart=on-failure
RestartSec=5
TimeoutStopSec=5
KillMode=control-group
{SANDBOX}
[Install]
WantedBy=multi-user.target
''',
    }
    if role == 'client':
        files['etc/anonguard/native.nft'] = client_firewall(transport_endpoints)
        files['etc/systemd/system/anonguard-native-firewall.service'] = FIREWALL_SERVICE
        files['etc/systemd/system/anonguard-native-adapter.service'] = f'''[Unit]
Description=Native transparent TCP and protected DNS adapter
BindsTo=anonguard-client.service
PartOf=anonguard-client.service
Requires=anonguard-native-firewall.service
After=anonguard-native-firewall.service anonguard-client.service

[Service]
Type=simple
User=anonguard-adapter
Group=anonguard-adapter
ExecStart=/usr/bin/anonguard-native-adapter
Restart=on-failure
RestartSec=5
TimeoutStopSec=5
KillMode=control-group
{SANDBOX}
[Install]
WantedBy=multi-user.target
'''
        for manager in ('NetworkManager', 'systemd-networkd'):
            files[f'etc/systemd/system/{manager}.service.d/anonguard-native.conf'] = '''[Unit]
Requires=anonguard-native-firewall.service
After=anonguard-native-firewall.service
'''
    if transport is not None:
        files['etc/anonguard/pt-native.json'] = json.dumps(transport, sort_keys=True) + '\n'
        pt_sandbox = SANDBOX.replace('TasksMax=256', 'TasksMax=64').replace('MemoryHigh=768M', 'MemoryHigh=192M').replace('MemoryMax=1G', 'MemoryMax=256M').replace('CPUQuota=200%', 'CPUQuota=100%')
        files['etc/systemd/system/anonguard-native-pt.service'] = f'''[Unit]
Description=Native AnonGuard protected entry transport
Requires=anonguard-native-firewall.service
After=network-online.target anonguard-native-firewall.service
Wants=network-online.target
Before=anonguard-client.service

[Service]
Type=notify
NotifyAccess=main
User=anonguard-pt-native
Group=anonguard-pt-native
StateDirectory=anonguard-native-pt
StateDirectoryMode=0700
RuntimeDirectory=anonguard-native-pt
RuntimeDirectoryMode=0700
LoadCredential=pt.json:/etc/anonguard/pt-native.json
ExecStart=/usr/bin/python3 /usr/bin/anonguard-pt --config ${{CREDENTIALS_DIRECTORY}}/pt.json --state /var/lib/anonguard-native-pt --runtime /run/anonguard-native-pt
Restart=on-failure
RestartSec=5
TimeoutStartSec=20
TimeoutStopSec=5
KillMode=control-group
{pt_sandbox}
[Install]
WantedBy=multi-user.target
'''
    files['etc/anonguard/device.json'] = json.dumps({
        'version': 1, 'role': role, 'bootstrap_sha256': digest,
        'socks': '127.0.0.1:9050' if role == 'client' else None,
        'relay_bind': bound if role == 'volunteer' else None,
        'relay_advertise': advertised if role == 'volunteer' else None,
        'exit_node': False, 'deployment_accepted': False,
        'entry_policy': 'protected-obfs4' if transport is not None else ('direct-lab' if role == 'client' else None),
        'transport_sha256': transport_digest,
        'link_cover_profile': link_cover_profile,
        'privacy_profile': privacy_profile if role == 'client' else None,
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
    if 'etc/anonguard/pt-native.json' in files:
        for required in ('/usr/bin/anonguard-pt', '/usr/bin/obfs4proxy', '/usr/bin/python3'):
            path = Path(required).resolve(strict=True)
            metadata = path.stat()
            if (not stat.S_ISREG(metadata.st_mode) or metadata.st_uid != 0
                    or metadata.st_mode & 0o022 or not os.access(path, os.X_OK)):
                raise ValueError('Protected entry dependency must be a trusted installed executable')
            for parent in path.parents:
                metadata = parent.stat()
                if metadata.st_uid != 0 or metadata.st_mode & 0o022:
                    raise ValueError('Protected entry dependency ancestor must be administrator-controlled')
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
    policy = parser.add_mutually_exclusive_group()
    policy.add_argument('--transport-config', type=Path, help='Private operator-provisioned obfs4 client configuration')
    policy.add_argument('--direct-entry-lab', action='store_true', help='Explicit lab-only opt-in to recognizable direct entry TLS')
    parser.add_argument('--transport-config-sha256', help='Independently authenticated transport config digest')
    parser.add_argument('--link-cover-profile', choices=('strict', 'economy'), default='strict',
                        help='Authenticated link schedule; economy requires matching configuration at every hop')
    parser.add_argument('--privacy-profile', choices=('balanced', 'balanced-longtail'), default='balanced',
                        help='Client session tail policy; longer tails consume additional cover bandwidth')
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
        if args.role == 'client' and args.transport_config is None and not args.direct_entry_lab and sys.stdin.isatty():
            args.transport_config = Path(input('Private operator transport configuration file: ').strip())
        if args.transport_config is not None and args.transport_config_sha256 is None and sys.stdin.isatty():
            args.transport_config_sha256 = input('Independently authenticated transport configuration SHA-256: ').strip()
        if args.transport_config_sha256 and args.transport_config is None:
            raise ValueError('Transport digest requires --transport-config')
        transport, transport_digest = (read_transport(args.transport_config, args.transport_config_sha256, document)
                                       if args.transport_config else (None, None))
        files = profile(args.role, document, digest, args.relay_bind, args.relay_advertise,
                        transport, transport_digest, args.direct_entry_lab,
                        args.link_cover_profile, args.privacy_profile)
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
