#!/usr/bin/python3 -I
"""Guided Linux native Client/Volunteer setup; requires authentic operator inputs."""
import argparse
from contextlib import contextmanager
import fcntl
from importlib.machinery import SourceFileLoader
import importlib.util
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys


def module(name, installed):
    source = Path(__file__).with_name(name + '.py')
    if not source.exists():
        source = Path(__file__).with_name(installed)
    spec = importlib.util.spec_from_loader(name, SourceFileLoader(name, str(source)))
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


setup = module('device_setup', 'anonguard-setup')
browser = module('browser_session', 'anonguard-browser')
RECEIPT = Path('/etc/anonguard/onboarding.json')
DEPENDENCIES = ('/usr/bin/anonguard-daemon', '/usr/bin/systemctl', '/usr/bin/systemd-sysusers',
                '/usr/bin/python3', '/usr/sbin/nft', '/usr/bin/obfs4proxy', '/usr/sbin/ip',
                '/usr/bin/pgrep', '/usr/bin/anonguard-browser', '/usr/bin/anonguard-native-adapter')


def guarded_write(path, content, mode=0o644):
    """Install a new root-controlled file; matching files are left unchanged."""
    for parent in reversed(path.parents):
        if not parent.exists() and not parent.is_symlink():
            parent.mkdir(mode=0o755)
        info = parent.lstat()
        if not parent.is_dir() or parent.is_symlink() or info.st_uid != 0 or info.st_mode & 0o022:
            raise ValueError('Configuration ancestors must be root-controlled')
    if path.exists() or path.is_symlink():
        if browser.trusted_file(path, maximum=2 * 1024 * 1024) != content.encode():
            raise ValueError('Conflicting existing configuration requires reviewed migration: ' + str(path))
        return
    setup.write_exclusive(path, content, mode)


def browser_files(executable):
    return {
        Path('/etc/firefox/policies/policies.json'): json.dumps(browser.policy('127.0.0.1', 9050, True, True), indent=2) + '\n',
        executable.parent / 'distribution/policies.json': json.dumps(browser.policy('127.0.0.1', 9050, True, True), indent=2) + '\n',
        executable.parent / 'anonguard.cfg': browser.autoconfig(),
        executable.parent / 'defaults/pref/anonguard.js': browser.AUTOCONFIG_LOADER,
    }


def validate_targets(files):
    """Check all existing destinations before publishing any browser configuration."""
    for path, content in files.items():
        if path.exists() or path.is_symlink():
            if browser.trusted_file(path, maximum=2 * 1024 * 1024) != content.encode():
                raise ValueError('Conflicting existing browser configuration: ' + str(path))
        for parent in path.parents:
            if parent.exists() or parent.is_symlink():
                info = parent.lstat()
                if parent.is_symlink() or not parent.is_dir() or info.st_uid != 0 or info.st_mode & 0o022:
                    raise ValueError('Browser configuration ancestor is not root-controlled')


def inspect(args):
    if sys.platform != 'linux':
        raise ValueError('Native onboarding currently supports Linux only')
    if args.role == 'volunteer' and any(getattr(args, key) is not None for key in (
            'transport_config', 'transport_config_sha256', 'browser', 'extension',
            'extension_sha256', 'extension_version', 'previous_extension_sha256')):
        raise ValueError('Client browser/transport options cannot be applied to a volunteer')
    document, _, digest = setup.read_bootstrap(args.bootstrap, args.bootstrap_sha256)
    transport = transport_digest = None
    if args.role == 'client':
        if args.transport_config is None:
            raise ValueError('Client onboarding requires authentic protected-entry transport configuration')
        transport, transport_digest = setup.read_transport(args.transport_config, args.transport_config_sha256, document)
    files = setup.profile(args.role, document, digest, advertised=args.relay_advertise,
                          transport=transport, transport_digest=transport_digest,
                          privacy_profile=getattr(args, 'privacy_profile', 'balanced'))
    missing = [name for name in DEPENDENCIES if not os.access(name, os.X_OK)]
    if missing:
        raise ValueError('Install the native package dependencies first: ' + ', '.join(missing))
    executable = None
    policies = {}
    if args.role == 'client':
        if args.browser is None:
            raise ValueError('Client onboarding requires --browser pointing to a maintained root-installed Firefox ESR')
        executable = args.browser.resolve(strict=True)
        browser.trusted_file(executable, maximum=64 * 1024 * 1024)
        if os.statvfs(executable.parent).f_flag & os.ST_RDONLY:
            raise ValueError('Firefox layout is read-only; provision a dedicated writable root-installed ESR')
        if not os.access(executable, os.X_OK):
            raise ValueError('Browser must be executable')
        version = subprocess.run([str(executable), '--version'], capture_output=True, text=True,
                                 check=True, timeout=10, env={'PATH': '/usr/bin:/bin'}).stdout
        if not re.search(r'Firefox (?:1[4-9]\d|[2-9]\d{2})\.\d+(?:\.\d+)*esr\b', version):
            raise ValueError('Supported browsing foundation is maintained Firefox ESR 140 or later')
        policies = browser_files(executable)
        validate_targets(policies)
        if args.extension:
            content = browser.read_addon_file(args.extension, 1024 * 1024)
            observed = browser.validate_extension(content)
            if observed['sha256'] != args.extension_sha256 or observed['version'] != args.extension_version:
                raise ValueError('Signed-addon bytes/version differ from authenticated operator approval')
            browser.addon_version(observed['version'])
        else:
            browser.installed_extension()
    return files, policies, executable


@contextmanager
def configuration_lock():
    descriptor = os.open('/run/anonguard-onboard.lock', os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_NONBLOCK, 0o600)
    try:
        info = os.fstat(descriptor)
        if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o077:
            raise ValueError('Unsafe onboarding lock')
        fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        yield
    finally:
        os.close(descriptor)


def apply(args, files, policies, executable):
    if os.geteuid() != 0 or os.environ.get('SSH_CONNECTION'):
        raise ValueError('Apply requires root at the local device console; use --plan over SSH')
    setup.require_console()
    with configuration_lock():
        return _apply_locked(args, files, policies, executable)


def _apply_locked(args, files, policies, executable):
    if os.geteuid() != 0 or os.environ.get('SSH_CONNECTION'):
        raise ValueError('Apply requires root at the local device console; use --plan over SSH')
    if RECEIPT.exists() or RECEIPT.is_symlink():
        raise ValueError('This device is already onboarded; use reviewed upgrade/recovery, not fresh setup')
    setup.validate_apply(files)
    if args.role == 'client':
        running = subprocess.run(['/usr/bin/pgrep', '-x', 'firefox|firefox-esr|firefox-bin'], capture_output=True)
        if running.returncode != 1:
            raise ValueError('Stop Firefox before configuring the dedicated installation')
        if args.extension:
            command = ['/usr/bin/anonguard-browser', '--install-extension', str(args.extension.absolute()),
                       '--extension-sha256', args.extension_sha256, '--extension-version', args.extension_version]
            if args.previous_extension_sha256:
                command += ['--previous-extension-sha256', args.previous_extension_sha256]
            subprocess.run(command, check=True, timeout=30)
        for path, content in policies.items():
            guarded_write(path, content)
    # Existing setup owns identity/config no-overwrite and firewall-before-service
    # ordering. Never remove restrictions on any subsequent failure.
    setup.apply(files)
    units = (['anonguard-native-firewall.service', 'anonguard-native-pt.service',
              'anonguard-client.service', 'anonguard-native-adapter.service']
             if args.role == 'client' else ['anonguard-relay.service'])
    for unit in units:
        subprocess.run(['/usr/bin/systemctl', 'is-active', '--quiet', unit], check=True, timeout=10)
    if args.role == 'client':
        browser.validate_autoconfig(executable)
        browser.installed_extension()
        browser.validate_native(json.loads(files['etc/anonguard/device.json']))
    receipt = {'version': 1, 'role': args.role, 'browser': str(executable) if executable else None,
               'configuration_complete': True, 'browser_accepted': False, 'deployment_accepted': False}
    guarded_write(RECEIPT, json.dumps(receipt, indent=2) + '\n')
    return receipt


def launch():
    if os.geteuid() == 0:
        raise ValueError('Launch browsing as the ordinary desktop user, not root')
    receipt = json.loads(browser.trusted_file(RECEIPT))
    if (type(receipt.get('version')) is not int or receipt.get('version') != 1 or receipt.get('role') != 'client'
            or receipt.get('configuration_complete') is not True or not isinstance(receipt.get('browser'), str)):
        raise ValueError('Complete native client onboarding before browsing')
    return subprocess.run(['/usr/bin/anonguard-browser', '--native-client', '--circuit-isolation',
                           '--browser', receipt['browser'], '--launch'], check=False).returncode


def start():
    """Ordinary-user desktop entry: configure once, then launch the client."""
    if os.geteuid() == 0:
        raise ValueError('Start AnonGuard as the ordinary desktop user')
    if not RECEIPT.exists() and not RECEIPT.is_symlink():
        if os.environ.get('SSH_CONNECTION'):
            raise ValueError('First-run setup must run at the local device console')
        subprocess.run(['/usr/bin/sudo', '/usr/bin/anonguard-onboard', '--apply'], check=True)
    receipt = json.loads(browser.trusted_file(RECEIPT))
    if (type(receipt.get('version')) is not int or receipt.get('version') != 1
            or receipt.get('configuration_complete') is not True):
        raise ValueError('Onboarding is incomplete; inspect from the device console')
    if receipt.get('role') == 'volunteer':
        print('This device is configured as a non-exit Volunteer. Client browsing is not configured.')
        return 0
    return launch()


def prompt(args):
    if not sys.stdin.isatty():
        return
    if args.role is None:
        print('1. Client: configure this dedicated Linux device for browsing\n2. Volunteer: non-exit relay')
        args.role = {'1': 'client', '2': 'volunteer'}.get(input('Choose 1 or 2: ').strip())
        if args.role is None:
            raise ValueError('Choose Client or Volunteer')
    for name, label in [('bootstrap', 'Trusted network bootstrap file'),
                        ('bootstrap_sha256', 'Independently authenticated bootstrap SHA-256')]:
        if getattr(args, name) is None:
            value = input(label + ': ').strip()
            setattr(args, name, Path(value) if name == 'bootstrap' else value)
    if args.role == 'client':
        if args.browser is None and Path('/usr/bin/firefox-esr').exists():
            args.browser = Path('/usr/bin/firefox-esr')
        for name, label, path in [('transport_config', 'Private transport configuration file', True),
                                  ('transport_config_sha256', 'Authenticated transport SHA-256', False),
                                  ('browser', 'Root-installed maintained Firefox ESR executable', True)]:
            if getattr(args, name) is None:
                value = input(label + ': ').strip(); setattr(args, name, Path(value) if path else value)
        if args.extension is None and not Path('/usr/share/anonguard/browser/isolation-signed.json').exists():
            args.extension = Path(input('Mozilla-signed addon XPI: ').strip())
        if args.extension:
            if args.extension_sha256 is None: args.extension_sha256 = input('Authenticated addon SHA-256: ').strip()
            if args.extension_version is None: args.extension_version = input('Exact addon version: ').strip()
    elif args.role == 'volunteer' and args.relay_advertise is None:
        args.relay_advertise = input('Reachable relay IPv4:port; configure NAT forwarding separately: ').strip()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    action = parser.add_mutually_exclusive_group(required=True)
    action.add_argument('--plan', action='store_true', help='Validate prerequisites and inputs; change nothing')
    action.add_argument('--apply', action='store_true', help='Configure this dedicated device from its local console')
    action.add_argument('--launch', action='store_true', help='Launch the configured browser as the desktop user')
    action.add_argument('--start', action='store_true', help='Desktop flow: first-run setup if needed, then ordinary-user browsing')
    parser.add_argument('--role', choices=('client', 'volunteer'))
    parser.add_argument('--privacy-profile', choices=('balanced', 'balanced-longtail', 'fixed-window'), default='balanced',
                        help='Optional fixed-window cover has a high bandwidth cost; requires upgraded relays')
    parser.add_argument('--bootstrap', type=Path); parser.add_argument('--bootstrap-sha256')
    parser.add_argument('--transport-config', type=Path); parser.add_argument('--transport-config-sha256')
    parser.add_argument('--relay-advertise'); parser.add_argument('--browser', type=Path)
    parser.add_argument('--extension', type=Path); parser.add_argument('--extension-sha256')
    parser.add_argument('--extension-version'); parser.add_argument('--previous-extension-sha256')
    args = parser.parse_args()
    try:
        if args.launch: return launch()
        if args.start: return start()
        if args.apply and (os.geteuid() != 0 or os.environ.get('SSH_CONNECTION')):
            raise ValueError('Run sudo anonguard-onboard --apply at the local console; --plan is read-only')
        if args.apply:
            setup.require_console()
        prompt(args)
        if args.role is None or args.bootstrap is None or args.bootstrap_sha256 is None:
            raise ValueError('Role and authentic bootstrap are required')
        files, policies, executable = inspect(args)
        if args.plan:
            print(json.dumps({'role': args.role, 'prerequisites_checked': True, 'changes_applied': False,
                              'browser_configuration_targets': len(policies), 'deployment_accepted': False}))
        else:
            print(json.dumps(apply(args, files, policies, executable)))
            if args.role == 'client': print('Configuration complete. As your ordinary desktop user, open AnonGuard Browser. Installed browser/network acceptance is still required.')
        return 0
    except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError) as error:
        print('Onboarding refused: ' + str(error), file=sys.stderr)
        if args.apply: print('Partial configuration may remain; inspect from the console and preserve firewall/security state.', file=sys.stderr)
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
