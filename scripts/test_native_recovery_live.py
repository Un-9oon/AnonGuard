#!/usr/bin/env python3
"""Disposable systemd dependency/credential fixture; no host firewall or relay.
Uses generated dependency edges with UUID service names and synthetic PT data.
"""
import importlib.util
import json
import os
from pathlib import Path
import signal
import subprocess
import time
import uuid


def run(*args):
    return subprocess.run(args, check=True, capture_output=True, text=True, timeout=30).stdout.strip()


def wait_for(predicate, message, seconds=20):
    deadline = time.monotonic() + seconds
    while not predicate():
        if time.monotonic() >= deadline:
            raise AssertionError(message)
        time.sleep(.1)


def main():
    if os.geteuid() != 0 or os.environ.get('ANONGUARD_DISPOSABLE_RECOVERY_TEST') != '1':
        raise SystemExit('Requires root and ANONGUARD_DISPOSABLE_RECOVERY_TEST=1 on a disposable VM')
    spec = importlib.util.spec_from_file_location('setup', Path(__file__).with_name('device_setup.py'))
    setup = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(setup)
    bootstrap = {'version': 6, 'quorum': 1, 'authorities': [
        {'id': 'fixture', 'address': '192.0.2.10:9100', 'public_key': '01' * 32}]}
    binding = {'identity': [1] * 32, 'bridge': '192.168.1.2:8443', 'arguments': {'cert': 'fixture'}}
    config = {'mode': 'client', 'binary': '/usr/bin/obfs4proxy',
              'bridges': [binding], 'authorities': [binding]}
    files = setup.profile('client', bootstrap, 'ab' * 32, transport=config, transport_digest='cd' * 32)
    prefix = 'ag-recovery-' + uuid.uuid4().hex
    names = {'anonguard-native-firewall': prefix + '-firewall',
             'anonguard-native-pt': prefix + '-pt', 'anonguard-client': prefix + '-client',
             'anonguard-native-adapter': prefix + '-adapter'}
    runtime = Path('/run') / names['anonguard-native-pt']
    helper = Path('/usr/local/bin') / (prefix + '.py')
    units = []
    states = [Path('/var/lib/private') / names[key] for key in ('anonguard-client', 'anonguard-native-adapter')]
    helper.write_text('''import json, os, signal, socket, sys, uuid
from pathlib import Path
role, root = sys.argv[1:]
if role == 'pt':
 p=Path(root); token=uuid.uuid4().hex
 for name in ('bridges.json','authorities.json'):
  target=p/name; target.write_text(json.dumps({'generation':token})); target.chmod(0o600)
 address=os.environ['NOTIFY_SOCKET']
 if address.startswith('@'): address='\\0'+address[1:]
 with socket.socket(socket.AF_UNIX,socket.SOCK_DGRAM) as s: s.connect(address); s.sendall(b'READY=1')
else:
 result={'pid':os.getpid()}
 if role=='client':
  p=Path(os.environ['CREDENTIALS_DIRECTORY'])
  result['bridge']=json.loads((p/'bridges.json').read_text())
  result['authority']=json.loads((p/'authorities.json').read_text())
 Path(root,'observed.json').write_text(json.dumps(result))
while True: signal.pause()
''')
    helper.chmod(0o755)
    try:
        for original, name in names.items():
            text = files['etc/systemd/system/' + original + '.service']
            # Preserve generated Unit dependency edges and stop/restart settings.
            # Replace only execution/files/users with synthetic disposable fixtures.
            for old, new in names.items():
                text = text.replace(old + '.service', new + '.service')
            lines = []
            for line in text.splitlines():
                if line.startswith(('User=', 'Group=', 'EnvironmentFile=', 'LoadCredential=',
                                    'ExecStart=', 'ExecReload=', 'StateDirectory=', 'RuntimeDirectory=')):
                    continue
                lines.append(line)
            text = '\n'.join(lines).split('[Install]')[0]
            role = original.rsplit('-', 1)[-1]
            if role == 'firewall':
                text += '\nExecStart=/usr/bin/true\n'
            elif role == 'pt':
                text += f'\nDynamicUser=yes\nRuntimeDirectory={name}\nExecStart=/usr/bin/python3 {helper} pt {runtime}\n'
            else:
                text += f'\nDynamicUser=yes\nStateDirectory={name}\nExecStart=/usr/bin/python3 {helper} {role} /var/lib/{name}\n'
                if role == 'client':
                    text += f'LoadCredential=bridges.json:{runtime}/bridges.json\nLoadCredential=authorities.json:{runtime}/authorities.json\n'
            unit = Path('/run/systemd/system') / (name + '.service')
            assert not unit.exists(), 'Unexpected fixture collision'
            unit.write_text(text)
            units.append(unit)
        run('systemd-analyze', 'verify', *map(str, units))
        run('systemctl', 'daemon-reload')
        client = names['anonguard-client'] + '.service'
        pt = names['anonguard-native-pt'] + '.service'
        adapter = names['anonguard-native-adapter'] + '.service'
        observed = Path('/var/lib') / names['anonguard-client'] / 'observed.json'
        adapter_observed = Path('/var/lib') / names['anonguard-native-adapter'] / 'observed.json'
        def active(service):
            return subprocess.run(['systemctl', 'is-active', '--quiet', service], check=False).returncode == 0
        def state(path):
            try:
                return json.loads(path.read_text())
            except (FileNotFoundError, json.JSONDecodeError):
                return {}
        run('systemctl', 'start', client)
        wait_for(lambda: state(observed) and state(adapter_observed), 'Initial chain not ready')
        first = state(observed)
        first_adapter = state(adapter_observed)['pid']
        run('systemctl', 'restart', client)
        wait_for(lambda: state(observed).get('pid', first['pid']) != first['pid'] and
                 state(adapter_observed).get('pid', first_adapter) != first_adapter and active(adapter), 'Adapter did not restart')
        before = state(observed)
        pid = int(run('systemctl', 'show', '--property=MainPID', '--value', pt))
        os.kill(pid, signal.SIGKILL)
        wait_for(lambda: not active(client) and not active(adapter), 'Dependency loss did not stop applications')
        wait_for(lambda: active(pt), 'PT did not recover')
        run('systemctl', 'restart', client)
        wait_for(lambda: state(observed).get('bridge', before['bridge']) != before['bridge'] and active(adapter), 'Fresh credentials not loaded')
        renewed = state(observed)
        assert renewed['bridge'] == renewed['authority'], 'Mixed credential generations'
        run('systemctl', 'restart', pt)
        wait_for(lambda: state(observed).get('bridge', renewed['bridge']) != renewed['bridge'] and active(client) and active(adapter),
                 'Explicit PT restart failed to refresh dependent chain')
        assert active(names['anonguard-native-firewall'] + '.service'), 'Firewall fixture disappeared'
        print(json.dumps({'generated_dependency_graph': True, 'client_restart_restarts_adapter': True,
                          'pt_crash_stops_dependents': True, 'fresh_credentials_after_recovery': True,
                          'explicit_pt_restart_propagates': True, 'host_firewall_modified': False,
                          'synthetic_transport': True, 'real_relay_backend': False, 'production_accepted': False}))
    finally:
        for unit in reversed(units):
            subprocess.run(['systemctl', 'stop', unit.name], capture_output=True, timeout=30, check=False)
            subprocess.run(['systemctl', 'reset-failed', unit.name], capture_output=True, timeout=10, check=False)
            unit.unlink(missing_ok=True)
        helper.unlink(missing_ok=True)
        run('systemctl', 'daemon-reload')
        import shutil
        for state_path in states:
            link = Path('/var/lib') / state_path.name
            if link.is_symlink():
                link.unlink()
            if state_path.exists():
                shutil.rmtree(state_path)


if __name__ == '__main__':
    main()
